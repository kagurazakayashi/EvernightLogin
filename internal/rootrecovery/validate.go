package rootrecovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	sqlitestore "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// instanceInfo 是校验通过后的实例快照（不含秘密）。
type instanceInfo struct {
	RootUserID            string
	RootUsername          string
	RootStatus            string
	SecurityVersion       int64
	InitializationState   string
	AppliedMigrationCount int
}

// validateDatabase 校验所选数据库是本项目当前版本的实例：
//   - schema_history 存在且与内嵌迁移的数量、版本、校验和完全一致（旧版本/未知
//     数据库拒绝）；
//   - 唯一 root 账户存在、状态 active、security_version > 0；
//   - root_initializations 单例记录存在并指向该 root。
//
// 只读查询，失败时不写入数据库。
func validateDatabase(ctx context.Context, store *sqlitestore.Store) (instanceInfo, error) {
	if store == nil {
		return instanceInfo{}, ErrOptionsInvalid
	}
	expected, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil || len(expected) == 0 {
		return instanceInfo{}, fmt.Errorf("%w: 无法加载当前迁移清单", ErrOptionsInvalid)
	}
	rows, err := store.QueryContext(ctx,
		`SELECT version, source_sha256 FROM schema_history ORDER BY version`)
	if err != nil {
		// 缺少 schema_history、文件不是 SQLite 或不是本项目库：统一视为无效实例。
		return instanceInfo{}, fmt.Errorf("%w: 数据库缺少可识别的迁移历史", ErrInvalidDatabase)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return instanceInfo{}, fmt.Errorf("%w: 迁移历史不可读", ErrInvalidDatabase)
		}
		if count >= len(expected) {
			return instanceInfo{}, fmt.Errorf("%w: 数据库迁移版本多于当前程序", ErrInvalidDatabase)
		}
		if version != expected[count].Version || checksum != expected[count].Checksum {
			return instanceInfo{}, fmt.Errorf("%w: 数据库迁移版本或校验和与当前程序不一致", ErrInvalidDatabase)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return instanceInfo{}, fmt.Errorf("%w: 迁移历史读取失败", ErrInvalidDatabase)
	}
	if count != len(expected) {
		return instanceInfo{}, fmt.Errorf("%w: 数据库迁移不完整（%d/%d）", ErrInvalidDatabase, count, len(expected))
	}
	info := instanceInfo{AppliedMigrationCount: count}

	rootRows, err := store.QueryContext(ctx,
		`SELECT id, username, status, security_version FROM users WHERE is_root=1`)
	if err != nil {
		return instanceInfo{}, fmt.Errorf("%w: 无法读取 root 账户", ErrInvalidDatabase)
	}
	defer rootRows.Close()
	rootCount := 0
	for rootRows.Next() {
		var securityVersion int64
		if err := rootRows.Scan(&info.RootUserID, &info.RootUsername, &info.RootStatus,
			&securityVersion); err != nil {
			return instanceInfo{}, fmt.Errorf("%w: root 账户不可读", ErrInvalidDatabase)
		}
		info.SecurityVersion = securityVersion
		rootCount++
	}
	if err := rootRows.Err(); err != nil {
		return instanceInfo{}, fmt.Errorf("%w: root 账户读取失败", ErrInvalidDatabase)
	}
	if rootCount == 0 {
		return instanceInfo{}, fmt.Errorf("%w: %w", ErrRootNotFound, ErrInvalidDatabase)
	}
	if rootCount != 1 {
		return instanceInfo{}, fmt.Errorf("%w: 数据库存在多个 root 账户", ErrInvalidDatabase)
	}
	if info.RootStatus != "active" {
		return instanceInfo{}, fmt.Errorf("%w: 当前 root 状态为 %q", ErrRootNotEligible, info.RootStatus)
	}
	if info.SecurityVersion <= 0 {
		return instanceInfo{}, fmt.Errorf("%w: root 安全版本无效", ErrInvalidDatabase)
	}

	initRows, err := store.QueryContext(ctx,
		`SELECT root_user_id, state FROM root_initializations WHERE singleton=1`)
	if err != nil {
		return instanceInfo{}, fmt.Errorf("%w: 无法读取 root 初始化状态", ErrInvalidDatabase)
	}
	defer initRows.Close()
	if !initRows.Next() {
		return instanceInfo{}, fmt.Errorf("%w: 缺少 root 初始化状态记录", ErrInvalidDatabase)
	}
	var rootUserID string
	if err := initRows.Scan(&rootUserID, &info.InitializationState); err != nil {
		return instanceInfo{}, fmt.Errorf("%w: root 初始化状态不可读", ErrInvalidDatabase)
	}
	if rootUserID != info.RootUserID {
		return instanceInfo{}, fmt.Errorf("%w: root 初始化记录与 root 账户不一致", ErrInvalidDatabase)
	}
	switch info.InitializationState {
	case "pending_setup", "setup_verified", "ready":
	default:
		return instanceInfo{}, fmt.Errorf("%w: root 初始化状态未知", ErrInvalidDatabase)
	}
	return info, nil
}

// queryIntTx 在审计事务内读取单值整数（计数使用）。
func queryIntTx(ctx context.Context, tx interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query string, args ...any) (int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("查询没有结果")
	}
	var value int64
	if err := rows.Scan(&value); err != nil {
		return 0, err
	}
	return value, nil
}
