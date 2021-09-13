package backup

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// SQLiteSnapshotter 是基于 SQLite 官方在线备份机制（modernc.org/sqlite 的
// sqlite3_backup 封装）的生产快照实现。它不复制运行中的数据库主文件，也不读取
// WAL/journal 旁文件，因此在持续写入时仍能得到一致快照。
type SQLiteSnapshotter struct {
	store *storagesqlite.Store
}

// NewSQLiteSnapshotter 校验并包装一个已打开、已迁移的 SQLite 存储。
func NewSQLiteSnapshotter(store *storagesqlite.Store) (*SQLiteSnapshotter, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", ErrOptionsInvalid)
	}
	return &SQLiteSnapshotter{store: store}, nil
}

// Snapshot 执行在线备份并读取快照中的最高迁移版本。destination 必须不存在；
// 失败时目标文件可能不完整，由调用方清理，本实现不留下“成功但版本未知”的结果。
func (s *SQLiteSnapshotter) Snapshot(ctx context.Context, destination string,
	progress func(donePages, totalPages int)) (SnapshotInfo, error) {
	if s == nil || s.store == nil {
		return SnapshotInfo{}, fmt.Errorf("%w: SQLite 快照器未初始化", ErrOptionsInvalid)
	}
	// 创建快照前先检查源库完整性：损坏的源库不得产出“成功”备份。使用
	// quick_check(1) 做有界快速检查，不修改数据库；损坏时明确 fail-closed。
	if err := probeSourceIntegrity(ctx, s.store); err != nil {
		return SnapshotInfo{}, err
	}
	if err := s.store.OnlineBackup(ctx, destination, progress); err != nil {
		return SnapshotInfo{}, fmt.Errorf("%w: %w", ErrSnapshotFailed, err)
	}
	info, err := inspectSnapshotDatabase(ctx, destination)
	if err != nil {
		return SnapshotInfo{}, err
	}
	return info, nil
}

// probeSourceIntegrity 在创建备份前对源数据库执行 PRAGMA quick_check(1)。
// 它只读取，不改库；并发写入下由 SQLite 自行取得一致读视图。检查失败/非 ok
// 都使备份明确失败，不把损坏源库的副本当成可用备份。
func probeSourceIntegrity(ctx context.Context, store *storagesqlite.Store) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	var result string
	if err := store.DB().QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&result); err != nil {
		return fmt.Errorf("%w: 源数据库完整性检查失败", ErrSnapshotFailed)
	}
	if !strings.EqualFold(strings.TrimSpace(result), "ok") {
		return fmt.Errorf("%w: 源数据库完整性检查未通过，拒绝生成备份", ErrSnapshotFailed)
	}
	return nil
}

// inspectSnapshotDatabase 以只读方式打开刚生成的快照，读取 schema_history 最高
// 迁移版本与页信息。缺少迁移历史说明这不是本项目已完成迁移的数据库，必须失败而
// 不是产出没有版本信息的“备份”。
func inspectSnapshotDatabase(ctx context.Context, path string) (SnapshotInfo, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SnapshotInfo{}, err
	}
	// 快照文件由本进程创建后不再写入；只读、单连接打开不影响其它连接。
	db, err := sql.Open("sqlite", path+"?_query_only=1&_busy_timeout=5000")
	if err != nil {
		return SnapshotInfo{}, fmt.Errorf("%w: 无法打开数据库快照检查版本", ErrSnapshotFailed)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var exists int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_history'`).
		Scan(&exists); err != nil {
		return SnapshotInfo{}, fmt.Errorf("%w: 无法检查迁移历史表", ErrSnapshotFailed)
	}
	if exists == 0 {
		return SnapshotInfo{}, fmt.Errorf("%w: 数据库缺少迁移历史，拒绝生成无版本备份",
			ErrSnapshotFailed)
	}
	var version string
	if err := db.QueryRowContext(ctx,
		`SELECT version FROM schema_history ORDER BY version DESC LIMIT 1`).
		Scan(&version); err != nil {
		if err == sql.ErrNoRows {
			return SnapshotInfo{}, fmt.Errorf("%w: 数据库迁移历史为空", ErrSnapshotFailed)
		}
		return SnapshotInfo{}, fmt.Errorf("%w: 无法读取数据库迁移版本", ErrSnapshotFailed)
	}
	if err := validateDisplayField("数据库版本", version, 128); err != nil {
		return SnapshotInfo{}, err
	}
	info := SnapshotInfo{Engine: "sqlite", SchemaVersion: version,
		SchemaVersionNumber: parseSchemaVersionNumber(version)}
	// 页信息只用于诊断与进度核对；读取失败不使已成功的在线备份失败。
	_ = db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&info.PageSize)
	_ = db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&info.PageCount)
	return info, nil
}

// parseSchemaVersionNumber 解析迁移版本文本的零填充数字前缀；无法解析时返回 0，
// 清单中仍保留原始文本供人工核对。
func parseSchemaVersionNumber(version string) int {
	prefix := version
	if index := strings.IndexByte(version, '_'); index >= 0 {
		prefix = version[:index]
	}
	number, err := strconv.Atoi(prefix)
	if err != nil || number < 0 || number > 1_000_000 {
		return 0
	}
	return number
}
