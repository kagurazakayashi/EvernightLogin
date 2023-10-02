package appcore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// OpenStore 按配置打开 SQLite 存储；writeGuard 非 nil 时接入维护门闸。
func OpenStore(ctx context.Context, cfg config.Config,
	writeGuard func(context.Context) (func(), error)) (*sqlite.Store, error) {
	options := sqlite.DefaultOptions(cfg.Database.Path)
	options.WAL = cfg.Database.WAL
	options.BusyTimeout = time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond
	options.WriteGuard = writeGuard
	if err := os.MkdirAll(filepath.Dir(cfg.Database.Path), 0o700); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	store, err := sqlite.Open(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	return store, nil
}

// LoadKeyring 解析主密钥环：配置中的 secrets.master_key 优先，其次显式文件路径；
// allowCreate 为 true 时文件不存在则生成受保护主密钥环。
func LoadKeyring(ctx context.Context, cfg config.Config, masterKeyFile string,
	allowCreate bool, now func() time.Time) (*secrets.Keyring, string, error) {
	if cfg.Secrets.MasterKey.IsSet() {
		provider := secrets.ProviderFunc(func(context.Context) ([]byte, error) {
			return cfg.Secrets.MasterKey.Value(), nil
		})
		ring, err := secrets.LoadKeyring(ctx, provider)
		if err != nil {
			return nil, "", fmt.Errorf("加载配置中的主密钥环失败: %w", err)
		}
		return ring, "", nil
	}
	if strings.TrimSpace(masterKeyFile) == "" {
		return nil, "", fmt.Errorf("缺少主密钥环：请在配置中设置 secrets.master_key，" +
			"或用 --master-key-file 指定受保护密钥文件")
	}
	absolutePath, err := filepath.Abs(strings.TrimSpace(masterKeyFile))
	if err != nil {
		return nil, "", fmt.Errorf("主密钥文件路径无效: %w", err)
	}
	provider, err := secrets.NewFileProvider(absolutePath)
	if err != nil {
		return nil, "", fmt.Errorf("主密钥文件路径无效: %w", err)
	}
	if info, statErr := os.Stat(absolutePath); statErr == nil {
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("主密钥文件必须是普通文件")
		}
		ring, loadErr := secrets.LoadKeyring(ctx, provider)
		if loadErr != nil {
			return nil, "", fmt.Errorf("加载主密钥环失败: %w", loadErr)
		}
		return ring, absolutePath, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, "", fmt.Errorf("读取主密钥文件状态失败: %w", statErr)
	}
	if !allowCreate {
		return nil, "", fmt.Errorf("主密钥文件不存在: %s", absolutePath)
	}
	if now == nil {
		now = time.Now
	}
	ring, err := secrets.GenerateKeyring("k1", now())
	if err != nil {
		return nil, "", fmt.Errorf("生成主密钥环失败: %w", err)
	}
	document, err := ring.Document()
	if err != nil {
		return nil, "", fmt.Errorf("序列化主密钥环失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, "", fmt.Errorf("创建主密钥目录失败: %w", err)
	}
	if err := secrets.WriteProtectedFile(absolutePath, document); err != nil {
		return nil, "", fmt.Errorf("写入受保护主密钥文件失败: %w", err)
	}
	return ring, absolutePath, nil
}

// NewAuditRecorder 构造安全审计写入器；审计不可用时装配失败（fail-closed）。
func NewAuditRecorder(ctx context.Context, store *sqlite.Store,
	logger *slog.Logger, now func() time.Time) (*audit.Recorder, error) {
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("构造审计存储失败: %w", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: now, Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("构造安全审计失败: %w", err)
	}
	return recorder, nil
}

// CheckMigrated 只读检查数据库迁移状态；数据库无 schema_history 视为未迁移。
func CheckMigrated(ctx context.Context, store *sqlite.Store) (pending []string, err error) {
	list, err := migrationSet()
	if err != nil {
		return nil, err
	}
	db := store.DB()
	var bookkeeping int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_history'`).
		Scan(&bookkeeping); err != nil {
		return nil, fmt.Errorf("读取数据库迁移记录失败: %w", err)
	}
	if bookkeeping == 0 {
		pending = make([]string, 0, len(list))
		for _, migration := range list {
			pending = append(pending, migration.Version)
		}
		return pending, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_history`)
	if err != nil {
		return nil, fmt.Errorf("读取数据库迁移记录失败: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]struct{}, len(list))
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("读取数据库迁移记录失败: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取数据库迁移记录失败: %w", err)
	}
	var failures int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_failures'`).
		Scan(&bookkeeping); err != nil {
		return nil, fmt.Errorf("读取数据库迁移失败记录失败: %w", err)
	}
	if bookkeeping > 0 {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_failures`).Scan(&failures); err != nil {
			return nil, fmt.Errorf("读取数据库迁移失败记录失败: %w", err)
		}
	}
	if failures > 0 {
		return nil, fmt.Errorf("数据库存在 %d 条未清理的迁移失败记录", failures)
	}
	for _, migration := range list {
		if _, ok := applied[migration.Version]; !ok {
			pending = append(pending, migration.Version)
		}
	}
	return pending, nil
}

// ApplyMigrations 执行全部未应用迁移并返回数量。
func ApplyMigrations(ctx context.Context, store *sqlite.Store) (int, error) {
	list, err := migrationSet()
	if err != nil {
		return 0, err
	}
	if _, err := CheckMigrated(ctx, store); err != nil {
		return 0, err
	}
	result, err := store.Migrate(ctx, list)
	if err != nil {
		return 0, fmt.Errorf("执行数据库迁移失败: %w", err)
	}
	return len(result.Applied), nil
}

// migrationSet 加载内嵌迁移清单。
func migrationSet() ([]migrate.Migration, error) {
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return nil, fmt.Errorf("加载数据库迁移清单失败: %w", err)
	}
	return list, nil
}

var _ = context.Background
