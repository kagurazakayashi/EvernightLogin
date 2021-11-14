package serverapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// LoadConfig 严格加载并校验 YAML 配置，然后应用可选的数据库路径覆盖。
//
// 加载失败（未知字段、重复键、类型错误、越界值、非法组合）一律返回错误，且
// 加载器本身不产生监听、数据库或文件写入副作用。覆盖数据库路径后再次整体校验，
// 避免通过 --database 绕过路径规则。配置文件路径与数据库路径统一规范为绝对路径，
// 防止服务因工作目录变化使用不同数据库。
func LoadConfig(configPath, databasePath string) (login.Config, error) {
	if strings.TrimSpace(configPath) == "" {
		return login.Config{}, fmt.Errorf("缺少 --config 配置文件路径")
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return login.Config{}, fmt.Errorf("配置文件路径无效: %w", err)
	}
	if info, statErr := os.Stat(absoluteConfig); statErr != nil || !info.Mode().IsRegular() {
		return login.Config{}, fmt.Errorf("配置文件不存在或不是普通文件: %s", absoluteConfig)
	}
	cfg, err := login.Load(login.LoadOptions{YAMLFile: absoluteConfig})
	if err != nil {
		return login.Config{}, fmt.Errorf("配置加载失败: %w", err)
	}
	if !cfg.Database.Driver.Valid() || cfg.Database.Driver != login.DatabaseDriverSQLite {
		return login.Config{}, fmt.Errorf("当前版本独立服务只支持 sqlite 数据库驱动，实际为 %q", string(cfg.Database.Driver))
	}
	if strings.TrimSpace(databasePath) != "" {
		cfg.Database.Path = databasePath
	}
	absoluteDatabase, err := filepath.Abs(cfg.Database.Path)
	if err != nil {
		return login.Config{}, fmt.Errorf("数据库路径无效: %w", err)
	}
	cfg.Database.Path = filepath.Clean(absoluteDatabase)
	if err := cfg.Validate(); err != nil {
		return login.Config{}, fmt.Errorf("最终配置校验失败: %w", err)
	}
	return cfg, nil
}

// LoadKeyring 解析主密钥环。优先级：
//  1. 配置里的 secrets.master_key（env:/file: 受保护来源）；
//  2. 显式 --master-key-file 路径（allowCreate 为 true 时，文件不存在则生成新
//     密钥环并以受保护权限写入，用于首次初始化）。
//
// 两条来源都不可用时返回错误，绝不自动生成"隐式默认密钥"。返回值 second 是实际
// 生效的密钥文件路径（仅用于诊断，不是秘密）。
func LoadKeyring(ctx context.Context, cfg login.Config, masterKeyFile string,
	allowCreate bool, now func() time.Time) (*secrets.Keyring, string, error) {
	if cfg.Secrets.MasterKey.IsSet() {
		provider := secrets.ProviderFunc(func(ctx context.Context) ([]byte, error) {
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
	absolutePath, err := filepath.Abs(masterKeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("主密钥文件路径无效: %w", err)
	}
	provider, err := secrets.NewFileProvider(absolutePath)
	if err != nil {
		return nil, "", fmt.Errorf("主密钥文件路径无效: %w", err)
	}
	if info, statErr := os.Stat(absolutePath); statErr == nil {
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("主密钥文件必须是普通文件: %s", absolutePath)
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

// migrationSet 加载内嵌迁移清单；失败表示编译产物损坏，直接拒绝启动。
func migrationSet() ([]migrate.Migration, error) {
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return nil, fmt.Errorf("加载数据库迁移清单失败: %w", err)
	}
	return list, nil
}

// CheckMigrated 只读检查数据库迁移状态。
//
// 返回 pending 为尚未应用的迁移版本（升序）。数据库没有 schema_history 表时视为
// 未迁移（pending 为全部版本）；存在失败记录时返回错误，要求先人工处置，不允许
// 在失败记录未清理时继续启动。
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
		return nil, fmt.Errorf("数据库存在 %d 条未清理的迁移失败记录，请先按迁移工具的提示人工处置", failures)
	}
	for _, migration := range list {
		if _, ok := applied[migration.Version]; !ok {
			pending = append(pending, migration.Version)
		}
	}
	return pending, nil
}

// ApplyMigrations 执行全部未应用的数据库迁移并返回本次应用数量。
//
// 迁移前先做只读检查，存在失败记录时拒绝执行；迁移过程由 migrate.Runner 的
// 排他锁与事务保证，失败会返回带版本号的错误。
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

// csrfOrigins 从显式公开地址与监听地址推导 CSRF 允许来源。
//
// CSRF 中间件只接受精确来源，不做通配匹配。推导范围刻意保守：显式配置的
// public_base_url，加上回环监听地址对应的本机来源（http 或 https）。通配监听
// 地址无法在启动前知道浏览器实际使用的来源，此时要求部署方配置 public_base_url；
// 一个来源都推导不出时启动失败，绝不退化为"不校验来源"。
func csrfOrigins(cfg login.Config) ([]string, error) {
	origins := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		origins = append(origins, candidate)
	}
	if strings.TrimSpace(cfg.Server.PublicBaseURL) != "" {
		parsed, err := url.Parse(cfg.Server.PublicBaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("server.public_base_url 无法解析为来源")
		}
		add(parsed.Scheme + "://" + parsed.Host)
	}
	scheme := "http"
	if cfg.Server.TLSEnabled() {
		scheme = "https"
	}
	for _, raw := range cfg.Server.ListenAddresses() {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || port == "0" {
			continue
		}
		loopback := host == "" || host == "::" || host == "0.0.0.0" ||
			strings.EqualFold(host, "localhost") || strings.HasPrefix(host, "127.") || host == "::1"
		if !loopback {
			continue
		}
		for _, candidateHost := range []string{"127.0.0.1", "localhost", "[::1]"} {
			add(scheme + "://" + candidateHost + ":" + port)
		}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("无法推导 CSRF 允许来源：请配置 server.public_base_url，" +
			"或使用回环监听地址")
	}
	sort.Strings(origins)
	return origins, nil
}
