// 本文件实现 managecli 各命令共用的配置加载、数据库打开与迁移状态检查辅助。
package managecli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
	"go.yaml.in/yaml/v3"
)

// maxConfigFileBytes 与 root 配置加载器一致：配置文件最大 1 MiB。
const maxConfigFileBytes = 1 << 20

// configErrorDetail 是配置错误的脱敏结构化投影，供 --json 输出。
type configErrorDetail struct {
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
	Field  string `json:"field,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail"`
}

// loadEffectiveConfig 读取有效配置。--config 指向 YAML 文件；其余来源（环境变量）
// 由 login.Load 按既有优先级合并。配置文件里只允许秘密来源引用，不允许秘密值。
func (r *runner) loadEffectiveConfig(values map[string]string) (login.Config, int) {
	options := login.LoadOptions{LookupEnv: r.options.LookupEnv}
	if path := stringFlag(values, "config"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return login.Config{}, r.usage("--config 路径无效")
		}
		info, err := os.Stat(absolute)
		if err != nil || !info.Mode().IsRegular() {
			return login.Config{}, r.fail("CONFIG_FILE_INVALID", ExitError,
				"配置文件不存在或不是普通文件", nil)
		}
		if info.Size() > maxConfigFileBytes {
			return login.Config{}, r.fail("CONFIG_FILE_INVALID", ExitError,
				"配置文件超过 1 MiB 上限", nil)
		}
		options.YAMLFile = absolute
	}
	config, err := login.Load(options)
	if err == nil {
		return config, ExitOK
	}
	var configErrors login.ConfigErrors
	if errors.As(err, &configErrors) {
		details := make([]configErrorDetail, 0, len(configErrors))
		for _, item := range configErrors {
			details = append(details, configErrorDetail{Kind: item.Kind.String(),
				Source: item.Source, Field: item.Field, Line: item.Line,
				Detail: item.Detail})
		}
		return login.Config{}, r.fail("CONFIG_INVALID", ExitError, err.Error(), details)
	}
	return login.Config{}, r.fail("CONFIG_INVALID", ExitError, err.Error(), nil)
}

// loadEffectiveConfigTolerant 读取有效配置，但对未设置的秘密来源使用占位值，
// 使 `config show/get/diff` 在秘密环境变量暂未设置时仍能展示其他已校验字段。
// 它不改变真实启动路径：服务启动仍使用 login.Load 的严格行为。
func (r *runner) loadEffectiveConfigTolerant(values map[string]string) (login.Config, int) {
	file := stringFlag(values, "config")
	// 只对 YAML 中实际出现的 env: 秘密来源使用占位值；不能对所有已知秘密环境
	// 变量名占位，否则会把“未设置的环境覆盖”伪造成已设置，改变配置含义。
	names := secretEnvNamesFromYAMLFile(file)
	lookup := func(name string) (string, bool) {
		value, ok := readEnv(r.options.LookupEnv, name)
		if ok && value != "" {
			return value, true
		}
		if _, isSecretSource := names[name]; isSecretSource {
			return "managecli-diagnostic-placeholder-secret", true
		}
		return value, ok
	}
	options := login.LoadOptions{LookupEnv: lookup}
	if file != "" {
		absolute, err := filepath.Abs(file)
		if err != nil {
			return login.Config{}, r.usage("--config 路径无效")
		}
		if info, statErr := os.Stat(absolute); statErr != nil || !info.Mode().IsRegular() {
			return login.Config{}, r.fail("CONFIG_FILE_INVALID", ExitError,
				"配置文件不存在或不是普通文件", nil)
		}
		options.YAMLFile = absolute
	}
	config, err := login.Load(options)
	if err == nil {
		return config, ExitOK
	}
	var configErrors login.ConfigErrors
	if errors.As(err, &configErrors) {
		details := configErrorDetails(err)
		return login.Config{}, r.fail("CONFIG_INVALID", ExitError, err.Error(), details)
	}
	return login.Config{}, r.fail("CONFIG_INVALID", ExitError, err.Error(), nil)
}

// secretEnvNamesFromYAMLFile 读取 YAML 配置文件中的 env: 秘密来源变量名；文件
// 不存在或不是合法 YAML 时返回空集合（具体错误由加载器报告）。
func secretEnvNamesFromYAMLFile(path string) map[string]struct{} {
	names := make(map[string]struct{})
	if strings.TrimSpace(path) == "" {
		return names
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return names
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return names
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return names
	}
	return secretEnvNames(&document)
}

// defaultDatabasePath 返回内置默认配置的数据库绝对路径（即 database/login.db）。
// 未显式指定数据库路径时命令会拒绝使用它，避免误触真实/基线库。
func defaultDatabasePath() string {
	absolute, err := filepath.Abs(login.Default().Database.Path)
	if err != nil {
		return ""
	}
	return filepath.Clean(absolute)
}

// isDefaultDatabasePath 报告路径是否就是默认 database/login.db。
func isDefaultDatabasePath(absolute string) bool {
	defaultPath := defaultDatabasePath()
	return defaultPath != "" && filepath.Clean(absolute) == defaultPath
}

// refuseImplicitDefaultDatabase 在默认数据库路径未被显式允许时返回错误。
func (r *runner) refuseImplicitDefaultDatabase(absolute string) int {
	return r.fail("CONFIG_DEFAULT_DATABASE_REFUSED", ExitUsage,
		"命令指向内置默认数据库 database/login.db 且未显式允许；"+
			"请用 --config 指定部署配置，或确需操作该库时显式加 --allow-default-database",
		map[string]any{"database_path": absolute})
}

// dataPath 返回有效配置中的 SQLite 数据库绝对路径；未配置、非 SQLite 驱动或隐式
// 指向默认 database/login.db 时返回明确错误码。它是所有本地管理命令的唯一数据库
// 入口，避免各命令各自拼路径。
func (r *runner) dataPath(config login.Config) (string, int) {
	path, code := r.tryDataPath(config)
	if code != "" {
		if code == "CONFIG_DEFAULT_DATABASE_REFUSED" {
			return "", r.refuseImplicitDefaultDatabase(path)
		}
		if code == "DATABASE_UNSUPPORTED" {
			return "", r.fail("DATABASE_UNSUPPORTED", ExitError,
				"当前 CLI 只支持 SQLite 数据库（其他驱动需步骤 85+ 适配）", nil)
		}
		if code == "CONFIG_INVALID" {
			return "", r.fail("CONFIG_INVALID", ExitError, "未配置 database.path", nil)
		}
		return "", r.fail("DATABASE_PATH_INVALID", ExitError, "database.path 无效", nil)
	}
	return path, ExitOK
}

// openDatabase 打开一个已迁移的 SQLite 数据库。它拒绝创建新数据库文件：诊断与
// 管理命令对不存在的库返回 DATABASE_NOT_INITIALIZED，避免掩盖错误路径。
func (r *runner) openDatabase(config login.Config) (*storagesqlite.Store, int) {
	path, exit := r.dataPath(config)
	if exit != ExitOK {
		return nil, exit
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, r.fail("DATABASE_NOT_INITIALIZED", ExitError,
			"数据库文件不存在或不是普通文件（不会创建新数据库）", nil)
	}
	options := storagesqlite.Options{Path: path, WAL: config.Database.WAL,
		BusyTimeout: time.Duration(config.Database.BusyTimeoutMS) * time.Millisecond}
	store, err := storagesqlite.Open(r.ctx, options)
	if err != nil {
		return nil, r.fail("DB_UNAVAILABLE", ExitError, "无法打开数据库", nil)
	}
	return store, ExitOK
}

// tryDataPath 与 dataPath 相同但不输出错误，供诊断命令自行聚合结果。返回值第二项
// 是稳定错误码；返回的路径仅在错误码为空时有效（拒绝默认库时也返回该路径供报告）。
func (r *runner) tryDataPath(config login.Config) (string, string) {
	if !config.Database.Driver.Valid() || config.Database.Driver != login.DatabaseDriverSQLite {
		return "", "DATABASE_UNSUPPORTED"
	}
	path := strings.TrimSpace(config.Database.Path)
	if path == "" {
		return "", "CONFIG_INVALID"
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "DATABASE_PATH_INVALID"
	}
	if isDefaultDatabasePath(absolute) && !r.allowDefaultDatabase {
		return absolute, "CONFIG_DEFAULT_DATABASE_REFUSED"
	}
	return absolute, ""
}

// tryDatabaseReadOnly 与 openDatabaseReadOnly 相同但只返回稳定错误码，不写输出；
// 诊断命令据此把失败聚合进结构化检查列表，避免重复错误输出。
func (r *runner) tryDatabaseReadOnly(config login.Config) (*storagesqlite.Store, string) {
	path, code := r.tryDataPath(config)
	if code != "" {
		return nil, code
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "DATABASE_NOT_INITIALIZED"
	}
	store, err := storagesqlite.Open(r.ctx, storagesqlite.Options{Path: path,
		WAL: false, BusyTimeout: time.Duration(config.Database.BusyTimeoutMS) * time.Millisecond})
	if err != nil {
		return nil, "DB_UNAVAILABLE"
	}
	return store, ""
}

// openDatabaseReadOnly 以不强制 WAL、不写入的意图打开数据库，供只读诊断/查询
// 命令使用。它仍然使用既有 SQLite 连接实现（不复制连接参数），只是不主动切换
// journal_mode；调用方只执行 SELECT/PRAGMA 查询。
func (r *runner) openDatabaseReadOnly(config login.Config) (*storagesqlite.Store, int) {
	path, exit := r.dataPath(config)
	if exit != ExitOK {
		return nil, exit
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, r.fail("DATABASE_NOT_INITIALIZED", ExitError,
			"数据库文件不存在或不是普通文件（不会创建新数据库）", nil)
	}
	store, err := storagesqlite.Open(r.ctx, storagesqlite.Options{Path: path,
		WAL: false, BusyTimeout: time.Duration(config.Database.BusyTimeoutMS) * time.Millisecond})
	if err != nil {
		return nil, r.fail("DB_UNAVAILABLE", ExitError, "无法打开数据库", nil)
	}
	return store, ExitOK
}

// migrationReport 是迁移状态诊断结果（不含任何数据库凭据）。
type migrationReport struct {
	AppliedCount     int      `json:"applied_count"`
	AppliedVersion   string   `json:"applied_version,omitempty"`
	EmbeddedVersion  string   `json:"embedded_version,omitempty"`
	Pending          []string `json:"pending,omitempty"`
	UnknownApplied   []string `json:"unknown_applied,omitempty"`
	ChecksumMismatch []string `json:"checksum_mismatch,omitempty"`
	Failed           []string `json:"failed,omitempty"`
	Current          bool     `json:"current"`
}

// tableExists 检查指定表是否存在（迁移记录表属于基础设施，旧库可能尚未创建）。
func tableExists(ctx context.Context, store *storagesqlite.Store, name string) (bool, error) {
	var count int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).
		Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// inspectMigrations 只读检查 schema_history/schema_failures，并与内嵌迁移目录比较。
// 它不执行任何迁移、不写数据库；任何查询失败都返回错误由调用方映射为 DB_UNAVAILABLE。
func inspectMigrations(ctx context.Context, store *storagesqlite.Store) (migrationReport, error) {
	report := migrationReport{}
	embedded, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return report, fmt.Errorf("加载内嵌迁移失败: %w", err)
	}
	byVersion := make(map[string]migrate.Migration, len(embedded))
	for _, item := range embedded {
		byVersion[item.Version] = item
	}
	if len(embedded) > 0 {
		report.EmbeddedVersion = embedded[len(embedded)-1].Version
	}
	hasHistory, err := tableExists(ctx, store, "schema_history")
	if err != nil {
		return report, err
	}
	if hasHistory {
		rows, err := store.DB().QueryContext(ctx,
			`SELECT version, source_sha256 FROM schema_history ORDER BY version`)
		if err != nil {
			return report, err
		}
		defer rows.Close()
		applied := make(map[string]string)
		for rows.Next() {
			var version, checksum string
			if err := rows.Scan(&version, &checksum); err != nil {
				return report, err
			}
			applied[version] = checksum
			report.AppliedCount++
			report.AppliedVersion = version
		}
		if err := rows.Err(); err != nil {
			return report, err
		}
		for _, item := range embedded {
			checksum, ok := applied[item.Version]
			if !ok {
				report.Pending = append(report.Pending, item.Version)
				continue
			}
			if checksum != item.Checksum {
				report.ChecksumMismatch = append(report.ChecksumMismatch, item.Version)
			}
		}
		versions := make([]string, 0, len(applied))
		for version := range applied {
			versions = append(versions, version)
		}
		sort.Strings(versions)
		for _, version := range versions {
			if _, ok := byVersion[version]; !ok {
				report.UnknownApplied = append(report.UnknownApplied, version)
			}
		}
	}
	hasFailures, err := tableExists(ctx, store, "schema_failures")
	if err != nil {
		return report, err
	}
	if hasFailures {
		rows, err := store.DB().QueryContext(ctx,
			`SELECT version FROM schema_failures ORDER BY version`)
		if err != nil {
			return report, err
		}
		defer rows.Close()
		for rows.Next() {
			var version string
			if err := rows.Scan(&version); err != nil {
				return report, err
			}
			report.Failed = append(report.Failed, version)
		}
		if err := rows.Err(); err != nil {
			return report, err
		}
	}
	report.Current = hasHistory && len(report.Pending) == 0 &&
		len(report.UnknownApplied) == 0 && len(report.ChecksumMismatch) == 0 &&
		len(report.Failed) == 0
	return report, nil
}

// quickCheck 执行 SQLite 只读完整性检查；返回是否 ok 与首条问题描述。
func quickCheck(ctx context.Context, store *storagesqlite.Store) (bool, string, error) {
	rows, err := store.DB().QueryContext(ctx, `PRAGMA quick_check(1)`)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	var result string
	if rows.Next() {
		if err := rows.Scan(&result); err != nil {
			return false, "", err
		}
	}
	if err := rows.Err(); err != nil {
		return false, "", err
	}
	return strings.EqualFold(strings.TrimSpace(result), "ok"), result, nil
}

// exitForCode 把领域错误码映射为稳定退出码。只做类别映射，不改变原始错误文本。
func exitForCode(code string) int {
	switch code {
	case "ACCESS_DENIED", "ROOT_PROTECTED":
		return ExitForbidden
	case "CONFLICT", "STATE_CONFLICT", "TASK_CANCEL_CONFLICT":
		return ExitConflict
	case "TASK_NOT_FOUND":
		return ExitError
	default:
		return ExitError
	}
}
