// Package postgres 提供 PostgreSQL 的存储方言、迁移后端与在线备份能力声明。
//
// 与 internal/storage/mysql 同一设计模式：不复制业务仓储代码，仓储 SQL 经由
// database/sql 驱动连接器在 Prepare 层做 SQLite -> PostgreSQL 方言重写；迁移 DDL
// 使用未重写的原始连接池单独执行。
//
// 本包只做静态、编译与 SQL 生成/参数化检查；首次版本不启动 PostgreSQL 服务器、
// 容器或云实例，也没有连接真实数据库的运行验证。任何“PostgreSQL 兼容性已验证”
// 的说法都不成立。
//
// 实现边界：
//   - 方言：? -> $n 占位符、INSERT OR IGNORE -> ON CONFLICT DO NOTHING、
//     裸 rowid -> _rowid、LIKE -> ILIKE（SQLite LIKE 对 ASCII 大小写不敏感）。
//     无法等价翻译的 SQLite 语法在 Prepare 阶段显式报错（fail-closed）。
//   - 迁移：由 migrations/postgres 从已提交 SQLite 迁移确定性翻译；Backend 使用
//     pg_advisory_lock 做跨连接排他锁，逐条迁移放在单事务内执行并记录
//     schema_history/schema_failures（PostgreSQL 支持事务内 DDL）。
//   - 服务器校验：UTF8、UTC、standard_conforming_strings、search_path 收紧、
//     REPEATABLE READ、版本与分支校验，任一不满足即拒绝，不降级。
//   - 在线备份：明确不支持（ErrOnlineBackupUnsupported），不生成假备份。
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// MinServerVersion 是声明支持的最低 PostgreSQL 主版本。PostgreSQL 14 是首次
	// 版本支持的基线（更早版本已结束上游支持）；真实服务器校验未运行实测。
	MinServerVersion = 14
	// DefaultPort 是默认 PostgreSQL 端口。
	DefaultPort = 5432
	// DefaultMaxOpenConns 是默认连接池上限。
	DefaultMaxOpenConns = 8
	// MaxAllowedOpenConns 是允许的最大连接池上限，避免误配置压垮服务器。
	MaxAllowedOpenConns = 32
	// DefaultConnectTimeout 是建立连接超时。
	DefaultConnectTimeout = 5 * time.Second
	// DefaultLockTimeout 是迁移排他锁等待时间。
	DefaultLockTimeout = 30 * time.Second
	// DefaultApplicationName 是连接的应用名（数据库侧可见的诊断信息）。
	DefaultApplicationName = "EvernightLogin"
	// migrationLockPrefix 是 advisory lock 的派生前缀，避免与其他应用碰撞。
	migrationLockPrefix = "EvernightLogin:migrate:"
)

// 会话级安全设置：任何连接都必须使用 UTF8、UTC、标准字符串与收紧的 search_path。
// search_path 只保留 public，避免攻击者同名 schema 覆盖应用表（"$user" 默认项被移除）。
var requiredRuntimeParams = map[string]string{
	"search_path":                   "public",
	"default_transaction_isolation": "repeatable read",
	"standard_conforming_strings":   "on",
	"TimeZone":                      "UTC",
	"DateStyle":                     "ISO, MDY",
	"client_encoding":               "UTF8",
	"extra_float_digits":            "3",
}

// Options 是打开 PostgreSQL 存储的配置。密码只用于建立连接，不写入错误文本、
// 日志或诊断输出。
type Options struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	// SSLMode 映射到 lib/pq 的 sslmode。默认 verify-full（校验证书链与主机名）。
	// 低于 verify-full 的模式（disable/allow/prefer/require/verify-ca）必须显式
	// 设置 AllowInsecure=true，且仅允许本地测试实例。
	SSLMode string
	// SSLRootCert 是自定义 CA 证书文件路径（sslmode=verify-ca/verify-full）。
	SSLRootCert string
	// SSLCert/SSLKey 是可选的客户端证书（mTLS）。
	SSLCert string
	SSLKey  string
	// AllowInsecure 显式允许非完整校验的连接（明文或主机名校验缺失）。默认 false。
	AllowInsecure    bool
	ConnectTimeout   time.Duration
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxIdleTime  time.Duration
	Retry            storage.RetryPolicy
	WriteGuard       func(ctx context.Context) (func(), error)
	MigrationLockTTL time.Duration
	ApplicationName  string
}

// DefaultOptions 返回给定数据库的默认配置。
func DefaultOptions(host, user, database string) Options {
	return Options{
		Host:             host,
		Port:             DefaultPort,
		User:             user,
		Database:         database,
		SSLMode:          string(pq.SSLModeVerifyFull),
		ConnectTimeout:   DefaultConnectTimeout,
		MaxOpenConns:     DefaultMaxOpenConns,
		MaxIdleConns:     DefaultMaxOpenConns,
		ConnMaxIdleTime:  5 * time.Minute,
		Retry:            storage.DefaultRetryPolicy(),
		MigrationLockTTL: DefaultLockTimeout,
		ApplicationName:  DefaultApplicationName,
	}
}

func (o Options) validate() (Options, error) {
	if strings.TrimSpace(o.Host) == "" {
		return Options{}, fmt.Errorf("PostgreSQL 主机不能为空")
	}
	if net.ParseIP(o.Host) == nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(o.Host) {
		return Options{}, fmt.Errorf("PostgreSQL 主机名不合法")
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.Port < 1 || o.Port > 65535 {
		return Options{}, fmt.Errorf("PostgreSQL 端口必须在 1～65535 之间")
	}
	if strings.TrimSpace(o.User) == "" {
		return Options{}, fmt.Errorf("PostgreSQL 用户名不能为空")
	}
	if strings.TrimSpace(o.Database) == "" {
		return Options{}, fmt.Errorf("PostgreSQL 数据库名不能为空")
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.ConnectTimeout < 0 || o.ConnectTimeout > time.Minute {
		return Options{}, fmt.Errorf("PostgreSQL 连接超时必须在 0～60 秒之间")
	}
	if o.MaxOpenConns == 0 {
		o.MaxOpenConns = DefaultMaxOpenConns
	}
	if o.MaxOpenConns < 1 || o.MaxOpenConns > MaxAllowedOpenConns {
		return Options{}, fmt.Errorf("PostgreSQL 连接池上限必须在 1～%d 之间", MaxAllowedOpenConns)
	}
	if o.MaxIdleConns == 0 {
		o.MaxIdleConns = o.MaxOpenConns
	}
	if o.MaxIdleConns < 0 || o.MaxIdleConns > o.MaxOpenConns {
		return Options{}, fmt.Errorf("PostgreSQL 空闲连接上限不能超过连接池上限")
	}
	if o.ConnMaxIdleTime == 0 {
		o.ConnMaxIdleTime = 5 * time.Minute
	}
	if o.ConnMaxIdleTime < 0 {
		return Options{}, fmt.Errorf("PostgreSQL 空闲连接回收时间不能为负数")
	}
	if o.Retry.MaxAttempts == 0 {
		o.Retry = storage.DefaultRetryPolicy()
	}
	if err := o.Retry.Validate(); err != nil {
		return Options{}, err
	}
	if o.MigrationLockTTL == 0 {
		o.MigrationLockTTL = DefaultLockTimeout
	}
	if o.MigrationLockTTL < 0 || o.MigrationLockTTL > 5*time.Minute {
		return Options{}, fmt.Errorf("PostgreSQL 迁移锁等待必须在 0～300 秒之间")
	}
	if strings.TrimSpace(o.ApplicationName) == "" {
		o.ApplicationName = DefaultApplicationName
	}
	switch pq.SSLMode(strings.TrimSpace(o.SSLMode)) {
	case "":
		o.SSLMode = string(pq.SSLModeVerifyFull)
	case pq.SSLModeVerifyFull:
		// 完整校验（证书链 + 主机名），默认唯一无需 AllowInsecure 的模式。
	case pq.SSLModeDisable, pq.SSLModeAllow, pq.SSLModePrefer,
		pq.SSLModeRequire, pq.SSLModeVerifyCA:
		// 明文、可回退明文、只加密不校验证书、校验链但不校验主机名：安全等级都低于
		// verify-full，必须显式允许且仅限本地测试，防止生产误用。
		if !o.AllowInsecure {
			return Options{}, fmt.Errorf("PostgreSQL sslmode=%s 低于 verify-full，必须显式设置 AllowInsecure=true 且仅用于本地测试", o.SSLMode)
		}
	default:
		return Options{}, fmt.Errorf("PostgreSQL sslmode 不合法")
	}
	return o, nil
}

// Store 是 PostgreSQL 存储句柄。SQLStore() 返回可传给现有各模块 sqlite 仓储的共享
// 执行器（仓储代码不重写）；本类型额外提供迁移、方言与备份能力入口。
type Store struct {
	sqlStore *storagesqlite.Store
	// db 是带仓储 SQL 重写的连接池，只给业务仓储使用。
	db *sql.DB
	// rawDB 是未重写的连接池，只给迁移 DDL/服务器校验/迁移记录使用：迁移 DDL 含
	// PostgreSQL 原生语法（jsonb 校验、触发器函数、md5 表达式索引），不能经过
	// SQLite->PostgreSQL 重写器。
	rawDB   *sql.DB
	options Options
}

// SQLStore 返回共享执行器。所有权仍属 Store，调用方不得关闭它。
func (s *Store) SQLStore() *storagesqlite.Store {
	if s == nil {
		return nil
	}
	return s.sqlStore
}

// MigrationLockKey 返回迁移排他锁的 advisory lock 键（64 位整数）。
//
// 键由固定前缀与数据库名派生，同一数据库的所有实例得到同一把锁；不同数据库几乎
// 不会碰撞。保留正数以避免与 PostgreSQL 其他两参数锁形式混淆。
func (s *Store) MigrationLockKey() int64 {
	sum := sha256.Sum256([]byte(migrationLockPrefix + s.options.Database))
	key := int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
	if key == 0 {
		key = 1
	}
	return key
}

// MigrationLockName 返回人类可读的锁名，用于诊断与文档；实际加锁使用
// MigrationLockKey。
func (s *Store) MigrationLockName() string {
	return migrationLockPrefix + s.options.Database
}

// Open 校验配置与服务器设置后建立连接池并返回 Store。
//
// 校验项（失败即拒绝使用，不降级）：
//   - 服务器为 PostgreSQL 主分支且主版本 ≥ MinServerVersion；
//   - server_encoding/客户端编码为 UTF8、standard_conforming_strings=on；
//   - 会话时区 UTC、DateStyle ISO、事务隔离 REPEATABLE READ；
//   - search_path 收紧为 public（不含 "$user" 等可被同名对象劫持的项）。
//
// 真实连接与上述运行期校验在本步未运行实测；错误文本不含密码。
func Open(ctx context.Context, options Options) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := options.validate()
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 配置不合法", err)
	}
	baseConfig, err := buildPQConfig(normalized)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 连接参数不合法", err)
	}
	rawConfig := baseConfig
	baseConnector, err := pq.NewConnectorConfig(baseConfig)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 连接参数不合法", err)
	}
	rawConnector, err := pq.NewConnectorConfig(rawConfig)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 连接参数不合法", err)
	}
	// 两条连接池方向明确：仓储语句走重写池；迁移/校验走原始池（DDL 不过重写器）。
	db := sql.OpenDB(newRewriteConnector(baseConnector))
	db.SetMaxOpenConns(normalized.MaxOpenConns)
	db.SetMaxIdleConns(normalized.MaxIdleConns)
	db.SetConnMaxIdleTime(normalized.ConnMaxIdleTime)
	rawDB := sql.OpenDB(rawConnector)
	rawDB.SetMaxOpenConns(4)
	rawDB.SetMaxIdleConns(2)
	rawDB.SetConnMaxIdleTime(normalized.ConnMaxIdleTime)

	if err := verifyServerSettings(ctx, rawDB, normalized); err != nil {
		_ = db.Close()
		_ = rawDB.Close()
		return nil, err
	}
	sqlStore, err := storagesqlite.WrapHostDB(db, storagesqlite.Options{
		WriteGuard: normalized.WriteGuard,
		Retry:      normalized.Retry,
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, mapError)
	if err != nil {
		_ = db.Close()
		_ = rawDB.Close()
		return nil, err
	}
	return &Store{sqlStore: sqlStore, db: db, rawDB: rawDB, options: normalized}, nil
}

// buildPQConfig 把 Options 转换为 lib/pq 配置。密码只放在 Config.Password，不拼接
// 到 DSN 字符串，错误文本因此不会包含凭据。
func buildPQConfig(options Options) (pq.Config, error) {
	config := pq.Config{
		Host:            options.Host,
		Port:            uint16(options.Port),
		User:            options.User,
		Password:        options.Password,
		Database:        options.Database,
		SSLMode:         pq.SSLMode(options.SSLMode),
		SSLRootCert:     options.SSLRootCert,
		SSLCert:         options.SSLCert,
		SSLKey:          options.SSLKey,
		ConnectTimeout:  options.ConnectTimeout,
		ApplicationName: options.ApplicationName,
		Runtime:         map[string]string{},
	}
	for name, value := range requiredRuntimeParams {
		config.Runtime[name] = value
	}
	return config, nil
}

// verifyServerSettings 抽样验证服务器设置，拒绝“以为连上了 PostgreSQL 却语义不同”
// 的假安全。它需要真实数据库连接，本步未运行实测。
func verifyServerSettings(ctx context.Context, db *sql.DB, options Options) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()

	var version string
	if err := conn.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
		return mapError(err)
	}
	lowerVersion := strings.ToLower(version)
	if !strings.Contains(lowerVersion, "postgresql") {
		return storage.New(storage.ErrUnavailable,
			"连接的服务器不是 PostgreSQL，拒绝使用", nil)
	}
	for _, fork := range []string{"cockroachdb", "yugabytedb", "greenplum", "redshift"} {
		if strings.Contains(lowerVersion, fork) {
			return storage.New(storage.ErrUnavailable,
				"检测到非 PostgreSQL 主分支的兼容数据库，排序/锁/DDL 语义不同，拒绝使用", nil)
		}
	}
	var versionNumber string
	if err := conn.QueryRowContext(ctx, "SHOW server_version_num").Scan(&versionNumber); err != nil {
		return mapError(err)
	}
	number, convErr := strconv.Atoi(versionNumber)
	if convErr != nil || number < MinServerVersion*10000 {
		return storage.New(storage.ErrUnavailable,
			fmt.Sprintf("PostgreSQL 版本低于 %d，拒绝使用", MinServerVersion), nil)
	}

	settings := []struct {
		name     string
		expected func(string) bool
		message  string
	}{
		{"server_encoding", func(value string) bool { return strings.EqualFold(value, "UTF8") },
			"PostgreSQL 服务器编码不是 UTF8，拒绝使用"},
		{"standard_conforming_strings", func(value string) bool { return strings.EqualFold(value, "on") },
			"PostgreSQL standard_conforming_strings 必须为 on，拒绝使用"},
		{"TimeZone", func(value string) bool {
			return strings.EqualFold(value, "UTC") || value == "+00:00"
		}, "PostgreSQL 会话时区必须为 UTC，拒绝使用"},
		{"DateStyle", func(value string) bool {
			return strings.HasPrefix(strings.ToUpper(value), "ISO")
		}, "PostgreSQL DateStyle 必须为 ISO，拒绝使用"},
		{"default_transaction_isolation", func(value string) bool {
			return strings.EqualFold(strings.ReplaceAll(value, " ", ""), "repeatableread")
		}, "PostgreSQL 事务隔离级别必须为 REPEATABLE READ，拒绝使用"},
	}
	for _, setting := range settings {
		var value string
		if err := conn.QueryRowContext(ctx, "SHOW "+setting.name).Scan(&value); err != nil {
			return mapError(err)
		}
		if !setting.expected(value) {
			return storage.New(storage.ErrUnavailable, setting.message, nil)
		}
	}
	var searchPath string
	if err := conn.QueryRowContext(ctx, "SHOW search_path").Scan(&searchPath); err != nil {
		return mapError(err)
	}
	if !searchPathSafe(searchPath) {
		return storage.New(storage.ErrUnavailable,
			"PostgreSQL search_path 未收紧为 public（不能包含 \"$user\" 或其他可写 schema），拒绝使用", nil)
	}
	// 迁移后端依赖会话级 advisory lock 与 REPEATABLE READ 下的事务 DDL；确认函数存在。
	var lockAvailable sql.NullBool
	if err := conn.QueryRowContext(ctx, "SELECT to_regprocedure('pg_advisory_lock(bigint)') IS NOT NULL").
		Scan(&lockAvailable); err != nil {
		return mapError(err)
	}
	if !lockAvailable.Valid || !lockAvailable.Bool {
		return storage.New(storage.ErrUnavailable,
			"PostgreSQL 缺少 pg_advisory_lock(bigint)，拒绝使用", nil)
	}
	_ = options
	return nil
}

// searchPathSafe 要求 search_path 只包含 public（允许 pg_catalog 排在后面），
// 且不含 "$user" 或其他 schema：避免同名 schema 覆盖应用表。
func searchPathSafe(searchPath string) bool {
	trimmed := strings.TrimSpace(searchPath)
	if trimmed == "" {
		return false
	}
	entries := strings.Split(trimmed, ",")
	for index, entry := range entries {
		entry = strings.TrimSpace(entry)
		entry = strings.Trim(entry, "\"")
		switch entry {
		case "public":
			if index != 0 {
				return false
			}
		case "pg_catalog":
			// 允许显式排在 public 之后。
		default:
			return false
		}
	}
	return len(entries) > 0 && strings.EqualFold(strings.Trim(strings.TrimSpace(entries[0]), "\""), "public")
}

// Ping 检查数据库仍可用。
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.sqlStore == nil {
		return storage.New(storage.ErrClosed, "存储已关闭", nil)
	}
	return s.sqlStore.Ping(ctx)
}

// Close 关闭连接池。重复调用安全；仓储不再可用。
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var storeErr, dbErr error
	if s.sqlStore != nil {
		storeErr = s.sqlStore.Close()
	}
	if s.db != nil {
		dbErr = s.db.Close()
	}
	if s.rawDB != nil {
		dbErr = errors.Join(dbErr, s.rawDB.Close())
	}
	return errors.Join(storeErr, dbErr)
}
