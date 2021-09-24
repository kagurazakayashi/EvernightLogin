// Package mysql 提供 MySQL 8.0+ 的存储方言、迁移后端与在线备份能力声明。
//
// 本包只做静态、编译与 SQL 生成/参数化检查；首次版本不启动 MySQL、容器或云实例，
// 也没有连接真实数据库的运行验证。任何“兼容性已验证”的说法都不成立。
//
// 实现边界：
//   - 方言与 SQL 重写：把既有仓储 SQL 中的 SQLite 方言（ON CONFLICT、INSERT OR
//     IGNORE、rowid、同表 DELETE 子查询）确定性翻译为 MySQL 语法；无法等价翻译时
//     显式报错，不静默降级、不猜测。
//   - 迁移：迁移语句由 migrations/mysql 在加载时从已提交 SQLite 迁移翻译生成；
//     本包 Backend 用 GET_LOCK 做跨连接排他锁，按 MySQL DDL 隐式提交语义逐条执行
//     并记录 schema_history/schema_failures，失败不承诺自动回滚。
//   - 仓储接入：仓储代码本身不复制、不重写；Open 返回的 *sqlite.Store 通过重写
//     驱动器把所有经过 database/sql 的语句（含事务内语句）翻译为 MySQL 方言。
//   - 在线备份：明确不支持（ErrOnlineBackupUnsupported），不生成假备份。
package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// MinServerVersion 是声明支持的 MySQL 最低版本（CHECK 约束从 8.0.16 开始执行）。
	MinServerVersion = "8.0.16"
	// DefaultPort 是默认 MySQL 端口。
	DefaultPort = 3306
	// DefaultMaxOpenConns 是默认连接池上限。
	DefaultMaxOpenConns = 8
	// MaxAllowedOpenConns 是允许的最大连接池上限，避免误配置压垮服务器。
	MaxAllowedOpenConns = 32
	// DefaultConnectTimeout 是建立连接超时。
	DefaultConnectTimeout = 5 * time.Second
	// DefaultIOTimeout 是读写超时；服务器/网络异常时不无限等待。
	DefaultIOTimeout = 30 * time.Second
	// DefaultLockTimeout 是迁移排他锁等待时间。
	DefaultLockTimeout = 30 * time.Second
	// migrationLockPrefix 是 GET_LOCK 名称前缀，加数据库名后最长 64 字符。
	migrationLockPrefix = "EvernightLogin:migrate:"
)

// 严格 sql_mode：拒绝隐式截断/非法日期，避免 SQLite 与 MySQL 在数据截断上静默
// 分叉。通过连接参数在每条连接上设置。
const strictSQLMode = "STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"

// Options 是打开 MySQL 存储的配置。密码只用于建立连接，不写入错误文本、日志或
// 诊断输出。
type Options struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	// TLS 映射到 go-sql-driver 的 tls 参数：默认 "true"（校验服务器证书）。
	// 也接受已注册的自定义 TLS 配置名（校验证书）。仅本地测试时配合 AllowInsecure
	// 使用 ""（明文）、"skip-verify" 或 "preferred"（驱动允许回退明文/不校验证书）。
	TLS string
	// AllowInsecure 显式允许非加密/跳过证书校验的连接。默认 false，防止生产误用；
	// 仅在本地临时测试实例（127.0.0.1）使用，文档已标明不得用于生产。
	AllowInsecure    bool
	ConnectTimeout   time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxIdleTime  time.Duration
	Retry            storage.RetryPolicy
	WriteGuard       func(ctx context.Context) (func(), error)
	MigrationLockTTL time.Duration
}

// DefaultOptions 返回给定数据库的默认配置。
func DefaultOptions(host, user, database string) Options {
	return Options{
		Host:             host,
		Port:             DefaultPort,
		User:             user,
		Database:         database,
		TLS:              "true",
		ConnectTimeout:   DefaultConnectTimeout,
		ReadTimeout:      DefaultIOTimeout,
		WriteTimeout:     DefaultIOTimeout,
		MaxOpenConns:     DefaultMaxOpenConns,
		MaxIdleConns:     DefaultMaxOpenConns,
		ConnMaxIdleTime:  5 * time.Minute,
		Retry:            storage.DefaultRetryPolicy(),
		MigrationLockTTL: DefaultLockTimeout,
	}
}

func (o Options) validate() (Options, error) {
	if strings.TrimSpace(o.Host) == "" {
		return Options{}, fmt.Errorf("MySQL 主机不能为空")
	}
	if net.ParseIP(o.Host) == nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(o.Host) {
		return Options{}, fmt.Errorf("MySQL 主机名不合法")
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.Port < 1 || o.Port > 65535 {
		return Options{}, fmt.Errorf("MySQL 端口必须在 1～65535 之间")
	}
	if strings.TrimSpace(o.User) == "" {
		return Options{}, fmt.Errorf("MySQL 用户名不能为空")
	}
	if strings.TrimSpace(o.Database) == "" {
		return Options{}, fmt.Errorf("MySQL 数据库名不能为空")
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.ConnectTimeout < 0 || o.ConnectTimeout > time.Minute {
		return Options{}, fmt.Errorf("MySQL 连接超时必须在 0～60 秒之间")
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = DefaultIOTimeout
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = DefaultIOTimeout
	}
	if o.MaxOpenConns == 0 {
		o.MaxOpenConns = DefaultMaxOpenConns
	}
	if o.MaxOpenConns < 1 || o.MaxOpenConns > MaxAllowedOpenConns {
		return Options{}, fmt.Errorf("MySQL 连接池上限必须在 1～%d 之间", MaxAllowedOpenConns)
	}
	if o.MaxIdleConns == 0 {
		o.MaxIdleConns = o.MaxOpenConns
	}
	if o.MaxIdleConns < 0 || o.MaxIdleConns > o.MaxOpenConns {
		return Options{}, fmt.Errorf("MySQL 空闲连接上限不能超过连接池上限")
	}
	if o.ConnMaxIdleTime == 0 {
		o.ConnMaxIdleTime = 5 * time.Minute
	}
	if o.ConnMaxIdleTime < 0 {
		return Options{}, fmt.Errorf("MySQL 空闲连接回收时间不能为负数")
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
		return Options{}, fmt.Errorf("MySQL 迁移锁等待必须在 0～300 秒之间")
	}
	switch o.TLS {
	case "":
		if !o.AllowInsecure {
			return Options{}, fmt.Errorf("MySQL 默认要求 TLS（tls=true 或自定义 CA 配置名）；" +
				"本地明文测试必须显式设置 AllowInsecure=true")
		}
	case "skip-verify", "preferred":
		// preferred 由驱动实现为“优先 TLS、失败可回退明文/不校验证书”，安全等级等同
		// skip-verify；与 ""/skip-verify 一样必须显式 AllowInsecure 且仅限本地测试。
		if !o.AllowInsecure {
			return Options{}, fmt.Errorf("%s 会使证书校验失效或回退明文，只允许在本地测试配合 AllowInsecure=true 使用", o.TLS)
		}
	case "true":
	default:
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(o.TLS) {
			return Options{}, fmt.Errorf("MySQL TLS 配置名不合法")
		}
	}
	return o, nil
}

// Store 是 MySQL 存储句柄。SQLStore() 返回可传给现有各模块 sqlite 仓储的共享
// 执行器（仓储代码不重写）；本类型额外提供迁移、方言与备份能力入口。
type Store struct {
	sqlStore *storagesqlite.Store
	// db 是带仓储 SQL 重写的连接池，只给业务仓储使用。
	db *sql.DB
	// rawDB 是未重写的连接池，只给迁移 DDL/服务器校验/迁移记录使用；迁移 DDL 含
	// JSON_VALID 等 MySQL 原生语法，不能经过 SQLite→MySQL 重写器（会被拒绝或误改）。
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

// Open 校验配置与服务器设置后建立连接池并返回 Store。
//
// 校验项（失败即拒绝使用，不降级）：
//   - 服务器为 MySQL（拒绝 MariaDB）且版本 ≥ MinServerVersion；
//   - character_set_connection 为 utf8mb4、连接排序规则为 utf8mb4；
//   - lower_case_table_names=0（表名大小写一致，避免跨平台身份/表名歧义）；
//   - time_zone 为 UTC、事务隔离为 REPEATABLE-READ、sql_mode 含严格模式。
//
// 真实连接与上述运行期校验在本步未运行实测；错误文本不含密码。
func Open(ctx context.Context, options Options) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := options.validate()
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "MySQL 配置不合法", err)
	}
	config := gomysql.NewConfig()
	config.Net = "tcp"
	config.Addr = net.JoinHostPort(normalized.Host, strconv.Itoa(normalized.Port))
	config.User = normalized.User
	config.Passwd = normalized.Password
	config.DBName = normalized.Database
	config.Timeout = normalized.ConnectTimeout
	config.ReadTimeout = normalized.ReadTimeout
	config.WriteTimeout = normalized.WriteTimeout
	config.ParseTime = false
	config.Loc = time.UTC
	// 关闭 CLIENT_FOUND_ROWS：仓储的 ON CONFLICT DO NOTHING 依赖“重复键影响 0 行”
	// 判断幂等/冲突；开启后 MySQL 会把未变更行也计为 1，破坏该语义。
	config.ClientFoundRows = false
	config.MultiStatements = false
	config.InterpolateParams = false
	config.CheckConnLiveness = true
	config.Collation = "utf8mb4_0900_as_cs"
	config.Params = map[string]string{
		"time_zone": "'+00:00'",
		"sql_mode":  "'" + strictSQLMode + "'",
	}
	if normalized.TLS != "" {
		config.TLSConfig = normalized.TLS
	}
	baseConnector, err := gomysql.NewConnector(config)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "MySQL 连接参数不合法", err)
	}
	rawConnector, err := gomysql.NewConnector(config)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "MySQL 连接参数不合法", err)
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

// verifyServerSettings 抽样验证服务器设置，拒绝“以为连上了 MySQL 却语义不同”的
// 假安全。它需要真实数据库连接，本步未运行实测。
func verifyServerSettings(ctx context.Context, db *sql.DB, options Options) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()

	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return mapError(err)
	}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return storage.New(storage.ErrUnavailable,
			"检测到 MariaDB；本适配只声明支持 MySQL 8.0.16+，排序规则与触发器语义不同，拒绝使用", nil)
	}
	major, minor, patch, ok := parseVersion(version)
	if !ok || major < 8 || (major == 8 && (minor < 0 || (minor == 0 && patch < 16))) {
		return storage.New(storage.ErrUnavailable,
			"MySQL 版本低于 8.0.16；CHECK 约束在旧版本不执行，拒绝使用", nil)
	}
	var charset, collation, timeZone, sqlMode, isolation string
	var lowerCaseTableNames int
	if err := conn.QueryRowContext(ctx,
		`SELECT @@character_set_connection, @@collation_connection, @@time_zone, @@sql_mode,
		        @@lower_case_table_names, @@transaction_isolation`).
		Scan(&charset, &collation, &timeZone, &sqlMode, &lowerCaseTableNames, &isolation); err != nil {
		return mapError(err)
	}
	if !strings.EqualFold(charset, "utf8mb4") || !strings.HasPrefix(strings.ToLower(collation), "utf8mb4") {
		return storage.New(storage.ErrUnavailable, "MySQL 连接字符集不是 utf8mb4，拒绝使用", nil)
	}
	if lowerCaseTableNames != 0 {
		return storage.New(storage.ErrUnavailable, "MySQL lower_case_table_names 必须为 0，拒绝在表名大小写不敏感配置下运行", nil)
	}
	if timeZone != "+00:00" && !strings.EqualFold(timeZone, "UTC") {
		return storage.New(storage.ErrUnavailable, "MySQL 会话时区必须为 UTC，拒绝使用", nil)
	}
	if !strings.EqualFold(isolation, "REPEATABLE-READ") {
		return storage.New(storage.ErrUnavailable, "MySQL 事务隔离级别必须为 REPEATABLE-READ，拒绝使用", nil)
	}
	if !strings.Contains(sqlMode, "STRICT_") {
		return storage.New(storage.ErrUnavailable, "MySQL sql_mode 未启用严格模式，拒绝使用", nil)
	}
	_ = options
	return nil
}

func parseVersion(version string) (int, int, int, bool) {
	match := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(version)
	if match == nil {
		return 0, 0, 0, false
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	return major, minor, patch, true
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

// MigrationLockName 返回迁移排他锁名（GET_LOCK 名称最长 64 字符）。
func (s *Store) MigrationLockName() string {
	name := migrationLockPrefix + s.options.Database
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// 编译期确认 *gomysql.MySQLError 被错误映射使用，防止依赖被移除后静默失去分类。
var _ = (*gomysql.MySQLError)(nil)
var _ driver.Connector = (*rewriteConnector)(nil)
