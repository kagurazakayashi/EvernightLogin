package sqlserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	migrationssqlserver "github.com/kagurazakayashi/EvernightLogin/migrations/sqlserver"
)

const (
	// MinServerVersion 是声明支持的最低 SQL Server 主版本（15 = SQL Server 2019）。
	// SQL Server 2019 是当前仍有主流支持的基线；更早版本未验证。真实服务器校验
	// 未运行实测。
	MinServerVersion = 15
	// DefaultPort 是默认 SQL Server TCP 端口。
	DefaultPort = 1433
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
	// DefaultTLSMinVersion 是默认最低 TLS 版本；1.0/1.1 已废弃且始终拒绝。
	DefaultTLSMinVersion = "1.2"
	// migrationLockPrefix 是 applock 资源名的派生前缀，避免与其他应用碰撞。
	migrationLockPrefix = "EvernightLogin:migrate:"
	// migrationLockResourceMax 是 sp_getapplock 资源名上限（nvarchar(255)）。
	migrationLockResourceMax = 255
)

// sessionInitSQL 在每个新连接（及会话重置后）执行，固定 CREATE INDEX/计算列所需的
// SET 选项，并关闭隐式事务与 XACT_ABORT（保持与 SQLite 一致的语句级错误语义）。
// 不设置 NOCOUNT ON：既有仓储依赖 RowsAffected 判断条件更新/幂等写入是否生效。
const sessionInitSQL = `SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_WARNINGS ON; ` +
	`SET ANSI_PADDING ON; SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; ` +
	`SET NUMERIC_ROUNDABORT OFF; SET XACT_ABORT OFF; SET IMPLICIT_TRANSACTIONS OFF;`

// Options 是打开 SQL Server 存储的配置。密码只用于建立连接，不写入错误文本、日志
// 或诊断输出。
type Options struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	// AllowInsecure 显式允许弱化传输安全；只有同时设置 TrustServerCertificate 或
	// DisableEncryption 才会真正生效，且仅限本地测试，生产禁止。
	AllowInsecure bool
	// TrustServerCertificate 为 true 时仍加密但跳过证书链/主机名校验；必须同时设置
	// AllowInsecure=true。默认 false（完整校验）。
	TrustServerCertificate bool
	// DisableEncryption 为 true 时使用 encrypt=false（登录包之外不加密）；必须同时
	// 设置 AllowInsecure=true，仅限本地测试。默认 false（强制加密）。
	DisableEncryption bool
	// TLSMinVersion 是最低 TLS 版本，默认 1.2；只接受 1.2/1.3。
	TLSMinVersion string
	// CACertificate 是可选的服务器 CA 证书文件路径（PEM/DER），用于链式校验。
	CACertificate string
	// ServerCertificate 是可选的服务器证书文件路径，做字节比较校验（不做链式/
	// 主机名校验）；与 CACertificate 互斥。
	ServerCertificate string
	ConnectTimeout    time.Duration
	MaxOpenConns      int
	MaxIdleConns      int
	ConnMaxIdleTime   time.Duration
	Retry             storage.RetryPolicy
	WriteGuard        func(ctx context.Context) (func(), error)
	MigrationLockTTL  time.Duration
	ApplicationName   string
}

// DefaultOptions 返回给定数据库的默认配置。
func DefaultOptions(host, user, database string) Options {
	return Options{
		Host:             host,
		Port:             DefaultPort,
		User:             user,
		Database:         database,
		TLSMinVersion:    DefaultTLSMinVersion,
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
		return Options{}, fmt.Errorf("SQL Server 主机不能为空")
	}
	if net.ParseIP(o.Host) == nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(o.Host) {
		return Options{}, fmt.Errorf("SQL Server 主机名不合法")
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.Port < 1 || o.Port > 65535 {
		return Options{}, fmt.Errorf("SQL Server 端口必须在 1～65535 之间")
	}
	if strings.TrimSpace(o.User) == "" {
		return Options{}, fmt.Errorf("SQL Server 用户名不能为空")
	}
	if strings.TrimSpace(o.Database) == "" {
		return Options{}, fmt.Errorf("SQL Server 数据库名不能为空")
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.ConnectTimeout < 0 || o.ConnectTimeout > time.Minute {
		return Options{}, fmt.Errorf("SQL Server 连接超时必须在 0～60 秒之间")
	}
	if o.MaxOpenConns == 0 {
		o.MaxOpenConns = DefaultMaxOpenConns
	}
	if o.MaxOpenConns < 1 || o.MaxOpenConns > MaxAllowedOpenConns {
		return Options{}, fmt.Errorf("SQL Server 连接池上限必须在 1～%d 之间", MaxAllowedOpenConns)
	}
	if o.MaxIdleConns == 0 {
		o.MaxIdleConns = o.MaxOpenConns
	}
	if o.MaxIdleConns < 0 || o.MaxIdleConns > o.MaxOpenConns {
		return Options{}, fmt.Errorf("SQL Server 空闲连接上限不能超过连接池上限")
	}
	if o.ConnMaxIdleTime == 0 {
		o.ConnMaxIdleTime = 5 * time.Minute
	}
	if o.ConnMaxIdleTime < 0 {
		return Options{}, fmt.Errorf("SQL Server 空闲连接回收时间不能为负数")
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
		return Options{}, fmt.Errorf("SQL Server 迁移锁等待必须在 0～300 秒之间")
	}
	if strings.TrimSpace(o.ApplicationName) == "" {
		o.ApplicationName = DefaultApplicationName
	}
	if o.TLSMinVersion == "" {
		o.TLSMinVersion = DefaultTLSMinVersion
	}
	if o.TLSMinVersion != "1.2" && o.TLSMinVersion != "1.3" {
		return Options{}, fmt.Errorf("SQL Server 最低 TLS 版本只支持 1.2/1.3（1.0/1.1 已废弃且禁止）")
	}
	weakened := o.TrustServerCertificate || o.DisableEncryption
	if weakened && !o.AllowInsecure {
		return Options{}, fmt.Errorf("SQL Server 弱化传输安全（信任/关闭服务器证书校验或禁用加密）必须显式设置 AllowInsecure=true 且仅用于本地测试")
	}
	if o.DisableEncryption && o.TrustServerCertificate {
		return Options{}, fmt.Errorf("SQL Server 不能同时禁用加密与信任服务器证书")
	}
	if o.DisableEncryption && (o.CACertificate != "" || o.ServerCertificate != "") {
		return Options{}, fmt.Errorf("SQL Server 禁用加密时不能配置证书")
	}
	if o.CACertificate != "" && o.ServerCertificate != "" {
		return Options{}, fmt.Errorf("SQL Server 只能配置 CA 证书或固定服务器证书之一")
	}
	return o, nil
}

// Store 是 SQL Server 存储句柄。SQLStore() 返回可传给现有各模块 sqlite 仓储的共享
// 执行器（仓储代码不重写）；本类型额外提供迁移、方言与备份能力入口。
type Store struct {
	sqlStore *storagesqlite.Store
	// db 是带仓储 SQL 重写的连接池，只给业务仓储使用。
	db *sql.DB
	// rawDB 是未重写的连接池，只给迁移 DDL/服务器校验/迁移记录使用：迁移 DDL 含
	// T-SQL 原生语法（NVARCHAR/COLLATE/HASHBYTES 计算列/触发器/sp_rename），不能
	// 经过 SQLite->T-SQL 重写器。
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

// MigrationLockName 返回 sp_getapplock 使用的排他锁资源名。
//
// 资源名由固定前缀、数据库名与数据库名 SHA-256 前 16 位组成，同一数据库的所有实例
// 得到同一把锁，不同数据库不会碰撞；总长度远低于 nvarchar(255) 上限。
func (s *Store) MigrationLockName() string {
	sum := sha256.Sum256([]byte(migrationLockPrefix + s.options.Database))
	name := migrationLockPrefix + s.options.Database + ":" + hex.EncodeToString(sum[:8])
	if len(name) > migrationLockResourceMax {
		name = name[:migrationLockResourceMax]
	}
	return name
}

// Open 校验配置与服务器设置后建立连接池并返回 Store。
//
// 校验项（失败即拒绝使用，不降级）：
//   - 服务器为 Microsoft SQL Server 主产品且主版本 ≥ MinServerVersion；
//   - 引擎版本允许（拒绝 Azure Synapse 等 T-SQL 语义不同的引擎）；
//   - 数据库在线且可读写、连接到的数据库名与配置一致；
//   - 会话 SET 选项满足索引计算列/触发器要求（ANSI_NULLS 等）、隐式事务关闭；
//   - 显式二进制排序规则 Latin1_General_100_BIN2 在服务器可用。
//
// 传输安全默认强制加密（encrypt=true）并校验证书链与主机名（TLS≥1.2）；只有显式
// AllowInsecure + TrustServerCertificate/DisableEncryption 才允许弱化，且文档要求
// 仅本地测试。真实连接与上述运行期校验在本步未运行实测；错误文本不含密码。
func Open(ctx context.Context, options Options) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := options.validate()
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "SQL Server 配置不合法", err)
	}
	config, err := buildMSSQLConfig(normalized)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "SQL Server 连接参数不合法", err)
	}
	baseConnector := mssql.NewConnectorConfig(config)
	baseConnector.SessionInitSQL = sessionInitSQL
	rawDB := sql.OpenDB(baseConnector)
	rawDB.SetMaxOpenConns(4)
	rawDB.SetMaxIdleConns(2)
	rawDB.SetConnMaxIdleTime(normalized.ConnMaxIdleTime)

	// 两条连接池方向明确：仓储语句走重写池；迁移/校验走原始池（DDL 不过重写器）。
	db := sql.OpenDB(newRewriteConnector(baseConnector, migrationssqlserver.PrimaryKeyColumns))
	db.SetMaxOpenConns(normalized.MaxOpenConns)
	db.SetMaxIdleConns(normalized.MaxIdleConns)
	db.SetConnMaxIdleTime(normalized.ConnMaxIdleTime)

	if err := verifyServerSettings(ctx, rawDB, normalized); err != nil {
		_ = db.Close()
		_ = rawDB.Close()
		return nil, err
	}
	// Serializable 与 SQLite 的单写者串行语义最接近；并发冲突由 1205/1222 映射为
	// ErrBusy 交给有界重试，不静默丢更新。
	sqlStore, err := storagesqlite.WrapHostDB(db, storagesqlite.Options{
		WriteGuard: normalized.WriteGuard,
		Retry:      normalized.Retry,
	}, &sql.TxOptions{Isolation: sql.LevelSerializable}, mapError)
	if err != nil {
		_ = db.Close()
		_ = rawDB.Close()
		return nil, err
	}
	return &Store{sqlStore: sqlStore, db: db, rawDB: rawDB, options: normalized}, nil
}

// buildMSSQLConfig 把 Options 转换为 go-mssqldb 配置。密码只放在
// Config.Password，不拼接到 DSN 字符串，错误文本因此不会包含凭据。
func buildMSSQLConfig(options Options) (msdsn.Config, error) {
	values := url.Values{}
	values.Set(msdsn.Database, options.Database)
	values.Set(msdsn.TLSMin, options.TLSMinVersion)
	values.Set(msdsn.AppName, options.ApplicationName)
	values.Set(msdsn.DialTimeout, strconv.Itoa(int(options.ConnectTimeout/time.Second)))
	encrypt := "true"
	if options.DisableEncryption {
		encrypt = "false"
	}
	values.Set(msdsn.Encrypt, encrypt)
	values.Set(msdsn.TrustServerCertificate, strconv.FormatBool(options.TrustServerCertificate))
	if options.CACertificate != "" {
		values.Set(msdsn.Certificate, options.CACertificate)
	}
	if options.ServerCertificate != "" {
		values.Set(msdsn.ServerCertificate, options.ServerCertificate)
	}
	config, err := msdsn.Parse(buildMSSQLDSN(options, values))
	if err != nil {
		// 不包装驱动原始错误文本：其中可能含连接串片段。
		return msdsn.Config{}, errors.New("无法构造 SQL Server 连接配置")
	}
	config.Password = options.Password
	// 默认完整校验：encrypt 必须为 Required（或 Strict），证书链/主机名校验未关闭。
	if !options.DisableEncryption {
		if config.Encryption != msdsn.EncryptionRequired {
			return msdsn.Config{}, errors.New("SQL Server 加密连接未按要求启用")
		}
		if config.TrustServerCertificate && !options.TrustServerCertificate {
			return msdsn.Config{}, errors.New("SQL Server 服务器证书校验被意外关闭")
		}
	}
	return config, nil
}

// buildMSSQLDSN 构造不含密码的连接 URL：密码只通过 msdsn.Config.Password 传递，
// 因此错误/日志即使包含连接串也不会泄露凭据。
func buildMSSQLDSN(options Options, values url.Values) string {
	host := net.JoinHostPort(options.Host, strconv.Itoa(options.Port))
	dsn := url.URL{Scheme: "sqlserver", Host: host, User: url.User(options.User), RawQuery: values.Encode()}
	return dsn.String()
}

// verifyServerSettings 抽样验证服务器设置，拒绝“以为连上了 SQL Server 却语义不同”
// 的假安全。它需要真实数据库连接，本步未运行实测。
func verifyServerSettings(ctx context.Context, db *sql.DB, options Options) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()

	var versionText string
	if err := conn.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&versionText); err != nil {
		return mapError(err)
	}
	if !strings.Contains(versionText, "Microsoft SQL Server") {
		return storage.New(storage.ErrUnavailable,
			"连接的服务器不是 Microsoft SQL Server，拒绝使用", nil)
	}
	if strings.Contains(strings.ToLower(versionText), "synapse") {
		return storage.New(storage.ErrUnavailable,
			"检测到 Azure Synapse 分析引擎（T-SQL 语义不同），拒绝使用", nil)
	}
	var major sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		"SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)").Scan(&major); err != nil {
		return mapError(err)
	}
	if !major.Valid || major.Int64 < MinServerVersion {
		return storage.New(storage.ErrUnavailable,
			fmt.Sprintf("SQL Server 版本低于 %d（SQL Server 2019），拒绝使用", MinServerVersion), nil)
	}
	// 6 = Azure Synapse Analytics（T-SQL 方言不同）；其余常见引擎（Standard/Enterprise/
	// Express/Azure SQL Database/Managed Instance/Edge/Fabric SQL）接受。
	var engineEdition sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		"SELECT CAST(SERVERPROPERTY('EngineEdition') AS INT)").Scan(&engineEdition); err != nil {
		return mapError(err)
	}
	if !engineEdition.Valid || engineEdition.Int64 == 6 {
		return storage.New(storage.ErrUnavailable,
			"SQL Server 引擎类型不受支持（分析类引擎 T-SQL 语义不同），拒绝使用", nil)
	}
	var databaseName string
	if err := conn.QueryRowContext(ctx, "SELECT DB_NAME()").Scan(&databaseName); err != nil {
		return mapError(err)
	}
	if !strings.EqualFold(databaseName, options.Database) {
		return storage.New(storage.ErrUnavailable,
			"连接的 SQL Server 数据库与配置不一致，拒绝使用", nil)
	}
	var status, updateability string
	if err := conn.QueryRowContext(ctx,
		"SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'Status') AS NVARCHAR(60))").Scan(&status); err != nil {
		return mapError(err)
	}
	if !strings.EqualFold(status, "ONLINE") {
		return storage.New(storage.ErrUnavailable, "SQL Server 数据库不在线，拒绝使用", nil)
	}
	if err := conn.QueryRowContext(ctx,
		"SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS NVARCHAR(60))").Scan(&updateability); err != nil {
		return mapError(err)
	}
	if !strings.EqualFold(updateability, "READ_WRITE") {
		return storage.New(storage.ErrUnavailable, "SQL Server 数据库为只读，拒绝使用", nil)
	}
	// 显式二进制排序规则必须在本服务器可用；否则迁移 DDL 的 COLLATE 会在运行期失败。
	var codePage sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		"SELECT CAST(COLLATIONPROPERTY('Latin1_General_100_BIN2', 'CodePage') AS INT)").Scan(&codePage); err != nil {
		return mapError(err)
	}
	if !codePage.Valid || codePage.Int64 <= 0 {
		return storage.New(storage.ErrUnavailable,
			"SQL Server 缺少 Latin1_General_100_BIN2 二进制排序规则，拒绝使用", nil)
	}
	// 索引计算列/触发器要求固定的会话 SET 选项；SessionInitSQL 未生效时 fail-closed。
	settings := []struct {
		name     string
		property string
		expected int64
		message  string
	}{
		{"ANSI_NULLS", "ANSI_NULLS", 1, "SQL Server 会话 ANSI_NULLS 必须为 ON，拒绝使用"},
		{"QUOTED_IDENTIFIER", "QUOTED_IDENTIFIER", 1, "SQL Server 会话 QUOTED_IDENTIFIER 必须为 ON，拒绝使用"},
		{"ANSI_WARNINGS", "ANSI_WARNINGS", 1, "SQL Server 会话 ANSI_WARNINGS 必须为 ON，拒绝使用"},
		{"ANSI_PADDING", "ANSI_PADDING", 1, "SQL Server 会话 ANSI_PADDING 必须为 ON，拒绝使用"},
		{"ARITHABORT", "ARITHABORT", 1, "SQL Server 会话 ARITHABORT 必须为 ON，拒绝使用"},
		{"CONCAT_NULL_YIELDS_NULL", "CONCAT_NULL_YIELDS_NULL", 1, "SQL Server 会话 CONCAT_NULL_YIELDS_NULL 必须为 ON，拒绝使用"},
		{"NUMERIC_ROUNDABORT", "NUMERIC_ROUNDABORT", 0, "SQL Server 会话 NUMERIC_ROUNDABORT 必须为 OFF，拒绝使用"},
	}
	for _, setting := range settings {
		var value sql.NullInt64
		query := "SELECT CAST(SESSIONPROPERTY('" + setting.property + "') AS INT)"
		if err := conn.QueryRowContext(ctx, query).Scan(&value); err != nil {
			return mapError(err)
		}
		if !value.Valid || value.Int64 != setting.expected {
			return storage.New(storage.ErrUnavailable, setting.message, nil)
		}
	}
	return nil
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
