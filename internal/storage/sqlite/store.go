// Package sqlite 提供基于 modernc.org/sqlite 的本地 SQLite 存储实现。
//
// 本包负责数据库打开/关闭、连接池与小范围配置、每连接外键、忙等待、WAL、
// 事务提交/回滚、上下文取消、并发冲突的可识别错误与有界重试，并实现
// internal/storage/migrate.Backend 以执行版本化迁移。
//
// 本步不实现用户管理 API、备份流程、审计或跨数据库方言；宿主传入的连接由宿主
// 拥有，本包不会关闭它。所有测试使用临时目录数据库，不读取或修改
// database/login.db 设计基线。
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	modernsqlite "modernc.org/sqlite"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

const (
	// DefaultBusyTimeout 是默认 SQLite 锁等待时间。
	DefaultBusyTimeout = 5 * time.Second
	// DefaultMaxOpenConns 是默认连接池上限；SQLite 是本地文件库，不盲目放大。
	DefaultMaxOpenConns = 4
	// MaxAllowedOpenConns 是本实现允许的连接池上限，防止误配置把本地库压垮。
	MaxAllowedOpenConns = 16
	// DefaultConnMaxIdleTime 是空闲连接回收时间。
	DefaultConnMaxIdleTime = 5 * time.Minute
)

// Options 是打开或包装 SQLite 存储的配置。
type Options struct {
	// Path 是 SQLite 数据库文件路径；不得包含 '?' 或 '#'（DSN 分隔符）。
	Path string
	// WAL 表示启用 WAL 预写日志（并对该连接设置 synchronous=NORMAL）。
	WAL bool
	// BusyTimeout 是锁等待时间；0 使用默认值。
	BusyTimeout time.Duration
	// MaxOpenConns 是连接池上限；0 使用默认值，最大 MaxAllowedOpenConns。
	MaxOpenConns int
	// MaxIdleConns 是空闲连接上限；0 使用 MaxOpenConns。
	MaxIdleConns int
	// ConnMaxIdleTime 是空闲连接回收时间；0 使用默认值。
	ConnMaxIdleTime time.Duration
	// Retry 是打开事务时的有界重试策略；零值使用 DefaultRetryPolicy。
	Retry storage.RetryPolicy
	// WriteGuard 可选的维护写入门闸：每次通过 Store 开始写事务或执行写语句前调用，
	// 返回的释放函数在写入结束后调用。它用于维护模式下阻止新写入（步骤 82 恢复流程：
	// 接 internal/maintenance.Gate.Guard）。返回错误时写入被拒绝并原样返回给调用方
	// （维护状态错误应映射 RESTORE_MAINTENANCE_REQUIRED，而不是 DB_UNAVAILABLE）。
	// nil 表示不检查；宿主未接线时必须在维护期间自行停止服务。
	WriteGuard func(ctx context.Context) (func(), error)
}

// DefaultOptions 返回给定路径的默认 SQLite 配置。
func DefaultOptions(path string) Options {
	return Options{
		Path:            path,
		WAL:             true,
		BusyTimeout:     DefaultBusyTimeout,
		MaxOpenConns:    DefaultMaxOpenConns,
		MaxIdleConns:    DefaultMaxOpenConns,
		ConnMaxIdleTime: DefaultConnMaxIdleTime,
		Retry:           storage.DefaultRetryPolicy(),
	}
}

// normalize 校验并补全配置。requirePath 为 false 时允许宿主连接场景的空路径。
func (o Options) normalize(requirePath bool) (Options, error) {
	if requirePath && strings.TrimSpace(o.Path) == "" {
		return Options{}, fmt.Errorf("SQLite 数据库路径不能为空")
	}
	if strings.ContainsAny(o.Path, "?#") {
		return Options{}, fmt.Errorf("SQLite 数据库路径不能包含 '?' 或 '#'")
	}
	if o.BusyTimeout == 0 {
		o.BusyTimeout = DefaultBusyTimeout
	}
	if o.BusyTimeout < 0 || o.BusyTimeout > time.Minute {
		return Options{}, fmt.Errorf("SQLite 锁等待必须在 0～60 秒之间")
	}
	if o.MaxOpenConns == 0 {
		o.MaxOpenConns = DefaultMaxOpenConns
	}
	if o.MaxOpenConns < 1 || o.MaxOpenConns > MaxAllowedOpenConns {
		return Options{}, fmt.Errorf("SQLite 连接池上限必须在 1～%d 之间", MaxAllowedOpenConns)
	}
	if o.MaxIdleConns == 0 {
		o.MaxIdleConns = o.MaxOpenConns
	}
	if o.MaxIdleConns < 0 || o.MaxIdleConns > o.MaxOpenConns {
		return Options{}, fmt.Errorf("SQLite 空闲连接上限不能超过连接池上限")
	}
	if o.ConnMaxIdleTime == 0 {
		o.ConnMaxIdleTime = DefaultConnMaxIdleTime
	}
	if o.ConnMaxIdleTime < 0 {
		return Options{}, fmt.Errorf("SQLite 空闲连接回收时间不能为负数")
	}
	if o.Retry.MaxAttempts == 0 {
		o.Retry = storage.DefaultRetryPolicy()
	}
	if err := o.Retry.Validate(); err != nil {
		return Options{}, err
	}
	return o, nil
}

// Store 是 SQLite 存储句柄。它不实现业务仓储；仓储按步骤在调用方定义。
//
// 所有权：由 Open 创建的连接由本包 Close；由 WrapDB 包装的宿主连接不由本包
// 关闭。Store 的方法在 Close 后返回 ErrClosed。
type Store struct {
	db      *sql.DB
	ownsDB  bool
	options Options
	closed  atomic.Bool
}

// Open 创建或打开 SQLite 数据库文件并验证关键 PRAGMA。
//
// DSN 对每个连接启用 foreign_keys、busy_timeout 与 _txlock=immediate；WAL 时
// 设置 journal_mode=WAL 与 synchronous=NORMAL。BeginTx 因此从开始就取得写锁，
// 避免 SQLite 读事务升级写锁时的不可重试 BUSY。父目录不存在、文件不可打开、
// 权限或磁盘错误会返回安全 storage.Error，不暴露路径或 SQL。
func Open(ctx context.Context, options Options) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := options.normalize(true)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "SQLite 配置不合法", err)
	}

	db, err := sql.Open("sqlite", normalized.dsn())
	if err != nil {
		return nil, mapError(err)
	}
	db.SetMaxOpenConns(normalized.MaxOpenConns)
	db.SetMaxIdleConns(normalized.MaxIdleConns)
	db.SetConnMaxIdleTime(normalized.ConnMaxIdleTime)

	store := &Store{db: db, ownsDB: true, options: normalized}
	if err := store.verify(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// dsn 构造 modernc.org/sqlite 的 DSN 参数。
func (o Options) dsn() string {
	values := url.Values{}
	values.Set("_foreign_keys", "1")
	values.Set("_busy_timeout", strconv.FormatInt(o.BusyTimeout.Milliseconds(), 10))
	// 所有 BeginTx 使用 IMMEDIATE：写事务在开始时就取得写锁，避免读事务升级
	// 为写事务时的 SQLITE_BUSY_SNAPSHOT；读查询不走事务，不受影响。
	values.Set("_txlock", "immediate")
	if o.WAL {
		values.Set("_journal_mode", "WAL")
		values.Set("_synchronous", "NORMAL")
	}
	return o.Path + "?" + values.Encode()
}

// WrapDB 包装宿主提供的 *sql.DB。宿主连接由宿主拥有，Store.Close 不会关闭它；
// 宿主必须自行配置连接池，并保证每个连接已启用 foreign_keys（WrapDB 会抽样验证
// 当前连接的 foreign_keys 与 busy_timeout 不覆盖宿主设置）。本包不修改宿主
// 连接池与 PRAGMA。
func WrapDB(host *sql.DB, options Options) (*Store, error) {
	if host == nil {
		return nil, storage.New(storage.ErrUnavailable, "宿主数据库连接为空", nil)
	}
	normalized, err := options.normalize(false)
	if err != nil {
		return nil, storage.New(storage.ErrUnavailable, "SQLite 配置不合法", err)
	}
	store := &Store{db: host, ownsDB: false, options: normalized}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.verify(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// verify 抽样验证连接 PRAGMA，避免“以为启用了外键/忙等待”的假安全。
func (s *Store) verify(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()

	var foreignKeys int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return mapError(err)
	}
	if foreignKeys != 1 {
		return storage.New(storage.ErrUnavailable, "数据库连接未启用外键，拒绝使用", nil)
	}
	var busyTimeout int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return mapError(err)
	}
	if s.ownsDB && time.Duration(busyTimeout)*time.Millisecond != s.options.BusyTimeout {
		return storage.New(storage.ErrUnavailable, "数据库连接锁等待配置未生效", nil)
	}
	if s.ownsDB && s.options.WAL {
		var journalMode string
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			return mapError(err)
		}
		if !strings.EqualFold(journalMode, "wal") {
			return storage.New(storage.ErrUnavailable, "数据库未能启用 WAL，拒绝在不一致配置下运行", nil)
		}
	}
	return nil
}

// DB 返回底层 *sql.DB，供同一模块的维护/迁移代码使用。宿主连接仍由宿主关闭；
// Close 后该句柄不可再用。
func (s *Store) DB() *sql.DB {
	return s.db
}

// Ping 检查数据库仍可用。
func (s *Store) Ping(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := s.db.PingContext(ctx); err != nil {
		return mapError(err)
	}
	return nil
}

// Close 关闭 Store。自建连接会关闭底层 *sql.DB；宿主连接不会被关闭。Close 可
// 安全重复调用。
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.ownsDB && s.db != nil {
		if err := s.db.Close(); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// ensureOpen 在 Store 关闭后拒绝继续使用。
func (s *Store) ensureOpen() error {
	if s == nil || s.db == nil {
		return storage.New(storage.ErrClosed, "存储已关闭", nil)
	}
	if s.closed.Load() {
		return storage.New(storage.ErrClosed, "存储已关闭", nil)
	}
	return nil
}

// Transaction 在事务中执行 fn。成功提交，fn 返回错误、panic 或提交失败时回滚。
// 由于 DSN 设置 _txlock=immediate，该事务从开始即取得写锁，适合写操作；只读查询
// 应直接使用 DB/WithConn，避免不必要地阻塞其他写事务。
//
// 配置了 WriteGuard 时，开始事务前先通过门闸登记写入；维护状态激活时直接拒绝
// （门闸错误原样返回，调用方按 RESTORE_MAINTENANCE_REQUIRED 处理）。
func (s *Store) Transaction(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	release, err := s.enterWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.beginTxWithRetry(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback() // 提交成功后返回 sql.ErrTxDone，可忽略。
	}()
	if err := fn(ctx, tx); err != nil {
		return mapDriverError(err)
	}
	if err := tx.Commit(); err != nil {
		return mapError(err)
	}
	return nil
}

// AcquireWriteGuard 为必须使用原生 DB()/BeginTx 的既有写路径显式登记维护写入门闸，
// 返回幂等释放函数。新代码应优先使用 Transaction/ExecContext；该入口用于收敛历史
// raw 写路径，维护状态激活时返回 maintenance.ErrMaintenanceActive 同类错误。
func (s *Store) AcquireWriteGuard(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	return s.enterWrite(ctx)
}

// enterWrite 在配置了维护写入门闸时登记一次写入，返回幂等释放函数。未配置时返回
// 空实现；门闸错误原样返回（不能伪装成 DB_UNAVAILABLE）。
func (s *Store) enterWrite(ctx context.Context) (func(), error) {
	if s == nil || s.options.WriteGuard == nil {
		return func() {}, nil
	}
	return s.options.WriteGuard(ctx)
}

// mapDriverError 只映射驱动原始错误，保留业务/存储哨兵错误不变。
func mapDriverError(err error) error {
	if err == nil {
		return nil
	}
	var driverError *modernsqlite.Error
	if errors.As(err, &driverError) {
		return mapError(err)
	}
	return err
}

// beginTxWithRetry 只对 BeginTx 的忙/锁错误做有界重试；事务体本身不自动重试，
// 由调用方决定业务重试。
func (s *Store) beginTxWithRetry(ctx context.Context) (*sql.Tx, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	var tx *sql.Tx
	err := storage.Retry(ctx, s.options.Retry, storage.Retryable, func(attemptCtx context.Context) error {
		begun, err := s.db.BeginTx(attemptCtx, nil)
		if err != nil {
			return mapError(err)
		}
		tx = begun
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// WithConn 从连接池取一条连接执行 fn，用于内部维护/备份等扩展（例如后续步骤
// 通过 sql.Conn.Raw 访问驱动备份接口）。本步不实现备份流程；调用方不得长期
// 占用连接，fn 返回后连接自动归还。
func (s *Store) WithConn(ctx context.Context, fn func(context.Context, *sql.Conn) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()
	return fn(ctx, conn)
}

// ExecContext 执行写语句，并把驱动错误映射为安全 storage.Error。仓储代码应优先
// 使用本方法而不是直接使用 DB()，以统一唯一性、锁、权限等错误类别。配置了
// WriteGuard 时先通过门闸登记写入（维护状态拒绝新写）。
func (s *Store) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	release, err := s.enterWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, mapError(err)
	}
	return result, nil
}

// QueryContext 执行查询并把驱动错误映射为安全 storage.Error；行迭代后的
// rows.Err() 仍是驱动错误，调用方需要时可再用 storage 类别判断或记录。
func (s *Store) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapError(err)
	}
	return rows, nil
}

// MigrationBackend 返回供 internal/storage/migrate 使用的 SQLite 后端。
func (s *Store) MigrationBackend() migrate.Backend {
	return &sqliteBackend{store: s}
}

// MigrationRunner 构造迁移执行器；调用方负责 Run/ClearFailure。
func (s *Store) MigrationRunner(migrations []migrate.Migration) (*migrate.Runner, error) {
	return migrate.NewRunner(s.MigrationBackend(), migrations)
}

// Migrate 在排他迁移锁内按版本执行迁移。SQLite DDL 在事务中执行，失败回滚当前
// 迁移；已成功迁移与失败记录在结束前提交。
func (s *Store) Migrate(ctx context.Context, migrations []migrate.Migration) (migrate.Result, error) {
	runner, err := s.MigrationRunner(migrations)
	if err != nil {
		return migrate.Result{}, err
	}
	return runner.Run(ctx)
}
