package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	migrationsmysql "github.com/kagurazakayashi/EvernightLogin/migrations/mysql"
)

const (
	// bookkeepingLockTimeout 限制失败记录写入等清理操作的墙钟时间。
	bookkeepingLockTimeout = 10 * time.Second
)

// Backend 是 migrate.Backend 的 MySQL 实现。
//
// 关键差异（相对 SQLite）：
//   - MySQL DDL 隐式提交：所有迁移按 non-transactional 逐条执行，失败不承诺回滚；
//     迁移失败记录写入独立的 schema_failures 表，再次运行会拒绝并要求人工核对后
//     ClearFailure。
//   - 排他锁使用 MySQL GET_LOCK（连接级），不依赖事务；DDL 隐式提交不会释放它。
//   - 迁移记录表用显式 InnoDB/utf8mb4/排序规则创建，并通过 information_schema
//     核对列集合，不能用 IF NOT EXISTS 掩盖已有表结构差异。
type Backend struct {
	db       *sql.DB
	lockName string
	lockTTL  time.Duration
	database string
	now      func() time.Time
}

// NewMigrationBackend 构造迁移后端。db 必须是已通过 Open/verify 的连接池。
func NewMigrationBackend(db *sql.DB, database, lockName string, lockTTL time.Duration) (*Backend, error) {
	if db == nil {
		return nil, storage.New(storage.ErrUnavailable, "MySQL 迁移后端缺少数据库连接", nil)
	}
	if strings.TrimSpace(lockName) == "" {
		return nil, storage.New(storage.ErrUnavailable, "MySQL 迁移锁名不能为空", nil)
	}
	if lockTTL <= 0 {
		lockTTL = DefaultLockTimeout
	}
	return &Backend{db: db, lockName: lockName, lockTTL: lockTTL, database: database, now: time.Now}, nil
}

// MigrationBackend 返回 Store 对应的迁移后端。
func (s *Store) MigrationBackend() migrate.Backend {
	backend, err := NewMigrationBackend(s.rawDB, s.options.Database, s.MigrationLockName(), s.options.MigrationLockTTL)
	if err != nil {
		// MigrationBackend 接口不返回错误；构造失败时返回一个始终报错的后端。
		return failingBackend{err: err}
	}
	return backend
}

// Migrate 加载翻译后的 MySQL 迁移并执行。调用方应只在维护/启动阶段调用。
func (s *Store) Migrate(ctx context.Context) (migrate.Result, error) {
	migrations, err := migrationsmysql.Load()
	if err != nil {
		return migrate.Result{}, err
	}
	runner, err := migrate.NewRunner(s.MigrationBackend(), migrations)
	if err != nil {
		return migrate.Result{}, err
	}
	return runner.Run(ctx)
}

// ClearMigrationFailure 删除指定版本的失败记录（人工核对完成后调用）。
func (s *Store) ClearMigrationFailure(ctx context.Context, version string) error {
	migrations, err := migrationsmysql.Load()
	if err != nil {
		return err
	}
	runner, err := migrate.NewRunner(s.MigrationBackend(), migrations)
	if err != nil {
		return err
	}
	return runner.ClearFailure(ctx, version)
}

type connContextKey struct{}

// connFromContext 取出 Lock 回调期间共享的独占连接。
func connFromContext(ctx context.Context) (*sql.Conn, error) {
	connection, ok := ctx.Value(connContextKey{}).(*sql.Conn)
	if !ok || connection == nil {
		return nil, storage.New(storage.ErrUnavailable, "迁移操作不在排他锁连接中", nil)
	}
	return connection, nil
}

// Lock 获取 GET_LOCK 排他锁后执行 fn，并在结束时释放。
//
// GET_LOCK 是连接级锁：DDL 的隐式提交不会释放它。回调期间的迁移记录读写与 DDL
// 都使用同一连接；ctx 取消时释放并返回错误。
func (b *Backend) Lock(ctx context.Context, fn func(ctx context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	connection, err := b.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer connection.Close()

	var acquired sql.NullInt64
	if err := connection.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", b.lockName, int(b.lockTTL/time.Second)).
		Scan(&acquired); err != nil {
		return mapError(err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return storage.New(storage.ErrBusy, "未取得 MySQL 迁移排他锁（其他实例正在迁移）", nil)
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeepingLockTimeout)
	defer cancel()
	defer func() {
		_, _ = connection.ExecContext(releaseCtx, "DO RELEASE_LOCK(?)", b.lockName)
	}()

	lockCtx := context.WithValue(ctx, connContextKey{}, connection)
	return fn(lockCtx)
}

// EnsureBookkeeping 幂等创建记录表，并用 information_schema 核对列集合。
func (b *Backend) EnsureBookkeeping(ctx context.Context) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	ddl := []string{
		"CREATE TABLE IF NOT EXISTS `schema_history` (" +
			"`version` VARCHAR(16) COLLATE utf8mb4_0900_bin NOT NULL," +
			"`description` VARCHAR(255) NOT NULL," +
			"`applied_at_ms` BIGINT NOT NULL," +
			"`source_sha256` CHAR(64) COLLATE utf8mb4_0900_bin NOT NULL," +
			"PRIMARY KEY (`version`)" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs",
		"CREATE TABLE IF NOT EXISTS `schema_failures` (" +
			"`version` VARCHAR(16) COLLATE utf8mb4_0900_bin NOT NULL," +
			"`description` VARCHAR(255) NOT NULL," +
			"`source_sha256` CHAR(64) COLLATE utf8mb4_0900_bin NOT NULL," +
			"`failed_at_ms` BIGINT NOT NULL," +
			"`error_summary` TEXT NOT NULL," +
			"PRIMARY KEY (`version`)" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs",
	}
	for _, statement := range ddl {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			return mapError(err)
		}
	}
	if err := b.verifyBookkeepingColumns(ctx, connection); err != nil {
		return err
	}
	return nil
}

// verifyBookkeepingColumns 检查记录表列集合与顺序，防止旧表结构被 IF NOT EXISTS
// 掩盖后在错误结构上继续迁移。
func (b *Backend) verifyBookkeepingColumns(ctx context.Context, connection *sql.Conn) error {
	expected := map[string][]string{
		"schema_history":  {"version", "description", "applied_at_ms", "source_sha256"},
		"schema_failures": {"version", "description", "source_sha256", "failed_at_ms", "error_summary"},
	}
	for table, columns := range expected {
		rows, err := connection.QueryContext(ctx,
			`SELECT COLUMN_NAME FROM information_schema.COLUMNS
			 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, table)
		if err != nil {
			return mapError(err)
		}
		var actual []string
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				rows.Close()
				return mapError(err)
			}
			actual = append(actual, column)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return mapError(err)
		}
		rows.Close()
		if strings.Join(actual, ",") != strings.Join(columns, ",") {
			return storage.New(storage.ErrCorrupt,
				fmt.Sprintf("迁移记录表 %s 的列结构不符合预期（期望 %v，实际 %v），拒绝在未知结构上迁移",
					table, columns, actual), nil)
		}
	}
	return nil
}

// LoadApplied 读取已应用迁移，按版本升序返回。
func (b *Backend) LoadApplied(ctx context.Context) ([]migrate.AppliedMigration, error) {
	connection, err := connFromContext(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := connection.QueryContext(ctx,
		"SELECT version, description, source_sha256, applied_at_ms FROM schema_history ORDER BY version")
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var applied []migrate.AppliedMigration
	for rows.Next() {
		var record migrate.AppliedMigration
		var appliedAtMS int64
		if err := rows.Scan(&record.Version, &record.Description, &record.Checksum, &appliedAtMS); err != nil {
			return nil, mapError(err)
		}
		record.AppliedAt = time.UnixMilli(appliedAtMS).UTC()
		applied = append(applied, record)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return applied, nil
}

// LoadFailed 读取迁移失败记录。
func (b *Backend) LoadFailed(ctx context.Context) ([]migrate.FailedMigration, error) {
	connection, err := connFromContext(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := connection.QueryContext(ctx,
		"SELECT version, description, source_sha256, failed_at_ms, error_summary FROM schema_failures ORDER BY version")
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var failed []migrate.FailedMigration
	for rows.Next() {
		var record migrate.FailedMigration
		var failedAtMS int64
		if err := rows.Scan(&record.Version, &record.Description, &record.Checksum, &failedAtMS, &record.ErrorSummary); err != nil {
			return nil, mapError(err)
		}
		record.FailedAt = time.UnixMilli(failedAtMS).UTC()
		failed = append(failed, record)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return failed, nil
}

// Apply 逐条执行一条迁移的语句后写入 schema_history。
//
// MySQL DDL 隐式提交，整条迁移不是原子操作；失败时已执行的语句不会回滚，由
// Runner 写入 schema_failures 并停止后续迁移，必须人工核对结构后才能 ClearFailure。
func (b *Backend) Apply(ctx context.Context, statements []string, record migrate.AppliedMigration) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			return mapError(err)
		}
	}
	if _, err := connection.ExecContext(ctx,
		"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES(?,?,?,?)",
		record.Version, record.Description, appliedAtMillis(record.AppliedAt, b.now), record.Checksum); err != nil {
		return mapError(err)
	}
	return nil
}

// RecordFailure 持久化失败记录（同版本覆盖）。
func (b *Backend) RecordFailure(ctx context.Context, record migrate.FailedMigration) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	if _, err := connection.ExecContext(ctx,
		`INSERT INTO schema_failures(version, description, source_sha256, failed_at_ms, error_summary)
		 VALUES(?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE description=VALUES(description), source_sha256=VALUES(source_sha256),
		   failed_at_ms=VALUES(failed_at_ms), error_summary=VALUES(error_summary)`,
		record.Version, record.Description, record.Checksum,
		appliedAtMillis(record.FailedAt, b.now), record.ErrorSummary); err != nil {
		return mapError(err)
	}
	return nil
}

// ClearFailure 删除指定版本的失败记录。
func (b *Backend) ClearFailure(ctx context.Context, version string) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	if _, err := connection.ExecContext(ctx, "DELETE FROM schema_failures WHERE version = ?", version); err != nil {
		return mapError(err)
	}
	return nil
}

func appliedAtMillis(value time.Time, now func() time.Time) int64 {
	if value.IsZero() {
		if now == nil {
			value = time.Now()
		} else {
			value = now()
		}
	}
	return value.UTC().UnixMilli()
}

// failingBackend 在迁移后端构造失败时把错误暴露给每次调用。
type failingBackend struct{ err error }

func (b failingBackend) Lock(ctx context.Context, fn func(context.Context) error) error {
	return b.err
}
func (b failingBackend) EnsureBookkeeping(context.Context) error { return b.err }
func (b failingBackend) LoadApplied(context.Context) ([]migrate.AppliedMigration, error) {
	return nil, b.err
}
func (b failingBackend) LoadFailed(context.Context) ([]migrate.FailedMigration, error) {
	return nil, b.err
}
func (b failingBackend) Apply(context.Context, []string, migrate.AppliedMigration) error {
	return b.err
}
func (b failingBackend) RecordFailure(context.Context, migrate.FailedMigration) error { return b.err }
func (b failingBackend) ClearFailure(context.Context, string) error                   { return b.err }

var (
	_ migrate.Backend = (*Backend)(nil)
	_ migrate.Backend = failingBackend{}
)
