package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	migrationspostgres "github.com/kagurazakayashi/EvernightLogin/migrations/postgres"
)

const (
	// bookkeepingLockTimeout 限制失败记录写入等清理操作的墙钟时间。
	bookkeepingLockTimeout = 10 * time.Second
)

// Backend 是 migrate.Backend 的 PostgreSQL 实现。
//
// 关键差异（相对 SQLite / MySQL）：
//   - PostgreSQL 支持事务内 DDL：每条迁移的语句与 schema_history 记录放在同一事务，
//     失败整体回滚（不会留下半完成结构）；DDL 与记录仍使用原始连接池，不经过仓储
//     SQL 重写器。
//   - 排他锁使用会话级 pg_advisory_lock(bigint)（阻塞等待），通过专用连接持有；
//     等待上限由 MigrationLockTTL 换算的 statement_timeout 限定，超时（57014）
//     映射为 ErrBusy，不静默继续。
//   - 迁移记录表结构与列类型通过 information_schema + pg_catalog 核对，不能用
//     IF NOT EXISTS 掩盖已有表结构差异。
//
// 限制：CREATE INDEX CONCURRENTLY / VACUUM 等不能在事务中执行的语句会使迁移失败
// （fail-closed）；当前 44 条迁移不含此类语句，未来新增需要先改后端再执行。
type Backend struct {
	db       *sql.DB
	lockKey  int64
	lockName string
	lockTTL  time.Duration
	now      func() time.Time
}

// NewMigrationBackend 构造迁移后端。db 必须是未重写的原始连接池（Store.rawDB）。
func NewMigrationBackend(db *sql.DB, lockKey int64, lockName string, lockTTL time.Duration) (*Backend, error) {
	if db == nil {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 迁移后端缺少数据库连接", nil)
	}
	if strings.TrimSpace(lockName) == "" {
		return nil, storage.New(storage.ErrUnavailable, "PostgreSQL 迁移锁名不能为空", nil)
	}
	if lockTTL <= 0 {
		lockTTL = DefaultLockTimeout
	}
	return &Backend{db: db, lockKey: lockKey, lockName: lockName, lockTTL: lockTTL, now: time.Now}, nil
}

// MigrationBackend 返回 Store 对应的迁移后端。
func (s *Store) MigrationBackend() migrate.Backend {
	backend, err := NewMigrationBackend(s.rawDB, s.MigrationLockKey(), s.MigrationLockName(), s.options.MigrationLockTTL)
	if err != nil {
		// MigrationBackend 接口不返回错误；构造失败时返回一个始终报错的后端。
		return failingBackend{err: err}
	}
	return backend
}

// Migrate 加载翻译后的 PostgreSQL 迁移并执行。调用方应只在维护/启动阶段调用。
func (s *Store) Migrate(ctx context.Context) (migrate.Result, error) {
	migrations, err := migrationspostgres.Load()
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
	migrations, err := migrationspostgres.Load()
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

// Lock 获取 pg_advisory_lock 排他锁后执行 fn，并在结束时释放。
//
// advisory lock 是会话级锁：DDL 事务提交不会释放它；回调期间的迁移记录读写与 DDL
// 都使用同一连接。加锁为阻塞等待，等待上限由 lockTTL 换算的 statement_timeout 限制，
// 超时/取消返回 ErrBusy（fail-closed，不静默继续）。
func (b *Backend) Lock(ctx context.Context, fn func(ctx context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	connection, err := b.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer connection.Close()

	timeoutMS := int(b.lockTTL / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = int(DefaultLockTimeout / time.Millisecond)
	}
	// SET 不接收参数占位符；timeoutMS 是内部整数，不含外部输入。
	if _, err := connection.ExecContext(ctx, fmt.Sprintf("SET statement_timeout = %d", timeoutMS)); err != nil {
		return mapError(err)
	}
	// pg_advisory_lock 返回 void；用 ExecContext 执行，阻塞直到取得锁或 statement_timeout。
	acquireErr := func() error {
		_, err := connection.ExecContext(ctx, "SELECT pg_advisory_lock($1)", b.lockKey)
		return err
	}()
	// 恢复会话默认的无限 statement_timeout（本次连接只用于迁移）。
	if _, err := connection.ExecContext(ctx, "SET statement_timeout = 0"); err != nil {
		_ = connection.Close()
		return mapError(err)
	}
	if acquireErr != nil {
		var pqErr interface{ SQLState() string }
		if errors.As(acquireErr, &pqErr) && pqErr.SQLState() == "57014" {
			return storage.New(storage.ErrBusy, "等待 PostgreSQL 迁移排他锁超时（其他实例正在迁移）", acquireErr)
		}
		return mapError(acquireErr)
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeepingLockTimeout)
	defer cancel()
	defer func() {
		_, _ = connection.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", b.lockKey)
	}()

	lockCtx := context.WithValue(ctx, connContextKey{}, connection)
	return fn(lockCtx)
}

// EnsureBookkeeping 幂等创建记录表，并用 information_schema/pg_catalog 核对列集合与
// 列类型。记录表不是业务表，迁移语句本身不创建它们。
func (b *Backend) EnsureBookkeeping(ctx context.Context) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	ddl := []string{
		`CREATE TABLE IF NOT EXISTS schema_history (
			version TEXT COLLATE "C" NOT NULL,
			description TEXT COLLATE "C" NOT NULL,
			applied_at_ms BIGINT NOT NULL,
			source_sha256 TEXT COLLATE "C" NOT NULL,
			PRIMARY KEY (version)
		)`,
		`CREATE TABLE IF NOT EXISTS schema_failures (
			version TEXT COLLATE "C" NOT NULL,
			description TEXT COLLATE "C" NOT NULL,
			source_sha256 TEXT COLLATE "C" NOT NULL,
			failed_at_ms BIGINT NOT NULL,
			error_summary TEXT COLLATE "C" NOT NULL,
			PRIMARY KEY (version)
		)`,
	}
	for _, statement := range ddl {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			return mapError(err)
		}
	}
	return b.verifyBookkeeping(ctx, connection)
}

// verifyBookkeeping 通过 information_schema 核对列集合/顺序，并通过 pg_catalog 核对
// 表确实是普通表（不是视图/外部表），防止旧结构或替身被 IF NOT EXISTS 掩盖。
func (b *Backend) verifyBookkeeping(ctx context.Context, connection *sql.Conn) error {
	expected := map[string][]string{
		"schema_history":  {"version", "description", "applied_at_ms", "source_sha256"},
		"schema_failures": {"version", "description", "source_sha256", "failed_at_ms", "error_summary"},
	}
	for table, columns := range expected {
		var relkind string
		if err := connection.QueryRowContext(ctx,
			`SELECT c.relkind::text FROM pg_catalog.pg_class c
			 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = current_schema() AND c.relname = $1`, table).Scan(&relkind); err != nil {
			return mapError(err)
		}
		if relkind != "r" {
			return storage.New(storage.ErrCorrupt,
				fmt.Sprintf("迁移记录对象 %s 不是普通表（relkind=%s），拒绝在未知结构上迁移", table, relkind), nil)
		}
		rows, err := connection.QueryContext(ctx,
			`SELECT column_name FROM information_schema.columns
			 WHERE table_schema = current_schema() AND table_name = $1
			 ORDER BY ordinal_position`, table)
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

// Apply 在单个事务中执行一条迁移的全部语句并写入 schema_history。
//
// PostgreSQL 支持事务内 DDL，因此迁移失败会整体回滚，不会留下半完成结构；失败记录
// 由 Runner 在事务外写入 schema_failures。含非事务 DDL（CREATE INDEX CONCURRENTLY
// 等）的迁移会在事务中报错，必须修改后端后才可执行（fail-closed）。
func (b *Backend) Apply(ctx context.Context, statements []string, record migrate.AppliedMigration) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	transaction, err := connection.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return mapError(err)
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			_ = transaction.Rollback()
			return mapError(err)
		}
	}
	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES($1,$2,$3,$4)",
		record.Version, record.Description, appliedAtMillis(record.AppliedAt, b.now), record.Checksum); err != nil {
		_ = transaction.Rollback()
		return mapError(err)
	}
	if err := transaction.Commit(); err != nil {
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
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT (version) DO UPDATE SET
		   description = excluded.description,
		   source_sha256 = excluded.source_sha256,
		   failed_at_ms = excluded.failed_at_ms,
		   error_summary = excluded.error_summary`,
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
	if _, err := connection.ExecContext(ctx, "DELETE FROM schema_failures WHERE version = $1", version); err != nil {
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
