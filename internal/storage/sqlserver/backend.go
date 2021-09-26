package sqlserver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	migrationssqlserver "github.com/kagurazakayashi/EvernightLogin/migrations/sqlserver"
)

const (
	// bookkeepingLockTimeout 限制失败记录写入/释放锁等清理操作的墙钟时间。
	bookkeepingLockTimeout = 10 * time.Second
)

// Backend 是 migrate.Backend 的 SQL Server 实现。
//
// 关键差异（相对 SQLite / MySQL / PostgreSQL）：
//   - 排他锁使用 sp_getapplock(@LockOwner='Session')，由专用连接持有；等待上限由
//     MigrationLockTTL 换算为 @LockTimeout 毫秒，超时返回负数结果码映射为 ErrBusy，
//     不静默继续。会话级锁不会因事务提交释放，必须显式 sp_releaseapplock。
//   - SQL Server 的 DDL 在普通事务内可回滚（不同于 MySQL 隐式提交），因此默认把
//     一条迁移的全部语句与 schema_history 记录放在同一事务；源迁移若声明
//     non-transactional（SQLite 迁移当前没有），则按语句顺序执行、失败后保留部分
//     结构并记录 schema_failures，由人工核对后 ClearFailure（不假装自动回滚）。
//   - 执行器按行首 GO 拆分批次：驱动作为单个 T-SQL 批次发送语句，GO 只是客户端
//     批次分隔符，不能出现在发送给服务器的文本中。当前 44 条翻译迁移不含 GO。
//   - 迁移记录表通过 sys.objects/sys.columns/sys.indexes 核对对象类型、列顺序/类型/
//     可空性与主键，不能用 IF NOT EXISTS 掩盖已有表结构差异。
type Backend struct {
	db           *sql.DB
	lockResource string
	lockTTL      time.Duration
	now          func() time.Time
}

// NewMigrationBackend 构造迁移后端。db 必须是未重写的原始连接池（Store.rawDB）。
func NewMigrationBackend(db *sql.DB, lockResource string, lockTTL time.Duration) (*Backend, error) {
	if db == nil {
		return nil, storage.New(storage.ErrUnavailable, "SQL Server 迁移后端缺少数据库连接", nil)
	}
	if strings.TrimSpace(lockResource) == "" {
		return nil, storage.New(storage.ErrUnavailable, "SQL Server 迁移锁资源名不能为空", nil)
	}
	if len(lockResource) > migrationLockResourceMax {
		return nil, storage.New(storage.ErrUnavailable, "SQL Server 迁移锁资源名超过 255 字符上限", nil)
	}
	if lockTTL <= 0 {
		lockTTL = DefaultLockTimeout
	}
	return &Backend{db: db, lockResource: lockResource, lockTTL: lockTTL, now: time.Now}, nil
}

// MigrationBackend 返回 Store 对应的迁移后端。
func (s *Store) MigrationBackend() migrate.Backend {
	backend, err := NewMigrationBackend(s.rawDB, s.MigrationLockName(), s.options.MigrationLockTTL)
	if err != nil {
		// MigrationBackend 接口不返回错误；构造失败时返回一个始终报错的后端。
		return failingBackend{err: err}
	}
	return backend
}

// Migrate 加载翻译后的 SQL Server 迁移并执行。调用方应只在维护/启动阶段调用。
func (s *Store) Migrate(ctx context.Context) (migrate.Result, error) {
	migrations, err := migrationssqlserver.Load()
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
	migrations, err := migrationssqlserver.Load()
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

// Lock 获取 sp_getapplock 会话级排他锁后执行 fn，并在结束时释放。
//
// sp_getapplock 返回 0/1 表示取得锁，负数表示超时/取消/死锁；负数映射为 ErrBusy
// （fail-closed，不静默继续）。锁资源名与超时通过参数传入，不拼接外部文本。
func (b *Backend) Lock(ctx context.Context, fn func(ctx context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	connection, err := b.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer connection.Close()

	timeoutMS := int64(b.lockTTL / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = int64(DefaultLockTimeout / time.Millisecond)
	}
	var result sql.NullInt64
	acquire := `DECLARE @result INT;
EXEC @result = sp_getapplock @Resource=@p1, @LockMode=N'Exclusive', @LockOwner=N'Session', @LockTimeout=@p2;
SELECT @result;`
	if err := connection.QueryRowContext(ctx, acquire, b.lockResource, timeoutMS).Scan(&result); err != nil {
		return mapError(err)
	}
	if !result.Valid {
		return storage.New(storage.ErrBusy, "无法确认 SQL Server 迁移排他锁结果", nil)
	}
	if result.Int64 < 0 {
		message := "等待 SQL Server 迁移排他锁超时（其他实例正在迁移）"
		switch result.Int64 {
		case -1:
			message = "等待 SQL Server 迁移排他锁超时（其他实例正在迁移）"
		case -2:
			message = "SQL Server 迁移排他锁请求被取消"
		case -3:
			message = "SQL Server 迁移排他锁请求成为死锁牺牲者，请重试"
		case -999:
			return storage.New(storage.ErrUnavailable,
				"SQL Server 迁移排他锁参数无效（内部错误）", nil)
		}
		return storage.New(storage.ErrBusy, message, nil)
	}
	lockCtx := context.WithValue(ctx, connContextKey{}, connection)
	fnErr := fn(lockCtx)

	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeepingLockTimeout)
	defer cancel()
	releaseErr := releaseAppLock(releaseCtx, connection, b.lockResource)
	if releaseErr != nil {
		// 释放失败时连接可能仍持有会话级 applock；必须把连接从池中丢弃，避免后续
		// 复用同一连接造成锁计数残留（database/sql 只在 Raw 返回 ErrBadConn 时才
		// 移除连接）。错误同时上报，不静默忽略。
		_ = connection.Raw(func(any) error { return driver.ErrBadConn })
		if fnErr != nil {
			return errors.Join(fnErr, releaseErr)
		}
		return releaseErr
	}
	return fnErr
}

// releaseAppLock 释放 sp_getapplock 会话级锁并核对返回码。
func releaseAppLock(ctx context.Context, connection *sql.Conn, resource string) error {
	var result sql.NullInt64
	release := `DECLARE @result INT;
EXEC @result = sp_releaseapplock @Resource=@p1, @LockOwner=N'Session';
SELECT @result;`
	if err := connection.QueryRowContext(ctx, release, resource).Scan(&result); err != nil {
		return mapError(err)
	}
	if !result.Valid || result.Int64 < 0 {
		return storage.New(storage.ErrBusy, "SQL Server 迁移排他锁释放失败；连接已丢弃并需人工核对锁状态", nil)
	}
	return nil
}

// splitGOBatches 按行首 GO 拆分 T-SQL 批次。GO 是客户端批次分隔符，不能发送给
// 服务器；拼接后含 GO 的语句（例如未来手写迁移）必须拆分。当前翻译迁移不含 GO。
//
// 只接受不带计数的 GO 或 GO 1（重复执行计数 > 1 未实现，显式报错而不是静默丢弃）；
// GO 后的行尾注释允许。
func splitGOBatches(statement string) ([]string, error) {
	lines := strings.Split(statement, "\n")
	var batches []string
	var builder strings.Builder
	flush := func() {
		if text := strings.TrimSpace(builder.String()); text != "" {
			batches = append(batches, text)
		}
		builder.Reset()
	}
	for lineNumber, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if upper == "GO" || strings.HasPrefix(upper, "GO ") || strings.HasPrefix(upper, "GO\t") {
			rest := strings.TrimSpace(trimmed[len("GO"):])
			commentIndex := strings.Index(rest, "--")
			if commentIndex >= 0 {
				rest = strings.TrimSpace(rest[:commentIndex])
			}
			if rest == "" {
				flush()
				continue
			}
			if count, err := strconv.Atoi(rest); err == nil {
				if count == 1 {
					flush()
					continue
				}
				return nil, fmt.Errorf("迁移语句第 %d 行的 %q 批次重复计数未实现；拒绝静默丢弃或误执行", lineNumber+1, trimmed)
			}
			return nil, fmt.Errorf("迁移语句第 %d 行的 GO 批次分隔符无法解析：%q", lineNumber+1, trimmed)
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	flush()
	return batches, nil
}

// EnsureBookkeeping 幂等创建记录表，并用 sys 目录核对列集合、列类型、可空性与主键。
// 记录表不是业务表，迁移语句本身不创建它们。
func (b *Backend) EnsureBookkeeping(ctx context.Context) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	ddl := []string{
		`IF OBJECT_ID(N'schema_history', N'U') IS NULL CREATE TABLE schema_history (
	version NVARCHAR(16) COLLATE Latin1_General_100_BIN2 NOT NULL,
	description NVARCHAR(200) COLLATE Latin1_General_100_BIN2 NOT NULL,
	applied_at_ms BIGINT NOT NULL,
	source_sha256 NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
	CONSTRAINT [PK_schema_history] PRIMARY KEY NONCLUSTERED (version)
)`,
		`IF OBJECT_ID(N'schema_failures', N'U') IS NULL CREATE TABLE schema_failures (
	version NVARCHAR(16) COLLATE Latin1_General_100_BIN2 NOT NULL,
	description NVARCHAR(200) COLLATE Latin1_General_100_BIN2 NOT NULL,
	source_sha256 NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
	failed_at_ms BIGINT NOT NULL,
	error_summary NVARCHAR(500) COLLATE Latin1_General_100_BIN2 NOT NULL,
	CONSTRAINT [PK_schema_failures] PRIMARY KEY NONCLUSTERED (version)
)`,
	}
	for _, statement := range ddl {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			return mapError(err)
		}
	}
	return b.verifyBookkeeping(ctx, connection)
}

// columnExpectation 描述迁移记录表的期望列（顺序、类型、可空性）。
type columnExpectation struct {
	name    string
	typeSQL string
	notNull bool
}

// verifyBookkeeping 通过 sys.objects/sys.columns/sys.indexes 核对对象类型、列集合/
// 顺序/类型/可空性与主键，防止旧结构或替身被 IF NOT EXISTS 掩盖。
func (b *Backend) verifyBookkeeping(ctx context.Context, connection *sql.Conn) error {
	expected := map[string][]columnExpectation{
		"schema_history": {
			{"version", "nvarchar", true},
			{"description", "nvarchar", true},
			{"applied_at_ms", "bigint", true},
			{"source_sha256", "nvarchar", true},
		},
		"schema_failures": {
			{"version", "nvarchar", true},
			{"description", "nvarchar", true},
			{"source_sha256", "nvarchar", true},
			{"failed_at_ms", "bigint", true},
			{"error_summary", "nvarchar", true},
		},
	}
	for table, columns := range expected {
		var objectType sql.NullString
		if err := connection.QueryRowContext(ctx,
			`SELECT type FROM sys.objects WHERE object_id = OBJECT_ID(@p1)`, table).Scan(&objectType); err != nil {
			return mapError(err)
		}
		if !objectType.Valid || objectType.String != "U" {
			return storage.New(storage.ErrCorrupt,
				fmt.Sprintf("迁移记录对象 %s 不是用户表（type=%v），拒绝在未知结构上迁移", table, objectType.String), nil)
		}
		var primaryKeys sql.NullInt64
		if err := connection.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sys.indexes WHERE object_id = OBJECT_ID(@p1) AND is_primary_key = 1`,
			table).Scan(&primaryKeys); err != nil {
			return mapError(err)
		}
		if !primaryKeys.Valid || primaryKeys.Int64 != 1 {
			return storage.New(storage.ErrCorrupt,
				fmt.Sprintf("迁移记录表 %s 缺少唯一主键，拒绝在未知结构上迁移", table), nil)
		}
		rows, err := connection.QueryContext(ctx,
			`SELECT c.name, t.name, c.is_nullable
			 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
			 WHERE c.object_id = OBJECT_ID(@p1) ORDER BY c.column_id`, table)
		if err != nil {
			return mapError(err)
		}
		var actual []columnExpectation
		for rows.Next() {
			var column columnExpectation
			var nullable bool
			if err := rows.Scan(&column.name, &column.typeSQL, &nullable); err != nil {
				rows.Close()
				return mapError(err)
			}
			column.notNull = !nullable
			actual = append(actual, column)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return mapError(err)
		}
		rows.Close()
		if len(actual) != len(columns) {
			return storage.New(storage.ErrCorrupt,
				fmt.Sprintf("迁移记录表 %s 的列数不符合预期（期望 %d，实际 %d），拒绝在未知结构上迁移",
					table, len(columns), len(actual)), nil)
		}
		for index := range columns {
			if actual[index].name != columns[index].name ||
				!strings.EqualFold(actual[index].typeSQL, columns[index].typeSQL) ||
				actual[index].notNull != columns[index].notNull {
				return storage.New(storage.ErrCorrupt,
					fmt.Sprintf("迁移记录表 %s 的列结构不符合预期（第 %d 列期望 %s/%s/NOT NULL=%v，实际 %s/%s/NOT NULL=%v），拒绝在未知结构上迁移",
						table, index+1, columns[index].name, columns[index].typeSQL, columns[index].notNull,
						actual[index].name, actual[index].typeSQL, actual[index].notNull), nil)
			}
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

// Apply 执行一条迁移的全部语句并写入 schema_history。
//
// 默认在单个事务中执行（SQL Server 支持事务内 DDL），失败整体回滚，不会留下半完成
// 结构；失败记录由 Runner 在事务外写入 schema_failures。源迁移标记
// NonTransactional 时按语句顺序执行、不承诺回滚（失败后人工核对），与 MySQL 适配
// 的隐式提交语义一致；当前 SQLite 迁移没有该标记。
func (b *Backend) Apply(ctx context.Context, statements []string, record migrate.AppliedMigration) error {
	connection, err := connFromContext(ctx)
	if err != nil {
		return err
	}
	batches := make([]string, 0, len(statements))
	for _, statement := range statements {
		statementBatches, err := splitGOBatches(statement)
		if err != nil {
			return mapError(err)
		}
		batches = append(batches, statementBatches...)
	}
	if record.NonTransactional {
		for _, batch := range batches {
			if _, err := connection.ExecContext(ctx, batch); err != nil {
				return mapError(err)
			}
		}
		_, err := connection.ExecContext(ctx,
			"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES(@p1,@p2,@p3,@p4)",
			record.Version, record.Description, appliedAtMillis(record.AppliedAt, b.now), record.Checksum)
		return mapError(err)
	}
	transaction, err := connection.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return mapError(err)
	}
	for _, batch := range batches {
		if _, err := transaction.ExecContext(ctx, batch); err != nil {
			_ = transaction.Rollback()
			return mapError(err)
		}
	}
	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES(@p1,@p2,@p3,@p4)",
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
	statement := `MERGE INTO schema_failures WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS version, @p2 AS description, @p3 AS source_sha256, @p4 AS failed_at_ms, @p5 AS error_summary) AS source
ON target.version = source.version
WHEN MATCHED THEN UPDATE SET description = source.description, source_sha256 = source.source_sha256,
  failed_at_ms = source.failed_at_ms, error_summary = source.error_summary
WHEN NOT MATCHED THEN INSERT (version, description, source_sha256, failed_at_ms, error_summary)
  VALUES (source.version, source.description, source.source_sha256, source.failed_at_ms, source.error_summary);`
	if _, err := connection.ExecContext(ctx, statement,
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
	if _, err := connection.ExecContext(ctx, "DELETE FROM schema_failures WHERE version = @p1", version); err != nil {
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
