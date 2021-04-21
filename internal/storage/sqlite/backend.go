package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

// savepointRollbackTimeout 限制失败迁移回滚保存点的墙钟时间，避免 ctx 取消后
// 无法清理部分语句。
const savepointRollbackTimeout = 5 * time.Second

// txContextKey 让 Backend 的方法在 Lock 回调期间共享同一个迁移事务。
type txContextKey struct{}

// sqliteBackend 是 migrate.Backend 的 SQLite 实现。Lock 使用一个 IMMEDIATE
// 写事务作为排他锁；所有记录读写与迁移语句都在该事务内执行，结束统一提交。
// 每条迁移使用 SAVEPOINT 保证单条迁移失败时回滚该迁移，但保留此前已成功迁移
// 与失败记录（失败记录在 Runner 中写入）。
type sqliteBackend struct {
	store *Store
}

func (b *sqliteBackend) tx(ctx context.Context) (*sql.Tx, error) {
	if ctx == nil {
		return nil, storage.New(storage.ErrUnavailable, "迁移上下文为空", nil)
	}
	tx, ok := ctx.Value(txContextKey{}).(*sql.Tx)
	if !ok || tx == nil {
		return nil, storage.New(storage.ErrUnavailable, "迁移操作不在排他事务中", nil)
	}
	return tx, nil
}

// Lock 开启 IMMEDIATE 写事务作为跨连接迁移排他锁，执行 fn 后统一提交。
//
// 即使 fn 返回错误也提交：Runner 在失败路径上会写入失败记录与已成功迁移，必须
// 持久化；单条迁移的部分语句已由保存点回滚。提交失败时与回调错误合并返回。
func (b *sqliteBackend) Lock(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := b.store.ensureOpen(); err != nil {
		return err
	}
	tx, err := b.store.beginTxWithRetry(ctx)
	if err != nil {
		return err
	}
	lockCtx := context.WithValue(ctx, txContextKey{}, tx)
	callbackErr := fn(lockCtx)
	commitErr := tx.Commit()
	if commitErr != nil {
		_ = tx.Rollback()
		if callbackErr != nil {
			return errors.Join(callbackErr, mapError(commitErr))
		}
		return mapError(commitErr)
	}
	return callbackErr
}

// EnsureBookkeeping 幂等创建迁移记录表。它们属于迁移基础设施，不进入用户迁移
// 历史。DDL 在 Lock 事务内执行，失败回滚。
func (b *sqliteBackend) EnsureBookkeeping(ctx context.Context) error {
	tx, err := b.tx(ctx)
	if err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_history (
version TEXT PRIMARY KEY NOT NULL,
description TEXT NOT NULL,
applied_at_ms INTEGER NOT NULL,
source_sha256 TEXT NOT NULL
)`,
		`CREATE TABLE IF NOT EXISTS schema_failures (
version TEXT PRIMARY KEY NOT NULL,
description TEXT NOT NULL,
source_sha256 TEXT NOT NULL,
failed_at_ms INTEGER NOT NULL,
error_summary TEXT NOT NULL
)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// LoadApplied 读取已应用迁移，按版本升序返回。
func (b *sqliteBackend) LoadApplied(ctx context.Context) ([]migrate.AppliedMigration, error) {
	tx, err := b.tx(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT version, description, source_sha256, applied_at_ms FROM schema_history ORDER BY version`)
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
func (b *sqliteBackend) LoadFailed(ctx context.Context) ([]migrate.FailedMigration, error) {
	tx, err := b.tx(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT version, description, source_sha256, failed_at_ms, error_summary FROM schema_failures ORDER BY version`)
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

// Apply 在迁移事务内执行一条迁移。事务性迁移使用保存点，失败时回滚该迁移的
// 语句且不写已应用记录；非事务迁移按约定逐条执行，失败可能留下部分结构并由
// Runner 记录失败状态。
func (b *sqliteBackend) Apply(ctx context.Context, statements []string, record migrate.AppliedMigration) error {
	tx, err := b.tx(ctx)
	if err != nil {
		return err
	}
	if record.NonTransactional {
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return mapError(err)
			}
		}
		return b.insertHistory(ctx, tx, record)
	}

	if _, err := tx.ExecContext(ctx, "SAVEPOINT login_migration_apply"); err != nil {
		return mapError(err)
	}
	applyErr := func() error {
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return mapError(err)
			}
		}
		return b.insertHistory(ctx, tx, record)
	}()
	if applyErr != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), savepointRollbackTimeout)
		defer cancel()
		_, rollbackErr := tx.ExecContext(rollbackCtx, "ROLLBACK TO login_migration_apply")
		_, releaseErr := tx.ExecContext(rollbackCtx, "RELEASE login_migration_apply")
		if rollbackErr != nil || releaseErr != nil {
			return errors.Join(applyErr, mapError(rollbackErr), mapError(releaseErr))
		}
		return applyErr
	}
	if _, err := tx.ExecContext(ctx, "RELEASE login_migration_apply"); err != nil {
		return mapError(err)
	}
	return nil
}

func (b *sqliteBackend) insertHistory(ctx context.Context, tx *sql.Tx, record migrate.AppliedMigration) error {
	appliedAt := record.AppliedAt
	if appliedAt.IsZero() {
		appliedAt = time.Now()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_history(version, description, applied_at_ms, source_sha256) VALUES(?,?,?,?)`,
		record.Version, record.Description, appliedAt.UTC().UnixMilli(), record.Checksum); err != nil {
		return mapError(err)
	}
	return nil
}

// RecordFailure 持久化失败记录（删除同版本旧记录后插入）。
func (b *sqliteBackend) RecordFailure(ctx context.Context, record migrate.FailedMigration) error {
	tx, err := b.tx(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_failures WHERE version=?`, record.Version); err != nil {
		return mapError(err)
	}
	failedAt := record.FailedAt
	if failedAt.IsZero() {
		failedAt = time.Now()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_failures(version, description, source_sha256, failed_at_ms, error_summary) VALUES(?,?,?,?,?)`,
		record.Version, record.Description, record.Checksum, failedAt.UTC().UnixMilli(), record.ErrorSummary); err != nil {
		return mapError(err)
	}
	return nil
}

// ClearFailure 删除指定版本的失败记录。
func (b *sqliteBackend) ClearFailure(ctx context.Context, version string) error {
	tx, err := b.tx(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_failures WHERE version=?`, version); err != nil {
		return mapError(err)
	}
	return nil
}

// 编译期确认实现 migrate.Backend。
var _ migrate.Backend = (*sqliteBackend)(nil)
