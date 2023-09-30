// Package sqlite 实现 internal/credential.Store 的 SQLite 生产仓储。
//
// 表由 migrations/0002_one_time_credentials.sql 创建，本包不执行迁移；调用方应
// 在启动或测试中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库
// 连接：*sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine 并发
// 使用。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	insertSQL = `INSERT INTO one_time_credentials(
id,purpose,subject_id,app_id,verifier_hash,key_id,context_json,attempts,max_attempts,created_at_ms,expires_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?)`

	revokeScopeSQL = `UPDATE one_time_credentials SET revoked_at_ms=?
WHERE purpose=? AND subject_id=? AND ((app_id IS NULL AND ? IS NULL) OR app_id=?)
AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL`

	loadByIDSQL = `SELECT id,purpose,subject_id,app_id,verifier_hash,key_id,context_json,
attempts,max_attempts,created_at_ms,expires_at_ms,consumed_at_ms,revoked_at_ms
FROM one_time_credentials WHERE id=?`

	consumeSQL = `UPDATE one_time_credentials SET consumed_at_ms=?
WHERE id=? AND purpose=? AND subject_id=? AND ((app_id IS NULL AND ? IS NULL) OR app_id=?)
AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>? AND attempts<max_attempts`

	failedAttemptSQL = `UPDATE one_time_credentials SET attempts=attempts+1
WHERE id=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL
AND expires_at_ms>? AND attempts<max_attempts`

	failedAttemptStateSQL = `SELECT attempts,max_attempts,consumed_at_ms,revoked_at_ms,expires_at_ms
FROM one_time_credentials WHERE id=?`

	revokeSQL = `UPDATE one_time_credentials SET revoked_at_ms=?
WHERE id=? AND purpose=? AND subject_id=? AND ((app_id IS NULL AND ? IS NULL) OR app_id=?)
AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>?`

	deleteExpiredSQL = `DELETE FROM one_time_credentials WHERE expires_at_ms<=?`
)

// Store 是 credential.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。store 为空时返回
// credential.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", credential.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 credential.Store 与可选事务扩展。
var (
	_ credential.Store            = (*Store)(nil)
	_ credential.TransactionStore = (*Store)(nil)
)

// rowQuerier 抽象“独立存储或调用方事务”的最小读取能力：*storage/sqlite.Store 与
// credential.Transaction（生产上由 audit.Tx 满足）都实现，使同一份 SQL 与扫描逻辑
// 同时服务独立路径与事务内路径，避免复制查询。
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// rowExecer 抽象“独立存储或调用方事务”的最小写入能力，用途同上。
type rowExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// nullableAppID 把空应用绑定映射为 SQL NULL（系统范围）。
func nullableAppID(appID string) any {
	if appID == "" {
		return nil
	}
	return appID
}

// nullableKeyID 把空 key_id 映射为 SQL NULL（高熵令牌摘要不依赖密钥）。
func nullableKeyID(keyID string) any {
	if keyID == "" {
		return nil
	}
	return keyID
}

// Insert 写入一条新凭证。verifier_hash 唯一约束冲突时由调用方收到存储错误，
// 不会静默覆盖已有记录。
func (s *Store) Insert(ctx context.Context, record credential.Record) error {
	_, err := s.store.ExecContext(ctx, insertSQL,
		record.ID,
		record.Purpose,
		record.Target,
		nullableAppID(record.AppID),
		record.VerifierHash,
		nullableKeyID(record.KeyID),
		record.ContextJSON,
		record.Attempts,
		record.MaxAttempts,
		record.CreatedAt.UTC().UnixMilli(),
		record.ExpiresAt.UTC().UnixMilli(),
	)
	return err
}

// ReplaceActiveAndInsert 在同一 IMMEDIATE 写事务中撤销同用途、同目标、同应用的
// 活动凭证，再插入新记录；任一步失败整体回滚，不会留下“旧凭证已撤销但新凭证
// 未写入”的中间状态。
func (s *Store) ReplaceActiveAndInsert(ctx context.Context, record credential.Record, now time.Time) error {
	appID := nullableAppID(record.AppID)
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx, revokeScopeSQL,
			now.UTC().UnixMilli(),
			record.Purpose,
			record.Target,
			appID,
			appID,
		); err != nil {
			return err
		}
		_, err := tx.ExecContext(txCtx, insertSQL,
			record.ID,
			record.Purpose,
			record.Target,
			nullableAppID(record.AppID),
			record.VerifierHash,
			nullableKeyID(record.KeyID),
			record.ContextJSON,
			record.Attempts,
			record.MaxAttempts,
			record.CreatedAt.UTC().UnixMilli(),
			record.ExpiresAt.UTC().UnixMilli(),
		)
		return err
	})
}

// LoadByID 读取一条凭证记录；不存在时返回 (Record{}, false, nil)。
func (s *Store) LoadByID(ctx context.Context, id string) (credential.Record, bool, error) {
	return s.loadByID(ctx, s.store, id)
}

// LoadByIDTx 在调用方事务内读取凭证记录，语义同 LoadByID。
func (s *Store) LoadByIDTx(ctx context.Context, tx credential.Transaction,
	id string) (credential.Record, bool, error) {
	return s.loadByID(ctx, tx, id)
}

// loadByID 是独立与事务内路径共用的读取/扫描实现。
func (s *Store) loadByID(ctx context.Context, querier rowQuerier,
	id string) (credential.Record, bool, error) {
	rows, err := querier.QueryContext(ctx, loadByIDSQL, id)
	if err != nil {
		return credential.Record{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return credential.Record{}, false, err
		}
		return credential.Record{}, false, nil
	}
	var (
		record     credential.Record
		appID      sql.NullString
		keyID      sql.NullString
		createdAt  int64
		expiresAt  int64
		consumedAt sql.NullInt64
		revokedAt  sql.NullInt64
	)
	if err := rows.Scan(
		&record.ID,
		&record.Purpose,
		&record.Target,
		&appID,
		&record.VerifierHash,
		&keyID,
		&record.ContextJSON,
		&record.Attempts,
		&record.MaxAttempts,
		&createdAt,
		&expiresAt,
		&consumedAt,
		&revokedAt,
	); err != nil {
		return credential.Record{}, false, err
	}
	if err := rows.Err(); err != nil {
		return credential.Record{}, false, err
	}
	record.AppID = appID.String
	record.KeyID = keyID.String
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	if consumedAt.Valid {
		consumed := time.UnixMilli(consumedAt.Int64).UTC()
		record.ConsumedAt = &consumed
	}
	if revokedAt.Valid {
		revoked := time.UnixMilli(revokedAt.Int64).UTC()
		record.RevokedAt = &revoked
	}
	return record, true, nil
}

// Consume 用一条条件 UPDATE 原子判断并消费凭证。返回 true 表示本次调用成功
// 消费；false 表示记录已不满足活动、未过期、未达尝试上限或绑定一致等条件。
func (s *Store) Consume(ctx context.Context, condition credential.ConsumeCondition) (bool, error) {
	return s.consume(ctx, s.store, condition)
}

// ConsumeTx 在调用方事务内用同一条条件 UPDATE 原子判断并消费凭证；语义同 Consume。
// 事务由调用方拥有：返回错误时调用方整体回滚，凭证不会被消费。
func (s *Store) ConsumeTx(ctx context.Context, tx credential.Transaction,
	condition credential.ConsumeCondition) (bool, error) {
	return s.consume(ctx, tx, condition)
}

// consume 是独立与事务内路径共用的条件消费实现。
func (s *Store) consume(ctx context.Context, execer rowExecer,
	condition credential.ConsumeCondition) (bool, error) {
	nowMS := condition.Now.UTC().UnixMilli()
	appID := nullableAppID(condition.AppID)
	result, err := execer.ExecContext(ctx, consumeSQL,
		nowMS,
		condition.ID,
		condition.Purpose,
		condition.Target,
		appID,
		appID,
		nowMS,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// RecordFailedAttempt 对仍活动且未达上限的记录原子增加一次尝试次数，并返回用于
// 内部诊断的剩余次数与活动状态。更新本身是条件语句，并发失败尝试不会超过上限。
func (s *Store) RecordFailedAttempt(ctx context.Context, id string, now time.Time) (credential.FailedAttemptResult, error) {
	nowMS := now.UTC().UnixMilli()
	if _, err := s.store.ExecContext(ctx, failedAttemptSQL, id, nowMS); err != nil {
		return credential.FailedAttemptResult{}, err
	}
	rows, err := s.store.QueryContext(ctx, failedAttemptStateSQL, id)
	if err != nil {
		return credential.FailedAttemptResult{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return credential.FailedAttemptResult{}, err
		}
		return credential.FailedAttemptResult{Remaining: 0, Active: false}, nil
	}
	var (
		attempts   int
		maxAttempt int
		consumedAt sql.NullInt64
		revokedAt  sql.NullInt64
		expiresAt  int64
	)
	if err := rows.Scan(&attempts, &maxAttempt, &consumedAt, &revokedAt, &expiresAt); err != nil {
		return credential.FailedAttemptResult{}, err
	}
	if err := rows.Err(); err != nil {
		return credential.FailedAttemptResult{}, err
	}
	remaining := maxAttempt - attempts
	if remaining < 0 {
		remaining = 0
	}
	active := !consumedAt.Valid && !revokedAt.Valid && expiresAt > nowMS && remaining > 0
	return credential.FailedAttemptResult{Remaining: remaining, Active: active}, nil
}

// Revoke 用一条条件 UPDATE 撤销仍活动、未过期且绑定一致的凭证。
func (s *Store) Revoke(ctx context.Context, condition credential.RevokeCondition) (bool, error) {
	return s.revoke(ctx, s.store, condition)
}

// RevokeTx 在调用方事务内用同一条条件 UPDATE 撤销凭证；语义同 Revoke。
func (s *Store) RevokeTx(ctx context.Context, tx credential.Transaction,
	condition credential.RevokeCondition) (bool, error) {
	return s.revoke(ctx, tx, condition)
}

// revoke 是独立与事务内路径共用的条件撤销实现。
func (s *Store) revoke(ctx context.Context, execer rowExecer,
	condition credential.RevokeCondition) (bool, error) {
	appID := nullableAppID(condition.AppID)
	result, err := execer.ExecContext(ctx, revokeSQL,
		condition.Now.UTC().UnixMilli(),
		condition.ID,
		condition.Purpose,
		condition.Target,
		appID,
		appID,
		condition.Now.UTC().UnixMilli(),
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// DeleteExpired 删除过期时间不晚于 cutoff 的凭证，返回删除数量。
func (s *Store) DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.store.ExecContext(ctx, deleteExpiredSQL, cutoff.UTC().UnixMilli())
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}
