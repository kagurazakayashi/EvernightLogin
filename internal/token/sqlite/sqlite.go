// Package sqlite 实现 internal/token.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0030_token_signing_keys.sql 创建；本包不执行迁移、不拥有数据库
// 连接、不保存私钥明文。密钥状态迁移全部使用条件更新，配合数据库部分唯一索引保证
// 同一时刻最多一个 active/next，并发轮换只有一个成功。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

const selectKeyColumns = `kid,algorithm,status,public_jwk,sealed_private,created_at_ms,
COALESCE(activated_at_ms,0),COALESCE(retired_at_ms,0),COALESCE(retire_after_ms,0),
COALESCE(revoked_at_ms,0),COALESCE(revoked_reason,'')`

const selectKeySQL = `SELECT ` + selectKeyColumns + ` FROM token_signing_keys WHERE kid=?`

const selectActiveKeySQL = `SELECT ` + selectKeyColumns + ` FROM token_signing_keys
WHERE status='active' LIMIT 1`

const listKeysSQL = `SELECT ` + selectKeyColumns + ` FROM token_signing_keys ORDER BY created_at_ms`

const insertKeySQL = `INSERT INTO token_signing_keys(
kid,algorithm,status,public_jwk,sealed_private,created_at_ms,activated_at_ms,
retired_at_ms,retire_after_ms,revoked_at_ms,revoked_reason,row_version)
VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,1)`

const activateKeySQL = `UPDATE token_signing_keys
SET status='active',activated_at_ms=?,row_version=row_version+1
WHERE kid=? AND status='next'`

const retireKeySQL = `UPDATE token_signing_keys
SET status='retired',retired_at_ms=?,retire_after_ms=?,row_version=row_version+1
WHERE kid=? AND status='active'`

const revokeKeySQL = `UPDATE token_signing_keys
SET status='revoked',revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE kid=? AND status IN('next','active','retired')`

// Store 是 token.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", token.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ token.Store = (*Store)(nil)

// storeError 把驱动错误包装为稳定领域错误，避免原始 SQL 文本外泄。
func storeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s失败", token.ErrStoreUnavailable, operation)
}

// GetKey 按 kid 读取密钥记录。
func (s *Store) GetKey(ctx context.Context, kid string) (token.KeyRecord, bool, error) {
	return s.scanKey(s.store.QueryContext(ctx, selectKeySQL, kid))
}

// GetActiveKey 返回当前 active 签名密钥。
func (s *Store) GetActiveKey(ctx context.Context) (token.KeyRecord, bool, error) {
	return s.scanKey(s.store.QueryContext(ctx, selectActiveKeySQL))
}

// scanKey 执行单行密钥查询并扫描记录。
func (s *Store) scanKey(rows *sql.Rows, queryErr error) (token.KeyRecord, bool, error) {
	if queryErr != nil {
		return token.KeyRecord{}, false, storeError("读取签名密钥", queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return token.KeyRecord{}, false, storeError("读取签名密钥", err)
		}
		return token.KeyRecord{}, false, nil
	}
	record, err := scanKeyRow(rows)
	if err != nil {
		return token.KeyRecord{}, false, err
	}
	return record, true, nil
}

// ListKeys 返回全部密钥记录。
func (s *Store) ListKeys(ctx context.Context) ([]token.KeyRecord, error) {
	rows, err := s.store.QueryContext(ctx, listKeysSQL)
	if err != nil {
		return nil, storeError("列出签名密钥", err)
	}
	defer rows.Close()
	records := make([]token.KeyRecord, 0, 4)
	for rows.Next() {
		record, err := scanKeyRow(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError("列出签名密钥", err)
	}
	return records, nil
}

// scanKeyRow 扫描一行密钥记录。
func scanKeyRow(rows *sql.Rows) (token.KeyRecord, error) {
	var record token.KeyRecord
	var algorithm, status string
	var createdMS, activatedMS, retiredMS, retireAfterMS, revokedMS int64
	if err := rows.Scan(&record.Kid, &algorithm, &status, &record.PublicJWK, &record.SealedPrivate,
		&createdMS, &activatedMS, &retiredMS, &retireAfterMS, &revokedMS, &record.RevokedReason); err != nil {
		return token.KeyRecord{}, storeError("扫描签名密钥", err)
	}
	record.Algorithm = algorithm
	record.Status = token.KeyStatus(status)
	record.CreatedAt = time.UnixMilli(createdMS).UTC()
	if activatedMS != 0 {
		record.ActivatedAt = time.UnixMilli(activatedMS).UTC()
	}
	if retiredMS != 0 {
		record.RetiredAt = time.UnixMilli(retiredMS).UTC()
	}
	if retireAfterMS != 0 {
		record.RetireAfter = time.UnixMilli(retireAfterMS).UTC()
	}
	if revokedMS != 0 {
		record.RevokedAt = time.UnixMilli(revokedMS).UTC()
	}
	return record, nil
}

// InsertKeyTx 在审计事务内插入密钥记录。
func (s *Store) InsertKeyTx(ctx context.Context, tx audit.Tx, record token.KeyRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", token.ErrOptionsInvalid)
	}
	var activatedAt any
	if !record.ActivatedAt.IsZero() {
		activatedAt = record.ActivatedAt.UnixMilli()
	}
	_, err := tx.ExecContext(ctx, insertKeySQL, record.Kid, record.Algorithm,
		string(record.Status), record.PublicJWK, record.SealedPrivate,
		record.CreatedAt.UnixMilli(), activatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return token.ErrKeyUnavailable
		}
		return storeError("写入签名密钥", err)
	}
	return nil
}

// ActivateKeyTx 条件把 next 密钥迁移为 active。
func (s *Store) ActivateKeyTx(ctx context.Context, tx audit.Tx, kid string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, activateKeySQL, now.UnixMilli(), kid)
	if err != nil {
		return false, storeError("启用签名密钥", err)
	}
	return rowsAffected(result, "启用签名密钥")
}

// RetireKeyTx 条件把 active 密钥迁移为 retired。
func (s *Store) RetireKeyTx(ctx context.Context, tx audit.Tx, kid string, now, retireAfter time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, retireKeySQL, now.UnixMilli(), retireAfter.UnixMilli(), kid)
	if err != nil {
		return false, storeError("退役签名密钥", err)
	}
	return rowsAffected(result, "退役签名密钥")
}

// RevokeKeyTx 条件撤销密钥（next/active/retired → revoked）。
func (s *Store) RevokeKeyTx(ctx context.Context, tx audit.Tx, kid, reason string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, revokeKeySQL, now.UnixMilli(), reason, kid)
	if err != nil {
		return false, storeError("撤销签名密钥", err)
	}
	return rowsAffected(result, "撤销签名密钥")
}

// rowsAffected 把条件更新结果转换为“恰好一行生效”。
func rowsAffected(result sql.Result, operation string) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError(operation, err)
	}
	return affected == 1, nil
}

// isUniqueViolation 识别 SQLite 唯一约束冲突（active/next 并发轮换）。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed") || strings.Contains(message, "constraint failed")
}
