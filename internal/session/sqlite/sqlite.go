// Package sqlite 实现 internal/session.Store 的 SQLite 生产持久化。
//
// 表结构来自 migrations/0010_sessions.sql（会话验证摘要、类别/受限原因、到期与
// 撤销状态）。本包不执行迁移，调用方应在启动或测试中先应用全部迁移；本包不拥有
// 数据库连接，*storage/sqlite.Store 的关闭由外层负责。构造后不可变，可被多个
// goroutine 并发使用；Insert/Revoke/RevokeUser 要求调用方提供同一审计事务
// （audit.Tx），与成功审计一致提交或整体回滚。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// selectSessionColumns 是会话记录的公共选择列表；app_id 用 COALESCE 统一空值。
	selectSessionColumns = `id,user_id,COALESCE(app_id,''),kind,restricted_reason,required_steps_json,
security_version,secret_digest,csrf_digest,key_id,strong_auth_verified_at_ms,row_version,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms,revoked_at_ms,revoked_reason`

	selectSessionByIDSQL = `SELECT ` + selectSessionColumns + ` FROM sessions WHERE id=?`

	// insertSessionSQL 写入一条新会话；数据库只保存验证摘要，绝不保存秘密明文。
	insertSessionSQL = `INSERT INTO sessions(
id,user_id,app_id,kind,restricted_reason,required_steps_json,security_version,
secret_digest,csrf_digest,key_id,strong_auth_verified_at_ms,row_version,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms,request_id
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	// touchSessionSQL 条件续期：只有未撤销且未到期时才更新最后活动与空闲到期。
	touchSessionSQL = `UPDATE sessions
SET last_seen_at_ms=?,idle_expires_at_ms=?,row_version=row_version+1
WHERE id=? AND revoked_at_ms IS NULL AND idle_expires_at_ms>? AND absolute_expires_at_ms>?`

	// revokeSessionSQL 条件撤销单条会话；已撤销会话不会被重复计数。
	revokeSessionSQL = `UPDATE sessions
SET revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE id=? AND revoked_at_ms IS NULL`

	// revokeUserSessionsSQL 撤销账户全部活动会话。
	revokeUserSessionsSQL = `UPDATE sessions
SET revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE user_id=? AND revoked_at_ms IS NULL`

	selectUserStateSQL = `SELECT status,security_version,is_root FROM users WHERE id=?`

	// selectMembershipSQL 一次读取应用状态与成员状态；成员缺失时成员状态为空串。
	selectMembershipSQL = `SELECT a.status,COALESCE(m.status,'')
FROM applications a LEFT JOIN app_memberships m ON m.app_id=a.id AND m.user_id=?
WHERE a.id=?`

	deleteExpiredSQL = `DELETE FROM sessions
WHERE absolute_expires_at_ms<=? OR (revoked_at_ms IS NOT NULL AND revoked_at_ms<=?)`
)

// Store 是 session.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空返回
// session.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", session.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// Insert 在调用方审计事务中写入会话记录。
func (s *Store) Insert(ctx context.Context, tx audit.Tx, record session.Record) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	steps, err := encodeSteps(record.RequiredSteps)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, insertSessionSQL,
		record.ID,
		record.UserID,
		nullString(record.AppID),
		string(record.Kind),
		string(record.Reason),
		steps,
		record.SecurityVersion,
		record.SecretDigest,
		record.CSRFDigest,
		record.KeyID,
		nullableTime(record.StrongAuthAt),
		record.RowVersion,
		toUnixMilli(record.CreatedAt),
		toUnixMilli(record.LastSeenAt),
		toUnixMilli(record.IdleExpiresAt),
		toUnixMilli(record.AbsoluteExpiresAt),
		record.RequestID,
	)
	if err != nil {
		return storeError("写入会话", err)
	}
	return nil
}

// Load 按会话 ID 读取记录；不存在返回 found=false。
func (s *Store) Load(ctx context.Context, id string) (session.Record, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectSessionByIDSQL, id)
	if err != nil {
		return session.Record{}, false, storeError("读取会话", err)
	}
	record, found, err := scanRecord(rows)
	if err != nil {
		return session.Record{}, false, err
	}
	return record, found, nil
}

// Touch 条件续期并返回更新后的记录。会话已撤销、已到期或被并发撤销时返回
// changed=false。
func (s *Store) Touch(ctx context.Context, condition session.TouchCondition) (session.Record, bool, error) {
	nowMS := toUnixMilli(condition.Now)
	result, err := s.store.ExecContext(ctx, touchSessionSQL,
		nowMS,
		toUnixMilli(condition.IdleExpiresAt),
		condition.ID,
		nowMS,
		nowMS,
	)
	if err != nil {
		return session.Record{}, false, storeError("续期会话", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return session.Record{}, false, storeError("续期会话", err)
	}
	if affected == 0 {
		return session.Record{}, false, nil
	}
	record, found, err := s.Load(ctx, condition.ID)
	if err != nil {
		return session.Record{}, false, err
	}
	if !found {
		return session.Record{}, false, nil
	}
	// 并发撤销可能发生在本事务提交之后：以最新状态为准，不能返回刚被撤销的会话。
	if !record.RevokedAt.IsZero() || !record.IdleExpiresAt.After(condition.Now) ||
		!record.AbsoluteExpiresAt.After(condition.Now) {
		return session.Record{}, false, nil
	}
	return record, true, nil
}

// Revoke 条件撤销单条会话；返回是否实际变更。
func (s *Store) Revoke(ctx context.Context, tx audit.Tx, condition session.RevokeCondition) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeSessionSQL,
		toUnixMilli(condition.Now),
		condition.Reason,
		condition.ID,
	)
	if err != nil {
		return false, storeError("撤销会话", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError("撤销会话", err)
	}
	return affected > 0, nil
}

// RevokeUser 撤销账户全部活动会话；返回实际撤销数量。
func (s *Store) RevokeUser(ctx context.Context, tx audit.Tx, condition session.RevokeUserCondition) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeUserSessionsSQL,
		toUnixMilli(condition.Now),
		condition.Reason,
		condition.UserID,
	)
	if err != nil {
		return 0, storeError("批量撤销会话", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, storeError("批量撤销会话", err)
	}
	return affected, nil
}

// LoadUserState 读取账户状态、安全版本与 root 标记；账户不存在返回 found=false。
func (s *Store) LoadUserState(ctx context.Context, userID string) (session.UserState, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserStateSQL, userID)
	if err != nil {
		return session.UserState{}, false, storeError("读取账户状态", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return session.UserState{}, false, storeError("读取账户状态", err)
		}
		return session.UserState{}, false, nil
	}
	var status string
	var isRoot int
	state := session.UserState{}
	if err := rows.Scan(&status, &state.SecurityVersion, &isRoot); err != nil {
		return session.UserState{}, false, storeError("读取账户状态", err)
	}
	state.Status = account.Status(status)
	state.IsRoot = isRoot == 1
	if err := rows.Err(); err != nil {
		return session.UserState{}, false, storeError("读取账户状态", err)
	}
	return state, true, nil
}

// LoadMembership 读取应用状态与成员状态；应用不存在返回 found=false。
func (s *Store) LoadMembership(ctx context.Context, appID, userID string) (session.MembershipState, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectMembershipSQL, userID, appID)
	if err != nil {
		return session.MembershipState{}, false, storeError("读取应用成员状态", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return session.MembershipState{}, false, storeError("读取应用成员状态", err)
		}
		return session.MembershipState{}, false, nil
	}
	var applicationStatus, memberStatus string
	if err := rows.Scan(&applicationStatus, &memberStatus); err != nil {
		return session.MembershipState{}, false, storeError("读取应用成员状态", err)
	}
	if err := rows.Err(); err != nil {
		return session.MembershipState{}, false, storeError("读取应用成员状态", err)
	}
	return session.MembershipState{
		ApplicationActive: applicationStatus == "active",
		MemberActive:      memberStatus == "active",
	}, true, nil
}

// DeleteExpired 删除绝对到期或撤销时间早于 cutoff 的会话记录，返回删除数量。
func (s *Store) DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffMS := toUnixMilli(cutoff)
	result, err := s.store.ExecContext(ctx, deleteExpiredSQL, cutoffMS, cutoffMS)
	if err != nil {
		return 0, storeError("清理过期会话", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, storeError("清理过期会话", err)
	}
	return deleted, nil
}

// scanRecord 读取一行会话记录；没有数据时返回 found=false。
func scanRecord(rows *sql.Rows) (session.Record, bool, error) {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return session.Record{}, false, storeError("读取会话", err)
		}
		return session.Record{}, false, nil
	}
	var (
		record            session.Record
		appID             string
		kindText          string
		reasonText        string
		stepsJSON         string
		strongAuthMS      sql.NullInt64
		createdMS         int64
		lastSeenMS        int64
		idleExpiresMS     int64
		absoluteExpiresMS int64
		revokedMS         sql.NullInt64
		revokeReason      string
	)
	if err := rows.Scan(
		&record.ID,
		&record.UserID,
		&appID,
		&kindText,
		&reasonText,
		&stepsJSON,
		&record.SecurityVersion,
		&record.SecretDigest,
		&record.CSRFDigest,
		&record.KeyID,
		&strongAuthMS,
		&record.RowVersion,
		&createdMS,
		&lastSeenMS,
		&idleExpiresMS,
		&absoluteExpiresMS,
		&revokedMS,
		&revokeReason,
	); err != nil {
		return session.Record{}, false, storeError("读取会话", err)
	}
	if err := rows.Err(); err != nil {
		return session.Record{}, false, storeError("读取会话", err)
	}
	record.AppID = appID
	record.Kind = session.Kind(kindText)
	record.Reason = session.Reason(reasonText)
	if !session.ValidCombination(record.Kind, record.Reason) {
		return session.Record{}, false, fmt.Errorf("%w: 会话类别或受限原因不一致", session.ErrStoreUnavailable)
	}
	steps, err := decodeSteps(stepsJSON)
	if err != nil {
		return session.Record{}, false, err
	}
	record.RequiredSteps = steps
	record.CreatedAt = fromUnixMilli(createdMS)
	record.LastSeenAt = fromUnixMilli(lastSeenMS)
	record.IdleExpiresAt = fromUnixMilli(idleExpiresMS)
	record.AbsoluteExpiresAt = fromUnixMilli(absoluteExpiresMS)
	if strongAuthMS.Valid {
		record.StrongAuthAt = fromUnixMilli(strongAuthMS.Int64)
	}
	if revokedMS.Valid {
		record.RevokedAt = fromUnixMilli(revokedMS.Int64)
	}
	record.RevokeReason = revokeReason
	return record, true, nil
}

// encodeSteps 把仍需完成的认证步骤编码为稳定 JSON 数组；不保存任何秘密。
func encodeSteps(steps []authn.Step) (string, error) {
	if len(steps) == 0 {
		return "[]", nil
	}
	values := make([]string, 0, len(steps))
	for _, step := range steps {
		if !step.Valid() {
			return "", fmt.Errorf("%w: 剩余认证步骤标识未知", session.ErrOptionsInvalid)
		}
		values = append(values, string(step))
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("%w: 无法编码剩余认证步骤", session.ErrStoreUnavailable)
	}
	return string(encoded), nil
}

// decodeSteps 解码剩余认证步骤；损坏或未知标识按存储不一致 fail-closed。
func decodeSteps(encoded string) ([]authn.Step, error) {
	if encoded == "" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(encoded), &values); err != nil {
		return nil, fmt.Errorf("%w: 剩余认证步骤数据损坏", session.ErrStoreUnavailable)
	}
	steps := make([]authn.Step, 0, len(values))
	for _, value := range values {
		step := authn.Step(value)
		if !step.Valid() {
			return nil, fmt.Errorf("%w: 剩余认证步骤标识未知", session.ErrStoreUnavailable)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// storeError 把原始 SQL 错误映射为安全的 ErrStoreUnavailable，不暴露驱动文本。
func storeError(operation string, err error) error {
	return fmt.Errorf("%w: %s", session.ErrStoreUnavailable, operation)
}

// toUnixMilli 把时间统一转换为 UTC 毫秒。
func toUnixMilli(value time.Time) int64 {
	return value.UTC().UnixMilli()
}

// fromUnixMilli 把毫秒时间转换为 UTC time.Time。
func fromUnixMilli(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}

// nullString 把空字符串写为 NULL（保留“未设置”语义）。
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// nullableTime 把零值时间写为 NULL。
func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return toUnixMilli(value)
}
