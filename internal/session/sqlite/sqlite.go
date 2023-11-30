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
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms,revoked_at_ms,revoked_reason,
remember_me,client_user_agent,client_address,auth_methods_json`

	selectSessionByIDSQL = `SELECT ` + selectSessionColumns + ` FROM sessions WHERE id=?`

	// insertSessionSQL 写入一条新会话；数据库只保存验证摘要，绝不保存秘密明文。
	insertSessionSQL = `INSERT INTO sessions(
id,user_id,app_id,kind,restricted_reason,required_steps_json,security_version,
secret_digest,csrf_digest,key_id,strong_auth_verified_at_ms,row_version,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms,request_id,
remember_me,client_user_agent,client_address,auth_methods_json
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	// touchSessionSQL 条件续期：只有未撤销且未到期时才更新最后活动与空闲到期。
	touchSessionSQL = `UPDATE sessions
SET last_seen_at_ms=?,idle_expires_at_ms=?,row_version=row_version+1
WHERE id=? AND revoked_at_ms IS NULL AND idle_expires_at_ms>? AND absolute_expires_at_ms>?`

	// revokeSessionSQL 条件撤销单条会话；已撤销会话不会被重复计数。
	revokeSessionSQL = `UPDATE sessions
SET revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE id=? AND revoked_at_ms IS NULL`

	// revokeUserSessionsSQL 撤销账户全部活动会话（可按应用与保留会话追加条件）。
	revokeUserSessionsSQL = `UPDATE sessions
SET revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE user_id=? AND revoked_at_ms IS NULL
AND idle_expires_at_ms>? AND absolute_expires_at_ms>?`

	// revokeOldestSessionsSQL 保留最近活动的 keep 条会话，撤销其余活动会话。
	// 它使用单条条件 UPDATE 完成“计数 + 淘汰”，在调用方 IMMEDIATE 写事务内原子
	// 执行，避免并发登录时先查后写造成的超限竞态。
	revokeOldestSessionsSQL = `UPDATE sessions
SET revoked_at_ms=?,revoked_reason=?,row_version=row_version+1
WHERE user_id=? AND revoked_at_ms IS NULL AND idle_expires_at_ms>? AND absolute_expires_at_ms>?
AND id NOT IN (
 SELECT id FROM sessions
 WHERE user_id=? AND revoked_at_ms IS NULL AND idle_expires_at_ms>? AND absolute_expires_at_ms>?
 ORDER BY last_seen_at_ms DESC, created_at_ms DESC, id DESC LIMIT ?
)`

	// activeSessionsFilter 是“活动会话”的统一判定条件（未撤销且两道到期都未过）。
	activeSessionsFilter = `revoked_at_ms IS NULL AND idle_expires_at_ms>? AND absolute_expires_at_ms>?`

	countUserSessionsSQL = `SELECT COUNT(*) FROM sessions WHERE user_id=? AND ` + activeSessionsFilter

	selectUserStateSQL = `SELECT status,security_version,is_root,valid_from_ms,valid_until_ms FROM users WHERE id=?`

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
	methods, err := encodeMethods(record.AuthMethods)
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
		boolInt(record.RememberMe),
		record.ClientUserAgent,
		record.ClientAddress,
		methods,
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

// RevokeUser 撤销账户活动会话；AppID 非空时只限该应用，ExceptSessionID 非空时
// 保留该会话。返回实际撤销数量。所有条件写在同一条 UPDATE 中，避免先查后写。
func (s *Store) RevokeUser(ctx context.Context, tx audit.Tx, condition session.RevokeUserCondition) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	query := revokeUserSessionsSQL
	args := []any{toUnixMilli(condition.Now), condition.Reason, condition.UserID, toUnixMilli(condition.Now), toUnixMilli(condition.Now)}
	if condition.AppID != "" {
		query += ` AND app_id=?`
		args = append(args, condition.AppID)
	}
	if condition.ExceptSessionID != "" {
		query += ` AND id<>?`
		args = append(args, condition.ExceptSessionID)
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, storeError("批量撤销会话", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, storeError("批量撤销会话", err)
	}
	return affected, nil
}

// RevokeOldest 保留最近活动的 Keep 条活动会话，撤销其余活动会话，返回撤销数量。
// 单条条件 UPDATE 在调用方 IMMEDIATE 写事务内原子执行，供并发登录上限与单设备
// 策略使用，不存在“先计数后写入”的竞态窗口。
func (s *Store) RevokeOldest(ctx context.Context, tx audit.Tx, condition session.RevokeOldestCondition) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	if condition.Keep < 0 {
		return 0, fmt.Errorf("%w: 保留会话数量不能为负", session.ErrOptionsInvalid)
	}
	nowMS := toUnixMilli(condition.Now)
	result, err := tx.ExecContext(ctx, revokeOldestSessionsSQL,
		nowMS,
		condition.Reason,
		condition.UserID,
		nowMS,
		nowMS,
		condition.UserID,
		nowMS,
		nowMS,
		condition.Keep,
	)
	if err != nil {
		return 0, storeError("自动淘汰会话", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, storeError("自动淘汰会话", err)
	}
	return affected, nil
}

// CountActiveSessions 在调用方事务内统计账户活动会话数，供登录后数量约束复核。
func (s *Store) CountActiveSessions(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", session.ErrOptionsInvalid)
	}
	nowMS := toUnixMilli(now)
	rows, err := tx.QueryContext(ctx, countUserSessionsSQL, userID, nowMS, nowMS)
	if err != nil {
		return 0, storeError("统计活动会话", err)
	}
	var total int64
	if err := scanSingleValue(rows, &total); err != nil {
		return 0, err
	}
	return total, nil
}

// ListUserSessions 返回账户活动会话分页与总数；AppID 非空时只限该应用。只读取
// 活动（未撤销、空闲/绝对到期未过）会话，按最近活动倒序，同一活动时间用创建
// 时间与会话 ID 稳定排序，保证分页结果确定。
func (s *Store) ListUserSessions(ctx context.Context, query session.UserSessionQuery) (session.UserSessionPage, error) {
	nowMS := toUnixMilli(query.Now)
	countSQL := countUserSessionsSQL
	countArgs := []any{query.UserID, nowMS, nowMS}
	listSQL := `SELECT ` + selectSessionColumns + ` FROM sessions
WHERE user_id=? AND ` + activeSessionsFilter
	listArgs := []any{query.UserID, nowMS, nowMS}
	if query.AppID != "" {
		countSQL += ` AND app_id=?`
		countArgs = append(countArgs, query.AppID)
		listSQL += ` AND app_id=?`
		listArgs = append(listArgs, query.AppID)
	}
	listSQL += ` ORDER BY last_seen_at_ms DESC, created_at_ms DESC, id ASC LIMIT ? OFFSET ?`
	listArgs = append(listArgs, query.PageSize, query.Offset)
	rows, err := s.store.QueryContext(ctx, countSQL, countArgs...)
	if err != nil {
		return session.UserSessionPage{}, storeError("统计活动会话", err)
	}
	var total int64
	if err := scanSingleValue(rows, &total); err != nil {
		return session.UserSessionPage{}, err
	}
	sessionRows, err := s.store.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return session.UserSessionPage{}, storeError("读取活动会话", err)
	}
	defer sessionRows.Close()
	records := make([]session.Record, 0, query.PageSize)
	for sessionRows.Next() {
		record, ok, scanErr := scanRecordRow(sessionRows)
		if scanErr != nil {
			return session.UserSessionPage{}, scanErr
		}
		if !ok {
			break
		}
		records = append(records, record)
	}
	if err := sessionRows.Err(); err != nil {
		return session.UserSessionPage{}, storeError("读取活动会话", err)
	}
	return session.UserSessionPage{Records: records, Total: total}, nil
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
	var validFromMS sql.NullInt64
	var validUntilMS sql.NullInt64
	state := session.UserState{}
	if err := rows.Scan(&status, &state.SecurityVersion, &isRoot,
		&validFromMS, &validUntilMS); err != nil {
		return session.UserState{}, false, storeError("读取账户状态", err)
	}
	state.Status = account.Status(status)
	state.IsRoot = isRoot == 1
	state.ValidFrom = sessionTimeFromMilli(validFromMS)
	state.ValidUntil = sessionTimeFromMilli(validUntilMS)
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
	return scanRecordRow(rows)
}

// scanRecordRow 扫描当前游标指向的一行会话记录（不负责关闭游标），供单行读取与
// 列表分页共用同一列顺序。
func scanRecordRow(rows *sql.Rows) (session.Record, bool, error) {
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
		rememberMe        int
		methodsJSON       string
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
		&rememberMe,
		&record.ClientUserAgent,
		&record.ClientAddress,
		&methodsJSON,
	); err != nil {
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
	authMethods, err := decodeMethods(methodsJSON)
	if err != nil {
		return session.Record{}, false, err
	}
	record.AuthMethods = authMethods
	record.CreatedAt = fromUnixMilli(createdMS)
	record.LastSeenAt = fromUnixMilli(lastSeenMS)
	record.IdleExpiresAt = fromUnixMilli(idleExpiresMS)
	record.AbsoluteExpiresAt = fromUnixMilli(absoluteExpiresMS)
	record.RememberMe = rememberMe == 1
	if strongAuthMS.Valid {
		record.StrongAuthAt = fromUnixMilli(strongAuthMS.Int64)
	}
	if revokedMS.Valid {
		record.RevokedAt = fromUnixMilli(revokedMS.Int64)
	}
	record.RevokeReason = revokeReason
	return record, true, nil
}

// scanSingleValue 读取单行单列的整数值并关闭游标。
func scanSingleValue(rows *sql.Rows, value *int64) error {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return storeError("读取统计结果", err)
		}
		return storeError("读取统计结果", fmt.Errorf("没有结果行"))
	}
	if err := rows.Scan(value); err != nil {
		return storeError("读取统计结果", err)
	}
	return nil
}

// encodeMethods 把登录时真实完成的认证方法编码为稳定 JSON 数组；不保存秘密。
func encodeMethods(methods []authn.Method) (string, error) {
	if len(methods) == 0 {
		return "[]", nil
	}
	values := make([]string, 0, len(methods))
	for _, method := range methods {
		if !method.Valid() {
			return "", fmt.Errorf("%w: 认证方法标识未知", session.ErrOptionsInvalid)
		}
		values = append(values, string(method))
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("%w: 无法编码认证方法", session.ErrStoreUnavailable)
	}
	return string(encoded), nil
}

// decodeMethods 解码认证方法；损坏或未知标识按存储不一致 fail-closed。
func decodeMethods(encoded string) ([]authn.Method, error) {
	if encoded == "" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(encoded), &values); err != nil {
		return nil, fmt.Errorf("%w: 认证方法不是合法 JSON", session.ErrStoreUnavailable)
	}
	methods := make([]authn.Method, 0, len(values))
	for _, value := range values {
		method := authn.Method(value)
		if !method.Valid() {
			return nil, fmt.Errorf("%w: 认证方法标识未知", session.ErrStoreUnavailable)
		}
		methods = append(methods, method)
	}
	return methods, nil
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

// boolInt 把布尔值写为 0/1 整数列。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// nullableTime 把零值时间写为 NULL。
func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return toUnixMilli(value)
}

// sessionTimeFromMilli 把可空毫秒列转成 UTC 时间；NULL 表示该端不限制。
func sessionTimeFromMilli(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := time.UnixMilli(value.Int64).UTC()
	return &converted
}
