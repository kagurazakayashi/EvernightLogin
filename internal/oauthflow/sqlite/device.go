package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// 本文件实现步骤 57 设备授权（Device Authorization Grant）的 SQLite 仓储。
// 表结构由 migrations/0035_oauth_device_authorization.sql 创建；本包不执行迁移、
// 不拥有数据库连接。device_code/user_code 明文从不写入数据库：device_code 为
// 256 bit 高熵，只存无密钥 SHA-256 摘要；user_code 为低熵人工短码，只存带密钥
// HMAC-SHA256 摘要与 key_id（密钥环轮换后仍可核对历史记录）。状态迁移全部使用
// 条件更新，保证批准/取消/领取的并发单赢家。

const deviceColumns = `id,client_id,scope,audience_json,status,COALESCE(user_id,''),
COALESCE(session_id,''),COALESCE(security_version,0),interval_seconds,
COALESCE(last_polled_at_ms,0),request_id,created_at_ms,expires_at_ms,
COALESCE(decided_at_ms,0),COALESCE(cancelled_at_ms,0),COALESCE(consumed_at_ms,0),
user_code_key_id,user_code_digest`

const (
	insertDeviceAuthorizationSQL = `INSERT INTO oauth_device_authorizations(
id,device_code_sha256,user_code_digest,user_code_key_id,client_id,scope,audience_json,status,
user_id,session_id,security_version,interval_seconds,last_polled_at_ms,request_id,
created_at_ms,expires_at_ms,decided_at_ms,cancelled_at_ms,consumed_at_ms
) VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,NULL,?,NULL,?,?,?,NULL,NULL,NULL)`

	selectDeviceByDeviceCodeSQL = `SELECT ` + deviceColumns + `
FROM oauth_device_authorizations WHERE device_code_sha256=?`

	selectDeviceByUserCodeSQL = `SELECT ` + deviceColumns + `
FROM oauth_device_authorizations WHERE user_code_digest=?`

	// claimDevicePollSQL 是“服务端强制轮询间隔”的原子化：只有距上次轮询已满当前
	// 间隔（或从未轮询）、请求仍可轮询且未过期的调用方能更新成功，从而并发轮询
	// 无法绕过间隔。interval_seconds*1000 在 SQLite 中是整数运算。
	claimDevicePollSQL = `UPDATE oauth_device_authorizations SET last_polled_at_ms=?
WHERE id=? AND status IN('pending','approved') AND expires_at_ms>?
  AND (last_polled_at_ms IS NULL OR last_polled_at_ms + interval_seconds*1000 <= ?)`

	increaseDeviceIntervalSQL = `UPDATE oauth_device_authorizations
SET interval_seconds = MIN(interval_seconds + 5, 300)
WHERE id=? AND status IN('pending','approved') AND expires_at_ms>?`

	decideDeviceSQL = `UPDATE oauth_device_authorizations
SET status=?, user_id=?, session_id=?, security_version=?, decided_at_ms=?
WHERE id=? AND status='pending' AND expires_at_ms>?`

	cancelDeviceSQL = `UPDATE oauth_device_authorizations
SET status='cancelled', cancelled_at_ms=?
WHERE id=? AND status='pending' AND expires_at_ms>?`

	consumeDeviceSQL = `UPDATE oauth_device_authorizations
SET status='consumed', consumed_at_ms=?
WHERE id=? AND status='approved'`
)

// CreateDeviceAuthorizationTx 在审计事务内创建 pending 设备授权申请。
func (s *Store) CreateDeviceAuthorizationTx(ctx context.Context, tx audit.Tx,
	record oauthflow.DeviceAuthorizationRecord) error {
	if tx == nil {
		return oauthflow.ErrOptionsInvalid
	}
	audience, err := json.Marshal(record.Audiences)
	if err != nil {
		return oauthflow.ErrOptionsInvalid
	}
	if record.Audiences == nil {
		audience = []byte("[]")
	}
	if _, err := tx.ExecContext(ctx, insertDeviceAuthorizationSQL,
		record.ID, record.DeviceCodeSHA256[:], record.UserCodeDigest[:],
		record.UserCodeKeyID, record.ClientID, joinScopes(record.Scopes), string(audience),
		record.IntervalSeconds, record.RequestID,
		record.CreatedAt.UTC().UnixMilli(), record.ExpiresAt.UTC().UnixMilli(),
	); err != nil {
		return oauthflow.ErrStoreUnavailable
	}
	return nil
}

// GetDeviceAuthorizationByDeviceCodeHash 按 device_code 摘要读取申请。
func (s *Store) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context,
	digest [32]byte) (oauthflow.DeviceAuthorizationRecord, bool, error) {
	return s.getDeviceAuthorization(ctx, selectDeviceByDeviceCodeSQL, digest[:])
}

// GetDeviceAuthorizationByUserCodeDigest 按 user_code 的带密钥 HMAC 摘要读取申请。
func (s *Store) GetDeviceAuthorizationByUserCodeDigest(ctx context.Context,
	digest [32]byte) (oauthflow.DeviceAuthorizationRecord, bool, error) {
	return s.getDeviceAuthorization(ctx, selectDeviceByUserCodeSQL, digest[:])
}

func (s *Store) getDeviceAuthorization(ctx context.Context, query string,
	digest []byte) (oauthflow.DeviceAuthorizationRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, digest)
	if err != nil {
		return oauthflow.DeviceAuthorizationRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthflow.DeviceAuthorizationRecord{}, false, rows.Err()
	}
	record, err := scanDeviceAuthorization(rows)
	if err != nil {
		return oauthflow.DeviceAuthorizationRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	return record, true, nil
}

// ClaimDevicePollSlot 条件更新轮询时间，返回是否赢得本次轮询槽位。
func (s *Store) ClaimDevicePollSlot(ctx context.Context, recordID string,
	now time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx, claimDevicePollSQL,
		now.UTC().UnixMilli(), recordID, now.UTC().UnixMilli(), now.UTC().UnixMilli())
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// IncreaseDevicePollInterval 在 slow_down 时增大间隔并返回新间隔（秒）。
func (s *Store) IncreaseDevicePollInterval(ctx context.Context, recordID string,
	now time.Time) (int, error) {
	if _, err := s.store.ExecContext(ctx, increaseDeviceIntervalSQL, recordID,
		now.UTC().UnixMilli()); err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	rows, err := s.store.QueryContext(ctx,
		`SELECT interval_seconds FROM oauth_device_authorizations WHERE id=?`, recordID)
	if err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, oauthflow.ErrStoreUnavailable
	}
	var interval int
	if err := rows.Scan(&interval); err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	return interval, nil
}

// DecideDeviceAuthorizationTx 条件把 pending 迁移为 approved/denied。
func (s *Store) DecideDeviceAuthorizationTx(ctx context.Context, tx audit.Tx,
	recordID, status, userID, sessionID string, securityVersion int64,
	now time.Time) (bool, error) {
	if tx == nil {
		return false, oauthflow.ErrOptionsInvalid
	}
	var version any
	if securityVersion > 0 {
		version = securityVersion
	}
	result, err := tx.ExecContext(ctx, decideDeviceSQL, status, nullIfEmpty(userID),
		nullIfEmpty(sessionID), version, now.UTC().UnixMilli(), recordID,
		now.UTC().UnixMilli())
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// CancelDeviceAuthorizationTx 条件把 pending 迁移为 cancelled。
func (s *Store) CancelDeviceAuthorizationTx(ctx context.Context, tx audit.Tx,
	recordID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, oauthflow.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, cancelDeviceSQL, now.UTC().UnixMilli(), recordID,
		now.UTC().UnixMilli())
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// ConsumeDeviceAuthorizationTx 条件把 approved 迁移为 consumed。
func (s *Store) ConsumeDeviceAuthorizationTx(ctx context.Context, tx audit.Tx,
	recordID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, oauthflow.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, consumeDeviceSQL, now.UTC().UnixMilli(), recordID)
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// scanDeviceAuthorization 扫描一行设备授权记录（时间列使用毫秒整数）。
func scanDeviceAuthorization(rows rowScanner) (oauthflow.DeviceAuthorizationRecord, error) {
	var (
		record      oauthflow.DeviceAuthorizationRecord
		scope       string
		audienceRaw string
		createdMS   int64
		expiresMS   int64
		decidedMS   int64
		cancelledMS int64
		consumedMS  int64
		lastPollMS  int64
		userDigest  []byte
	)
	if err := rows.Scan(&record.ID, &record.ClientID, &scope, &audienceRaw,
		&record.Status, &record.UserID, &record.SessionID, &record.SecurityVersion,
		&record.IntervalSeconds, &lastPollMS, &record.RequestID, &createdMS,
		&expiresMS, &decidedMS, &cancelledMS, &consumedMS,
		&record.UserCodeKeyID, &userDigest); err != nil {
		return oauthflow.DeviceAuthorizationRecord{}, err
	}
	if len(userDigest) == 32 {
		copy(record.UserCodeDigest[:], userDigest)
	}
	record.Scopes = parseScopes(scope)
	if err := json.Unmarshal([]byte(audienceRaw), &record.Audiences); err != nil {
		return oauthflow.DeviceAuthorizationRecord{}, err
	}
	record.CreatedAt = deviceTime(createdMS)
	record.ExpiresAt = deviceTime(expiresMS)
	record.DecidedAt = deviceTime(decidedMS)
	record.CancelledAt = deviceTime(cancelledMS)
	record.ConsumedAt = deviceTime(consumedMS)
	record.LastPolledAt = deviceTime(lastPollMS)
	return record, nil
}

// deviceTime 把毫秒时间戳还原为 UTC 时间；0 表示该事件尚未发生。
func deviceTime(millis int64) time.Time {
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis).UTC()
}
