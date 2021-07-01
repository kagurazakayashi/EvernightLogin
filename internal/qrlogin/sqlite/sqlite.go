// Package sqlite 实现 internal/qrlogin 的 SQLite 持久化。
//
// 表结构由 migrations/0036_app_qr_login.sql 创建；本包不执行迁移、不拥有数据库
// 连接。领取绑定明文从不写入数据库：只保存 keyring HMAC-SHA256 摘要与 key_id。
// 所有状态迁移使用条件更新（status/版本/未过期），保证批准/取消/领取的并发单赢家。
package sqlite

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const requestColumns = `id,claim_digest,claim_key_id,client_id,scopes_json,request_version,
status,COALESCE(user_id,''),COALESCE(session_id,''),COALESCE(security_version,0),
auth_methods_json,requester_user_agent,requester_address,request_id,interval_seconds,
COALESCE(last_polled_at_ms,0),created_at_ms,expires_at_ms,
COALESCE(decided_at_ms,0),COALESCE(cancelled_at_ms,0),COALESCE(claimed_at_ms,0),
COALESCE(claimed_session_id,'')`

const (
	insertRequestSQL = `INSERT INTO app_qr_login_requests(
id,claim_digest,claim_key_id,client_id,scopes_json,request_version,status,user_id,
session_id,security_version,auth_methods_json,requester_user_agent,requester_address,
request_id,interval_seconds,last_polled_at_ms,created_at_ms,expires_at_ms,
decided_at_ms,cancelled_at_ms,claimed_at_ms,claimed_session_id)
VALUES(?,?,?,?,?,?,'pending',NULL,NULL,NULL,'[]',?,?,?,?,NULL,?,?,NULL,NULL,NULL,NULL)`

	selectRequestByIDSQL = `SELECT ` + requestColumns + `
FROM app_qr_login_requests WHERE id=?`

	selectRequestByClaimSQL = `SELECT ` + requestColumns + `
FROM app_qr_login_requests WHERE claim_digest=?`

	touchPollSQL = `UPDATE app_qr_login_requests SET last_polled_at_ms=?
WHERE id=? AND status IN('pending','approved') AND expires_at_ms>?`

	approveSQL = `UPDATE app_qr_login_requests
SET status='approved',user_id=?,session_id=?,security_version=?,auth_methods_json=?,decided_at_ms=?
WHERE id=? AND status='pending' AND request_version=? AND expires_at_ms>?`

	denySQL = `UPDATE app_qr_login_requests
SET status='denied',user_id=?,decided_at_ms=?
WHERE id=? AND status='pending' AND request_version=? AND expires_at_ms>?`

	cancelSQL = `UPDATE app_qr_login_requests
SET status='cancelled',cancelled_at_ms=?
WHERE id=? AND status IN('pending','approved') AND request_version=? AND expires_at_ms>?`

	consumeSQL = `UPDATE app_qr_login_requests
SET status='claimed',claimed_at_ms=?
WHERE id=? AND status='approved' AND request_version=? AND expires_at_ms>?`

	regenerateCancelSQL = `UPDATE app_qr_login_requests
SET status='cancelled',cancelled_at_ms=?
WHERE id=? AND status IN('pending','approved') AND request_version=? AND expires_at_ms>?`

	setClaimedSessionSQL = `UPDATE app_qr_login_requests SET claimed_session_id=?
WHERE id=? AND status='claimed'`
)

// Store 是 qrlogin.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 构造 SQLite 存储；底层存储为空时拒绝。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, qrlogin.ErrOptionsInvalid
	}
	return &Store{store: store}, nil
}

// 编译期断言实现 qrlogin.Store。
var _ qrlogin.Store = (*Store)(nil)

// CreateTx 在审计事务内创建 pending 扫码登录请求。
func (s *Store) CreateTx(ctx context.Context, tx audit.Tx, record qrlogin.RequestRecord) error {
	if tx == nil {
		return qrlogin.ErrOptionsInvalid
	}
	scopes, err := json.Marshal(nonNilStrings(record.Scopes))
	if err != nil {
		return qrlogin.ErrOptionsInvalid
	}
	digest := record.ClaimDigest
	if _, err := tx.ExecContext(ctx, insertRequestSQL,
		record.ID, digest[:], record.ClaimKeyID, record.ClientID, string(scopes),
		record.RequestVersion, record.RequesterUserAgent, record.RequesterAddress,
		record.RequestID, record.IntervalSeconds,
		record.CreatedAt.UTC().UnixMilli(), record.ExpiresAt.UTC().UnixMilli(),
	); err != nil {
		return qrlogin.ErrStoreUnavailable
	}
	return nil
}

// GetRequest 按请求标识读取记录。
func (s *Store) GetRequest(ctx context.Context, id string) (qrlogin.RequestRecord, bool, error) {
	return s.getRequest(ctx, selectRequestByIDSQL, id)
}

// GetByClaimDigest 按领取绑定摘要读取记录。
func (s *Store) GetByClaimDigest(ctx context.Context,
	digest [32]byte) (qrlogin.RequestRecord, bool, error) {
	return s.getRequest(ctx, selectRequestByClaimSQL, digest[:])
}

// getRequest 执行单行查询并扫描记录。
func (s *Store) getRequest(ctx context.Context, query string,
	argument any) (qrlogin.RequestRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, argument)
	if err != nil {
		return qrlogin.RequestRecord{}, false, qrlogin.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return qrlogin.RequestRecord{}, false, qrlogin.ErrStoreUnavailable
		}
		return qrlogin.RequestRecord{}, false, nil
	}
	record, err := scanRequest(rows)
	if err != nil {
		return qrlogin.RequestRecord{}, false, qrlogin.ErrStoreUnavailable
	}
	return record, true, nil
}

// scanner 是 *sql.Rows 的最小扫描接口（便于测试注入）。
type scanner interface {
	Scan(dest ...any) error
}

// scanRequest 把一行记录转换为内存模型。
func scanRequest(row scanner) (qrlogin.RequestRecord, error) {
	var (
		record             qrlogin.RequestRecord
		digest             []byte
		scopesJSON         string
		methodsJSON        string
		lastPolledAtMS     int64
		createdAtMS        int64
		expiresAtMS        int64
		decidedAtMS        int64
		cancelledAtMS      int64
		claimedAtMS        int64
		claimedSessionID   string
		userID             string
		sessionID          string
		securityVersion    int64
		requesterUserAgent string
		requesterAddress   string
	)
	if err := row.Scan(&record.ID, &digest, &record.ClaimKeyID, &record.ClientID,
		&scopesJSON, &record.RequestVersion, &record.Status, &userID, &sessionID,
		&securityVersion, &methodsJSON, &requesterUserAgent, &requesterAddress,
		&record.RequestID, &record.IntervalSeconds, &lastPolledAtMS, &createdAtMS,
		&expiresAtMS, &decidedAtMS, &cancelledAtMS, &claimedAtMS,
		&claimedSessionID); err != nil {
		return qrlogin.RequestRecord{}, err
	}
	if len(digest) != 32 {
		return qrlogin.RequestRecord{}, qrlogin.ErrStoreUnavailable
	}
	copy(record.ClaimDigest[:], digest)
	if err := json.Unmarshal([]byte(scopesJSON), &record.Scopes); err != nil {
		return qrlogin.RequestRecord{}, err
	}
	if err := json.Unmarshal([]byte(methodsJSON), &record.AuthMethods); err != nil {
		return qrlogin.RequestRecord{}, err
	}
	record.UserID = userID
	record.SessionID = sessionID
	record.SecurityVersion = securityVersion
	record.RequesterUserAgent = requesterUserAgent
	record.RequesterAddress = requesterAddress
	record.LastPolledAt = unixMilli(lastPolledAtMS)
	record.CreatedAt = unixMilli(createdAtMS)
	record.ExpiresAt = unixMilli(expiresAtMS)
	record.DecidedAt = unixMilli(decidedAtMS)
	record.CancelledAt = unixMilli(cancelledAtMS)
	record.ClaimedAt = unixMilli(claimedAtMS)
	record.ClaimedSessionID = claimedSessionID
	return record, nil
}

// TouchPoll 条件更新最近查询时间（服务端强制最小查询间隔）。
func (s *Store) TouchPoll(ctx context.Context, id string, polledAt time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx, touchPollSQL,
		polledAt.UTC().UnixMilli(), id, polledAt.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// ApproveTx 条件把 pending 迁移为 approved 并写入批准快照。
func (s *Store) ApproveTx(ctx context.Context, tx audit.Tx,
	approval qrlogin.ApprovalDecision) (bool, error) {
	if tx == nil {
		return false, qrlogin.ErrOptionsInvalid
	}
	methods := make([]string, 0, len(approval.AuthMethods))
	for _, method := range approval.AuthMethods {
		if !method.Valid() {
			return false, qrlogin.ErrInvalidRequest
		}
		methods = append(methods, string(method))
	}
	methodsJSON, err := json.Marshal(nonNilStrings(methods))
	if err != nil {
		return false, qrlogin.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, approveSQL, approval.UserID, approval.SessionID,
		approval.SecurityVersion, string(methodsJSON), approval.Now.UTC().UnixMilli(),
		approval.ID, approval.ExpectedVersion, approval.Now.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// DenyTx 条件把 pending 迁移为 denied。
func (s *Store) DenyTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
	userID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, denySQL, userID, now.UTC().UnixMilli(),
		id, expectedVersion, now.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// CancelTx 条件把 pending/approved 迁移为 cancelled。
func (s *Store) CancelTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
	now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, cancelSQL, now.UTC().UnixMilli(),
		id, expectedVersion, now.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// ConsumeTx 条件把 approved 迁移为 claimed（并发领取单赢家）。
func (s *Store) ConsumeTx(ctx context.Context, tx audit.Tx, id string, expectedVersion int64,
	now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, consumeSQL, now.UTC().UnixMilli(),
		id, expectedVersion, now.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// RegenerateTx 同一事务内取消旧请求并创建新请求。
func (s *Store) RegenerateTx(ctx context.Context, tx audit.Tx, oldID string,
	expectedVersion int64, now time.Time, record qrlogin.RequestRecord) (bool, error) {
	if tx == nil {
		return false, qrlogin.ErrOptionsInvalid
	}
	result, err := tx.ExecContext(ctx, regenerateCancelSQL, now.UTC().UnixMilli(),
		oldID, expectedVersion, now.UTC().UnixMilli())
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	updated, err := affectedOne(result)
	if err != nil || !updated {
		return false, err
	}
	if err := s.CreateTx(ctx, tx, record); err != nil {
		return false, err
	}
	return true, nil
}

// SetClaimedSession 尽力回写领取成功后的会话 ID。
func (s *Store) SetClaimedSession(ctx context.Context, id, sessionID string) (bool, error) {
	result, err := s.store.ExecContext(ctx, setClaimedSessionSQL, sessionID, id)
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affectedOne(result)
}

// affectedOne 报告条件更新是否影响一行。
func affectedOne(result sqlResult) (bool, error) {
	if result == nil {
		return false, nil
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, qrlogin.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// sqlResult 是 *sql.Result 的最小接口。
type sqlResult interface {
	RowsAffected() (int64, error)
}

// unixMilli 把毫秒时间戳转换为 UTC 时间；0 表示零值。
func unixMilli(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

// nonNilStrings 把 nil 切片替换为空切片，避免 JSON "null"。
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.TrimSpace(value))
	}
	return result
}
