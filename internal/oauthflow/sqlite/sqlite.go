// Package sqlite 实现 internal/oauthflow.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0031_oauth_authorization.sql 创建；本包不执行迁移、不拥有数据库
// 连接。授权码只保存 SHA-256 摘要；确认请求与授权码的状态迁移使用条件更新，保证
// 确认决定/授权码兑换的并发单赢家。所有变更必须在调用方审计事务内完成。
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const requestColumns = `id,user_id,client_id,redirect_uri,response_type,scope,audience_json,
state,nonce,code_challenge,code_challenge_method,session_id,security_version,status,
request_id,created_at_ms,expires_at_ms,COALESCE(decided_at_ms,0)`

const codeColumns = `id,code_sha256,authorization_request_id,user_id,client_id,redirect_uri,
scope,audience_json,nonce,code_challenge,code_challenge_method,session_id,security_version,
request_id,issued_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0),COALESCE(replayed_at_ms,0)`

const (
	insertRequestSQL = `INSERT INTO oauth_authorization_requests(
id,user_id,client_id,redirect_uri,response_type,scope,audience_json,state,nonce,
code_challenge,code_challenge_method,session_id,security_version,status,request_id,
created_at_ms,expires_at_ms,decided_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,NULL)`

	selectRequestSQL = `SELECT ` + requestColumns + ` FROM oauth_authorization_requests WHERE id=?`

	decideRequestSQL = `UPDATE oauth_authorization_requests SET status=?,decided_at_ms=?
WHERE id=? AND status='pending' AND expires_at_ms>?`

	insertCodeSQL = `INSERT INTO oauth_authorization_codes(
id,code_sha256,authorization_request_id,user_id,client_id,redirect_uri,scope,audience_json,
nonce,code_challenge,code_challenge_method,session_id,security_version,request_id,
issued_at_ms,expires_at_ms,consumed_at_ms,replayed_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)`

	selectCodeByHashSQL = `SELECT ` + codeColumns + ` FROM oauth_authorization_codes
WHERE code_sha256=?`

	consumeCodeSQL = `UPDATE oauth_authorization_codes SET consumed_at_ms=?
WHERE id=? AND consumed_at_ms IS NULL AND expires_at_ms>?`

	replayCodeSQL = `UPDATE oauth_authorization_codes SET replayed_at_ms=COALESCE(replayed_at_ms,?)
WHERE id=?`

	userStateSQL = `SELECT id,status,is_root,security_version FROM users WHERE id=?`

	membershipSQL = `SELECT COUNT(*) FROM app_memberships
WHERE user_id=? AND app_id=? AND status='active'`

	sessionSnapshotSQL = `SELECT id,user_id,COALESCE(app_id,''),kind,security_version,
COALESCE(strong_auth_verified_at_ms,0),idle_expires_at_ms,absolute_expires_at_ms,
COALESCE(revoked_at_ms,0) FROM sessions WHERE id=?`
)

// Store 是 oauthflow.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", oauthflow.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ oauthflow.Store = (*Store)(nil)

// CreateAuthorizationRequestTx 在审计事务内创建 pending 确认请求。
func (s *Store) CreateAuthorizationRequestTx(ctx context.Context, tx audit.Tx,
	request oauthflow.AuthorizationRequestRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	audience, err := json.Marshal(request.Audiences)
	if err != nil {
		return fmt.Errorf("%w: 目标资源编码失败", oauthflow.ErrOptionsInvalid)
	}
	if request.Audiences == nil {
		audience = []byte("[]")
	}
	if _, err := tx.ExecContext(ctx, insertRequestSQL,
		request.ID, request.UserID, request.ClientID, request.RedirectURI,
		request.ResponseType, joinScopes(request.Scopes), string(audience),
		request.State, request.Nonce, request.CodeChallenge, request.CodeChallengeMethod,
		request.SessionID, request.SecurityVersion, request.RequestID,
		request.CreatedAt.UTC().UnixMilli(), request.ExpiresAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// GetAuthorizationRequest 读取确认请求。
func (s *Store) GetAuthorizationRequest(ctx context.Context,
	requestID string) (oauthflow.AuthorizationRequestRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRequestSQL, requestID)
	if err != nil {
		return oauthflow.AuthorizationRequestRecord{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return oauthflow.AuthorizationRequestRecord{}, false, fmt.Errorf("%w: %w",
				oauthflow.ErrStoreUnavailable, err)
		}
		return oauthflow.AuthorizationRequestRecord{}, false, nil
	}
	record, scanErr := scanRequest(rows)
	if scanErr != nil {
		return oauthflow.AuthorizationRequestRecord{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, scanErr)
	}
	return record, true, nil
}

// DecideAuthorizationRequestTx 条件迁移 pending 请求。
func (s *Store) DecideAuthorizationRequestTx(ctx context.Context, tx audit.Tx,
	requestID, status string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, decideRequestSQL, status, now.UTC().UnixMilli(),
		requestID, now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// CreateAuthorizationCodeTx 在审计事务内插入授权码摘要。
func (s *Store) CreateAuthorizationCodeTx(ctx context.Context, tx audit.Tx,
	code oauthflow.AuthorizationCodeRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	audience, err := json.Marshal(code.Audiences)
	if err != nil {
		return fmt.Errorf("%w: 目标资源编码失败", oauthflow.ErrOptionsInvalid)
	}
	if code.Audiences == nil {
		audience = []byte("[]")
	}
	digest := code.CodeSHA256
	if _, err := tx.ExecContext(ctx, insertCodeSQL,
		code.ID, digest[:], code.RequestRef, code.UserID, code.ClientID, code.RedirectURI,
		joinScopes(code.Scopes), string(audience), code.Nonce, code.CodeChallenge,
		code.CodeChallengeMethod, code.SessionID, code.SecurityVersion, code.RequestID,
		code.IssuedAt.UTC().UnixMilli(), code.ExpiresAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// GetAuthorizationCodeByHash 按摘要读取授权码。
func (s *Store) GetAuthorizationCodeByHash(ctx context.Context,
	digest [32]byte) (oauthflow.AuthorizationCodeRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectCodeByHashSQL, digest[:])
	if err != nil {
		return oauthflow.AuthorizationCodeRecord{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return oauthflow.AuthorizationCodeRecord{}, false, fmt.Errorf("%w: %w",
				oauthflow.ErrStoreUnavailable, err)
		}
		return oauthflow.AuthorizationCodeRecord{}, false, nil
	}
	code, scanErr := scanCode(rows)
	if scanErr != nil {
		return oauthflow.AuthorizationCodeRecord{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, scanErr)
	}
	return code, true, nil
}

// ConsumeAuthorizationCodeTx 条件消费未过期未消费的授权码。
func (s *Store) ConsumeAuthorizationCodeTx(ctx context.Context, tx audit.Tx,
	codeID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, consumeCodeSQL, now.UTC().UnixMilli(), codeID,
		now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// MarkAuthorizationCodeReplayed 记录重复兑换探测。
func (s *Store) MarkAuthorizationCodeReplayed(ctx context.Context, codeID string,
	now time.Time) error {
	if _, err := s.store.ExecContext(ctx, replayCodeSQL, now.UTC().UnixMilli(), codeID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// UserState 读取账户状态快照。
func (s *Store) UserState(ctx context.Context, userID string) (oauthflow.UserState, bool, error) {
	rows, err := s.store.QueryContext(ctx, userStateSQL, userID)
	if err != nil {
		return oauthflow.UserState{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthflow.UserState{}, false, nil
	}
	var (
		state  oauthflow.UserState
		isRoot int
	)
	if err := rows.Scan(&state.UserID, &state.Status, &isRoot, &state.SecurityVersion); err != nil {
		return oauthflow.UserState{}, false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	state.IsRoot = isRoot != 0
	return state, true, nil
}

// MembershipActive 报告用户是否为应用的 active 成员。
func (s *Store) MembershipActive(ctx context.Context, userID, appID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, membershipSQL, userID, appID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, nil
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

// SessionSnapshot 读取授权码绑定会话的服务端状态。
func (s *Store) SessionSnapshot(ctx context.Context,
	sessionID string) (oauthflow.SessionSnapshot, bool, error) {
	rows, err := s.store.QueryContext(ctx, sessionSnapshotSQL, sessionID)
	if err != nil {
		return oauthflow.SessionSnapshot{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthflow.SessionSnapshot{}, false, nil
	}
	var (
		snapshot     oauthflow.SessionSnapshot
		strongAuthMS int64
		idleMS       int64
		absoluteMS   int64
		revokedMS    int64
	)
	if err := rows.Scan(&snapshot.ID, &snapshot.UserID, &snapshot.AppID, &snapshot.Kind,
		&snapshot.SecurityVersion, &strongAuthMS, &idleMS, &absoluteMS, &revokedMS); err != nil {
		return oauthflow.SessionSnapshot{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	if strongAuthMS > 0 {
		snapshot.StrongAuthAt = time.UnixMilli(strongAuthMS).UTC()
	}
	snapshot.IdleExpiresAt = time.UnixMilli(idleMS).UTC()
	snapshot.AbsoluteExpiresAt = time.UnixMilli(absoluteMS).UTC()
	if revokedMS > 0 {
		snapshot.RevokedAt = time.UnixMilli(revokedMS).UTC()
	}
	return snapshot, true, nil
}

// ===== 行扫描辅助 =====

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRequest(rows rowScanner) (oauthflow.AuthorizationRequestRecord, error) {
	var (
		record      oauthflow.AuthorizationRequestRecord
		scope       string
		audienceRaw string
		createdMS   int64
		expiresMS   int64
		decidedMS   int64
	)
	if err := rows.Scan(&record.ID, &record.UserID, &record.ClientID, &record.RedirectURI,
		&record.ResponseType, &scope, &audienceRaw, &record.State, &record.Nonce,
		&record.CodeChallenge, &record.CodeChallengeMethod, &record.SessionID,
		&record.SecurityVersion, &record.Status, &record.RequestID, &createdMS, &expiresMS,
		&decidedMS); err != nil {
		return oauthflow.AuthorizationRequestRecord{}, err
	}
	record.Scopes = parseScopes(scope)
	if err := json.Unmarshal([]byte(audienceRaw), &record.Audiences); err != nil {
		return oauthflow.AuthorizationRequestRecord{}, err
	}
	record.CreatedAt = time.UnixMilli(createdMS).UTC()
	record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if decidedMS > 0 {
		record.DecidedAt = time.UnixMilli(decidedMS).UTC()
	}
	return record, nil
}

func scanCode(rows rowScanner) (oauthflow.AuthorizationCodeRecord, error) {
	var (
		code        oauthflow.AuthorizationCodeRecord
		digest      []byte
		scope       string
		audienceRaw string
		issuedMS    int64
		expiresMS   int64
		consumedMS  int64
		replayedMS  int64
	)
	if err := rows.Scan(&code.ID, &digest, &code.RequestRef, &code.UserID, &code.ClientID,
		&code.RedirectURI, &scope, &audienceRaw, &code.Nonce, &code.CodeChallenge,
		&code.CodeChallengeMethod, &code.SessionID, &code.SecurityVersion, &code.RequestID,
		&issuedMS, &expiresMS, &consumedMS, &replayedMS); err != nil {
		return oauthflow.AuthorizationCodeRecord{}, err
	}
	if len(digest) != 32 {
		return oauthflow.AuthorizationCodeRecord{}, fmt.Errorf("授权码摘要长度非法")
	}
	copy(code.CodeSHA256[:], digest)
	code.Scopes = parseScopes(scope)
	if err := json.Unmarshal([]byte(audienceRaw), &code.Audiences); err != nil {
		return oauthflow.AuthorizationCodeRecord{}, err
	}
	code.IssuedAt = time.UnixMilli(issuedMS).UTC()
	code.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if consumedMS > 0 {
		code.ConsumedAt = time.UnixMilli(consumedMS).UTC()
	}
	if replayedMS > 0 {
		code.ReplayedAt = time.UnixMilli(replayedMS).UTC()
	}
	return code, nil
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

func parseScopes(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}
