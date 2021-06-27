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
request_id,created_at_ms,expires_at_ms,COALESCE(decided_at_ms,0),auth_time_ms,auth_methods_json`

const codeColumns = `id,code_sha256,authorization_request_id,user_id,client_id,redirect_uri,
scope,audience_json,nonce,code_challenge,code_challenge_method,session_id,security_version,
request_id,issued_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0),COALESCE(replayed_at_ms,0),
auth_time_ms,auth_methods_json`

const (
	insertRequestSQL = `INSERT INTO oauth_authorization_requests(
id,user_id,client_id,redirect_uri,response_type,scope,audience_json,state,nonce,
code_challenge,code_challenge_method,session_id,security_version,status,request_id,
created_at_ms,expires_at_ms,decided_at_ms,auth_time_ms,auth_methods_json
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,NULL,?,?)`

	selectRequestSQL = `SELECT ` + requestColumns + ` FROM oauth_authorization_requests WHERE id=?`

	decideRequestSQL = `UPDATE oauth_authorization_requests SET status=?,decided_at_ms=?
WHERE id=? AND status='pending' AND expires_at_ms>?`

	insertCodeSQL = `INSERT INTO oauth_authorization_codes(
id,code_sha256,authorization_request_id,user_id,client_id,redirect_uri,scope,audience_json,
nonce,code_challenge,code_challenge_method,session_id,security_version,request_id,
issued_at_ms,expires_at_ms,consumed_at_ms,replayed_at_ms,auth_time_ms,auth_methods_json
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,?)`

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
COALESCE(revoked_at_ms,0),created_at_ms,auth_methods_json FROM sessions WHERE id=?`
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
		request.CreatedAt.UTC().UnixMilli(), request.ExpiresAt.UTC().UnixMilli(),
		authTimeMillis(request.AuthTime), string(mustJSON(request.AuthMethods, "[]")),
	); err != nil {
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
		code.IssuedAt.UTC().UnixMilli(), code.ExpiresAt.UTC().UnixMilli(),
		authTimeMillis(code.AuthTime), string(mustJSON(code.AuthMethods, "[]")),
	); err != nil {
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
		createdMS    int64
		methodsJSON  string
	)
	if err := rows.Scan(&snapshot.ID, &snapshot.UserID, &snapshot.AppID, &snapshot.Kind,
		&snapshot.SecurityVersion, &strongAuthMS, &idleMS, &absoluteMS, &revokedMS,
		&createdMS, &methodsJSON); err != nil {
		return oauthflow.SessionSnapshot{}, false, fmt.Errorf("%w: %w",
			oauthflow.ErrStoreUnavailable, err)
	}
	if strongAuthMS > 0 {
		snapshot.StrongAuthAt = time.UnixMilli(strongAuthMS).UTC()
	}
	snapshot.AuthTime = time.UnixMilli(createdMS).UTC()
	if err := json.Unmarshal([]byte(methodsJSON), &snapshot.AuthMethods); err != nil {
		return oauthflow.SessionSnapshot{}, false, fmt.Errorf("%w: 认证方法不是合法 JSON",
			oauthflow.ErrStoreUnavailable)
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
		authTimeMS  int64
		methodsJSON string
	)
	if err := rows.Scan(&record.ID, &record.UserID, &record.ClientID, &record.RedirectURI,
		&record.ResponseType, &scope, &audienceRaw, &record.State, &record.Nonce,
		&record.CodeChallenge, &record.CodeChallengeMethod, &record.SessionID,
		&record.SecurityVersion, &record.Status, &record.RequestID, &createdMS, &expiresMS,
		&decidedMS, &authTimeMS, &methodsJSON); err != nil {
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
	if authTimeMS > 0 {
		record.AuthTime = time.UnixMilli(authTimeMS).UTC()
	}
	if err := json.Unmarshal([]byte(methodsJSON), &record.AuthMethods); err != nil {
		return oauthflow.AuthorizationRequestRecord{}, err
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
		authTimeMS  int64
		methodsJSON string
	)
	if err := rows.Scan(&code.ID, &digest, &code.RequestRef, &code.UserID, &code.ClientID,
		&code.RedirectURI, &scope, &audienceRaw, &code.Nonce, &code.CodeChallenge,
		&code.CodeChallengeMethod, &code.SessionID, &code.SecurityVersion, &code.RequestID,
		&issuedMS, &expiresMS, &consumedMS, &replayedMS, &authTimeMS, &methodsJSON); err != nil {
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
	if authTimeMS > 0 {
		code.AuthTime = time.UnixMilli(authTimeMS).UTC()
	}
	if err := json.Unmarshal([]byte(methodsJSON), &code.AuthMethods); err != nil {
		return oauthflow.AuthorizationCodeRecord{}, err
	}
	return code, nil
}

// authTimeMillis 把认证时间转为毫秒；零值写 0（表示无可用认证事实）。
func authTimeMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixMilli()
}

// mustJSON 编码稳定字符串数组；编码失败返回 fallback（仅接受静态合法值）。
func mustJSON(values []string, fallback string) []byte {
	if values == nil {
		return []byte(fallback)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return []byte(fallback)
	}
	return encoded
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

func parseScopes(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}

// ===== 刷新令牌（步骤 54） =====

const insertRefreshFamilySQL = `INSERT INTO refresh_token_families(
id,client_id,subject_user_id,authorization_id,scope,audiences_json,security_version,
created_at_ms,absolute_expires_at_ms,idle_timeout_ms,revoked_at_ms,revoke_reason)
VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)`

const insertRefreshTokenSQL = `INSERT INTO refresh_tokens(
id,family_id,token_sha256,status,issued_at_ms,idle_expires_at_ms,expires_at_ms,
used_at_ms,revoked_at_ms,revoke_reason,replaced_by_id,request_id)
VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL,?,?)`

const selectRefreshTokenSQL = `SELECT id,family_id,token_sha256,status,issued_at_ms,
idle_expires_at_ms,expires_at_ms,COALESCE(used_at_ms,0),COALESCE(revoked_at_ms,0),
COALESCE(revoke_reason,''),COALESCE(replaced_by_id,''),COALESCE(request_id,'')
FROM refresh_tokens WHERE token_sha256=?`

const selectRefreshFamilySQL = `SELECT id,client_id,subject_user_id,authorization_id,scope,
audiences_json,security_version,created_at_ms,absolute_expires_at_ms,idle_timeout_ms,
COALESCE(revoked_at_ms,0),COALESCE(revoke_reason,'')
FROM refresh_token_families WHERE id=?`

const consumeRefreshTokenSQL = `UPDATE refresh_tokens SET status='used',used_at_ms=?
WHERE id=? AND status='active' AND idle_expires_at_ms>?`

const expireRefreshTokenSQL = `UPDATE refresh_tokens SET status='expired',revoked_at_ms=?,
revoke_reason='idle_expired' WHERE id=? AND status='active'`

const revokeRefreshFamilySQL = `UPDATE refresh_token_families SET revoked_at_ms=?,
revoke_reason=? WHERE id=? AND revoked_at_ms IS NULL`

const revokeRefreshFamilyTokensSQL = `UPDATE refresh_tokens SET status='revoked',
revoked_at_ms=?,revoke_reason=? WHERE family_id=? AND status='active'`

// CreateRefreshFamilyTx 在审计事务内创建刷新令牌族与首个令牌。
func (s *Store) CreateRefreshFamilyTx(ctx context.Context, tx audit.Tx, family oauthflow.RefreshFamilyRecord,
	refreshToken oauthflow.RefreshTokenRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertRefreshFamilySQL, family.ID, family.ClientID,
		family.SubjectUserID, family.AuthorizationID, joinScopes(family.Scopes),
		string(mustJSON(family.Audiences, "[]")), family.SecurityVersion,
		family.CreatedAt.UnixMilli(), family.AbsoluteExpiresAt.UnixMilli(),
		family.IdleTimeout.Milliseconds()); err != nil {
		return oauthflow.ErrStoreUnavailable
	}
	return s.InsertRefreshTokenTx(ctx, tx, refreshToken)
}

// GetRefreshTokenByHash 按摘要读取刷新令牌记录。
func (s *Store) GetRefreshTokenByHash(ctx context.Context, digest [32]byte) (oauthflow.RefreshTokenRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRefreshTokenSQL, digest[:])
	if err != nil {
		return oauthflow.RefreshTokenRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthflow.RefreshTokenRecord{}, false, rows.Err()
	}
	var record oauthflow.RefreshTokenRecord
	var digestBytes []byte
	var status string
	var issuedMS, idleMS, expiresMS, usedMS, revokedMS int64
	if err := rows.Scan(&record.ID, &record.FamilyID, &digestBytes, &status, &issuedMS,
		&idleMS, &expiresMS, &usedMS, &revokedMS, &record.RevokeReason,
		&record.ReplacedByID, &record.RequestID); err != nil {
		return oauthflow.RefreshTokenRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	if len(digestBytes) != 32 {
		return oauthflow.RefreshTokenRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	copy(record.TokenSHA256[:], digestBytes)
	record.Status = status
	record.IssuedAt = time.UnixMilli(issuedMS).UTC()
	record.IdleExpiresAt = time.UnixMilli(idleMS).UTC()
	record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if usedMS != 0 {
		record.UsedAt = time.UnixMilli(usedMS).UTC()
	}
	if revokedMS != 0 {
		record.RevokedAt = time.UnixMilli(revokedMS).UTC()
	}
	return record, true, nil
}

// GetRefreshFamily 按 ID 读取刷新令牌族。
func (s *Store) GetRefreshFamily(ctx context.Context, familyID string) (oauthflow.RefreshFamilyRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRefreshFamilySQL, familyID)
	if err != nil {
		return oauthflow.RefreshFamilyRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return oauthflow.RefreshFamilyRecord{}, false, rows.Err()
	}
	var record oauthflow.RefreshFamilyRecord
	var scope, audiencesJSON, revokeReason string
	var createdMS, absoluteMS, revokedMS, idleTimeoutMS int64
	if err := rows.Scan(&record.ID, &record.ClientID, &record.SubjectUserID,
		&record.AuthorizationID, &scope, &audiencesJSON, &record.SecurityVersion,
		&createdMS, &absoluteMS, &idleTimeoutMS, &revokedMS, &revokeReason); err != nil {
		return oauthflow.RefreshFamilyRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	record.Scopes = parseScopes(scope)
	if err := json.Unmarshal([]byte(audiencesJSON), &record.Audiences); err != nil {
		return oauthflow.RefreshFamilyRecord{}, false, oauthflow.ErrStoreUnavailable
	}
	record.CreatedAt = time.UnixMilli(createdMS).UTC()
	record.AbsoluteExpiresAt = time.UnixMilli(absoluteMS).UTC()
	record.IdleTimeout = time.Duration(idleTimeoutMS) * time.Millisecond
	if revokedMS != 0 {
		record.RevokedAt = time.UnixMilli(revokedMS).UTC()
	}
	record.RevokeReason = revokeReason
	return record, true, nil
}

// ConsumeRefreshTokenTx 条件消费 active 刷新令牌。
func (s *Store) ConsumeRefreshTokenTx(ctx context.Context, tx audit.Tx, tokenID string,
	now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, consumeRefreshTokenSQL, now.UnixMilli(), tokenID, now.UnixMilli())
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// InsertRefreshTokenTx 在审计事务内插入轮换产生的新刷新令牌。
func (s *Store) InsertRefreshTokenTx(ctx context.Context, tx audit.Tx,
	refreshToken oauthflow.RefreshTokenRecord) error {
	_, err := tx.ExecContext(ctx, insertRefreshTokenSQL, refreshToken.ID, refreshToken.FamilyID,
		refreshToken.TokenSHA256[:], refreshToken.Status, refreshToken.IssuedAt.UnixMilli(),
		refreshToken.IdleExpiresAt.UnixMilli(), refreshToken.ExpiresAt.UnixMilli(),
		nullIfEmpty(refreshToken.ReplacedByID), nullIfEmpty(refreshToken.RequestID))
	if err != nil {
		return oauthflow.ErrStoreUnavailable
	}
	return nil
}

// ExpireRefreshTokenTx 条件标记空闲到期的刷新令牌。
func (s *Store) ExpireRefreshTokenTx(ctx context.Context, tx audit.Tx, tokenID string,
	now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, expireRefreshTokenSQL, now.UnixMilli(), tokenID)
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return refreshRowsAffected(result)
}

// RevokeRefreshFamilyTx 撤销整族及其全部 active 令牌。
func (s *Store) RevokeRefreshFamilyTx(ctx context.Context, tx audit.Tx, familyID, reason string,
	now time.Time) (int64, error) {
	if _, err := tx.ExecContext(ctx, revokeRefreshFamilySQL, now.UnixMilli(), reason, familyID); err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	result, err := tx.ExecContext(ctx, revokeRefreshFamilyTokensSQL, now.UnixMilli(), reason, familyID)
	if err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, oauthflow.ErrStoreUnavailable
	}
	return affected, nil
}

// refreshRowsAffected 把条件更新结果转换为“恰好一行生效”。
func refreshRowsAffected(result interface{ RowsAffected() (int64, error) }) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, oauthflow.ErrStoreUnavailable
	}
	return affected == 1, nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ===== 步骤 55：授权撤回、令牌撤销与退出联动 =====

const selectRefreshFamiliesFilterSQL = `SELECT id,client_id,subject_user_id,authorization_id,
scope,audiences_json,security_version,created_at_ms,absolute_expires_at_ms,idle_timeout_ms,
COALESCE(revoked_at_ms,0),COALESCE(revoke_reason,'')
FROM refresh_token_families
WHERE (?='' OR subject_user_id=?) AND (?='' OR client_id=?) AND (?='' OR authorization_id=?)
ORDER BY created_at_ms`

const revokeAuthorizationCodesSQL = `UPDATE oauth_authorization_codes SET revoked_at_ms=?
WHERE consumed_at_ms IS NULL AND revoked_at_ms IS NULL
  AND (?='' OR user_id=?) AND (?='' OR client_id=?) AND (?='' OR authorization_request_id=?)`

const upsertClientUserRevocationSQL = `INSERT INTO oauth_client_user_revocations(
user_id,client_id,revoked_at_ms,reason,request_id) VALUES(?,?,?,?,?)
ON CONFLICT(user_id,client_id) DO UPDATE SET revoked_at_ms=excluded.revoked_at_ms,
reason=excluded.reason,request_id=excluded.request_id`

const upsertUserRevocationSQL = `INSERT INTO oauth_user_revocations(
user_id,revoked_at_ms,reason,request_id) VALUES(?,?,?,?)
ON CONFLICT(user_id) DO UPDATE SET revoked_at_ms=excluded.revoked_at_ms,
reason=excluded.reason,request_id=excluded.request_id`

const insertAccessTokenRevocationSQL = `INSERT INTO oauth_access_token_revocations(
jti,client_id,user_id,subject_type,revoked_at_ms,expires_at_ms,reason,request_id)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(jti) DO NOTHING`

const selectAccessTokenRevocationSQL = `SELECT COUNT(*) FROM oauth_access_token_revocations WHERE jti=?`

const selectRevocationTimesSQL = `SELECT COALESCE((SELECT revoked_at_ms FROM oauth_user_revocations WHERE user_id=?),0),
COALESCE((SELECT revoked_at_ms FROM oauth_client_user_revocations WHERE user_id=? AND client_id=?),0)`

const selectActiveAppSessionsSQL = `SELECT id FROM sessions
WHERE user_id=? AND app_id=? AND revoked_at_ms IS NULL
  AND idle_expires_at_ms>? AND absolute_expires_at_ms>?`

const pendingRevocationEventsSQL = `SELECT id,user_id,reason,created_at_ms,attempt_count
FROM oauth_revocation_events WHERE processed_at_ms IS NULL ORDER BY created_at_ms LIMIT ?`

const markRevocationEventProcessedSQL = `UPDATE oauth_revocation_events
SET processed_at_ms=?, reason=COALESCE(NULLIF(?,''),reason) WHERE id=? AND processed_at_ms IS NULL`

const markRevocationEventFailedSQL = `UPDATE oauth_revocation_events
SET attempt_count=attempt_count+1 WHERE id=? AND processed_at_ms IS NULL`

// ListRefreshFamilies 列出匹配条件的刷新令牌族。
func (s *Store) ListRefreshFamilies(ctx context.Context, userID, clientID,
	authorizationID string) ([]oauthflow.RefreshFamilyRecord, error) {
	rows, err := s.store.QueryContext(ctx, selectRefreshFamiliesFilterSQL,
		userID, userID, clientID, clientID, authorizationID, authorizationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	families := make([]oauthflow.RefreshFamilyRecord, 0, 4)
	for rows.Next() {
		var family oauthflow.RefreshFamilyRecord
		var scope, audiencesJSON, revokeReason string
		var createdMS, absoluteMS, idleTimeoutMS, revokedMS int64
		if err := rows.Scan(&family.ID, &family.ClientID, &family.SubjectUserID,
			&family.AuthorizationID, &scope, &audiencesJSON, &family.SecurityVersion,
			&createdMS, &absoluteMS, &idleTimeoutMS, &revokedMS, &revokeReason); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
		}
		family.Scopes = parseScopes(scope)
		if err := json.Unmarshal([]byte(audiencesJSON), &family.Audiences); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
		}
		family.CreatedAt = time.UnixMilli(createdMS).UTC()
		family.AbsoluteExpiresAt = time.UnixMilli(absoluteMS).UTC()
		family.IdleTimeout = time.Duration(idleTimeoutMS) * time.Millisecond
		if revokedMS != 0 {
			family.RevokedAt = time.UnixMilli(revokedMS).UTC()
		}
		family.RevokeReason = revokeReason
		families = append(families, family)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return families, nil
}

// RevokeUnconsumedAuthorizationCodesTx 撤销未兑换授权码。
func (s *Store) RevokeUnconsumedAuthorizationCodesTx(ctx context.Context, tx audit.Tx,
	userID, clientID, authorizationID string, now time.Time) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeAuthorizationCodesSQL, now.UTC().UnixMilli(),
		userID, userID, clientID, clientID, authorizationID, authorizationID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return affected, nil
}

// UpsertClientUserRevocationTx 记录（用户,客户端）撤销标记。
func (s *Store) UpsertClientUserRevocationTx(ctx context.Context, tx audit.Tx,
	userID, clientID, reason, requestID string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, upsertClientUserRevocationSQL, userID, clientID,
		now.UTC().UnixMilli(), reason, requestID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// UpsertUserRevocationTx 记录用户级撤销标记。
func (s *Store) UpsertUserRevocationTx(ctx context.Context, tx audit.Tx,
	userID, reason, requestID string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, upsertUserRevocationSQL, userID,
		now.UTC().UnixMilli(), reason, requestID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// InsertAccessTokenRevocationTx 记录访问令牌 jti 撤销。
func (s *Store) InsertAccessTokenRevocationTx(ctx context.Context, tx audit.Tx,
	record oauthflow.AccessTokenRevocationRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertAccessTokenRevocationSQL, record.JTI,
		record.ClientID, record.UserID, record.SubjectType, record.RevokedAt.UTC().UnixMilli(),
		record.ExpiresAt.UTC().UnixMilli(), record.Reason, record.RequestID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// AccessTokenRevocation 报告 jti 是否已撤销。
func (s *Store) AccessTokenRevocation(ctx context.Context, jti string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, selectAccessTokenRevocationSQL, jti)
	if err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, nil
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		return false, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

// RevocationTimes 返回用户级与客户端级在线撤销时间。
func (s *Store) RevocationTimes(ctx context.Context, userID,
	clientID string) (time.Time, time.Time, error) {
	rows, err := s.store.QueryContext(ctx, selectRevocationTimesSQL, userID, userID, clientID)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return time.Time{}, time.Time{}, nil
	}
	var userMS, clientMS int64
	if err := rows.Scan(&userMS, &clientMS); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	var userSince, clientSince time.Time
	if userMS > 0 {
		userSince = time.UnixMilli(userMS).UTC()
	}
	if clientMS > 0 {
		clientSince = time.UnixMilli(clientMS).UTC()
	}
	return userSince, clientSince, nil
}

// ListActiveAppSessionIDs 列出用户在某应用上的活动会话 ID。
func (s *Store) ListActiveAppSessionIDs(ctx context.Context, userID, clientID string,
	now time.Time) ([]string, error) {
	nowMS := now.UTC().UnixMilli()
	rows, err := s.store.QueryContext(ctx, selectActiveAppSessionsSQL, userID, clientID, nowMS, nowMS)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	ids := make([]string, 0, 4)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListPendingOAuthRevocationEvents 读取待处理撤销事件。
func (s *Store) ListPendingOAuthRevocationEvents(ctx context.Context,
	limit int) ([]oauthflow.OAuthRevocationEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.store.QueryContext(ctx, pendingRevocationEventsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	events := make([]oauthflow.OAuthRevocationEvent, 0, limit)
	for rows.Next() {
		var event oauthflow.OAuthRevocationEvent
		var createdMS int64
		if err := rows.Scan(&event.ID, &event.UserID, &event.Reason, &createdMS,
			&event.Attempts); err != nil {
			return nil, fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
		}
		event.CreatedAt = time.UnixMilli(createdMS).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

// MarkOAuthRevocationEventProcessedTx 标记事件已处理。
func (s *Store) MarkOAuthRevocationEventProcessedTx(ctx context.Context, tx audit.Tx,
	eventID, reason string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", oauthflow.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, markRevocationEventProcessedSQL, now.UTC().UnixMilli(),
		reason, eventID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}

// MarkOAuthRevocationEventFailed 累计消费失败次数，保留 pending 供重试。
func (s *Store) MarkOAuthRevocationEventFailed(ctx context.Context, eventID string,
	now time.Time) error {
	_ = now
	if _, err := s.store.ExecContext(ctx, markRevocationEventFailedSQL, eventID); err != nil {
		return fmt.Errorf("%w: %w", oauthflow.ErrStoreUnavailable, err)
	}
	return nil
}
