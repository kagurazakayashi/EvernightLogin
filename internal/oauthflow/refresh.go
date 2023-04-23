package oauthflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 刷新令牌领域常量与审计动作。
const (
	refreshTokenPrefix    = "rt_"
	refreshTokenIDPrefix  = "reftok_"
	refreshFamilyIDPrefix = "reffam_"
	refreshTokenBytes     = 32
	// maxRefreshTokenInputBytes 是客户端提交刷新令牌的最大长度。
	maxRefreshTokenInputBytes = 4096
	// ActionRefreshFamilyCreated/ActionRefreshRotated/ActionRefreshReplayed/
	// ActionRefreshDenied/ActionTokenInspected 是刷新与查询审计动作。
	ActionRefreshFamilyCreated = "oauth.refresh.family_created"
	ActionRefreshRotated       = "oauth.refresh.rotated"
	ActionRefreshReplayed      = "oauth.refresh.replayed"
	ActionRefreshDenied        = "oauth.refresh.denied"
	ActionRefreshFamilyRevoked = "oauth.refresh.family_revoked"
	ActionTokenInspected       = "oauth.token.inspected"
)

// createRefreshToken 生成高熵不透明刷新令牌明文与其 SHA-256 验证摘要。
func (s *Service) createRefreshToken() (string, [32]byte, error) {
	buffer := make([]byte, refreshTokenBytes)
	random := s.opts.Random
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", [32]byte{}, fmt.Errorf("%w: 无法生成刷新令牌", ErrOptionsInvalid)
	}
	value := refreshTokenPrefix + base64.RawURLEncoding.EncodeToString(buffer)
	return value, sha256.Sum256([]byte(value)), nil
}

// hashRefreshToken 计算提交值的 SHA-256 摘要。
func hashRefreshToken(value string) [32]byte { return sha256.Sum256([]byte(value)) }

// refreshFamilyInput 是创建刷新令牌族与首个令牌所需的已校验参数。授权码与设备码
// 流程共用同一族语义（绑定客户端/用户/授权/Scope/audience/安全版本快照）。
type refreshFamilyInput struct {
	ClientID        string
	SubjectUserID   string
	AuthorizationID string
	Scopes          []string
	Audiences       []string
	SecurityVersion int64
	// GrantType 是签发来源（authorization_code 或 device_code），只写入审计。
	GrantType string
	Actor     audit.Actor
	RequestID string
}

// issueRefreshTokenForCode 在授权码兑换成功时按策略创建刷新令牌族与首个令牌。
// 仅当客户端登记 refresh_token 且授权 scope 含 offline_access 才签发；客户端凭据
// 流程从不创建刷新令牌族（服务令牌不得用于刷新）。
func (s *Service) issueRefreshTokenForCode(ctx context.Context, code AuthorizationCodeRecord,
	client ClientInfo, scopes []string, actor audit.Actor,
	requestID string) (token.Token, time.Time, error) {
	if !client.GrantsRefreshToken() || !client.GrantsAuthorizationCode() ||
		!containsString(scopes, ScopeOfflineAccess) {
		return token.Token{}, time.Time{}, nil
	}
	return s.issueRefreshTokenFamily(ctx, refreshFamilyInput{
		ClientID: code.ClientID, SubjectUserID: code.UserID,
		AuthorizationID: code.RequestRef, Scopes: scopes, Audiences: code.Audiences,
		SecurityVersion: code.SecurityVersion, GrantType: "authorization_code",
		Actor: actor, RequestID: requestID,
	})
}

// issueRefreshTokenForDevice 在设备码领取成功时按策略创建刷新令牌族与首个令牌。
// 要求客户端登记 refresh_token 与设备码授权，且授权 scope 含 offline_access；
// 族绑定设备授权请求 ID 作为授权来源。
func (s *Service) issueRefreshTokenForDevice(ctx context.Context,
	record DeviceAuthorizationRecord, client ClientInfo, scopes []string, actor audit.Actor,
	requestID string) (token.Token, time.Time, error) {
	if !client.GrantsRefreshToken() || !client.GrantsDeviceCode() ||
		!containsString(scopes, ScopeOfflineAccess) {
		return token.Token{}, time.Time{}, nil
	}
	return s.issueRefreshTokenFamily(ctx, refreshFamilyInput{
		ClientID: record.ClientID, SubjectUserID: record.UserID,
		AuthorizationID: record.ID, Scopes: scopes, Audiences: record.Audiences,
		SecurityVersion: record.SecurityVersion, GrantType: "device_code",
		Actor: actor, RequestID: requestID,
	})
}

// issueRefreshTokenFamily 生成刷新令牌族与首个令牌；审计事务内原子写入，失败整体
// 回滚（不留下“已签发但未记录”的令牌）。
func (s *Service) issueRefreshTokenFamily(ctx context.Context,
	input refreshFamilyInput) (token.Token, time.Time, error) {
	familyID, err := s.newID(refreshFamilyIDPrefix)
	if err != nil {
		return token.Token{}, time.Time{}, err
	}
	tokenID, err := s.newID(refreshTokenIDPrefix)
	if err != nil {
		return token.Token{}, time.Time{}, err
	}
	secret, digest, err := s.createRefreshToken()
	if err != nil {
		return token.Token{}, time.Time{}, err
	}
	now := s.now()
	absoluteExpiresAt := now.Add(s.refreshAbsoluteTTL)
	idleExpiresAt := now.Add(s.refreshIdleTTL)
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}
	family := RefreshFamilyRecord{
		ID: familyID, ClientID: input.ClientID, SubjectUserID: input.SubjectUserID,
		AuthorizationID: input.AuthorizationID,
		Scopes:          append([]string(nil), input.Scopes...),
		Audiences:       append([]string(nil), input.Audiences...),
		SecurityVersion: input.SecurityVersion,
		CreatedAt:       now, AbsoluteExpiresAt: absoluteExpiresAt, IdleTimeout: s.refreshIdleTTL,
	}
	refreshToken := RefreshTokenRecord{
		ID: tokenID, FamilyID: familyID, TokenSHA256: digest,
		Status: RefreshStatusActive, IssuedAt: now, IdleExpiresAt: idleExpiresAt,
		ExpiresAt: absoluteExpiresAt, RequestID: validRequestIDString(input.RequestID),
	}
	critical := s.criticalEvent(ActionRefreshFamilyCreated, input.Actor, input.ClientID,
		"oauth_refresh_family", familyID, input.RequestID, []audit.FieldChange{
			{Field: "family_id", After: familyID},
			{Field: "token_id", After: tokenID},
			{Field: "grant_type", After: input.GrantType},
			{Field: "scope", After: truncateAudit(joinScopes(input.Scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(input.Audiences, " "), 160)},
			{Field: "idle_expires_at", After: idleExpiresAt.UTC().Format(time.RFC3339)},
			{Field: "absolute_expires_at", After: absoluteExpiresAt.UTC().Format(time.RFC3339)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateRefreshFamilyTx(txCtx, tx, family, refreshToken)
	}); err != nil {
		return token.Token{}, time.Time{}, err
	}
	return token.NewTokenValue(secret), idleExpiresAt, nil
}

// exchangeRefreshToken 处理 grant_type=refresh_token：验证客户端与刷新令牌族、
// 检查用户/成员/客户端当前状态、原子消费旧令牌并生成新令牌；检测到旧值重放时
// 撤销整个令牌族。并发刷新只有一方成功，失败方按重放处理（无无限宽限）。
func (s *Service) exchangeRefreshToken(ctx context.Context, request ExchangeRequest) (TokenResponse, error) {
	failureActor := audit.Actor{Type: audit.ActorAnonymous}
	if request.ClientID == "" || len(request.ClientID) > 128 ||
		request.RefreshToken == "" || len(request.RefreshToken) > maxRefreshTokenInputBytes {
		return TokenResponse{}, oauthInvalidRequest("刷新请求参数无效")
	}
	if err := validRequestID(request.RequestID); err != nil {
		return TokenResponse{}, oauthInvalidRequest("请求编号无效")
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		s.failure(ctx, failureActor, ActionRefreshDenied, request.ClientID,
			"client_source_unavailable", "DB_UNAVAILABLE", request.RequestID)
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || !client.Active() {
		s.failure(ctx, failureActor, ActionRefreshDenied, request.ClientID,
			"invalid_client", "CLIENT_AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidClient()
	}
	// 刷新令牌只适用于“授权码（用户）流程 + 登记 refresh_token”的客户端；
	// client_credentials 服务令牌没有刷新令牌族，任何服务调用都拒绝刷新。
	if !client.GrantsAuthorizationCode() || !client.GrantsRefreshToken() {
		s.failure(ctx, failureActor, ActionRefreshDenied, client.ClientID,
			"grant_not_allowed", "CLIENT_AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthUnauthorizedClient()
	}
	// 客户端身份验证与授权码兑换一致：公开客户端无需 secret，保密客户端必须验证。
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if err := s.verifyClientAuthentication(ctx, client, request); err != nil {
			s.failure(ctx, failureActor, ActionRefreshDenied, client.ClientID,
				"client_auth_failed", "CLIENT_AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidClient()
		}
	}
	now := s.now()
	record, found, err := s.opts.Store.GetRefreshTokenByHash(ctx, hashRefreshToken(request.RefreshToken))
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, failureActor, ActionRefreshDenied, client.ClientID,
			"unknown_refresh_token", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌无效")
	}
	family, found, err := s.opts.Store.GetRefreshFamily(ctx, record.FamilyID)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, failureActor, ActionRefreshDenied, client.ClientID,
			"family_missing", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌无效")
	}
	// 客户端错配：刷新令牌族绑定签发时的客户端，换客户端使用一律拒绝。
	if family.ClientID != client.ClientID || record.FamilyID == "" {
		s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
			"client_mismatch", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌与客户端不匹配")
	}
	// 重放/已撤销令牌：撤销整个令牌族（含全部后代），不再签发任何访问权。
	if record.Status != RefreshStatusActive {
		s.revokeRefreshFamily(ctx, family, record, "refresh_token_replayed", request.RequestID)
		s.failure(ctx, failureActor, ActionRefreshReplayed, client.ClientID,
			"refresh_token_replayed", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌已被使用")
	}
	if !family.ActiveAt(now) {
		s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
			"family_revoked", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌已失效")
	}
	// 空闲到期：标记令牌 expired 并拒绝（不再延续族）。
	if !now.Before(record.IdleExpiresAt) {
		if err := s.expireRefreshToken(ctx, record, "refresh_idle_expired", request.RequestID); err != nil {
			return TokenResponse{}, err
		}
		s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
			"refresh_idle_expired", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("刷新令牌已过期")
	}
	// 用户/成员/安全版本变化：撤销族并拒绝（真实业务状态变化影响 active）。
	userState, found, err := s.opts.Store.UserState(ctx, family.SubjectUserID)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	member, memberErr := s.opts.Store.MembershipActive(ctx, family.SubjectUserID, client.ClientID)
	if memberErr != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() || userState.SecurityVersion != family.SecurityVersion || !member {
		s.revokeRefreshFamily(ctx, family, record, "account_or_membership_changed", request.RequestID)
		s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
			"account_or_membership_changed", "USER_DISABLED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("账户或应用成员状态已变化")
	}
	// Scope 与 audience 只能缩减，不得扩大原授权。
	scopes := family.Scopes
	if len(request.Scope) > 0 {
		requested, scopeErr := normalizeScopes(request.Scope, family.Scopes)
		if scopeErr != nil {
			s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
				"scope_expansion", "REQ_INVALID", request.RequestID)
			return TokenResponse{}, oauthInvalidScope()
		}
		scopes = requested
	}
	audiences := family.Audiences
	if len(request.Resource) > 0 {
		requested, audienceErr := normalizeAudiences(request.Resource, family.Audiences)
		if audienceErr != nil {
			s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
				"audience_expansion", "REQ_INVALID", request.RequestID)
			return TokenResponse{}, oauthInvalidRequest("目标资源超出原授权范围")
		}
		audiences = requested
	}
	// 客户端当前登记配置仍须覆盖原授权（配置收窄时拒绝刷新，不静默放宽）。
	if !scopesSubset(scopes, client.Scopes) || !containsAll(audiences, client.Audiences) {
		s.recordRefreshFailure(ctx, failureActor, client.ClientID, family.ID, record.ID,
			"client_configuration_changed", "REQ_INVALID", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("客户端授权配置已变化")
	}
	// 先签发新 Access Token（无持久状态）；随后再原子轮换刷新令牌。若轮换事务
	// 失败，旧令牌保持 active，调用方可安全重试（不会因失败路径触发重放撤销）。
	issueRequestID, err := s.newID(tokenRequestPrefix)
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	caller, err := token.UserCaller(family.SubjectUserID)
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	issued, issueErr := s.opts.Tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: client.ClientID, SubjectUserID: family.SubjectUserID,
		GrantType: token.GrantAuthorizationCode, Scopes: scopes,
		Audiences: audiences, RequestID: issueRequestID,
	})
	if issueErr != nil {
		reason := "access_token_issue_failed"
		switch {
		case errors.Is(issueErr, token.ErrStoreUnavailable):
			reason = "token_store_unavailable"
		case errors.Is(issueErr, token.ErrGrantNotAllowed), errors.Is(issueErr, token.ErrScopeNotAllowed),
			errors.Is(issueErr, token.ErrAudienceNotAllowed):
			reason = "token_configuration_changed"
		}
		s.recordRefreshFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: family.SubjectUserID},
			client.ClientID, family.ID, record.ID, reason, "INTERNAL_ERROR", request.RequestID)
		if reason == "token_store_unavailable" {
			return TokenResponse{}, oauthTemporarilyUnavailable()
		}
		return TokenResponse{}, oauthServerError()
	}
	newSecret, newDigest, err := s.createRefreshToken()
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	newTokenID, err := s.newID(refreshTokenIDPrefix)
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	idleExpiresAt := now.Add(s.refreshIdleTTL)
	if idleExpiresAt.After(family.AbsoluteExpiresAt) {
		idleExpiresAt = family.AbsoluteExpiresAt
	}
	successor := RefreshTokenRecord{
		ID: newTokenID, FamilyID: family.ID, TokenSHA256: newDigest,
		Status: RefreshStatusActive, IssuedAt: now, IdleExpiresAt: idleExpiresAt,
		ExpiresAt: family.AbsoluteExpiresAt, RequestID: validRequestIDString(request.RequestID),
	}
	critical := s.criticalEvent(ActionRefreshRotated, audit.Actor{Type: audit.ActorUser, ID: family.SubjectUserID},
		client.ClientID, "oauth_refresh_family", family.ID, request.RequestID,
		[]audit.FieldChange{
			{Field: "consumed_token_id", After: record.ID},
			{Field: "new_token_id", After: newTokenID},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(audiences, " "), 160)},
			{Field: "idle_expires_at", After: idleExpiresAt.UTC().Format(time.RFC3339)},
		})
	consumeLost := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		consumed, consumeErr := s.opts.Store.ConsumeRefreshTokenTx(txCtx, tx, record.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !consumed {
			consumeLost = true
			return ErrConsentNotFound
		}
		return s.opts.Store.InsertRefreshTokenTx(txCtx, tx, successor)
	}); err != nil {
		if consumeLost {
			// 并发刷新失败方：按重放处理并撤销整族（不允许无限宽限）。
			s.revokeRefreshFamily(ctx, family, record, "refresh_concurrent_replay", request.RequestID)
			s.failure(ctx, failureActor, ActionRefreshReplayed, client.ClientID,
				"refresh_concurrent_replay", "AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidGrant("刷新令牌已被使用")
		}
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	successEvent := audit.Event{
		Actor: audit.Actor{Type: audit.ActorUser, ID: family.SubjectUserID},
		AppID: client.ClientID, Action: "oauth.token.refreshed",
		Target:  audit.Target{Type: "oauth_client", ID: client.ClientID},
		Outcome: audit.OutcomeSuccess, RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "grant_type", After: "refresh_token"},
			{Field: "family_id", After: family.ID},
			{Field: "jti", After: issued.TokenID},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
		},
	}
	if err := s.opts.Audit.Record(ctx, successEvent); err != nil {
		s.opts.Logger.Warn("刷新成功审计写入失败", "reason", "audit_unavailable")
	}
	expiresIn := int64(issued.ExpiresAt.Sub(issued.IssuedAt).Seconds())
	if expiresIn <= 0 {
		expiresIn = 0
	}
	return TokenResponse{
		AccessToken: issued.Token, RefreshToken: token.NewTokenValue(newSecret),
		RefreshExpiresAt: idleExpiresAt, TokenType: "Bearer", ExpiresIn: expiresIn,
		Scope: joinScopes(scopes), RequestID: request.RequestID,
	}, nil
}

// verifyClientAuthentication 复用客户端身份验证契约（保密客户端必须验证通过）。
func (s *Service) verifyClientAuthentication(ctx context.Context, client ClientInfo,
	request ExchangeRequest) error {
	if request.ClientSecret != "" {
		identity, err := s.opts.ClientAuth.VerifyClientSecret(ctx, client.ClientID, request.ClientSecret)
		if err != nil || identity.ClientID != client.ClientID {
			return errors.New("客户端密钥验证失败")
		}
		return nil
	}
	if request.ClientCertificatePEM != "" {
		identity, err := s.opts.ClientAuth.VerifyClientCertificate(ctx, client.ClientID,
			request.ClientCertificatePEM)
		if err != nil || identity.ClientID != client.ClientID {
			return errors.New("客户端证书验证失败")
		}
		return nil
	}
	return errors.New("缺少客户端身份验证")
}

// revokeRefreshFamily 在审计事务内撤销整族（重放/账户变化遏制）。
func (s *Service) revokeRefreshFamily(ctx context.Context, family RefreshFamilyRecord,
	record RefreshTokenRecord, reason, requestID string) {
	now := s.now()
	critical := s.criticalEvent(ActionRefreshFamilyRevoked, audit.Actor{Type: audit.ActorSystem, ID: "oauthflow-service"},
		family.ClientID, "oauth_refresh_family", family.ID, requestID, []audit.FieldChange{
			{Field: "reason", After: reason},
			{Field: "trigger_token_id", After: record.ID},
			{Field: "revoke_all_descendants", After: "true"},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, revokeErr := s.opts.Store.RevokeRefreshFamilyTx(txCtx, tx, family.ID, reason, now)
		return revokeErr
	}); err != nil {
		s.opts.Logger.Warn("刷新令牌族撤销失败", "family_id", family.ID, "error_category", "audit_or_store")
	}
}

// expireRefreshToken 在审计事务内把空闲到期的令牌标记 expired。
func (s *Service) expireRefreshToken(ctx context.Context, record RefreshTokenRecord, reason, requestID string) error {
	now := s.now()
	critical := s.criticalEvent(ActionRefreshDenied, audit.Actor{Type: audit.ActorSystem, ID: "oauthflow-service"},
		record.FamilyID, "oauth_refresh_token", record.ID, requestID, []audit.FieldChange{
			{Field: "reason", After: reason},
			{Field: "status", After: "expired"},
		})
	return s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, err := s.opts.Store.ExpireRefreshTokenTx(txCtx, tx, record.ID, now)
		return err
	})
}

// recordRefreshFailure 写刷新拒绝的失败审计（不含刷新令牌明文/摘要）。
func (s *Service) recordRefreshFailure(ctx context.Context, actor audit.Actor, clientID, familyID,
	tokenID, reason, errorCode, requestID string) {
	s.failure(ctx, actor, ActionRefreshDenied, clientID, reason, errorCode, requestID)
}

// validRequestIDString 返回可写审计的请求编号（非法值置空）。
func validRequestIDString(requestID string) string {
	if validRequestID(requestID) == nil {
		return requestID
	}
	return ""
}

// ===== 令牌状态查询（RFC 7662 风格，按权限裁剪披露） =====

// TokenInspectRequest 是令牌状态查询请求。TokenTypeHint 可为 access_token/
// refresh_token（空表示自动判断：三段式按 Access Token，其余按刷新令牌）。
type TokenInspectRequest struct {
	Token         string
	TokenTypeHint string
	// Audience 是资源服务声明的目标资源；Access Token 查询必须提供，用于校验令牌
	// 是否属于当前资源，以及授权器判定调用者能否查询该资源。
	Audience string
	// ResourceServerClientID 是经过客户端认证的资源服务稳定 ID（不能由普通请求参数自称）。
	ResourceServerClientID string
	RequestID              string
}

// TokenInspection 是状态查询结果。Active 只表示令牌/族当前有效，**不等于**该调用者
// 可执行任意业务动作（权限与当前主体状态联合判定属后续阶段）。
type TokenInspection struct {
	Active    bool
	TokenType string
	ClientID  string
	Scope     string
	Audience  []string
	// Subject/SubjectType 仅在授权器允许披露（ShowSubject）且调用者有权查看该资源时返回；
	// 默认不返回用户身份，避免其他应用探测用户。
	Subject     string
	SubjectType string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// oauthInspectAccessDenied 构造状态查询拒绝的协议错误。
func oauthInspectAccessDenied(description string) *OAuthError {
	return newOAuthError("access_denied", description, 403)
}

// InspectToken 实现标准令牌状态查询：调用者必须经客户端身份验证并由注入的
// InspectAuthorizer 授权查询该 audience；active 与披露字段按权限裁剪；无效/过期/
// 撤销令牌统一返回 Active=false（不提供区别化细节，避免令牌探测）。
func (s *Service) InspectToken(ctx context.Context, request TokenInspectRequest) (TokenInspection, error) {
	ctx = normalizeContext(ctx)
	if request.ResourceServerClientID == "" || len(request.ResourceServerClientID) > 128 ||
		request.Token == "" || len(request.Token) > MaxTokenInspectBytes {
		return TokenInspection{}, oauthInvalidRequest("状态查询参数无效")
	}
	if err := validRequestID(request.RequestID); err != nil {
		return TokenInspection{}, oauthInvalidRequest("请求编号无效")
	}
	if isNilInterface(s.opts.InspectAuthorizer) {
		s.failure(ctx, audit.Actor{Type: audit.ActorSystem, ID: request.ResourceServerClientID},
			ActionRefreshDenied, request.ResourceServerClientID, "inspect_not_configured", "ACCESS_DENIED", request.RequestID)
		return TokenInspection{}, oauthTemporarilyUnavailable()
	}
	permission, authErr := s.opts.InspectAuthorizer.AuthorizeInspection(ctx,
		request.ResourceServerClientID, request.Audience)
	if authErr != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorSystem, ID: request.ResourceServerClientID},
			ActionRefreshDenied, request.ResourceServerClientID, "inspect_authz_unavailable", "AUTHZ_UNAVAILABLE", request.RequestID)
		return TokenInspection{}, oauthTemporarilyUnavailable()
	}
	if !permission.Allowed {
		s.failure(ctx, audit.Actor{Type: audit.ActorSystem, ID: request.ResourceServerClientID},
			ActionRefreshDenied, request.ResourceServerClientID, "inspect_access_denied", "ACCESS_DENIED", request.RequestID)
		return TokenInspection{}, oauthInspectAccessDenied("无权查询该令牌状态")
	}
	// 刷新令牌（不透明）：按摘要查询，只能看到令牌族信息，用户主体默认不披露。
	if request.TokenTypeHint == "refresh_token" || strings.Count(request.Token, ".") != 2 {
		record, found, err := s.opts.Store.GetRefreshTokenByHash(ctx, hashRefreshToken(request.Token))
		if err != nil {
			return TokenInspection{}, oauthTemporarilyUnavailable()
		}
		if !found {
			s.recordInspection(ctx, request, false, "unknown_refresh_token")
			return TokenInspection{Active: false}, nil
		}
		family, found, err := s.opts.Store.GetRefreshFamily(ctx, record.FamilyID)
		if err != nil {
			return TokenInspection{}, oauthTemporarilyUnavailable()
		}
		now := s.now()
		active := found && record.Status == RefreshStatusActive && family.ActiveAt(now) &&
			now.Before(record.IdleExpiresAt)
		// 查询隐私边界（步骤 54-FIX）：刷新令牌元数据绑定具体客户端/令牌族，
		// 资源服务必须声明非空且属于该族 audience 的目标资源，并与所属客户端存在
		// 可信关系；任一不满足都只返回 inactive，不披露 ClientID/Scope/Audience/主体。
		if !active || !found {
			s.recordInspection(ctx, request, false, "inactive_refresh_token")
			return TokenInspection{Active: false}, nil
		}
		if request.Audience == "" || !containsString(family.Audiences, request.Audience) {
			s.recordInspection(ctx, request, false, "refresh_token_audience_mismatch")
			return TokenInspection{Active: false}, nil
		}
		if isNilInterface(s.opts.InspectClientAuthorizer) {
			s.recordInspection(ctx, request, false, "inspect_client_relationship_not_configured")
			return TokenInspection{Active: false}, nil
		}
		if relErr := s.opts.InspectClientAuthorizer.AuthorizeClientInspection(ctx,
			request.ResourceServerClientID, family.ClientID, request.Audience); relErr != nil {
			s.recordInspection(ctx, request, false, "resource_server_client_relationship_denied")
			return TokenInspection{Active: false}, nil
		}
		if checker := s.opts.TokenStateChecker; checker != nil {
			active, reason, stateErr := checker.CheckRefreshTokenState(ctx, family.ClientID)
			if stateErr != nil {
				return TokenInspection{}, oauthTemporarilyUnavailable()
			}
			if !active {
				s.recordInspection(ctx, request, false, "refresh_state_"+reason)
				return TokenInspection{Active: false}, nil
			}
		}
		inspection := TokenInspection{
			Active: true, TokenType: "refresh_token", ClientID: family.ClientID,
			Scope: joinScopes(family.Scopes), Audience: append([]string(nil), family.Audiences...),
			IssuedAt: record.IssuedAt, ExpiresAt: record.IdleExpiresAt,
		}
		if permission.ShowSubject {
			inspection.Subject = family.SubjectUserID
			inspection.SubjectType = "user"
		}
		s.recordInspection(ctx, request, true, "refresh_token")
		return inspection, nil
	}
	// Access Token：必须声明当前资源 audience 并完成验证。
	if request.Audience == "" {
		return TokenInspection{}, oauthInvalidRequest("缺少目标资源 audience")
	}
	if isNilInterface(s.opts.TokenVerifier) {
		s.failure(ctx, audit.Actor{Type: audit.ActorSystem, ID: request.ResourceServerClientID},
			ActionRefreshDenied, request.ResourceServerClientID, "verifier_not_configured", "INTERNAL_ERROR", request.RequestID)
		return TokenInspection{}, oauthTemporarilyUnavailable()
	}
	claims, err := s.opts.TokenVerifier.VerifyAccessToken(ctx, request.Token, request.Audience)
	if err != nil {
		// 标准状态查询对无效令牌返回 active=false；失败审计只记录稳定原因码。
		reason := "invalid_access_token"
		switch {
		case errors.Is(err, token.ErrTokenExpired):
			reason = "expired_access_token"
		case errors.Is(err, token.ErrAudienceMismatch):
			reason = "access_token_audience_mismatch"
		case errors.Is(err, token.ErrKeyRevoked):
			reason = "access_token_key_revoked"
		}
		s.recordInspection(ctx, request, false, reason)
		return TokenInspection{Active: false}, nil
	}
	// 步骤 55：访问令牌在线撤销联动。自包含 JWT 的离线验证无法感知撤销，资源服务
	// 使用状态查询/在线校验时按 jti 与用户/应用级撤销标记判无效；撤销标记只对签发
	// 时间不晚于撤销时间的令牌生效。
	revoked, revokeErr := s.accessTokenRevokedOnline(ctx, claims)
	if revokeErr != nil {
		return TokenInspection{}, oauthTemporarilyUnavailable()
	}
	if revoked {
		s.recordInspection(ctx, request, false, "revoked_access_token")
		return TokenInspection{Active: false}, nil
	}
	if checker := s.opts.TokenStateChecker; checker != nil {
		active, reason, stateErr := checker.CheckAccessTokenState(ctx, claims)
		if stateErr != nil {
			return TokenInspection{}, oauthTemporarilyUnavailable()
		}
		if !active {
			s.recordInspection(ctx, request, false, "access_state_"+reason)
			return TokenInspection{Active: false}, nil
		}
	}
	inspection := TokenInspection{
		Active: true, TokenType: "access_token", ClientID: claims.ClientID,
		Scope: strings.Join(claims.Scopes, " "), Audience: append([]string(nil), claims.Audience...),
		IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}
	if permission.ShowSubject {
		inspection.Subject = claims.Subject
		inspection.SubjectType = "user"
	}
	s.recordInspection(ctx, request, true, "access_token")
	return inspection, nil
}

// MaxTokenInspectBytes 是状态查询令牌输入上限。
const MaxTokenInspectBytes = 16 * 1024

// recordInspection 写状态查询审计（成功/失败均记录，不含令牌明文）。
func (s *Service) recordInspection(ctx context.Context, request TokenInspectRequest,
	active bool, reason string) {
	outcome := audit.OutcomeFailure
	if active {
		outcome = audit.OutcomeSuccess
	}
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorSystem, ID: request.ResourceServerClientID},
		Action:     ActionTokenInspected,
		Target:     audit.Target{Type: "oauth_client", ID: request.ResourceServerClientID},
		Outcome:    outcome,
		ReasonCode: reason,
		Changes: []audit.FieldChange{
			{Field: "active", After: fmt.Sprint(active)},
			{Field: "reason", After: reason},
			{Field: "audience", After: truncateAudit(request.Audience, 160)},
		},
		RequestID: validRequestIDString(request.RequestID),
	}
	var err error
	if active {
		err = s.opts.Audit.Record(ctx, event)
	} else {
		err = s.opts.Audit.RecordFailure(ctx, event)
	}
	if err != nil {
		s.opts.Logger.Warn("令牌状态查询审计写入失败", "reason", "audit_unavailable")
	}
}
