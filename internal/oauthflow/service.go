package oauthflow

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// Options 是 OAuth 授权流程依赖；存储/审计/客户端来源/客户端认证/会话/令牌签发
// 缺失时拒绝构造（fail-closed）。Reauth 未注入时授权确认一律拒绝（不自动批准）。
type Options struct {
	Store      Store
	Audit      AuditRecorder
	Clients    ClientSource
	ClientAuth ClientAuthenticator
	Sessions   Sessions
	Tokens     TokenIssuer
	// Reauth 是步骤 39 敏感操作收敛入口；nil 时授权确认拒绝。
	Reauth reauth.OperationRunner
	// AllowConfidentialWithoutPKCE 允许保密客户端在既未登记 RequirePKCE、也未收到
	// code_challenge 时省略 PKCE；默认 false（所有客户端强制 S256）。任何情况下都
	// 不接受 plain challenge method。
	AllowConfidentialWithoutPKCE bool
	RequestTTL                   time.Duration
	CodeTTL                      time.Duration
	Now                          func() time.Time
	Random                       io.Reader
	Logger                       *slog.Logger
}

// Service 是授权确认与授权码兑换服务。构造后不可变、可并发使用；不提供页面/HTTP。
type Service struct {
	opts       Options
	requestTTL time.Duration
	codeTTL    time.Duration
}

// New 校验依赖与参数并构造服务。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 授权流程存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Clients) {
		return nil, fmt.Errorf("%w: OAuth 客户端来源为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.ClientAuth) {
		return nil, fmt.Errorf("%w: 客户端身份验证器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话校验器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Tokens) {
		return nil, fmt.Errorf("%w: 令牌签发器为空", ErrOptionsInvalid)
	}
	if options.RequestTTL == 0 {
		options.RequestTTL = DefaultRequestTTL
	}
	if options.RequestTTL < MinRequestTTL || options.RequestTTL > MaxRequestTTL {
		return nil, fmt.Errorf("%w: 确认请求有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinRequestTTL, MaxRequestTTL)
	}
	if options.CodeTTL == 0 {
		options.CodeTTL = DefaultCodeTTL
	}
	if options.CodeTTL < MinCodeTTL || options.CodeTTL > MaxCodeTTL {
		return nil, fmt.Errorf("%w: 授权码有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinCodeTTL, MaxCodeTTL)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, requestTTL: options.RequestTTL, codeTTL: options.CodeTTL}, nil
}

// BeginAuthorization 校验授权请求并创建待用户确认的授权确认请求。
//
// 无效 client_id/redirect_uri 返回 *OAuthError 且不带可重定向地址（宿主不得重定向）；
// 其余协议错误附带已验证的合法回调与 state，宿主可用 RedirectLocation 生成标准错误
// 重定向。用户会话必须是完整普通会话；不自动批准、不接受客户端自报用户。
func (s *Service) BeginAuthorization(ctx context.Context, sessionSecret string,
	request AuthorizeRequest) (ConsentPrompt, error) {
	ctx = normalizeContext(ctx)
	if err := validRequestID(request.RequestID); err != nil {
		return ConsentPrompt{}, oauthInvalidRequest("请求编号无效")
	}
	if request.ClientID == "" || len(request.ClientID) > 128 {
		return ConsentPrompt{}, oauthInvalidRequest("client_id 无效")
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil || !found {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			request.ClientID, "unknown_client", string(oauthcode("CLIENT_AUTH_FAILED")), request.RequestID)
		return ConsentPrompt{}, oauthInvalidClient()
	}
	if !client.Active() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "client_disabled", "CLIENT_DISABLED", request.RequestID)
		return ConsentPrompt{}, newOAuthError("unauthorized_client", "客户端所属应用已停用", 403)
	}
	redirectURI, matchErr := oauthclient.MatchRedirectURI(client.RedirectURIs,
		request.RedirectURI, client.ClientType)
	if matchErr != nil || redirectURI == "" {
		// 无效回调不得重定向，也不在错误中回显请求的回调地址。
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "invalid_redirect_uri", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, oauthInvalidRequest("redirect_uri 未登记或格式非法")
	}
	// 绑定令牌端点时必须使用与授权请求完全一致的回调字符串。
	if len(request.RedirectURI) > MaxRedirectURIBytes {
		return ConsentPrompt{}, oauthInvalidRequest("redirect_uri 过长")
	}
	redirectErr := func(description string) *OAuthError {
		return oauthInvalidRequest(description).withRedirect(request.RedirectURI, request.State)
	}
	if request.ResponseType != "code" {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "unsupported_response_type", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, oauthUnsupportedResponseType().withRedirect(request.RedirectURI, request.State)
	}
	if !client.GrantsAuthorizationCode() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "grant_not_allowed", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, oauthUnauthorizedClient().withRedirect(request.RedirectURI, request.State)
	}
	// PKCE：公开客户端强制；保密客户端按策略/登记要求；任何情况都不接受 plain。
	pkceRequired := client.ClientType == oauthclient.ClientTypePublic || client.RequirePKCE ||
		!s.opts.AllowConfidentialWithoutPKCE
	if request.CodeChallenge != "" || request.CodeChallengeMethod != "" {
		if request.CodeChallengeMethod != "S256" {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
				client.ClientID, "pkce_plain_not_allowed", "REQ_INVALID", request.RequestID)
			return ConsentPrompt{}, redirectErr("只接受 PKCE S256，禁止 plain")
		}
		if !validPKCEChallenge(request.CodeChallenge) {
			return ConsentPrompt{}, redirectErr("code_challenge 格式无效")
		}
	} else if pkceRequired {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "pkce_required", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, redirectErr("该客户端必须使用 PKCE S256")
	}
	scopes, scopeErr := normalizeScopes(request.Scope, client.Scopes)
	if scopeErr != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "invalid_scope", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, scopeErr.withRedirect(request.RedirectURI, request.State)
	}
	audiences, audienceErr := normalizeAudiences(request.Resource, client.Audiences)
	if audienceErr != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "invalid_audience", "REQ_INVALID", request.RequestID)
		return ConsentPrompt{}, audienceErr.withRedirect(request.RedirectURI, request.State)
	}
	if len(audiences) == 0 {
		// 规范允许省略 resource；仅当客户端只登记一个目标资源时使用该默认值，
		// 多目标资源必须显式请求，避免隐式扩大 audience。
		if len(client.Audiences) == 1 {
			audiences = []string{client.Audiences[0]}
		} else {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
				client.ClientID, "audience_required", "REQ_INVALID", request.RequestID)
			return ConsentPrompt{}, redirectErr("必须显式指定目标资源（resource）")
		}
	}
	if !validOpaque(request.State, MaxStateBytes) {
		return ConsentPrompt{}, redirectErr("state 参数无效")
	}
	if !validOpaque(request.Nonce, MaxNonceBytes) {
		return ConsentPrompt{}, redirectErr("nonce 参数无效")
	}

	// 真实用户会话：必须是完整普通会话，且与客户端应用作用域兼容。
	userSession, err := s.opts.Sessions.Validate(ctx, sessionSecret)
	if err != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.begin_denied",
			client.ClientID, "session_invalid", "AUTH_FAILED", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("需要登录后重新发起授权", request.RedirectURI,
			request.State)
	}
	if !userSession.IsNormal() || userSession.UserID == "" {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorize.begin_denied",
			client.ClientID, "restricted_session", "ACCESS_DENIED", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("当前会话不允许授权", request.RedirectURI,
			request.State)
	}
	if userSession.AppID != "" && userSession.AppID != client.ClientID {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorize.begin_denied",
			client.ClientID, "session_app_mismatch", "APP_SCOPE_MISMATCH", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("会话的应用作用域不匹配", request.RedirectURI,
			request.State)
	}
	userState, found, err := s.opts.Store.UserState(ctx, userSession.UserID)
	if err != nil {
		return ConsentPrompt{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorize.begin_denied",
			client.ClientID, "user_not_active", "USER_DISABLED", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("账户状态不允许授权", request.RedirectURI,
			request.State)
	}
	member, err := s.opts.Store.MembershipActive(ctx, userSession.UserID, client.ClientID)
	if err != nil {
		return ConsentPrompt{}, oauthTemporarilyUnavailable()
	}
	if !member {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorize.begin_denied",
			client.ClientID, "not_app_member", "APP_MEMBERSHIP_REQUIRED", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("不是该应用的成员", request.RedirectURI,
			request.State)
	}
	if userSession.SecurityVersion != userState.SecurityVersion {
		s.failure(ctx, sessionActor(userSession.UserID), "oauth.authorize.begin_denied",
			client.ClientID, "security_version_mismatch", "AUTH_FAILED", request.RequestID)
		return ConsentPrompt{}, oauthAccessDeniedRedirect("会话已失效", request.RedirectURI, request.State)
	}

	now := s.now()
	requestID, err := s.newID(authorizationRequestPrefix)
	if err != nil {
		return ConsentPrompt{}, oauthServerError()
	}
	record := AuthorizationRequestRecord{
		ID: requestID, UserID: userSession.UserID, ClientID: client.ClientID,
		RedirectURI: request.RedirectURI, ResponseType: "code", Scopes: scopes,
		Audiences: audiences, State: request.State, Nonce: request.Nonce,
		CodeChallenge: request.CodeChallenge, CodeChallengeMethod: request.CodeChallengeMethod,
		SessionID: userSession.ID, SecurityVersion: userSession.SecurityVersion,
		Status: "pending", RequestID: request.RequestID, CreatedAt: now,
		ExpiresAt: now.Add(s.requestTTL),
	}
	critical := s.criticalEvent("oauth.authorize.requested", sessionActor(userSession.UserID),
		client.ClientID, "oauth_authorization_request", requestID, request.RequestID,
		[]audit.FieldChange{
			{Field: "client_id", After: client.ClientID},
			{Field: "redirect_uri", After: truncateAudit(request.RedirectURI, 120)},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(audiences, " "), 160)},
			{Field: "pkce_method", After: request.CodeChallengeMethod},
			{Field: "state_present", After: fmt.Sprint(request.State != "")},
			{Field: "nonce_present", After: fmt.Sprint(request.Nonce != "")},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateAuthorizationRequestTx(txCtx, tx, record)
	}); err != nil {
		return ConsentPrompt{}, mapCriticalProtocolError(err)
	}
	return ConsentPrompt{
		RequestID: requestID, ClientID: client.ClientID, ClientType: client.ClientType,
		Scopes: append([]string(nil), scopes...), Audiences: append([]string(nil), audiences...),
		RedirectURI: request.RedirectURI, ExpiresAt: record.ExpiresAt,
		StatePresent: request.State != "",
	}, nil
}

// DecideAuthorization 执行用户对授权请求的决定：同会话、未过期、pending 条件迁移；
// 批准前按敏感策略要求近期认证，然后原子签发授权码；拒绝返回标准 access_denied
// 重定向且不签发授权码。取消/拒绝不改变任何其他安全状态。
func (s *Service) DecideAuthorization(ctx context.Context, sessionSecret string,
	request DecideRequest) (AuthorizationResult, error) {
	ctx = normalizeContext(ctx)
	if strings.TrimSpace(request.RequestID) == "" || len(request.RequestID) > 64 {
		return AuthorizationResult{}, oauthInvalidRequest("确认请求编号无效")
	}
	if err := validRequestID(request.DecisionRequestID); err != nil {
		return AuthorizationResult{}, oauthInvalidRequest("请求编号无效")
	}
	record, found, err := s.opts.Store.GetAuthorizationRequest(ctx, request.RequestID)
	if err != nil {
		return AuthorizationResult{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.authorize.decide_denied",
			"", "unknown_request", "REQ_INVALID", request.DecisionRequestID)
		return AuthorizationResult{}, oauthInvalidRequest("授权确认请求不存在或已失效")
	}
	now := s.now()
	if record.Status != "pending" || !now.Before(record.ExpiresAt) {
		s.failure(ctx, sessionActor(record.UserID), "oauth.authorize.decide_denied",
			record.ClientID, "request_not_pending", "REQ_INVALID", request.DecisionRequestID)
		return AuthorizationResult{}, oauthInvalidRequest("授权确认请求已失效").
			withRedirect(record.RedirectURI, record.State)
	}
	userSession, err := s.opts.Sessions.Validate(ctx, sessionSecret)
	if err != nil || userSession.UserID != record.UserID || userSession.ID != record.SessionID ||
		!userSession.IsNormal() ||
		(userSession.AppID != "" && userSession.AppID != record.ClientID) {
		s.failure(ctx, sessionActor(record.UserID), "oauth.authorize.decide_denied",
			record.ClientID, "session_invalid", "AUTH_FAILED", request.DecisionRequestID)
		return AuthorizationResult{}, oauthAccessDeniedRedirect("会话已失效，请重新登录",
			record.RedirectURI, record.State)
	}
	userState, found, err := s.opts.Store.UserState(ctx, record.UserID)
	if err != nil {
		return AuthorizationResult{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() ||
		userState.SecurityVersion != record.SecurityVersion ||
		userSession.SecurityVersion != record.SecurityVersion {
		s.failure(ctx, sessionActor(record.UserID), "oauth.authorize.decide_denied",
			record.ClientID, "user_state_changed", "AUTH_FAILED", request.DecisionRequestID)
		return AuthorizationResult{}, oauthAccessDeniedRedirect("账户状态或安全版本已变化，请重新登录",
			record.RedirectURI, record.State)
	}
	member, err := s.opts.Store.MembershipActive(ctx, record.UserID, record.ClientID)
	if err != nil {
		return AuthorizationResult{}, oauthTemporarilyUnavailable()
	}
	if !member {
		s.failure(ctx, sessionActor(record.UserID), "oauth.authorize.decide_denied",
			record.ClientID, "not_app_member", "APP_MEMBERSHIP_REQUIRED", request.DecisionRequestID)
		return AuthorizationResult{}, oauthAccessDeniedRedirect("不是该应用的成员", record.RedirectURI,
			record.State)
	}
	if !request.Approve {
		critical := s.criticalEvent("oauth.authorize.denied", sessionActor(record.UserID),
			record.ClientID, "oauth_authorization_request", record.ID, request.DecisionRequestID,
			[]audit.FieldChange{{Field: "decision", After: "denied"}})
		if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
			ok, decideErr := s.opts.Store.DecideAuthorizationRequestTx(txCtx, tx, record.ID, "denied", now)
			if decideErr != nil {
				return decideErr
			}
			if !ok {
				return ErrConsentNotFound
			}
			return nil
		}); err != nil {
			return AuthorizationResult{}, mapCriticalProtocolError(err)
		}
		redirectURL, _ := oauthAccessDeniedRedirect("", record.RedirectURI, record.State).RedirectLocation()
		return AuthorizationResult{RequestID: record.ID, Approved: false, RedirectURL: redirectURL,
			State: record.State}, nil
	}
	// 批准前的近期认证/敏感策略（fail-closed：未接线或拒绝则不发码）。
	authorization, reauthErr := s.authorizeConsent(ctx, record, request.DecisionRequestID)
	if reauthErr != nil {
		s.failure(ctx, sessionActor(record.UserID), "oauth.authorize.approve_denied",
			record.ClientID, "reauth_denied", string(reauthCode(reauthErr)), request.DecisionRequestID)
		return AuthorizationResult{}, oauthAccessDeniedRedirect("需要重新验证身份后确认授权",
			record.RedirectURI, record.State)
	}
	code, err := s.newAuthorizationCode()
	if err != nil {
		return AuthorizationResult{}, oauthServerError()
	}
	codeID, err := s.newID(authorizationCodePrefix)
	if err != nil {
		return AuthorizationResult{}, oauthServerError()
	}
	codeRecord := AuthorizationCodeRecord{
		ID: codeID, CodeSHA256: hashAuthorizationCode(code), RequestID: record.RequestID,
		UserID: record.UserID, ClientID: record.ClientID, RedirectURI: record.RedirectURI,
		Scopes:    append([]string(nil), record.Scopes...),
		Audiences: append([]string(nil), record.Audiences...),
		Nonce:     record.Nonce, CodeChallenge: record.CodeChallenge,
		CodeChallengeMethod: record.CodeChallengeMethod, SessionID: record.SessionID,
		SecurityVersion: record.SecurityVersion, RequestRef: record.ID,
		IssuedAt: now, ExpiresAt: now.Add(s.codeTTL),
	}
	critical := s.criticalEvent("oauth.authorize.approved", sessionActor(record.UserID),
		record.ClientID, "oauth_authorization_request", record.ID, request.DecisionRequestID,
		[]audit.FieldChange{
			{Field: "decision", After: "approved"},
			{Field: "code_id", After: codeID},
			{Field: "scope", After: truncateAudit(joinScopes(record.Scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(record.Audiences, " "), 160)},
			{Field: "code_expires_at", After: codeRecord.ExpiresAt.UTC().Format(time.RFC3339)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, decideErr := s.opts.Store.DecideAuthorizationRequestTx(txCtx, tx, record.ID, "approved", now)
		if decideErr != nil {
			return decideErr
		}
		if !ok {
			return ErrConsentNotFound
		}
		return s.opts.Store.CreateAuthorizationCodeTx(txCtx, tx, codeRecord)
	}); err != nil {
		return AuthorizationResult{}, mapCriticalProtocolError(err)
	}
	redirectURL := buildSuccessRedirect(record.RedirectURI, code, record.State)
	s.notifyConsent(ctx, authorization)
	return AuthorizationResult{
		RequestID: record.ID, Approved: true, Code: code, RedirectURL: redirectURL,
		State: record.State, CodeExpiresAt: codeRecord.ExpiresAt,
	}, nil
}

// Exchange 在 Token 端点用授权码兑换 Access Token。全部错误返回 *OAuthError（标准
// error/error_description 与 HTTP 状态），不使用项目业务响应格式。授权码原子消费，
// 并发/重放只有一方成功；重复兑换记录 replayed_at_ms 并按无效授权拒绝。
func (s *Service) Exchange(ctx context.Context, request ExchangeRequest) (TokenResponse, error) {
	ctx = normalizeContext(ctx)
	if request.GrantType != "authorization_code" {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
			request.ClientID, "unsupported_grant_type", "REQ_INVALID", request.RequestID)
		return TokenResponse{}, oauthUnsupportedGrantType()
	}
	if request.ClientID == "" || len(request.ClientID) > 128 ||
		request.Code == "" || len(request.Code) > 512 ||
		request.RedirectURI == "" || len(request.RedirectURI) > MaxRedirectURIBytes {
		return TokenResponse{}, oauthInvalidRequest("兑换请求参数无效")
	}
	if err := validRequestID(request.RequestID); err != nil {
		return TokenResponse{}, oauthInvalidRequest("请求编号无效")
	}
	client, found, err := s.opts.Clients.LoadClient(ctx, request.ClientID)
	if err != nil {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
			request.ClientID, "client_source_unavailable", "DB_UNAVAILABLE", request.RequestID)
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || !client.Active() || !client.GrantsAuthorizationCode() {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
			request.ClientID, "invalid_client", "CLIENT_AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidClient()
	}
	// 客户端身份验证：公开客户端不需要 secret；保密客户端必须成功验证。
	if client.ClientType == oauthclient.ClientTypeConfidential {
		if request.ClientSecret == "" && request.ClientCertificatePEM == "" {
			s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
				request.ClientID, "missing_client_auth", "CLIENT_AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidClient()
		}
		if request.ClientSecret != "" {
			identity, authErr := s.opts.ClientAuth.VerifyClientSecret(ctx, request.ClientID,
				request.ClientSecret)
			if authErr != nil || identity.ClientID != request.ClientID {
				s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
					request.ClientID, "client_auth_failed", "CLIENT_AUTH_FAILED", request.RequestID)
				return TokenResponse{}, oauthInvalidClient()
			}
		} else {
			identity, authErr := s.opts.ClientAuth.VerifyClientCertificate(ctx, request.ClientID,
				request.ClientCertificatePEM)
			if authErr != nil || identity.ClientID != request.ClientID {
				s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
					request.ClientID, "client_cert_auth_failed", "CLIENT_AUTH_FAILED", request.RequestID)
				return TokenResponse{}, oauthInvalidClient()
			}
		}
	}
	now := s.now()
	digest := hashAuthorizationCode(request.Code)
	code, found, err := s.opts.Store.GetAuthorizationCodeByHash(ctx, digest)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found {
		s.failure(ctx, audit.Actor{Type: audit.ActorAnonymous}, "oauth.token.exchange_denied",
			request.ClientID, "unknown_code", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权码无效")
	}
	actor := sessionActor(code.UserID)
	if !code.ConsumedAt.IsZero() {
		// 已兑换授权码被再次提交：记录重放探测并按标准 invalid_grant 拒绝。访问令牌
		// 是无状态 JWT，本步没有撤销列表/刷新家族（步骤 54），不宣称已撤销令牌。
		_ = s.opts.Store.MarkAuthorizationCodeReplayed(ctx, code.ID, now)
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"code_replayed", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权码已被使用")
	}
	if !now.Before(code.ExpiresAt) {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"code_expired", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权码已过期")
	}
	// 逐项绑定校验：client、精确回调、PKCE、用户/会话/成员、客户端当前登记配置。
	if code.ClientID != request.ClientID ||
		subtle.ConstantTimeCompare([]byte(code.RedirectURI), []byte(request.RedirectURI)) != 1 {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"binding_mismatch", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权码绑定信息不匹配")
	}
	pkceRequired := client.ClientType == oauthclient.ClientTypePublic || client.RequirePKCE ||
		!s.opts.AllowConfidentialWithoutPKCE
	if code.CodeChallenge != "" {
		if !validPKCEVerifier(request.CodeVerifier) ||
			subtle.ConstantTimeCompare([]byte(pkceS256(request.CodeVerifier)),
				[]byte(code.CodeChallenge)) != 1 {
			s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
				"pkce_mismatch", "AUTH_FAILED", request.RequestID)
			return TokenResponse{}, oauthInvalidGrant("PKCE 校验失败")
		}
	} else if pkceRequired {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"pkce_missing", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("缺少 PKCE 绑定")
	}
	userState, found, err := s.opts.Store.UserState(ctx, code.UserID)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || !userState.Active() || userState.SecurityVersion != code.SecurityVersion {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"user_state_changed", "USER_DISABLED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("账户状态已变化")
	}
	snapshot, found, err := s.opts.Store.SessionSnapshot(ctx, code.SessionID)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !found || snapshot.UserID != code.UserID || !snapshot.ActiveAt(now) ||
		snapshot.SecurityVersion != code.SecurityVersion ||
		(snapshot.AppID != "" && snapshot.AppID != code.ClientID) {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"session_invalid", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权会话已失效")
	}
	member, err := s.opts.Store.MembershipActive(ctx, code.UserID, code.ClientID)
	if err != nil {
		return TokenResponse{}, oauthTemporarilyUnavailable()
	}
	if !member {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"not_app_member", "APP_MEMBERSHIP_REQUIRED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("应用成员关系已失效")
	}
	scopes := parseStoredScopes(code.ScopesRaw())
	if !scopesSubset(scopes, client.Scopes) {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"scope_no_longer_allowed", "REQ_INVALID", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("客户端 Scope 配置已变化")
	}
	if !containsAll(code.Audiences, client.Audiences) {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"audience_no_longer_allowed", "REQ_INVALID", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("客户端目标资源配置已变化")
	}
	// 原子消费：条件更新保证并发兑换单赢家。
	critical := s.criticalEvent("oauth.code.consumed", actor, code.ClientID,
		"oauth_authorization_code", code.ID, request.RequestID,
		[]audit.FieldChange{
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(code.Audiences, " "), 160)},
		})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		consumed, consumeErr := s.opts.Store.ConsumeAuthorizationCodeTx(txCtx, tx, code.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !consumed {
			return ErrConsentNotFound
		}
		return nil
	}); err != nil {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"code_consume_conflict", "AUTH_FAILED", request.RequestID)
		return TokenResponse{}, oauthInvalidGrant("授权码已被使用")
	}
	caller, err := token.UserCaller(code.UserID)
	if err != nil {
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID,
			"issuer_caller_invalid", "INTERNAL_ERROR", request.RequestID)
		return TokenResponse{}, oauthServerError()
	}
	issueRequestID, err := s.newID(tokenRequestPrefix)
	if err != nil {
		return TokenResponse{}, oauthServerError()
	}
	issued, issueErr := s.opts.Tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: code.ClientID, SubjectUserID: code.UserID,
		GrantType: token.GrantAuthorizationCode, Scopes: scopes,
		Audiences: append([]string(nil), code.Audiences...), RequestID: issueRequestID,
	})
	if issueErr != nil {
		reason := "token_issuance_failed"
		switch {
		case errors.Is(issueErr, token.ErrGrantNotAllowed), errors.Is(issueErr, token.ErrScopeNotAllowed),
			errors.Is(issueErr, token.ErrAudienceNotAllowed):
			reason = "token_configuration_changed"
		case errors.Is(issueErr, token.ErrStoreUnavailable):
			reason = "token_store_unavailable"
		case errors.Is(issueErr, token.ErrAccessDenied):
			reason = "token_issuance_not_authorized"
		}
		s.failure(ctx, actor, "oauth.token.exchange_denied", code.ClientID, reason,
			"INTERNAL_ERROR", request.RequestID)
		if reason == "token_store_unavailable" {
			return TokenResponse{}, oauthTemporarilyUnavailable()
		}
		return TokenResponse{}, oauthServerError()
	}
	// 协议成功事件；令牌服务已独立写签发审计，这里失败只记录日志（不重复宣称成功）。
	successEvent := audit.Event{
		Actor: actor, AppID: code.ClientID, Action: "oauth.token.exchanged",
		Target:    audit.Target{Type: "oauth_client", ID: code.ClientID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "grant_type", After: "authorization_code"},
			{Field: "code_id", After: code.ID},
			{Field: "jti", After: issued.TokenID},
			{Field: "kid", After: issued.KeyID},
			{Field: "scope", After: truncateAudit(joinScopes(scopes), 160)},
			{Field: "audience", After: truncateAudit(strings.Join(code.Audiences, " "), 160)},
		},
	}
	if err := s.opts.Audit.Record(ctx, successEvent); err != nil {
		s.opts.Logger.Warn("OAuth 兑换成功审计写入失败", "reason", "audit_unavailable")
	}
	expiresIn := int64(issued.ExpiresAt.Sub(issued.IssuedAt).Seconds())
	if expiresIn <= 0 {
		expiresIn = int64(s.opts.Now().UTC().Unix()) // 防御性兜底：正常情况下 Token 服务返回正数
		expiresIn = 0
	}
	return TokenResponse{AccessToken: issued.Token, TokenType: "Bearer", ExpiresIn: expiresIn,
		Scope: joinScopes(scopes), RequestID: request.RequestID, CodeID: code.ID}, nil
}

// ===== 内部辅助 =====

// authorizeConsent 复用步骤 39 敏感操作策略要求近期认证；未接线时 fail-closed。
func (s *Service) authorizeConsent(ctx context.Context, record AuthorizationRequestRecord,
	requestID string) (reauth.Result, error) {
	if isNilInterface(s.opts.Reauth) {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	caller, err := reauthCaller(record.UserID)
	if err != nil {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	params := map[string]string{
		"client_id":    record.ClientID,
		"redirect_uri": record.RedirectURI,
		"scope":        joinScopes(record.Scopes),
		"audience":     strings.Join(record.Audiences, " "),
		"request":      record.ID,
	}
	result, err := s.opts.Reauth.Authorize(ctx, caller, reauth.Request{
		ScopeID: "system", OperationID: operationAuthorizationApprove,
		TargetType: "oauth_client", TargetID: record.ClientID,
		Params: params, Description: "批准 OAuth 应用授权请求", RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, err
	}
	return result, nil
}

// notifyConsent 在授权码签发后发送成功安全告知；失败只记录日志、不回滚已发码。
func (s *Service) notifyConsent(ctx context.Context, authorization reauth.Result) {
	if isNilInterface(s.opts.Reauth) || authorization.OperationID == "" {
		return
	}
	if err := s.opts.Reauth.NotifyOutcome(ctx, authorization, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("OAuth 授权成功告知发送失败", "reason", "notify_unavailable")
	}
}

// now 返回 UTC 毫秒精度时间。
func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// newID 生成带前缀的安全随机标识。
func (s *Service) newID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// newAuthorizationCode 生成高熵授权码明文（32 字节 base64url，无填充）。
func (s *Service) newAuthorizationCode() (string, error) {
	buffer := make([]byte, codeRandomBytes)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// criticalEvent 构造带稳定失败码映射的关键审计请求。
func (s *Service) criticalEvent(action string, actor audit.Actor, appID, targetType, targetID,
	requestID string, changes []audit.FieldChange) audit.CriticalRequest {
	event := audit.Event{
		Actor: actor, AppID: appID, Action: action,
		Target:    audit.Target{Type: targetType, ID: targetID},
		RequestID: requestID, Changes: changes,
	}
	return audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: action + "_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(protocolAuditCode(mapCriticalProtocolError(err)))
		},
	}
}

// failure 写失败审计（best-effort，不改变拒绝结果）；reason 只允许稳定小写原因码。
func (s *Service) failure(ctx context.Context, actor audit.Actor, action, appID, reason, code, requestID string) {
	if actor.Validate() != nil {
		return
	}
	event := audit.Event{
		Actor: actor, AppID: appID, Action: action,
		Target:  audit.Target{Type: "oauth_client", ID: appID},
		Outcome: audit.OutcomeFailure, ErrorCode: code,
		ReasonCode: stableReason(reason), RequestID: requestID,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("OAuth 协议失败审计写入失败", "reason", "audit_unavailable")
	}
}

// mapCriticalProtocolError 把审计事务错误映射为标准协议错误。
func mapCriticalProtocolError(err error) *OAuthError {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConsentNotFound) {
		return oauthInvalidRequest("授权确认请求已失效")
	}
	if errors.Is(err, audit.ErrAuditUnavailable) {
		return oauthServerError()
	}
	return oauthTemporarilyUnavailable()
}

// protocolAuditCode 把协议错误映射为根包已登记错误码（仅审计使用）。
func protocolAuditCode(err *OAuthError) ErrorCode {
	if err == nil {
		return ""
	}
	switch err.Code {
	case "invalid_client":
		return "CLIENT_AUTH_FAILED"
	case "access_denied":
		return "ACCESS_DENIED"
	case "invalid_grant":
		return "AUTH_FAILED"
	case "server_error", "temporarily_unavailable":
		return "DB_UNAVAILABLE"
	default:
		return "REQ_INVALID"
	}
}

// reauthCode 把再次认证错误映射为审计错误码。
func reauthCode(err error) ErrorCode {
	switch {
	case errors.Is(err, reauth.ErrMFARequired):
		return "MFA_REQUIRED"
	case errors.Is(err, reauth.ErrAccessDenied):
		return "ACCESS_DENIED"
	default:
		return "REAUTH_REQUIRED"
	}
}

// oauthAccessDeniedRedirect 构造带合法回调与 state 的 access_denied 错误。
func oauthAccessDeniedRedirect(description, redirectURI, state string) *OAuthError {
	err := newOAuthError("access_denied", description, 403)
	if redirectURI != "" {
		err.withRedirect(redirectURI, state)
	}
	return err
}

// buildSuccessRedirect 构造带 code+state 的授权成功重定向 URL。
func buildSuccessRedirect(redirectURI, code, state string) string {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	values := parsed.Query()
	values.Set("code", code)
	if state != "" {
		values.Set("state", state)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

// scopesSubset 报告 scopes 是否为 allowed 的子集。
func scopesSubset(scopes, allowed []string) bool {
	for _, scope := range scopes {
		if !containsString(allowed, scope) {
			return false
		}
	}
	return true
}

// containsAll 报告 values 是否全部包含于 allowed。
func containsAll(values, allowed []string) bool {
	for _, value := range values {
		if !containsString(allowed, value) {
			return false
		}
	}
	return true
}

// truncateAudit 按码点截断审计差异值，避免超长值使事件无效。
func truncateAudit(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

// stableReason 只保留小写字母/数字/下划线且长度有界的原因码，避免日志注入。
func stableReason(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return ""
	}
	return value
}

// ScopesRaw/AudiencesRaw 是记录辅助方法：持久化层使用规范 scope 字符串与 audience。
func (c AuthorizationCodeRecord) ScopesRaw() string { return joinScopes(c.Scopes) }

// oauthcode 是协议错误到根包错误码的稳定映射辅助（避免重复字符串字面量）。
func oauthcode(code string) ErrorCode { return ErrorCode(code) }
