// 本文件把步骤 65 页面契约接到真实 oauthflow/qrlogin 服务。页面只转发公开数据与
// opaque Cookie/RedirectURL；授权码、Token、device_code、ClaimSecret 不进入日志/URL。
package uiauthadapter

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const qrStatePurpose = "qr.claim"

// qrClaimState 是匿名扫码发起端的签名状态（ClaimSecret 只放 HttpOnly Cookie）。
type qrClaimState struct {
	RequestID   string `json:"request_id"`
	ClaimSecret string `json:"claim_secret"`
	QRPayload   string `json:"qr_payload,omitempty"`
}

// splitOAuthValues 把空格分隔的 OAuth scope/resource 参数展开为列表。
func splitOAuthValues(values []string) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, strings.Fields(value)...)
	}
	return result
}

// scopeDescriptions 是 scope 的中文动作说明；未知自定义 scope fail-closed 不引导批准。
var scopeDescriptions = map[string]login.UIPageScopeInfo{
	"openid": {Value: "openid", Description: "确认你的身份标识（OIDC）",
		Limits: "不包含密码或长期令牌"},
	"profile": {Value: "profile", Description: "读取你的公开资料（显示名称等）",
		Limits: "不包含安全设置或秘密"},
	"email": {Value: "email", Description: "读取你的已验证邮箱地址",
		Limits: "不包含邮箱验证凭证"},
	"offline_access": {Value: "offline_access", Description: "在你离线时继续代表你访问",
		Limits: "可在授权管理页撤回"},
}

// consentScopes 把 scope 转中文说明；未知值拒绝。
func consentScopes(scopes []string) ([]login.UIPageScopeInfo, error) {
	result := make([]login.UIPageScopeInfo, 0, len(scopes))
	for _, scope := range scopes {
		info, ok := scopeDescriptions[scope]
		if !ok {
			return nil, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
		}
		result = append(result, info)
	}
	return result, nil
}

// audienceInfos 把 audience 转稳定值 + 通用说明（不虚构数据范围）。
func audienceInfos(audiences []string) []login.UIPageAudienceInfo {
	result := make([]login.UIPageAudienceInfo, 0, len(audiences))
	for _, audience := range audiences {
		result = append(result, login.UIPageAudienceInfo{Value: audience,
			Description: "目标资源服务（audience）"})
	}
	return result
}

// publicOAuthError 把 oauthflow/qrlogin 错误映射为页面稳定公开错误。
func publicOAuthError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *login.UIPageAuthError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	var oauthErr *oauthflow.OAuthError
	if errors.As(err, &oauthErr) {
		code := "REQ_INVALID"
		switch oauthErr.Code {
		case "access_denied":
			code = "ACCESS_DENIED"
		case "invalid_grant":
			code = "CHALLENGE_INVALID"
		case "temporarily_unavailable", "server_error":
			code = "DB_UNAVAILABLE"
		case "slow_down":
			code = "RATE_LIMITED"
		case "invalid_client", "unauthorized_client":
			code = "AUTH_FAILED"
		}
		return &login.UIPageAuthError{Code: code}
	}
	switch {
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationReauthRequired):
		return &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	case errors.Is(err, oauthflow.ErrConsentNotFound):
		return &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	case errors.Is(err, qrlogin.ErrRequestNotFound), errors.Is(err, qrlogin.ErrRequestExpired),
		errors.Is(err, qrlogin.ErrAlreadyClaimed), errors.Is(err, qrlogin.ErrVersionConflict):
		return &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	case errors.Is(err, qrlogin.ErrRateLimited):
		return &login.UIPageAuthError{Code: "RATE_LIMITED"}
	case errors.Is(err, qrlogin.ErrAccessDenied):
		return &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	case errors.Is(err, oauthflow.ErrStoreUnavailable), errors.Is(err, qrlogin.ErrStoreUnavailable):
		return &login.UIPageAuthError{Code: "DB_UNAVAILABLE"}
	case errors.Is(err, oauthflow.ErrAuditUnavailable), errors.Is(err, qrlogin.ErrAuditUnavailable):
		return &login.UIPageAuthError{Code: "AUDIT_WRITE_FAILED"}
	}
	return &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
}

// sessionSecretOrError 从请求读取会话秘密（页面不解析用户身份，只转发给真实服务）。
func (a *Adapter) sessionSecretOrError(request *http.Request) (string, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return "", &login.UIPageAuthError{Code: "AUTH_FAILED"}
	}
	return secret, nil
}

// withSessionReauthSignals 把已验证会话的近期强认证事实交给敏感操作策略。
// OAuth 同意/设备确认/扫码确认属于需要近期认证的操作；页面本身已完成用户确认
// （点击批准），因此这里只转发服务端会话中的强认证时间与强度，不接受客户端自述。
// 会话没有有效强认证时保持原上下文，由 oauthflow/qrlogin fail-closed 拒绝。
func (a *Adapter) withSessionReauthSignals(ctx context.Context, secret string) context.Context {
	if a.opts.Sessions == nil || strings.TrimSpace(secret) == "" {
		return ctx
	}
	record, err := a.opts.Sessions.Validate(ctx, secret)
	if err != nil || record.StrongAuthVerifiedAt.IsZero() {
		return ctx
	}
	return reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: record.StrongAuthVerifiedAt,
		Strength: policy.StrengthStrong, Complete: true, Confirmed: true})
}

// BeginConsent 从授权请求参数创建真实确认请求并补充受控应用名/scope 说明。
func (a *Adapter) BeginConsent(ctx context.Context, request *http.Request,
	params url.Values) (login.UIPageConsentPrompt, error) {
	if a.opts.OAuth == nil {
		return login.UIPageConsentPrompt{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageConsentPrompt{}, err
	}
	requestID := strings.TrimSpace(params.Get("request_id"))
	prompt, beginErr := a.opts.OAuth.BeginAuthorization(ctx, secret, oauthflow.AuthorizeRequest{
		ClientID: params.Get("client_id"), RedirectURI: params.Get("redirect_uri"),
		ResponseType: params.Get("response_type"), Scope: splitOAuthValues(params["scope"]),
		Resource: splitOAuthValues(params["resource"]), State: params.Get("state"),
		Nonce:               params.Get("nonce"),
		CodeChallenge:       params.Get("code_challenge"),
		CodeChallengeMethod: params.Get("code_challenge_method"), RequestID: requestID})
	if beginErr != nil {
		return login.UIPageConsentPrompt{}, publicOAuthError(beginErr)
	}
	scopes, scopeErr := consentScopes(prompt.Scopes)
	if scopeErr != nil {
		return login.UIPageConsentPrompt{}, scopeErr
	}
	applicationName := a.applicationName(prompt.ClientID)
	userDisplay := "当前账户"
	if a.opts.App != nil {
		if caller, callerErr := app.SystemCaller("passwordreset"); callerErr == nil {
			if record, getErr := a.opts.App.GetApplication(ctx, caller, prompt.ClientID); getErr == nil {
				applicationName = record.Name
			}
		}
	}
	if a.opts.Account != nil {
		if caller, callerErr := account.SystemCaller("web-page"); callerErr == nil {
			if user, getErr := a.opts.Account.GetUser(ctx, caller, promptUserID(request, a)); getErr == nil {
				if user.Nickname != "" {
					userDisplay = user.Nickname
				} else if user.Username != "" {
					userDisplay = user.Username
				}
			}
		}
	}
	return login.UIPageConsentPrompt{RequestID: prompt.RequestID,
		ApplicationName: applicationName, ClientID: prompt.ClientID,
		ClientType: string(prompt.ClientType), Scopes: scopes,
		Audiences: audienceInfos(prompt.Audiences), RedirectURI: prompt.RedirectURI,
		ExpiresAt: prompt.ExpiresAt, UserDisplayName: userDisplay,
		UserID: promptUserID(request, a)}, nil
}

// applicationName 返回受控应用展示名（无则回退稳定 ClientID，绝不使用客户端自报）。
func (a *Adapter) applicationName(clientID string) string {
	if name := strings.TrimSpace(a.opts.ApplicationNames[clientID]); name != "" {
		return name
	}
	return clientID
}

// promptUserID 读取当前会话用户 ID（仅展示用，不参与授权判断）。
func promptUserID(request *http.Request, a *Adapter) string {
	if a.opts.Sessions == nil {
		return ""
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return ""
	}
	record, err := a.opts.Sessions.Validate(context.Background(), secret)
	if err != nil {
		return ""
	}
	return record.UserID
}

// DecideConsent 调用真实决定接口；批准返回后端生成的重定向 URL。
func (a *Adapter) DecideConsent(ctx context.Context, request *http.Request,
	decision login.UIPageConsentDecision) (login.UIPageConsentResult, error) {
	if a.opts.OAuth == nil {
		return login.UIPageConsentResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageConsentResult{}, err
	}
	result, decideErr := a.opts.OAuth.DecideAuthorization(
		a.withSessionReauthSignals(ctx, secret), secret,
		oauthflow.DecideRequest{RequestID: decision.RequestID, Approve: decision.Approve,
			DecisionRequestID: requestIDFromRequest(request)})
	if decideErr != nil {
		return login.UIPageConsentResult{}, publicOAuthError(decideErr)
	}
	return login.UIPageConsentResult{Approved: result.Approved,
		RedirectURL: result.RedirectURL.Reveal()}, nil
}

// DeviceDescribe 只读短码对应设备授权请求。
func (a *Adapter) DeviceDescribe(ctx context.Context, request *http.Request,
	userCode string) (login.UIPageDevicePrompt, error) {
	if a.opts.OAuth == nil {
		return login.UIPageDevicePrompt{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageDevicePrompt{}, err
	}
	prompt, describeErr := a.opts.OAuth.DescribeDeviceAuthorization(ctx, secret, userCode,
		requestIDFromRequest(request))
	if describeErr != nil {
		return login.UIPageDevicePrompt{}, publicOAuthError(describeErr)
	}
	scopes, scopeErr := consentScopes(prompt.Scopes)
	if scopeErr != nil {
		return login.UIPageDevicePrompt{}, scopeErr
	}
	applicationName := a.applicationName(prompt.ClientID)
	if a.opts.App != nil {
		if caller, callerErr := app.SystemCaller("web-page"); callerErr == nil {
			if record, getErr := a.opts.App.GetApplication(ctx, caller, prompt.ClientID); getErr == nil {
				applicationName = record.Name
			}
		}
	}
	return login.UIPageDevicePrompt{RequestID: prompt.RequestID,
		ApplicationName: applicationName, ClientID: prompt.ClientID,
		ClientType: string(prompt.ClientType), Scopes: scopes,
		Audiences: audienceInfos(prompt.Audiences), ExpiresAt: prompt.ExpiresAt,
		UserCode: strings.TrimSpace(userCode)}, nil
}

// DeviceDecide 提交真实设备授权决定。
func (a *Adapter) DeviceDecide(ctx context.Context, request *http.Request,
	decision login.UIPageDeviceDecision) (login.UIPageDeviceResult, error) {
	if a.opts.OAuth == nil {
		return login.UIPageDeviceResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageDeviceResult{}, err
	}
	result, decideErr := a.opts.OAuth.DecideDeviceAuthorization(
		a.withSessionReauthSignals(ctx, secret), secret,
		oauthflow.DeviceDecisionRequest{UserCode: decision.UserCode, Approve: decision.Approve,
			RequestID: requestIDFromRequest(request)})
	if decideErr != nil {
		return login.UIPageDeviceResult{}, publicOAuthError(decideErr)
	}
	return login.UIPageDeviceResult{RequestID: result.RequestID,
		Approved: result.Approved}, nil
}

// BeginQR 创建匿名扫码请求并写签名状态 Cookie。
func (a *Adapter) BeginQR(ctx context.Context, request *http.Request) (login.UIPageQRBegin, error) {
	if a.opts.QR == nil || a.opts.PageState == nil || a.opts.QRClientID == "" {
		return login.UIPageQRBegin{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	result, err := a.opts.QR.Begin(ctx, qrlogin.BeginRequest{ClientID: a.opts.QRClientID,
		Scopes: append([]string(nil), a.opts.QRScopes...), RequestID: requestIDFromRequest(request)})
	if err != nil {
		return login.UIPageQRBegin{}, publicOAuthError(err)
	}
	return a.qrBeginOf(result)
}

// qrBeginOf 编码 BeginResult 为页面视图与签名状态。
func (a *Adapter) qrBeginOf(result qrlogin.BeginResult) (login.UIPageQRBegin, error) {
	state := qrClaimState{RequestID: result.RequestID,
		ClaimSecret: result.ClaimSecret.Reveal(), QRPayload: result.QRPayload}
	token, err := a.opts.PageState.Seal(qrStatePurpose, state)
	if err != nil {
		return login.UIPageQRBegin{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageQRBegin{RequestID: result.RequestID, QRPayload: result.QRPayload,
		ExpiresAt: result.ExpiresAt, Version: result.Version,
		PollIntervalSeconds: result.PollIntervalSeconds,
		StateCookie:         stateCookie("ln_qr_state", token, a.stateTTLSeconds())}, nil
}

// loadQRState 读取签名状态。
func (a *Adapter) loadQRState(request *http.Request) (qrClaimState, error) {
	if a.opts.PageState == nil {
		return qrClaimState{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	cookie, err := request.Cookie("ln_qr_state")
	if err != nil || cookie == nil {
		return qrClaimState{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	var state qrClaimState
	if err := a.opts.PageState.Open(qrStatePurpose, cookie.Value, &state); err != nil {
		return qrClaimState{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return state, nil
}

// QueryQR 查询原发起端状态。
func (a *Adapter) QueryQR(ctx context.Context, request *http.Request) (login.UIPageQRStatus, error) {
	state, err := a.loadQRState(request)
	if err != nil {
		return login.UIPageQRStatus{}, err
	}
	status, statusErr := a.opts.QR.Status(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: claimSecretOf(state), RequestID: state.RequestID,
		AuditRequestID: requestIDFromRequest(request)})
	if statusErr != nil {
		return login.UIPageQRStatus{}, publicOAuthError(statusErr)
	}
	return login.UIPageQRStatus{Status: status.Status, ExpiresAt: status.ExpiresAt,
		Version: status.Version, RetryAfterSeconds: status.RetryAfterSeconds,
		QRPayload: state.QRPayload}, nil
}

// ClaimQR 领取并写目标应用会话 Cookie。
func (a *Adapter) ClaimQR(ctx context.Context, request *http.Request) (login.UIPageQRClaim, error) {
	state, err := a.loadQRState(request)
	if err != nil {
		return login.UIPageQRClaim{}, err
	}
	issued, claimErr := a.opts.QR.Claim(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: claimSecretOf(state), RequestID: state.RequestID,
		AuditRequestID: requestIDFromRequest(request)})
	if claimErr != nil {
		return login.UIPageQRClaim{}, publicOAuthError(claimErr)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(issued)
	if cookieErr != nil {
		return login.UIPageQRClaim{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageQRClaim{SessionCookie: cookie,
		StateCookie: stateCookie("ln_qr_state", "", -1), UserID: issued.Session.UserID}, nil
}

// claimSecretOf 从签名状态恢复领取绑定（仅服务端使用）。
func claimSecretOf(state qrClaimState) qrlogin.ClaimSecret {
	secret, err := qrlogin.ClaimSecretFromString(state.ClaimSecret)
	if err != nil {
		return qrlogin.ClaimSecret{}
	}
	return secret
}

// RegenerateQR 取消旧请求并创建新请求。
func (a *Adapter) RegenerateQR(ctx context.Context, request *http.Request) (login.UIPageQRBegin, error) {
	state, err := a.loadQRState(request)
	if err != nil {
		return login.UIPageQRBegin{}, err
	}
	result, regenErr := a.opts.QR.Regenerate(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: claimSecretOf(state), RequestID: state.RequestID,
		AuditRequestID: requestIDFromRequest(request)})
	if regenErr != nil {
		return login.UIPageQRBegin{}, publicOAuthError(regenErr)
	}
	return a.qrBeginOf(result)
}

// CancelQR 取消当前扫码请求。
func (a *Adapter) CancelQR(ctx context.Context, request *http.Request) (login.UIPageQRStatus, error) {
	state, err := a.loadQRState(request)
	if err != nil {
		return login.UIPageQRStatus{}, err
	}
	status, cancelErr := a.opts.QR.Cancel(ctx, qrlogin.ClaimedRequest{
		ClaimSecret: claimSecretOf(state), RequestID: state.RequestID,
		AuditRequestID: requestIDFromRequest(request)})
	if cancelErr != nil {
		return login.UIPageQRStatus{}, publicOAuthError(cancelErr)
	}
	return login.UIPageQRStatus{Status: status.Status, ExpiresAt: status.ExpiresAt,
		Version: status.Version, RetryAfterSeconds: status.RetryAfterSeconds,
		StateCookie: stateCookie("ln_qr_state", "", -1)}, nil
}

// DescribeQR 供 APP 确认端读取请求。
func (a *Adapter) DescribeQR(ctx context.Context, request *http.Request,
	requestID string) (login.UIPageQRPrompt, error) {
	if a.opts.QR == nil {
		return login.UIPageQRPrompt{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageQRPrompt{}, err
	}
	prompt, describeErr := a.opts.QR.Describe(ctx, qrlogin.PromptRequest{
		SessionSecret: secret, RequestID: requestID,
		AuditRequestID: requestIDFromRequest(request)})
	if describeErr != nil {
		return login.UIPageQRPrompt{}, publicOAuthError(describeErr)
	}
	scopes, scopeErr := consentScopes(prompt.Scopes)
	if scopeErr != nil {
		return login.UIPageQRPrompt{}, scopeErr
	}
	return login.UIPageQRPrompt{RequestID: prompt.RequestID,
		ApplicationName: prompt.ApplicationName, ClientID: prompt.ClientID,
		ClientType: prompt.ClientType, Scopes: scopes,
		RequesterHint: requesterHint(prompt.Requester), Status: prompt.Status,
		CreatedAt: prompt.CreatedAt, ExpiresAt: prompt.ExpiresAt,
		Version: prompt.Version, Warning: prompt.Warning}, nil
}

// requesterHint 生成适度脱敏的请求端说明（不作为授权依据）。
func requesterHint(info qrlogin.RequesterInfo) string {
	description := strings.TrimSpace(info.UserAgent)
	if len(description) > 96 {
		description = description[:96]
	}
	if description == "" {
		return "请求端信息未提供"
	}
	return description
}

// DecideQR 提交 APP 扫码决定。
func (a *Adapter) DecideQR(ctx context.Context, request *http.Request,
	decision login.UIPageQRDecision) (login.UIPageQRPrompt, error) {
	if a.opts.QR == nil {
		return login.UIPageQRPrompt{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	secret, err := a.sessionSecretOrError(request)
	if err != nil {
		return login.UIPageQRPrompt{}, err
	}
	decideRequest := qrlogin.DecideRequest{SessionSecret: secret,
		RequestID: decision.RequestID, ExpectedVersion: decision.ExpectedVersion,
		AuditRequestID: requestIDFromRequest(request)}
	var prompt qrlogin.Prompt
	var decideErr error
	decisionCtx := a.withSessionReauthSignals(ctx, secret)
	if decision.Approve {
		prompt, decideErr = a.opts.QR.Approve(decisionCtx, decideRequest)
	} else {
		prompt, decideErr = a.opts.QR.Deny(decisionCtx, decideRequest)
	}
	if decideErr != nil {
		return login.UIPageQRPrompt{}, publicOAuthError(decideErr)
	}
	scopes, scopeErr := consentScopes(prompt.Scopes)
	if scopeErr != nil {
		return login.UIPageQRPrompt{}, scopeErr
	}
	return login.UIPageQRPrompt{RequestID: prompt.RequestID,
		ApplicationName: prompt.ApplicationName, ClientID: prompt.ClientID,
		ClientType: prompt.ClientType, Scopes: scopes,
		RequesterHint: requesterHint(prompt.Requester), Status: prompt.Status,
		CreatedAt: prompt.CreatedAt, ExpiresAt: prompt.ExpiresAt,
		Version: prompt.Version, Warning: prompt.Warning}, nil
}

// 编译期断言：会话类型用于用户展示的安全摘要。
var _ session.Session
var _ = time.Time{}
