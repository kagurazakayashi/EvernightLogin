// 本文件把步骤 64 页面契约接到真实 mfa/passkey/recovery/passwordreset/session 服务。
//
// 安全边界：
//   - 第二因素尝试令牌与挑战 ID 只在签名短时效 HttpOnly Cookie 中随页面传递，
//     不进入 URL/localStorage/日志；每次读取都重新校验签名、到期与受限会话绑定。
//   - 页面不能自报“密码已通过”或“恢复代码已验证”：恢复代码前由 mfa 的只读交接
//     校验挑战+尝试令牌+受限会话，再由 recovery.Begin 原子消费代码。
//   - 强初始化只允许真实 Passkey 注册 + CompleteStrongSetup；完成后撤销受限会话并
//     要求重新登录，不签发完整会话。
//   - 取消/重绑/完成均调用既有服务，页面只转发 opaque Cookie 与一次性代码，不记录
//     明文秘密。
package uiauthadapter

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

const (
	mfaStateCookieName = "ln_mfa_state"
	mfaStatePurpose    = "mfa.second_factor"
)

// mfaPageState 是第二因素页面之间传递的签名状态（只含用户自己本次流程数据）。
type mfaPageState struct {
	ChallengeID       string   `json:"challenge_id"`
	AttemptToken      string   `json:"attempt_token"`
	FactorType        string   `json:"factor_type"`
	MaskedEmail       string   `json:"masked_email,omitempty"`
	ExpiresAtMs       int64    `json:"expires_at_ms"`
	PasskeyCeremonyID string   `json:"passkey_ceremony_id,omitempty"`
	PasskeyOptions    string   `json:"passkey_options,omitempty"`
	SetupRequired     bool     `json:"setup_required,omitempty"`
	AllowedMethods    []string `json:"allowed_methods,omitempty"`
	UserID            string   `json:"user_id"`
	AppID             string   `json:"app_id,omitempty"`
	SessionID         string   `json:"session_id"`
}

// stateCookie 构造短期 HttpOnly 状态 Cookie（内容已签名，不加密但只含流程数据）。
func stateCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// mfaView 把 BeginLogin/Resend 结果编码为页面视图与签名状态 Cookie。
func (a *Adapter) mfaView(start mfa.LoginStart) (login.UIPageSecondFactor,
	*http.Cookie, error) {
	if a.opts.PageState == nil {
		return login.UIPageSecondFactor{}, nil, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	sessionRecord := start.RestrictedSession.Session
	state := mfaPageState{ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		FactorType: string(start.FactorType), MaskedEmail: start.MaskedEmail,
		ExpiresAtMs:       start.ExpiresAt.UTC().UnixMilli(),
		PasskeyCeremonyID: start.PasskeyCeremonyID,
		PasskeyOptions:    base64.RawURLEncoding.EncodeToString(start.PasskeyOptions),
		SetupRequired:     start.SetupRequired, UserID: sessionRecord.UserID,
		AppID: sessionRecord.AppID, SessionID: sessionRecord.ID}
	for _, method := range start.AllowedSetupMethods {
		state.AllowedMethods = append(state.AllowedMethods, string(method))
	}
	token, err := a.opts.PageState.Seal(mfaStatePurpose, state)
	if err != nil {
		return login.UIPageSecondFactor{}, nil, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	view := login.UIPageSecondFactor{FactorType: state.FactorType,
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		MaskedEmail: start.MaskedEmail, ExpiresAt: start.ExpiresAt,
		PasskeyCeremonyID: start.PasskeyCeremonyID,
		PasskeyOptions:    start.PasskeyOptions, SetupRequired: start.SetupRequired,
		AllowedMethods: state.AllowedMethods, UserID: state.UserID, AppID: state.AppID}
	return view, stateCookie(mfaStateCookieName, token, int(a.stateTTLSeconds())), nil
}

// stateTTLSeconds 返回状态 Cookie 的浏览器保留秒数（略大于服务端令牌有效期）。
func (a *Adapter) stateTTLSeconds() int { return 15 * 60 }

// loadMFAState 读取并校验签名状态与当前受限会话绑定。
func (a *Adapter) loadMFAState(ctx context.Context, request *http.Request) (mfaPageState,
	string, error) {
	if a.opts.PageState == nil {
		return mfaPageState{}, "", &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	cookie, err := request.Cookie(mfaStateCookieName)
	if err != nil || cookie == nil {
		return mfaPageState{}, "", &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	var state mfaPageState
	if err := a.opts.PageState.Open(mfaStatePurpose, cookie.Value, &state); err != nil {
		return mfaPageState{}, "", &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return mfaPageState{}, "", &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	record, err := a.opts.Sessions.Validate(ctx, secret)
	if err != nil || record.UserID != state.UserID || record.ID != state.SessionID ||
		!record.IsRestricted() || record.Kind != session.KindRestricted ||
		record.Reason != session.ReasonPendingSecondFactor || record.AppID != state.AppID {
		return mfaPageState{}, "", &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return state, secret, nil
}

// LoadSecondFactor 读取当前挑战页面数据（不消费挑战）。
func (a *Adapter) LoadSecondFactor(ctx context.Context,
	request *http.Request) (login.UIPageSecondFactor, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageSecondFactor{}, err
	}
	options, decodeErr := base64.RawURLEncoding.DecodeString(state.PasskeyOptions)
	if decodeErr != nil {
		return login.UIPageSecondFactor{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return login.UIPageSecondFactor{FactorType: state.FactorType,
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		MaskedEmail:       state.MaskedEmail,
		ExpiresAt:         time.UnixMilli(state.ExpiresAtMs).UTC(),
		PasskeyCeremonyID: state.PasskeyCeremonyID, PasskeyOptions: options,
		SetupRequired: state.SetupRequired, AllowedMethods: state.AllowedMethods,
		UserID: state.UserID, AppID: state.AppID}, nil
}

// VerifySecondFactor 调用真实 mfa.Verify；成功返回完整会话 Cookie 并清除临时状态。
func (a *Adapter) VerifySecondFactor(ctx context.Context, request *http.Request,
	verify login.UIPageSecondFactorVerify) (login.UIPageSecondFactorResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageSecondFactorResult{}, err
	}
	if verify.ChallengeID != state.ChallengeID || verify.AttemptToken != state.AttemptToken {
		return login.UIPageSecondFactorResult{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	result, verifyErr := a.opts.MFA.Verify(ctx, mfa.VerifyRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		Code: verify.Code, PasskeyCeremonyID: verify.PasskeyCeremonyID,
		PasskeyResponse: verify.PasskeyResponse, ExistingSession: secret,
		RequestID: verify.RequestID})
	if verifyErr != nil {
		return login.UIPageSecondFactorResult{}, publicMFAError(verifyErr)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(result.Session)
	if cookieErr != nil {
		return login.UIPageSecondFactorResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageSecondFactorResult{SessionCookie: cookie,
		StateCookie: stateCookie(mfaStateCookieName, "", -1),
		UserID:      result.Authenticated.UserID, Username: result.Authenticated.Username}, nil
}

// ResendSecondFactor 只对邮件因素重发，更新尝试令牌/到期并旧码失效。返回的视图
// 携带新的签名状态 Cookie，由页面框架写入响应。
func (a *Adapter) ResendSecondFactor(ctx context.Context,
	request *http.Request) (login.UIPageSecondFactor, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageSecondFactor{}, err
	}
	start, resendErr := a.opts.MFA.Resend(ctx, mfa.ResendRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		RequestID: requestIDFromRequest(request)})
	if resendErr != nil {
		return login.UIPageSecondFactor{}, publicMFAError(resendErr)
	}
	state.AttemptToken = start.AttemptToken
	state.MaskedEmail = start.MaskedEmail
	state.ExpiresAtMs = start.ExpiresAt.UTC().UnixMilli()
	state.FactorType = string(start.FactorType)
	token, sealErr := a.opts.PageState.Seal(mfaStatePurpose, state)
	if sealErr != nil {
		return login.UIPageSecondFactor{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	options, decodeErr := base64.RawURLEncoding.DecodeString(state.PasskeyOptions)
	if decodeErr != nil {
		return login.UIPageSecondFactor{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return login.UIPageSecondFactor{FactorType: state.FactorType,
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		MaskedEmail: state.MaskedEmail, ExpiresAt: time.UnixMilli(state.ExpiresAtMs).UTC(),
		PasskeyCeremonyID: state.PasskeyCeremonyID, PasskeyOptions: options,
		SetupRequired: state.SetupRequired, AllowedMethods: state.AllowedMethods,
		UserID: state.UserID, AppID: state.AppID,
		StateCookie: stateCookie(mfaStateCookieName, token, a.stateTTLSeconds())}, nil
}

// CancelSecondFactor 取消挑战并退出受限会话，返回清除 Cookie。
func (a *Adapter) CancelSecondFactor(ctx context.Context,
	request *http.Request) (login.UIPageMFACancelResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageMFACancelResult{}, err
	}
	if cancelErr := a.opts.MFA.CancelLogin(ctx, mfa.CancelRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		ExistingSession: secret}); cancelErr != nil && !errors.Is(cancelErr, mfa.ErrChallengeInvalid) {
		return login.UIPageMFACancelResult{}, publicMFAError(cancelErr)
	}
	_ = a.opts.Sessions.Logout(ctx, secret)
	return login.UIPageMFACancelResult{
		StateCookie:   stateCookie(mfaStateCookieName, "", -1),
		SessionCookie: a.opts.Sessions.ClearCookie()}, nil
}

// BeginStrongSetupPasskey 开始真实 Passkey 注册（PurposeBoth：可同时用于主登录与第二步）。
func (a *Adapter) BeginStrongSetupPasskey(ctx context.Context,
	request *http.Request, currentPassword string) (login.UIPageStrongSetupStart, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageStrongSetupStart{}, err
	}
	if !state.SetupRequired || a.opts.Passkeys == nil {
		return login.UIPageStrongSetupStart{}, &login.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	caller, callerErr := passkey.UserCaller(state.UserID)
	if callerErr != nil {
		return login.UIPageStrongSetupStart{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return login.UIPageStrongSetupStart{}, &login.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approvePasskey(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "注册 Passkey")
	if approveErr != nil {
		return login.UIPageStrongSetupStart{}, approveErr
	}
	start, startErr := a.opts.Passkeys.BeginRegistrationWithPurpose(challengeCtx, caller,
		requestIDFromRequest(request), passkey.PurposeBoth)
	if startErr != nil {
		return login.UIPageStrongSetupStart{}, publicMFAError(startErr)
	}
	return login.UIPageStrongSetupStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt, RPID: start.RPID}, nil
}

// FinishStrongSetupPasskey 完成真实注册并调用 CompleteStrongSetup；成功后撤销受限会话。
func (a *Adapter) FinishStrongSetupPasskey(ctx context.Context, request *http.Request,
	response []byte, currentPassword string) (login.UIPageStrongSetupResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageStrongSetupResult{}, err
	}
	if !state.SetupRequired || a.opts.Passkeys == nil {
		return login.UIPageStrongSetupResult{}, &login.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	// ceremony ID 由页面 hidden 字段承载；这里取请求表单中的单一值。
	ceremonyID := strings.TrimSpace(request.PostForm.Get("passkey_ceremony_id"))
	if ceremonyID == "" {
		return login.UIPageStrongSetupResult{}, &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	caller, callerErr := passkey.UserCaller(state.UserID)
	if callerErr != nil {
		return login.UIPageStrongSetupResult{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return login.UIPageStrongSetupResult{}, &login.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approvePasskey(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "注册 Passkey")
	if approveErr != nil {
		return login.UIPageStrongSetupResult{}, approveErr
	}
	if _, finishErr := a.opts.Passkeys.FinishRegistration(challengeCtx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: ceremonyID, Response: response,
			RequestID: requestIDFromRequest(request)}); finishErr != nil {
		return login.UIPageStrongSetupResult{}, publicMFAError(finishErr)
	}
	completed, completeErr := a.opts.MFA.CompleteStrongSetup(ctx,
		mfa.StrongSetupCompleteRequest{ChallengeID: state.ChallengeID,
			AttemptToken: state.AttemptToken, ExistingSession: secret,
			RequestID: requestIDFromRequest(request)})
	if completeErr != nil {
		return login.UIPageStrongSetupResult{}, publicMFAError(completeErr)
	}
	methods := make([]string, 0, len(completed.Methods))
	for _, method := range completed.Methods {
		methods = append(methods, string(method))
	}
	return login.UIPageStrongSetupResult{UserID: completed.UserID, Methods: methods,
		ReloginRequired: completed.MustReauthenticate,
		SessionCookie:   a.opts.Sessions.ClearCookie()}, nil
}

// BeginRecoveryCode 只读交接挑战后调用 recovery.Begin 原子消费恢复代码。
func (a *Adapter) BeginRecoveryCode(ctx context.Context, request *http.Request,
	code login.UIPageRecoveryCodeRequest) (login.UIPageRecoveryBeginResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return login.UIPageRecoveryBeginResult{}, err
	}
	if a.opts.Recovery == nil {
		return login.UIPageRecoveryBeginResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	result, handoffErr := a.opts.MFA.RecoveryAuthentication(ctx,
		mfa.RecoveryAuthenticationRequest{ChallengeID: state.ChallengeID,
			AttemptToken: state.AttemptToken, ExistingSession: secret,
			RequestID: code.RequestID})
	if handoffErr != nil {
		return login.UIPageRecoveryBeginResult{}, publicMFAError(handoffErr)
	}
	begin, beginErr := a.opts.Recovery.Begin(ctx, recovery.BeginRequest{Result: result,
		Code: code.Code, ExistingSession: secret, RequestID: code.RequestID})
	if beginErr != nil {
		return login.UIPageRecoveryBeginResult{}, publicMFAError(beginErr)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(begin.Session)
	if cookieErr != nil {
		return login.UIPageRecoveryBeginResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return login.UIPageRecoveryBeginResult{SessionCookie: cookie,
		StateCookie:    stateCookie(mfaStateCookieName, "", -1),
		ExpiresAt:      begin.ExpiresAt,
		CodesRemaining: begin.CodesRemaining}, nil
}

// LoadRecovery 读取受限恢复会话状态（只读）。
func (a *Adapter) LoadRecovery(ctx context.Context,
	request *http.Request) (login.UIPageRecoverySnapshot, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return login.UIPageRecoverySnapshot{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	snapshot, err := a.opts.Recovery.Snapshot(ctx, secret)
	if err != nil {
		return login.UIPageRecoverySnapshot{}, publicMFAError(err)
	}
	methods := make([]string, 0, len(snapshot.AllowedMethods))
	for _, method := range snapshot.AllowedMethods {
		methods = append(methods, string(method))
	}
	return login.UIPageRecoverySnapshot{ExpiresAt: snapshot.ExpiresAt,
		RequiredStrength: string(snapshot.RequiredStrength), AllowedMethods: methods,
		CodesRemaining: snapshot.CodesRemaining}, nil
}

// StartRecoveryRebind 开始绑定新安全方式。
func (a *Adapter) StartRecoveryRebind(ctx context.Context, request *http.Request,
	start login.UIPageRecoveryRebindRequest) (login.UIPageRecoveryRebindStart, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return login.UIPageRecoveryRebindStart{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	begin, err := a.opts.Recovery.BeginRebind(ctx, secret, recovery.BeginRebindRequest{
		Method: recovery.FactorMethod(start.Method), RequestID: start.RequestID})
	if err != nil {
		return login.UIPageRecoveryRebindStart{}, publicMFAError(err)
	}
	return login.UIPageRecoveryRebindStart{Method: string(begin.Method),
		BindingID: begin.BindingID, PublicData: begin.PublicData,
		ExpiresAt: begin.ExpiresAt}, nil
}

// CompleteRecoveryRebind 完成真实验证并一次性返回新代码。
func (a *Adapter) CompleteRecoveryRebind(ctx context.Context, request *http.Request,
	complete login.UIPageRecoveryRebindComplete) (login.UIPageRecoveryCompletion, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return login.UIPageRecoveryCompletion{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	result, err := a.opts.Recovery.Complete(ctx, secret, recovery.CompleteRequest{
		BindingID: complete.BindingID, Response: complete.Response,
		RequestID: complete.RequestID})
	if err != nil {
		return login.UIPageRecoveryCompletion{}, publicMFAError(err)
	}
	codes := make([]string, 0, len(result.Codes))
	for _, code := range result.Codes {
		if code.IsSet() {
			codes = append(codes, code.Reveal())
		}
	}
	return login.UIPageRecoveryCompletion{Codes: codes,
		ReloginRequired: result.ReloginRequired,
		SessionCookie:   a.opts.Sessions.ClearCookie()}, nil
}

// CancelRecovery 取消恢复尝试并退出受限恢复会话。
func (a *Adapter) CancelRecovery(ctx context.Context,
	request *http.Request) (login.UIPageMFACancelResult, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return login.UIPageMFACancelResult{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if err := a.opts.Recovery.Cancel(ctx, secret, recovery.CancelRequest{
		RequestID: requestIDFromRequest(request)}); err != nil {
		return login.UIPageMFACancelResult{}, publicMFAError(err)
	}
	_ = a.opts.Sessions.Logout(ctx, secret)
	return login.UIPageMFACancelResult{
		StateCookie:   stateCookie(mfaStateCookieName, "", -1),
		SessionCookie: a.opts.Sessions.ClearCookie()}, nil
}

// BeginPasswordReset 统一受理找回；内部故障才返回可重试系统错误。
func (a *Adapter) BeginPasswordReset(ctx context.Context, request *http.Request,
	forgot login.UIPagePasswordForgotRequest) (login.UIPagePasswordForgotResult, error) {
	if a.opts.PasswordReset == nil {
		return login.UIPagePasswordForgotResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	clientIP, _ := transport.ClientIPFromContext(ctx)
	if clientIP == "" {
		clientIP = clientIPFromRequest(request)
	}
	_, err := a.opts.PasswordReset.BeginReset(ctx, passwordreset.BeginResetRequest{
		Identifier: forgot.Identifier, ClientIP: clientIP, RequestID: forgot.RequestID})
	if err != nil {
		if errors.Is(err, passwordreset.ErrStoreUnavailable) ||
			errors.Is(err, passwordreset.ErrAuditUnavailable) {
			return login.UIPagePasswordForgotResult{}, &login.UIPageAuthError{Code: "DB_UNAVAILABLE"}
		}
		// BeginReset 对普通输入返回统一零值成功；其余错误按统一受理处理，不枚举。
		return login.UIPagePasswordForgotResult{}, nil
	}
	return login.UIPagePasswordForgotResult{}, nil
}

// ValidatePasswordReset 只读校验邮件 token（不消费）。
func (a *Adapter) ValidatePasswordReset(ctx context.Context, _ *http.Request,
	token string) error {
	if a.opts.PasswordReset == nil {
		return &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	if err := a.opts.PasswordReset.ValidateResetToken(ctx, token); err != nil {
		return &login.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return nil
}

// CompletePasswordReset 原子消费 token 并重置密码，不签发会话。
func (a *Adapter) CompletePasswordReset(ctx context.Context, request *http.Request,
	complete login.UIPagePasswordResetRequest) (login.UIPagePasswordResetResult, error) {
	if a.opts.PasswordReset == nil {
		return login.UIPagePasswordResetResult{}, &login.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	if complete.NewPassword != complete.Confirm {
		return login.UIPagePasswordResetResult{}, &login.UIPageAuthError{Code: "REQ_INVALID"}
	}
	if _, err := a.opts.PasswordReset.CompleteReset(ctx, passwordreset.CompleteRequest{
		Token: complete.Token, NewPassword: complete.NewPassword,
		RequestID: complete.RequestID}); err != nil {
		return login.UIPagePasswordResetResult{}, publicMFAError(err)
	}
	return login.UIPagePasswordResetResult{ReloginRequired: true}, nil
}

// publicMFAError 把各领域错误映射为页面稳定公开错误码。按领域哨兵显式匹配，
// 避免某领域 CodeOf 的默认 INTERNAL_ERROR 抢先命中导致其它领域用户可纠正错误
// 退化为内部错误；无任何领域匹配才返回 INTERNAL_ERROR。
func publicMFAError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *login.UIPageAuthError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	code := ""
	switch {
	case mfaError(err):
		code = string(mfa.CodeOf(err))
	case passkeyError(err):
		code = string(passkey.CodeOf(err))
	case recoveryError(err):
		code = string(recovery.CodeOf(err))
	case passwordResetError(err):
		code = string(passwordreset.CodeOf(err))
	}
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &login.UIPageAuthError{Code: code}
}

// matchesAny 报告 err 是否命中任一领域哨兵（支持 errors.Is 包装链）。
func matchesAny(err error, sentinels ...error) bool {
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// mfaError 报告错误是否属于 MFA 领域。
func mfaError(err error) bool {
	return matchesAny(err, mfa.ErrOptionsInvalid, mfa.ErrInvalidRequest, mfa.ErrAccessDenied,
		mfa.ErrStrongAuthRequired, mfa.ErrSecondFactorRequired, mfa.ErrChallengeInvalid,
		mfa.ErrChallengeExpired, mfa.ErrCodeInvalid, mfa.ErrAttemptsExceeded,
		mfa.ErrRateLimited, mfa.ErrNoVerifiedEmail, mfa.ErrFactorExists, mfa.ErrFactorNotFound,
		mfa.ErrFactorRequired, mfa.ErrMailFailed, mfa.ErrSessionUnavailable,
		mfa.ErrPolicyUnavailable, mfa.ErrStoreUnavailable, mfa.ErrAuditUnavailable,
		mfa.ErrNoAvailableMethod, mfa.ErrStrongSetupIncomplete, mfa.ErrStrongSetupDenied)
}

// passkeyError 报告错误是否属于 Passkey 领域。
func passkeyError(err error) bool {
	return matchesAny(err, passkey.ErrOptionsInvalid, passkey.ErrInvalidRequest,
		passkey.ErrAccessDenied, passkey.ErrReauthRequired, passkey.ErrMFARequired,
		passkey.ErrAuthenticationFailed, passkey.ErrCeremonyInvalid, passkey.ErrCeremonyExpired,
		passkey.ErrCredentialNotFound, passkey.ErrCredentialConflict, passkey.ErrCredentialLimit,
		passkey.ErrCloneDetected, passkey.ErrLastLoginMethod, passkey.ErrLastStrongFactor,
		passkey.ErrPurposeNotAllowed, passkey.ErrNoSecondFactor, passkey.ErrSessionUnavailable,
		passkey.ErrStoreUnavailable, passkey.ErrAuditUnavailable, passkey.ErrInternal)
}

// recoveryError 报告错误是否属于恢复领域。
func recoveryError(err error) bool {
	return matchesAny(err, recovery.ErrOptionsInvalid, recovery.ErrInvalidRequest,
		recovery.ErrAccessDenied, recovery.ErrReauthRequired, recovery.ErrStrongAuthRequired,
		recovery.ErrMFARequired, recovery.ErrRootProtected, recovery.ErrNoActiveGroup,
		recovery.ErrCodeInvalid, recovery.ErrCodeExhausted, recovery.ErrAttemptNotActive,
		recovery.ErrAttemptExpired, recovery.ErrAttemptsExceeded, recovery.ErrSessionRequired,
		recovery.ErrMethodNotAllowed, recovery.ErrStrengthNotMet, recovery.ErrRebindNotStarted,
		recovery.ErrRebindFailed, recovery.ErrBinderUnavailable, recovery.ErrFactorRevokerUnavail,
		recovery.ErrRequirementsUnavail, recovery.ErrStoreUnavailable,
		recovery.ErrSessionUnavailable, recovery.ErrAuditUnavailable,
		recovery.ErrNotificationFailed, recovery.ErrPolicyUnavailable, recovery.ErrRateLimited,
		recovery.ErrConcurrentRotation, recovery.ErrAttemptInProgress)
}

// passwordResetError 报告错误是否属于密码找回领域。
func passwordResetError(err error) bool {
	return matchesAny(err, passwordreset.ErrOptionsInvalid, passwordreset.ErrInvalidRequest,
		passwordreset.ErrAccessDenied, passwordreset.ErrTokenInvalid,
		passwordreset.ErrTokenExpired, passwordreset.ErrAccountDisabled,
		passwordreset.ErrNoPassword, passwordreset.ErrMailFailed,
		passwordreset.ErrNoVerifiedEmail, passwordreset.ErrRateLimited,
		passwordreset.ErrSessionRevoke, passwordreset.ErrStoreUnavailable,
		passwordreset.ErrAuditUnavailable)
}

// requestIDFromRequest 读取可信请求编号（缺失时返回空，服务端会以自身规则处理）。
func requestIDFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}
	return request.Header.Get("X-Request-ID")
}

// clientIPFromRequest 读取连接地址作为限流分桶回退（不是可信来源依据）。
func clientIPFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}
	host := request.RemoteAddr
	if index := strings.LastIndex(host, ":"); index > 0 {
		host = host[:index]
	}
	return strings.Trim(host, "[]")
}

// approvePasskey 通过真实 reauth 完成 passkey.register 的页面级再次认证；只产生
// 一次性批准信号，不把密码写入日志/存储。
func (a *Adapter) approvePasskey(ctx context.Context, userID, currentPassword,
	requestID, description string) (context.Context, reauth.Result, error) {
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return ctx, reauth.Result{}, &login.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	challenge, err := a.opts.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "passkey.register", TargetType: "user",
		TargetID: userID, Params: map[string]string{"purpose": "both"},
		Description: description, RequestID: requestID})
	if err != nil {
		return ctx, reauth.Result{}, publicMFAError(err)
	}
	result := reauth.Result{OperationID: "passkey.register", TargetType: "user", TargetID: userID,
		UserID: userID}
	if !challenge.Required {
		return ctx, result, nil
	}
	grant, verifyErr := a.opts.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: currentPassword, RequestID: requestID})
	if verifyErr != nil {
		return ctx, reauth.Result{}, publicMFAError(verifyErr)
	}
	strength := policy.StrengthPassword
	if grant.GrantedStrength == policy.StrengthStrong {
		strength = policy.StrengthStrong
	}
	ctx = reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: a.opts.Now().UTC(),
		Strength: strength, Complete: true, Confirmed: true, ApprovalToken: grant.Token})
	return ctx, result, nil
}
