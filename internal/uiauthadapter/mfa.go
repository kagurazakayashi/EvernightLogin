// 本文件把步骤 64 页面契约接到真实 mfa/passkey/recovery/passwordreset/session 服务。
//
// 安全边界：
//   - 第二因素尝试令牌与挑战 ID 只在签名短时效 HttpOnly Cookie 中随页面传递，
//     不进入 URL/localStorage/日志；每次读取都重新校验签名、到期与受限会话绑定。
//   - 页面不能自报“密码已通过”或“恢复代码已验证”：恢复代码前由 mfa 的只读交接
//     校验挑战+尝试令牌+受限会话，再由 recovery.Begin 原子消费代码。
//   - 强初始化的允许绑定类别由服务端 mfa 按用户下发（root/高权限固定 Passkey；
//     人工恢复 MFA 重置后的重绑用户按显式配置可能含 TOTP）。Passkey 走真实注册
//     ceremony，TOTP 走真实 BeginBinding/ConfirmBinding 验证码持久化；两者都要求
//     页面近期密码复核产生的 reauth mfa.add 证据，完成后调用 CompleteStrongSetup
//     撤销受限会话并要求重新登录，不签发完整会话。
//   - 取消/重绑/完成均调用既有服务，页面只转发 opaque Cookie 与一次性代码，不记录
//     明文秘密。
package uiauthadapter

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"net/http"
	"strings"
	"time"
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
func (a *Adapter) mfaView(start mfa.LoginStart) (ui.UIPageSecondFactor,
	*http.Cookie, error) {
	if a.opts.PageState == nil {
		return ui.UIPageSecondFactor{}, nil, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
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
		return ui.UIPageSecondFactor{}, nil, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	view := ui.UIPageSecondFactor{FactorType: state.FactorType,
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
		return mfaPageState{}, "", &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	cookie, err := request.Cookie(mfaStateCookieName)
	if err != nil || cookie == nil {
		return mfaPageState{}, "", &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	var state mfaPageState
	if err := a.opts.PageState.Open(mfaStatePurpose, cookie.Value, &state); err != nil {
		return mfaPageState{}, "", &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok {
		return mfaPageState{}, "", &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	record, err := a.opts.Sessions.Validate(ctx, secret)
	if err != nil || record.UserID != state.UserID || record.ID != state.SessionID ||
		!record.IsRestricted() || record.Kind != session.KindRestricted ||
		record.Reason != session.ReasonPendingSecondFactor || record.AppID != state.AppID {
		return mfaPageState{}, "", &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return state, secret, nil
}

// LoadSecondFactor 读取当前挑战页面数据（不消费挑战）。
func (a *Adapter) LoadSecondFactor(ctx context.Context,
	request *http.Request) (ui.UIPageSecondFactor, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageSecondFactor{}, err
	}
	options, decodeErr := base64.RawURLEncoding.DecodeString(state.PasskeyOptions)
	if decodeErr != nil {
		return ui.UIPageSecondFactor{}, &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return ui.UIPageSecondFactor{FactorType: state.FactorType,
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		MaskedEmail:       state.MaskedEmail,
		ExpiresAt:         time.UnixMilli(state.ExpiresAtMs).UTC(),
		PasskeyCeremonyID: state.PasskeyCeremonyID, PasskeyOptions: options,
		SetupRequired: state.SetupRequired, AllowedMethods: state.AllowedMethods,
		UserID: state.UserID, AppID: state.AppID}, nil
}

// VerifySecondFactor 调用真实 mfa.Verify；成功返回完整会话 Cookie 并清除临时状态。
func (a *Adapter) VerifySecondFactor(ctx context.Context, request *http.Request,
	verify ui.UIPageSecondFactorVerify) (ui.UIPageSecondFactorResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageSecondFactorResult{}, err
	}
	if verify.ChallengeID != state.ChallengeID || verify.AttemptToken != state.AttemptToken {
		return ui.UIPageSecondFactorResult{}, &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	result, verifyErr := a.opts.MFA.Verify(ctx, mfa.VerifyRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		Code: verify.Code, PasskeyCeremonyID: verify.PasskeyCeremonyID,
		PasskeyResponse: verify.PasskeyResponse, ExistingSession: secret,
		RequestID: verify.RequestID})
	if verifyErr != nil {
		return ui.UIPageSecondFactorResult{}, publicMFAError(verifyErr)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(result.Session)
	if cookieErr != nil {
		return ui.UIPageSecondFactorResult{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return ui.UIPageSecondFactorResult{SessionCookie: cookie,
		StateCookie: stateCookie(mfaStateCookieName, "", -1),
		UserID:      result.Authenticated.UserID, Username: result.Authenticated.Username}, nil
}

// ResendSecondFactor 只对邮件因素重发，更新尝试令牌/到期并旧码失效。返回的视图
// 携带新的签名状态 Cookie，由页面框架写入响应。
func (a *Adapter) ResendSecondFactor(ctx context.Context,
	request *http.Request) (ui.UIPageSecondFactor, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageSecondFactor{}, err
	}
	start, resendErr := a.opts.MFA.Resend(ctx, mfa.ResendRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		RequestID: requestIDFromRequest(request)})
	if resendErr != nil {
		return ui.UIPageSecondFactor{}, publicMFAError(resendErr)
	}
	state.AttemptToken = start.AttemptToken
	state.MaskedEmail = start.MaskedEmail
	state.ExpiresAtMs = start.ExpiresAt.UTC().UnixMilli()
	state.FactorType = string(start.FactorType)
	token, sealErr := a.opts.PageState.Seal(mfaStatePurpose, state)
	if sealErr != nil {
		return ui.UIPageSecondFactor{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	options, decodeErr := base64.RawURLEncoding.DecodeString(state.PasskeyOptions)
	if decodeErr != nil {
		return ui.UIPageSecondFactor{}, &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return ui.UIPageSecondFactor{FactorType: state.FactorType,
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		MaskedEmail: state.MaskedEmail, ExpiresAt: time.UnixMilli(state.ExpiresAtMs).UTC(),
		PasskeyCeremonyID: state.PasskeyCeremonyID, PasskeyOptions: options,
		SetupRequired: state.SetupRequired, AllowedMethods: state.AllowedMethods,
		UserID: state.UserID, AppID: state.AppID,
		StateCookie: stateCookie(mfaStateCookieName, token, a.stateTTLSeconds())}, nil
}

// CancelSecondFactor 取消挑战并退出受限会话，返回清除 Cookie。
func (a *Adapter) CancelSecondFactor(ctx context.Context,
	request *http.Request) (ui.UIPageMFACancelResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageMFACancelResult{}, err
	}
	if cancelErr := a.opts.MFA.CancelLogin(ctx, mfa.CancelRequest{
		ChallengeID: state.ChallengeID, AttemptToken: state.AttemptToken,
		ExistingSession: secret}); cancelErr != nil && !errors.Is(cancelErr, mfa.ErrChallengeInvalid) {
		return ui.UIPageMFACancelResult{}, publicMFAError(cancelErr)
	}
	_ = a.opts.Sessions.Logout(ctx, secret)
	return ui.UIPageMFACancelResult{
		StateCookie:   stateCookie(mfaStateCookieName, "", -1),
		SessionCookie: a.opts.Sessions.ClearCookie()}, nil
}

// BeginStrongSetupPasskey 开始真实 Passkey 注册（PurposeBoth：可同时用于主登录与第二步）。
func (a *Adapter) BeginStrongSetupPasskey(ctx context.Context,
	request *http.Request, currentPassword string) (ui.UIPageStrongSetupStart, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageStrongSetupStart{}, err
	}
	if !state.SetupRequired || a.opts.Passkeys == nil {
		return ui.UIPageStrongSetupStart{}, &ui.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	if !mfaStateAllowsMethod(state, authfact.MethodPasskey) {
		return ui.UIPageStrongSetupStart{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	// 步骤 253：按当前账户/角色/策略复核 Passkey 仍是允许的初始化方法。
	if methodErr := a.requireCurrentStrongSetupMethod(ctx, state.UserID,
		authfact.MethodPasskey); methodErr != nil {
		return ui.UIPageStrongSetupStart{}, methodErr
	}
	caller, callerErr := passkey.UserCaller(state.UserID)
	if callerErr != nil {
		return ui.UIPageStrongSetupStart{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return ui.UIPageStrongSetupStart{}, &ui.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approveOperation(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "passkey.register",
		map[string]string{"purpose": "both"}, "注册 Passkey")
	if approveErr != nil {
		return ui.UIPageStrongSetupStart{}, approveErr
	}
	start, startErr := a.opts.Passkeys.BeginRegistrationWithPurpose(challengeCtx, caller,
		requestIDFromRequest(request), passkey.PurposeBoth)
	if startErr != nil {
		return ui.UIPageStrongSetupStart{}, publicMFAError(startErr)
	}
	return ui.UIPageStrongSetupStart{CeremonyID: start.CeremonyID,
		PublicKey: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt, RPID: start.RPID}, nil
}

// FinishStrongSetupPasskey 完成真实注册并调用 CompleteStrongSetup；成功后撤销受限会话。
func (a *Adapter) FinishStrongSetupPasskey(ctx context.Context, request *http.Request,
	response []byte, currentPassword string) (ui.UIPageStrongSetupResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageStrongSetupResult{}, err
	}
	if !state.SetupRequired || a.opts.Passkeys == nil {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	if !mfaStateAllowsMethod(state, authfact.MethodPasskey) {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	// 步骤 253：完成注册前复核 Passkey 仍是允许方法；CompleteStrongSetup 内再在
	// 同一事务里复核方法与绑定，防止角色/策略在该窗口变化后仍完成初始化。
	if methodErr := a.requireCurrentStrongSetupMethod(ctx, state.UserID,
		authfact.MethodPasskey); methodErr != nil {
		return ui.UIPageStrongSetupResult{}, methodErr
	}
	// ceremony ID 由页面 hidden 字段承载；这里取请求表单中的单一值。
	ceremonyID := strings.TrimSpace(request.PostForm.Get("passkey_ceremony_id"))
	if ceremonyID == "" {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	caller, callerErr := passkey.UserCaller(state.UserID)
	if callerErr != nil {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approveOperation(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "passkey.register",
		map[string]string{"purpose": "both"}, "注册 Passkey")
	if approveErr != nil {
		return ui.UIPageStrongSetupResult{}, approveErr
	}
	if _, finishErr := a.opts.Passkeys.FinishRegistration(challengeCtx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: ceremonyID, Response: response,
			RequestID: requestIDFromRequest(request)}); finishErr != nil {
		return ui.UIPageStrongSetupResult{}, publicMFAError(finishErr)
	}
	completed, completeErr := a.opts.MFA.CompleteStrongSetup(ctx,
		mfa.StrongSetupCompleteRequest{ChallengeID: state.ChallengeID,
			AttemptToken: state.AttemptToken, ExistingSession: secret,
			Method: authfact.MethodPasskey, RequestID: requestIDFromRequest(request)})
	if completeErr != nil {
		return ui.UIPageStrongSetupResult{}, publicMFAError(completeErr)
	}
	methods := make([]string, 0, len(completed.Methods))
	for _, method := range completed.Methods {
		methods = append(methods, string(method))
	}
	return ui.UIPageStrongSetupResult{UserID: completed.UserID, Methods: methods,
		ReloginRequired: completed.MustReauthenticate,
		SessionCookie:   a.opts.Sessions.ClearCookie()}, nil
}

// BeginStrongSetupTOTP 在受限初始化/人工恢复重绑会话内开始真实 TOTP 绑定：
//   - 状态必须来自服务端签名 Cookie 且 SetupRequired，当前会话必须是该受限会话；
//   - 绑定方法必须在服务端下发的 AllowedMethods 中（页面隐藏字段不可信）；
//   - 页面密码复核通过 reauth 的 mfa.add（近期主密码，与普通绑定同一要求，不放宽）
//     后才调用 totp.BeginBinding 生成加密保存的 pending 绑定；
//   - 只返回一次性种子/otpauth URI 给当前用户，不写日志/审计/普通存储。
func (a *Adapter) BeginStrongSetupTOTP(ctx context.Context,
	request *http.Request, currentPassword string) (ui.UIPageStrongSetupTOTPStart, error) {
	state, _, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageStrongSetupTOTPStart{}, err
	}
	if !state.SetupRequired || a.opts.TOTP == nil {
		return ui.UIPageStrongSetupTOTPStart{}, &ui.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	if !mfaStateAllowsMethod(state, authfact.MethodTOTP) {
		return ui.UIPageStrongSetupTOTPStart{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	// 步骤 253：按当前账户/角色/策略复核 TOTP 仍是允许的初始化方法，避免在角色
	// 提升/撤销后继续生成可用的 TOTP 绑定（R10-19）。
	if methodErr := a.requireCurrentStrongSetupMethod(ctx, state.UserID,
		authfact.MethodTOTP); methodErr != nil {
		return ui.UIPageStrongSetupTOTPStart{}, methodErr
	}
	caller, callerErr := totp.UserCaller(state.UserID)
	if callerErr != nil {
		return ui.UIPageStrongSetupTOTPStart{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return ui.UIPageStrongSetupTOTPStart{}, &ui.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approveOperation(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "mfa.add",
		map[string]string{"factor": "totp"}, "绑定 TOTP 验证器")
	if approveErr != nil {
		return ui.UIPageStrongSetupTOTPStart{}, approveErr
	}
	start, startErr := a.opts.TOTP.BeginBinding(challengeCtx, caller,
		requestIDFromRequest(request))
	if startErr != nil {
		return ui.UIPageStrongSetupTOTPStart{}, publicMFAError(startErr)
	}
	return ui.UIPageStrongSetupTOTPStart{BindingID: start.BindingID,
		Secret: start.Secret, URI: start.URI, ExpiresAt: start.ExpiresAt,
		PeriodSeconds: start.PeriodSeconds, Digits: start.Digits}, nil
}

// FinishStrongSetupTOTP 完成真实 TOTP 绑定并结束受限初始化：
//   - 再次要求页面密码复核（与 Passkey 完成一致），并取得 mfa.add reauth 证据后
//     调用 totp.ConfirmBinding 验证真实验证码并原子激活新绑定；
//   - 只有服务端确认 TOTP 已真实新绑定后，mfa.CompleteStrongSetup 才清除重绑需求、
//     撤销受限会话并要求重新登录；不返回完整会话。
func (a *Adapter) FinishStrongSetupTOTP(ctx context.Context, request *http.Request,
	bindingID, code, currentPassword string) (ui.UIPageStrongSetupResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageStrongSetupResult{}, err
	}
	if !state.SetupRequired || a.opts.TOTP == nil {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "MFA_REQUIRED"}
	}
	if !mfaStateAllowsMethod(state, authfact.MethodTOTP) {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	// 步骤 253：确认验证码前复核 TOTP 仍是允许方法（角色提升/撤销、恢复要求变化
	// 时立即拒绝，不激活本次绑定）。
	if methodErr := a.requireCurrentStrongSetupMethod(ctx, state.UserID,
		authfact.MethodTOTP); methodErr != nil {
		return ui.UIPageStrongSetupResult{}, methodErr
	}
	if bindingID == "" || len(bindingID) > 128 || code == "" || len(code) > 16 {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "REQ_INVALID"}
	}
	caller, callerErr := totp.UserCaller(state.UserID)
	if callerErr != nil {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return ui.UIPageStrongSetupResult{}, &ui.UIPageAuthError{Code: "REAUTH_REQUIRED"}
	}
	challengeCtx, _, approveErr := a.approveOperation(ctx, state.UserID, currentPassword,
		requestIDFromRequest(request), "mfa.add",
		map[string]string{"factor": "totp"}, "绑定 TOTP 验证器")
	if approveErr != nil {
		return ui.UIPageStrongSetupResult{}, approveErr
	}
	binding, confirmErr := a.opts.TOTP.ConfirmBinding(challengeCtx, caller,
		totp.BindConfirm{BindingID: bindingID, Code: code,
			RequestID: requestIDFromRequest(request)})
	if confirmErr != nil {
		return ui.UIPageStrongSetupResult{}, publicMFAError(confirmErr)
	}
	completed, completeErr := a.opts.MFA.CompleteStrongSetup(ctx,
		mfa.StrongSetupCompleteRequest{ChallengeID: state.ChallengeID,
			AttemptToken: state.AttemptToken, ExistingSession: secret,
			Method: authfact.MethodTOTP, RequestID: requestIDFromRequest(request)})
	if completeErr != nil {
		// 步骤 253 / R10-19：TOTP 已激活但完成被拒（例如在确认与完成之间角色/
		// 策略变化）。回滚本次刚激活的绑定，避免留下“暂存 TOTP 存在但重绑要求
		// 未清除”的受限残留；回滚失败只记录，不改变原始拒绝结果（fail-closed）。
		if rollbackErr := a.opts.TOTP.RollbackStrongSetupBinding(ctx, caller,
			binding.ID, requestIDFromRequest(request)); rollbackErr != nil {
			a.opts.Logger.Warn("强初始化完成后回滚 TOTP 绑定失败",
				"error_category", "strong_setup_rollback_failed")
		}
		return ui.UIPageStrongSetupResult{}, publicMFAError(completeErr)
	}
	methods := make([]string, 0, len(completed.Methods))
	for _, method := range completed.Methods {
		methods = append(methods, string(method))
	}
	return ui.UIPageStrongSetupResult{UserID: completed.UserID, Methods: methods,
		ReloginRequired: completed.MustReauthenticate,
		SessionCookie:   a.opts.Sessions.ClearCookie()}, nil
}

// requireCurrentStrongSetupMethod 在开始/完成具体强因素绑定前，按当前账户、角色/
// 高权限过渡态与策略重新确认该方法仍允许绑定（步骤 253 / R10-19）：不能只信任
// 登录时签入页面的签名状态；角色在受限初始化期间被提升/撤销或恢复要求已更新时，
// 应立即拒绝，不能继续产生可用因素或宣称完成。判定不可用一律 fail-closed。
func (a *Adapter) requireCurrentStrongSetupMethod(ctx context.Context, userID string,
	method authfact.Method) error {
	if a.opts.MFA == nil {
		return &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	if _, err := a.opts.MFA.CheckStrongSetupMethod(ctx, userID, method); err != nil {
		switch {
		case errors.Is(err, mfa.ErrStrongSetupIncomplete):
			return &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
		case errors.Is(err, mfa.ErrPolicyUnavailable):
			return &ui.UIPageAuthError{Code: "AUTHZ_UNAVAILABLE"}
		default:
			return &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
		}
	}
	return nil
}

// publicReauthError 把再次认证领域错误映射为页面稳定公开错误码；密码错误返回
// AUTH_FAILED（可纠正），挑战过期/已用显示失效，存储故障为可重试系统错误，只有
// 真正未映射的内部错误才返回 INTERNAL_ERROR。
func publicReauthError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIPageAuthError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	code := "INTERNAL_ERROR"
	switch {
	case errors.Is(err, reauth.ErrAccessDenied):
		code = "ACCESS_DENIED"
	case errors.Is(err, reauth.ErrAuthenticationFailed):
		code = "AUTH_FAILED"
	case errors.Is(err, reauth.ErrChallengeInvalid), errors.Is(err, reauth.ErrChallengeExpired),
		errors.Is(err, reauth.ErrAttemptsExceeded):
		code = "CHALLENGE_INVALID"
	case errors.Is(err, reauth.ErrMFARequired):
		code = "MFA_REQUIRED"
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrApprovalInvalid),
		errors.Is(err, reauth.ErrApprovalExpired), errors.Is(err, reauth.ErrApprovalConsumed):
		code = "REAUTH_REQUIRED"
	case errors.Is(err, reauth.ErrRateLimited):
		code = "RATE_LIMITED"
	case errors.Is(err, reauth.ErrStoreUnavailable), errors.Is(err, reauth.ErrPolicyUnavailable),
		errors.Is(err, reauth.ErrAuditUnavailable), errors.Is(err, reauth.ErrNotificationFailed):
		code = "DB_UNAVAILABLE"
	}
	return &ui.UIPageAuthError{Code: code}
}

// mfaStateAllowsMethod 报告服务端签名状态下发的方法类别是否包含指定方法。
func mfaStateAllowsMethod(state mfaPageState, method authfact.Method) bool {
	for _, allowed := range state.AllowedMethods {
		if allowed == string(method) {
			return true
		}
	}
	return false
}

// BeginRecoveryCode 只读交接挑战后调用 recovery.Begin 原子消费恢复代码。
func (a *Adapter) BeginRecoveryCode(ctx context.Context, request *http.Request,
	code ui.UIPageRecoveryCodeRequest) (ui.UIPageRecoveryBeginResult, error) {
	state, secret, err := a.loadMFAState(ctx, request)
	if err != nil {
		return ui.UIPageRecoveryBeginResult{}, err
	}
	if a.opts.Recovery == nil {
		return ui.UIPageRecoveryBeginResult{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	result, handoffErr := a.opts.MFA.RecoveryAuthentication(ctx,
		mfa.RecoveryAuthenticationRequest{ChallengeID: state.ChallengeID,
			AttemptToken: state.AttemptToken, ExistingSession: secret,
			RequestID: code.RequestID})
	if handoffErr != nil {
		return ui.UIPageRecoveryBeginResult{}, publicMFAError(handoffErr)
	}
	begin, beginErr := a.opts.Recovery.Begin(ctx, recovery.BeginRequest{Result: result,
		Code: code.Code, ExistingSession: secret, RequestID: code.RequestID})
	if beginErr != nil {
		return ui.UIPageRecoveryBeginResult{}, publicMFAError(beginErr)
	}
	cookie, cookieErr := a.opts.Sessions.NewCookie(begin.Session)
	if cookieErr != nil {
		return ui.UIPageRecoveryBeginResult{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	return ui.UIPageRecoveryBeginResult{SessionCookie: cookie,
		StateCookie:    stateCookie(mfaStateCookieName, "", -1),
		ExpiresAt:      begin.ExpiresAt,
		CodesRemaining: begin.CodesRemaining}, nil
}

// LoadRecovery 读取受限恢复会话状态（只读）。
func (a *Adapter) LoadRecovery(ctx context.Context,
	request *http.Request) (ui.UIPageRecoverySnapshot, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return ui.UIPageRecoverySnapshot{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	snapshot, err := a.opts.Recovery.Snapshot(ctx, secret)
	if err != nil {
		return ui.UIPageRecoverySnapshot{}, publicMFAError(err)
	}
	methods := make([]string, 0, len(snapshot.AllowedMethods))
	for _, method := range snapshot.AllowedMethods {
		methods = append(methods, string(method))
	}
	return ui.UIPageRecoverySnapshot{ExpiresAt: snapshot.ExpiresAt,
		RequiredStrength: string(snapshot.RequiredStrength), AllowedMethods: methods,
		CodesRemaining: snapshot.CodesRemaining}, nil
}

// StartRecoveryRebind 开始绑定新安全方式。
func (a *Adapter) StartRecoveryRebind(ctx context.Context, request *http.Request,
	start ui.UIPageRecoveryRebindRequest) (ui.UIPageRecoveryRebindStart, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return ui.UIPageRecoveryRebindStart{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	begin, err := a.opts.Recovery.BeginRebind(ctx, secret, recovery.BeginRebindRequest{
		Method: recovery.FactorMethod(start.Method), RequestID: start.RequestID})
	if err != nil {
		return ui.UIPageRecoveryRebindStart{}, publicMFAError(err)
	}
	return ui.UIPageRecoveryRebindStart{Method: string(begin.Method),
		BindingID: begin.BindingID, PublicData: begin.PublicData,
		ExpiresAt: begin.ExpiresAt}, nil
}

// CompleteRecoveryRebind 完成真实验证并一次性返回新代码。
func (a *Adapter) CompleteRecoveryRebind(ctx context.Context, request *http.Request,
	complete ui.UIPageRecoveryRebindComplete) (ui.UIPageRecoveryCompletion, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return ui.UIPageRecoveryCompletion{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	result, err := a.opts.Recovery.Complete(ctx, secret, recovery.CompleteRequest{
		BindingID: complete.BindingID, Response: complete.Response,
		RequestID: complete.RequestID})
	if err != nil {
		return ui.UIPageRecoveryCompletion{}, publicMFAError(err)
	}
	codes := make([]string, 0, len(result.Codes))
	for _, code := range result.Codes {
		if code.IsSet() {
			codes = append(codes, code.Reveal())
		}
	}
	return ui.UIPageRecoveryCompletion{Codes: codes,
		ReloginRequired: result.ReloginRequired,
		SessionCookie:   a.opts.Sessions.ClearCookie()}, nil
}

// CancelRecovery 取消恢复尝试并退出受限恢复会话。
func (a *Adapter) CancelRecovery(ctx context.Context,
	request *http.Request) (ui.UIPageMFACancelResult, error) {
	secret, ok := a.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || a.opts.Recovery == nil {
		return ui.UIPageMFACancelResult{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	if err := a.opts.Recovery.Cancel(ctx, secret, recovery.CancelRequest{
		RequestID: requestIDFromRequest(request)}); err != nil {
		return ui.UIPageMFACancelResult{}, publicMFAError(err)
	}
	_ = a.opts.Sessions.Logout(ctx, secret)
	return ui.UIPageMFACancelResult{
		StateCookie:   stateCookie(mfaStateCookieName, "", -1),
		SessionCookie: a.opts.Sessions.ClearCookie()}, nil
}

// BeginPasswordReset 统一受理找回；内部故障才返回可重试系统错误。
func (a *Adapter) BeginPasswordReset(ctx context.Context, request *http.Request,
	forgot ui.UIPagePasswordForgotRequest) (ui.UIPagePasswordForgotResult, error) {
	if a.opts.PasswordReset == nil {
		return ui.UIPagePasswordForgotResult{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
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
			return ui.UIPagePasswordForgotResult{}, &ui.UIPageAuthError{Code: "DB_UNAVAILABLE"}
		}
		// BeginReset 对普通输入返回统一零值成功；其余错误按统一受理处理，不枚举。
		return ui.UIPagePasswordForgotResult{}, nil
	}
	return ui.UIPagePasswordForgotResult{}, nil
}

// ValidatePasswordReset 只读校验邮件 token（不消费）。
func (a *Adapter) ValidatePasswordReset(ctx context.Context, _ *http.Request,
	token string) error {
	if a.opts.PasswordReset == nil {
		return &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	if err := a.opts.PasswordReset.ValidateResetToken(ctx, token); err != nil {
		return &ui.UIPageAuthError{Code: "CHALLENGE_INVALID"}
	}
	return nil
}

// CompletePasswordReset 原子消费 token 并重置密码，不签发会话。
func (a *Adapter) CompletePasswordReset(ctx context.Context, request *http.Request,
	complete ui.UIPagePasswordResetRequest) (ui.UIPagePasswordResetResult, error) {
	if a.opts.PasswordReset == nil {
		return ui.UIPagePasswordResetResult{}, &ui.UIPageAuthError{Code: "INTERNAL_ERROR"}
	}
	if complete.NewPassword != complete.Confirm {
		return ui.UIPagePasswordResetResult{}, &ui.UIPageAuthError{Code: "REQ_INVALID"}
	}
	if _, err := a.opts.PasswordReset.CompleteReset(ctx, passwordreset.CompleteRequest{
		Token: complete.Token, NewPassword: complete.NewPassword,
		RequestID: complete.RequestID}); err != nil {
		return ui.UIPagePasswordResetResult{}, publicMFAError(err)
	}
	return ui.UIPagePasswordResetResult{ReloginRequired: true}, nil
}

// publicMFAError 把各领域错误映射为页面稳定公开错误码。按领域哨兵显式匹配，
// 避免某领域 CodeOf 的默认 INTERNAL_ERROR 抢先命中导致其它领域用户可纠正错误
// 退化为内部错误；无任何领域匹配才返回 INTERNAL_ERROR。
func publicMFAError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIPageAuthError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	code := ""
	switch {
	case mfaError(err):
		code = string(mfa.CodeOf(err))
	case passkeyError(err):
		code = string(passkey.CodeOf(err))
	case totpError(err):
		code = string(totp.CodeOf(err))
	case recoveryError(err):
		code = string(recovery.CodeOf(err))
	case passwordResetError(err):
		code = string(passwordreset.CodeOf(err))
	}
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &ui.UIPageAuthError{Code: code}
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

// totpError 报告错误是否属于 TOTP 领域。
func totpError(err error) bool {
	return matchesAny(err, totp.ErrOptionsInvalid, totp.ErrInvalidRequest,
		totp.ErrAccessDenied, totp.ErrReauthRequired, totp.ErrMFARequired,
		totp.ErrBindingNotFound, totp.ErrBindingExpired, totp.ErrCodeInvalid,
		totp.ErrAttemptsExceeded, totp.ErrReplay, totp.ErrFactorRequired,
		totp.ErrRateLimited, totp.ErrSealFailed, totp.ErrPolicyUnavailable,
		totp.ErrStoreUnavailable, totp.ErrAuditUnavailable)
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

// approveOperation 通过真实 reauth 完成页面级敏感操作的再次认证；只产生一次性批准
// 信号，不把密码写入日志/存储。operationID/params 必须与目标领域服务在执行时向
// reauth.Authorize 提交的完全一致，否则批准令牌无法被消费（fail-closed）。
func (a *Adapter) approveOperation(ctx context.Context, userID, currentPassword,
	requestID, operationID string, params map[string]string,
	description string) (context.Context, reauth.Result, error) {
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return ctx, reauth.Result{}, &ui.UIPageAuthError{Code: "ACCESS_DENIED"}
	}
	challenge, err := a.opts.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: operationID, TargetType: "user",
		TargetID: userID, Params: params,
		Description: description, RequestID: requestID})
	if err != nil {
		return ctx, reauth.Result{}, publicReauthError(err)
	}
	result := reauth.Result{OperationID: operationID, TargetType: "user", TargetID: userID,
		UserID: userID}
	if !challenge.Required {
		return ctx, result, nil
	}
	grant, verifyErr := a.opts.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: currentPassword, RequestID: requestID})
	if verifyErr != nil {
		return ctx, reauth.Result{}, publicReauthError(verifyErr)
	}
	strength := policy.StrengthPassword
	if grant.GrantedStrength == policy.StrengthStrong {
		strength = policy.StrengthStrong
	}
	ctx = reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: a.opts.Now().UTC(),
		Strength: strength, Complete: true, Confirmed: true, ApprovalToken: grant.Token})
	return ctx, result, nil
}
