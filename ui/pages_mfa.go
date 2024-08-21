// 本文件实现步骤 64 的页面契约与处理器：第二因素（邮件/TOTP/Passkey）、强因素
// 初始化、忘记/重置密码、恢复代码与受限恢复重绑。
//
// 安全边界：
//   - 页面只消费公开安全摘要与后端适配器返回的白名单数据；受限会话、挑战、尝试
//     令牌、Passkey ceremony、恢复绑定等真实校验全部在服务端适配器与既有域名服务
//     中完成；页面不解析 Cookie 身份、不信任客户端自报状态。
//   - 第二因素/恢复/找回表单在匿名公开路径上使用步骤 63 的签名双提交令牌与
//     Origin/Referer 校验；会话 Cookie 由适配器用真实 session 服务生成，页面只
//     转发 opaque Cookie，不读取/记录明文秘密。
//   - Passkey 只使用服务端 options 与真实 ceremony；浏览器异常只映射安全文案，
//     不自动降级、不把失败当成功；秘密不进入 URL/localStorage/日志/审计。
package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// UIPageMFAOptions 是步骤 64 页面配置。
type UIPageMFAOptions struct {
	Backend UIPageMFABackend
	// LoginPath 是未登录/流程失效时的站内登录路径；空使用 "/login"。
	LoginPath string
	// PostLoginPath 是第二因素成功后的站内落地路径；空使用 "/home"。
	PostLoginPath string
}

// UIPageMFABackend 是页面调用真实 MFA/恢复/找回服务的最小契约。生产适配器必须
// 使用 internal/mfa、internal/passkey、internal/recovery、internal/passwordreset、
// internal/session 完成真实校验与 Cookie 签发；页面输入只有白名单表单字段。
type UIPageMFABackend interface {
	// LoadSecondFactor 读取当前受限第二因素会话对应的挑战页面数据（无状态/失效
	// 返回稳定公开错误）。
	LoadSecondFactor(ctx context.Context, request *http.Request) (UIPageSecondFactor, error)
	// VerifySecondFactor 执行邮件/TOTP 验证码或 Passkey 第二步断言；成功返回完整
	// 会话 Cookie 并要求清除临时状态。
	VerifySecondFactor(ctx context.Context, request *http.Request,
		verify UIPageSecondFactorVerify) (UIPageSecondFactorResult, error)
	ResendSecondFactor(ctx context.Context, request *http.Request) (UIPageSecondFactor, error)
	CancelSecondFactor(ctx context.Context, request *http.Request) (UIPageMFACancelResult, error)

	// BeginStrongSetupPasskey 为受限初始化会话开始真实 Passkey 注册 ceremony。
	BeginStrongSetupPasskey(ctx context.Context, request *http.Request, currentPassword string) (UIPageStrongSetupStart, error)
	// FinishStrongSetupPasskey 完成真实 Passkey 注册并调用 CompleteStrongSetup；
	// 成功后受限会话撤销、必须重新登录。
	FinishStrongSetupPasskey(ctx context.Context, request *http.Request,
		response []byte, currentPassword string) (UIPageStrongSetupResult, error)
	// BeginStrongSetupTOTP 为受限初始化会话（人工恢复 MFA 重置后的重绑用户）开始
	// 真实 TOTP 绑定；只有服务端下发允许 TOTP 类别时可用，页面密码复核不放宽。
	BeginStrongSetupTOTP(ctx context.Context, request *http.Request,
		currentPassword string) (UIPageStrongSetupTOTPStart, error)
	// FinishStrongSetupTOTP 验证真实 TOTP 验证码并完成初始化；成功后清重绑需求、
	// 撤销受限会话、必须重新登录。
	FinishStrongSetupTOTP(ctx context.Context, request *http.Request,
		bindingID, code, currentPassword string) (UIPageStrongSetupResult, error)

	// BeginRecoveryCode 用恢复代码替代第二步：受控读取当前挑战并原子消费代码，
	// 成功返回受限恢复会话 Cookie。
	BeginRecoveryCode(ctx context.Context, request *http.Request,
		code UIPageRecoveryCodeRequest) (UIPageRecoveryBeginResult, error)
	LoadRecovery(ctx context.Context, request *http.Request) (UIPageRecoverySnapshot, error)
	StartRecoveryRebind(ctx context.Context, request *http.Request,
		start UIPageRecoveryRebindRequest) (UIPageRecoveryRebindStart, error)
	CompleteRecoveryRebind(ctx context.Context, request *http.Request,
		complete UIPageRecoveryRebindComplete) (UIPageRecoveryCompletion, error)
	CancelRecovery(ctx context.Context, request *http.Request) (UIPageMFACancelResult, error)

	// BeginPasswordReset 统一受理找回请求（不枚举账户）。
	BeginPasswordReset(ctx context.Context, request *http.Request,
		requestData UIPagePasswordForgotRequest) (UIPagePasswordForgotResult, error)
	// ValidatePasswordReset 只读校验邮件入口 token（不消费）。
	ValidatePasswordReset(ctx context.Context, request *http.Request, token string) error
	// CompletePasswordReset 原子消费 token 并重置密码；不签发会话、不解除 MFA。
	CompletePasswordReset(ctx context.Context, request *http.Request,
		complete UIPagePasswordResetRequest) (UIPagePasswordResetResult, error)
}

// UIPageSecondFactor 是第二因素页可展示状态（不含会话秘密）。
type UIPageSecondFactor struct {
	FactorType        string
	ChallengeID       string
	AttemptToken      string
	MaskedEmail       string
	ExpiresAt         time.Time
	PasskeyCeremonyID string
	PasskeyOptions    []byte
	SetupRequired     bool
	AllowedMethods    []string
	UserID            string
	AppID             string
	// StateCookie 是重发后需要更新的签名状态 Cookie（仅适配器设置）。
	StateCookie *http.Cookie
}

// UIPageSecondFactorVerify 是第二因素验证表单字段。
type UIPageSecondFactorVerify struct {
	ChallengeID       string
	AttemptToken      string
	Code              string
	PasskeyCeremonyID string
	PasskeyResponse   []byte
	RequestID         string
}

// UIPageSecondFactorResult 是第二因素成功结果。
type UIPageSecondFactorResult struct {
	SessionCookie *http.Cookie
	StateCookie   *http.Cookie // 清除临时状态（MaxAge<0）
	UserID        string
	Username      string
}

// UIPageMFACancelResult 是取消当前流程的结果（清除 Cookie；不伪造登录成功）。
type UIPageMFACancelResult struct {
	StateCookie   *http.Cookie
	SessionCookie *http.Cookie
	Message       string
}

// UIPageStrongSetupStart 是强初始化 Passkey 注册 ceremony。
type UIPageStrongSetupStart struct {
	CeremonyID string
	PublicKey  []byte
	ExpiresAt  time.Time
	RPID       string
}

// UIPageStrongSetupTOTPStart 是强初始化 TOTP 绑定开始结果；Secret/URI 只展示给
// 当前用户（otpauth URI 可作为二维码内容），不进入日志/审计/URL。
type UIPageStrongSetupTOTPStart struct {
	BindingID     string
	Secret        string
	URI           string
	ExpiresAt     time.Time
	PeriodSeconds int
	Digits        int
}

// UIPageStrongSetupResult 是强初始化完成结果；必须重新登录。
type UIPageStrongSetupResult struct {
	UserID          string
	Methods         []string
	ReloginRequired bool
	SessionCookie   *http.Cookie // 清除受限会话
}

// UIPageRecoveryCodeRequest 是恢复代码表单。
type UIPageRecoveryCodeRequest struct {
	Code      string
	RequestID string
}

// UIPageRecoveryBeginResult 是恢复代码成功后的受限恢复会话。
type UIPageRecoveryBeginResult struct {
	SessionCookie  *http.Cookie
	StateCookie    *http.Cookie
	ExpiresAt      time.Time
	CodesRemaining int
}

// UIPageRecoverySnapshot 是恢复页只读状态。
type UIPageRecoverySnapshot struct {
	ExpiresAt        time.Time
	RequiredStrength string
	AllowedMethods   []string
	CodesRemaining   int
}

// UIPageRecoveryRebindRequest 是选择新安全方式请求。
type UIPageRecoveryRebindRequest struct {
	Method    string
	RequestID string
}

// UIPageRecoveryRebindStart 是绑定开始结果（PublicData 只展示给当前用户）。
type UIPageRecoveryRebindStart struct {
	Method     string
	BindingID  string
	PublicData []byte
	ExpiresAt  time.Time
}

// UIPageRecoveryRebindComplete 是完成重绑请求（真实认证器/验证器响应）。
type UIPageRecoveryRebindComplete struct {
	BindingID string
	Method    string
	Response  []byte
	RequestID string
}

// UIPageRecoveryCompletion 是恢复完成结果。
type UIPageRecoveryCompletion struct {
	Codes           []string
	ReloginRequired bool
	SessionCookie   *http.Cookie
}

// UIPagePasswordForgotRequest 是找回受理表单。
type UIPagePasswordForgotRequest struct {
	Identifier string
	RequestID  string
}

// UIPagePasswordForgotResult 是统一受理结果（不区分账户状态）。
type UIPagePasswordForgotResult struct{}

// UIPagePasswordResetRequest 是重置密码表单。
type UIPagePasswordResetRequest struct {
	Token       string
	NewPassword string
	Confirm     string
	RequestID   string
}

// UIPagePasswordResetResult 是重置结果（不签发会话）。
type UIPagePasswordResetResult struct {
	ReloginRequired bool
}

// PageMFARouteNames 返回步骤 64 注册的命名路由（供宿主配置公开表单路径/诊断）。
func PageMFARouteNames() []string {
	return []string{
		"auth.second_factor", "auth.second_factor.verify", "auth.second_factor.resend",
		"auth.second_factor.cancel", "auth.strong_setup", "auth.strong_setup.passkey_start",
		"auth.strong_setup.passkey_finish", "auth.strong_setup.totp_start",
		"auth.strong_setup.totp_finish", "auth.recovery_code",
		"auth.recovery_code.submit", "auth.recovery_rebind", "auth.recovery_rebind.start",
		"auth.recovery_rebind.complete", "auth.recovery_cancel", "auth.password_forgot",
		"auth.password_forgot.submit", "auth.password_reset", "auth.password_reset.submit",
	}
}

// UIPageMFAPublicFormPaths 返回匿名公开表单路径与用途（含部署前缀），供宿主配置
// transport CSRF 公开表单白名单与匿名令牌校验器。
func UIPageMFAPublicFormPaths(prefix string) map[string]string {
	return map[string]string{
		prefix + "/login/second-factor":               "auth.second_factor",
		prefix + "/login/second-factor/resend":        "auth.second_factor",
		prefix + "/login/second-factor/cancel":        "auth.second_factor",
		prefix + "/login/strong-setup/passkey/start":  "auth.strong_setup",
		prefix + "/login/strong-setup/passkey/finish": "auth.strong_setup",
		prefix + "/login/strong-setup/totp/start":     "auth.strong_setup",
		prefix + "/login/strong-setup/totp/finish":    "auth.strong_setup",
		prefix + "/login/recovery-code":               "auth.recovery_code",
		prefix + "/login/recovery/rebind/start":       "auth.recovery_rebind",
		prefix + "/login/recovery/rebind/complete":    "auth.recovery_rebind",
		prefix + "/login/recovery/cancel":             "auth.recovery_rebind",
		prefix + "/login/forgot-password":             "auth.password_forgot",
		prefix + "/login/reset-password":              "auth.password_reset",
	}
}

// pageMFAPages 是步骤 64 内置页面的路由与处理器。
type pageMFAPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageMFAOptions
}

// newPageMFAPages 校验配置并构造路由/处理器。
func newPageMFAPages(options UIPageMFAOptions) (*pageMFAPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("页面 MFA/恢复适配器不能为空")
	}
	if options.LoginPath == "" {
		options.LoginPath = "/login"
	}
	if options.PostLoginPath == "" {
		options.PostLoginPath = "/home"
	}
	if !safeRelativePath(options.LoginPath) || !safeRelativePath(options.PostLoginPath) {
		return nil, fmt.Errorf("MFA 页面登录/落地路径必须是站内相对路径")
	}
	pages := &pageMFAPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &mfaPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "auth.second_factor", Method: http.MethodGet, Path: "/login/second-factor",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/second_factor"},
		{Name: "auth.second_factor.verify", Method: http.MethodPost, Path: "/login/second-factor",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/second_factor"},
		{Name: "auth.second_factor.resend", Method: http.MethodPost, Path: "/login/second-factor/resend",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/second_factor"},
		{Name: "auth.second_factor.cancel", Method: http.MethodPost, Path: "/login/second-factor/cancel",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/second_factor"},
		{Name: "auth.strong_setup", Method: http.MethodGet, Path: "/login/strong-setup",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/strong_setup"},
		{Name: "auth.strong_setup.passkey_start", Method: http.MethodPost,
			Path: "/login/strong-setup/passkey/start", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/strong_setup"},
		{Name: "auth.strong_setup.passkey_finish", Method: http.MethodPost,
			Path: "/login/strong-setup/passkey/finish", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/strong_setup"},
		{Name: "auth.strong_setup.totp_start", Method: http.MethodPost,
			Path: "/login/strong-setup/totp/start", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/strong_setup"},
		{Name: "auth.strong_setup.totp_finish", Method: http.MethodPost,
			Path: "/login/strong-setup/totp/finish", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/strong_setup"},
		{Name: "auth.recovery_code", Method: http.MethodGet, Path: "/login/recovery-code",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/recovery_code"},
		{Name: "auth.recovery_code.submit", Method: http.MethodPost, Path: "/login/recovery-code",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/recovery_code"},
		{Name: "auth.recovery_rebind", Method: http.MethodGet, Path: "/login/recovery/rebind",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/recovery_rebind"},
		{Name: "auth.recovery_rebind.start", Method: http.MethodPost,
			Path: "/login/recovery/rebind/start", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/recovery_rebind"},
		{Name: "auth.recovery_rebind.complete", Method: http.MethodPost,
			Path: "/login/recovery/rebind/complete", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/recovery_rebind"},
		{Name: "auth.recovery_cancel", Method: http.MethodPost, Path: "/login/recovery/cancel",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/recovery_rebind"},
		{Name: "auth.password_forgot", Method: http.MethodGet, Path: "/login/forgot-password",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/password_forgot"},
		{Name: "auth.password_forgot.submit", Method: http.MethodPost,
			Path: "/login/forgot-password", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/password_forgot"},
		{Name: "auth.password_reset", Method: http.MethodGet, Path: "/login/reset-password",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/password_reset"},
		{Name: "auth.password_reset.submit", Method: http.MethodPost,
			Path: "/login/reset-password", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/password_reset"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// mfaFormPurposeForRoute 把步骤 64 路由映射为匿名 CSRF 表单用途。
func mfaFormPurposeForRoute(routeName string) string {
	switch routeName {
	case "auth.second_factor", "auth.second_factor.verify",
		"auth.second_factor.resend", "auth.second_factor.cancel":
		return "auth.second_factor"
	case "auth.strong_setup", "auth.strong_setup.passkey_start",
		"auth.strong_setup.passkey_finish", "auth.strong_setup.totp_start",
		"auth.strong_setup.totp_finish":
		return "auth.strong_setup"
	case "auth.recovery_code", "auth.recovery_code.submit":
		return "auth.recovery_code"
	case "auth.recovery_rebind", "auth.recovery_rebind.start",
		"auth.recovery_rebind.complete", "auth.recovery_cancel":
		return "auth.recovery_rebind"
	case "auth.password_forgot", "auth.password_forgot.submit":
		return "auth.password_forgot"
	case "auth.password_reset", "auth.password_reset.submit":
		return "auth.password_reset"
	}
	return ""
}

// textMFA 返回页面摘要中文基线（缺失时回退 i18n 键名，不伪造内容）。
func textMFA(key string) string {
	if message, ok := builtinAuthMessage(key); ok {
		return message
	}
	return text(key)
}

// mfaPageHandlers 实现步骤 64 页面处理器。
type mfaPageHandlers struct {
	pages *pageMFAPages
}

// HandlePage 按路由分派。
func (h *mfaPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend := h.pages.options.Backend
	switch page.RouteName {
	case "auth.second_factor", "auth.second_factor.verify",
		"auth.second_factor.resend", "auth.second_factor.cancel":
		return h.secondFactor(ctx, request, page, backend)
	case "auth.strong_setup", "auth.strong_setup.passkey_start", "auth.strong_setup.passkey_finish",
		"auth.strong_setup.totp_start", "auth.strong_setup.totp_finish":
		return h.strongSetup(ctx, request, page, backend)
	case "auth.recovery_code", "auth.recovery_code.submit":
		return h.recoveryCode(ctx, request, page, backend)
	case "auth.recovery_rebind", "auth.recovery_rebind.start",
		"auth.recovery_rebind.complete", "auth.recovery_cancel":
		return h.recoveryRebind(ctx, request, page, backend)
	case "auth.password_forgot", "auth.password_forgot.submit":
		return h.passwordForgot(ctx, request, page, backend)
	case "auth.password_reset", "auth.password_reset.submit":
		return h.passwordReset(ctx, request, page, backend)
	default:
		return UIPageOutcome{}, nil
	}
}

// mfaErrorOutcome 把适配器公开错误映射为页面状态与稳定文案。用户可纠正错误
// 返回 400 + 已翻译文案；权限/强度/限流等按语义返回 403/409/429/503；只有真正
// 的内部故障返回 500 + 通用兜底文案，不显示未翻译键或内部错误。
func mfaErrorOutcome(err error) UIPageOutcome {
	var publicErr *UIPageAuthError
	if !errors.As(err, &publicErr) || publicErr.Code == "" {
		return UIPageOutcome{StatusCode: http.StatusInternalServerError,
			ErrorCode: "INTERNAL_ERROR", ErrorSummary: textMFA("error.business.INTERNAL_ERROR")}
	}
	status := http.StatusBadRequest
	switch publicErr.Code {
	case "ACCESS_DENIED", "AUTH_FAILED", "MFA_REQUIRED", "MFA_REBIND_REQUIRED",
		"REAUTH_REQUIRED", "USER_DISABLED":
		status = http.StatusForbidden
	case "CONFLICT":
		status = http.StatusConflict
	case "RATE_LIMITED":
		status = http.StatusTooManyRequests
	case "AUTHZ_UNAVAILABLE", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
		status = http.StatusServiceUnavailable
	case "INTERNAL_ERROR":
		status = http.StatusInternalServerError
	}
	return UIPageOutcome{StatusCode: status, ErrorCode: publicErr.Code,
		ErrorSummary: textMFA("error.business." + publicErr.Code)}
}

// pageForm 读取并校验公开页面表单（仅允许白名单字段与当前 CSRF 字段）。
func pageForm(request *http.Request, page UIPageContext, allowed ...string) (url.Values, bool) {
	form, err := readPageForm(request, page.CSRFField, allowed)
	if err != nil {
		return nil, false
	}
	return form, true
}

// secondFactor 渲染/处理第二因素、重发与取消。
func (h *mfaPageHandlers) secondFactor(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	switch page.RouteName {
	case "auth.second_factor.cancel":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		result, err := backend.CancelSecondFactor(ctx, request)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{RedirectPath: h.pages.options.LoginPath}
		outcome.SetCookies = append(outcome.SetCookies, result.StateCookie, result.SessionCookie)
		return outcome, nil
	case "auth.second_factor.resend":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		if _, ok := pageForm(request, page, "challenge_id", "attempt_token"); !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorCode: "CHALLENGE_INVALID", ErrorSummary: textMFA("page.auth.second_factor.expired")}, nil
		}
		view, err := backend.ResendSecondFactor(ctx, request)
		if err != nil {
			outcome := mfaErrorOutcome(err)
			if fallback, loadErr := backend.LoadSecondFactor(ctx, request); loadErr == nil {
				outcome.Data = map[string]any{"SecondFactor": fallback}
			}
			return outcome, nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"SecondFactor": view, "Resent": true}}
		if view.StateCookie != nil {
			outcome.SetCookies = append(outcome.SetCookies, view.StateCookie)
		}
		return outcome, nil
	}
	// GET 渲染，POST 验证。
	if request.Method == http.MethodGet {
		view, err := backend.LoadSecondFactor(ctx, request)
		if err != nil {
			var publicErr *UIPageAuthError
			if errors.As(err, &publicErr) {
				return UIPageOutcome{RedirectPath: h.pages.options.LoginPath}, nil
			}
			return mfaErrorOutcome(err), nil
		}
		if view.SetupRequired {
			return UIPageOutcome{RedirectRoute: "auth.strong_setup"}, nil
		}
		return UIPageOutcome{Data: map[string]any{"SecondFactor": view}}, nil
	}
	form, ok := pageForm(request, page, "challenge_id", "attempt_token", "code",
		"passkey_ceremony_id", "passkey_response")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "CHALLENGE_INVALID",
			ErrorSummary: textMFA("page.auth.second_factor.expired")}, nil
	}
	verify := UIPageSecondFactorVerify{RequestID: page.RequestID}
	verify.ChallengeID, _ = singleValue(form, "challenge_id", 128)
	verify.AttemptToken, _ = singleValue(form, "attempt_token", 128)
	verify.Code, _ = singleValue(form, "code", 64)
	verify.PasskeyCeremonyID, _ = singleValue(form, "passkey_ceremony_id", 128)
	if encoded, okResponse := singleValue(form, "passkey_response", 24*1024); okResponse {
		verify.PasskeyResponse = []byte(encoded)
	}
	if verify.ChallengeID == "" || verify.AttemptToken == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "CHALLENGE_INVALID",
			ErrorSummary: textMFA("page.auth.second_factor.expired")}, nil
	}
	if verify.Code == "" && len(verify.PasskeyResponse) == 0 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	result, err := backend.VerifySecondFactor(ctx, request, verify)
	if err != nil {
		outcome := mfaErrorOutcome(err)
		if view, loadErr := backend.LoadSecondFactor(ctx, request); loadErr == nil {
			outcome.Data = map[string]any{"SecondFactor": view}
		}
		return outcome, nil
	}
	outcome := UIPageOutcome{RedirectPath: h.pages.options.PostLoginPath,
		Data: map[string]any{"Complete": true}}
	if result.SessionCookie != nil {
		outcome.SetCookies = append(outcome.SetCookies, result.SessionCookie)
	}
	outcome.SetCookies = append(outcome.SetCookies, result.StateCookie)
	return outcome, nil
}

// strongSetup 处理强因素初始化页与 Passkey 注册。
func (h *mfaPageHandlers) strongSetup(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	switch page.RouteName {
	case "auth.strong_setup.passkey_start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorCode: "REQ_INVALID", ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		start, err := backend.BeginStrongSetupPasskey(ctx, request, password)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		view, _ := backend.LoadSecondFactor(ctx, request)
		return UIPageOutcome{Data: map[string]any{"StrongSetup": view, "PasskeyStart": start}}, nil
	case "auth.strong_setup.passkey_finish":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "passkey_response", "passkey_ceremony_id", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		encoded, _ := singleValue(form, "passkey_response", 24*1024)
		if encoded == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		result, err := backend.FinishStrongSetupPasskey(ctx, request, []byte(encoded), password)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"StrongSetupDone": result}}
		outcome.SetCookies = append(outcome.SetCookies, result.SessionCookie)
		return outcome, nil
	case "auth.strong_setup.totp_start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorCode: "REQ_INVALID", ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		password, _ := singleValue(form, "current_password", 1024)
		start, err := backend.BeginStrongSetupTOTP(ctx, request, password)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		view, _ := backend.LoadSecondFactor(ctx, request)
		return UIPageOutcome{Data: map[string]any{"StrongSetup": view, "TOTPStart": start}}, nil
	case "auth.strong_setup.totp_finish":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "binding_id", "code", "current_password")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		bindingID, _ := singleValue(form, "binding_id", 128)
		code, _ := singleValue(form, "code", 16)
		password, _ := singleValue(form, "current_password", 1024)
		if bindingID == "" || code == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		result, err := backend.FinishStrongSetupTOTP(ctx, request, bindingID, code, password)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"StrongSetupDone": result}}
		outcome.SetCookies = append(outcome.SetCookies, result.SessionCookie)
		return outcome, nil
	}
	view, err := backend.LoadSecondFactor(ctx, request)
	if err != nil {
		var publicErr *UIPageAuthError
		if errors.As(err, &publicErr) {
			return UIPageOutcome{RedirectPath: h.pages.options.LoginPath}, nil
		}
		return mfaErrorOutcome(err), nil
	}
	if !view.SetupRequired {
		return UIPageOutcome{RedirectPath: "/login/second-factor"}, nil
	}
	return UIPageOutcome{Data: map[string]any{"StrongSetup": view}}, nil
}

// recoveryCode 渲染/提交恢复代码。
func (h *mfaPageHandlers) recoveryCode(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	if request.Method == http.MethodGet {
		return UIPageOutcome{Data: map[string]any{}}, nil
	}
	form, ok := pageForm(request, page, "code", "challenge_id", "attempt_token")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	code, _ := singleValue(form, "code", 256)
	if code == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("page.auth.recovery_code.description")}, nil
	}
	result, err := backend.BeginRecoveryCode(ctx, request, UIPageRecoveryCodeRequest{
		Code: code, RequestID: page.RequestID})
	if err != nil {
		return mfaErrorOutcome(err), nil
	}
	outcome := UIPageOutcome{RedirectRoute: "auth.recovery_rebind",
		Data: map[string]any{"Recovery": result}}
	outcome.SetCookies = append(outcome.SetCookies, result.SessionCookie, result.StateCookie)
	return outcome, nil
}

// recoveryRebind 渲染恢复状态/开始绑定/完成/取消。
func (h *mfaPageHandlers) recoveryRebind(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	switch page.RouteName {
	case "auth.recovery_cancel":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		result, err := backend.CancelRecovery(ctx, request)
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{RedirectPath: h.pages.options.LoginPath,
			Data: map[string]any{"Cancelled": true}}
		outcome.SetCookies = append(outcome.SetCookies, result.SessionCookie, result.StateCookie)
		return outcome, nil
	case "auth.recovery_rebind.start":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "method")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		method, _ := singleValue(form, "method", 32)
		start, err := backend.StartRecoveryRebind(ctx, request,
			UIPageRecoveryRebindRequest{Method: method, RequestID: page.RequestID})
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		snapshot, _ := backend.LoadRecovery(ctx, request)
		return UIPageOutcome{Data: map[string]any{"Recovery": snapshot, "RebindStart": start}}, nil
	case "auth.recovery_rebind.complete":
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		form, ok := pageForm(request, page, "binding_id", "method", "response")
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		bindingID, _ := singleValue(form, "binding_id", 128)
		method, _ := singleValue(form, "method", 32)
		response, _ := singleValue(form, "response", 24*1024)
		if bindingID == "" || response == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
		}
		completion, err := backend.CompleteRecoveryRebind(ctx, request,
			UIPageRecoveryRebindComplete{BindingID: bindingID, Method: method,
				Response: []byte(response), RequestID: page.RequestID})
		if err != nil {
			return mfaErrorOutcome(err), nil
		}
		outcome := UIPageOutcome{Data: map[string]any{"RecoveryDone": completion}}
		outcome.SetCookies = append(outcome.SetCookies, completion.SessionCookie)
		return outcome, nil
	}
	snapshot, err := backend.LoadRecovery(ctx, request)
	if err != nil {
		var publicErr *UIPageAuthError
		if errors.As(err, &publicErr) {
			return UIPageOutcome{RedirectPath: h.pages.options.LoginPath}, nil
		}
		return mfaErrorOutcome(err), nil
	}
	return UIPageOutcome{Data: map[string]any{"Recovery": snapshot}}, nil
}

// passwordForgot 渲染/受理找回请求（统一提示）。
func (h *mfaPageHandlers) passwordForgot(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	if request.Method == http.MethodGet {
		return UIPageOutcome{Data: map[string]any{}}, nil
	}
	form, ok := pageForm(request, page, "identifier")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	identifier, _ := singleValue(form, "identifier", 254)
	if identifier == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	if _, err := backend.BeginPasswordReset(ctx, request, UIPagePasswordForgotRequest{
		Identifier: identifier, RequestID: page.RequestID}); err != nil {
		return mfaErrorOutcome(err), nil
	}
	return UIPageOutcome{Data: map[string]any{"Submitted": true}}, nil
}

// passwordReset 渲染/完成重置密码。
func (h *mfaPageHandlers) passwordReset(ctx context.Context, request *http.Request,
	page UIPageContext, backend UIPageMFABackend) (UIPageOutcome, error) {
	if request.Method == http.MethodGet {
		token := request.URL.Query().Get("token")
		if token == "" || len(token) > 512 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "CHALLENGE_INVALID",
				ErrorSummary: textMFA("page.auth.password_reset.invalid")}, nil
		}
		if err := backend.ValidatePasswordReset(ctx, request, token); err != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "CHALLENGE_INVALID",
				ErrorSummary: textMFA("page.auth.password_reset.invalid")}, nil
		}
		return UIPageOutcome{Data: map[string]any{"Token": token}}, nil
	}
	form, ok := pageForm(request, page, "token", "new_password", "confirm_password")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	token, _ := singleValue(form, "token", 512)
	newPassword, _ := singleValue(form, "new_password", 1024)
	confirm, _ := singleValue(form, "confirm_password", 1024)
	if token == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "CHALLENGE_INVALID",
			ErrorSummary: textMFA("page.auth.password_reset.invalid")}, nil
	}
	if newPassword == "" || newPassword != confirm {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			Data: map[string]any{"Token": token},
			FieldErrors: map[string]string{"confirm_password": textMFA(
				"page.auth.password_reset.mismatch")},
			ErrorSummary: textMFA("error.business.REQ_INVALID")}, nil
	}
	result, err := backend.CompletePasswordReset(ctx, request, UIPagePasswordResetRequest{
		Token: token, NewPassword: newPassword, Confirm: confirm, RequestID: page.RequestID})
	if err != nil {
		return mfaErrorOutcome(err), nil
	}
	return UIPageOutcome{Data: map[string]any{"ResetDone": result}}, nil
}

// init 补充步骤 64 页面摘要使用的中文基线文案（模板静态文案仍走 i18n 目录）。
func init() {
	for key, value := range map[string]string{
		"error.business.CHALLENGE_INVALID":          "验证请求无效或已失效，请重新发起",
		"error.business.INTERNAL_ERROR":             "服务暂时无法完成请求，请稍后重试",
		"error.business.REQ_INVALID":                "请求参数未被接受",
		"error.business.RATE_LIMITED":               "请求过于频繁，请稍后重试",
		"error.business.MFA_REQUIRED":               "需要完成两步验证",
		"error.business.MFA_REBIND_REQUIRED":        "需要重新绑定安全方式",
		"error.business.ACCESS_DENIED":              "请求未获准",
		"error.business.CHALLENGE_INVALID_RECOVERY": "恢复代码无效或已失效",
		"error.business.MAIL_DELIVERY_FAILED":       "验证邮件未能发送，请稍后重试",
		"error.business.AUTH_FAILED":                "无法完成验证，请检查输入后重试",
		"error.business.REAUTH_REQUIRED":            "需要再次验证身份",
		"error.business.USER_DISABLED":              "账户当前不可用",
		"error.business.CONFLICT":                   "数据已被其他操作修改，请重新读取后再试",
		"error.business.AUTHZ_UNAVAILABLE":          "暂时无法判定访问权限，请稍后重试",
		"error.business.DB_UNAVAILABLE":             "服务暂时不可用，请稍后重试",
		"error.business.AUDIT_WRITE_FAILED":         "服务暂时无法可靠记录操作，请稍后重试",
		"page.auth.second_factor.expired":           "验证请求已失效，请重新登录后发起",
		"page.auth.recovery_code.description":       "恢复代码只替代第二步，不替代密码",
		"page.auth.password_reset.invalid":          "重置入口无效或已失效，请重新发起找回",
		"page.auth.password_reset.mismatch":         "两次输入的新密码不一致",
	} {
		builtinAuthMessages[key] = value
	}
}
