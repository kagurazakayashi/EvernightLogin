package login

// 本文件实现步骤 63 账户入口页面：登录（密码/Passkey 入口）、注册、注册审核状态、
// 邀请接受、邮箱验证/重发、退出与登录落地页。
//
// 安全不变量：
//   - 页面不解析 Cookie 身份、不缓存权限；只消费 UISessionService 的公开摘要并调用
//     宿主注入的 UIPageAuthBackend（生产适配器内部再调用真实 authn/session/
//     registration/onboarding 服务）。
//   - 登录必须按后端真实 Outcome/Restricted/RequiredSteps 分支：MFA_REQUIRED 等不完整
//     结果绝不当作登录成功、不跳转业务页；只有完整非受限结果才签发正常会话 Cookie。
//   - 公开错误不枚举账户：用户名/邮箱/密码错误统一文案；邀请/邮箱验证无效不区分
//     “不存在/已用/不属于你”。
//   - 一次性秘密只在邮件链接 query 与 POST 隐藏字段出现，不进入正文/日志/URL 回显；
//     页面响应由框架统一 no-store，transport 已设置 no-referrer 且访问日志只记路径。
//   - 重定向只允许站内相对路径或命名路由白名单，非法 return 回默认落地页。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// UIPageAuthOptions 是步骤 63 账户入口页配置。Backend 缺失时 NewWebUI 拒绝构造。
type UIPageAuthOptions struct {
	Backend UIPageAuthBackend
	// PostLoginPath 是登录成功默认落地站内相对路径；空使用 "/"。必须是站内相对路径。
	PostLoginPath string
	// PasskeyLoginPath 非空时登录页显示 Passkey 入口并跳转到该站内相对路径
	// （实际 WebAuthn 流程属步骤 64；未配置时入口显示“尚未启用”）。
	PasskeyLoginPath string
}

// UIPageAuthBackend 是页面调用真实账户入口服务的最小契约；生产适配器在内部构造
// 可信 Caller 并复用既有服务，页面无法自报身份或权限。
type UIPageAuthBackend interface {
	PasswordLogin(ctx context.Context, request *http.Request,
		login UIPasswordLoginRequest) (UIPageLoginResult, error)
	RegistrationAvailability(ctx context.Context) (UIPageRegistrationAvailability, error)
	Register(ctx context.Context, request UIRegisterRequest) (UIPageRegisterResult, error)
	VerifyEmail(ctx context.Context, request UIVerifyEmailRequest) (UIPageVerifyResult, error)
	ResendVerification(ctx context.Context, request *http.Request) (UIPageResendResult, error)
	AcceptInvitation(ctx context.Context, request *http.Request,
		accept UIPageInvitationAcceptRequest) (UIPageInvitationAcceptResult, error)
	Logout(ctx context.Context, request *http.Request) (*http.Cookie, error)
}

// UIPageAuthError 是后端页面适配层可返回的稳定公开错误（不含内部细节）。
type UIPageAuthError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIPageAuthError) Error() string { return "页面账户操作失败: " + e.Code }

// UIPasswordLoginRequest 是密码登录页面请求（不含会话秘密）。
type UIPasswordLoginRequest struct {
	Identifier string
	Password   string
	RememberMe bool
	RequestID  string
}

// UIPageLoginResult 是登录结果（Cookie 由适配器用真实会话服务生成）。
type UIPageLoginResult struct {
	UserID        string
	Username      string
	Complete      bool
	Restricted    bool
	RequiredSteps []string
	Cookie        *http.Cookie
}

// UIPageRegistrationAvailability 是注册开关与邮箱策略快照。
type UIPageRegistrationAvailability struct {
	Enabled                  bool
	EmailCapability          bool
	RequireEmailVerification bool
	RequireReview            bool
}

// UIRegisterRequest 是注册表单白名单字段。
type UIRegisterRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// UIPageRegisterResult 是注册结果（不含会话/验证链接）。
type UIPageRegisterResult struct {
	UserID                string
	Username              string
	Status                string
	VerificationSent      bool
	VerificationExpiresAt time.Time
	ResendAllowedAt       time.Time
	SendErrorCode         string
}

// UIVerifyEmailRequest 是邮箱验证消费请求。
type UIVerifyEmailRequest struct {
	UserID       string
	CredentialID string
	Token        string
	RequestID    string
}

// UIPageVerifyResult 是邮箱验证结果。
type UIPageVerifyResult struct {
	Verified bool
}

// UIPageResendResult 是重发验证邮件的对外统一结果：成功、冷却、票据/用户不存在
// 一律返回同一“已受理”语义，差异只写入受限运行日志，页面不得据此推断状态。
type UIPageResendResult struct {
	// Accepted 恒为 true（对外统一受理语义）。
	Accepted bool
}

// UIPageNewUser 是邀请接受时创建新账户的资料白名单。
type UIPageNewUser struct {
	Username string
	Password string
	Nickname string
	Language string
	Timezone string
}

// UIPageInvitationAcceptRequest 是邀请接受请求。
type UIPageInvitationAcceptRequest struct {
	InvitationID string
	CredentialID string
	Token        string
	NewUser      *UIPageNewUser
}

// UIPageInvitationAcceptResult 是真实接受结果（应用/角色来自服务端）。
type UIPageInvitationAcceptResult struct {
	InvitationID string
	UserID       string
	AppID        string
	Roles        []string
	NewUser      bool
}

// pageAuthPages 是内置账户入口页的路由与处理器。
type pageAuthPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAuthOptions
}

// newPageAuthPages 校验账户入口页配置并构造路由/处理器。
func newPageAuthPages(options UIPageAuthOptions) (*pageAuthPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("账户入口页面缺少后端适配器")
	}
	postLoginPath := options.PostLoginPath
	if postLoginPath == "" {
		postLoginPath = "/home"
	}
	if !safeRelativePath(postLoginPath) {
		return nil, fmt.Errorf("登录后落地路径必须是站内相对路径")
	}
	if options.PasskeyLoginPath != "" && !safeRelativePath(options.PasskeyLoginPath) {
		return nil, fmt.Errorf("Passkey 登录路径必须是站内相对路径")
	}
	options.PostLoginPath = postLoginPath
	pages := &pageAuthPages{handlers: map[string]UIPageHandler{}, options: options}
	page := &authPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "auth.login", Method: http.MethodGet, Path: "/login", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/auth/login"},
		{Name: "auth.login.submit", Method: http.MethodPost, Path: "/login",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/login"},
		{Name: "auth.register", Method: http.MethodGet, Path: "/register",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/register"},
		{Name: "auth.register.submit", Method: http.MethodPost, Path: "/register",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/register"},
		{Name: "auth.registration_status", Method: http.MethodGet, Path: "/register/status",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/registration_status"},
		{Name: "auth.invitation_accept", Method: http.MethodGet, Path: "/invitation/accept",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/invitation_accept"},
		{Name: "auth.invitation_accept.submit", Method: http.MethodPost,
			Path: "/invitation/accept", Access: UIAccessPublic, Layout: "layout/auth",
			Template: "page/auth/invitation_accept"},
		{Name: "auth.email_verify", Method: http.MethodGet, Path: "/email/verify",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/email_verify"},
		{Name: "auth.email_verify.submit", Method: http.MethodPost, Path: "/email/verify",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/email_verify"},
		{Name: "auth.email_verify_resend", Method: http.MethodPost,
			Path: "/email/verify/resend", Access: UIAccessPublic, Layout: "layout/auth",
			Template: "page/auth/email_verify"},
		{Name: "auth.logout", Method: http.MethodPost, Path: "/logout",
			Access: UIAccessUser, Layout: "layout/auth", Template: "page/auth/logout"},
		{Name: "auth.landing", Method: http.MethodGet, Path: "/home",
			Access: UIAccessUser, Layout: "layout/auth", Template: "page/auth/landing"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = page
	}
	return pages, nil
}

// UIPageAuthPublicFormPaths 返回公开表单路径与用途的对应关系（已含部署前缀），
// 供宿主配置 transport CSRF 公开表单白名单/匿名令牌校验器。
func UIPageAuthPublicFormPaths(prefix string) map[string]string {
	return map[string]string{
		prefix + "/login":             "auth.login",
		prefix + "/register":          "auth.register",
		prefix + "/invitation/accept": "auth.invitation",
		prefix + "/email/verify":      "auth.email_verify",
		// 邮箱验证页的验证与重发两表单共用同一页面用途令牌（同一信任边界），
		// 避免 GET 只签发单一令牌导致重发表单恒 403。
		prefix + "/email/verify/resend": "auth.email_verify",
	}
}

// formPurposeForRoute 把公开页面路由映射为匿名 CSRF 表单用途（与 POST 路径一致）。
func formPurposeForRoute(routeName string) string {
	switch routeName {
	case "auth.login", "auth.login.submit":
		return "auth.login"
	case "auth.register", "auth.register.submit":
		return "auth.register"
	case "auth.invitation_accept", "auth.invitation_accept.submit":
		return "auth.invitation"
	case "auth.email_verify", "auth.email_verify.submit", "auth.email_verify_resend":
		return "auth.email_verify"
	}
	return ""
}

// isNilUIValue 检测 nil 接口（含 typed nil）。
func isNilUIValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflectValue(value)
	switch reflected.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return reflected.IsNil()
	default:
		return false
	}
}

// authPageHandlers 实现全部账户入口页处理器。
type authPageHandlers struct {
	pages *pageAuthPages
}

// HandlePage 按路由名分派处理器。
func (h *authPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "auth.login", "auth.login.submit":
		return h.login(ctx, request, page)
	case "auth.register", "auth.register.submit":
		return h.register(ctx, request, page)
	case "auth.registration_status":
		return UIPageOutcome{Data: map[string]any{}}, nil
	case "auth.invitation_accept", "auth.invitation_accept.submit":
		return h.invitation(ctx, request, page)
	case "auth.email_verify", "auth.email_verify.submit", "auth.email_verify_resend":
		return h.emailVerify(ctx, request, page)
	case "auth.logout":
		return h.logout(ctx, request, page)
	case "auth.landing":
		return h.landing(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// login 渲染登录表单或处理密码登录。
func (h *authPageHandlers) login(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.Session.Authenticated && page.Session.Kind == "normal" {
		return UIPageOutcome{RedirectPath: h.pages.options.PostLoginPath}, nil
	}
	availability, err := h.pages.options.Backend.RegistrationAvailability(ctx)
	if err != nil {
		return UIPageOutcome{}, err
	}
	data := map[string]any{
		"registrationEnabled": availability.Enabled,
		"passkeyPath":         h.pages.options.PasskeyLoginPath,
		"returnPath":          safeRelativePath(request.URL.Query().Get("return")),
	}
	if request.Method != http.MethodPost {
		if requested := request.URL.Query().Get("return"); requested != "" {
			if safeRelativePath(requested) {
				data["returnValue"] = requested
			}
		}
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"identifier", "password",
		"remember_me", "return"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.login.error_generic")}, nil
	}
	identifier, okIdentifier := singleValue(form, "identifier", 256)
	password, okPassword := singleValue(form, "password", 4096)
	if !okIdentifier || !okPassword || identifier == "" || password == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.login.error_generic"),
			FieldErrors:  map[string]string{"identifier": text("page.auth.login.error_generic")}}, nil
	}
	result, loginErr := h.pages.options.Backend.PasswordLogin(ctx, request,
		UIPasswordLoginRequest{Identifier: identifier, Password: password,
			RememberMe: form.Get("remember_me") != "",
			RequestID:  page.RequestID})
	if loginErr != nil {
		var publicErr *UIPageAuthError
		if errors.As(loginErr, &publicErr) && publicErr.Code == "RATE_LIMITED" {
			return UIPageOutcome{StatusCode: http.StatusTooManyRequests, Data: data,
				ErrorCode:    "RATE_LIMITED",
				ErrorSummary: text("common.state.rate_limited")}, nil
		}
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "AUTH_FAILED",
			ErrorSummary: text("page.auth.login.error_generic")}, nil
	}
	if result.Complete && !result.Restricted {
		outcome := UIPageOutcome{Data: data}
		if result.Cookie != nil {
			outcome.SetCookies = append(outcome.SetCookies, result.Cookie)
		}
		if returnPath := form.Get("return"); safeRelativePath(returnPath) {
			outcome.RedirectPath = returnPath
		} else {
			outcome.RedirectPath = h.pages.options.PostLoginPath
		}
		return outcome, nil
	}
	// 需要补充验证/受限结果：绝不是登录成功。允许适配器下发受限会话 Cookie 供
	// 后续步骤继续，但页面只显示真实受限状态，不跳转业务页。
	outcome := UIPageOutcome{Data: data, ErrorCode: "MFA_REQUIRED",
		ErrorSummary: text("page.auth.login.restricted"), FieldErrors: map[string]string{}}
	if result.Cookie != nil {
		outcome.SetCookies = append(outcome.SetCookies, result.Cookie)
	}
	return outcome, nil
}

// register 渲染注册表单或处理注册。
func (h *authPageHandlers) register(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	availability, err := h.pages.options.Backend.RegistrationAvailability(ctx)
	if err != nil {
		return UIPageOutcome{}, err
	}
	data := map[string]any{
		"registrationEnabled": availability.Enabled,
		"emailCapability":     availability.EmailCapability,
		"emailRequired":       availability.RequireEmailVerification,
		"requireReview":       availability.RequireReview,
	}
	if !availability.Enabled {
		return UIPageOutcome{Data: data, StatusCode: http.StatusForbidden,
			ErrorCode: "REQ_INVALID"}, nil
	}
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"username", "password",
		"password_confirm", "email", "nickname", "language", "timezone"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.register.error_generic")}, nil
	}
	password, okPassword := singleValue(form, "password", 4096)
	confirm, okConfirm := singleValue(form, "password_confirm", 4096)
	if okPassword && okConfirm && password != confirm {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.register.password_mismatch"),
			FieldErrors:  map[string]string{"password_confirm": text("page.auth.register.password_mismatch")}}, nil
	}
	username, okUsername := singleValue(form, "username", 256)
	email, _ := singleValue(form, "email", 320)
	if !okUsername || !okPassword || username == "" || password == "" ||
		(availability.RequireEmailVerification && email == "") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.register.error_generic")}, nil
	}
	nickname, _ := singleValue(form, "nickname", 256)
	language, _ := singleValue(form, "language", 64)
	timezone, _ := singleValue(form, "timezone", 64)
	result, registerErr := h.pages.options.Backend.Register(ctx, UIRegisterRequest{
		Username: username, Password: password, Email: email, Nickname: nickname,
		Language: language, Timezone: timezone, RequestID: page.RequestID})
	if registerErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.auth.register.error_generic")}, nil
	}
	data["result"] = map[string]any{
		"username":              result.Username,
		"status":                result.Status,
		"verificationSent":      result.VerificationSent,
		"verificationExpiresAt": result.VerificationExpiresAt,
		"resendAllowedAt":       result.ResendAllowedAt,
		"sendErrorCode":         result.SendErrorCode,
	}
	return UIPageOutcome{Data: data, StatusCode: http.StatusOK}, nil
}

// invitation 渲染邀请接受表单或处理接受。
func (h *authPageHandlers) invitation(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	values := request.URL.Query()
	if request.Method == http.MethodPost {
		form, formErr := readPageForm(request, page.CSRFField, []string{"iid", "cid", "token",
			"username", "password", "password_confirm", "nickname", "language", "timezone"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.auth.invitation.invalid")}, nil
		}
		values = form
	}
	invitationID, okInvitation := singleValue(values, "iid", 128)
	credentialID, okCredential := singleValue(values, "cid", 128)
	tokenValue, okToken := singleValue(values, "token", 512)
	data := map[string]any{
		"authenticated": page.Session.Authenticated && page.Session.Kind == "normal",
	}
	if !okInvitation || !okCredential || !okToken || invitationID == "" ||
		credentialID == "" || tokenValue == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "CHALLENGE_INVALID",
			ErrorSummary: text("page.auth.invitation.invalid")}, nil
	}
	data["invitationID"] = invitationID
	data["credentialID"] = credentialID
	data["token"] = tokenValue
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	accept := UIPageInvitationAcceptRequest{InvitationID: invitationID,
		CredentialID: credentialID, Token: tokenValue}
	authenticated := data["authenticated"].(bool)
	if !authenticated {
		username, okUsername := singleValue(formValue(request), "username", 256)
		password, okPassword := singleValue(formValue(request), "password", 4096)
		confirm, _ := singleValue(formValue(request), "password_confirm", 4096)
		if !okUsername || !okPassword || username == "" || password == "" ||
			password != confirm {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: text("page.auth.invitation.invalid")}, nil
		}
		nickname, _ := singleValue(formValue(request), "nickname", 256)
		language, _ := singleValue(formValue(request), "language", 64)
		timezone, _ := singleValue(formValue(request), "timezone", 64)
		accept.NewUser = &UIPageNewUser{Username: username, Password: password,
			Nickname: nickname, Language: language, Timezone: timezone}
	}
	result, acceptErr := h.pages.options.Backend.AcceptInvitation(ctx, request, accept)
	if acceptErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "CHALLENGE_INVALID",
			ErrorSummary: text("page.auth.invitation.invalid")}, nil
	}
	return UIPageOutcome{Data: map[string]any{
		"accepted":     true,
		"appID":        result.AppID,
		"roles":        result.Roles,
		"newUser":      result.NewUser,
		"invitationID": result.InvitationID,
	}}, nil
}

// emailVerify 渲染邮箱验证表单/结果，或处理验证/重发。
func (h *authPageHandlers) emailVerify(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.RouteName == "auth.email_verify_resend" {
		// 对外统一“已受理”：不区分成功/冷却/绑定失败/用户不存在，避免账户与票据
		// 状态探测；真实发送结果只写受限运行日志。
		_, _ = h.pages.options.Backend.ResendVerification(ctx, request)
		return UIPageOutcome{Data: map[string]any{"resendAccepted": true}}, nil
	}
	values := request.URL.Query()
	if request.Method == http.MethodPost {
		form, formErr := readPageForm(request, page.CSRFField, []string{"uid", "cid", "token"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.auth.email_verify.invalid")}, nil
		}
		values = form
	}
	userID, okUser := singleValue(values, "uid", 64)
	credentialID, okCredential := singleValue(values, "cid", 128)
	tokenValue, okToken := singleValue(values, "token", 512)
	data := map[string]any{}
	if !okUser || !okCredential || !okToken || userID == "" || credentialID == "" ||
		tokenValue == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "CHALLENGE_INVALID",
			ErrorSummary: text("page.auth.email_verify.invalid")}, nil
	}
	data["userID"] = userID
	data["credentialID"] = credentialID
	data["token"] = tokenValue
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: data}, nil
	}
	result, verifyErr := h.pages.options.Backend.VerifyEmail(ctx, UIVerifyEmailRequest{
		UserID: userID, CredentialID: credentialID, Token: tokenValue,
		RequestID: page.RequestID})
	if verifyErr != nil || !result.Verified {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorCode:    "CHALLENGE_INVALID",
			ErrorSummary: text("page.auth.email_verify.invalid")}, nil
	}
	return UIPageOutcome{Data: map[string]any{"verified": true}}, nil
}

// logout 处理仅 POST 退出。
func (h *authPageHandlers) logout(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if request.Method != http.MethodPost {
		return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed,
			ErrorSummary: text("common.state.forbidden")}, nil
	}
	clearCookie, err := h.pages.options.Backend.Logout(ctx, request)
	if err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.auth.logout.failed")}, nil
	}
	outcome := UIPageOutcome{RedirectRoute: "auth.login"}
	if clearCookie != nil {
		outcome.SetCookies = append(outcome.SetCookies, clearCookie)
	}
	return outcome, nil
}

// landing 是登录后的临时落地页。
func (h *authPageHandlers) landing(_ context.Context, _ *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return UIPageOutcome{Data: map[string]any{
		"userID": page.Session.UserID, "appID": page.Session.AppID,
	}}, nil
}

// ===== 表单辅助 =====

// readPageForm 解析 form-urlencoded 表单并执行字段白名单：未知字段、重复敏感字段、
// 非表单类型一律拒绝（返回 error）。
func readPageForm(request *http.Request, csrfField string, allowed []string) (url.Values, error) {
	if request == nil {
		return nil, errors.New("请求为空")
	}
	contentType := request.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		return nil, errors.New("只接受表单提交")
	}
	if err := request.ParseForm(); err != nil {
		return nil, err
	}
	if len(request.PostForm) == 0 {
		return nil, errors.New("表单为空")
	}
	allowSet := make(map[string]struct{}, len(allowed)+1)
	for _, key := range allowed {
		allowSet[key] = struct{}{}
	}
	if csrfField != "" {
		allowSet[csrfField] = struct{}{}
	}
	for key, values := range request.PostForm {
		if _, ok := allowSet[key]; !ok {
			return nil, fmt.Errorf("未知表单字段")
		}
		if len(values) > 1 {
			return nil, fmt.Errorf("重复表单字段")
		}
	}
	return request.PostForm, nil
}

// singleValue 读取唯一字段值并检查长度上限。
func singleValue(values url.Values, key string, maxBytes int) (string, bool) {
	list, ok := values[key]
	if !ok || len(list) != 1 {
		return "", false
	}
	value := list[0]
	if len(value) > maxBytes {
		return "", false
	}
	return value, true
}

// formValue 返回已解析表单（不存在时返回空集合）。
func formValue(request *http.Request) url.Values {
	if request == nil || request.PostForm == nil {
		return url.Values{}
	}
	return request.PostForm
}

// text 返回页面静态文案键对应的内置 zh-CN 文本（模板仍使用 i18n 键显示）。
func text(key string) string {
	if message, ok := builtinAuthMessage(key); ok {
		return message
	}
	return key
}

// reflectValue 返回反射值（辅助 typed nil 检测）。
func reflectValue(value any) reflect.Value { return reflect.ValueOf(value) }

// builtinAuthMessages 是页面摘要使用的中文基线文案（zh-CN 内置目录；模板静态文案
// 仍走 i18n 键，后续语言目录可覆盖摘要文本）。
var builtinAuthMessages = map[string]string{
	"page.auth.login.error_generic":        "无法完成登录，请检查输入后重试",
	"page.auth.login.restricted":           "需要补充验证后才能继续登录，当前不是登录成功状态",
	"common.state.rate_limited":            "请求过于频繁，请稍后重试",
	"page.auth.register.error_generic":     "无法完成注册，请检查输入后重试",
	"page.auth.register.password_mismatch": "两次输入的密码不一致",
	"page.auth.invitation.invalid":         "该邀请无法使用或已失效",
	"page.auth.email_verify.invalid":       "该验证入口无法使用或已失效",
	"page.auth.email_verify.resend_failed": "暂时无法重发验证邮件，请稍后重试",
	"page.auth.logout.failed":              "退出请求未能完成，请稍后重试",
	"common.state.forbidden":               "当前操作不被允许",
}

// builtinAuthMessage 查询内置中文摘要文案。
func builtinAuthMessage(key string) (string, bool) {
	message, ok := builtinAuthMessages[key]
	return message, ok
}
