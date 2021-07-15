// 本文件实现步骤 65 的 OAuth 授权确认、设备码与扫码登录页面契约与处理器。
//
// 安全边界：
//   - 授权页只显示后端校验后的应用/scope/audience；批准与拒绝都调用真实 oauthflow
//     决定接口，批准再次认证由后端完成；授权码只出现在后端生成的重定向 Location，
//     不进入页面 DOM/日志。
//   - 设备页 GET 不消费；POST 先按短码读取描述，再以同一短码提交决定；页面不接触
//     device_code/Token。
//   - 扫码页只显示 request_id/短时请求，ClaimSecret 只放签名 HttpOnly 状态 Cookie；
//     APP 确认页使用真实完整会话 + 版本号；批准/拒绝/领取都调用真实服务。
//   - 所有公开表单使用步骤 63 匿名 CSRF + Origin/Referer；已登录 APP 确认使用会话 CSRF。
package login

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// UIPageOAuthOptions 是步骤 65 页面配置。
type UIPageOAuthOptions struct {
	Backend UIPageOAuthBackend
	// LoginPath/PostLoginPath 是流程失效登录路径与领取成功落地路径。
	LoginPath     string
	PostLoginPath string
}

// UIPageOAuthBackend 是页面调用真实 oauthflow/qrlogin 服务的最小契约。
type UIPageOAuthBackend interface {
	// BeginConsent 从授权请求参数创建真实确认请求（客户端/回调/PKCE/scope 全部在后端校验）。
	BeginConsent(ctx context.Context, request *http.Request, params url.Values) (UIPageConsentPrompt, error)
	// DecideConsent 调用真实决定接口；批准返回后端生成的重定向 URL（含一次性 code）。
	DecideConsent(ctx context.Context, request *http.Request,
		decision UIPageConsentDecision) (UIPageConsentResult, error)
	// DeviceDescribe 只读按短码读取设备授权请求；不消费。
	DeviceDescribe(ctx context.Context, request *http.Request, userCode string) (UIPageDevicePrompt, error)
	// DeviceDecide 按短码提交真实批准/拒绝。
	DeviceDecide(ctx context.Context, request *http.Request,
		decision UIPageDeviceDecision) (UIPageDeviceResult, error)
	// BeginQR 创建匿名扫码登录请求；ClaimSecret 只由适配器写入签名状态 Cookie。
	BeginQR(ctx context.Context, request *http.Request) (UIPageQRBegin, error)
	// QueryQR 按签名状态查询原发起端状态（不签发凭证）。
	QueryQR(ctx context.Context, request *http.Request) (UIPageQRStatus, error)
	// ClaimQR 由原发起端领取并签发目标应用会话 Cookie。
	ClaimQR(ctx context.Context, request *http.Request) (UIPageQRClaim, error)
	RegenerateQR(ctx context.Context, request *http.Request) (UIPageQRBegin, error)
	CancelQR(ctx context.Context, request *http.Request) (UIPageQRStatus, error)
	// DescribeQR 供 APP 确认端用真实完整会话读取请求。
	DescribeQR(ctx context.Context, request *http.Request, requestID string) (UIPageQRPrompt, error)
	// DecideQR 供 APP 确认端按当前版本批准/拒绝。
	DecideQR(ctx context.Context, request *http.Request,
		decision UIPageQRDecision) (UIPageQRPrompt, error)
}

// UIPageConsentPrompt 是授权确认页可展示数据（应用展示名/中文 scope 说明由后端受控补充）。
type UIPageConsentPrompt struct {
	RequestID       string
	ApplicationName string
	ClientID        string
	ClientType      string
	Scopes          []UIPageScopeInfo
	Audiences       []UIPageAudienceInfo
	RedirectURI     string
	ExpiresAt       time.Time
	UserDisplayName string
	UserID          string
}

// UIPageScopeInfo 是单个 scope 的中文说明与稳定值。
type UIPageScopeInfo struct {
	Value       string
	Description string
	Limits      string
}

// UIPageAudienceInfo 是目标资源的中文说明与稳定值。
type UIPageAudienceInfo struct {
	Value       string
	Description string
}

// UIPageConsentDecision 是授权决定表单。
type UIPageConsentDecision struct {
	RequestID string
	Approve   bool
}

// UIPageConsentResult 是授权决定结果；RedirectURL 只来自后端。
type UIPageConsentResult struct {
	Approved    bool
	RedirectURL string
}

// UIPageDevicePrompt 是设备码确认数据（不含 device_code/Token）。
type UIPageDevicePrompt struct {
	RequestID       string
	ApplicationName string
	ClientID        string
	ClientType      string
	Scopes          []UIPageScopeInfo
	Audiences       []UIPageAudienceInfo
	ExpiresAt       time.Time
	UserCode        string
}

// UIPageDeviceDecision 是设备码决定表单。
type UIPageDeviceDecision struct {
	UserCode string
	Approve  bool
}

// UIPageDeviceResult 是设备码决定结果。
type UIPageDeviceResult struct {
	ApplicationName string
	Approved        bool
	RequestID       string
}

// UIPageQRBegin 是匿名扫码发起结果（ClaimSecret 不在此结构出现，由适配器写 Cookie）。
type UIPageQRBegin struct {
	RequestID           string
	QRPayload           string
	ExpiresAt           time.Time
	Version             int64
	PollIntervalSeconds int
	StateCookie         *http.Cookie
}

// UIPageQRStatus 是发起端状态。
type UIPageQRStatus struct {
	Status              string
	ExpiresAt           time.Time
	Version             int64
	RetryAfterSeconds   int
	QRPayload           string
	PollIntervalSeconds int
	StateCookie         *http.Cookie
}

// UIPageQRClaim 是领取结果（会话 Cookie 由适配器生成）。
type UIPageQRClaim struct {
	SessionCookie *http.Cookie
	StateCookie   *http.Cookie
	UserID        string
}

// UIPageQRPrompt 是 APP 确认端展示数据。
type UIPageQRPrompt struct {
	RequestID       string
	ApplicationName string
	ClientID        string
	ClientType      string
	Scopes          []UIPageScopeInfo
	RequesterHint   string
	Status          string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	Version         int64
	Warning         string
}

// UIPageQRDecision 是 APP 决定表单。
type UIPageQRDecision struct {
	RequestID       string
	ExpectedVersion int64
	Approve         bool
}

// PageOAuthRouteNames 返回步骤 65 命名路由。
func PageOAuthRouteNames() []string {
	return []string{
		"oauth.consent", "oauth.consent.decide", "oauth.device_verify",
		"oauth.device_verify.describe", "oauth.device_confirm", "oauth.device_confirm.decide",
		"auth.qr_login", "auth.qr_login.poll", "auth.qr_login.claim",
		"auth.qr_login.regenerate", "auth.qr_login.cancel",
		"app.scan_confirm", "app.scan_confirm.decide",
	}
}

// UIPageOAuthPublicFormPaths 返回匿名公开表单路径与用途（含前缀）。
func UIPageOAuthPublicFormPaths(prefix string) map[string]string {
	return map[string]string{
		prefix + "/oauth/authorize":      "oauth.consent",
		prefix + "/oauth/device":         "oauth.device",
		prefix + "/oauth/device/confirm": "oauth.device",
		prefix + "/login/qr":             "auth.qr_login",
		prefix + "/login/qr/poll":        "auth.qr_login",
		prefix + "/login/qr/claim":       "auth.qr_login",
		prefix + "/login/qr/regenerate":  "auth.qr_login",
		prefix + "/login/qr/cancel":      "auth.qr_login",
		prefix + "/app/scan":             "app.scan_confirm",
	}
}

// oauthFormPurposeForRoute 映射步骤 65 路由到匿名 CSRF 用途。
func oauthFormPurposeForRoute(routeName string) string {
	switch routeName {
	case "oauth.consent", "oauth.consent.decide":
		return "oauth.consent"
	case "oauth.device_verify", "oauth.device_verify.describe",
		"oauth.device_confirm", "oauth.device_confirm.decide":
		return "oauth.device"
	case "auth.qr_login", "auth.qr_login.poll", "auth.qr_login.claim",
		"auth.qr_login.regenerate", "auth.qr_login.cancel":
		return "auth.qr_login"
	case "app.scan_confirm", "app.scan_confirm.decide":
		return "app.scan_confirm"
	}
	return ""
}

// pageOAuthPages 是步骤 65 路由与处理器。
type pageOAuthPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageOAuthOptions
}

// newPageOAuthPages 校验配置并构造页面。
func newPageOAuthPages(options UIPageOAuthOptions) (*pageOAuthPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("OAuth/扫码页面后端适配器不能为空")
	}
	if options.LoginPath == "" {
		options.LoginPath = "/login"
	}
	if options.PostLoginPath == "" {
		options.PostLoginPath = "/home"
	}
	if !safeRelativePath(options.LoginPath) || !safeRelativePath(options.PostLoginPath) {
		return nil, fmt.Errorf("OAuth 页面登录/落地路径必须是站内相对路径")
	}
	pages := &pageOAuthPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &oauthPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "oauth.consent", Method: http.MethodGet, Path: "/oauth/authorize",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/oauth/consent"},
		{Name: "oauth.consent.decide", Method: http.MethodPost, Path: "/oauth/authorize",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/oauth/consent"},
		{Name: "oauth.device_verify", Method: http.MethodGet, Path: "/oauth/device",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/oauth/device_verify"},
		{Name: "oauth.device_verify.describe", Method: http.MethodPost, Path: "/oauth/device",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/oauth/device_confirm"},
		{Name: "oauth.device_confirm", Method: http.MethodGet, Path: "/oauth/device/confirm",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/oauth/device_confirm"},
		{Name: "oauth.device_confirm.decide", Method: http.MethodPost,
			Path: "/oauth/device/confirm", Access: UIAccessPublic,
			Layout: "layout/auth", Template: "page/oauth/device_confirm"},
		{Name: "auth.qr_login", Method: http.MethodGet, Path: "/login/qr",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/qr_login"},
		{Name: "auth.qr_login.poll", Method: http.MethodPost, Path: "/login/qr/poll",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/qr_login"},
		{Name: "auth.qr_login.claim", Method: http.MethodPost, Path: "/login/qr/claim",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/qr_login"},
		{Name: "auth.qr_login.regenerate", Method: http.MethodPost, Path: "/login/qr/regenerate",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/qr_login"},
		{Name: "auth.qr_login.cancel", Method: http.MethodPost, Path: "/login/qr/cancel",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/auth/qr_login"},
		{Name: "app.scan_confirm", Method: http.MethodGet, Path: "/app/scan",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/app/scan_confirm"},
		{Name: "app.scan_confirm.decide", Method: http.MethodPost, Path: "/app/scan",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/app/scan_confirm"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// oauthText 返回中文基线文案（缺失时回退键名）。
func oauthText(key string) string { return textMFA(key) }
