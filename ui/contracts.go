// 本文件实现内置 Web 页面的公开契约与基础框架（步骤 62，契约版本 ui.v1）。
//
// 技术基线：Go html/template + embed + 原生 CSS/ES 模块，服务端渲染、渐进增强；
// 不引入 Node/npm，不加载任何第三方在线资源。页面可被宿主替换：
//   - 宿主页面渲染器（HostRenderer）优先于宿主模板，宿主模板优先于内置模板；
//   - 宿主可为任意命名路由提供自己的模板或渲染器；
//   - DisableBuiltinPages 只关闭内置页面，不影响核心 Go API、受保护业务 API 与
//     标准 OAuth/OIDC 端点；不把“未提供服务”伪装成成功页。
//
// 安全边界：
//   - 页面不自己解析 Cookie 身份：统一经 UISessionService（由宿主注入真实会话服务）
//     取得公开安全摘要；未登录/过期/受限/无权限分别呈现 401/受限/403，不复用 API
//     身份解析，也不在前端缓存权限。
//   - 无 JavaScript 表单使用与会话绑定的确定性页面 CSRF 令牌（隐藏字段），
//     transport 的 CSRF 中间件仍调用同一会话校验器并校验 Origin/Referer；令牌
//     不写入 URL、localStorage、日志或审计。
//   - 所有页面模板受 html/template 自动转义；不提供通用 raw_html；不可信昵称/
//     描述/错误文本不拼接 HTML。HTML 响应 no-store 并显式使用页面 CSP（由宿主
//     通过 UIHTTPOptions 提供，默认见 DefaultUIPageContentSecurityPolicy）。
//   - 静态资源只允许本地、白名单扩展名与规范化逻辑路径；拒绝路径穿越、编码斜杠、
//     反斜杠、重复斜杠；带内容指纹的资源可长期缓存。
package ui

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/text/language"
)

// UIContractVersion 是本页面框架的公开契约版本。新增可选字段属于兼容扩展；
// 删除字段、改变路由含义、放宽安全要求必须升级契约版本。
const UIContractVersion = "ui.v1"

// DefaultUIPageContentSecurityPolicy 是内置页面的 CSP 基线：仅允许同源脚本/
// 样式/图片/连接，禁止内联脚本样式、eval、对象、base 与跨源表单，禁止被嵌入。
const DefaultUIPageContentSecurityPolicy = "default-src 'none'; script-src 'self'; " +
	"style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

// UIAccess 是页面访问级别。
type UIAccess string

const (
	// UIAccessPublic 表示无需登录即可渲染的页面（登录/错误页等）。
	UIAccessPublic UIAccess = "public"
	// UIAccessUser 表示需要普通完整会话的页面。
	UIAccessUser UIAccess = "user"
	// UIAccessManagement 表示需要管理会话（宿主 UISessionService 内部完成强认证
	// 与敏感策略判定；页面层不重复实现）。
	UIAccessManagement UIAccess = "management"
)

// Valid 报告访问级别是否已定义。
func (a UIAccess) Valid() bool {
	return a == UIAccessPublic || a == UIAccessUser || a == UIAccessManagement
}

// UIRoute 是冻结的命名路由：路径由框架统一加 BasePath，模板与路由解耦。
type UIRoute struct {
	Name     string
	Method   string
	Path     string
	Access   UIAccess
	Layout   string
	Template string
	Module   string
}

// BuiltinUIRoutes 返回步骤 62 冻结的内置系统页面路由。
func BuiltinUIRoutes() []UIRoute {
	return []UIRoute{
		{Name: "system.forbidden", Method: http.MethodGet, Path: "/403",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/forbidden"},
		{Name: "system.not_found", Method: http.MethodGet, Path: "/404",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/not_found"},
		{Name: "system.session_expired", Method: http.MethodGet, Path: "/401",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/session_expired"},
		{Name: "system.error", Method: http.MethodGet, Path: "/500",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/error"},
	}
}

// ComponentPreviewRoute 返回仅用于测试/示例的组件隔离预览路由（默认不注册）。
func ComponentPreviewRoute() UIRoute {
	return UIRoute{Name: "ui.component_preview", Method: http.MethodGet,
		Path: "/_ui/preview", Access: UIAccessUser, Layout: "layout/base",
		Template: "page/system/component_preview"}
}

// ComponentPreviewSubmitRoute 是组件预览页的 POST 路由（仅测试/示例；只演示
// 表单经过 CSRF 与字段渲染，不授予任何业务能力）。
func ComponentPreviewSubmitRoute() UIRoute {
	return UIRoute{Name: "ui.component_preview.submit", Method: http.MethodPost,
		Path: "/_ui/preview", Access: UIAccessUser, Layout: "layout/base",
		Template: "page/system/component_preview"}
}

// UISession 是页面可用的会话公开摘要（不含会话秘密/CSRF/内部安全版本）。
type UISession struct {
	Authenticated bool
	UserID        string
	AppID         string
	Kind          string
	Reason        string
	RequiredSteps []string
	ExpiresAt     time.Time
}

// 页面会话错误哨兵。实现必须把“未登录/会话无效/过期”统一映射为
// ErrUISessionExpired，把“已登录但无权限/受限”映射为 ErrUIForbidden。
var (
	// ErrUISessionExpired 表示没有有效会话或会话已过期/撤销。
	ErrUISessionExpired = errors.New("页面会话已过期")
	// ErrUIForbidden 表示当前会话不允许访问该页面（无权限或受限会话）。
	ErrUIForbidden = errors.New("页面访问未获准")
)

// UISessionService 是宿主注入的页面会话契约。生产实现应使用 internal/session
// 的 Validate/AuthorizeBusiness/AuthorizeManagement 与 IssuePageCSRFToken，并
// 在每次请求重新校验；页面层不信任 Cookie 之外的任何自报身份。
type UISessionService interface {
	ResolvePageSession(ctx context.Context, request *http.Request) (UISession, error)
	IssueCSRFToken(ctx context.Context, request *http.Request) (string, error)
}

// UIFormTokenProvider 为公开（匿名）页面表单签发短时效 CSRF 令牌与 Cookie。
// 生产实现必须使用密钥环签名、绑定表单用途、只放在隐藏字段与 HttpOnly Cookie，
// 绝不放入 URL；未提供时公开页面 POST 由宿主自行保证同源防护（默认 fail-closed）。
type UIFormTokenProvider interface {
	Issue(ctx context.Context, request *http.Request, purpose string) (token string,
		cookie *http.Cookie, err error)
}

// UIPageHandler 是命名路由的业务处理器：在框架完成固定前缀、方法匹配、会话级别、
// CSRF 与请求限流后调用；页面只消费安全摘要并调用真实后端，不解析 Cookie 身份。
type UIPageHandler interface {
	HandlePage(ctx context.Context, request *http.Request, page UIPageContext) (UIPageOutcome, error)
}

// UIPageOutcome 是页面处理器输出。框架负责设置 Cookie/状态码/重定向与模板渲染；
// 页面处理器不得自行写响应头或响应体。
type UIPageOutcome struct {
	// StatusCode 为 0 时保持 200；错误状态由框架统一渲染当前页面错误摘要。
	StatusCode int
	Data       any
	// FieldErrors 是字段级公开错误（键为表单字段名）。
	FieldErrors map[string]string
	// ErrorCode/ErrorSummary 作用于错误摘要与页面状态；不包含内部细节。
	ErrorCode    string
	ErrorSummary string
	// ExternalRedirectURL 是后端生成的受控绝对跳转（例如 OAuth 已登记回调）；
	// 框架只允许不含控制字符、长度受限且非 javascript/data 的绝对 URL。
	ExternalRedirectURL string
	// RedirectRoute 是命名路由；RedirectPath 是站内相对路径（框架加 BasePath）。
	// RedirectQuery 只允许白名单键（页面处理器负责校验）。
	RedirectRoute string
	RedirectPath  string
	RedirectQuery url.Values
	// SetCookies 只用于会话/短期提示 Cookie；框架在写响应前设置。
	SetCookies []*http.Cookie
	// ContentType 非空时表示二进制/原始响应（例如受控头像字节），框架跳过模板，
	// 使用 Body/Headers 输出；此时 StatusCode 必须为有效状态。
	ContentType string
	Body        []byte
	Headers     http.Header
}

// UIBrand 是页面品牌设置（默认仅本地资源）。
type UIBrand struct {
	Name      string
	LogoAsset string
	Theme     string
}

// UINavItem 是服务端生成的导航项（可见/禁用/原因均由服务端决定）。
type UINavItem struct {
	Key              string
	Label            string
	RouteName        string
	Visible          bool
	Enabled          bool
	Current          bool
	DisabledReason   string
	PermissionReason string
}

// UINavigationProvider 按请求上下文生成导航；仅影响展示，不是授权证明。
type UINavigationProvider interface {
	Navigation(ctx context.Context, page UIPageContext) ([]UINavItem, error)
}

// UIFieldError 是字段级错误（页面只显示公开说明与稳定码）。
type UIFieldError struct {
	Field   string
	Code    string
	Message string
}

// UIPageContext 是页面渲染视图模型（公开、只含安全摘要）。
type UIPageContext struct {
	ContractVersion string
	RouteName       string
	BasePath        string
	CanonicalURL    string
	Locale          string
	FallbackLocale  string
	TimeZone        string
	RequestID       string
	Session         UISession
	Brand           UIBrand
	Navigation      []UINavItem
	CSRF            string
	// CSRFField 是当前框架使用的表单隐藏字段名（与 transport CSRF 契约一致）。
	CSRFField    string
	StatusCode   int
	ErrorCode    string
	ErrorMessage string
	ErrorSummary string
	FieldErrors  map[string]string
	Data         any
}

// UIPageResponse 是宿主页面渲染器输出。
type UIPageResponse struct {
	StatusCode  int
	ContentType string
	Headers     http.Header
	Body        []byte
}

// UIPageRenderer 是宿主单页渲染器：返回 handled=false 表示未提供该页面并回退到
// 模板渲染；error 表示宿主模板/渲染契约错误（明确报错，不静默回退掩盖）。
type UIPageRenderer interface {
	RenderPage(ctx context.Context, page UIPageContext) (response UIPageResponse, handled bool, err error)
}

// UITemplateOverride 把命名路由指向宿主模板文件（相对 HostTemplates.FS 根）。
type UITemplateOverride struct {
	RouteName    string
	TemplatePath string
}

// UIHostTemplates 是宿主模板覆盖来源；同相对路径可覆盖内置 layout/component/page。
type UIHostTemplates struct {
	FS        fs.FS
	Overrides []UITemplateOverride
}

// UICatalogProvider 提供真实完成翻译的语言目录；未提供的语言不得声明可用。
type UICatalogProvider interface {
	Catalog(locale string) (map[string]string, bool)
	SupportedLocales() []string
}

// WebUIOptions 是内置页面框架构造参数。
type WebUIOptions struct {
	// ContractVersion 为空或 ui.v1；未知版本拒绝构造。
	ContractVersion string
	// Prefix 必须与宿主 HTTP Handler 的固定路径前缀一致（复用同一规范化规则）。
	Prefix string
	Brand  UIBrand
	// Routes 是宿主追加的命名路由；不能与内置路由重名或路径冲突。
	Routes []UIRoute
	// Session 是页面会话服务；nil 时受保护页面一律 fail-closed 为 401 过期页。
	Session UISessionService
	// CSRFField 是表单隐藏字段名；空使用 csrf_token，必须与 HTTP 防护的
	// CSRFPolicy.TokenFormField 保持一致（否则表单校验会失败）。
	CSRFField string
	// Navigation 生成服务端导航；nil 时使用空导航。
	Navigation UINavigationProvider
	// HostRenderer 是最高优先级的单页渲染器。
	HostRenderer UIPageRenderer
	// HostTemplates 是宿主模板覆盖来源。
	HostTemplates *UIHostTemplates
	// AssetOverlays 按顺序覆盖内置静态资源（同逻辑路径后者优先）。
	AssetOverlays []fs.FS
	// Translations 是可选的翻译目录来源；默认内置 zh-CN。
	Translations UICatalogProvider
	// Handlers 是按命名路由注册的页面处理器（键必须是已注册路由名）。
	Handlers map[string]UIPageHandler
	// FormTokens 为公开页面表单签发匿名 CSRF 令牌；nil 时不渲染匿名令牌。
	FormTokens UIFormTokenProvider
	// PageAuth 非 nil 时注册步骤 63 账户入口页面（登录/注册/邀请/邮箱验证/退出）。
	PageAuth *UIPageAuthOptions
	// PageAccount 非 nil 时注册步骤 66 个人资料/头像/邮箱/密码页面。
	PageAccount *UIPageAccountOptions
	// PageAdmin 非 nil 时注册步骤 68 用户管理/注册审核/用户组页面。
	PageAdmin *UIPageAdminOptions
	// PageMFA 非 nil 时注册步骤 64 两步验证/Passkey/恢复/找回页面。
	PageMFA *UIPageMFAOptions
	// PageOAuth 非 nil 时注册步骤 65 OAuth 授权/设备码/扫码登录页面。
	PageOAuth *UIPageOAuthOptions
	// PageSecurity 非 nil 时注册步骤 67 安全中心/会话/已授权应用页面。
	PageSecurity *UIPageSecurityOptions
	// PageRBAC 非 nil 时注册步骤 69 角色/权限/委派/有效权限页面。
	PageRBAC *UIPageRBACOptions
	// PageManage 非 nil 时注册步骤 185 业务应用管理员页面（我可管理的应用/成员/
	// 应用内角色与权限关联），全部 UIAccessUser，供应用范围管理员在普通业务会话使用。
	PageManage *UIPageManageOptions
	// PageApps 非 nil 时注册步骤 70 应用资料/成员/安全接入/凭证/许可/状态页面。
	PageApps *UIPageAppsOptions
	// PageSupport 非 nil 时注册步骤 71 客服求助/人工恢复申请/独立审批页面。
	PageSupport *UIPageSupportOptions
	// PageSecurityPolicy 非 nil 时注册步骤 72 敏感操作策略与安全通知设置页面。
	PageSecurityPolicy *UIPageSecurityPolicyOptions
	// PageAudit 非 nil 时注册步骤 74 审计记录/错误诊断/导出任务/审计清理页面。
	PageAudit *UIPageAuditOptions
	// PageStats 非 nil 时注册步骤 76 统计看板/活跃度与错误趋势/错误分类明细页面。
	PageStats *UIPageStatsOptions
	// PageReports 非 nil 时注册步骤 79 报告计划/历史/下载/保留清理页面。
	PageReports *UIPageReportsOptions
	// PageBackups 非 nil 时注册步骤 81 备份计划/任务/历史/下载/保留清理页面。
	PageBackups *UIPageBackupOptions
	// PageAdminSessions 非 nil 时注册步骤 187 管理员强制下线页面（目标会话查询、
	// 影响说明、撤销当前范围/指定会话；系统管理 UIAccessManagement）。
	PageAdminSessions *UIPageAdminSessionsOptions
	// DisableBuiltinPages 为 true 时关闭内置页面，仅宿主渲染器/模板可提供页面。
	DisableBuiltinPages bool
	// EnableComponentPreview 允许注册 ui.component_preview（仅测试/示例）。
	EnableComponentPreview bool
	Now                    func() time.Time
	Logger                 *slog.Logger
}

// assetEntry 是一个已加载静态资源。
type assetEntry struct {
	logical string
	hash    string
	data    []byte
	mime    string
}

// catalog 是内置/宿主翻译目录的运行时。
type catalog struct {
	fallback  map[string]string
	byTag     map[string]map[string]string
	supported []language.Tag
}

// WebUI 是内置页面处理器（实现 http.Handler）；构造后不可变、可并发使用。
type WebUI struct {
	opts                WebUIOptions
	prefix              string
	routes              []UIRoute
	byName              map[string]UIRoute
	byPath              map[string][]UIRoute
	tmpl                map[string]*template.Template
	assets              map[string]assetEntry
	catalog             *catalog
	now                 func() time.Time
	logger              *slog.Logger
	hostPage            map[string]string
	builtinPageDisabled bool
	pageAuth            *pageAuthPages
	pageAccount         *pageAccountPages
	pageAdmin           *pageAdminPages
	pageMFA             *pageMFAPages
	pageOAuth           *pageOAuthPages
	pageSecurity        *pageSecurityPages
	pageRBAC            *pageRBACPages
	pageManage          *pageManagePages
	pageApps            *pageAppsPages
	pageSupport         *pageSupportPages
	pageSecurityPolicy  *pageSecurityPolicyPages
	pageAudit           *pageAuditPages
	pageStats           *pageStatsPages
	pageReports         *pageReportsPages
	pageBackups         *pageBackupPages
	pageAdminSessions   *pageAdminSessionsPages
}

// NewWebUI 校验依赖与页面资源并构造页面处理器。
