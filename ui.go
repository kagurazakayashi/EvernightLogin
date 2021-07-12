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
package login

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/language"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
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
	// RedirectRoute 是命名路由；RedirectPath 是站内相对路径（框架加 BasePath）。
	// RedirectQuery 只允许白名单键（页面处理器负责校验）。
	RedirectRoute string
	RedirectPath  string
	RedirectQuery url.Values
	// SetCookies 只用于会话/短期提示 Cookie；框架在写响应前设置。
	SetCookies []*http.Cookie
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
}

// NewWebUI 校验依赖与页面资源并构造页面处理器。
func NewWebUI(options WebUIOptions) (*WebUI, error) {
	version := strings.TrimSpace(options.ContractVersion)
	if version != "" && version != UIContractVersion {
		return nil, fmt.Errorf("不支持的页面契约版本 %q（当前 %s）", version, UIContractVersion)
	}
	prefix, err := transport.NormalizePrefix(options.Prefix)
	if err != nil {
		return nil, fmt.Errorf("页面路径前缀无效: %w", err)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	if options.CSRFField == "" {
		options.CSRFField = "csrf_token"
	}
	if !validFormFieldName(options.CSRFField) {
		return nil, fmt.Errorf("页面 CSRF 字段名无效")
	}
	brand := options.Brand
	if strings.TrimSpace(brand.Name) == "" {
		brand.Name = "EvernightLogin"
	}
	if brand.Theme != "" && brand.Theme != "light" && brand.Theme != "dark" && brand.Theme != "auto" {
		return nil, fmt.Errorf("页面主题必须是 light、dark 或 auto")
	}
	if brand.LogoAsset != "" && !validAssetLogicalPath(brand.LogoAsset) {
		return nil, fmt.Errorf("品牌 Logo 资源路径无效")
	}
	ui := &WebUI{opts: options, prefix: prefix, now: now, logger: logger,
		byName: map[string]UIRoute{}, byPath: map[string][]UIRoute{},
		tmpl: map[string]*template.Template{}, assets: map[string]assetEntry{},
		hostPage: map[string]string{}, builtinPageDisabled: options.DisableBuiltinPages}
	if options.PageAuth != nil {
		pages, pageErr := newPageAuthPages(*options.PageAuth)
		if pageErr != nil {
			return nil, pageErr
		}
		ui.pageAuth = pages
	}
	ui.opts.Brand = brand
	if err := ui.loadCatalog(); err != nil {
		return nil, err
	}
	if err := ui.loadAssets(); err != nil {
		return nil, err
	}
	if brand.LogoAsset != "" {
		if _, ok := ui.assets[brand.LogoAsset]; !ok {
			return nil, fmt.Errorf("品牌 Logo 资源不存在: %s", brand.LogoAsset)
		}
	}
	if err := ui.registerRoutes(); err != nil {
		return nil, err
	}
	if err := ui.parseTemplates(); err != nil {
		return nil, err
	}
	return ui, nil
}

// ContractVersion 返回框架契约版本。
func (ui *WebUI) ContractVersion() string { return UIContractVersion }

// Routes 返回已注册路由副本（诊断/装配校验用）。
func (ui *WebUI) Routes() []UIRoute { return append([]UIRoute(nil), ui.routes...) }

// loadCatalog 加载内置 zh-CN 与可选宿主目录。
func (ui *WebUI) loadCatalog() error {
	fallbackRaw, err := webEmbedded.ReadFile("web/i18n/zh-CN.json")
	if err != nil {
		return fmt.Errorf("读取内置 zh-CN 文案失败: %w", err)
	}
	fallback := map[string]string{}
	if err := json.Unmarshal(fallbackRaw, &fallback); err != nil {
		return fmt.Errorf("内置 zh-CN 文案不是合法 JSON: %w", err)
	}
	if len(fallback) == 0 {
		return fmt.Errorf("内置 zh-CN 文案为空")
	}
	catalog := &catalog{fallback: fallback, byTag: map[string]map[string]string{
		"zh-CN": fallback,
	}}
	catalog.supported = []language.Tag{language.MustParse("zh-CN")}
	if ui.opts.Translations != nil {
		seen := map[string]struct{}{"zh-CN": {}}
		for _, tag := range ui.opts.Translations.SupportedLocales() {
			normalized, parseErr := language.Parse(strings.TrimSpace(tag))
			if parseErr != nil {
				continue
			}
			canonical := normalized.String()
			if _, duplicated := seen[canonical]; duplicated {
				continue
			}
			translations, ok := ui.opts.Translations.Catalog(canonical)
			if !ok || len(translations) == 0 {
				continue
			}
			seen[canonical] = struct{}{}
			catalog.byTag[canonical] = translations
			catalog.supported = append(catalog.supported, normalized)
		}
	}
	ui.catalog = catalog
	return nil
}

// loadAssets 加载内置资源并按顺序应用宿主覆盖，计算内容指纹。
func (ui *WebUI) loadAssets() error {
	err := fs.WalkDir(webEmbedded, "web/assets", func(logicalPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative := strings.TrimPrefix(logicalPath, "web/assets/")
		data, readErr := webEmbedded.ReadFile(logicalPath)
		if readErr != nil {
			return readErr
		}
		ui.addAsset(relative, data)
		return nil
	})
	if err != nil {
		return fmt.Errorf("加载内置静态资源失败: %w", err)
	}
	for _, overlay := range ui.opts.AssetOverlays {
		if overlay == nil {
			continue
		}
		walkErr := fs.WalkDir(overlay, ".", func(logicalPath string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			relative := strings.TrimPrefix(strings.ReplaceAll(logicalPath, "\\", "/"), "./")
			if !validAssetLogicalPath(relative) {
				return fmt.Errorf("宿主静态资源路径无效: %q", relative)
			}
			data, readErr := fs.ReadFile(overlay, logicalPath)
			if readErr != nil {
				return readErr
			}
			ui.addAsset(relative, data)
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("加载宿主静态资源失败: %w", walkErr)
		}
	}
	if len(ui.assets) == 0 {
		return fmt.Errorf("内置静态资源为空")
	}
	return nil
}

// addAsset 记录一个逻辑资源及其内容指纹与 MIME 类型。ES 模块必须使用
// JavaScript MIME（text/javascript），不能沿用部分系统把 .mjs 映射成
// text/plain 的结果，否则 nosniff 会拒绝执行。
func (ui *WebUI) addAsset(logical string, data []byte) {
	extension := strings.ToLower(path.Ext(logical))
	var contentType string
	switch extension {
	case ".mjs", ".js":
		contentType = "text/javascript; charset=utf-8"
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".svg":
		contentType = "image/svg+xml"
	case ".png":
		contentType = "image/png"
	case ".webp":
		contentType = "image/webp"
	case ".ico":
		contentType = "image/x-icon"
	case ".json":
		contentType = "application/json"
	case ".txt":
		contentType = "text/plain; charset=utf-8"
	default:
		return
	}
	if contentType == "" {
		return
	}
	sum := sha256.Sum256(data)
	ui.assets[logical] = assetEntry{logical: logical,
		hash: hex.EncodeToString(sum[:8]), data: data, mime: contentType}
}

// registerRoutes 合并内置/预览/宿主路由并校验唯一性与安全语义。
func (ui *WebUI) registerRoutes() error {
	var routes []UIRoute
	if !ui.opts.DisableBuiltinPages {
		routes = append(routes, BuiltinUIRoutes()...)
		if ui.opts.EnableComponentPreview {
			routes = append(routes, ComponentPreviewRoute(), ComponentPreviewSubmitRoute())
		}
	}
	routes = append(routes, ui.opts.Routes...)
	if ui.pageAuth != nil {
		routes = append(routes, ui.pageAuth.routes...)
	}
	for _, route := range routes {
		if err := validateUIRoute(route); err != nil {
			return err
		}
		if _, exists := ui.byName[route.Name]; exists {
			return fmt.Errorf("页面路由名称重复: %s", route.Name)
		}
		if len(ui.byPath[route.Path]) > 0 {
			for _, existing := range ui.byPath[route.Path] {
				if existing.Method == route.Method {
					return fmt.Errorf("页面路由路径与方法重复: %s %s", route.Method, route.Path)
				}
			}
		}
		ui.byName[route.Name] = route
		ui.byPath[route.Path] = append(ui.byPath[route.Path], route)
	}
	ui.routes = routes
	// 处理器必须指向已注册路由；未知处理器或缺失处理器都拒绝构造，避免静默失效。
	for name := range ui.opts.Handlers {
		if _, ok := ui.byName[name]; !ok {
			return fmt.Errorf("页面处理器引用了未注册路由: %s", name)
		}
	}
	if ui.pageAuth != nil {
		for name := range ui.pageAuth.handlers {
			if _, ok := ui.byName[name]; !ok {
				return fmt.Errorf("页面处理器引用了未注册路由: %s", name)
			}
		}
	}
	return nil
}

// validateUIRoute 校验单条路由定义。
func validateUIRoute(route UIRoute) error {
	if strings.TrimSpace(route.Name) == "" || len(route.Name) > 128 {
		return fmt.Errorf("页面路由名称无效")
	}
	if route.Method != http.MethodGet && route.Method != http.MethodPost &&
		route.Method != http.MethodHead {
		return fmt.Errorf("页面路由 %s 的方法不受支持", route.Name)
	}
	if !strings.HasPrefix(route.Path, "/") || strings.HasSuffix(route.Path, "/") ||
		len(route.Path) > 256 || strings.ContainsAny(route.Path, "\\%?#") ||
		strings.Contains(route.Path, "//") || strings.Contains(route.Path, "..") {
		return fmt.Errorf("页面路由 %s 的路径无效", route.Name)
	}
	if !route.Access.Valid() {
		return fmt.Errorf("页面路由 %s 的访问级别无效", route.Name)
	}
	if strings.TrimSpace(route.Layout) == "" || strings.TrimSpace(route.Template) == "" {
		return fmt.Errorf("页面路由 %s 缺少布局或模板", route.Name)
	}
	if !validTemplateLogicalPath(route.Layout) || !validTemplateLogicalPath(route.Template) {
		return fmt.Errorf("页面路由 %s 的模板路径无效", route.Name)
	}
	return nil
}

// validFormFieldName 校验 CSRF 隐藏字段名（字母、数字、下划线、连字符）。
func validFormFieldName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// validTemplateLogicalPath 校验模板相对路径（不允许穿越/绝对路径/反斜杠）。
func validTemplateLogicalPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.ContainsAny(value, "\\%") || strings.Contains(value, "..") ||
		strings.Contains(value, "//") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value
}

// validAssetLogicalPath 校验静态资源逻辑路径。
func validAssetLogicalPath(value string) bool {
	if !validTemplateLogicalPath(value) {
		return false
	}
	extension := strings.ToLower(path.Ext(value))
	switch extension {
	case ".css", ".js", ".mjs", ".svg", ".png", ".webp", ".ico", ".json", ".txt":
		return true
	default:
		return false
	}
}

// parseTemplates 为每条路由解析独立模板集合：布局 + 页面 + 组件；宿主可逐文件
// 覆盖（同相对路径优先宿主模板），宿主页面模板通过 Overrides 按路由替换。
func (ui *WebUI) parseTemplates() error {
	if ui.opts.HostTemplates != nil && ui.opts.HostTemplates.FS == nil {
		return fmt.Errorf("宿主模板来源不能为空")
	}
	overrides := map[string]string{}
	if ui.opts.HostTemplates != nil {
		for _, override := range ui.opts.HostTemplates.Overrides {
			if !ui.routeExists(override.RouteName) {
				return fmt.Errorf("宿主模板覆盖引用了未知路由: %s", override.RouteName)
			}
			if !validTemplateLogicalPath(override.TemplatePath) {
				return fmt.Errorf("宿主模板路径无效: %s", override.TemplatePath)
			}
			if _, exists := overrides[override.RouteName]; exists {
				return fmt.Errorf("宿主模板覆盖重复路由: %s", override.RouteName)
			}
			overrides[override.RouteName] = override.TemplatePath
		}
	}
	componentFiles, err := ui.templateFiles("component")
	if err != nil {
		return err
	}
	for _, route := range ui.routes {
		layouts, layoutErr := ui.chooseTemplateFile(route.Layout + ".html")
		if layoutErr != nil {
			return layoutErr
		}
		pageFile := route.Template + ".html"
		if override, ok := overrides[route.Name]; ok {
			pageFile = override
		}
		pageSource, pageErr := ui.readTemplateFile(pageFile)
		if pageErr != nil {
			if ui.opts.DisableBuiltinPages && ui.opts.HostRenderer != nil {
				continue
			}
			return fmt.Errorf("页面路由 %s 缺少模板 %s: %w", route.Name, pageFile, pageErr)
		}
		set := template.New(route.Name).Funcs(templateFuncs(funcState{ui: ui}))
		for _, component := range componentFiles {
			source, readErr := ui.readTemplateFile(component)
			if readErr != nil {
				return readErr
			}
			if _, parseErr := set.Parse(string(source)); parseErr != nil {
				return fmt.Errorf("解析页面组件模板失败: %w", parseErr)
			}
		}
		layoutSource, readErr := ui.readTemplateFile(layouts)
		if readErr != nil {
			return readErr
		}
		if _, parseErr := set.Parse(string(layoutSource)); parseErr != nil {
			return fmt.Errorf("解析页面布局 %s 失败: %w", layouts, parseErr)
		}
		if _, parseErr := set.Parse(string(pageSource)); parseErr != nil {
			return fmt.Errorf("解析页面模板 %s 失败: %w", pageFile, parseErr)
		}
		if override, ok := overrides[route.Name]; ok {
			ui.hostPage[route.Name] = override
		}
		ui.tmpl[route.Name] = set
	}
	return nil
}

// templateFiles 返回某目录下内置模板相对路径（component 等共享文件）。
func (ui *WebUI) templateFiles(directory string) ([]string, error) {
	root := "web/templates/" + directory
	entries, err := fs.ReadDir(webEmbedded, root)
	if err != nil {
		return nil, fmt.Errorf("读取内置模板目录失败: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, directory+"/"+entry.Name())
	}
	sort.Strings(files)
	return files, nil
}

// chooseTemplateFile 选择布局文件：宿主同路径覆盖优先，否则内置。
func (ui *WebUI) chooseTemplateFile(logical string) (string, error) {
	if _, err := ui.readTemplateFile(logical); err != nil {
		return "", fmt.Errorf("缺少模板 %s: %w", logical, err)
	}
	return logical, nil
}

// readTemplateFile 读取模板内容：宿主模板同逻辑路径优先，内置回退。
func (ui *WebUI) readTemplateFile(logical string) ([]byte, error) {
	if ui.opts.HostTemplates != nil && ui.opts.HostTemplates.FS != nil {
		if data, err := fs.ReadFile(ui.opts.HostTemplates.FS, logical); err == nil {
			return data, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("读取宿主模板 %s 失败: %w", logical, err)
		}
	}
	return webEmbedded.ReadFile("web/templates/" + logical)
}

// routeExists 报告命名路由是否已注册。
func (ui *WebUI) routeExists(name string) bool {
	_, ok := ui.byName[name]
	return ok
}

// ServeHTTP 实现 http.Handler：按固定前缀、静态资源、命名路由、会话级别顺序处理。
func (ui *WebUI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestPath, ok := ui.stripPrefix(request.URL.Path)
	if !ok {
		ui.writePlain(writer, request, http.StatusNotFound, "页面不存在")
		return
	}
	requestID := transport.RequestIDFromContext(request.Context())
	if strings.HasPrefix(requestPath, "/assets/") {
		ui.serveAsset(writer, request, requestPath, requestID)
		return
	}
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		if strings.HasPrefix(requestPath, "/assets/") {
			return
		}
	}
	route, methodProblem := ui.matchRoute(requestPath, request.Method)
	if methodProblem {
		ui.writePlain(writer, request, http.StatusMethodNotAllowed, "请求方法不受支持")
		return
	}
	if route == nil {
		ui.renderErrorPage(writer, request, requestID, "system.not_found",
			http.StatusNotFound, "ACCESS_DENIED", ui.translate("zh-CN", "page.system.not_found.description", nil), nil)
		return
	}
	ui.serveRoute(writer, request, requestID, route)
}

// stripPrefix 校验并去掉固定路径前缀。
func (ui *WebUI) stripPrefix(requestPath string) (string, bool) {
	if ui.prefix == "" {
		return requestPath, strings.HasPrefix(requestPath, "/")
	}
	if requestPath == ui.prefix {
		return "/", true
	}
	if !strings.HasPrefix(requestPath, ui.prefix+"/") {
		return "", false
	}
	return strings.TrimPrefix(requestPath, ui.prefix), true
}

// matchRoute 返回匹配的方法+路径路由；methodProblem 表示路径存在但方法不匹配。
func (ui *WebUI) matchRoute(requestPath, method string) (*UIRoute, bool) {
	candidates := ui.byPath[requestPath]
	if len(candidates) == 0 {
		return nil, false
	}
	for index := range candidates {
		candidate := candidates[index]
		if candidate.Method == method ||
			(method == http.MethodHead && candidate.Method == http.MethodGet) {
			return &candidate, false
		}
	}
	return nil, true
}

// serveRoute 解析会话并渲染页面。
func (ui *WebUI) serveRoute(writer http.ResponseWriter, request *http.Request,
	requestID string, route *UIRoute) {
	ctx := request.Context()
	session, sessionErr := ui.resolveSession(ctx, request, route)
	if sessionErr != nil {
		status := http.StatusUnauthorized
		target := "system.session_expired"
		message := ui.translate("zh-CN", "page.system.session_expired.description", nil)
		if errors.Is(sessionErr, ErrUIForbidden) {
			status = http.StatusForbidden
			target = "system.forbidden"
			message = ui.translate("zh-CN", "page.system.forbidden.description", nil)
		} else if !errors.Is(sessionErr, ErrUISessionExpired) {
			status = http.StatusInternalServerError
			target = "system.error"
			message = ui.translate("zh-CN", "page.system.error.description", nil)
		}
		ui.renderErrorPage(writer, request, requestID, target, status,
			ui.statusCode(status), message, nil)
		return
	}
	csrfToken := ""
	var issuedCookies []*http.Cookie
	if route.Access != UIAccessPublic && ui.opts.Session != nil {
		token, err := ui.opts.Session.IssueCSRFToken(ctx, request)
		if err != nil {
			ui.renderErrorPage(writer, request, requestID, "system.session_expired",
				http.StatusUnauthorized, "ACCESS_DENIED",
				ui.translate("zh-CN", "page.system.session_expired.description", nil), nil)
			return
		}
		csrfToken = token
	}
	if route.Access == UIAccessPublic && ui.opts.FormTokens != nil {
		if purpose := formPurposeForRoute(route.Name); purpose != "" {
			token, cookie, err := ui.opts.FormTokens.Issue(ctx, request, purpose)
			if err == nil {
				csrfToken = token
				if cookie != nil {
					issuedCookies = append(issuedCookies, cookie)
				}
			}
		}
	}
	page := ui.pageContext(request, route, session, csrfToken, http.StatusOK, "", "", nil)
	handler := ui.opts.Handlers[route.Name]
	if handler == nil && ui.pageAuth != nil {
		handler = ui.pageAuth.handlers[route.Name]
	}
	if handler != nil {
		outcome, handleErr := handler.HandlePage(ctx, request, page)
		if handleErr != nil {
			ui.logger.Warn("页面处理器执行失败", "route", route.Name,
				"error_category", "ui_page_handler_failed")
			ui.renderErrorPage(writer, request, requestID, "system.error",
				http.StatusInternalServerError, "INTERNAL_ERROR",
				ui.translate("zh-CN", "page.system.error.description", nil), nil)
			return
		}
		for _, cookie := range issuedCookies {
			http.SetCookie(writer, cookie)
		}
		for _, cookie := range outcome.SetCookies {
			if cookie != nil {
				http.SetCookie(writer, cookie)
			}
		}
		if target, redirect := ui.redirectTarget(outcome); redirect {
			http.Redirect(writer, request, target, http.StatusSeeOther)
			return
		}
		if outcome.StatusCode != 0 {
			page.StatusCode = outcome.StatusCode
		}
		page.Data = outcome.Data
		if len(outcome.FieldErrors) > 0 {
			page.FieldErrors = outcome.FieldErrors
		}
		if outcome.ErrorCode != "" {
			page.ErrorCode = outcome.ErrorCode
		}
		if outcome.ErrorSummary != "" {
			page.ErrorSummary = outcome.ErrorSummary
		}
		ui.renderPage(writer, request, page, route)
		return
	}
	for _, cookie := range issuedCookies {
		http.SetCookie(writer, cookie)
	}
	data := any(nil)
	if request.Method == http.MethodPost && route.Path == "/_ui/preview" {
		// 组件预览页的 POST 仅演示“表单通过 CSRF 后渲染成功状态”，不授予业务能力。
		data = map[string]any{"submitted": true}
	}
	page.Data = data
	ui.renderPage(writer, request, page, route)
}

// redirectTarget 解析页面处理器输出的重定向目标：命名路由或站内相对路径（加
// BasePath），仅允许白名单查询键；非法目标回退到默认首页而不是开放重定向。
func (ui *WebUI) redirectTarget(outcome UIPageOutcome) (string, bool) {
	if outcome.RedirectRoute != "" {
		route, ok := ui.byName[outcome.RedirectRoute]
		if !ok || route.Access == UIAccessManagement {
			return ui.prefix + "/home", true
		}
		target := ui.routeURL(outcome.RedirectRoute)
		if len(outcome.RedirectQuery) > 0 {
			values := url.Values{}
			for key, list := range outcome.RedirectQuery {
				if !validRedirectQueryKey(key) {
					continue
				}
				for _, value := range list {
					if len(value) <= 256 {
						values.Add(key, value)
					}
				}
			}
			if encoded := values.Encode(); encoded != "" {
				target += "?" + encoded
			}
		}
		return target, true
	}
	if outcome.RedirectPath != "" {
		if !safeRelativePath(outcome.RedirectPath) {
			return ui.prefix + "/home", true
		}
		return ui.prefix + outcome.RedirectPath, true
	}
	return "", false
}

// validRedirectQueryKey 限制页面处理器可附加的查询键（仅用于提示类参数）。
func validRedirectQueryKey(key string) bool {
	switch key {
	case "status", "next":
		return true
	}
	return false
}

// safeRelativePath 报告值是否是站内相对路径（拒绝 //host、scheme、反斜杠与控制字符）。
func safeRelativePath(value string) bool {
	if value == "" || len(value) > 1024 || !strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	// 拒绝点段逃逸：浏览器会把 /a/../b 规范化为 /b，可能越过 UI BasePath 或路由预期。
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." || segment == "." {
			return false
		}
	}
	return true
}

// resolveSession 按路由访问级别解析并校验会话。
func (ui *WebUI) resolveSession(ctx context.Context, request *http.Request,
	route *UIRoute) (UISession, error) {
	if route.Access == UIAccessPublic {
		if ui.opts.Session == nil {
			return UISession{}, nil
		}
		session, err := ui.opts.Session.ResolvePageSession(ctx, request)
		if err != nil {
			return UISession{}, nil
		}
		return session, nil
	}
	if ui.opts.Session == nil {
		return UISession{}, ErrUISessionExpired
	}
	session, err := ui.opts.Session.ResolvePageSession(ctx, request)
	if err != nil {
		return UISession{}, err
	}
	if !session.Authenticated {
		return UISession{}, ErrUISessionExpired
	}
	if route.Access == UIAccessUser && session.Kind != "normal" {
		return UISession{}, ErrUIForbidden
	}
	if route.Access == UIAccessManagement && session.Kind != "management" {
		return UISession{}, ErrUIForbidden
	}
	return session, nil
}

// renderPage 优先调用宿主渲染器，否则用模板渲染。
func (ui *WebUI) renderPage(writer http.ResponseWriter, request *http.Request,
	page UIPageContext, route *UIRoute) {
	if ui.opts.HostRenderer != nil {
		response, handled, err := ui.opts.HostRenderer.RenderPage(request.Context(), page)
		if err != nil {
			ui.logger.Error("宿主页面渲染器失败", "route", page.RouteName,
				"error_category", "ui_renderer_failed")
			ui.renderErrorPage(writer, request, page.RequestID, "system.error",
				http.StatusInternalServerError, "INTERNAL_ERROR",
				ui.translate("zh-CN", "page.system.error.description", nil), nil)
			return
		}
		if handled {
			ui.writePageResponse(writer, request, response)
			return
		}
	}
	ui.renderPageWithTemplates(writer, request, page, route)
}

// renderPageWithTemplates 只用内置/宿主模板渲染（不调用宿主渲染器）；系统错误页
// 走此路径，避免宿主渲染器持续失败时递归调用自身。
func (ui *WebUI) renderPageWithTemplates(writer http.ResponseWriter, request *http.Request,
	page UIPageContext, route *UIRoute) {
	set, ok := ui.tmpl[route.Name]
	if !ok {
		ui.writePlain(writer, request, http.StatusNotFound, "页面不存在")
		return
	}
	clone, err := set.Clone()
	if err != nil {
		ui.logger.Error("页面模板复制失败", "route", page.RouteName, "error_category", "ui_render_failed")
		ui.writePlain(writer, request, http.StatusInternalServerError, "页面暂时不可用")
		return
	}
	clone.Funcs(templateFuncs(renderFuncState{ui: ui, page: page, request: request}))
	var buffer bytes.Buffer
	if err := clone.ExecuteTemplate(&buffer, route.Layout, page); err != nil {
		ui.logger.Error("页面模板执行失败", "route", page.RouteName, "error_category", "ui_render_failed", "error", err)
		ui.writePlain(writer, request, http.StatusInternalServerError, "页面暂时不可用")
		return
	}
	ui.writeHTML(writer, request, page.StatusCode, buffer.Bytes())
}

// funcState 是模板函数需要的静态上下文。
type funcState struct {
	ui *WebUI
}

// renderFuncState 是单次渲染的函数上下文。
type renderFuncState struct {
	ui      *WebUI
	page    UIPageContext
	request *http.Request
}

// templateFuncs 构造模板函数集合（无 raw_html 通用函数）。
func templateFuncs(state any) template.FuncMap {
	return template.FuncMap{
		"t": func(key string) string {
			switch typed := state.(type) {
			case funcState:
				return typed.ui.translate("zh-CN", key, nil)
			case renderFuncState:
				return typed.ui.translate(typed.page.Locale, key, nil)
			default:
				return key
			}
		},
		"route": func(name string) string {
			switch typed := state.(type) {
			case funcState:
				return typed.ui.routeURL(name)
			case renderFuncState:
				return typed.ui.routeURL(name)
			default:
				return ""
			}
		},
		"asset": func(logical string) string {
			switch typed := state.(type) {
			case funcState:
				return typed.ui.assetURL(logical)
			case renderFuncState:
				return typed.ui.assetURL(logical)
			default:
				return ""
			}
		},
		"label": func(key string) string {
			switch typed := state.(type) {
			case funcState:
				return typed.ui.translate("zh-CN", key, nil)
			case renderFuncState:
				return typed.ui.translate(typed.page.Locale, key, nil)
			default:
				return key
			}
		},
		"brand_name": func() string {
			switch typed := state.(type) {
			case funcState:
				return typed.ui.opts.Brand.Name
			case renderFuncState:
				return typed.page.Brand.Name
			default:
				return ""
			}
		},
		"locale": func() string {
			if typed, ok := state.(renderFuncState); ok {
				return typed.page.Locale
			}
			return "zh-CN"
		},
		"request_id": func() string {
			if typed, ok := state.(renderFuncState); ok {
				return typed.page.RequestID
			}
			return ""
		},
		"csrf_field": func() template.HTML {
			typed, ok := state.(renderFuncState)
			if !ok || typed.page.CSRF == "" {
				return template.HTML("")
			}
			return template.HTML(`<input type="hidden" name="` +
				html.EscapeString(typed.ui.opts.CSRFField) + `" value="` +
				html.EscapeString(typed.page.CSRF) + `">`)
		},
		"field_error": func(field string) string {
			typed, ok := state.(renderFuncState)
			if !ok {
				return ""
			}
			return typed.page.FieldErrors[field]
		},
		"format_time": func(value time.Time, timezone string) string {
			return formatUITime(value, timezone)
		},
		"format_number": func(value any) string {
			switch typed := value.(type) {
			case int:
				return formatUINumber(int64(typed))
			case int64:
				return formatUINumber(typed)
			case int32:
				return formatUINumber(int64(typed))
			default:
				return fmt.Sprintf("%v", value)
			}
		},
		"mask": func(value string) string { return maskUIValue(value) },
		"list": func(values ...any) []any { return values },
		"dict": func(values ...any) map[string]any {
			result := map[string]any{}
			for index := 0; index+1 < len(values); index += 2 {
				key, ok := values[index].(string)
				if ok {
					result[key] = values[index+1]
				}
			}
			return result
		},
		"t_fmt": func(key string, values ...string) string {
			replacements := map[string]string{}
			for index := 0; index+1 < len(values); index += 2 {
				replacements[values[index]] = values[index+1]
			}
			switch typed := state.(type) {
			case funcState:
				return typed.ui.translate("zh-CN", key, replacements)
			case renderFuncState:
				return typed.ui.translate(typed.page.Locale, key, replacements)
			default:
				return key
			}
		},
	}
}

// pageContext 构造页面视图模型。
func (ui *WebUI) pageContext(request *http.Request, route *UIRoute, session UISession,
	csrfToken string, status int, errorCode, errorMessage string,
	fieldErrors map[string]string) UIPageContext {
	locale := ui.negotiateLocale(request)
	navigation := []UINavItem{}
	if ui.opts.Navigation != nil {
		items, err := ui.opts.Navigation.Navigation(request.Context(), UIPageContext{
			ContractVersion: UIContractVersion, RouteName: route.Name, BasePath: ui.prefix,
			Locale: locale, FallbackLocale: "zh-CN",
			RequestID: transport.RequestIDFromContext(request.Context()),
			Session:   session, Brand: ui.opts.Brand,
		})
		if err == nil {
			navigation = items
		} else {
			ui.logger.Warn("页面导航生成失败", "route", route.Name, "error_category", "ui_navigation_failed")
		}
	}
	return UIPageContext{
		ContractVersion: UIContractVersion, RouteName: route.Name, BasePath: ui.prefix,
		CanonicalURL: ui.prefix + route.Path, Locale: locale, FallbackLocale: "zh-CN",
		TimeZone: "UTC", RequestID: transport.RequestIDFromContext(request.Context()),
		Session: session, Brand: ui.opts.Brand, Navigation: navigation, CSRF: csrfToken,
		CSRFField: ui.opts.CSRFField, StatusCode: status, ErrorCode: errorCode, ErrorMessage: errorMessage,
		FieldErrors: fieldErrors,
	}
}

// renderErrorPage 渲染系统错误页（不泄露内部路径/堆栈）。
func (ui *WebUI) renderErrorPage(writer http.ResponseWriter, request *http.Request,
	requestID, routeName string, status int, errorCode, message string,
	fieldErrors map[string]string) {
	route, ok := ui.byName[routeName]
	if !ok || ui.builtinPageDisabled {
		ui.writePlain(writer, request, status, message)
		return
	}
	page := ui.pageContext(request, &route, UISession{}, "", status, errorCode, message, fieldErrors)
	page.ErrorSummary = message
	ui.renderPageWithTemplates(writer, request, page, &route)
}

// statusCode 返回状态对应的稳定错误码。
func (ui *WebUI) statusCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "AUTH_FAILED"
	case http.StatusForbidden:
		return "ACCESS_DENIED"
	case http.StatusNotFound:
		return "REQ_INVALID"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	default:
		return "REQ_INVALID"
	}
}

// writePageResponse 写出宿主渲染器响应。
func (ui *WebUI) writePageResponse(writer http.ResponseWriter, request *http.Request,
	response UIPageResponse) {
	for key, values := range response.Headers {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	contentType := response.ContentType
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", "no-store")
	status := response.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(response.Body)
	}
}

// writeHTML 写出 HTML 页面（no-store；CSP 由 transport 统一写入）。
func (ui *WebUI) writeHTML(writer http.ResponseWriter, request *http.Request,
	status int, body []byte) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(body)
	}
}

// writePlain 写出最小文本错误（页面/模板不可用时；不泄露内部细节）。
func (ui *WebUI) writePlain(writer http.ResponseWriter, request *http.Request,
	status int, message string) {
	body := []byte(message)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(body)
	}
}

// assetURL 生成带内容指纹的本地资源 URL。
func (ui *WebUI) assetURL(logical string) string {
	logical = strings.TrimPrefix(logical, "/")
	entry, ok := ui.assets[logical]
	if !ok {
		return ui.prefix + "/assets/missing"
	}
	return ui.prefix + "/assets/" + entry.hash + "/" + logical
}

// routeURL 生成命名路由 URL；未知路由返回空字符串（模板输出为空）。
func (ui *WebUI) routeURL(name string) string {
	route, ok := ui.byName[name]
	if !ok {
		return ""
	}
	return ui.prefix + route.Path
}

// serveAsset 处理带指纹/不带指纹的静态资源请求。
func (ui *WebUI) serveAsset(writer http.ResponseWriter, request *http.Request,
	requestPath, requestID string) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		ui.writePlain(writer, request, http.StatusMethodNotAllowed, "请求方法不受支持")
		return
	}
	relative := strings.TrimPrefix(requestPath, "/assets/")
	parts := strings.SplitN(relative, "/", 2)
	entry := assetEntry{}
	_, hashed := ui.assets[parts[0]]
	if len(parts) == 2 && len(parts[0]) == 16 && !hashed {
		logical := parts[1]
		candidate, ok := ui.assets[logical]
		if !ok || candidate.hash != parts[0] {
			ui.writePlain(writer, request, http.StatusNotFound, "资源不存在")
			return
		}
		entry = candidate
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		candidate, ok := ui.assets[relative]
		if !ok {
			ui.writePlain(writer, request, http.StatusNotFound, "资源不存在")
			return
		}
		entry = candidate
		writer.Header().Set("Cache-Control", "no-cache")
	}
	writer.Header().Set("Content-Type", entry.mime)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(entry.data)
	}
}

// negotiateLocale 按 Accept-Language 与真实提供目录协商语言（默认 zh-CN）。
func (ui *WebUI) negotiateLocale(request *http.Request) string {
	if query := request.URL.Query().Get("lang"); query != "" {
		for _, supported := range ui.catalog.supported {
			if strings.EqualFold(supported.String(), query) {
				return supported.String()
			}
		}
	}
	header := request.Header.Get("Accept-Language")
	if header == "" || len(ui.catalog.supported) == 0 {
		return "zh-CN"
	}
	tags, _, err := language.ParseAcceptLanguage(header)
	if err != nil || len(tags) == 0 {
		return "zh-CN"
	}
	tags = append(tags, language.MustParse("zh-CN"))
	matcher := language.NewMatcher(ui.catalog.supported)
	_, index, confidence := matcher.Match(tags...)
	if confidence == language.No || index < 0 || index >= len(ui.catalog.supported) {
		return "zh-CN"
	}
	return ui.catalog.supported[index].String()
}

// translate 返回翻译文本：当前语言 → zh-CN 回退 → 键名（不记录用户秘密）。
func (ui *WebUI) translate(locale, key string, replacements map[string]string) string {
	message, ok := ui.lookupMessage(locale, key)
	if !ok {
		message, ok = ui.catalog.fallback[key]
	}
	if !ok {
		return key
	}
	for name, value := range replacements {
		message = strings.ReplaceAll(message, "{"+name+"}", value)
	}
	return message
}

// lookupMessage 在指定语言目录查找键。
func (ui *WebUI) lookupMessage(locale, key string) (string, bool) {
	catalog, ok := ui.catalog.byTag[locale]
	if !ok {
		return "", false
	}
	message, ok := catalog[key]
	return message, ok
}

// formatUITime 按 IANA 时区格式化服务端时间；非法时区回退 UTC 并显式显示。
func formatUITime(value time.Time, timezone string) string {
	if value.IsZero() {
		return "—"
	}
	location := time.UTC
	if timezone != "" {
		if loaded, err := time.LoadLocation(timezone); err == nil {
			location = loaded
		}
	}
	return value.In(location).Format("2006-01-02 15:04:05 MST")
}

// formatUINumber 格式化整数（本地化分组由后续统计步骤细化；此处确定性输出）。
func formatUINumber(value int64) string {
	negative := value < 0
	if negative {
		value = -value
	}
	digits := fmt.Sprintf("%d", value)
	var builder strings.Builder
	for index, character := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			builder.WriteByte(',')
		}
		builder.WriteRune(character)
	}
	if negative {
		return "-" + builder.String()
	}
	return builder.String()
}

// maskUIValue 对稳定 ID/编号做服务端一致脱敏（短值完全隐藏）。
func maskUIValue(value string) string {
	if value == "" {
		return "—"
	}
	runes := []rune(value)
	if len(runes) <= 8 {
		return "[REDACTED]"
	}
	return string(runes[:3]) + "***" + string(runes[len(runes)-3:])
}
