package app

import (
	login "github.com/kagurazakayashi/EvernightLogin"
	"io"
	"io/fs"
)

// HTTPOptions 是嵌入式 HTTP 与页面挂载选项；nil 表示不装配 HTTP（宿主只使用 Go API）。
// 装配沿用独立服务的完整安全链（限流/CSRF/安全头/会话/权限），不复制实现；
// 缺依赖时 Open 直接失败，不会退化为“只有健康页”的最小服务。
type HTTPOptions struct {
	// Prefix 覆盖站内路径前缀；空使用配置的 server.path_prefix。
	Prefix string
	// AccessLog 是宿主提供的 W3C 访问日志输出；nil 表示不写访问日志。
	AccessLog io.Writer
	// EnableProtocol 启用 OAuth2/OIDC 协议端点（需配置合法 protocol.issuer）。
	EnableProtocol bool
	// EnableAdminAPI 启用内置管理 JSON API（复用同一管理会话/CSRF 契约）。
	EnableAdminAPI bool
	AdminAPIPrefix string
	// EnableManagedAPI 启用业务应用托管管理 API。
	EnableManagedAPI bool
	ManagedAPIPrefix string
	// EnableAppSupport 启用应用受限客服 API（需要同时启用协议端点）。
	EnableAppSupport   bool
	AppSupportPrefix   string
	AppSupportAudience string
	// PageOverrides 是宿主页面/资源替换选项；替换不改变路由访问级别、会话/权限
	// 判定与 CSRF 校验。
	PageOverrides *PageOverrides
}

// PageOverrides 是宿主页面/资源替换选项；替换不改变路由访问级别、会话/权限判定与 CSRF 校验。
type PageOverrides struct {
	// HostTemplates 是宿主模板覆盖来源；HostRenderer 是最高优先级单页渲染器。
	HostTemplates *login.UIHostTemplates
	HostRenderer  login.UIPageRenderer
	// Brand 覆盖页面品牌；nil 使用内置品牌。
	Brand *login.UIBrand
	// AssetOverlays 按顺序覆盖内置静态资源（同逻辑路径后者优先）。
	AssetOverlays []fs.FS
	// Translations 追加/覆盖翻译目录；nil 使用内置 zh-CN。
	Translations login.UICatalogProvider
	// DisableBuiltinPages 关闭内置页面，仅由宿主模板/渲染器提供页面。
	DisableBuiltinPages bool
}
