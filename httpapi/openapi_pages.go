// 本文件定义页面处理器向 HTTP 装配层报告的命名路由投影契约。
//
// 分层目的：页面/表单 OpenAPI 需要“实际注册的页面路由”作为唯一事实来源，但
// internal/httpassemble（公开 HTTP 装配）不能反向 import 公开包 ui：公开包 ui
// 的同包测试会 import internal/httpassemble（真实 serve 测试辅助），双向 import
// 会形成测试导入环。因此把投影契约放在两者共用的叶子包 httpapi：
//   - ui.WebUI 实现 UIPageRouteLister（返回自身注册路由的只读投影）；
//   - httpassemble 只在 Handler 上做接口断言，不依赖 ui 具体类型；
//   - 自定义页面处理器也可实现该接口，让宿主装配获得同样的 OpenAPI 页面文档。
package httpapi

// UIPageRouteInfo 是页面命名路由的公开投影：只含名称/方法/路径/访问级别，
// 不含模板、处理器或会话秘密，供 OpenAPI 生成与契约核对使用。
type UIPageRouteInfo struct {
	// Name 是冻结的命名路由名，如 auth.login.submit。
	Name string
	// Method 是 GET 或 POST。
	Method string
	// Path 是相对站内前缀的页面路径，如 /login。
	Path string
	// Access 是页面访问级别：public / user / management。
	Access string
}

// UIPageRouteLister 由页面处理器实现，向 HTTP 装配层提供已注册页面路由投影。
// 未实现的处理器不影响服务，只是 OpenAPI 不会包含页面/表单操作段。
type UIPageRouteLister interface {
	// OpenAPIPageRoutes 返回当前处理器实际注册的页面命名路由投影。
	OpenAPIPageRoutes() []UIPageRouteInfo
}
