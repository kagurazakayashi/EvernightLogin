package login

// HTTP Handler 公开门面（步骤 213 迁移后）。
//
// 公开契约（HTTPOptions/UIHTTPOptions/Identity/防护选项）位于 httpapi 叶子包；
// Handler 组装与公开↔内部转换位于 internal/httpassemble；根包只保留薄函数转发，
// 保持既有公开 API 与行为不变。

import (
	"context"
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/internal/httpassemble"
)

// NewHTTPHandler 构造标准 net/http Handler。生产实例只注册固定预热用的健康
// 端点与 OpenAPI 文档；未鉴权的管理功能、调试路由和测试路由都不会注册。默认
// 启用安全响应头、多维限流、请求期限/并发上限与精确 CORS 配置入口；CSRF 默认
// 关闭，需宿主显式提供校验器并绑定 Cookie 会话契约。
//
// 选项非法时返回 CONFIG_INVALID 统一错误，不创建任何监听、协程或文件。
// NewHTTPHandler 不创建服务器、不监听端口、不启动后台 goroutine。
func NewHTTPHandler(options HTTPOptions) (http.Handler, error) {
	return httpassemble.NewHTTPHandler(options, CurrentBuildInfo().Version)
}

// OpenAPIDocument 生成指定路径前缀的机器可读 OpenAPI 文档。错误码 enum 与
// x-login-error-registry 直接来自错误码注册表，新增错误码时不会遗漏。
//
// prefix 的合法性规则与 HTTPOptions.Prefix 相同；非法前缀返回 CONFIG_INVALID。
func OpenAPIDocument(prefix string) ([]byte, error) {
	return httpassemble.OpenAPIDocument(prefix, CurrentBuildInfo().Version)
}

// IdentityFromContext 返回 HTTP Handler 或宿主中间件放入请求上下文的可信身份。
// 服务层只能使用这里的身份做授权判断；没有身份表示匿名访问，由具体接口决定
// 是否允许。
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	return httpassemble.IdentityFromContext(ctx)
}

// WithIdentity 把已由可信边界建立的身份放入上下文，供宿主或测试中间件使用。
// 身份必须通过 Validate；不要把客户端请求字段直接转成 Identity。
func WithIdentity(ctx context.Context, identity Identity) (context.Context, error) {
	return httpassemble.WithIdentity(ctx, identity)
}

// RequestIDFromContext 返回当前请求的查询编号；没有时返回空字符串。请求编号
// 不是凭证，不能用于授权判断。
func RequestIDFromContext(ctx context.Context) string {
	return httpassemble.RequestIDFromContext(ctx)
}

// ClientServiceIdentityFromContext 返回独立监听的 mTLS 边界验证并显式映射后的
// 可信服务身份名称。未启用客户端证书认证、嵌入模式自行监听或匿名连接时返回
// 空字符串与 false。
//
// 该身份来自 TLS 客户端证书的显式“DNS 名称 -> 服务身份”映射，不是用户身份，
// 不会被当作 root 或自动获得任何业务权限；服务层必须独立授权。它也不能由请求
// 头、查询参数或请求体声明。
func ClientServiceIdentityFromContext(ctx context.Context) (string, bool) {
	return httpassemble.ClientServiceIdentityFromContext(ctx)
}
