package transport

import (
	"context"
	"strings"
)

// clientServiceIdentityKey 是请求上下文中可信服务身份的键。使用包内私有类型，
// 外部包无法伪造同名键；身份只能由代理边界在 TLS 客户端证书已验证并显式映射后
// 写入，不能来自请求头、查询参数或请求体。
type clientServiceIdentityKey struct{}

// WithClientServiceIdentity 把 mTLS 边界验证并映射后的可信服务身份名称放入上下文。
func WithClientServiceIdentity(ctx context.Context, identity string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	name := strings.TrimSpace(identity)
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, clientServiceIdentityKey{}, name)
}

// ClientServiceIdentityFromContext 返回请求上下文中由独立 Server 的 mTLS 边界
// 建立的可信服务身份。没有该身份时返回空字符串与 false。
//
// 返回值只是已通过 TLS 客户端证书验证并显式映射的受限身份名称，不携带 root、
// 系统资格或业务权限；服务层仍必须独立做授权判断。嵌入模式直接使用
// NewHTTPHandler 时，本包不知道宿主的 TLS 终止方式，不会建立该身份。
func ClientServiceIdentityFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(clientServiceIdentityKey{}).(string)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}
