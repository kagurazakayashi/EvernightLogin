package transport

import (
	"context"
	"net/netip"
	"strings"
)

// clientIPContextKey 是经过代理边界验证的客户端地址上下文键。键类型不导出，
// 其他包无法用普通字符串键伪造。
type clientIPContextKey struct{}

// WithClientIP 把代理边界已验证的客户端地址放入请求上下文。只有传输层代理
// 边界（Boundary）与内部测试可以调用；地址必须是合法 IP，非法值被忽略，避免
// 把任意字符串写进限流键或访问日志。
func WithClientIP(ctx context.Context, clientIP string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	address, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, clientIPContextKey{}, address.Unmap().String())
}

// ClientIPFromContext 返回代理边界验证过的客户端地址；没有时返回 false。
// 该地址只用于限流、访问日志与排障，不是身份凭证，不能用于授权判断。
func ClientIPFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	clientIP, ok := ctx.Value(clientIPContextKey{}).(string)
	if !ok || clientIP == "" {
		return "", false
	}
	return clientIP, true
}
