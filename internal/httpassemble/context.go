package httpassemble

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// IdentityFromContext 返回 HTTP Handler 或宿主中间件放入请求上下文的可信身份。
// 服务层只能使用这里的身份做授权判断；没有身份表示匿名访问，由具体接口决定
// 是否允许。
func IdentityFromContext(ctx context.Context) (httpapi.Identity, bool) {
	internalIdentity, ok := transport.IdentityFromContext(ctx)
	if !ok {
		return httpapi.Identity{}, false
	}
	return httpapi.Identity{
		Kind:      httpapi.IdentityKind(internalIdentity.Kind),
		SubjectID: internalIdentity.SubjectID,
		AppID:     internalIdentity.AppID,
	}, true
}

// WithIdentity 把已由可信边界建立的身份放入上下文，供宿主或测试中间件使用。
// 身份必须通过 Validate；不要把客户端请求字段直接转成 Identity。
func WithIdentity(ctx context.Context, identity httpapi.Identity) (context.Context, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	return transport.WithIdentity(ctx, transport.Identity{
		Kind:      string(identity.Kind),
		SubjectID: identity.SubjectID,
		AppID:     identity.AppID,
	}), nil
}

// RequestIDFromContext 返回当前请求的查询编号；没有时返回空字符串。请求编号
// 不是凭证，不能用于授权判断。
func RequestIDFromContext(ctx context.Context) string {
	return transport.RequestIDFromContext(ctx)
}

// ClientServiceIdentityFromContext 返回独立监听的 mTLS 边界验证并显式映射后的
// 可信服务身份名称。未启用客户端证书认证、嵌入模式自行监听或匿名连接时返回
// 空字符串与 false。
//
// 该身份来自 TLS 客户端证书的显式“DNS 名称 -> 服务身份”映射，不是用户身份，
// 不会被当作 root 或自动获得任何业务权限；服务层必须独立授权。它也不能由请求
// 头、查询参数或请求体声明。
func ClientServiceIdentityFromContext(ctx context.Context) (string, bool) {
	return transport.ClientServiceIdentityFromContext(ctx)
}
