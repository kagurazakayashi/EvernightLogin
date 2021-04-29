package transport

import (
	"context"
	"errors"
	"net/http"
)

// identityContextKey 是可信身份在请求上下文中的键；类型不导出，避免其他包用
// 普通字符串键覆盖或伪造身份。
type identityContextKey struct{}

// requestIDContextKey 是请求编号在请求上下文中的键。
type requestIDContextKey struct{}

// WithIdentity 把已由可信解析函数建立的身份放入上下文；公开包用它提供宿主与
// 服务层的上下文传递接口。调用方必须先验证身份结构，不能把客户端自填字段当作
// 身份。
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// IdentityFromContext 返回请求上下文中由传输层建立的可信身份。服务层只能使用
// 这里返回的身份，不能从请求参数、客户端头或自定义上下文键读取操作者 ID。
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	if ctx == nil {
		return Identity{}, false
	}
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	if !ok || identity.SubjectID == "" {
		return Identity{}, false
	}
	return identity, true
}

// WithRequestID 把本次请求编号放入上下文。
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// RequestIDFromContext 返回本次请求编号；没有时为空字符串。请求编号只用于
// 关联与排障，不是凭证，也不能用于授权判断。
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

// validIdentity 报告身份是否满足最低结构要求：已知类型、稳定非空 ID；应用
// 身份必须带应用范围。身份内容由可信解析函数保证，本函数只做防御性校验。
func validIdentity(identity Identity) bool {
	if identity.SubjectID == "" || len(identity.SubjectID) > 128 {
		return false
	}
	if !validIdentityKind(identity.Kind) {
		return false
	}
	if identity.Kind == "application" && identity.AppID == "" {
		return false
	}
	return true
}

// validIdentityKind 报告身份类型是否是本步定义的受控枚举。
func validIdentityKind(kind string) bool {
	switch kind {
	case "user", "application", "system":
		return true
	default:
		return false
	}
}

// resolveRequestIdentity 调用注入的可信解析函数建立身份。解析函数必须基于
// 已认证会话/令牌或宿主可信上下文；本函数不读取任何客户端自填身份字段。
func (h *handler) resolveRequestIdentity(ctx context.Context, r *http.Request) (Identity, *problem) {
	if h.resolveIdentity == nil {
		return Identity{}, newProblem(http.StatusForbidden, "ACCESS_DENIED", "该接口需要已验证身份，但当前 Handler 未配置身份解析")
	}
	identity, err := h.resolveIdentity(ctx, r)
	if err != nil {
		var identityErr *IdentityError
		if errors.As(err, &identityErr) {
			status := identityErr.Status
			if status < 400 || status > 599 {
				status = http.StatusUnauthorized
			}
			code := identityErr.Code
			if code == "" {
				code = "AUTH_FAILED"
			}
			message := identityErr.Message
			if message == "" {
				message = "无法完成登录"
			}
			return Identity{}, newProblem(status, code, message)
		}
		return Identity{}, newProblem(http.StatusUnauthorized, "AUTH_FAILED", "无法完成登录")
	}
	if !validIdentity(identity) {
		return Identity{}, newProblem(http.StatusUnauthorized, "AUTH_FAILED", "无法完成登录")
	}
	return identity, nil
}
