package serverapp

import (
	"context"
	"sync/atomic"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// lazySessionScopeAuthorizer 是会话服务的延迟范围授权器。
//
// 装配顺序：session.New 先于 authz.Service 构造，因此先注入本对象，等 managed
// 授权层就绪后再 Set 真实 AuthzAuthorizer。未注入前所有管理强制下线一律返回
// session.ErrAccessDenied（fail-closed），绝不把“尚未装配”当成放行。
type lazySessionScopeAuthorizer struct {
	inner atomic.Pointer[lazyAuthorizerHolder]
}

// lazyAuthorizerHolder 保存接口值；atomic.Pointer 只能存具体指针类型。
type lazyAuthorizerHolder struct {
	authorizer session.ScopeAuthorizer
}

// newLazySessionScopeAuthorizer 构造未注入状态的延迟授权器。
func newLazySessionScopeAuthorizer() *lazySessionScopeAuthorizer {
	return &lazySessionScopeAuthorizer{}
}

// Set 原子注入真实授权器；nil 会清除（回到 fail-closed）。
func (l *lazySessionScopeAuthorizer) Set(authorizer session.ScopeAuthorizer) {
	if l == nil {
		return
	}
	l.inner.Store(&lazyAuthorizerHolder{authorizer: authorizer})
}

// AuthorizeSessionRevoke 实现 session.ScopeAuthorizer；未注入时拒绝。
func (l *lazySessionScopeAuthorizer) AuthorizeSessionRevoke(ctx context.Context,
	actor audit.Actor, scopeAppID, targetUserID string) error {
	if l == nil {
		return session.ErrAccessDenied
	}
	holder := l.inner.Load()
	if holder == nil || holder.authorizer == nil {
		return session.ErrAccessDenied
	}
	return holder.authorizer.AuthorizeSessionRevoke(ctx, actor, scopeAppID, targetUserID)
}

var _ session.ScopeAuthorizer = (*lazySessionScopeAuthorizer)(nil)
