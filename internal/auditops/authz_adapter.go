package auditops

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// AuthzChecker 是 internal/authz 权限检查的最小契约（生产 *authz.Service）。
type AuthzChecker interface {
	Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
}

// authzScopeAuthorizer 把 internal/authz 的权限检查结果适配为本包的作用范围授权。
type authzScopeAuthorizer struct {
	checker AuthzChecker
}

// NewAuthzAuthorizer 构造生产作用范围授权适配器：功能权限通过后把数据范围映射为
// ScopeGrant（all/资源集合）；数据范围 undefined/none、来源截断或依赖失败一律
// 不授权（fail-closed），不把“未声明数据范围”当作全部数据。root 不经过普通权限
// 引擎：调用方的 RootChecker 在 Service 内先行放行，本适配器只处理非 root 主体。
func NewAuthzAuthorizer(checker AuthzChecker) (Authorizer, error) {
	if isNil(checker) {
		return nil, fmt.Errorf("%w: 授权检查器缺失", ErrOptionsInvalid)
	}
	return &authzScopeAuthorizer{checker: checker}, nil
}

// AuthorizeScope 实现 Authorizer。
func (a *authzScopeAuthorizer) AuthorizeScope(ctx context.Context, caller account.Caller,
	permissionKey, scopeID string) (ScopeGrant, error) {
	actor := caller.Actor()
	authzCaller, err := authzCallerFromActor(actor)
	if err != nil {
		return ScopeGrant{}, ErrAccessDenied
	}
	result, err := a.checker.Check(ctx, authzCaller, authz.CheckRequest{
		SubjectUserID: actor.ID, ScopeID: scopeID,
		Permissions: []string{permissionKey}, Mode: authz.ModeAll,
	})
	if err != nil {
		// 授权依赖失败默认拒绝，由服务层映射为 ACCESS_DENIED，不泄露底层错误。
		return ScopeGrant{}, fmt.Errorf("%w: 授权检查不可用", ErrAccessDenied)
	}
	if !result.Allowed {
		return ScopeGrant{Allowed: false}, nil
	}
	grant := ScopeGrant{Allowed: true}
	for _, decision := range result.Permissions {
		if decision.Key != permissionKey {
			continue
		}
		switch decision.DataScope.Mode {
		case authz.DataScopeAll:
			grant.AllData = true
			return grant, nil
		case authz.DataScopeResources:
			grant.ResourceIDs = append([]string(nil), decision.DataScope.Resources...)
			return grant, nil
		default:
			// undefined/none 默认拒绝资源级访问。
			return ScopeGrant{Allowed: false}, nil
		}
	}
	return ScopeGrant{Allowed: false}, nil
}

// authzCallerFromActor 把可信审计身份转换为 internal/authz 调用者；匿名拒绝。
func authzCallerFromActor(actor audit.Actor) (authz.Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return authz.UserCaller(actor.ID)
	case audit.ActorSystem:
		return authz.SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return authz.LocalBootstrapCaller(actor.ID)
	default:
		return authz.Caller{}, ErrAccessDenied
	}
}
