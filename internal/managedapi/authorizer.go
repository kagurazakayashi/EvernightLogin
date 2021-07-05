package managedapi

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// grantContextKey 是托管授权 grant 在 context 中的私有键；服务层只能在托管层
// 建立的同一请求上下文内使用，普通请求无法伪造。
type grantContextKey struct{}

// Grant 是一次托管调用的已批准授权快照（由托管层在判权后建立）。
type Grant struct {
	Actor       audit.Actor
	AppID       string
	OperationID string
	Policy      Policy
	RequestID   string
	Service     bool
}

// WithGrant 把已批准授权放入上下文（仅托管层调用）。
func WithGrant(ctx context.Context, grant Grant) context.Context {
	return context.WithValue(ctx, grantContextKey{}, grant)
}

// GrantFromContext 读取上下文中的托管授权；缺失时 ok=false（fail-closed）。
func GrantFromContext(ctx context.Context) (Grant, bool) {
	if ctx == nil {
		return Grant{}, false
	}
	grant, ok := ctx.Value(grantContextKey{}).(Grant)
	if !ok || grant.AppID == "" || grant.OperationID == "" {
		return Grant{}, false
	}
	return grant, true
}

// 托管授权器族：既有服务各自定义同名但签名不同的 Authorizer 接口，Go 不允许
// 同名方法重载，因此为每个服务提供独立类型（共享同一 grant 判定逻辑）。没有
// 托管 grant 时一律拒绝，防止绕过托管层直接调用服务；grant 存在时只允许本次
// 托管操作映射到的服务动作，且作用域限定在 grant 的应用。它不复制业务逻辑，
// 也不替代既有服务的审计/委派 Guard。
type baseAuthorizer struct {
	// Audit 用于记录被拒绝的直接调用（best-effort；nil 时只返回错误）。
	Audit AuditRecorder
}

// AccountAuthorizer 实现 account.Authorizer。
type AccountAuthorizer struct{ baseAuthorizer }

// AppAuthorizer 实现 app.Authorizer。
type AppAuthorizer struct{ baseAuthorizer }

// RoleAuthorizer 实现 role.Authorizer。
type RoleAuthorizer struct{ baseAuthorizer }

// GroupAuthorizer 实现 group.Authorizer。
type GroupAuthorizer struct{ baseAuthorizer }

// PermissionAuthorizer 实现 permission.Authorizer。
type PermissionAuthorizer struct{ baseAuthorizer }

// NewDelegatedAuthorizers 构造五个既有服务需要的托管授权器（共享审计写入器）。
func NewDelegatedAuthorizers(auditRecorder AuditRecorder) (account.Authorizer, app.Authorizer,
	role.Authorizer, group.Authorizer, permission.Authorizer) {
	base := baseAuthorizer{Audit: auditRecorder}
	return &AccountAuthorizer{base}, &AppAuthorizer{base}, &RoleAuthorizer{base},
		&GroupAuthorizer{base}, &PermissionAuthorizer{base}
}

// actionAllowed 报告服务动作是否被本次 grant 的操作映射允许。
func actionAllowed(grant Grant, serviceAction string) bool {
	for _, action := range actionsForOperation(grant.OperationID) {
		if action == serviceAction {
			return true
		}
	}
	return false
}

// deny 返回统一拒绝（不泄露内部原因），并尽力写失败审计：有 grant 时记录真实
// 主体，无 grant（绕过托管层的直接调用）记录匿名失败。
func (a *baseAuthorizer) deny(ctx context.Context, serviceAction string) error {
	actor := audit.Actor{Type: audit.ActorAnonymous}
	reason := "delegated_authorizer_grant_missing"
	if grant, ok := GrantFromContext(ctx); ok {
		actor = grant.Actor
		reason = "delegated_authorizer_action_not_granted"
	}
	if a != nil && !isNilInterface(a.Audit) {
		event := audit.Event{
			Actor: actor, Action: "managed_api.direct_call_denied",
			Outcome: audit.OutcomeFailure, ErrorCode: string(CodeAccessDenied),
			ReasonCode: reason,
		}
		_ = a.Audit.RecordFailure(ctx, event)
	}
	return fmt.Errorf("%w: 未通过托管管理 API 授权", ErrAccessDenied)
}

// Authorize 实现 account.Authorizer。
func (a *AccountAuthorizer) Authorize(ctx context.Context, caller account.Caller, action account.Action) error {
	grant, ok := GrantFromContext(ctx)
	if !ok || !actionAllowed(grant, "account:"+string(action)) || grant.AppID == "" {
		return a.deny(ctx, "account:"+string(action))
	}
	return nil
}

// Authorize 实现 app.Authorizer。
func (a *AppAuthorizer) Authorize(ctx context.Context, caller app.Caller, action app.Action,
	applicationID string) error {
	grant, ok := GrantFromContext(ctx)
	if !ok || applicationID != grant.AppID || !actionAllowed(grant, "app:"+string(action)) {
		return a.deny(ctx, "app:"+string(action))
	}
	return nil
}

// ApplicationScope 实现 app.Authorizer；只返回本次 grant 的应用作用域。
func (a *AppAuthorizer) ApplicationScope(ctx context.Context,
	caller app.Caller) (bool, []string, error) {
	grant, ok := GrantFromContext(ctx)
	if !ok {
		return false, nil, a.deny(ctx, "app:scope")
	}
	return false, []string{grant.AppID}, nil
}

// Authorize 实现 role.Authorizer。
func (a *RoleAuthorizer) Authorize(ctx context.Context, caller role.Caller, action role.Action,
	scopeID string) error {
	grant, ok := GrantFromContext(ctx)
	if !ok || scopeID != grant.AppID || !actionAllowed(grant, "role:"+string(action)) {
		return a.deny(ctx, "role:"+string(action))
	}
	return nil
}

// ManageableScopes 实现 role.Authorizer；只返回本次 grant 的应用作用域。
func (a *RoleAuthorizer) ManageableScopes(ctx context.Context,
	caller role.Caller) (bool, []string, error) {
	grant, ok := GrantFromContext(ctx)
	if !ok {
		return false, nil, a.deny(ctx, "role:scope")
	}
	return false, []string{grant.AppID}, nil
}

// Authorize 实现 group.Authorizer。
func (a *GroupAuthorizer) Authorize(ctx context.Context, caller group.Caller, action group.Action,
	scopeID string) error {
	grant, ok := GrantFromContext(ctx)
	if !ok || scopeID != grant.AppID || !actionAllowed(grant, "group:"+string(action)) {
		return a.deny(ctx, "group:"+string(action))
	}
	return nil
}

// ManageableScopes 实现 group.Authorizer；只返回本次 grant 的应用作用域。
func (a *GroupAuthorizer) ManageableScopes(ctx context.Context,
	caller group.Caller) (bool, []string, error) {
	grant, ok := GrantFromContext(ctx)
	if !ok {
		return false, nil, a.deny(ctx, "group:scope")
	}
	return false, []string{grant.AppID}, nil
}

// Authorize 实现 permission.Authorizer。
func (a *PermissionAuthorizer) Authorize(ctx context.Context, caller permission.Caller,
	action permission.Action, scopeID string) error {
	grant, ok := GrantFromContext(ctx)
	if !ok || scopeID != grant.AppID || !actionAllowed(grant, "permission:"+string(action)) {
		return a.deny(ctx, "permission:"+string(action))
	}
	return nil
}

// ManageableScopes 实现 permission.Authorizer；只返回本次 grant 的应用作用域。
func (a *PermissionAuthorizer) ManageableScopes(ctx context.Context,
	caller permission.Caller) (bool, []string, error) {
	grant, ok := GrantFromContext(ctx)
	if !ok {
		return false, nil, a.deny(ctx, "permission:scope")
	}
	return false, []string{grant.AppID}, nil
}

// actionsForOperation 把托管操作映射到允许触发的既有服务动作。服务层只会在
// 托管层已判权后执行本操作对应的调用，因此映射必须最小化（不授予额外动作）。
func actionsForOperation(operationID string) []string {
	switch operationID {
	case OpApplicationGet:
		return []string{"app:" + string(app.ActionGetApplication),
			"app:" + string(app.ActionGetApplicationMember)}
	case OpMembersList:
		return []string{"app:" + string(app.ActionListApplicationMembers), "account:" + string(account.ActionGetUser)}
	case OpMembersGet:
		return []string{"app:" + string(app.ActionGetApplicationMember), "account:" + string(account.ActionGetUser)}
	case OpMembersUpdateProfile:
		return []string{"app:" + string(app.ActionUpdateApplicationMemberProfile), "app:" + string(app.ActionGetApplicationMember)}
	case OpMembersDisable:
		return []string{"app:" + string(app.ActionDisableApplicationMember), "app:" + string(app.ActionGetApplicationMember)}
	case OpMembersEnable:
		return []string{"app:" + string(app.ActionEnableApplicationMember), "app:" + string(app.ActionGetApplicationMember)}
	case OpMembersRemove:
		return []string{"app:" + string(app.ActionRemoveApplicationMember), "app:" + string(app.ActionGetApplicationMember)}
	case OpUsersCreate:
		return []string{"account:" + string(account.ActionCreateUser), "app:" + string(app.ActionAddApplicationMember)}
	case OpGroupsList:
		return []string{"group:" + string(group.ActionListGroups)}
	case OpGroupsGet:
		return []string{"group:" + string(group.ActionGetGroup)}
	case OpGroupsCreate:
		return []string{"group:" + string(group.ActionCreateGroup)}
	case OpGroupsUpdate:
		return []string{"group:" + string(group.ActionUpdateGroup), "group:" + string(group.ActionGetGroup)}
	case OpGroupsDelete:
		return []string{"group:" + string(group.ActionDeleteGroup), "group:" + string(group.ActionGetGroup)}
	case OpGroupMembersList:
		return []string{"group:" + string(group.ActionListMembers), "group:" + string(group.ActionGetGroup)}
	case OpGroupMembersAdd:
		return []string{"group:" + string(group.ActionAddMembers), "group:" + string(group.ActionGetGroup)}
	case OpGroupMembersRemove:
		return []string{"group:" + string(group.ActionRemoveMembers), "group:" + string(group.ActionGetGroup)}
	case OpRolesList:
		return []string{"role:" + string(role.ActionListRoles)}
	case OpRolesGet:
		return []string{"role:" + string(role.ActionGetRole)}
	case OpRolesCreate:
		return []string{"role:" + string(role.ActionCreateRole)}
	case OpRolesUpdate:
		return []string{"role:" + string(role.ActionUpdateRole), "role:" + string(role.ActionGetRole)}
	case OpRolesDelete:
		return []string{"role:" + string(role.ActionDeleteRole), "role:" + string(role.ActionGetRole)}
	case OpRolePermissionsList:
		return []string{"role:" + string(role.ActionListRolePermissions), "role:" + string(role.ActionGetRole)}
	case OpRoleAssignUser:
		return []string{"role:" + string(role.ActionAssignUserRole), "role:" + string(role.ActionGetRole)}
	case OpRoleRevokeUser:
		return []string{"role:" + string(role.ActionRevokeUserRole), "role:" + string(role.ActionGetRole)}
	case OpRoleAssignGroup:
		return []string{"role:" + string(role.ActionAssignGroupRole), "role:" + string(role.ActionGetRole)}
	case OpRoleRevokeGroup:
		return []string{"role:" + string(role.ActionRevokeGroupRole), "role:" + string(role.ActionGetRole)}
	case OpRoleAssignmentsList:
		return []string{"role:" + string(role.ActionListRoleAssignments), "role:" + string(role.ActionGetRole)}
	case OpPermissionsList:
		return []string{"permission:" + string(permission.ActionListPermissions)}
	case OpPermissionsGet:
		return []string{"permission:" + string(permission.ActionGetPermission)}
	case OpPermissionsCreate:
		return []string{"permission:" + string(permission.ActionCreatePermission)}
	case OpPermissionsUpdate:
		return []string{"permission:" + string(permission.ActionUpdatePermission), "permission:" + string(permission.ActionGetPermission)}
	case OpPermissionsDelete:
		return []string{"permission:" + string(permission.ActionDeletePermission), "permission:" + string(permission.ActionGetPermission)}
	case OpPermissionsEnable:
		return []string{"permission:" + string(permission.ActionEnablePermission), "permission:" + string(permission.ActionGetPermission)}
	case OpPermissionsDisable:
		return []string{"permission:" + string(permission.ActionDisablePermission), "permission:" + string(permission.ActionGetPermission)}
	default:
		return nil
	}
}
