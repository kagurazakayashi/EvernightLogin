// Package uiadminadapter 的步骤 69 角色/权限/委派/有效权限页面适配器。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的管理员用户 ID，
// 每次都重新构造各领域可信 Caller 并调用真实 role/permission/authz/delegation 服务；
// 管理授权、作用范围、数据范围与委派 Guard 由宿主注入的真实服务判定，本包不实现
// 权限放行、不缓存授权、不读取前端自报角色。预设差异为只读计算：默认值来自版本化
// 预设目录，当前值来自受权读取的角色/权限目录；实际“恢复预设”仍只允许受信本地/
// 系统通道执行，本适配器不提供执行入口。
package uiadminadapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// RBACOptions 是角色/权限/委派/有效权限页适配器依赖。Roles/Permissions/Access/
// Delegations 必填；Catalog 为空时使用内置预设目录（只读默认值来源）。
// ManageableScopes/ApplicationNames 是展示辅助钩子，不参与授权判定。
type RBACOptions struct {
	Roles       *role.Service
	Permissions *permission.Service
	Access      *authz.Service
	Delegations *delegation.Service
	Catalog     *preset.Catalog
	// Authorize 是宿主页面层管理动作复核（可选；nil 时依赖各领域服务自身 Authorizer，
	// 仍 fail-closed）。
	Authorize func(ctx context.Context, adminUserID, action string) error
	// ManageableScopes 由宿主按真实应用服务给出可选作用范围（可选）；为空时从当前
	// 可读取的角色/权限范围推导，并始终包含 system。
	ManageableScopes func(ctx context.Context, adminUserID string) ([]string, error)
	// ApplicationNames 返回应用显示名（可选；仅展示，不参与授权）。
	ApplicationNames func(ctx context.Context, adminUserID string) (map[string]string, error)
	// Reauth 是步骤 189 高风险权限目录动作（创建自定义权限、删除自定义权限、内置
	// 权限启停）的宿主再次认证回调。action 为 permission.create /
	// permission.delete / permission.state.builtin；target 为作用范围 ID（创建）或
	// 权限 ID；requestID 来自页面/管理 API。为 nil 时上述动作 fail-closed 拒绝，
	// 不会因为宿主漏配而放行；只读页面与自定义权限启停不受影响。
	Reauth func(ctx context.Context, adminUserID, action, target, requestID string) error
	Logger *slog.Logger
}

// RBACAdapter 实现 login.UIRBACBackend。
type RBACAdapter struct {
	opts    RBACOptions
	catalog *preset.Catalog
}

// NewRBAC 校验依赖并构造适配器。
func NewRBAC(options RBACOptions) (*RBACAdapter, error) {
	if options.Roles == nil || options.Permissions == nil || options.Access == nil ||
		options.Delegations == nil {
		return nil, fmt.Errorf("角色权限页适配器缺少必需服务")
	}
	catalog := options.Catalog
	if catalog == nil {
		catalog = preset.DefaultCatalog()
	}
	if err := catalog.Validate(); err != nil {
		return nil, fmt.Errorf("预设目录无效: %w", err)
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &RBACAdapter{opts: options, catalog: catalog}, nil
}

// 页面层复核动作名与真实权限目录键对齐：读取类使用 *.read，写入类使用
// roles.manage/permissions.manage，角色分配使用 roles.assign。宿主注入的
// Authorize 实现必须按同一权限键判定，不得使用页面自造的短名。
const (
	rbacActionRolesRead         = "roles.read"
	rbacActionRolesManage       = "roles.manage"
	rbacActionRolesAssign       = "roles.assign"
	rbacActionPermissionsRead   = "permissions.read"
	rbacActionPermissionsManage = "permissions.manage"
)

// 步骤 189：高风险权限目录动作的再次认证动作名（由页面/管理 API 适配器传给宿主
// Reauth 回调；宿主实现必须按同一名称绑定操作参数，不得使用页面自造的短名）。
const (
	rbacReauthActionPermissionCreate       = "permission.create"
	rbacReauthActionPermissionDelete       = "permission.delete"
	rbacReauthActionPermissionStateBuiltin = "permission.state.builtin"
)

// verifyReauth 调用宿主再次认证（步骤 189）。未装配即 fail-closed：高风险目录动作
// 不能因为宿主漏配回调而被当作已授权；只读页面与自定义权限启停不经过这里。
func (a *RBACAdapter) verifyReauth(ctx context.Context, adminUserID, action, target,
	requestID string) error {
	if a.opts.Reauth == nil {
		return rbacErr("REAUTH_REQUIRED")
	}
	if err := a.opts.Reauth(ctx, adminUserID, action, target, requestID); err != nil {
		return mapReauthError(err)
	}
	return nil
}

// mapReauthError 把宿主的再次认证/敏感策略错误映射为稳定公开错误码；未知错误一律
// 按需要再次认证处理（fail-closed），不泄露内部原因。
func mapReauthError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, reauth.ErrAccessDenied):
		return rbacErr("ACCESS_DENIED")
	case errors.Is(err, reauth.ErrMFARequired):
		return rbacErr("MFA_REQUIRED")
	case errors.Is(err, reauth.ErrRateLimited):
		return rbacErr("RATE_LIMITED")
	case errors.Is(err, reauth.ErrStoreUnavailable):
		return rbacErr("DB_UNAVAILABLE")
	case errors.Is(err, reauth.ErrAuditUnavailable):
		return rbacErr("AUDIT_WRITE_FAILED")
	default:
		return rbacErr("REAUTH_REQUIRED")
	}
}

// check 执行可选的页面层管理动作复核（失败即拒绝）。
func (a *RBACAdapter) check(ctx context.Context, adminUserID, action string) error {
	if adminUserID == "" || !account.ValidUserID(adminUserID) {
		return rbacErr("ACCESS_DENIED")
	}
	if a.opts.Authorize != nil {
		if err := a.opts.Authorize(ctx, adminUserID, action); err != nil {
			return rbacErr("ACCESS_DENIED")
		}
	}
	return nil
}

// appNames 读取应用展示名（失败只记日志并返回空映射，不阻断受权读取）。
func (a *RBACAdapter) appNames(ctx context.Context, adminUserID string) map[string]string {
	if a.opts.ApplicationNames == nil {
		return map[string]string{}
	}
	names, err := a.opts.ApplicationNames(ctx, adminUserID)
	if err != nil {
		a.opts.Logger.Warn("应用名称读取失败", "error_category", "ui_rbac_app_names_failed")
		return map[string]string{}
	}
	return names
}

// ListScopes 返回当前管理员可选作用范围（系统+可读取角色/权限出现的应用范围）。
func (a *RBACAdapter) ListScopes(ctx context.Context,
	adminUserID string) ([]login.UIRBACScope, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return nil, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return nil, rbacErr("ACCESS_DENIED")
	}
	seen := map[string]struct{}{"system": {}}
	if a.opts.ManageableScopes != nil {
		scopes, scopeErr := a.opts.ManageableScopes(ctx, adminUserID)
		if scopeErr != nil {
			return nil, rbacErr("ACCESS_DENIED")
		}
		for _, scopeID := range scopes {
			if trimmed := strings.TrimSpace(scopeID); trimmed != "" {
				seen[trimmed] = struct{}{}
			}
		}
	}
	// 作用范围列表只依赖 roles.read（单一功能权限）：来源为宿主可选
	// ManageableScopes（权威）与当前可读取角色出现的范围；不因缺少 permissions.read
	// 而失败，也不把权限目录读取结果当作应用范围的存在证明。
	roles, err := a.allRoles(ctx, caller, "")
	if err != nil {
		return nil, mapRBACError(err)
	}
	for _, record := range roles {
		seen[record.ScopeID] = struct{}{}
	}
	names := a.appNames(ctx, adminUserID)
	result := make([]login.UIRBACScope, 0, len(seen)+1)
	for scopeID := range seen {
		scope, parseErr := authz.ParseScope(scopeID)
		if parseErr != nil {
			continue
		}
		view := login.UIRBACScope{ScopeID: scopeID, Kind: string(scope.Kind),
			Active: true}
		if scope.Kind == authz.ScopeKindApplication {
			view.ApplicationID = scope.ApplicationID
			view.ApplicationName = names[scope.ApplicationID]
		}
		result = append(result, view)
	}
	// 稳定排序：system 最前，其余按作用范围 ID。
	sortRBACScopes(result)
	return result, nil
}

// ListRoles 列出角色（含默认/当前权限与分配数量）。
func (a *RBACAdapter) ListRoles(ctx context.Context, adminUserID string,
	query login.UIRBACRoleQuery) (login.UIRBACRolePage, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACRolePage{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACRolePage{}, rbacErr("ACCESS_DENIED")
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if query.Offset < 0 || query.Offset > role.MaxListOffset {
		return login.UIRBACRolePage{}, rbacErr("REQ_INVALID")
	}
	sortField := role.SortField(strings.TrimSpace(query.Sort))
	if sortField == "" {
		sortField = role.SortCreatedAt
	}
	if !sortField.Valid() {
		return login.UIRBACRolePage{}, rbacErr("REQ_INVALID")
	}
	result, err := a.opts.Roles.ListRoles(ctx, caller, role.ListRequest{
		ScopeID: strings.TrimSpace(query.ScopeID), Limit: limit, Offset: query.Offset,
		Enabled: query.Enabled, Sort: sortField, Descending: query.Descending})
	if err != nil {
		return login.UIRBACRolePage{}, mapRBACError(err)
	}
	names := a.appNames(ctx, adminUserID)
	page := login.UIRBACRolePage{HasMore: result.HasMore,
		NextOffset: query.Offset + len(result.Roles),
		Roles:      make([]login.UIRBACRoleView, 0, len(result.Roles))}
	for _, record := range result.Roles {
		view, viewErr := a.buildRoleView(ctx, caller, adminUserID, record, names)
		if viewErr != nil {
			return login.UIRBACRolePage{}, viewErr
		}
		page.Roles = append(page.Roles, view)
	}
	return page, nil
}

// GetRole 读取角色详情（默认/当前权限、可组合权限、分配）。
func (a *RBACAdapter) GetRole(ctx context.Context, adminUserID,
	roleID string) (login.UIRBACRoleDetail, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACRoleDetail{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACRoleDetail{}, rbacErr("ACCESS_DENIED")
	}
	record, err := a.opts.Roles.GetRole(ctx, caller, strings.TrimSpace(roleID))
	if err != nil {
		return login.UIRBACRoleDetail{}, mapRBACError(err)
	}
	names := a.appNames(ctx, adminUserID)
	view, err := a.buildRoleView(ctx, caller, adminUserID, record, names)
	if err != nil {
		return login.UIRBACRoleDetail{}, err
	}
	currentIDs := make(map[string]struct{}, len(view.CurrentPermissions))
	for _, item := range view.CurrentPermissions {
		currentIDs[item.PermissionID] = struct{}{}
	}
	allByID, detailsAvailable, err := a.permissionDetails(ctx, adminUserID, record.ScopeID)
	if err != nil {
		return login.UIRBACRoleDetail{}, err
	}
	available := make([]login.UIRBACPermissionView, 0, len(allByID))
	for _, item := range allByID {
		if item.RootOnly || !item.Enabled {
			continue
		}
		if _, exists := currentIDs[item.ID]; exists {
			continue
		}
		available = append(available, a.permissionView(item, names))
	}
	sortRBACPermissionViews(available)
	assignments, err := a.assignmentViews(ctx, caller, record.ID)
	if err != nil {
		return login.UIRBACRoleDetail{}, err
	}
	return login.UIRBACRoleDetail{Role: view, Available: available,
		Assignments:                  assignments,
		PermissionCatalogUnavailable: !detailsAvailable}, nil
}

// CreateRole 创建自定义角色（机器键/范围创建后不可变）。
func (a *RBACAdapter) CreateRole(ctx context.Context, adminUserID string,
	create login.UIRBACCreateRole, requestID string) (login.UIRBACRoleView, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesManage); err != nil {
		return login.UIRBACRoleView{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACRoleView{}, rbacErr("ACCESS_DENIED")
	}
	created, err := a.opts.Roles.CreateRole(ctx, caller, role.CreateRequest{
		ScopeID: strings.TrimSpace(create.ScopeID), Key: strings.TrimSpace(create.Key),
		Name: strings.TrimSpace(create.Name), Description: strings.TrimSpace(create.Description),
		Limits: strings.TrimSpace(create.Limits)})
	if err != nil {
		return login.UIRBACRoleView{}, mapRBACError(err)
	}
	return a.buildRoleView(ctx, caller, adminUserID, created, a.appNames(ctx, adminUserID))
}

// UpdateRole 修改角色直白名称/说明/明确限制（机器键/范围不可改）。
func (a *RBACAdapter) UpdateRole(ctx context.Context, adminUserID, roleID string,
	change login.UIRBACTextChange, requestID string) (login.UIRBACRoleView, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesManage); err != nil {
		return login.UIRBACRoleView{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACRoleView{}, rbacErr("ACCESS_DENIED")
	}
	updated, err := a.opts.Roles.UpdateRole(ctx, caller, strings.TrimSpace(roleID),
		role.UpdateRequest{Name: strings.TrimSpace(change.Name),
			Description: strings.TrimSpace(change.Description),
			Limits:      strings.TrimSpace(change.Limits)})
	if err != nil {
		return login.UIRBACRoleView{}, mapRBACError(err)
	}
	return a.buildRoleView(ctx, caller, adminUserID, updated, a.appNames(ctx, adminUserID))
}

// SetRoleState 启用/停用角色并返回是否实际变化。
func (a *RBACAdapter) SetRoleState(ctx context.Context, adminUserID, roleID string,
	enable bool, requestID string) (login.UIRBACRoleView, bool, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesManage); err != nil {
		return login.UIRBACRoleView{}, false, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACRoleView{}, false, rbacErr("ACCESS_DENIED")
	}
	var updated role.Role
	var changed bool
	if enable {
		updated, changed, err = a.opts.Roles.EnableRole(ctx, caller, strings.TrimSpace(roleID))
	} else {
		updated, changed, err = a.opts.Roles.DisableRole(ctx, caller, strings.TrimSpace(roleID))
	}
	if err != nil {
		return login.UIRBACRoleView{}, false, mapRBACError(err)
	}
	view, viewErr := a.buildRoleView(ctx, caller, adminUserID, updated, a.appNames(ctx, adminUserID))
	if viewErr != nil {
		return login.UIRBACRoleView{}, false, viewErr
	}
	return view, changed, nil
}

// ComposeRolePermission 组合/移除角色权限，返回改动前后真实权限与受影响分配。
func (a *RBACAdapter) ComposeRolePermission(ctx context.Context, adminUserID, roleID,
	permissionID string, add bool, requestID string) (login.UIRBACComposeResult, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesManage); err != nil {
		return login.UIRBACComposeResult{}, err
	}
	permissionID = strings.TrimSpace(permissionID)
	if !permission.ValidPermissionID(permissionID) {
		return login.UIRBACComposeResult{}, rbacErr("REQ_INVALID")
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACComposeResult{}, rbacErr("ACCESS_DENIED")
	}
	record, err := a.opts.Roles.GetRole(ctx, caller, strings.TrimSpace(roleID))
	if err != nil {
		return login.UIRBACComposeResult{}, mapRBACError(err)
	}
	names := a.appNames(ctx, adminUserID)
	before, err := a.rolePermissionViews(ctx, caller, adminUserID, record, names)
	if err != nil {
		return login.UIRBACComposeResult{}, err
	}
	assignments, err := a.assignmentViews(ctx, caller, record.ID)
	if err != nil {
		return login.UIRBACComposeResult{}, err
	}
	var changed bool
	if add {
		changed, err = a.opts.Roles.AddRolePermission(ctx, caller, record.ID, permissionID)
	} else {
		changed, err = a.opts.Roles.RemoveRolePermission(ctx, caller, record.ID, permissionID)
	}
	if err != nil {
		return login.UIRBACComposeResult{}, mapRBACError(err)
	}
	after, err := a.rolePermissionViews(ctx, caller, adminUserID, record, names)
	if err != nil {
		return login.UIRBACComposeResult{}, err
	}
	result := login.UIRBACComposeResult{Before: before, After: after,
		AffectedUsers: len(assignments.Users), AffectedGroups: len(assignments.Groups)}
	if add {
		result.Action = "add"
	} else {
		result.Action = "remove"
	}
	_ = changed
	beforeSet := map[string]login.UIRBACPermissionView{}
	for _, item := range before {
		beforeSet[item.PermissionID] = item
	}
	afterSet := map[string]login.UIRBACPermissionView{}
	for _, item := range after {
		afterSet[item.PermissionID] = item
	}
	for id, item := range afterSet {
		if _, exists := beforeSet[id]; !exists {
			result.Added = append(result.Added, item)
		}
	}
	for id, item := range beforeSet {
		if _, exists := afterSet[id]; !exists {
			result.Removed = append(result.Removed, item)
		}
	}
	return result, nil
}

// ListAssignments 读取角色直接用户/用户组分配（用户组名称由有效权限页展示）。
func (a *RBACAdapter) ListAssignments(ctx context.Context, adminUserID,
	roleID string) (login.UIRBACAssignments, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACAssignments{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACAssignments{}, rbacErr("ACCESS_DENIED")
	}
	return a.assignmentViews(ctx, caller, strings.TrimSpace(roleID))
}

// AssignRole 分配/撤回角色到实际用户或用户组（目标与自我提权由服务端 Guard 判定）。
func (a *RBACAdapter) AssignRole(ctx context.Context, adminUserID, roleID, targetKind,
	targetID, requestID string, assign bool) (login.UIRBACAssignResult, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesAssign); err != nil {
		return login.UIRBACAssignResult{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACAssignResult{}, rbacErr("ACCESS_DENIED")
	}
	targetID = strings.TrimSpace(targetID)
	result := login.UIRBACAssignResult{TargetKind: targetKind, TargetID: targetID}
	if assign {
		result.Action = "assign"
	} else {
		result.Action = "revoke"
	}
	switch targetKind {
	case "user":
		if !account.ValidUserID(targetID) {
			return login.UIRBACAssignResult{}, rbacErr("REQ_INVALID")
		}
		if assign {
			result.Changed, err = a.opts.Roles.AssignUserRole(ctx, caller,
				strings.TrimSpace(roleID), targetID)
		} else {
			result.Changed, err = a.opts.Roles.RevokeUserRole(ctx, caller,
				strings.TrimSpace(roleID), targetID)
		}
	case "group":
		if !validRBACGroupID(targetID) {
			return login.UIRBACAssignResult{}, rbacErr("REQ_INVALID")
		}
		if assign {
			result.Changed, err = a.opts.Roles.AssignGroupRole(ctx, caller,
				strings.TrimSpace(roleID), targetID)
		} else {
			result.Changed, err = a.opts.Roles.RevokeGroupRole(ctx, caller,
				strings.TrimSpace(roleID), targetID)
		}
	default:
		return login.UIRBACAssignResult{}, rbacErr("REQ_INVALID")
	}
	if err != nil {
		return login.UIRBACAssignResult{}, mapRBACError(err)
	}
	// 数据范围来自真实分配记录（服务端当前不接受页面自定义数据范围）。
	assignments, assignErr := a.assignmentViews(ctx, caller, strings.TrimSpace(roleID))
	if assignErr == nil {
		for _, item := range assignments.Users {
			if item.UserID == targetID {
				result.DataScope = item.DataScope
				result.DataScopeText = item.DataScopeText
			}
		}
		for _, item := range assignments.Groups {
			if item.GroupID == targetID {
				result.DataScope = item.DataScope
				result.DataScopeText = item.DataScopeText
			}
		}
	}
	return result, nil
}

// ListPermissions 列出权限目录（应用同名权限带应用上下文）。
func (a *RBACAdapter) ListPermissions(ctx context.Context, adminUserID string,
	query login.UIRBACPermissionQuery) (login.UIRBACPermissionPage, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsRead); err != nil {
		return login.UIRBACPermissionPage{}, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionPage{}, rbacErr("ACCESS_DENIED")
	}
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if query.Offset < 0 || query.Offset > permission.MaxListOffset {
		return login.UIRBACPermissionPage{}, rbacErr("REQ_INVALID")
	}
	sortField := permission.SortField(strings.TrimSpace(query.Sort))
	if sortField == "" {
		sortField = permission.SortCreatedAt
	}
	if !sortField.Valid() {
		return login.UIRBACPermissionPage{}, rbacErr("REQ_INVALID")
	}
	result, err := a.opts.Permissions.ListPermissions(ctx, caller, permission.ListRequest{
		ScopeID: strings.TrimSpace(query.ScopeID), Limit: limit, Offset: query.Offset,
		Enabled: query.Enabled, Sort: sortField, Descending: query.Descending})
	if err != nil {
		return login.UIRBACPermissionPage{}, mapRBACError(err)
	}
	names := a.appNames(ctx, adminUserID)
	page := login.UIRBACPermissionPage{HasMore: result.HasMore,
		NextOffset:  query.Offset + len(result.Permissions),
		Permissions: make([]login.UIRBACPermissionView, 0, len(result.Permissions))}
	for _, record := range result.Permissions {
		page.Permissions = append(page.Permissions, a.permissionView(record, names))
	}
	return page, nil
}

// GetPermission 读取权限详情（含预设默认授予角色）。
func (a *RBACAdapter) GetPermission(ctx context.Context, adminUserID,
	permissionID string) (login.UIRBACPermissionDetail, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsRead); err != nil {
		return login.UIRBACPermissionDetail{}, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionDetail{}, rbacErr("ACCESS_DENIED")
	}
	record, err := a.opts.Permissions.GetPermission(ctx, caller, strings.TrimSpace(permissionID))
	if err != nil {
		return login.UIRBACPermissionDetail{}, mapRBACError(err)
	}
	roles := []string{}
	// 默认授予角色属于系统预设目录语义：应用范围同名权限绝不能回退到系统目录，
	// 否则会把 system_admin/user_admin 等系统默认角色显示到应用权限上。
	if record.ScopeKind == permission.ScopeKindSystem {
		if definition := a.catalogPermission(record.Key); definition != nil {
			roles = append(roles, definition.DefaultRoles...)
		}
	}
	return login.UIRBACPermissionDetail{Permission: a.permissionView(record,
		a.appNames(ctx, adminUserID)), DefaultRoles: roles}, nil
}

// UpdatePermission 修改自定义权限直白名称/说明/明确限制（内置/root_only 由后端保护）。
func (a *RBACAdapter) UpdatePermission(ctx context.Context, adminUserID, permissionID string,
	change login.UIRBACTextChange, requestID string) (login.UIRBACPermissionView, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsManage); err != nil {
		return login.UIRBACPermissionView{}, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionView{}, rbacErr("ACCESS_DENIED")
	}
	updated, err := a.opts.Permissions.UpdatePermission(ctx, caller,
		strings.TrimSpace(permissionID), permission.UpdateRequest{
			Name: strings.TrimSpace(change.Name), Description: strings.TrimSpace(change.Description),
			Limits: strings.TrimSpace(change.Limits)})
	if err != nil {
		return login.UIRBACPermissionView{}, mapRBACError(err)
	}
	return a.permissionView(updated, a.appNames(ctx, adminUserID)), nil
}

// SetPermissionState 启用/停用权限并返回是否实际变化（停用即拒绝，不级联删除组合）。
//
// 步骤 189：内置权限（含 root_only）的启停属于高风险目录变更，必须先调用宿主
// 再次认证（fail-closed）；自定义权限启停不要求额外再次认证，但仍由领域服务做
// 委派资格、作用范围与审计判定。启用会让已组合该权限的角色重新生效，服务端在
// 事务内继续复核可转授范围与目标。
func (a *RBACAdapter) SetPermissionState(ctx context.Context, adminUserID, permissionID string,
	enable bool, requestID string) (login.UIRBACPermissionView, bool, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsManage); err != nil {
		return login.UIRBACPermissionView{}, false, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionView{}, false, rbacErr("ACCESS_DENIED")
	}
	id := strings.TrimSpace(permissionID)
	if !permission.ValidPermissionID(id) {
		return login.UIRBACPermissionView{}, false, rbacErr("REQ_INVALID")
	}
	// 先读取真实记录：内置/root_only 语义不能由页面自报；读取同时写真实读取审计。
	current, err := a.opts.Permissions.GetPermission(ctx, caller, id)
	if err != nil {
		return login.UIRBACPermissionView{}, false, mapRBACError(err)
	}
	if current.IsBuiltin {
		if err := a.verifyReauth(ctx, adminUserID,
			rbacReauthActionPermissionStateBuiltin, id, requestID); err != nil {
			return login.UIRBACPermissionView{}, false, err
		}
	}
	var updated permission.Permission
	var changed bool
	if enable {
		updated, changed, err = a.opts.Permissions.EnablePermission(ctx, caller, id)
	} else {
		updated, changed, err = a.opts.Permissions.DisablePermission(ctx, caller, id)
	}
	if err != nil {
		return login.UIRBACPermissionView{}, false, mapRBACError(err)
	}
	return a.permissionView(updated, a.appNames(ctx, adminUserID)), changed, nil
}

// CreatePermission 登记系统/应用自定义权限（步骤 189）。
//
// 安全边界：IsBuiltin/RootOnly 恒为 false（页面表单不是这两个字段的来源），创建
// 属于高风险目录变更，必须先通过宿主再次认证；最终作用范围、调用者资格、机器标识
// 与文本校验由真实 permission 服务判定并写关键审计。
func (a *RBACAdapter) CreatePermission(ctx context.Context, adminUserID string,
	create login.UIRBACCreatePermission, requestID string) (login.UIRBACPermissionView, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsManage); err != nil {
		return login.UIRBACPermissionView{}, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionView{}, rbacErr("ACCESS_DENIED")
	}
	scopeID := strings.TrimSpace(create.ScopeID)
	if err := a.verifyReauth(ctx, adminUserID, rbacReauthActionPermissionCreate, scopeID,
		requestID); err != nil {
		return login.UIRBACPermissionView{}, err
	}
	record, err := a.opts.Permissions.CreatePermission(ctx, caller, permission.CreateRequest{
		ScopeID: scopeID, Key: strings.TrimSpace(create.Key),
		Name:        strings.TrimSpace(create.Name),
		Description: strings.TrimSpace(create.Description),
		Limits:      strings.TrimSpace(create.Limits),
		// 页面/接口不得创建内置权限或 root_only 权限：这两项不是表单/请求字段。
		IsBuiltin: false, RootOnly: false,
	})
	if err != nil {
		return login.UIRBACPermissionView{}, mapRBACError(err)
	}
	return a.permissionView(record, a.appNames(ctx, adminUserID)), nil
}

// DeletePermission 删除自定义权限（步骤 189）。
//
// 内置权限永远拒绝；仍被 role_permissions 引用时由领域服务在同一事务条件删除中返回
// 冲突（不隐式级联破坏授权）；删除前必须通过宿主再次认证。读取记录仅为确定内置
// 语义与再次认证目标，最终删除仍由真实服务重新鉴权并写关键审计。
func (a *RBACAdapter) DeletePermission(ctx context.Context, adminUserID, permissionID,
	requestID string) error {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsManage); err != nil {
		return err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return rbacErr("ACCESS_DENIED")
	}
	id := strings.TrimSpace(permissionID)
	if !permission.ValidPermissionID(id) {
		return rbacErr("REQ_INVALID")
	}
	current, err := a.opts.Permissions.GetPermission(ctx, caller, id)
	if err != nil {
		return mapRBACError(err)
	}
	if current.IsBuiltin {
		return rbacErr("ACCESS_DENIED")
	}
	if err := a.verifyReauth(ctx, adminUserID, rbacReauthActionPermissionDelete, id,
		requestID); err != nil {
		return err
	}
	if err := a.opts.Permissions.DeletePermission(ctx, caller, id); err != nil {
		return mapRBACError(err)
	}
	return nil
}

// PermissionImpact 返回删除/停用影响预览（步骤 189）：引用该权限的真实角色、角色
// 启停状态与删除阻塞原因。角色列表依赖 roles.read；缺少该权限时只降级隐藏列表，不
// 影响 permissions.read 详情读取，也不改变任何写操作的授权判定。
func (a *RBACAdapter) PermissionImpact(ctx context.Context, adminUserID,
	permissionID string) (login.UIRBACPermissionImpact, error) {
	if err := a.check(ctx, adminUserID, rbacActionPermissionsRead); err != nil {
		return login.UIRBACPermissionImpact{}, err
	}
	caller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPermissionImpact{}, rbacErr("ACCESS_DENIED")
	}
	id := strings.TrimSpace(permissionID)
	if !permission.ValidPermissionID(id) {
		return login.UIRBACPermissionImpact{}, rbacErr("REQ_INVALID")
	}
	record, err := a.opts.Permissions.GetPermission(ctx, caller, id)
	if err != nil {
		return login.UIRBACPermissionImpact{}, mapRBACError(err)
	}
	names := a.appNames(ctx, adminUserID)
	impact := login.UIRBACPermissionImpact{Permission: a.permissionView(record, names)}
	if record.IsBuiltin {
		impact.DeleteBlockedReason = "内置权限不可删除；只能按规则启用或停用"
	} else {
		impact.CanDelete = true
	}
	roleCaller, err := role.UserCaller(adminUserID)
	if err != nil {
		impact.RolesUnavailableReason = "无法构造角色调用者：降级隐藏引用角色列表"
		return impact, nil
	}
	roles, err := a.allRoles(ctx, roleCaller, record.ScopeID)
	if err != nil {
		mapped := mapRBACError(err)
		var publicErr *login.UIRBACError
		if errors.As(mapped, &publicErr) && publicErr.Code == "ACCESS_DENIED" {
			impact.RolesUnavailableReason = "缺少读取角色的权限，无法列出引用该权限的角色"
			return impact, nil
		}
		return login.UIRBACPermissionImpact{}, mapped
	}
	impact.RolesAvailable = true
	referencing := make([]login.UIRBACImpactRole, 0, len(roles))
	for _, item := range roles {
		current, listErr := a.opts.Roles.ListRolePermissions(ctx, roleCaller, item.ID)
		if listErr != nil {
			mapped := mapRBACError(listErr)
			var publicErr *login.UIRBACError
			if errors.As(mapped, &publicErr) && publicErr.Code == "ACCESS_DENIED" {
				impact.RolesAvailable = false
				impact.RolesUnavailableReason = "缺少读取角色权限组合的资格，无法列出引用该权限的角色"
				return impact, nil
			}
			return login.UIRBACPermissionImpact{}, mapped
		}
		for _, summary := range current {
			if summary.PermissionID != id {
				continue
			}
			referencing = append(referencing, login.UIRBACImpactRole{
				RoleID: item.ID, RoleKey: item.Key, RoleName: item.Name,
				ScopeID: item.ScopeID, Builtin: item.IsBuiltin, Enabled: item.Enabled})
			break
		}
	}
	sortRBACImpactRoles(referencing)
	impact.ReferencingRoles = referencing
	impact.ReferencedRoleCount = len(referencing)
	if !record.IsBuiltin && len(referencing) > 0 {
		impact.CanDelete = false
		impact.DeleteBlockedReason = fmt.Sprintf("仍被 %d 个角色引用；请先在角色页解除组合后再删除",
			len(referencing))
	}
	return impact, nil
}

// DelegationView 读取当前管理员的委派资格与“当前实际可转授”的权限。
//
// 普通用户 Caller 只能读取自己的资格与可转授权限；签发/撤回只允许受信本地/系统
// 通道，页面因此只读，不提供发放入口，也不把页面确认当作转授授权。
func (a *RBACAdapter) DelegationView(ctx context.Context, adminUserID, scopeID string,
	includeRevoked bool, limit, offset int) (login.UIRBACDelegationView, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACDelegationView{}, err
	}
	caller, err := delegation.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACDelegationView{}, rbacErr("ACCESS_DENIED")
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		scopeID = delegation.ScopeSystem
	}
	kind, _, err := delegation.ParseScope(scopeID)
	if err != nil {
		return login.UIRBACDelegationView{}, rbacErr("REQ_INVALID")
	}
	if limit <= 0 || limit > delegation.MaxListLimit {
		limit = 20
	}
	if offset < 0 || offset > delegation.MaxListOffset {
		return login.UIRBACDelegationView{}, rbacErr("REQ_INVALID")
	}
	delegatable, err := a.opts.Delegations.DelegatablePermissions(ctx, caller, scopeID)
	if err != nil {
		return login.UIRBACDelegationView{}, mapRBACError(err)
	}
	grants, err := a.opts.Delegations.List(ctx, caller, delegation.ListRequest{
		IncludeRevoked: includeRevoked, Limit: limit, Offset: offset})
	if err != nil {
		return login.UIRBACDelegationView{}, mapRBACError(err)
	}
	view := login.UIRBACDelegationView{ScopeID: scopeID, ScopeKind: string(kind),
		IncludeRevoked: includeRevoked, TrustedWriteRequired: true,
		GrantsHasMore: len(grants) == limit, NextOffset: offset + len(grants),
		Delegatable: make([]login.UIRBACDelegatable, 0, len(delegatable))}
	for _, item := range delegatable {
		entry := login.UIRBACDelegatable{PermissionID: item.PermissionID, Key: item.Key,
			Name: item.Name, MaxDataScope: item.MaxDataScope,
			MaxDataScopeText: dataScopeText(item.MaxDataScope),
			AllowSelf:        item.AllowSelf}
		if item.ExpiresAt != nil {
			entry.ExpiresAt = *item.ExpiresAt
			entry.ExpiresAtSet = true
		}
		view.Delegatable = append(view.Delegatable, entry)
	}
	for _, item := range grants {
		entry := login.UIRBACGrant{ID: item.ID, DelegatorUserID: item.DelegatorUserID,
			ScopeID: item.ScopeID, PermissionKey: item.PermissionKey,
			PermissionName: item.PermissionName, MaxDataScope: item.MaxDataScope,
			MaxDataScopeText: dataScopeText(item.MaxDataScope),
			AllowSelf:        item.AllowSelf, Active: item.Active(a.now()),
			AllowedUserCount:  len(item.AllowedTargets.Users),
			AllowedGroupCount: len(item.AllowedTargets.Groups),
			CreatedAt:         item.CreatedAt}
		if item.ExpiresAt != nil {
			entry.ExpiresAt = *item.ExpiresAt
			entry.ExpiresAtSet = true
		}
		if item.RevokedAt != nil {
			entry.RevokedAt = *item.RevokedAt
			entry.RevokedAtSet = true
		}
		view.Grants = append(view.Grants, entry)
	}
	return view, nil
}

// now 返回当前时间（供委派资格有效状态展示）。
func (a *RBACAdapter) now() time.Time { return time.Now() }

// EffectivePermissions 查询主体当前实际权限、来源（直接角色/组）与数据范围。
func (a *RBACAdapter) EffectivePermissions(ctx context.Context, adminUserID, subjectUserID,
	scopeID string, limit, offset int) (login.UIRBACEffectiveView, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACEffectiveView{}, err
	}
	caller, err := authz.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACEffectiveView{}, rbacErr("ACCESS_DENIED")
	}
	if limit <= 0 || limit > authz.MaxListLimit {
		limit = 20
	}
	if offset < 0 || offset > authz.MaxListOffset {
		return login.UIRBACEffectiveView{}, rbacErr("REQ_INVALID")
	}
	result, err := a.opts.Access.EffectivePermissions(ctx, caller,
		strings.TrimSpace(subjectUserID), strings.TrimSpace(scopeID),
		authz.ListOptions{Limit: limit, Offset: offset})
	if err != nil {
		return login.UIRBACEffectiveView{}, mapRBACError(err)
	}
	view := login.UIRBACEffectiveView{SubjectUserID: result.SubjectUserID,
		ScopeID: result.Scope.ID, ScopeKind: string(result.Scope.Kind),
		AccountStatus:         string(result.AccountStatus),
		AccountStatusText:     accountStatusText(string(result.AccountStatus)),
		ApplicationStatus:     string(result.ApplicationStatus),
		ApplicationStatusText: applicationStatusText(string(result.ApplicationStatus)),
		MembershipStatus:      string(result.MembershipStatus),
		MembershipStatusText:  membershipStatusText(string(result.MembershipStatus)),
		DeniedCode:            string(result.DeniedCode),
		DeniedReason:          result.DeniedReason,
		DeniedReasonText:      deniedReasonText(result.DeniedReason),
		HasMore:               result.HasMore, NextOffset: offset + len(result.Permissions),
		SourceLimitReached: result.SourceLimitReached,
		Permissions:        make([]login.UIRBACEffectivePermission, 0, len(result.Permissions))}
	for _, item := range result.Permissions {
		entry := login.UIRBACEffectivePermission{Key: item.Key, Name: item.Name,
			ScopeID: item.ScopeID, DataScope: toUIRBACDataScope(item.DataScope)}
		for _, source := range item.Sources {
			entry.Sources = append(entry.Sources, login.UIRBACSource{
				Kind: string(source.Kind), RoleID: source.RoleID, RoleKey: source.RoleKey,
				RoleName: source.RoleName, GroupID: source.GroupID, GroupKey: source.GroupKey,
				GroupName: source.GroupName, Included: source.Included,
				ExcludedReason: excludedReasonText(source.ExcludedReason),
				DataScope:      toUIRBACDataScope(source.DataScope),
				AssignedBy:     source.AssignedBy, CreatedAt: source.CreatedAt})
		}
		view.Permissions = append(view.Permissions, entry)
	}
	return view, nil
}

// PresetDiff 只读计算“恢复预设”默认值与当前实际值的差异。
//
// 差异口径与 preset 恢复计划一致：目录角色缺失、目录默认权限缺失、角色的默认权限
// 新增/移除；目录权限缺失与停用单独计数。自定义角色/权限不在恢复范围。实际恢复
// 只允许受信通道执行，本方法不写任何状态、不签发确认令牌。
func (a *RBACAdapter) PresetDiff(ctx context.Context, adminUserID,
	scopeID string) (login.UIRBACPresetDiff, error) {
	if err := a.check(ctx, adminUserID, rbacActionRolesRead); err != nil {
		return login.UIRBACPresetDiff{}, err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return login.UIRBACPresetDiff{}, rbacErr("ACCESS_DENIED")
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		scopeID = preset.ScopeSystem
	}
	kind, _, err := preset.ParseScope(scopeID)
	if err != nil {
		return login.UIRBACPresetDiff{}, rbacErr("REQ_INVALID")
	}
	names := a.appNames(ctx, adminUserID)
	diff := login.UIRBACPresetDiff{CatalogVersion: a.catalog.Version, ScopeID: scopeID,
		ScopeKind: string(kind), Available: true, ExecutionRestricted: true}
	definitions := []preset.PermissionDefinition{}
	templates := a.catalog.Roles
	if kind == preset.ScopeKindApplication {
		templates = a.catalog.ApplicationRoles
	} else {
		definitions = a.catalog.Permissions
	}
	allPermissions, err := a.allPermissions(ctx, adminUserID, scopeID)
	if err != nil {
		diff.Available = false
		diff.UnavailableReason = "无法读取当前权限目录"
		return diff, nil
	}
	permissionsByKey := make(map[string]permission.Permission, len(allPermissions))
	permissionsByID := make(map[string]permission.Permission, len(allPermissions))
	for _, item := range allPermissions {
		permissionsByKey[item.Key] = item
		permissionsByID[item.ID] = item
	}
	for _, definition := range definitions {
		if _, exists := permissionsByKey[definition.Key]; !exists {
			diff.Summary.MissingPermissions++
			continue
		}
		if !permissionsByKey[definition.Key].Enabled {
			diff.Summary.DisabledPermissions++
		}
	}
	allRoles, err := a.allRoles(ctx, caller, scopeID)
	if err != nil {
		diff.Available = false
		diff.UnavailableReason = "无法读取当前角色目录"
		return diff, nil
	}
	rolesByKey := make(map[string]role.Role, len(allRoles))
	for _, item := range allRoles {
		rolesByKey[item.Key] = item
	}
	for _, template := range templates {
		entry := login.UIRBACPresetRoleDiff{RoleKey: template.Key, Name: template.Name,
			Protected: template.Core}
		diff.Summary.RoleCount++
		record, exists := rolesByKey[template.Key]
		entry.Exists = exists
		if exists {
			entry.RoleID = record.ID
			current, listErr := a.opts.Roles.ListRolePermissions(ctx, caller, record.ID)
			if listErr != nil {
				return login.UIRBACPresetDiff{}, mapRBACError(listErr)
			}
			currentByKey := make(map[string]struct{}, len(current))
			for _, item := range current {
				currentByKey[item.Key] = struct{}{}
				view := login.UIRBACPermissionView{Key: item.Key, Name: item.Name,
					PermissionID: item.PermissionID, ScopeID: scopeID,
					Enabled: item.Enabled, RootOnly: item.RootOnly}
				entry.CurrentPermissions = append(entry.CurrentPermissions, view)
			}
			wanted := make(map[string]struct{}, len(template.DefaultPermissions))
			for _, key := range template.DefaultPermissions {
				wanted[key] = struct{}{}
				if _, present := currentByKey[key]; present {
					continue
				}
				entry.AddPermissions = append(entry.AddPermissions,
					a.presetPermissionView(scopeID, key, permissionsByKey, names))
			}
			for _, item := range current {
				if _, keep := wanted[item.Key]; keep {
					continue
				}
				view := login.UIRBACPermissionView{Key: item.Key, Name: item.Name,
					PermissionID: item.PermissionID, ScopeID: scopeID,
					Enabled: item.Enabled, RootOnly: item.RootOnly}
				entry.RemovePermissions = append(entry.RemovePermissions, view)
			}
			entry.Unchanged = len(entry.AddPermissions) == 0 &&
				len(entry.RemovePermissions) == 0
		} else {
			diff.Summary.MissingRoles++
			for _, key := range template.DefaultPermissions {
				entry.AddPermissions = append(entry.AddPermissions,
					a.presetPermissionView(scopeID, key, permissionsByKey, names))
			}
		}
		if !entry.Unchanged {
			diff.Summary.ChangedRoles++
		}
		diff.Summary.AddPermissions += len(entry.AddPermissions)
		diff.Summary.RemovePermissions += len(entry.RemovePermissions)
		diff.Roles = append(diff.Roles, entry)
	}
	sortRBACPresetRoles(diff.Roles)
	_ = permissionsByID
	return diff, nil
}

// ===== 内部构造辅助 =====

// allRoles 读取指定范围（空表示全部可管理范围）内的角色（有界分页）。
func (a *RBACAdapter) allRoles(ctx context.Context, caller role.Caller,
	scopeID string) ([]role.Role, error) {
	result := make([]role.Role, 0, 64)
	offset := 0
	for page := 0; page < 20; page++ {
		list, err := a.opts.Roles.ListRoles(ctx, caller, role.ListRequest{ScopeID: scopeID,
			Limit: 100, Offset: offset})
		if err != nil {
			return nil, err
		}
		result = append(result, list.Roles...)
		if !list.HasMore || len(list.Roles) == 0 {
			break
		}
		offset += len(list.Roles)
	}
	return result, nil
}

// permissionDetails 读取指定范围权限详情；缺少 permissions.read 时降级为
// “不可用”（不返回错误），其它存储/内部错误仍向上返回。授权语义不变：降级只影响
// 说明/默认值/可组合列表的展示，不改变任何写操作的服务端判定。
func (a *RBACAdapter) permissionDetails(ctx context.Context, adminUserID,
	scopeID string) (map[string]permission.Permission, bool, error) {
	permissions, err := a.allPermissions(ctx, adminUserID, scopeID)
	if err != nil {
		mapped := mapRBACError(err)
		var publicErr *login.UIRBACError
		if errors.As(mapped, &publicErr) && publicErr.Code == "ACCESS_DENIED" {
			return map[string]permission.Permission{}, false, nil
		}
		return nil, false, mapped
	}
	byID := make(map[string]permission.Permission, len(permissions))
	for _, item := range permissions {
		byID[item.ID] = item
	}
	return byID, true, nil
}

// allPermissions 读取指定范围全部权限（有界分页）。
func (a *RBACAdapter) allPermissions(ctx context.Context, adminUserID,
	scopeID string) ([]permission.Permission, error) {
	permissionCaller, err := permission.UserCaller(adminUserID)
	if err != nil {
		return nil, rbacErr("ACCESS_DENIED")
	}
	result := make([]permission.Permission, 0, 128)
	offset := 0
	for page := 0; page < 20; page++ {
		list, listErr := a.opts.Permissions.ListPermissions(ctx, permissionCaller,
			permission.ListRequest{ScopeID: scopeID, Limit: 100, Offset: offset})
		if listErr != nil {
			return nil, listErr
		}
		result = append(result, list.Permissions...)
		if !list.HasMore || len(list.Permissions) == 0 {
			break
		}
		offset += len(list.Permissions)
	}
	return result, nil
}

// buildRoleView 构造角色视图：默认值来自目录、当前值来自真实组合与分配。
func (a *RBACAdapter) buildRoleView(ctx context.Context, caller role.Caller,
	adminUserID string, record role.Role, names map[string]string) (login.UIRBACRoleView, error) {
	view := login.UIRBACRoleView{ID: record.ID, ScopeID: record.ScopeID,
		ScopeKind: string(record.ScopeKind), ApplicationID: record.ApplicationID,
		Key: record.Key, Name: record.Name, Description: record.Description,
		Limits: record.Limits, Builtin: record.IsBuiltin, Enabled: record.Enabled,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
	if record.ScopeKind == role.ScopeKindApplication {
		view.AppContext = names[record.ApplicationID]
	}
	current, err := a.rolePermissionViews(ctx, caller, adminUserID, record, names)
	if err != nil {
		return login.UIRBACRoleView{}, err
	}
	view.CurrentPermissions = current
	template := a.catalogRole(record.ScopeKind, record.Key)
	if template != nil {
		view.IsPreset = true
		byKey := map[string]permission.Permission{}
		for _, key := range template.DefaultPermissions {
			view.DefaultPermissions = append(view.DefaultPermissions,
				a.presetPermissionView(record.ScopeID, key, byKey, names))
		}
		view.Description = firstNonEmpty(record.Description, template.Summary)
		view.Limits = firstNonEmpty(record.Limits, template.Limits)
	}
	assignments, err := a.assignmentViews(ctx, caller, record.ID)
	if err != nil {
		return login.UIRBACRoleView{}, err
	}
	view.UserAssignments = len(assignments.Users)
	view.GroupAssignments = len(assignments.Groups)
	return view, nil
}

// rolePermissionViews 读取角色当前权限组合并解析为公开视图。
//
// 展示数据来源：同作用范围内真实权限记录的说明/限制优先；只有系统范围才用系统
// 预设目录补充“默认名称/默认生效范围”等默认值。应用范围的同名权限绝不回退系统
// 目录，缺失说明时保持“未提供”，并始终带应用上下文。
func (a *RBACAdapter) rolePermissionViews(ctx context.Context, caller role.Caller,
	adminUserID string, record role.Role, names map[string]string) ([]login.UIRBACPermissionView, error) {
	current, err := a.opts.Roles.ListRolePermissions(ctx, caller, record.ID)
	if err != nil {
		return nil, mapRBACError(err)
	}
	byID, _, err := a.permissionDetails(ctx, adminUserID, record.ScopeID)
	if err != nil {
		return nil, err
	}
	systemScope := record.ScopeKind == role.ScopeKindSystem
	result := make([]login.UIRBACPermissionView, 0, len(current))
	for _, summary := range current {
		if item, exists := byID[summary.PermissionID]; exists {
			entry := a.permissionView(item, names)
			if systemScope {
				if definition := a.catalogPermission(entry.Key); definition != nil {
					entry.DefaultName = definition.Name
					entry.DefaultScope = definition.Scope
				}
			}
			result = append(result, entry)
			continue
		}
		// 权限记录已不可读时退化为摘要（仍带范围与应用上下文，不补系统文案）。
		entry := login.UIRBACPermissionView{PermissionID: summary.PermissionID,
			ScopeID: summary.ScopeID, ScopeKind: string(record.ScopeKind),
			Key: summary.Key, Name: summary.Name,
			Enabled: summary.Enabled, RootOnly: summary.RootOnly}
		if record.ScopeKind == role.ScopeKindApplication {
			entry.ApplicationID = record.ApplicationID
			entry.AppContext = names[record.ApplicationID]
		}
		result = append(result, entry)
	}
	sortRBACPermissionViews(result)
	return result, nil
}

// assignmentViews 读取角色分配并转换为公开视图。
func (a *RBACAdapter) assignmentViews(ctx context.Context, caller role.Caller,
	roleID string) (login.UIRBACAssignments, error) {
	assignments, err := a.opts.Roles.ListRoleAssignments(ctx, caller, roleID)
	if err != nil {
		return login.UIRBACAssignments{}, mapRBACError(err)
	}
	view := login.UIRBACAssignments{Users: make([]login.UIRBACUserAssignment, 0,
		len(assignments.Users)), Groups: make([]login.UIRBACGroupAssignment, 0,
		len(assignments.Groups))}
	for _, item := range assignments.Users {
		view.Users = append(view.Users, login.UIRBACUserAssignment{UserID: item.UserID,
			DataScope: item.DataScope, DataScopeText: dataScopeText(item.DataScope),
			AssignedBy: item.AssignedBy, CreatedAt: item.CreatedAt})
	}
	for _, item := range assignments.Groups {
		view.Groups = append(view.Groups, login.UIRBACGroupAssignment{GroupID: item.GroupID,
			ScopeID: item.ScopeID, DataScope: item.DataScope,
			DataScopeText: dataScopeText(item.DataScope), CreatedAt: item.CreatedAt})
	}
	return view, nil
}

// permissionView 构造权限公开视图（应用同名权限带应用上下文与稳定 ID）。
func (a *RBACAdapter) permissionView(record permission.Permission,
	names map[string]string) login.UIRBACPermissionView {
	view := login.UIRBACPermissionView{PermissionID: record.ID, ScopeID: record.ScopeID,
		ScopeKind: string(record.ScopeKind), ApplicationID: record.ApplicationID,
		Key: record.Key, Group: record.Group, Name: record.Name,
		Description: record.Description, Limits: record.Limits,
		Builtin: record.IsBuiltin, RootOnly: record.RootOnly, Enabled: record.Enabled,
		Implemented: true, DefaultEnabled: true,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
	if record.ScopeKind == permission.ScopeKindApplication {
		view.AppContext = names[record.ApplicationID]
	}
	if definition := a.catalogPermission(record.Key); definition != nil &&
		record.ScopeKind == permission.ScopeKindSystem {
		view.DefaultName = definition.Name
		view.DefaultSummary = definition.Summary
		view.DefaultScope = definition.Scope
		view.DefaultLimits = definition.Limits
		view.DefaultEnabled = true
		view.DefaultRoles = append(view.DefaultRoles, definition.DefaultRoles...)
		view.RequiresReauth = definition.RequiresReauth
		view.Implemented = definition.Implemented
	}
	return view
}

// presetPermissionView 按目录键构造权限视图（目录键在当前目录缺失时仍可显示）。
func (a *RBACAdapter) presetPermissionView(scopeID, key string,
	permissionsByKey map[string]permission.Permission,
	names map[string]string) login.UIRBACPermissionView {
	if record, exists := permissionsByKey[key]; exists {
		return a.permissionView(record, names)
	}
	view := login.UIRBACPermissionView{Key: key, ScopeID: scopeID,
		Name: key, Enabled: true, DefaultEnabled: true}
	if scopeID != "system" {
		return view
	}
	if definition := a.catalogPermission(key); definition != nil {
		view.Name = definition.Name
		view.Description = definition.Summary
		view.Limits = definition.Limits
		view.DefaultName = definition.Name
		view.DefaultSummary = definition.Summary
		view.DefaultScope = definition.Scope
		view.DefaultLimits = definition.Limits
		view.RootOnly = definition.RootOnly
		view.RequiresReauth = definition.RequiresReauth
		view.Implemented = definition.Implemented
	}
	return view
}

// catalogPermission 返回系统预设权限定义（不存在返回 nil）。
func (a *RBACAdapter) catalogPermission(key string) *preset.PermissionDefinition {
	for index := range a.catalog.Permissions {
		if a.catalog.Permissions[index].Key == key {
			return &a.catalog.Permissions[index]
		}
	}
	return nil
}

// catalogRole 返回对应范围的预设角色模板（不存在返回 nil）。
func (a *RBACAdapter) catalogRole(kind role.ScopeKind, key string) *preset.RoleTemplate {
	templates := a.catalog.Roles
	if kind == role.ScopeKindApplication {
		templates = a.catalog.ApplicationRoles
	}
	for index := range templates {
		if templates[index].Key == key {
			return &templates[index]
		}
	}
	return nil
}

// toUIRBACDataScope 转换数据范围公开视图，并给出直白中文说明（页面不显示裸枚举）。
func toUIRBACDataScope(scope authz.DataScope) login.UIRBACDataScope {
	view := login.UIRBACDataScope{Mode: string(scope.Mode), Legacy: scope.LegacyUndefined}
	if scope.Mode == "" {
		view.Mode = string(authz.DataScopeUndefined)
	}
	view.Resources = append(view.Resources, scope.Resources...)
	switch authz.DataScopeMode(view.Mode) {
	case authz.DataScopeAll:
		view.Display = "全部数据（不限制）"
	case authz.DataScopeNone:
		view.Display = "无数据"
	case authz.DataScopeResources:
		view.Display = "仅指定资源：" + strings.Join(view.Resources, "、")
	default:
		view.Display = "未声明（资源级检查默认拒绝）"
		if view.Legacy {
			view.Display = "未声明（历史数据；资源级检查默认拒绝）"
		}
	}
	return view
}

// dataScopeText 把角色分配上的 data_scope_json 原始值转为直白中文；空/非法不直出
// JSON，按“未声明/无法解析”处理（资源级检查默认拒绝），不把未声明当作全部。
func dataScopeText(raw string) string {
	scope, err := authz.ParseDataScope(raw)
	if err != nil {
		return "未声明或无法解析（资源级检查默认拒绝）"
	}
	return toUIRBACDataScope(scope).Display
}

// accountStatusText 把账户状态枚举转为直白中文。
func accountStatusText(status string) string {
	switch status {
	case "active":
		return "正常"
	case "pending":
		return "待审核"
	case "disabled":
		return "已禁用"
	case "pending_delete":
		return "待删除"
	default:
		return "未知"
	}
}

// applicationStatusText 把应用状态枚举转为直白中文（系统范围不适用）。
func applicationStatusText(status string) string {
	switch status {
	case "active":
		return "已启用"
	case "disabled":
		return "已停用"
	default:
		return "不适用（系统范围）"
	}
}

// membershipStatusText 把应用成员状态枚举转为直白中文。
func membershipStatusText(status string) string {
	switch status {
	case "active":
		return "有效成员"
	case "disabled":
		return "成员已停用"
	default:
		return "非成员或不适用"
	}
}

// deniedReasonText 把授权引擎内部拒绝原因码转成可披露中文说明（不直出内部码）。
func deniedReasonText(reason string) string {
	switch reason {
	case "root_protected":
		return "root 账户不通过普通权限引擎推导权限"
	case "account_inactive", "account_disabled":
		return "账户当前不是正常状态"
	case "application_unknown":
		return "应用不存在或当前不可读取"
	case "application_inactive":
		return "应用已停用"
	case "membership_required":
		return "不是该应用的有效成员"
	default:
		if reason == "" {
			return ""
		}
		return "服务端按当前账户/应用/成员状态拒绝"
	}
}

// excludedReasonText 把来源排除原因码转成直白中文。
func excludedReasonText(reason string) string {
	switch reason {
	case "data_scope_invalid":
		return "数据范围声明无效"
	case "role_disabled":
		return "来源角色已停用"
	case "permission_disabled":
		return "权限已停用"
	case "root_only_permission":
		return "root_only 权限不能由普通角色生效"
	case "account_disabled":
		return "来源账户不可用"
	case "":
		return ""
	default:
		return "来源未计入当前权限"
	}
}

// validRBACGroupID 校验用户组稳定 ID 形状（grp_ + 32 位十六进制）。
func validRBACGroupID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "grp_") {
		return false
	}
	for index := 4; index < len(id); index++ {
		character := id[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// rbacErr 构造稳定公开错误。
func rbacErr(code string) error { return &login.UIRBACError{Code: code} }

// mapRBACError 把角色/权限/委派/授权领域错误映射为稳定公开错误码。
//
// 各领域 CodeOf 对“非本包错误”默认返回 INTERNAL_ERROR，因此这里先用 errors.Is
// 精确匹配各领域哨兵，再兜底 INTERNAL_ERROR；不能用领域 CodeOf 的默认值判定归属。
func mapRBACError(err error) error {
	if err == nil {
		return nil
	}
	if code := delegation.CodeOf(err); code != "" {
		return rbacErr(string(code))
	}
	switch {
	case errors.Is(err, authz.ErrInvalidRequest), errors.Is(err, authz.ErrSubjectNotFound):
		return rbacErr("REQ_INVALID")
	case errors.Is(err, authz.ErrAccessDenied), errors.Is(err, authz.ErrRootProtected):
		return rbacErr("ACCESS_DENIED")
	case errors.Is(err, authz.ErrStoreUnavailable):
		return rbacErr("DB_UNAVAILABLE")
	case errors.Is(err, role.ErrRoleNotFound), errors.Is(err, permission.ErrPermissionNotFound),
		errors.Is(err, role.ErrUserNotFound), errors.Is(err, role.ErrGroupNotFound):
		return rbacErr("CHALLENGE_INVALID")
	case errors.Is(err, role.ErrRoleKeyTaken), errors.Is(err, permission.ErrPermissionKeyTaken),
		errors.Is(err, role.ErrStateConflict), errors.Is(err, role.ErrRoleInUse),
		errors.Is(err, permission.ErrStateConflict), errors.Is(err, permission.ErrPermissionInUse):
		return rbacErr("CONFLICT")
	case errors.Is(err, role.ErrBuiltinProtected), errors.Is(err, role.ErrRootProtected),
		errors.Is(err, role.ErrRootOnlyPermission), errors.Is(err, permission.ErrBuiltinProtected),
		errors.Is(err, role.ErrAccessDenied), errors.Is(err, permission.ErrAccessDenied):
		return rbacErr("ACCESS_DENIED")
	case errors.Is(err, role.ErrUserNotMember):
		return rbacErr("APP_MEMBERSHIP_REQUIRED")
	case errors.Is(err, role.ErrUserNotEligible):
		return rbacErr("USER_DISABLED")
	case errors.Is(err, role.ErrPermissionScope), errors.Is(err, role.ErrGroupScope):
		return rbacErr("APP_SCOPE_MISMATCH")
	case errors.Is(err, role.ErrApplicationInactive), errors.Is(err, permission.ErrApplicationInactive):
		return rbacErr("CLIENT_DISABLED")
	case errors.Is(err, role.ErrPermissionInactive), errors.Is(err, role.ErrRoleDisabled):
		return rbacErr("CONFLICT")
	case errors.Is(err, role.ErrInvalidRequest), errors.Is(err, permission.ErrInvalidRequest),
		errors.Is(err, role.ErrScopeInvalid):
		return rbacErr("REQ_INVALID")
	case errors.Is(err, role.ErrStoreUnavailable), errors.Is(err, permission.ErrStoreUnavailable),
		errors.Is(err, delegation.ErrStoreUnavailable):
		return rbacErr("DB_UNAVAILABLE")
	case errors.Is(err, role.ErrAuditUnavailable), errors.Is(err, permission.ErrAuditUnavailable),
		errors.Is(err, delegation.ErrAuditUnavailable):
		return rbacErr("AUDIT_WRITE_FAILED")
	default:
		return rbacErr("INTERNAL_ERROR")
	}
}

// sortRBACImpactRoles 按角色机器键稳定排序影响预览中的引用角色。
func sortRBACImpactRoles(roles []login.UIRBACImpactRole) {
	for index := 1; index < len(roles); index++ {
		for position := index; position > 0 &&
			roles[position].RoleKey < roles[position-1].RoleKey; position-- {
			roles[position], roles[position-1] = roles[position-1], roles[position]
		}
	}
}

// sortRBACScopes 稳定排序作用范围（system 最前）。
func sortRBACScopes(scopes []login.UIRBACScope) {
	for index := 1; index < len(scopes); index++ {
		for position := index; position > 0; position-- {
			left, right := scopes[position-1], scopes[position]
			if rbacScopeLess(left, right) {
				break
			}
			scopes[position-1], scopes[position] = right, left
		}
	}
}

// rbacScopeLess 比较两个作用范围排序（system 优先，其余按 ID）。
func rbacScopeLess(left, right login.UIRBACScope) bool {
	if left.ScopeID == "system" {
		return right.ScopeID != "system"
	}
	if right.ScopeID == "system" {
		return false
	}
	return left.ScopeID < right.ScopeID
}

// sortRBACPermissionViews 按 Key 稳定排序权限视图。
func sortRBACPermissionViews(views []login.UIRBACPermissionView) {
	for index := 1; index < len(views); index++ {
		for position := index; position > 0 && views[position].Key < views[position-1].Key; position-- {
			views[position], views[position-1] = views[position-1], views[position]
		}
	}
}

// sortRBACPresetRoles 按角色机器键稳定排序预设差异。
func sortRBACPresetRoles(entries []login.UIRBACPresetRoleDiff) {
	for index := 1; index < len(entries); index++ {
		for position := index; position > 0 &&
			entries[position].RoleKey < entries[position-1].RoleKey; position-- {
			entries[position], entries[position-1] = entries[position-1], entries[position]
		}
	}
}

// DeleteRole 删除非内置角色并记录审计；内置角色与仍有引用的角色由领域服务拒绝。
func (a *RBACAdapter) DeleteRole(ctx context.Context, adminUserID, roleID,
	requestID string) error {
	if err := a.check(ctx, adminUserID, rbacActionRolesManage); err != nil {
		return err
	}
	caller, err := role.UserCaller(adminUserID)
	if err != nil {
		return rbacErr("ACCESS_DENIED")
	}
	if err := a.opts.Roles.DeleteRole(ctx, caller, strings.TrimSpace(roleID)); err != nil {
		return mapRBACError(err)
	}
	return nil
}
