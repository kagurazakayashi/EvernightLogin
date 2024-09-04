package app

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"strings"
)

// CreateRole 在系统或应用范围登记角色（创建不授予任何权限）。
func (f *adminFacade) CreateRole(ctx context.Context,
	req AdminCreateRoleRequest) (AdminRole, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRole{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRole{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRole{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRole{}, err
	}

	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = req.Name
	}
	limits := strings.TrimSpace(req.Limits)
	if limits == "" {
		limits = defaultAdminRoleLimits
	}
	created, err := managed.Role.CreateRole(ctx, caller, role.CreateRequest{
		ScopeID: req.ScopeID, Key: req.Key, Name: req.Name, Description: description,
		Limits: limits,
	})
	if err != nil {
		return AdminRole{}, call.domainError("创建角色失败", string(role.CodeOf(err)))
	}
	return AdminRole{ID: created.ID, ScopeID: created.ScopeID,
		ApplicationID: created.ApplicationID, Key: created.Key, Name: created.Name,
		Enabled: created.Enabled}, nil
}

// CreatePermission 在系统或应用范围登记自定义权限。
func (f *adminFacade) CreatePermission(ctx context.Context,
	req AdminCreatePermissionRequest) (AdminPermission, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermission{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return AdminPermission{}, call.configError("权限服务未装配")
	}
	caller, err := f.permissionCaller(call.identity)
	if err != nil {
		return AdminPermission{}, call.configError("权限服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermission{}, err
	}

	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = req.Name
	}
	limits := strings.TrimSpace(req.Limits)
	if limits == "" {
		limits = defaultAdminPermissionLimits
	}
	created, err := managed.Permission.CreatePermission(ctx, caller, permission.CreateRequest{
		ScopeID: req.ScopeID, Key: req.Key, Name: req.Name, Description: description,
		Limits: limits,
	})
	if err != nil {
		return AdminPermission{}, call.domainError("创建权限失败",
			string(permission.CodeOf(err)))
	}
	return AdminPermission{ID: created.ID, ScopeID: created.ScopeID, Key: created.Key,
		Name: created.Name, Enabled: created.Enabled, RootOnly: created.RootOnly}, nil
}

// AddRolePermission 向角色添加权限（敏感操作：用户主体需要真实近期再次认证；
// 委派资格在角色服务事务内复核，越权转授/自我提权由真实委派引擎拒绝）。
func (f *adminFacade) AddRolePermission(ctx context.Context,
	req AdminRolePermissionRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}

	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	approved, err := f.sensitiveContext(ctx, call.identity, "role.permission.change", "role",
		req.RoleID, map[string]string{"direction": "add", "permission_id": req.PermissionID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AddRolePermission(approved, caller, req.RoleID,
		req.PermissionID); err != nil {
		return call.roleError("为角色添加权限失败", err)
	}
	return nil
}

// GrantApplicationRole 把角色分配给用户（敏感操作；应用角色要求目标用户是该应用
// active 成员；操作者必须当前持有被转授的全部权限，否则拒绝）。
func (f *adminFacade) GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}

	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	approved, err := f.sensitiveContext(ctx, call.identity, "permission.role.assign", "user",
		req.UserID, map[string]string{"direction": "assign", "role_id": req.RoleID},
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return err
	}
	if _, err := managed.Role.AssignUserRole(approved, caller, req.RoleID, req.UserID); err != nil {
		return call.roleError("分配角色失败", err)
	}
	return nil
}

// RevokeApplicationRole 撤回角色分配（安全清理；不改变其他角色/权限）。
func (f *adminFacade) RevokeApplicationRole(ctx context.Context, req RevokeRoleRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	if _, err := managed.Role.RevokeUserRole(ctx, caller, req.RoleID, req.UserID); err != nil {
		return call.roleError("撤回角色分配失败", err)
	}
	return nil
}

// GrantDelegation 为本机受信操作者签发可转授资格（用户主体不能签发委派资格，
// 由委派服务自身强制）。资格只确定“可转授上限”，实际转授仍要当前持有权限并经
// 事务内委派检查。
func (f *adminFacade) GrantDelegation(ctx context.Context,
	req AdminDelegationGrantRequest) (AdminDelegation, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDelegation{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Delegation == nil {
		return AdminDelegation{}, call.configError("委派服务未装配")
	}
	var caller delegation.Caller
	if call.identity.local {
		caller, err = delegation.LocalBootstrapCaller(call.identity.actor.ID)
	} else {
		caller, err = delegation.UserCaller(call.identity.userID)
	}
	if err != nil {
		return AdminDelegation{}, call.configError("委派服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminDelegation{}, err
	}
	grant, err := managed.Delegation.Grant(ctx, caller, delegation.GrantRequest{
		DelegatorUserID: req.DelegatorUserID, ScopeID: req.ScopeID,
		PermissionKey: req.PermissionKey, MaxDataScope: req.MaxDataScope,
	})
	if err != nil {
		return AdminDelegation{}, call.domainError("签发委派资格失败",
			string(delegation.CodeOf(err)))
	}
	return AdminDelegation{ID: grant.ID, DelegatorUserID: grant.DelegatorUserID,
		ScopeID: grant.ScopeID, PermissionKey: grant.PermissionKey,
		GrantedBy: grant.CreatedBy.ID}, nil
}

// ListRolePermissions 读取角色当前权限组合。已授权但角色不存在时返回稳定的公开
// NotFoundError（NOT_FOUND），与角色 ID 参数非法 REQ_INVALID 区分。
func (f *adminFacade) ListRolePermissions(ctx context.Context,
	req AdminRoleRequest) ([]AdminPermission, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return nil, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return nil, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return nil, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return nil, err
	}
	summaries, err := managed.Role.ListRolePermissions(ctx, caller, req.RoleID)
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return nil, replaced
		}
		return nil, call.roleError("读取角色权限失败", err)
	}
	result := make([]AdminPermission, 0, len(summaries))
	for _, summary := range summaries {
		result = append(result, AdminPermission{ID: summary.PermissionID, Key: summary.Key,
			Name: summary.Name, ScopeID: summary.ScopeID, Enabled: summary.Enabled,
			RootOnly: summary.RootOnly})
	}
	return result, nil
}

// EffectivePermissions 查询用户在指定范围的有效权限（用户主体只能查询自己；
// 本机受信通道可查询任意主体）。已授权但目标账户不存在时返回 NotFoundError；
// 权限检查先于状态与权限数据读取。
//
// 目标为真实 root 时返回内核推导的全权限列表（只读预设目录已实现且已启用权限 +
// 数据库已启用的自定义/应用范围权限，来源 Kind="root"），不依赖普通角色分配；
// 停用/未实现权限不会出现在列表中。
func (f *adminFacade) EffectivePermissions(ctx context.Context,
	req AdminPermissionQuery) (AdminEffectivePermissions, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminEffectivePermissions{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminEffectivePermissions{}, call.configError("权限引擎未装配")
	}
	caller, err := f.authzCaller(call.identity)
	if err != nil {
		return AdminEffectivePermissions{}, call.configError("权限引擎调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminEffectivePermissions{}, err
	}
	result, err := managed.Authz.EffectivePermissions(ctx, caller, req.UserID, req.ScopeID,
		authz.ListOptions{Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, authz.ErrSubjectNotFound, "user"); ok {
			return AdminEffectivePermissions{}, replaced
		}
		return AdminEffectivePermissions{}, call.domainError("查询有效权限失败",
			string(authz.CodeOf(err)))
	}
	value := AdminEffectivePermissions{UserID: result.SubjectUserID,
		ScopeID: result.Scope.ID, DeniedCode: string(result.DeniedCode)}
	for _, item := range result.Permissions {
		value.Permissions = append(value.Permissions, AdminPermission{Key: item.Key,
			Name: item.Name, ScopeID: item.ScopeID, Enabled: true})
	}
	return value, nil
}

// CheckPermission 对用户执行一次联合权限检查（令牌/当前权限/范围交集语义由既有
// 权限引擎保证；用户主体只能检查自己，本机受信通道可检查任意主体）。
func (f *adminFacade) CheckPermission(ctx context.Context,
	req AdminPermissionCheck) (AdminPermissionDecision, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermissionDecision{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AdminPermissionDecision{}, call.configError("权限引擎未装配")
	}
	caller, err := f.authzCaller(call.identity)
	if err != nil {
		return AdminPermissionDecision{}, call.configError("权限引擎调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermissionDecision{}, err
	}
	mode := authz.Mode(req.Mode)
	if mode == "" {
		mode = authz.ModeAll
	}
	result, err := managed.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: req.UserID, ScopeID: req.ScopeID,
		Permissions: []string{req.Permission}, Mode: mode,
	})
	if err != nil {
		return AdminPermissionDecision{}, call.domainError("权限检查失败",
			string(authz.CodeOf(err)))
	}
	return AdminPermissionDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason}, nil
}

// ListGroups 分页查询用户组（作用范围筛选 + 白名单排序）。
//
// 授权与数据范围由用户组服务先行判定（只返回调用者可管理范围内的组），分页
// 在数据库查询阶段执行；非法排序字段/分页参数返回 REQ_INVALID，不静默纠正。
func (f *adminFacade) ListGroups(ctx context.Context,
	req AdminListGroupsRequest) (AdminGroupList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminGroupList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return AdminGroupList{}, call.configError("用户组服务未装配")
	}
	caller, err := f.groupCaller(call.identity)
	if err != nil {
		return AdminGroupList{}, call.configError("用户组服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminGroupList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminGroupList{}, err
	}
	result, err := managed.Group.ListGroups(ctx, caller, group.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Sort: group.GroupSortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminGroupList{}, call.domainError("查询用户组列表失败", string(group.CodeOf(err)))
	}
	groups := make([]AdminGroup, 0, len(result.Groups))
	for _, record := range result.Groups {
		groups = append(groups, AdminGroup{ID: record.ID, ScopeID: record.ScopeID,
			ApplicationID: record.ApplicationID, Key: record.GroupKey, Name: record.Name,
			Description: record.Description, CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt})
	}
	return AdminGroupList{Groups: groups, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(groups), result.HasMore)}, nil
}

// ListGroupMembers 分页查询组成员（只返回稳定用户 ID/加入时间，不携带跨域资料）。
func (f *adminFacade) ListGroupMembers(ctx context.Context,
	req AdminListGroupMembersRequest) (AdminGroupMemberList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminGroupMemberList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return AdminGroupMemberList{}, call.configError("用户组服务未装配")
	}
	caller, err := f.groupCaller(call.identity)
	if err != nil {
		return AdminGroupMemberList{}, call.configError("用户组服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminGroupMemberList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminGroupMemberList{}, err
	}
	result, err := managed.Group.ListMembers(ctx, caller, group.MemberListRequest{
		GroupID: strings.TrimSpace(req.GroupID), Limit: page.Limit, Offset: page.Offset,
		Sort: group.MemberSortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, group.ErrGroupNotFound, "group"); ok {
			return AdminGroupMemberList{}, replaced
		}
		return AdminGroupMemberList{}, call.domainError("查询组成员失败", string(group.CodeOf(err)))
	}
	members := make([]AdminGroupMember, 0, len(result.Members))
	for _, member := range result.Members {
		members = append(members, AdminGroupMember{GroupID: member.GroupID,
			UserID: member.UserID, JoinedAt: member.CreatedAt})
	}
	return AdminGroupMemberList{Members: members, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(members), result.HasMore)}, nil
}

// ListRoles 分页查询角色（作用范围/启停/内置筛选 + 白名单排序）。
func (f *adminFacade) ListRoles(ctx context.Context,
	req AdminListRolesRequest) (AdminRoleList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRoleList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRoleList{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRoleList{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRoleList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminRoleList{}, err
	}
	result, err := managed.Role.ListRoles(ctx, caller, role.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Enabled: req.Enabled, Builtin: req.Builtin,
		Sort: role.SortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminRoleList{}, call.domainError("查询角色列表失败", string(role.CodeOf(err)))
	}
	roles := make([]AdminRole, 0, len(result.Roles))
	for _, record := range result.Roles {
		roles = append(roles, AdminRole{ID: record.ID, ScopeID: record.ScopeID,
			ApplicationID: record.ApplicationID, Key: record.Key, Name: record.Name,
			Enabled: record.Enabled})
	}
	return AdminRoleList{Roles: roles, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(roles), result.HasMore)}, nil
}

// ListPermissions 分页查询权限目录（作用范围/启停筛选 + 白名单排序）。
func (f *adminFacade) ListPermissions(ctx context.Context,
	req AdminListPermissionsRequest) (AdminPermissionList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminPermissionList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Permission == nil {
		return AdminPermissionList{}, call.configError("权限目录服务未装配")
	}
	caller, err := f.permissionCaller(call.identity)
	if err != nil {
		return AdminPermissionList{}, call.configError("权限目录服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminPermissionList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminPermissionList{}, err
	}
	result, err := managed.Permission.ListPermissions(ctx, caller, permission.ListRequest{
		ScopeID: strings.TrimSpace(req.ScopeID), Limit: page.Limit, Offset: page.Offset,
		Enabled: req.Enabled, Sort: permission.SortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending})
	if err != nil {
		return AdminPermissionList{}, call.domainError("查询权限目录失败",
			string(permission.CodeOf(err)))
	}
	permissions := make([]AdminPermission, 0, len(result.Permissions))
	for _, record := range result.Permissions {
		permissions = append(permissions, AdminPermission{ID: record.ID, ScopeID: record.ScopeID,
			Key: record.Key, Name: record.Name, Enabled: record.Enabled,
			RootOnly: record.RootOnly})
	}
	return AdminPermissionList{Permissions: permissions, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(permissions), result.HasMore)}, nil
}

// ListRoleAssignments 在数据源处分页读取角色的用户/组分配；两类分配各自分页，
// 避免一类增长把另一类挤出结果。权限检查与数据范围由角色服务先于分页判定。
func (f *adminFacade) ListRoleAssignments(ctx context.Context,
	req AdminListRoleAssignmentsRequest) (AdminRoleAssignmentList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRoleAssignmentList{}, call.configError("角色服务未装配")
	}
	caller, err := f.roleCaller(call.identity)
	if err != nil {
		return AdminRoleAssignmentList{}, call.configError("角色服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminRoleAssignmentList{}, err
	}
	userPage, err := call.page(req.UserPage)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	groupPage, err := call.page(req.GroupPage)
	if err != nil {
		return AdminRoleAssignmentList{}, err
	}
	result, err := managed.Role.ListRoleAssignmentsPaged(ctx, caller, role.AssignmentListRequest{
		RoleID:    strings.TrimSpace(req.RoleID),
		UserLimit: userPage.Limit, UserOffset: userPage.Offset,
		GroupLimit: groupPage.Limit, GroupOffset: groupPage.Offset,
		Sort:       role.AssignmentSortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, role.ErrRoleNotFound, "role"); ok {
			return AdminRoleAssignmentList{}, replaced
		}
		return AdminRoleAssignmentList{}, call.roleError("查询角色分配失败", err)
	}
	users := make([]AdminRoleUserAssignment, 0, len(result.Users))
	for _, assignment := range result.Users {
		users = append(users, AdminRoleUserAssignment{UserID: assignment.UserID,
			ScopeID: assignment.ScopeID, DataScope: assignment.DataScope,
			AssignedBy: assignment.AssignedBy, AssignedAt: assignment.CreatedAt})
	}
	groups := make([]AdminRoleGroupAssignment, 0, len(result.Groups))
	for _, assignment := range result.Groups {
		groups = append(groups, AdminRoleGroupAssignment{GroupID: assignment.GroupID,
			ScopeID: assignment.ScopeID, DataScope: assignment.DataScope,
			AssignedAt: assignment.CreatedAt})
	}
	return AdminRoleAssignmentList{Users: users, UsersHasMore: result.UsersHasMore,
		UserPage: NewAdminPageInfo(userPage, len(users), result.UsersHasMore),
		Groups:   groups, GroupsHasMore: result.GroupsHasMore,
		GroupPage: NewAdminPageInfo(groupPage, len(groups), result.GroupsHasMore)}, nil
}
