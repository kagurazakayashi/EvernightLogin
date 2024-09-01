package app

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"strings"
)

// AddApplicationMember 把已有用户加入应用（需要该应用 applications.members.manage）。
func (f *adminFacade) AddApplicationMember(ctx context.Context, req AdminAddMemberRequest) error {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return err
	}
	if _, err := managed.App.AddApplicationMember(ctx, caller, app.AddMemberRequest{
		ApplicationID: req.ApplicationID, UserID: req.UserID,
	}); err != nil {
		return call.domainError("加入应用成员失败", string(app.CodeOf(err)))
	}
	return nil
}

// CreateApplication 登记应用（本机受信通道或系统范围 applications.create）。
func (f *adminFacade) CreateApplication(ctx context.Context,
	req AdminCreateApplicationRequest) (AdminApplication, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplication{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplication{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplication{}, err
	}
	owner := strings.TrimSpace(req.OwnerUserID)
	if owner == "" && !call.identity.local {
		owner = call.identity.userID
	}
	clientType := app.ClientType(strings.TrimSpace(req.ClientType))
	if clientType == "" {
		clientType = app.ClientTypeConfidential
	}
	created, err := managed.App.CreateApplication(ctx, caller, app.CreateRequest{
		Name: req.Name, Description: req.Description, OwnerUserID: owner,
		ClientType: clientType,
	})
	if err != nil {
		return AdminApplication{}, call.domainError("创建应用失败", string(app.CodeOf(err)))
	}
	return AdminApplication{ID: created.ID, Name: created.Name,
		Description: created.Description, OwnerUserID: created.OwnerUserID,
		Status: string(created.Status), RowVersion: created.RowVersion,
		CreatedAt: created.CreatedAt}, nil
}

// SetApplicationEnabled 启用或停用应用（应用启用会恢复其范围权限，由应用服务按
// 真实委派资格复核；停用不影响已有账户与角色记录）。
func (f *adminFacade) SetApplicationEnabled(ctx context.Context,
	req AdminSetApplicationEnabledRequest) (AdminApplication, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplication{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplication{}, call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplication{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplication{}, err
	}
	statusRequest := app.StatusRequest{ApplicationID: req.ApplicationID,
		ExpectedRowVersion: req.ExpectedRowVersion}
	var result app.StatusResult
	if req.Enabled {
		result, err = managed.App.EnableApplication(ctx, caller, statusRequest)
	} else {
		result, err = managed.App.DisableApplication(ctx, caller, statusRequest)
	}
	if err != nil {
		return AdminApplication{}, call.domainError("应用启停失败", string(app.CodeOf(err)))
	}
	return AdminApplication{ID: result.Application.ID, Name: result.Application.Name,
		Description: result.Application.Description,
		OwnerUserID: result.Application.OwnerUserID,
		Status:      string(result.Application.Status),
		RowVersion:  result.Application.RowVersion,
		CreatedAt:   result.Application.CreatedAt}, nil
}

// toAdminApplication 把领域应用快照投影为公开管理视图（不含客户端秘密）。
func toAdminApplication(record app.Application) AdminApplication {
	return AdminApplication{ID: record.ID, Name: record.Name, Description: record.Description,
		OwnerUserID: record.OwnerUserID, Status: string(record.Status),
		RowVersion: record.RowVersion, CreatedAt: record.CreatedAt}
}

// ListApplications 分页查询应用列表。授权与应用可见范围由应用服务先于分页判定
// （应用管理员只能看到被分配应用），门面只负责统一分页/筛选/排序参数与脱敏投影。
func (f *adminFacade) ListApplications(ctx context.Context,
	req AdminListApplicationsRequest) (AdminApplicationList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplicationList{}, call.configError("应用服务未装配")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplicationList{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplicationList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminApplicationList{}, err
	}
	status := app.Status(strings.TrimSpace(req.Status))
	if status != "" && !status.Valid() {
		return AdminApplicationList{}, call.domainError("应用状态无效", "REQ_INVALID")
	}
	result, err := managed.App.ListApplications(ctx, caller, app.ListRequest{
		Limit: page.Limit, Offset: page.Offset, Status: status,
		Sort:       app.SortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending, IncludeDeleted: req.IncludeDeleted,
		Search: req.Search, SearchFields: adminApplicationSearchFields(req.SearchFields)})
	if err != nil {
		return AdminApplicationList{}, call.domainError("查询应用列表失败", string(app.CodeOf(err)))
	}
	applications := make([]AdminApplication, 0, len(result.Applications))
	for _, record := range result.Applications {
		applications = append(applications, toAdminApplication(record))
	}
	return AdminApplicationList{Applications: applications, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(applications), result.HasMore)}, nil
}

// ListApplicationMembers 分页查询应用成员（状态筛选 + 白名单排序）。应用范围由应用
// 服务在查询中作为约束执行；一个用户属于两个应用时只返回目标应用的成员关系。
func (f *adminFacade) ListApplicationMembers(ctx context.Context,
	req AdminListApplicationMembersRequest) (AdminApplicationMemberList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminApplicationMemberList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.App == nil {
		return AdminApplicationMemberList{}, call.configError("应用服务未装配")
	}
	applicationID := strings.TrimSpace(req.ApplicationID)
	if applicationID == "" {
		return AdminApplicationMemberList{}, call.domainError("应用 ID 必填", "REQ_INVALID")
	}
	caller, err := f.appCaller(call.identity)
	if err != nil {
		return AdminApplicationMemberList{}, call.configError("应用服务调用者无效")
	}
	if caller, err = bindCaller(caller, call.requestID); err != nil {
		return AdminApplicationMemberList{}, err
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminApplicationMemberList{}, err
	}
	status := app.MembershipStatus(strings.TrimSpace(req.Status))
	if status != "" && !status.Valid() {
		return AdminApplicationMemberList{}, call.domainError("成员状态无效", "REQ_INVALID")
	}
	result, err := managed.App.ListApplicationMembers(ctx, caller, app.MemberListRequest{
		ApplicationID: applicationID, Limit: page.Limit, Offset: page.Offset,
		Status: status, Sort: app.MemberSortField(strings.TrimSpace(req.Sort)),
		Descending: req.Descending, Search: req.Search,
		SearchFields: adminUserSearchFields(req.SearchFields)})
	if err != nil {
		if replaced, ok := call.notFoundIfTargetMissing(err, app.ErrApplicationNotFound, "application"); ok {
			return AdminApplicationMemberList{}, replaced
		}
		return AdminApplicationMemberList{}, call.domainError("查询应用成员失败", string(app.CodeOf(err)))
	}
	members := make([]AdminApplicationMember, 0, len(result.Members))
	for _, member := range result.Members {
		members = append(members, AdminApplicationMember{
			ApplicationID: member.ApplicationID, UserID: member.UserID,
			Status: string(member.Status), RowVersion: member.RowVersion,
			CreatedAt: member.CreatedAt, UpdatedAt: member.UpdatedAt})
	}
	return AdminApplicationMemberList{Members: members, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(members), result.HasMore)}, nil
}

// ListApplicationRoles 分页查询指定应用范围的角色。作用范围固定为请求的应用 ID，
// 调用方不能借此读取系统或其他应用角色；授权由角色服务先于分页判定。
func (f *adminFacade) ListApplicationRoles(ctx context.Context,
	req AdminListApplicationRolesRequest) (AdminRoleList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRoleList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Role == nil {
		return AdminRoleList{}, call.configError("角色服务未装配")
	}
	applicationID := strings.TrimSpace(req.ApplicationID)
	if applicationID == "" {
		return AdminRoleList{}, call.domainError("应用 ID 必填", "REQ_INVALID")
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
		ScopeID: applicationID, Limit: page.Limit, Offset: page.Offset,
		Enabled: req.Enabled, Builtin: req.Builtin,
		Sort: role.SortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminRoleList{}, call.roleError("查询应用角色失败", err)
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

// ListApplicationGroups 分页查询指定应用范围的用户组。作用范围固定为请求的应用 ID；
// 授权由用户组服务先于分页判定。
func (f *adminFacade) ListApplicationGroups(ctx context.Context,
	req AdminListApplicationGroupsRequest) (AdminGroupList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminGroupList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Group == nil {
		return AdminGroupList{}, call.configError("用户组服务未装配")
	}
	applicationID := strings.TrimSpace(req.ApplicationID)
	if applicationID == "" {
		return AdminGroupList{}, call.domainError("应用 ID 必填", "REQ_INVALID")
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
		ScopeID: applicationID, Limit: page.Limit, Offset: page.Offset,
		Sort: group.GroupSortField(strings.TrimSpace(req.Sort)), Descending: req.Descending})
	if err != nil {
		return AdminGroupList{}, call.domainError("查询应用用户组失败", string(group.CodeOf(err)))
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

// adminApplicationSearchFields 把公开门面的字符串搜索字段转换为应用领域白名单；
// 空/未知值交给领域服务统一校验并返回 REQ_INVALID。
func adminApplicationSearchFields(fields []string) []app.ApplicationSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]app.ApplicationSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, app.ApplicationSearchField(strings.TrimSpace(field)))
	}
	return converted
}
