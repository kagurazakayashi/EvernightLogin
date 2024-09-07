package serverapp

import (
	"context"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"net/http"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// buildAdminDomainRoutes 构造步骤 156 的用户/组/角色/权限/应用/客服只读管理 API
// 路由。所有读取都先经页面同源授权检查，再由领域服务以真实用户 Caller 重新判定；
// 返回脱敏视图，不包含密码、令牌、完整邮箱等秘密。
func buildAdminDomainRoutes(managed *ManagedServices, pages *Pages, gate *SecurityGate) []adminapi.DomainRoute {
	if managed == nil || managed.Checker == nil {
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 16)
	add := func(method, pattern, action string,
		handler func(ctx context.Context, caller account.Caller, request *http.Request) (any, error)) {
		routes = append(routes, adminapi.DomainRoute{
			Method: method, Pattern: pattern,
			Handler: func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
				if err := managed.Checker.authorizePageAction(ctx, caller.Actor().ID, action); err != nil {
					return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Message: "无权执行该管理读取", Cause: err}
				}
				return handler(ctx, caller, request)
			},
		})
	}

	add(http.MethodGet, "users", "users.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "username", "id")
		if err != nil {
			return nil, err
		}
		searchText, searchFields, err := parseAdminListSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Account.ListUsers(ctx, caller, account.ListRequest{
			Limit: page.Limit, Offset: page.Offset,
			Status: account.Status(strings.TrimSpace(request.URL.Query().Get("status"))),
			Sort:   account.SortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: searchFields})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(account.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Users))
		for _, user := range result.Users {
			items = append(items, map[string]any{"id": user.ID, "username": user.Username,
				"nickname": user.Nickname, "status": string(user.Status), "row_version": user.RowVersion,
				"security_version": user.SecurityVersion, "created_at": user.CreatedAt,
				"updated_at": user.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	add(http.MethodGet, "users/{user_id}", "users.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		user, err := managed.Account.GetUser(ctx, caller,
			strings.TrimSpace(adminPathParam(request)))
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(account.CodeOf(e)) })
		}
		return map[string]any{"id": user.ID, "username": user.Username, "nickname": user.Nickname,
			"biography": user.Biography, "language": user.Language, "timezone": user.Timezone,
			"status": string(user.Status), "row_version": user.RowVersion,
			"security_version": user.SecurityVersion, "created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt}, nil
	})

	add(http.MethodGet, "groups", "groups.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "key")
		if err != nil {
			return nil, err
		}
		groupCaller, err := group.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Group.ListGroups(ctx, groupCaller, group.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")),
			Limit:   page.Limit, Offset: page.Offset,
			Sort: group.GroupSortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: toGroupSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(group.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Groups))
		for _, item := range result.Groups {
			items = append(items, map[string]any{"id": item.ID, "scope_id": item.ScopeID,
				"group_key": item.GroupKey, "name": item.Name, "description": item.Description,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	add(http.MethodGet, "groups/{group_id}", "groups.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		groupCaller, err := group.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		item, err := managed.Group.GetGroup(ctx, groupCaller, strings.TrimSpace(adminPathParam(request)))
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(group.CodeOf(e)) })
		}
		return map[string]any{"id": item.ID, "scope_id": item.ScopeID, "group_key": item.GroupKey,
			"name": item.Name, "description": item.Description, "created_at": item.CreatedAt,
			"updated_at": item.UpdatedAt}, nil
	})
	// 步骤 216：组成员与角色分配在数据源处分页；只返回稳定 ID/时间，不返回跨域资料。
	add(http.MethodGet, "groups/{group_id}/members", "groups.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "joined_at", "user_id")
		if err != nil {
			return nil, err
		}
		groupCaller, err := group.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.Group.ListMembers(ctx, groupCaller, group.MemberListRequest{
			GroupID: strings.TrimSpace(adminPathParam(request)),
			Limit:   page.Limit, Offset: page.Offset,
			Sort: group.MemberSortField(page.Sort), Descending: page.Descending})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(group.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Members))
		for _, item := range result.Members {
			items = append(items, map[string]any{"group_id": item.GroupID,
				"user_id": item.UserID, "joined_at": item.CreatedAt})
		}
		return page.result(items, result.HasMore), nil
	})

	add(http.MethodGet, "roles", "roles.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "key")
		if err != nil {
			return nil, err
		}
		roleCaller, err := role.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Role.ListRoles(ctx, roleCaller, role.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")),
			Limit:   page.Limit, Offset: page.Offset,
			Sort: role.SortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: toRoleSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(role.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Roles))
		for _, item := range result.Roles {
			items = append(items, map[string]any{"id": item.ID, "scope_id": item.ScopeID,
				"key": item.Key, "name": item.Name, "description": item.Description,
				"is_builtin": item.IsBuiltin, "enabled": item.Enabled,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	add(http.MethodGet, "roles/{role_id}", "roles.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		roleCaller, err := role.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		item, err := managed.Role.GetRole(ctx, roleCaller, strings.TrimSpace(adminPathParam(request)))
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(role.CodeOf(e)) })
		}
		return map[string]any{"id": item.ID, "scope_id": item.ScopeID, "key": item.Key,
			"name": item.Name, "description": item.Description, "limits": item.Limits,
			"is_builtin": item.IsBuiltin, "enabled": item.Enabled,
			"created_at": item.CreatedAt, "updated_at": item.UpdatedAt}, nil
	})
	// 步骤 216：角色分配（用户/用户组）各自分页，避免一类增长把另一类挤出结果。
	add(http.MethodGet, "roles/{role_id}/assignments", "roles.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "target_id")
		if err != nil {
			return nil, err
		}
		roleCaller, err := role.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.Role.ListRoleAssignmentsPaged(ctx, roleCaller, role.AssignmentListRequest{
			RoleID:    strings.TrimSpace(adminPathParam(request)),
			UserLimit: page.Limit, UserOffset: page.Offset,
			GroupLimit: page.Limit, GroupOffset: page.Offset,
			Sort: role.AssignmentSortField(page.Sort), Descending: page.Descending})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(role.CodeOf(e)) })
		}
		users := make([]map[string]any, 0, len(result.Users))
		for _, item := range result.Users {
			users = append(users, map[string]any{"user_id": item.UserID,
				"scope_id": item.ScopeID, "data_scope": item.DataScope,
				"assigned_by": item.AssignedBy, "assigned_at": item.CreatedAt})
		}
		groups := make([]map[string]any, 0, len(result.Groups))
		for _, item := range result.Groups {
			groups = append(groups, map[string]any{"group_id": item.GroupID,
				"scope_id": item.ScopeID, "data_scope": item.DataScope,
				"assigned_at": item.CreatedAt})
		}
		return map[string]any{"users": users, "users_has_more": result.UsersHasMore,
			"groups": groups, "groups_has_more": result.GroupsHasMore,
			"limit": page.Limit, "offset": page.Offset,
			"next_offset": page.Offset + len(users), "sort": page.Sort,
			"desc": page.Descending}, nil
	})

	add(http.MethodGet, "permissions", "permissions.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "key")
		if err != nil {
			return nil, err
		}
		permCaller, err := permission.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Permission.ListPermissions(ctx, permCaller, permission.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")),
			Limit:   page.Limit, Offset: page.Offset,
			Sort: permission.SortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: toPermissionSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(permission.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Permissions))
		for _, item := range result.Permissions {
			items = append(items, map[string]any{"id": item.ID, "key": item.Key, "name": item.Name,
				"scope_id": item.ScopeID, "enabled": item.Enabled, "root_only": item.RootOnly})
		}
		return page.result(items, result.HasMore), nil
	})

	add(http.MethodGet, "applications", "applications.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "id")
		if err != nil {
			return nil, err
		}
		appCaller, err := app.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		status := app.Status(strings.TrimSpace(request.URL.Query().Get("status")))
		if status != "" && !status.Valid() {
			return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "应用状态无效"}
		}
		includeDeleted := strings.TrimSpace(request.URL.Query().Get("include_deleted")) == "true"
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.App.ListApplications(ctx, appCaller, app.ListRequest{
			Limit: page.Limit, Offset: page.Offset, Status: status,
			Sort: app.SortField(page.Sort), Descending: page.Descending,
			IncludeDeleted: includeDeleted, Search: searchText,
			SearchFields: toApplicationSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(app.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Applications))
		for _, item := range result.Applications {
			items = append(items, map[string]any{"id": item.ID, "name": item.Name,
				"description": item.Description, "owner_user_id": item.OwnerUserID,
				"status": string(item.Status), "client_type": string(item.ClientType),
				"scope_id": item.ScopeID, "row_version": item.RowVersion,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	add(http.MethodGet, "applications/{application_id}", "applications.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		appCaller, err := app.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		item, err := managed.App.GetApplication(ctx, appCaller, strings.TrimSpace(adminPathParam(request)))
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(app.CodeOf(e)) })
		}
		return map[string]any{"id": item.ID, "name": item.Name, "description": item.Description,
			"homepage": item.Homepage, "owner_user_id": item.OwnerUserID,
			"status": string(item.Status), "client_type": string(item.ClientType),
			"scope_id": item.ScopeID, "row_version": item.RowVersion,
			"created_at": item.CreatedAt, "updated_at": item.UpdatedAt}, nil
	})
	add(http.MethodGet, "applications/{application_id}/members", "applications.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		appCaller, err := app.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		applicationID := ""
		if len(parts) >= 2 {
			applicationID = parts[len(parts)-2]
		}
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "user_id")
		if err != nil {
			return nil, err
		}
		status := app.MembershipStatus(strings.TrimSpace(request.URL.Query().Get("status")))
		if status != "" && !status.Valid() {
			return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "成员状态无效"}
		}
		searchText, searchFields, err := parseAdminListSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.App.ListApplicationMembers(ctx, appCaller, app.MemberListRequest{
			ApplicationID: applicationID, Limit: page.Limit, Offset: page.Offset,
			Status: status, Sort: app.MemberSortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: searchFields})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(app.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Members))
		for _, item := range result.Members {
			items = append(items, map[string]any{"user_id": item.UserID, "status": string(item.Status),
				"row_version": item.RowVersion,
				"created_at":  item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	// 步骤 217：应用范围的角色/用户组列表。作用范围固定为路径中的应用 ID，调用方
	// 不能通过查询参数读取系统/其他应用范围；授权仍由领域服务重新判定。
	add(http.MethodGet, "applications/{application_id}/roles", "roles.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "key")
		if err != nil {
			return nil, err
		}
		roleCaller, err := role.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		applicationID := strings.TrimSpace(adminApplicationPathParam(request))
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Role.ListRoles(ctx, roleCaller, role.ListRequest{
			ScopeID: applicationID, Limit: page.Limit, Offset: page.Offset,
			Sort: role.SortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: toRoleSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(role.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Roles))
		for _, item := range result.Roles {
			items = append(items, map[string]any{"id": item.ID, "scope_id": item.ScopeID,
				"key": item.Key, "name": item.Name, "description": item.Description,
				"is_builtin": item.IsBuiltin, "enabled": item.Enabled,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})
	add(http.MethodGet, "applications/{application_id}/groups", "groups.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		page, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "key")
		if err != nil {
			return nil, err
		}
		groupCaller, err := group.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		applicationID := strings.TrimSpace(adminApplicationPathParam(request))
		searchText, searchFields, err := parseAdminDomainSearch(request)
		if err != nil {
			return nil, err
		}
		result, err := managed.Group.ListGroups(ctx, groupCaller, group.ListRequest{
			ScopeID: applicationID, Limit: page.Limit, Offset: page.Offset,
			Sort: group.GroupSortField(page.Sort), Descending: page.Descending,
			Search: searchText, SearchFields: toGroupSearchFields(searchFields)})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(group.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Groups))
		for _, item := range result.Groups {
			items = append(items, map[string]any{"id": item.ID, "scope_id": item.ScopeID,
				"key": item.GroupKey, "name": item.Name, "description": item.Description,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return page.result(items, result.HasMore), nil
	})

	if managed.Support != nil {
		add(http.MethodGet, "support/cases", "support.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			supportCaller, err := support.UserCaller(caller.Actor().ID)
			if err != nil {
				return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
			}
			limit, offset := adminQueryPage(request)
			var statuses []support.CaseStatus
			if status := strings.TrimSpace(request.URL.Query().Get("status")); status != "" {
				statuses = append(statuses, support.CaseStatus(status))
			}
			page, err := managed.Support.ListCases(ctx, supportCaller, statuses, offset, limit)
			if err != nil {
				return nil, adminDomainError(err, func(e error) string { return string(support.CodeOf(e)) })
			}
			items := make([]map[string]any, 0, len(page.Cases))
			for _, item := range page.Cases {
				items = append(items, supportCaseJSON(item))
			}
			return map[string]any{"items": items, "has_more": page.HasMore, "next_offset": page.NextOffset}, nil
		})
		add(http.MethodGet, "support/cases/{case_id}", "support.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
			supportCaller, err := support.UserCaller(caller.Actor().ID)
			if err != nil {
				return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
			}
			view, err := managed.Support.GetCase(ctx, supportCaller, strings.TrimSpace(adminPathParam(request)))
			if err != nil {
				return nil, adminDomainError(err, func(e error) string { return string(support.CodeOf(e)) })
			}
			return supportCaseJSON(view), nil
		})
		if pages != nil && pages.Support != nil {
			// 步骤 188：独立审批/执行工作台与 CLI 的只读列表/详情（逐条服务端判权）。
			add(http.MethodGet, "support/recovery/requests", "support.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
				limit, offset := adminQueryPage(request)
				result, err := pages.Support.ListRecoveryForPage(ctx, caller.Actor().ID,
					strings.TrimSpace(request.URL.Query().Get("mode")),
					strings.TrimSpace(request.URL.Query().Get("operation")), offset, limit)
				if err != nil {
					return nil, adminDomainError(err, func(e error) string {
						if typed, ok := e.(*ui.UISupportError); ok {
							return typed.Code
						}
						return "ACCESS_DENIED"
					})
				}
				items := make([]map[string]any, 0, len(result.Items))
				for _, item := range result.Items {
					items = append(items, map[string]any{
						"request_id": item.RequestID, "support_case_id": item.SupportCaseID,
						"operation": string(item.Operation), "status": item.Status,
						"target_masked": item.TargetMasked, "created_at": item.CreatedAt,
						"expires_at": item.ExpiresAt, "my_relation": item.MyRelation,
					})
				}
				return map[string]any{"items": items, "has_more": result.HasMore,
					"next_offset": result.NextOffset}, nil
			})
			add(http.MethodGet, "support/recovery/requests/{request_id}", "support.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
				view, err := pages.Support.GetRecoveryRequest(ctx, caller.Actor().ID,
					strings.TrimSpace(adminPathParam(request)))
				if err != nil {
					return nil, adminDomainError(err, func(e error) string {
						if typed, ok := e.(*ui.UISupportError); ok {
							return typed.Code
						}
						return "ACCESS_DENIED"
					})
				}
				return map[string]any{
					"id": view.ID, "target_user_id": view.TargetUserID,
					"initiator_user_id": view.InitiatorUserID, "operation": view.Operation,
					"status": view.Status, "delivery": view.Delivery,
					"reason": view.Reason, "created_at": view.CreatedAt,
					"expires_at": view.ExpiresAt, "approval": view.Approval,
					"has_approval": view.HasApproval, "approval_id": view.ApprovalID,
					"content_digest":     view.ContentDigestHex,
					"content_consistent": view.ContentConsistent,
					"failure_reason":     view.ClosedReason,
				}, nil
			})
		}
	}
	routes = append(routes, buildAdminWriteRoutes(managed, pages)...)
	routes = append(routes, buildAdminWriteRoutesExtra(managed, pages, gate)...)
	routes = append(routes, buildAdminValidityRoutes(managed)...)
	return routes
}

// supportCaseJSON 转换脱敏客服工单视图。
func supportCaseJSON(view support.CaseView) map[string]any {
	return map[string]any{"id": view.ID, "target_user_id": view.TargetUserID,
		"target_masked_username": view.TargetMaskedUsername,
		"target_masked_email":    view.TargetMaskedEmail,
		"reason":                 view.Reason, "status": string(view.Status),
		"assignee_user_id": view.AssigneeUserID, "created_by_user_id": view.CreatedByUserID,
		"created_at": view.CreatedAt, "updated_at": view.UpdatedAt, "row_version": view.RowVersion}
}

// adminListPage 是管理列表 URL 分页参数（步骤 216 统一定义）。
type adminListPage struct {
	Limit      int
	Offset     int
	Sort       string
	Descending bool
}

// parseAdminListQuery 解析 limit/offset/sort/desc：
//   - limit 缺省 20，允许 1～100；offset 缺省 0，允许 0～1_000_000；显式非法值返回
//     REQ_INVALID（不静默截断/放大，避免调用方误以为取到了请求的页大小）；
//   - sort 缺省为空（由领域默认），显式值必须在调用方给出的白名单内；
//   - desc 接受 ""/"0"/"false" 与 "1"/"true"，其他值返回 REQ_INVALID。
//
// parseAdminListSearch 解析管理列表的可选搜索参数：search（字面子串）与
// search_fields（逗号分隔的字段白名单）。搜索文本按 internal/search 规范化
// （NFKC + Unicode 大小写折叠 + NFC），空值表示不过滤；超长/控制字符/未知字段
// （含尚未提供字段可见权限的邮箱/电话）返回 REQ_INVALID，不静默忽略或截断。
// 搜索条件必须随每次请求重发：这些列表使用 offset 分页，没有服务端游标。
func parseAdminListSearch(request *http.Request) (string, []account.UserSearchField, error) {
	searchText, err := search.NormalizeQuery(strings.TrimSpace(request.URL.Query().Get("search")))
	if err != nil {
		return "", nil, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "搜索条件无效：仅支持 64 个字符以内的用户名/昵称字面搜索", Cause: err}
	}
	rawFields := strings.TrimSpace(request.URL.Query().Get("search_fields"))
	var fields []account.UserSearchField
	if rawFields != "" {
		for _, part := range strings.Split(rawFields, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				continue
			}
			fields = append(fields, account.UserSearchField(value))
		}
	}
	normalizedFields, err := account.NormalizeUserSearchFields(fields)
	if err != nil {
		return "", nil, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "搜索字段无效：仅支持 username/nickname", Cause: err}
	}
	return searchText, normalizedFields, nil
}

func parseAdminListQuery(request *http.Request, allowedSorts ...string) (adminListPage, error) {
	page := adminListPage{Limit: 20}
	if raw := strings.TrimSpace(request.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return adminListPage{}, &adminapi.DomainError{Code: "REQ_INVALID", Message: "limit 必须在 1～100 之间"}
		}
		page.Limit = parsed
	}
	if raw := strings.TrimSpace(request.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 1_000_000 {
			return adminListPage{}, &adminapi.DomainError{Code: "REQ_INVALID", Message: "offset 必须在 0～1000000 之间"}
		}
		page.Offset = parsed
	}
	if raw := strings.TrimSpace(request.URL.Query().Get("sort")); raw != "" {
		allowed := false
		for _, candidate := range allowedSorts {
			if raw == candidate {
				allowed = true
				break
			}
		}
		if !allowed {
			return adminListPage{}, &adminapi.DomainError{Code: "REQ_INVALID", Message: "sort 不在允许的排序字段内"}
		}
		page.Sort = raw
	}
	switch strings.ToLower(strings.TrimSpace(request.URL.Query().Get("desc"))) {
	case "", "0", "false":
	case "1", "true":
		page.Descending = true
	default:
		return adminListPage{}, &adminapi.DomainError{Code: "REQ_INVALID", Message: "desc 只接受 0/1 或 false/true"}
	}
	return page, nil
}

// result 组装统一分页响应：items + has_more + 实际生效的 limit/offset/next_offset/sort。
func (p adminListPage) result(items any, hasMore bool) map[string]any {
	nextOffset := p.Offset
	if list, ok := items.([]map[string]any); ok {
		nextOffset = p.Offset + len(list)
	}
	return map[string]any{"items": items, "has_more": hasMore,
		"limit": p.Limit, "offset": p.Offset, "next_offset": nextOffset,
		"sort": p.Sort, "desc": p.Descending}
}

// adminQueryPage 解析 limit/offset，越界使用默认值（管理列表只读，不放大）。
func adminQueryPage(request *http.Request) (int, int) {
	limit, offset := 20, 0
	if raw := strings.TrimSpace(request.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if raw := strings.TrimSpace(request.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 1_000_000 {
			offset = parsed
		}
	}
	return limit, offset
}

// adminPathParam 读取 URL 最后一个非空路径段（extension 路由不做前缀解析）。
func adminPathParam(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// adminApplicationPathParam 读取 applications/{application_id}/... 路由中的应用 ID
// （倒数第二段），用于应用范围的角色/用户组列表。路径不足三段（只有
// applications/{id}）时返回空字符串，避免把固定段 applications 当成应用 ID；
// 非法应用 ID 最终仍由领域服务按 REQ_INVALID/ACCESS_DENIED 拒绝。
func adminApplicationPathParam(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	applicationID := parts[len(parts)-2]
	if applicationID == "applications" {
		return ""
	}
	return applicationID
}

// adminDomainError 把领域错误映射为 adminapi 稳定错误。未识别错误只返回
// INTERNAL_ERROR，不暴露底层细节。
func adminDomainError(err error, codeOf func(error) string) error {
	if err == nil {
		return nil
	}
	code := codeOf(err)
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &adminapi.DomainError{Code: code, Cause: err}
}
