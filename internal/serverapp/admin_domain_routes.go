package serverapp

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
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
		limit, offset := adminQueryPage(request)
		result, err := managed.Account.ListUsers(ctx, caller, account.ListRequest{
			Limit: limit, Offset: offset,
			Status: account.Status(strings.TrimSpace(request.URL.Query().Get("status")))})
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
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
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
		limit, offset := adminQueryPage(request)
		groupCaller, err := group.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.Group.ListGroups(ctx, groupCaller, group.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")), Limit: limit, Offset: offset})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(group.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Groups))
		for _, item := range result.Groups {
			items = append(items, map[string]any{"id": item.ID, "scope_id": item.ScopeID,
				"group_key": item.GroupKey, "name": item.Name, "description": item.Description,
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
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

	add(http.MethodGet, "roles", "roles.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		limit, offset := adminQueryPage(request)
		roleCaller, err := role.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.Role.ListRoles(ctx, roleCaller, role.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")), Limit: limit, Offset: offset})
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
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
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

	add(http.MethodGet, "permissions", "permissions.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		limit, offset := adminQueryPage(request)
		permCaller, err := permission.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.Permission.ListPermissions(ctx, permCaller, permission.ListRequest{
			ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")), Limit: limit, Offset: offset})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(permission.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Permissions))
		for _, item := range result.Permissions {
			items = append(items, map[string]any{"id": item.ID, "key": item.Key, "name": item.Name,
				"scope_id": item.ScopeID, "enabled": item.Enabled, "root_only": item.RootOnly})
		}
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
	})

	add(http.MethodGet, "applications", "applications.read", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		limit, offset := adminQueryPage(request)
		appCaller, err := app.UserCaller(caller.Actor().ID)
		if err != nil {
			return nil, &adminapi.DomainError{Code: "ACCESS_DENIED", Cause: err}
		}
		result, err := managed.App.ListApplications(ctx, appCaller, app.ListRequest{Limit: limit, Offset: offset})
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
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
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
		limit, offset := adminQueryPage(request)
		result, err := managed.App.ListApplicationMembers(ctx, appCaller, app.MemberListRequest{
			ApplicationID: applicationID, Limit: limit, Offset: offset})
		if err != nil {
			return nil, adminDomainError(err, func(e error) string { return string(app.CodeOf(e)) })
		}
		items := make([]map[string]any, 0, len(result.Members))
		for _, item := range result.Members {
			items = append(items, map[string]any{"user_id": item.UserID, "status": string(item.Status),
				"created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
		}
		return map[string]any{"items": items, "has_more": result.HasMore}, nil
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
	}
	routes = append(routes, buildAdminWriteRoutes(managed, pages)...)
	routes = append(routes, buildAdminWriteRoutesExtra(managed, pages, gate)...)
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
