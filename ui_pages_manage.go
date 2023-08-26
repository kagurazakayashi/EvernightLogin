package login

// 步骤 185：业务应用管理员（应用范围）页面：我可管理的应用、应用内成员、应用内
// 角色/权限关联与分配。
//
// 与 /admin/** 的区别（安全边界）：
//   - /admin/** 全部 UIAccessManagement（系统管理员 + 强认证管理会话）；本文件路由
//     全部 UIAccessUser，供被授予应用范围权限的业务管理员在普通业务会话中管理
//     **本应用**，不提供系统用户/系统权限/应用删除/客户端凭证等系统管理能力。
//   - 页面层不实现授权：每次读/写都调用真实后端适配器（内部再经 184 的真实
//     ApplicationScope/权限引擎按目标应用重判）；菜单隐藏不是授权。
//   - 目标 app_id 只来自当前请求；后端不可见的应用统一显示“不存在或无权访问”，
//     不渲染其它应用名称/计数。
//   - 所有表单使用会话绑定 CSRF（宿主 HTTP 保护层）；写操作带 row_version/
//     expected_version，冲突显示 409 语义提示并重新加载。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// UIPageManageOptions 是步骤 185 应用管理员页面配置。
type UIPageManageOptions struct {
	// Apps 复用步骤 70 的应用管理后端（内部按应用范围判定可读/可写）。
	Apps UIAppsBackend
	// RBAC 复用步骤 69 的角色/权限后端（内部按作用范围判定）。
	RBAC UIRBACBackend
}

// UIManageApplication 是“我可管理的应用”列表项（只包含已过滤的可读应用）。
type UIManageApplication struct {
	ID           string
	Name         string
	Status       string
	ClientType   string
	CanManage    bool
	MembersReady bool
	RolesReady   bool
}

// UIManagePage 是 /manage/applications 列表数据。
type UIManagePage struct {
	Applications []UIManageApplication
	HasMore      bool
	NextOffset   int
}

// UIManageAppContext 是当前页面锁定的应用（名称来自已授权读取的应用详情）。
type UIManageAppContext struct {
	ID       string
	Name     string
	Status   string
	CanWrite bool
}

// UIManageStatus 是操作结果提示（成功/冲突），只在重定向后渲染，不含秘密。
type UIManageStatus struct {
	Code   string
	Detail string
}

// managePageHandlers 实现步骤 185 页面处理器。
type managePageHandlers struct{ options UIPageManageOptions }

// newPageManagePages 校验配置并登记路由。
func newPageManagePages(options UIPageManageOptions) (*pageManagePages, error) {
	if isNilUIValue(options.Apps) {
		return nil, errors.New("应用管理员页面缺少应用后端")
	}
	if isNilUIValue(options.RBAC) {
		return nil, errors.New("应用管理员页面缺少角色权限后端")
	}
	pages := &pageManagePages{options: options, handlers: map[string]UIPageHandler{}}
	handler := &managePageHandlers{options: options}
	routes := []UIRoute{
		{Name: "manage.apps", Method: http.MethodGet, Path: "/manage/applications",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/manage/applications"},
		{Name: "manage.members", Method: http.MethodGet, Path: "/manage/applications/members",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/manage/members"},
		{Name: "manage.members_submit", Method: http.MethodPost,
			Path: "/manage/applications/members", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/members"},
		{Name: "manage.roles", Method: http.MethodGet, Path: "/manage/applications/roles",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/manage/roles"},
		{Name: "manage.role_detail", Method: http.MethodGet,
			Path: "/manage/applications/roles/detail", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/role_detail"},
		{Name: "manage.role_state", Method: http.MethodPost,
			Path: "/manage/applications/roles/state", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/roles"},
		{Name: "manage.role_permissions", Method: http.MethodPost,
			Path: "/manage/applications/roles/permissions", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/role_detail"},
		{Name: "manage.role_assignments", Method: http.MethodGet,
			Path: "/manage/applications/roles/assignments", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/role_assignments"},
		{Name: "manage.role_assign", Method: http.MethodPost,
			Path: "/manage/applications/roles/assignments", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/role_assignments"},
		{Name: "manage.permissions", Method: http.MethodGet,
			Path: "/manage/applications/permissions", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/permissions"},
		{Name: "manage.permission_state", Method: http.MethodPost,
			Path: "/manage/applications/permissions/state", Access: UIAccessUser,
			Layout: "layout/base", Template: "page/manage/permissions"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageManagePages 是步骤 185 路由与处理器集合。
type pageManagePages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageManageOptions
}

// HandlePage 按路由分派。
func (h *managePageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.RouteName == "manage.members_submit" ||
		page.RouteName == "manage.role_state" || page.RouteName == "manage.role_permissions" ||
		page.RouteName == "manage.role_assign" || page.RouteName == "manage.permission_state" {
		return h.submit(ctx, request, page)
	}
	return h.render(ctx, request, page)
}

// render 处理 GET 页面。
func (h *managePageHandlers) render(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := page.Session.UserID
	if strings.TrimSpace(userID) == "" {
		return UIPageOutcome{StatusCode: http.StatusUnauthorized, ErrorCode: "AUTH_FAILED",
			ErrorSummary: "会话无效，请重新登录"}, nil
	}
	switch page.RouteName {
	case "manage.apps":
		return h.apps(ctx, request, page, userID)
	case "manage.members":
		app, outcome := h.requireApp(ctx, request, page, userID)
		if outcome != nil {
			return *outcome, nil
		}
		return h.members(ctx, request, page, userID, app)
	case "manage.roles":
		app, outcome := h.requireApp(ctx, request, page, userID)
		if outcome != nil {
			return *outcome, nil
		}
		return h.roles(ctx, request, page, userID, app)
	case "manage.role_detail":
		app, outcome := h.requireApp(ctx, request, page, userID)
		if outcome != nil {
			return *outcome, nil
		}
		return h.roleDetail(ctx, request, page, userID, app)
	case "manage.role_assignments":
		app, outcome := h.requireApp(ctx, request, page, userID)
		if outcome != nil {
			return *outcome, nil
		}
		return h.roleAssignments(ctx, request, page, userID, app)
	case "manage.permissions":
		app, outcome := h.requireApp(ctx, request, page, userID)
		if outcome != nil {
			return *outcome, nil
		}
		return h.permissions(ctx, request, page, userID, app)
	default:
		return UIPageOutcome{StatusCode: http.StatusNotFound, ErrorCode: "REQ_INVALID",
			ErrorSummary: "页面不存在"}, nil
	}
}

// apps 渲染“我可管理的应用”列表。
func (h *managePageHandlers) apps(ctx context.Context, request *http.Request,
	page UIPageContext, userID string) (UIPageOutcome, error) {
	pageResult, err := h.options.Apps.ListApplications(ctx, userID, UIAppQuery{
		Limit: 50, Offset: manageOffset(request.URL.Query().Get("offset"))})
	if err != nil {
		outcome := appsErrorOutcome(err, map[string]any{"status": h.status(request)}, "")
		return outcome, nil
	}
	data := UIManagePage{HasMore: pageResult.HasMore, NextOffset: pageResult.NextOffset}
	for _, application := range pageResult.Applications {
		if application.Status == "disabled" {
			continue
		}
		data.Applications = append(data.Applications, UIManageApplication{
			ID: application.ID, Name: application.Name, Status: application.Status,
			ClientType: application.ClientType,
			CanManage:  application.Capabilities.ManageMembers,
		})
	}
	return UIPageOutcome{Data: map[string]any{
		"apps": data, "status": h.status(request)}}, nil
}

// requireApp 读取并锁定当前请求的应用；无权/不存在统一拒绝且不泄露其他应用信息。
func (h *managePageHandlers) requireApp(ctx context.Context, request *http.Request,
	page UIPageContext, userID string) (UIManageAppContext, *UIPageOutcome) {
	appID := strings.TrimSpace(request.URL.Query().Get("app_id"))
	if appID == "" {
		appID = strings.TrimSpace(request.PostFormValue("app_id"))
	}
	if appID == "" {
		outcome := UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: "缺少应用标识"}
		return UIManageAppContext{}, &outcome
	}
	application, err := h.options.Apps.GetApplication(ctx, userID, appID)
	if err != nil {
		outcome := appsErrorOutcome(err, map[string]any{"status": h.status(request),
			"appID": appID}, "page.manage.app_not_found")
		return UIManageAppContext{}, &outcome
	}
	return UIManageAppContext{ID: application.ID, Name: application.Name,
		Status:   application.Status,
		CanWrite: application.Capabilities.ManageMembers}, nil
}

// members 渲染成员列表。
func (h *managePageHandlers) members(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext) (UIPageOutcome, error) {
	members, err := h.options.Apps.ListMembers(ctx, userID, app.ID,
		UIAppMemberQuery{Limit: 100, Offset: manageOffset(request.URL.Query().Get("offset"))})
	if err != nil {
		outcome := appsErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.app_not_found")
		return outcome, nil
	}
	return UIPageOutcome{Data: map[string]any{"app": app, "members": members,
		"status": h.status(request)}}, nil
}

// roles 渲染应用内角色列表。
func (h *managePageHandlers) roles(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext) (UIPageOutcome, error) {
	roles, err := h.options.RBAC.ListRoles(ctx, userID, UIRBACRoleQuery{
		ScopeID: app.ID, Limit: 100, Offset: manageOffset(request.URL.Query().Get("offset"))})
	if err != nil {
		outcome := rbacErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.app_not_found")
		return outcome, nil
	}
	return UIPageOutcome{Data: map[string]any{"app": app, "roles": roles,
		"status": h.status(request)}}, nil
}

// roleDetail 渲染角色详情与可组合权限。
func (h *managePageHandlers) roleDetail(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext) (UIPageOutcome, error) {
	roleID := strings.TrimSpace(request.URL.Query().Get("role_id"))
	detail, err := h.options.RBAC.GetRole(ctx, userID, roleID)
	if err != nil {
		outcome := rbacErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.role_not_found")
		return outcome, nil
	}
	if detail.Role.ScopeID != app.ID {
		// 角色不属于当前应用：不泄露角色信息，统一拒绝。
		return UIPageOutcome{StatusCode: http.StatusNotFound, ErrorCode: "ACCESS_DENIED",
			ErrorSummary: "角色不存在或无权访问"}, nil
	}
	return UIPageOutcome{Data: map[string]any{"app": app, "detail": detail,
		"status": h.status(request)}}, nil
}

// roleAssignments 渲染角色分配页。
func (h *managePageHandlers) roleAssignments(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext) (UIPageOutcome, error) {
	roleID := strings.TrimSpace(request.URL.Query().Get("role_id"))
	detail, err := h.options.RBAC.GetRole(ctx, userID, roleID)
	if err != nil {
		outcome := rbacErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.role_not_found")
		return outcome, nil
	}
	if detail.Role.ScopeID != app.ID {
		return UIPageOutcome{StatusCode: http.StatusNotFound, ErrorCode: "ACCESS_DENIED",
			ErrorSummary: "角色不存在或无权访问"}, nil
	}
	assignments, err := h.options.RBAC.ListAssignments(ctx, userID, roleID)
	if err != nil {
		outcome := rbacErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.role_not_found")
		return outcome, nil
	}
	return UIPageOutcome{Data: map[string]any{"app": app, "role": detail.Role,
		"assignments": assignments, "status": h.status(request)}}, nil
}

// permissions 渲染应用内权限列表。
func (h *managePageHandlers) permissions(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext) (UIPageOutcome, error) {
	permissions, err := h.options.RBAC.ListPermissions(ctx, userID,
		UIRBACPermissionQuery{ScopeID: app.ID, Limit: 100,
			Offset: manageOffset(request.URL.Query().Get("offset"))})
	if err != nil {
		outcome := rbacErrorOutcome(err, map[string]any{"app": app,
			"status": h.status(request)}, "page.manage.app_not_found")
		return outcome, nil
	}
	return UIPageOutcome{Data: map[string]any{"app": app, "permissions": permissions,
		"status": h.status(request)}}, nil
}

// submit 处理所有写操作（POST）：成员增删改态、角色启停/组合、角色分配、权限启停。
func (h *managePageHandlers) submit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := page.Session.UserID
	if strings.TrimSpace(userID) == "" {
		return UIPageOutcome{StatusCode: http.StatusUnauthorized, ErrorCode: "AUTH_FAILED",
			ErrorSummary: "会话无效，请重新登录"}, nil
	}
	form, ok := pageForm(request, page, "app_id", "action", "user_id", "role_id",
		"permission_id", "target_kind", "target_id", "expected_version", "row_version",
		"display_name", "title", "note", "enable", "confirm")
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: "表单无效或字段超出白名单"}, nil
	}
	app, outcome := h.requireApp(ctx, request, page, userID)
	if outcome != nil {
		return *outcome, nil
	}
	requestID := derivePageRequestID(page, app.ID)
	action := strings.TrimSpace(form.Get("action"))
	switch page.RouteName {
	case "manage.members_submit":
		return h.membersSubmit(ctx, request, page, userID, app, form, action, requestID)
	case "manage.role_state":
		roleID := strings.TrimSpace(form.Get("role_id"))
		enable, enableOK := manageBoolForm(form.Get("enable"))
		if !enableOK {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: "缺少启用状态"}, nil
		}
		if err := h.requireRoleScope(ctx, userID, roleID, app); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		if _, _, err := h.options.RBAC.SetRoleState(ctx, userID, roleID, enable, requestID); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		return manageRedirect("/manage/applications/roles", app.ID, "role_state_saved"), nil
	case "manage.role_permissions":
		roleID := strings.TrimSpace(form.Get("role_id"))
		permissionID := strings.TrimSpace(form.Get("permission_id"))
		add, addOK := manageBoolForm(form.Get("enable"))
		if !addOK {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: "缺少组合动作"}, nil
		}
		if err := h.requireRoleScope(ctx, userID, roleID, app); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		if _, err := h.options.RBAC.ComposeRolePermission(ctx, userID, roleID, permissionID,
			add, requestID); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		return manageRedirectRole("/manage/applications/roles/detail", app.ID, roleID,
			"role_permissions_saved"), nil
	case "manage.role_assign":
		roleID := strings.TrimSpace(form.Get("role_id"))
		targetKind := strings.TrimSpace(form.Get("target_kind"))
		targetID := strings.TrimSpace(form.Get("target_id"))
		if action != "assign" && action != "revoke" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: "未知操作"}, nil
		}
		if (targetKind != "user" && targetKind != "group") || targetID == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: "分配目标无效"}, nil
		}
		if err := h.requireRoleScope(ctx, userID, roleID, app); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		result, err := h.options.RBAC.AssignRole(ctx, userID, roleID, targetKind, targetID,
			requestID, action == "assign")
		if err != nil {
			return manageRBACWriteError(err, app), nil
		}
		_ = result
		return manageRedirectRole("/manage/applications/roles/assignments", app.ID, roleID,
			"role_assigned"), nil
	case "manage.permission_state":
		permissionID := strings.TrimSpace(form.Get("permission_id"))
		enable, enableOK := manageBoolForm(form.Get("enable"))
		if !enableOK {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
				ErrorSummary: "缺少启用状态"}, nil
		}
		detail, err := h.options.RBAC.GetPermission(ctx, userID, permissionID)
		if err != nil {
			return manageRBACWriteError(err, app), nil
		}
		if detail.Permission.ScopeID != app.ID {
			return UIPageOutcome{StatusCode: http.StatusNotFound, ErrorCode: "ACCESS_DENIED",
				ErrorSummary: "权限不存在或无权访问"}, nil
		}
		if _, _, err := h.options.RBAC.SetPermissionState(ctx, userID, permissionID, enable,
			requestID); err != nil {
			return manageRBACWriteError(err, app), nil
		}
		return manageRedirect("/manage/applications/permissions", app.ID,
			"permission_state_saved"), nil
	default:
		return UIPageOutcome{StatusCode: http.StatusNotFound, ErrorCode: "REQ_INVALID",
			ErrorSummary: "未知操作"}, nil
	}
}

// membersSubmit 处理成员增删/启停。
func (h *managePageHandlers) membersSubmit(ctx context.Context, request *http.Request,
	page UIPageContext, userID string, app UIManageAppContext, form url.Values,
	action, requestID string) (UIPageOutcome, error) {
	targetUserID := strings.TrimSpace(form.Get("user_id"))
	rowVersion, _ := strconv.ParseInt(strings.TrimSpace(form.Get("row_version")), 10, 64)
	switch action {
	case "add":
		profile := UIAppMemberProfile{DisplayName: strings.TrimSpace(form.Get("display_name")),
			Title: strings.TrimSpace(form.Get("title")), Note: strings.TrimSpace(form.Get("note"))}
		if _, err := h.options.Apps.AddMember(ctx, userID, app.ID, targetUserID, profile,
			requestID); err != nil {
			return appsErrorOutcome(err, map[string]any{"app": app}, ""), nil
		}
		return manageRedirect("/manage/applications/members", app.ID, "member_added"), nil
	case "enable", "disable":
		if _, _, err := h.options.Apps.SetMemberState(ctx, userID, app.ID, targetUserID,
			action == "enable", rowVersion, requestID); err != nil {
			return appsErrorOutcome(err, map[string]any{"app": app}, ""), nil
		}
		return manageRedirect("/manage/applications/members", app.ID,
			"member_"+action+"d"), nil
	case "remove":
		if err := h.options.Apps.RemoveMember(ctx, userID, app.ID, targetUserID, rowVersion,
			requestID); err != nil {
			return appsErrorOutcome(err, map[string]any{"app": app}, ""), nil
		}
		return manageRedirect("/manage/applications/members", app.ID, "member_removed"), nil
	default:
		return UIPageOutcome{StatusCode: http.StatusBadRequest, ErrorCode: "REQ_INVALID",
			ErrorSummary: "未知成员操作"}, nil
	}
}

// requireRoleScope 复核角色属于当前应用（页面层提前拒绝，领域服务仍会再次判定）。
func (h *managePageHandlers) requireRoleScope(ctx context.Context, userID, roleID string,
	app UIManageAppContext) error {
	if strings.TrimSpace(roleID) == "" {
		return errors.New("缺少角色标识")
	}
	detail, err := h.options.RBAC.GetRole(ctx, userID, roleID)
	if err != nil {
		return err
	}
	if detail.Role.ScopeID != app.ID {
		return errors.New("角色不属于当前应用")
	}
	return nil
}

// status 从查询串读取成功/冲突提示（只用于展示，不是数据来源）。
func (h *managePageHandlers) status(request *http.Request) *UIManageStatus {
	code := strings.TrimSpace(request.URL.Query().Get("status"))
	if code == "" {
		return nil
	}
	return &UIManageStatus{Code: code}
}

// manageOffset 解析分页偏移（非法/负数按 0）。
func manageOffset(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 || value > 10000 {
		return 0
	}
	return value
}

// manageBoolForm 解析 enable/true/false 表单值。
func manageBoolForm(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// derivePageRequestID 生成页面请求编号（只用于审计关联；领域服务仍校验格式）。
func derivePageRequestID(page UIPageContext, appID string) string {
	suffix := strings.ReplaceAll(strings.TrimSpace(appID), "-", "")
	if len(suffix) > 32 {
		suffix = suffix[:32]
	}
	if suffix == "" {
		suffix = "app"
	}
	return "req_manage_" + suffix
}

// manageRedirect 302/303 回写成功提示并回到列表。
func manageRedirect(path, appID, status string) UIPageOutcome {
	return UIPageOutcome{RedirectPath: path, RedirectQuery: url.Values{
		"app_id": {appID}, "status": {status}}}
}

// manageRedirectRole 回写角色相关页面（带 role_id）。
func manageRedirectRole(path, appID, roleID, status string) UIPageOutcome {
	return UIPageOutcome{RedirectPath: path, RedirectQuery: url.Values{
		"app_id": {appID}, "role_id": {roleID}, "status": {status}}}
}

// manageRBACWriteError 把写操作错误映射为页面错误（角色不存在/无权限统一不泄露）。
func manageRBACWriteError(err error, app UIManageAppContext) UIPageOutcome {
	return rbacErrorOutcome(err, map[string]any{"app": app}, "page.manage.role_not_found")
}
