package ui

// 步骤 70 应用管理页处理器：所有写操作都是显式 POST + 服务端重新授权；页面把真实
// 服务返回的差异/状态/稳定错误码映射为中文说明，不渲染假开关或伪造成功。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// appsPageHandlers 实现应用管理页处理器。
type appsPageHandlers struct {
	pages *pageAppsPages
}

// HandlePage 按路由分派。
func (h *appsPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.applications":
		return h.list(ctx, request, page)
	case "admin.application_create":
		return h.create(ctx, request, page)
	case "admin.application_create.submit":
		return h.createSubmit(ctx, request, page)
	case "admin.application_profile":
		return h.profile(ctx, request, page)
	case "admin.application_profile.submit":
		return h.profileSubmit(ctx, request, page)
	case "admin.application_members":
		return h.members(ctx, request, page)
	case "admin.application_members.submit":
		return h.membersSubmit(ctx, request, page)
	case "admin.application_security":
		return h.security(ctx, request, page)
	case "admin.application_security.submit":
		return h.securitySubmit(ctx, request, page)
	case "admin.application_credentials":
		return h.credentials(ctx, request, page)
	case "admin.application_credentials.submit":
		return h.credentialsSubmit(ctx, request, page)
	case "admin.application_grants":
		return h.grants(ctx, request, page)
	case "admin.application_grants.submit":
		return h.grantsSubmit(ctx, request, page)
	case "admin.application_status":
		return h.status(ctx, request, page)
	case "admin.application_status.submit":
		return h.statusSubmit(ctx, request, page)
	case "admin.application_delete":
		return h.statusDelete(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// ===== 应用列表 =====

// list 渲染当前账户获准管理的应用（状态筛选/受控排序/HasMore 分页）。
func (h *appsPageHandlers) list(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := UIAppQuery{Status: strings.TrimSpace(request.URL.Query().Get("status")),
		Sort:       strings.TrimSpace(request.URL.Query().Get("sort")),
		Descending: request.URL.Query().Get("desc") == "1", Limit: 20}
	offset, ok := appsParseOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.list.load_failed")}, nil
	}
	query.Offset = offset
	result, err := h.pages.options.Backend.ListApplications(ctx, page.Session.UserID, query)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.list.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{
		"applications": result.Applications, "hasMore": result.HasMore,
		"nextOffset": result.NextOffset, "status": query.Status, "sort": query.Sort,
		"desc": request.URL.Query().Get("desc"), "offset": offset,
		"canCreate": h.canCreate(ctx, page.Session.UserID),
	}}, nil
}

// canCreate 报告当前后端是否提供真实的新建应用能力；页面仅据此显示入口，
// 服务端每次 POST 仍重新授权。能力查询失败按不可用处理，不显示按钮。
func (h *appsPageHandlers) canCreate(ctx context.Context, adminID string) bool {
	backend, ok := h.pages.options.Backend.(UIAppsCreateBackend)
	if !ok {
		return false
	}
	allowed, err := backend.CanCreateApplication(ctx, adminID)
	return err == nil && allowed
}

// ===== 新建应用 =====

// create 渲染新建应用表单；只有后端支持新建时路由才会注册。
func (h *appsPageHandlers) create(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if !h.canCreate(ctx, page.Session.UserID) {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.applications.create.unavailable")}, nil
	}
	return UIPageOutcome{Data: map[string]any{
		"form": UIApplicationCreate{ClientType: "confidential"}}}, nil
}

// createSubmit 提交应用新建白名单；ID/状态/行版本由服务端生成，页面不伪造成功。
func (h *appsPageHandlers) createSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	backend, ok := h.pages.options.Backend.(UIAppsCreateBackend)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.applications.create.unavailable")}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"name",
		"description", "icon_ref", "homepage", "owner_user_id", "contact_info",
		"client_type"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"form": UIApplicationCreate{ClientType: "confidential"}},
			ErrorSummary: text("page.admin.applications.create.invalid")}, nil
	}
	create := UIApplicationCreate{
		Name:        strings.TrimSpace(form.Get("name")),
		Description: strings.TrimSpace(form.Get("description")),
		IconRef:     strings.TrimSpace(form.Get("icon_ref")),
		Homepage:    strings.TrimSpace(form.Get("homepage")),
		OwnerUserID: strings.TrimSpace(form.Get("owner_user_id")),
		ContactInfo: strings.TrimSpace(form.Get("contact_info")),
		ClientType:  strings.TrimSpace(form.Get("client_type")),
	}
	if create.Name == "" ||
		(create.ClientType != "confidential" && create.ClientType != "public") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data: map[string]any{"form": create}, ErrorSummary: text(
				"page.admin.applications.create.invalid")}, nil
	}
	created, err := backend.CreateApplication(ctx, page.Session.UserID, create,
		page.RequestID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"form": create},
			"page.admin.applications.create.create_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"created": created,
		"status": "created", "form": create}}, nil
}

// ===== 资料 =====

// profile 渲染当前应用资料与只读身份。
func (h *appsPageHandlers) profile(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.profile.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": application,
		"status": strings.TrimSpace(request.URL.Query().Get("status"))}}, nil
}

// profileSubmit 保存资料白名单并显示“提交前快照 + 成功后快照”的实际生效差异。
func (h *appsPageHandlers) profileSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"app_id", "name",
		"description", "icon_ref", "homepage", "owner_user_id", "contact_info",
		"row_version"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.profile.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
	if appID == "" || !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	before, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.profile.load_failed"), nil
	}
	change := UIApplicationChange{
		Name:        strings.TrimSpace(form.Get("name")),
		Description: strings.TrimSpace(form.Get("description")),
		IconRef:     strings.TrimSpace(form.Get("icon_ref")),
		Homepage:    strings.TrimSpace(form.Get("homepage")),
		OwnerUserID: strings.TrimSpace(form.Get("owner_user_id")),
		ContactInfo: strings.TrimSpace(form.Get("contact_info")),
	}
	if change.Name == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": before},
			ErrorSummary: text("page.admin.applications.profile.invalid")}, nil
	}
	// 服务端规范化前先判断“明显没有变化”，避免无变更也制造一次审计成功；
	// 真正的规范化差异仍以服务端返回快照为准。
	if change.Name == before.Name && change.Description == before.Description &&
		change.IconRef == before.IconRef && change.Homepage == before.Homepage &&
		change.OwnerUserID == before.OwnerUserID &&
		change.ContactInfo == before.ContactInfo {
		return UIPageOutcome{Data: map[string]any{"app": before,
			"status": "no_changes"}}, nil
	}
	after, err := h.pages.options.Backend.UpdateApplication(ctx, page.Session.UserID, appID,
		change, rowVersion, page.RequestID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": before},
			"page.admin.applications.profile.save_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": after, "before": before,
		"status": "saved", "changes": appsProfileDiff(before, after)}}, nil
}

// appsProfileDiff 计算资料实际生效差异（敏感联系方式不区分新旧值，只报告字段变化）。
func appsProfileDiff(before, after UIApplicationView) []UIAppsFieldDiff {
	var changes []UIAppsFieldDiff
	appendDiff := func(field, oldValue, newValue string) {
		if oldValue == newValue {
			return
		}
		changes = append(changes, UIAppsFieldDiff{Field: field, Before: oldValue, After: newValue})
	}
	appendDiff("name", before.Name, after.Name)
	appendDiff("description", before.Description, after.Description)
	appendDiff("icon_ref", before.IconRef, after.IconRef)
	appendDiff("homepage", before.Homepage, after.Homepage)
	appendDiff("owner_user_id", before.OwnerUserID, after.OwnerUserID)
	if before.ContactInfo != after.ContactInfo {
		changes = append(changes, UIAppsFieldDiff{Field: "contact_info"})
	}
	return changes
}

// ===== 成员 =====

// members 渲染当前应用成员列表与应用内资料。
func (h *appsPageHandlers) members(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.members.load_failed"), nil
	}
	query := UIAppMemberQuery{Status: strings.TrimSpace(request.URL.Query().Get("status")),
		Sort: strings.TrimSpace(request.URL.Query().Get("sort")), Limit: 20}
	offset, ok := appsParseOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.members.invalid")}, nil
	}
	query.Offset = offset
	result, err := h.pages.options.Backend.ListMembers(ctx, page.Session.UserID, appID, query)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.members.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": application,
			"members": result.Members, "hasMore": result.HasMore,
			"nextOffset": result.NextOffset, "status": query.Status, "sort": query.Sort,
			"offset": offset, "requestStatus": strings.TrimSpace(request.URL.Query().Get("status"))}},
		nil
}

// membersSubmit 处理成员添加/资料/启停/移除；每项动作都重新读取当前应用上下文。
func (h *appsPageHandlers) membersSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"app_id", "action",
		"user_id", "display_name", "title", "note", "row_version", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.members.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	action := strings.TrimSpace(form.Get("action"))
	userID := strings.TrimSpace(form.Get("user_id"))
	if appID == "" || userID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.members.invalid")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.members.load_failed"), nil
	}
	profile := UIAppMemberProfile{DisplayName: strings.TrimSpace(form.Get("display_name")),
		Title: strings.TrimSpace(form.Get("title")), Note: strings.TrimSpace(form.Get("note"))}
	status := ""
	switch action {
	case "add":
		member, addErr := h.pages.options.Backend.AddMember(ctx, page.Session.UserID, appID,
			userID, profile, page.RequestID)
		if addErr != nil {
			return h.renderMembersError(ctx, request, page, application,
				appsErrorOutcome(addErr, nil, "page.admin.applications.members.add_failed"))
		}
		status = "member_added"
		return h.renderMembers(ctx, request, page, application, map[string]any{
			"changedMember": member, "status": status})
	case "profile":
		rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.members.invalid")}, nil
		}
		member, profileErr := h.pages.options.Backend.UpdateMemberProfile(ctx,
			page.Session.UserID, appID, userID, profile, rowVersion, page.RequestID)
		if profileErr != nil {
			return h.renderMembersError(ctx, request, page, application,
				appsErrorOutcome(profileErr, nil,
					"page.admin.applications.members.profile_failed"))
		}
		return h.renderMembers(ctx, request, page, application, map[string]any{
			"changedMember": member, "status": "member_profile_saved"})
	case "enable", "disable":
		if action == "disable" && form.Get("confirm") != "yes" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.members.confirm_required")}, nil
		}
		rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.members.invalid")}, nil
		}
		member, changed, stateErr := h.pages.options.Backend.SetMemberState(ctx,
			page.Session.UserID, appID, userID, action == "enable", rowVersion,
			page.RequestID)
		if stateErr != nil {
			return h.renderMembersError(ctx, request, page, application,
				appsErrorOutcome(stateErr, nil,
					"page.admin.applications.members.state_failed"))
		}
		return h.renderMembers(ctx, request, page, application, map[string]any{
			"changedMember": member, "changed": changed, "status": "member_state_" + action})
	case "remove":
		if form.Get("confirm") != "yes" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.members.confirm_required")}, nil
		}
		rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
		if !ok {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.members.invalid")}, nil
		}
		if removeErr := h.pages.options.Backend.RemoveMember(ctx, page.Session.UserID,
			appID, userID, rowVersion, page.RequestID); removeErr != nil {
			return h.renderMembersError(ctx, request, page, application,
				appsErrorOutcome(removeErr, nil,
					"page.admin.applications.members.remove_failed"))
		}
		return h.renderMembers(ctx, request, page, application, map[string]any{
			"removedUserID": userID, "status": "member_removed"})
	default:
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.members.invalid")}, nil
	}
}

// renderMembers 重新读取成员列表并渲染（写操作后保持当前应用上下文）。
func (h *appsPageHandlers) renderMembers(ctx context.Context, request *http.Request,
	page UIPageContext, application UIApplicationView, extra map[string]any) (UIPageOutcome, error) {
	result, err := h.pages.options.Backend.ListMembers(ctx, page.Session.UserID,
		application.ID, UIAppMemberQuery{Limit: 20})
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.members.load_failed"), nil
	}
	data := map[string]any{"app": application, "members": result.Members,
		"hasMore": result.HasMore, "nextOffset": result.NextOffset, "offset": 0}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// renderMembersError 把写操作错误与本应用上下文一起渲染（不丢当前应用上下文）。
func (h *appsPageHandlers) renderMembersError(ctx context.Context, request *http.Request,
	page UIPageContext, application UIApplicationView, outcome UIPageOutcome) (UIPageOutcome, error) {
	rendered, _ := h.renderMembers(ctx, request, page, application, nil)
	rendered.StatusCode = outcome.StatusCode
	rendered.ErrorCode = outcome.ErrorCode
	rendered.ErrorSummary = outcome.ErrorSummary
	return rendered, nil
}

// ===== 安全与接入（回调/授权方式） =====

// security 渲染 OAuth 客户端安全设置或首次登记表单。
func (h *appsPageHandlers) security(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.security.load_failed"), nil
	}
	settings, err := h.pages.options.Backend.GetOAuthSettings(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.security.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": application, "settings": settings,
		"form":   appsSecurityFormFromSettings(settings),
		"status": strings.TrimSpace(request.URL.Query().Get("status"))}}, nil
}

// securitySubmit 处理首次登记与安全设置更新（后者不改身份验证方式）。
func (h *appsPageHandlers) securitySubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"app_id", "action",
		"grant_code", "grant_refresh", "grant_credentials", "grant_device",
		"redirect_uris", "post_logout_redirect_uris", "scopes", "audiences",
		"auth_basic", "auth_post", "auth_tls", "require_pkce", "certificate_pem",
		"row_version", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	action := strings.TrimSpace(form.Get("action"))
	if appID == "" || (action != "register" && action != "update") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.security.confirm_required")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.security.load_failed"), nil
	}
	// 非敏感输入回填：失败时保留用户已填的回调/Scope/audience/授权勾选，便于纠正。
	grantTypesEcho := appsGrantTypes(form)
	authMethodsEcho := appsAuthMethods(form)
	formEcho := appsSecurityForm(grantTypesEcho, authMethodsEcho,
		form.Get("redirect_uris"), form.Get("post_logout_redirect_uris"),
		form.Get("scopes"), form.Get("audiences"), form.Get("certificate_pem"),
		appsChecked(form, "require_pkce"))
	grantTypes := appsGrantTypes(form)
	redirectURIs, ok := appsLines(form.Get("redirect_uris"), 20, 20*2048)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	postLogout, ok := appsLines(form.Get("post_logout_redirect_uris"), 20, 20*2048)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	scopes, ok := appsLines(form.Get("scopes"), 50, 50*128)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	audiences, ok := appsLines(form.Get("audiences"), 20, 20*256)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	requirePKCE := appsChecked(form, "require_pkce")
	if action == "register" {
		result, registerErr := h.pages.options.Backend.RegisterClient(ctx,
			page.Session.UserID, appID, UIOAuthRegister{
				GrantTypes: grantTypes, RedirectURIs: redirectURIs,
				PostLogoutRedirectURIs: postLogout, Scopes: scopes, Audiences: audiences,
				AuthMethods: appsAuthMethods(form), RequirePKCE: requirePKCE,
				CertificatePEM: strings.TrimSpace(form.Get("certificate_pem")),
			}, page.RequestID)
		if registerErr != nil {
			return h.renderSecurityErrorEcho(ctx, page, application,
				appsErrorOutcome(registerErr, nil,
					"page.admin.applications.security.register_failed"), formEcho)
		}
		data := map[string]any{"app": application, "settings": result.Settings,
			"form": appsSecurityFormFromSettings(result.Settings), "status": "registered"}
		if result.Secret != nil {
			// 明文只在本次响应出现一次；不写 URL/localStorage/隐藏字段。
			data["secret"] = result.Secret
		}
		if result.Certificate != nil {
			data["certificate"] = result.Certificate
		}
		return UIPageOutcome{Data: data}, nil
	}
	rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.security.invalid")}, nil
	}
	before, beforeErr := h.pages.options.Backend.GetOAuthSettings(ctx,
		page.Session.UserID, appID)
	after, updateErr := h.pages.options.Backend.UpdateClientSettings(ctx,
		page.Session.UserID, appID, UIOAuthChange{
			GrantTypes: grantTypes, RedirectURIs: redirectURIs,
			PostLogoutRedirectURIs: postLogout, Scopes: scopes, Audiences: audiences,
			RequirePKCE: requirePKCE}, rowVersion, page.RequestID)
	if updateErr != nil {
		return h.renderSecurityErrorEcho(ctx, page, application,
			appsErrorOutcome(updateErr, nil,
				"page.admin.applications.security.update_failed"), formEcho)
	}
	data := map[string]any{"app": application, "settings": after,
		"form": appsSecurityFormFromSettings(after), "status": "saved"}
	if beforeErr == nil {
		data["before"] = before
		data["changes"] = appsSettingsDiff(before, after)
	}
	return UIPageOutcome{Data: data}, nil
}

// renderSecurityError 读取当前安全设置并把错误与上下文一起渲染。
func (h *appsPageHandlers) renderSecurityError(ctx context.Context, page UIPageContext,
	application UIApplicationView, outcome UIPageOutcome) (UIPageOutcome, error) {
	settings, err := h.pages.options.Backend.GetOAuthSettings(ctx, page.Session.UserID,
		application.ID)
	if err != nil {
		outcome.Data = map[string]any{"app": application}
		return outcome, nil
	}
	outcome.Data = map[string]any{"app": application, "settings": settings,
		"form": appsSecurityFormFromSettings(settings)}
	return outcome, nil
}

// appsSecurityFormFromSettings 把真实生效设置转换为表单回填值（失败时保留用户
// 已填的非敏感输入，未提交时回填当前真实值）。
func appsSecurityFormFromSettings(settings UIOAuthSettings) map[string]any {
	return appsSecurityForm(settings.GrantTypes, settings.AuthMethods,
		strings.Join(settings.RedirectURIs, "\n"),
		strings.Join(settings.PostLogoutRedirectURIs, "\n"),
		strings.Join(settings.Scopes, "\n"),
		strings.Join(settings.Audiences, "\n"), "", settings.RequirePKCE)
}

// appsSecurityForm 生成安全设置表单回填值（字段名与模板 `$form.grantCode` 等一致），
// 保证打开页面时已有授权类型/认证方式正确勾选，失败时保留用户已填的非敏感输入。
func appsSecurityForm(grantTypes, authMethods []string, redirectURIs, postLogout, scopes,
	audiences, certificatePEM string, requirePKCE bool) map[string]any {
	has := func(values []string, target string) bool {
		for _, value := range values {
			if value == target {
				return true
			}
		}
		return false
	}
	return map[string]any{
		"grantTypes":       append([]string{}, grantTypes...),
		"authMethods":      append([]string{}, authMethods...),
		"grantCode":        has(grantTypes, "authorization_code"),
		"grantRefresh":     has(grantTypes, "refresh_token"),
		"grantCredentials": has(grantTypes, "client_credentials"),
		"grantDevice":      has(grantTypes, "urn:ietf:params:oauth:grant-type:device_code"),
		"authBasic":        has(authMethods, "client_secret_basic"),
		"authPost":         has(authMethods, "client_secret_post"),
		"authTLS":          has(authMethods, "tls_client_auth"),
		"redirectURIs":     redirectURIs, "postLogout": postLogout,
		"scopes": scopes, "audiences": audiences,
		"requirePKCE": requirePKCE, "certificatePEM": certificatePEM,
	}
}

// renderSecurityErrorEcho 在保留用户已填非敏感输入的同时渲染当前真实设置。
func (h *appsPageHandlers) renderSecurityErrorEcho(ctx context.Context, page UIPageContext,
	application UIApplicationView, outcome UIPageOutcome, formEcho map[string]any) (UIPageOutcome, error) {
	rendered, _ := h.renderSecurityError(ctx, page, application, outcome)
	if data, ok := rendered.Data.(map[string]any); ok {
		data["form"] = formEcho
	}
	return rendered, nil
}

// appsGrantTypes 把显式复选框映射为真实授权类型（不含 password/implicit）。
func appsGrantTypes(form url.Values) []string {
	var grants []string
	if appsChecked(form, "grant_code") {
		grants = append(grants, "authorization_code")
	}
	if appsChecked(form, "grant_refresh") {
		grants = append(grants, "refresh_token")
	}
	if appsChecked(form, "grant_credentials") {
		grants = append(grants, "client_credentials")
	}
	if appsChecked(form, "grant_device") {
		grants = append(grants, "urn:ietf:params:oauth:grant-type:device_code")
	}
	return grants
}

// appsAuthMethods 把显式复选框映射为真实客户端身份验证方式。
func appsAuthMethods(form url.Values) []string {
	var methods []string
	if appsChecked(form, "auth_basic") {
		methods = append(methods, "client_secret_basic")
	}
	if appsChecked(form, "auth_post") {
		methods = append(methods, "client_secret_post")
	}
	if appsChecked(form, "auth_tls") {
		methods = append(methods, "tls_client_auth")
	}
	return methods
}

// appsSettingsDiff 计算安全设置集合的新增/移除与 PKCE 变化。
func appsSettingsDiff(before, after UIOAuthSettings) []UIAppsFieldDiff {
	var changes []UIAppsFieldDiff
	appendSet := func(field string, oldValues, newValues []string) {
		removed := appsMissing(newValues, oldValues)
		added := appsMissing(oldValues, newValues)
		if len(removed) == 0 && len(added) == 0 {
			return
		}
		change := UIAppsFieldDiff{Field: field}
		if len(added) > 0 {
			change.After = strings.Join(added, "\n")
		}
		if len(removed) > 0 {
			change.Before = strings.Join(removed, "\n")
		}
		changes = append(changes, change)
	}
	appendSet("grant_types", before.GrantTypes, after.GrantTypes)
	appendSet("redirect_uris", before.RedirectURIs, after.RedirectURIs)
	appendSet("post_logout_redirect_uris", before.PostLogoutRedirectURIs,
		after.PostLogoutRedirectURIs)
	appendSet("scopes", before.Scopes, after.Scopes)
	appendSet("audiences", before.Audiences, after.Audiences)
	if before.RequirePKCE != after.RequirePKCE {
		changes = append(changes, UIAppsFieldDiff{Field: "require_pkce",
			Before: appsBoolText(before.RequirePKCE), After: appsBoolText(after.RequirePKCE)})
	}
	return changes
}

// appsMissing 返回 list 中不在 target 的项。
func appsMissing(target, list []string) []string {
	set := make(map[string]struct{}, len(target))
	for _, value := range target {
		set[value] = struct{}{}
	}
	var missing []string
	for _, value := range list {
		if _, ok := set[value]; !ok {
			missing = append(missing, value)
		}
	}
	return missing
}

// appsBoolText 把启用状态转中文（模板差异使用）。
func appsBoolText(value bool) string {
	if value {
		return "启用"
	}
	return "停用"
}

// ===== 应用凭证 =====

// credentials 渲染应用客户端秘密/证书元数据（永不含明文）。
func (h *appsPageHandlers) credentials(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil,
			"page.admin.applications.credentials.load_failed"), nil
	}
	credentials, err := h.pages.options.Backend.GetCredentials(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.credentials.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": application,
		"credentials": credentials,
		"status":      strings.TrimSpace(request.URL.Query().Get("status"))}}, nil
}

// credentialsSubmit 处理轮换/撤销密钥与登记/撤销客户端公钥证书。
func (h *appsPageHandlers) credentialsSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"app_id", "action",
		"secret_id", "certificate_id", "certificate_pem", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.credentials.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	action := strings.TrimSpace(form.Get("action"))
	if appID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil,
			"page.admin.applications.credentials.load_failed"), nil
	}
	switch action {
	case "rotate":
		if form.Get("confirm") != "yes" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.credentials.confirm_required")}, nil
		}
		revealed, rotateErr := h.pages.options.Backend.RotateSecret(ctx,
			page.Session.UserID, appID, page.RequestID)
		if rotateErr != nil {
			outcome := appsErrorOutcome(rotateErr, nil,
				"page.admin.applications.credentials.rotate_failed")
			// 仅“结果可能已发生但无法确认”的依赖故障使用结果未知文案；权限/冲突/
			// 参数错误保留精确稳定码说明，不把所有失败都说成“结果未知”。
			switch outcome.ErrorCode {
			case "INTERNAL_ERROR", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED", "AUTHZ_UNAVAILABLE":
				outcome.ErrorSummary = text("page.admin.applications.credentials.unknown_outcome")
			}
			return h.renderCredentialsError(ctx, page, application, outcome)
		}
		return h.renderCredentials(ctx, page, application, map[string]any{
			"secret": revealed, "status": "rotated"})
	case "revoke":
		secretID := strings.TrimSpace(form.Get("secret_id"))
		if secretID == "" || form.Get("confirm") != "yes" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.credentials.confirm_required")}, nil
		}
		if revokeErr := h.pages.options.Backend.RevokeSecret(ctx, page.Session.UserID,
			appID, secretID, page.RequestID); revokeErr != nil {
			return h.renderCredentialsError(ctx, page, application,
				appsErrorOutcome(revokeErr, nil,
					"page.admin.applications.credentials.revoke_failed"))
		}
		return h.renderCredentials(ctx, page, application, map[string]any{
			"revokedSecretID": secretID, "status": "revoked"})
	case "register_certificate":
		certificatePEM := strings.TrimSpace(form.Get("certificate_pem"))
		if certificatePEM == "" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.credentials.invalid")}, nil
		}
		certificate, certErr := h.pages.options.Backend.RegisterCertificate(ctx,
			page.Session.UserID, appID, certificatePEM, page.RequestID)
		if certErr != nil {
			return h.renderCredentialsError(ctx, page, application,
				appsErrorOutcome(certErr, nil,
					"page.admin.applications.credentials.revoke_failed"))
		}
		return h.renderCredentials(ctx, page, application, map[string]any{
			"certificate": certificate, "status": "certificate_registered"})
	case "revoke_certificate":
		certificateID := strings.TrimSpace(form.Get("certificate_id"))
		if certificateID == "" || form.Get("confirm") != "yes" {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				Data:         map[string]any{"app": application},
				ErrorSummary: text("page.admin.applications.credentials.confirm_required")}, nil
		}
		if revokeErr := h.pages.options.Backend.RevokeCertificate(ctx,
			page.Session.UserID, appID, certificateID, page.RequestID); revokeErr != nil {
			return h.renderCredentialsError(ctx, page, application,
				appsErrorOutcome(revokeErr, nil,
					"page.admin.applications.credentials.revoke_failed"))
		}
		return h.renderCredentials(ctx, page, application, map[string]any{
			"revokedCertificateID": certificateID, "status": "certificate_revoked"})
	default:
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         map[string]any{"app": application},
			ErrorSummary: text("page.admin.applications.credentials.invalid")}, nil
	}
}

// renderCredentials 重新读取元数据并渲染（秘密只在本次响应出现）。
func (h *appsPageHandlers) renderCredentials(ctx context.Context, page UIPageContext,
	application UIApplicationView, extra map[string]any) (UIPageOutcome, error) {
	credentials, err := h.pages.options.Backend.GetCredentials(ctx, page.Session.UserID,
		application.ID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.credentials.load_failed"), nil
	}
	data := map[string]any{"app": application, "credentials": credentials}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// renderCredentialsError 读取当前元数据并把错误与上下文一起渲染。
func (h *appsPageHandlers) renderCredentialsError(ctx context.Context, page UIPageContext,
	application UIApplicationView, outcome UIPageOutcome) (UIPageOutcome, error) {
	credentials, err := h.pages.options.Backend.GetCredentials(ctx, page.Session.UserID,
		application.ID)
	if err != nil {
		outcome.Data = map[string]any{"app": application}
		return outcome, nil
	}
	outcome.Data = map[string]any{"app": application, "credentials": credentials}
	return outcome, nil
}

// ===== 资源与接口/字段许可 =====

// grants 读取应用真实托管策略并渲染只读摘要/受控写表单。写表单只有在宿主注入
// PolicyBackend + PolicyReauth 且适配器确认可写时出现；服务端不信任表单开关。
func (h *appsPageHandlers) grants(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.grants.load_failed"), nil
	}
	policy, err := h.pages.options.Backend.GetManagedPolicy(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.grants.load_failed"), nil
	}
	canWrite := h.pages.options.PolicyBackend != nil &&
		h.pages.options.PolicyReauth != nil && policy.CanWrite
	return UIPageOutcome{Data: map[string]any{
		"app": application, "policy": policy,
		"policyForm": appsPolicyForm(policy), "canWrite": canWrite,
		"saved": strings.TrimSpace(request.URL.Query().Get("saved")) == "1",
	}}, nil
}

// grantsSubmit 受控写入应用策略：解析/白名单校验 → 一次性 reauth（绑定 app/
// row_version/policy digest/request_id）→ managedapi.SetPolicy（行版本/审计/
// 受信授权）。成功重定向回读取页；失败保留当前应用上下文与稳定错误摘要。
func (h *appsPageHandlers) grantsSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if h.pages.options.PolicyBackend == nil || h.pages.options.PolicyReauth == nil {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.applications.grants.write_unavailable")}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"app_id", "row_version", "policy_ops", "policy_service_ops", "policy_objects",
		"policy_fields", "policy_max_limit", "policy_max_offset", "policy_max_batch",
	})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.grants.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
	if appID == "" || !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	change, parseErr := appsParsePolicyChange(form)
	if parseErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.grants.invalid")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.grants.load_failed"), nil
	}
	requestID := strings.TrimSpace(page.RequestID)
	if requestID == "" {
		// 直接调用页面处理器/测试没有 transport 请求编号时生成合法的关联编号；
		// 生产链路仍使用真实 request_id 供审计与一次性绑定。
		requestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	binding := UIAppPolicyActionBinding{ApplicationID: appID, ExpectedRowVersion: rowVersion,
		PolicyDigest: change.Digest(), RequestID: requestID}
	if err := h.pages.options.PolicyReauth(ctx, page.Session.UserID, binding); err != nil {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorCode:    "REAUTH_REQUIRED",
			ErrorSummary: text("page.admin.applications.common.reauth_required"),
			Data:         map[string]any{"app": application}}, nil
	}
	if _, err := h.pages.options.PolicyBackend.SetManagedPolicy(ctx, page.Session.UserID,
		appID, change, rowVersion, requestID, binding.PolicyDigest); err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.grants.save_failed"), nil
	}
	// 重新读取服务端真实策略/应用，展示保存后的行版本；管理路由不允许通过
	// RedirectQuery 携带 app_id，故采用同页渲染而非站外跳转。
	after, reloadErr := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if reloadErr != nil {
		return appsErrorOutcome(reloadErr, map[string]any{"app": application},
			"page.admin.applications.grants.load_failed"), nil
	}
	policy, policyErr := h.pages.options.Backend.GetManagedPolicy(ctx, page.Session.UserID, appID)
	if policyErr != nil {
		return appsErrorOutcome(policyErr, map[string]any{"app": after},
			"page.admin.applications.grants.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{
		"app": after, "policy": policy, "policyForm": appsPolicyForm(policy),
		"canWrite": true, "saved": true,
	}}, nil
}

// appsPolicyForm 把当前策略转换为可编辑文本域初始值。
func appsPolicyForm(policy UIAppPolicyView) UIAppPolicyForm {
	joinOps := func(operations []UIAppPolicyOperation) string {
		ids := make([]string, 0, len(operations))
		for _, operation := range operations {
			ids = append(ids, operation.ID)
		}
		return strings.Join(ids, "\n")
	}
	objectLines := make([]string, 0, len(policy.Objects))
	for _, scope := range policy.Objects {
		objectLines = append(objectLines, scope.Object+"|"+scope.Mode+"|"+
			strings.Join(scope.Resources, ","))
	}
	fieldLines := make([]string, 0, len(policy.Fields))
	for _, fields := range policy.Fields {
		fieldLines = append(fieldLines, fields.Object+"|"+strings.Join(fields.Read, ",")+
			"|"+strings.Join(fields.Write, ","))
	}
	return UIAppPolicyForm{
		Allowed: joinOps(policy.Allowed), ServiceAllowed: joinOps(policy.ServiceAllowed),
		Objects: strings.Join(objectLines, "\n"), Fields: strings.Join(fieldLines, "\n"),
		MaxLimit: policy.Limits.MaxLimit, MaxOffset: policy.Limits.MaxOffset,
		MaxBatch: policy.Limits.MaxBatch,
	}
}

// appsParsePolicyChange 严格解析表单文本域；未知格式/重复项/超限值在进入
// managedapi 之前拒绝，最终仍由 managedapi.Validate 做权威校验。
func appsParsePolicyChange(form url.Values) (UIAppPolicyChange, error) {
	change := UIAppPolicyChange{
		Allowed:        appsSplitPolicyList(form.Get("policy_ops")),
		ServiceAllowed: appsSplitPolicyList(form.Get("policy_service_ops")),
	}
	objects, err := appsParsePolicyObjects(form.Get("policy_objects"))
	if err != nil {
		return UIAppPolicyChange{}, err
	}
	fields, err := appsParsePolicyFields(form.Get("policy_fields"))
	if err != nil {
		return UIAppPolicyChange{}, err
	}
	change.Objects = objects
	change.Fields = fields
	parseLimit := func(key string, fallback int) (int, error) {
		value := strings.TrimSpace(form.Get(key))
		if value == "" {
			return fallback, nil
		}
		number, err := strconv.Atoi(value)
		if err != nil || number <= 0 {
			return 0, fmt.Errorf("上限必须是正整数")
		}
		return number, nil
	}
	if change.Limits.MaxLimit, err = parseLimit("policy_max_limit", 20); err != nil {
		return UIAppPolicyChange{}, err
	}
	if change.Limits.MaxOffset, err = parseLimit("policy_max_offset", 100000); err != nil {
		return UIAppPolicyChange{}, err
	}
	if change.Limits.MaxBatch, err = parseLimit("policy_max_batch", 10); err != nil {
		return UIAppPolicyChange{}, err
	}
	return change, nil
}

// appsSplitPolicyList 按换行/逗号拆分操作 ID；去空、去重，保持输入顺序。
func appsSplitPolicyList(value string) []string {
	value = strings.ReplaceAll(value, ",", "\n")
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, line := range strings.Split(value, "\n") {
		item := strings.TrimSpace(line)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

// appsParsePolicyObjects 解析 object|mode|resources 行；mode 仅 all/resources。
func appsParsePolicyObjects(value string) ([]UIAppPolicyObject, error) {
	result := make([]UIAppPolicyObject, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("对象范围格式错误")
		}
		object := strings.TrimSpace(parts[0])
		mode := strings.TrimSpace(parts[1])
		if object == "" || (mode != "all" && mode != "resources") {
			return nil, fmt.Errorf("对象范围格式错误")
		}
		if _, exists := seen[object]; exists {
			return nil, fmt.Errorf("对象范围重复")
		}
		seen[object] = struct{}{}
		scope := UIAppPolicyObject{Object: object, Mode: mode}
		if len(parts) == 3 {
			scope.Resources = appsSplitPolicyList(parts[2])
		}
		if mode == "all" && len(scope.Resources) != 0 {
			return nil, fmt.Errorf("all 范围不能携带资源")
		}
		if mode == "resources" && len(scope.Resources) == 0 {
			return nil, fmt.Errorf("resources 范围必须列出资源")
		}
		result = append(result, scope)
	}
	return result, nil
}

// appsParsePolicyFields 解析 object|read,read|write,write 行。
func appsParsePolicyFields(value string) ([]UIAppPolicyFields, error) {
	result := make([]UIAppPolicyFields, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			return nil, fmt.Errorf("字段规则格式错误")
		}
		object := strings.TrimSpace(parts[0])
		if object == "" {
			return nil, fmt.Errorf("字段规则缺少对象")
		}
		if _, exists := seen[object]; exists {
			return nil, fmt.Errorf("字段规则重复")
		}
		seen[object] = struct{}{}
		result = append(result, UIAppPolicyFields{
			Object: object, Read: appsSplitPolicyList(parts[1]),
			Write: appsSplitPolicyList(parts[2]),
		})
	}
	return result, nil
}

// ===== 应用状态（停用/启用确认） =====

// status 渲染启停确认页（只读当前状态与真实影响说明），并在后端实现删除扩展
// 契约时附带逻辑删除影响预览（步骤 190）。
func (h *appsPageHandlers) status(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	appID, ok := appsQueryAppID(request)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.invalid_app")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.status.load_failed"), nil
	}
	data := map[string]any{"app": application,
		"status": strings.TrimSpace(request.URL.Query().Get("status"))}
	if deleteBackend, ok := h.pages.options.Backend.(UIAppsDeleteBackend); ok {
		impact, impactErr := deleteBackend.GetApplicationDeleteImpact(ctx,
			page.Session.UserID, appID)
		if impactErr != nil {
			data["deleteImpactUnavailable"] = text(
				"page.admin.applications.delete.impact_unavailable")
		} else {
			data["deleteImpact"] = impact
		}
	}
	return UIPageOutcome{Data: data}, nil
}

// statusDelete 执行应用逻辑删除（步骤 190）：必须显式确认、目标与行版本绑定，并
// 经宿主真实再次认证回调复核；未注入再认证或后端未提供删除能力时 fail-closed。
func (h *appsPageHandlers) statusDelete(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	deleteBackend, ok := h.pages.options.Backend.(UIAppsDeleteBackend)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusServiceUnavailable,
			ErrorSummary: text("page.admin.applications.delete.unavailable")}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField,
		[]string{"app_id", "row_version", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.delete.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	rowVersion, versionOK := appsParseRowVersion(form.Get("row_version"))
	if appID == "" || !versionOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.delete.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.delete.confirm_required")}, nil
	}
	if h.pages.options.DeleteReauth == nil {
		// 宿主未装配再次认证：高风险删除 fail-closed，不能用页面确认替代授权。
		return UIPageOutcome{StatusCode: http.StatusServiceUnavailable,
			ErrorSummary: text("page.admin.applications.delete.reauth_unavailable")}, nil
	}
	binding := UIAppDeleteBinding{ApplicationID: appID,
		ExpectedRowVersion: rowVersion, RequestID: page.RequestID}
	if err := h.pages.options.DeleteReauth(ctx, page.Session.UserID, binding); err != nil {
		var publicErr *UIAppsError
		if errors.As(err, &publicErr) && publicErr.Code == "ACCESS_DENIED" {
			return UIPageOutcome{StatusCode: http.StatusForbidden,
				ErrorSummary: text("page.admin.applications.delete.forbidden")}, nil
		}
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.applications.delete.reauth_required")}, nil
	}
	updated, changed, err := deleteBackend.DeleteApplication(ctx, page.Session.UserID,
		appID, rowVersion, page.RequestID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.delete.failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": updated, "deleted": true,
		"changed": changed}}, nil
}

// statusSubmit 执行停用/启用并显示服务端 Changed 语义（不伪造第二次变更）。
func (h *appsPageHandlers) statusSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"app_id", "action",
		"row_version", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.status.invalid")}, nil
	}
	appID := strings.TrimSpace(form.Get("app_id"))
	action := strings.TrimSpace(form.Get("action"))
	rowVersion, ok := appsParseRowVersion(form.Get("row_version"))
	if appID == "" || (action != "enable" && action != "disable") || !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.status.invalid")}, nil
	}
	if action == "disable" && form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.applications.status.confirm_required")}, nil
	}
	application, err := h.pages.options.Backend.GetApplication(ctx, page.Session.UserID, appID)
	if err != nil {
		return appsErrorOutcome(err, nil, "page.admin.applications.status.load_failed"), nil
	}
	updated, changed, err := h.pages.options.Backend.SetApplicationState(ctx,
		page.Session.UserID, appID, action == "enable", rowVersion, page.RequestID)
	if err != nil {
		return appsErrorOutcome(err, map[string]any{"app": application},
			"page.admin.applications.status.change_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"app": updated, "changed": changed,
		"action": action}}, nil
}
