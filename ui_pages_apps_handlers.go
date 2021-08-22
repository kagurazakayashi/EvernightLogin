package login

// 步骤 70 应用管理页处理器：所有写操作都是显式 POST + 服务端重新授权；页面把真实
// 服务返回的差异/状态/稳定错误码映射为中文说明，不渲染假开关或伪造成功。

import (
	"context"
	"net/http"
	"net/url"
	"strings"
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
	case "admin.application_status":
		return h.status(ctx, request, page)
	case "admin.application_status.submit":
		return h.statusSubmit(ctx, request, page)
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
	}}, nil
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

// grants 显示“尚未启用”真实状态：当前没有真实的许可目录/读取/差异/写入接口。
// 页面仍先通过真实服务读取当前应用以完成服务端授权，不渲染假开关。
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
	return UIPageOutcome{Data: map[string]any{"app": application, "policy": policy}}, nil
}

// ===== 应用状态（停用/启用确认） =====

// status 渲染启停确认页（只读当前状态与真实影响说明）。
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
	return UIPageOutcome{Data: map[string]any{"app": application,
		"status": strings.TrimSpace(request.URL.Query().Get("status"))}}, nil
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
