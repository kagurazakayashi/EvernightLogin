// Package uiadminadapter 的步骤 70 应用管理适配器：把登录根包的应用管理页公开契约
// 接到真实 internal/app 与 internal/oauthclient 服务。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的管理员用户 ID，
// 每次都重新构造可信 Caller 并调用真实领域服务；应用管理授权、应用作用范围、成员
// 状态与客户端凭证再次验证全部由领域服务判定。本包不实现权限放行、不缓存授权、
// 不读取前端自报角色，也不保存明文客户端秘密（秘密只在方法返回值出现一次）。
package uiadminadapter

import (
	"context"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"log/slog"
	"strings"
	"time"
)

// AppOptions 是应用管理页适配器依赖。Authorize 是宿主注入的页面层管理动作复核
// （可选；nil 时依赖 app/oauthclient 服务自身 Authorizer，仍 fail-closed）。
// 负责人变更能力无法从领域服务能力位读取；未提供 Authorize 时页面把负责人显示为
// 只读，并由服务端继续拒绝任何越权变更，不伪造可写能力。
type AppOptions struct {
	Apps  *app.Service
	OAuth *oauthclient.Service
	// ManagedAPI 是真实托管管理 API 委托策略服务（internal/managedapi）。nil 时
	// 页面明确显示“受信策略读取通道未装配”，不伪造策略内容与“未启用”。
	ManagedAPI ManagedPolicyService
	// ManagedPolicyActor 是宿主配置的受信只读通道标识（如 system 组件），其
	// PolicyAuthorizer 必须显式允许该标识读取策略。页面层仍先经过 Authorize 钩子
	// 与 UIAccessManagement 会话检查；写策略由 SetManagedPolicy 以当前管理员
	// 用户主体提交，再由 managedapi 的受信 PolicyAuthorizer/reauth/行版本校验。
	ManagedPolicyActor audit.Actor
	// Authorize 是宿主的页面层管理动作复核（可选）。参数 action 使用策略目录权限键：
	// applications.update / applications.credentials.manage；宿主可另外定义
	// “application.owner.change”能力标识用于负责人可编辑性（不是 policy 权限键）。
	// nil 时依赖服务自身 Authorizer，负责人字段按只读处理（保守）。
	Authorize func(ctx context.Context, adminUserID, action, applicationID string) error
	// AuthorizeAnyApp 是“没有单一目标应用”的列表读取复核（可选，步骤 184）：
	// 宿主按“系统范围或任一应用范围持有 action 权限”判定；实际返回范围仍由
	// app.Service.ApplicationScope 过滤。nil 时退回旧的空范围复核路径。
	AuthorizeAnyApp func(ctx context.Context, adminUserID, action string) error
	Now             func() time.Time
	Logger          *slog.Logger
}

// ManagedPolicyService 是托管 API 策略服务的只读契约（生产 *managedapi.Service）。
type ManagedPolicyService interface {
	GetPolicy(ctx context.Context, actor audit.Actor, applicationID,
		requestID string) (managedapi.PolicyView, error)
}

// ManagedPolicyWriterService 是可选策略写契约；只读实现/测试替身无需实现它。
// 生产 *managedapi.Service 同时满足两者。
type ManagedPolicyWriterService interface {
	SetPolicy(ctx context.Context, actor audit.Actor,
		request managedapi.SetPolicyRequest) (managedapi.PolicyView, error)
}

// AppsAdapter 实现 ui.UIAppsBackend。
type AppsAdapter struct {
	opts AppOptions
}

// NewApps 校验依赖并构造适配器。
func NewApps(options AppOptions) (*AppsAdapter, error) {
	if options.Apps == nil || options.OAuth == nil {
		return nil, fmt.Errorf("应用管理页适配器缺少必需服务")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &AppsAdapter{opts: options}, nil
}

// appsErr 构造稳定公开错误。
func appsErr(code string) error { return &ui.UIAppsError{Code: code} }

// check 执行页面层管理动作复核；管理员标识非法一律拒绝。
func (a *AppsAdapter) check(ctx context.Context, adminUserID, action, applicationID string) error {
	if adminUserID == "" || !account.ValidUserID(adminUserID) {
		return appsErr("ACCESS_DENIED")
	}
	if a.opts.Authorize != nil {
		if err := a.opts.Authorize(ctx, adminUserID, action, applicationID); err != nil {
			return appsErr("ACCESS_DENIED")
		}
	}
	return nil
}

// appCaller 构造应用服务可信调用者。
func (a *AppsAdapter) appCaller(adminUserID, requestID string) (app.Caller, error) {
	caller, err := app.UserCaller(adminUserID)
	if err != nil {
		return app.Caller{}, appsErr("ACCESS_DENIED")
	}
	if requestID != "" {
		caller, err = caller.WithRequestID(requestID)
		if err != nil {
			return app.Caller{}, appsErr("REQ_INVALID")
		}
	}
	return caller, nil
}

// oauthCaller 构造客户端服务可信调用者。
func (a *AppsAdapter) oauthCaller(adminUserID, requestID string) (oauthclient.Caller, error) {
	caller, err := oauthclient.UserCaller(adminUserID)
	if err != nil {
		return oauthclient.Caller{}, appsErr("ACCESS_DENIED")
	}
	if requestID != "" {
		caller, err = caller.WithRequestID(requestID)
		if err != nil {
			return oauthclient.Caller{}, appsErr("REQ_INVALID")
		}
	}
	return caller, nil
}

// mapAppsError 把 app/oauthclient 领域错误映射为稳定公开错误码。
// mapManagedPolicyError 把托管策略错误映射为稳定页面错误码；不泄露内部细节。
func mapManagedPolicyError(err error) error {
	switch {
	case errors.Is(err, managedapi.ErrVersionConflict):
		return appsErr("CONFLICT")
	case errors.Is(err, managedapi.ErrPolicyDisabled):
		return appsErr("ACCESS_DENIED")
	case errors.Is(err, managedapi.ErrAccessDenied):
		return appsErr("ACCESS_DENIED")
	case errors.Is(err, managedapi.ErrInvalidRequest):
		return appsErr("REQ_INVALID")
	case errors.Is(err, managedapi.ErrStoreUnavailable), errors.Is(err, managedapi.ErrAuditUnavailable):
		return appsErr("UNAVAILABLE")
	default:
		return appsErr("INTERNAL_ERROR")
	}
}

// managedPolicyOperationDescriptions 是策略操作目录的中文说明（页面展示用；机器
// 标识仍是 managedapi 目录的唯一操作 ID）。
var managedPolicyOperationDescriptions = map[string]string{
	managedapi.OpApplicationGet: "读取本应用资料",
	managedapi.OpMembersList:    "查询应用成员列表", managedapi.OpMembersGet: "读取应用成员",
	managedapi.OpMembersUpdateProfile: "更新应用内成员资料", managedapi.OpMembersDisable: "禁用应用成员",
	managedapi.OpMembersEnable: "启用应用成员", managedapi.OpMembersRemove: "移除应用成员",
	managedapi.OpUsersCreate: "创建新账户并加入本应用",
	managedapi.OpGroupsList:  "查询应用用户组", managedapi.OpGroupsGet: "读取应用用户组",
	managedapi.OpGroupsCreate: "创建应用用户组", managedapi.OpGroupsUpdate: "更新应用用户组",
	managedapi.OpGroupsDelete: "删除应用用户组", managedapi.OpGroupMembersList: "查询组成员",
	managedapi.OpGroupMembersAdd: "加入组成员", managedapi.OpGroupMembersRemove: "移除组成员",
	managedapi.OpRolesList: "查询应用角色", managedapi.OpRolesGet: "读取应用角色",
	managedapi.OpRolesCreate: "创建应用角色", managedapi.OpRolesUpdate: "更新应用角色",
	managedapi.OpRolesDelete: "删除应用角色", managedapi.OpRolePermissionsList: "查询角色权限",
	managedapi.OpRoleAssignUser: "分配角色给用户", managedapi.OpRoleRevokeUser: "撤销用户角色",
	managedapi.OpRoleAssignGroup: "分配角色给用户组", managedapi.OpRoleRevokeGroup: "撤销用户组角色",
	managedapi.OpRoleAssignmentsList: "查询角色分配",
	managedapi.OpPermissionsList:     "查询应用权限", managedapi.OpPermissionsGet: "读取应用权限",
	managedapi.OpPermissionsCreate: "创建应用权限", managedapi.OpPermissionsUpdate: "更新应用权限",
	managedapi.OpPermissionsDelete: "删除应用权限", managedapi.OpPermissionsEnable: "启用应用权限",
	managedapi.OpPermissionsDisable: "停用应用权限",
}

// managedPolicyCatalog 返回完整操作目录（不受当前策略限制）；页面用复选框选择，
// 提交后仍由 managedapi 严格校验未知操作/硬禁字段/上限。
func managedPolicyCatalog() []ui.UIAppPolicyOperationCatalog {
	ids := managedapi.OperationIDs()
	result := make([]ui.UIAppPolicyOperationCatalog, 0, len(ids))
	for _, id := range ids {
		operation, ok := managedapi.LookupOperation(id)
		if !ok {
			continue
		}
		result = append(result, ui.UIAppPolicyOperationCatalog{
			ID: id, Object: operation.ObjectType, Write: operation.Write,
			ServiceOK:   operation.ServiceAllowed,
			Description: managedPolicyOperationDescriptions[id],
		})
	}
	return result
}

// managedPolicyFieldCatalog 返回对象字段目录与可写字段建议；读字段来自 managedapi
// 的公开目录，写字段排除 id/scope/status/时间戳/builtin 等不可变标识。
func managedPolicyFieldCatalog() []ui.UIAppPolicyFieldCatalog {
	writable := map[string][]string{
		"application": {"name", "description"},
		"member":      {"display_name", "title", "note"},
		"user":        {"username", "nickname", "biography"},
		"group":       {"key", "name", "description"},
		"role":        {"key", "name", "description", "limits", "enabled"},
		"permission":  {"key", "name", "description", "limits", "enabled"},
	}
	result := make([]ui.UIAppPolicyFieldCatalog, 0, len(managedapi.ObjectTypes))
	for _, object := range managedapi.ObjectTypes {
		result = append(result, ui.UIAppPolicyFieldCatalog{
			Object: object, Read: managedapi.FieldsOf(object),
			Write: append([]string{}, writable[object]...),
		})
	}
	return result
}

func mapAppsError(err error) error {
	if err == nil {
		return nil
	}
	code := "INTERNAL_ERROR"
	appCode := app.CodeOf(err)
	oauthCode := oauthclient.CodeOf(err)
	managedCode := managedapi.CodeOf(err)
	switch {
	case appCode != "" && appCode != app.CodeInternalError:
		code = string(appCode)
	case oauthCode != "" && oauthCode != oauthclient.CodeInternalError:
		code = string(oauthCode)
	case managedCode != "" && managedCode != managedapi.CodeInternalError:
		code = string(managedCode)
	}
	return &ui.UIAppsError{Code: code}
}

// caps 读取宿主能力钩子（只是交互辅助；写操作仍由领域服务重新授权）。
func (a *AppsAdapter) caps(ctx context.Context, adminUserID, applicationID string) ui.UIApplicationCapabilities {
	capabilities := ui.UIApplicationCapabilities{Write: true, ManageMembers: true,
		ManageSecurity: true, ManageCredentials: true}
	if a.opts.Authorize == nil {
		return capabilities
	}
	allowed := func(action string) bool {
		return a.opts.Authorize(ctx, adminUserID, action, applicationID) == nil
	}
	// 真实 policy 目录只有 applications.update 与 applications.credentials.manage；
	// 成员/安全/状态写入均属应用资料更新权限，负责人可编辑性由宿主额外能力标识判定
	// （领域服务对用户操作者仍会拒绝负责人变更）。
	capabilities.Write = allowed("applications.update")
	capabilities.ChangeOwner = allowed("application.owner.change")
	capabilities.ManageMembers = capabilities.Write
	capabilities.ManageSecurity = capabilities.Write
	capabilities.ManageCredentials = allowed("applications.credentials.manage")
	return capabilities
}

// toApplicationView 转换应用记录公开视图。
func (a *AppsAdapter) toApplicationView(ctx context.Context, adminUserID string,
	record app.Application) ui.UIApplicationView {
	view := ui.UIApplicationView{
		ID: record.ID, ScopeID: record.ScopeID, Name: record.Name,
		Description: record.Description, IconRef: record.IconRef,
		Homepage: record.Homepage, OwnerUserID: record.OwnerUserID,
		ContactInfo: record.ContactInfo, Status: string(record.Status),
		ClientType: string(record.ClientType), RowVersion: record.RowVersion,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		DeletedAt: record.DeletedAt,
	}
	view.Capabilities = a.caps(ctx, adminUserID, record.ID)
	return view
}

// ListApplications 列出当前管理员获准管理的应用（状态筛选/白名单排序/分页）。
//
// 权限语义（步骤 184）：列表没有单一目标应用，先用列表读取复核（系统范围或任一
// 应用范围持有 applications.read），再由 app.Service.ApplicationScope 返回真实可读
// 应用集合过滤；分页/NextOffset/HasMore 只基于过滤后的集合，不泄露范围外应用。
func (a *AppsAdapter) ListApplications(ctx context.Context, adminUserID string,
	query ui.UIAppQuery) (ui.UIAppPage, error) {
	if adminUserID == "" || !account.ValidUserID(adminUserID) {
		return ui.UIAppPage{}, appsErr("ACCESS_DENIED")
	}
	if a.opts.AuthorizeAnyApp != nil {
		if err := a.opts.AuthorizeAnyApp(ctx, adminUserID, "applications.read"); err != nil {
			return ui.UIAppPage{}, appsErr("ACCESS_DENIED")
		}
	} else if a.opts.Authorize != nil {
		// 兼容未注入列表复核的宿主：保留既有空范围复核路径（fail-closed）。
		if err := a.opts.Authorize(ctx, adminUserID, "applications.update", ""); err != nil {
			return ui.UIAppPage{}, appsErr("ACCESS_DENIED")
		}
	}
	caller, err := a.appCaller(adminUserID, "")
	if err != nil {
		return ui.UIAppPage{}, err
	}
	limit := query.Limit
	if limit <= 0 {
		limit = app.DefaultListLimit
	}
	if limit > app.MaxListLimit {
		limit = app.MaxListLimit
	}
	if query.Offset < 0 || query.Offset > app.MaxListOffset {
		return ui.UIAppPage{}, appsErr("REQ_INVALID")
	}
	status := app.Status(strings.TrimSpace(query.Status))
	if status != "" && !status.Valid() {
		return ui.UIAppPage{}, appsErr("REQ_INVALID")
	}
	sortField := app.SortField(strings.TrimSpace(query.Sort))
	if sortField == "" {
		sortField = app.SortUpdatedAt
	}
	if !sortField.Valid() {
		return ui.UIAppPage{}, appsErr("REQ_INVALID")
	}
	result, err := a.opts.Apps.ListApplications(ctx, caller, app.ListRequest{
		Limit: limit, Offset: query.Offset, Status: status, Sort: sortField,
		Descending: query.Descending})
	if err != nil {
		return ui.UIAppPage{}, mapAppsError(err)
	}
	page := ui.UIAppPage{HasMore: result.HasMore,
		Applications: make([]ui.UIApplicationView, 0, len(result.Applications)),
		NextOffset:   query.Offset + len(result.Applications)}
	for _, record := range result.Applications {
		page.Applications = append(page.Applications, a.toApplicationView(ctx, adminUserID, record))
	}
	return page, nil
}

// GetApplication 读取单个应用资料（服务端重新判定管理范围）。
func (a *AppsAdapter) GetApplication(ctx context.Context, adminUserID,
	applicationID string) (ui.UIApplicationView, error) {
	if err := a.check(ctx, adminUserID, "applications.read", applicationID); err != nil {
		return ui.UIApplicationView{}, err
	}
	caller, err := a.appCaller(adminUserID, "")
	if err != nil {
		return ui.UIApplicationView{}, err
	}
	record, err := a.opts.Apps.GetApplication(ctx, caller, applicationID)
	if err != nil {
		return ui.UIApplicationView{}, mapAppsError(err)
	}
	return a.toApplicationView(ctx, adminUserID, record), nil
}

// CanCreateApplication 只对宿主返回“是否显示新建入口”；真实 POST 仍由
// CreateApplication 重新经过页面授权、app.Service Authorizer 与审计。没有
// 宿主 Authorize 钩子时无法安全判断页面能力，保守返回 false，不显示静态按钮。
func (a *AppsAdapter) CanCreateApplication(ctx context.Context,
	adminUserID string) (bool, error) {
	if adminUserID == "" || !account.ValidUserID(adminUserID) {
		return false, nil
	}
	if a.opts.Authorize == nil {
		return false, nil
	}
	if err := a.opts.Authorize(ctx, adminUserID, "applications.create", ""); err != nil {
		return false, nil
	}
	return true, nil
}

// CreateApplication 以页面管理会话登记应用；ID/状态/版本由领域服务生成，创建
// 成功后默认停用。页面层能力位只影响展示，实际授权由 applications.create 权限、
// 应用服务 Authorizer 与审计共同判定。
func (a *AppsAdapter) CreateApplication(ctx context.Context, adminUserID string,
	create ui.UIApplicationCreate, requestID string) (ui.UIApplicationView, error) {
	if err := a.check(ctx, adminUserID, "applications.create", ""); err != nil {
		return ui.UIApplicationView{}, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIApplicationView{}, err
	}
	record, err := a.opts.Apps.CreateApplication(ctx, caller, app.CreateRequest{
		Name: create.Name, Description: create.Description, IconRef: create.IconRef,
		Homepage: create.Homepage, OwnerUserID: create.OwnerUserID,
		ContactInfo: create.ContactInfo, ClientType: app.ClientType(create.ClientType),
	})
	if err != nil {
		return ui.UIApplicationView{}, mapAppsError(err)
	}
	return a.toApplicationView(ctx, adminUserID, record), nil
}

// UpdateApplication 保存资料白名单；应用 ID/客户端类型/状态不进入本请求。
func (a *AppsAdapter) UpdateApplication(ctx context.Context, adminUserID, applicationID string,
	change ui.UIApplicationChange, expectedRowVersion int64,
	requestID string) (ui.UIApplicationView, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIApplicationView{}, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIApplicationView{}, err
	}
	record, err := a.opts.Apps.UpdateApplication(ctx, caller, applicationID,
		app.UpdateRequest{Name: change.Name, Description: change.Description,
			IconRef: change.IconRef, Homepage: change.Homepage,
			OwnerUserID: change.OwnerUserID, ContactInfo: change.ContactInfo,
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return ui.UIApplicationView{}, mapAppsError(err)
	}
	return a.toApplicationView(ctx, adminUserID, record), nil
}

// SetApplicationState 停用/启用应用，返回真实 Changed 语义（幂等不算再次变更）。
func (a *AppsAdapter) SetApplicationState(ctx context.Context, adminUserID, applicationID string,
	enable bool, expectedRowVersion int64, requestID string) (ui.UIApplicationView, bool, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIApplicationView{}, false, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIApplicationView{}, false, err
	}
	request := app.StatusRequest{ApplicationID: applicationID,
		ExpectedRowVersion: expectedRowVersion}
	var result app.StatusResult
	if enable {
		result, err = a.opts.Apps.EnableApplication(ctx, caller, request)
	} else {
		result, err = a.opts.Apps.DisableApplication(ctx, caller, request)
	}
	if err != nil {
		return ui.UIApplicationView{}, false, mapAppsError(err)
	}
	return a.toApplicationView(ctx, adminUserID, result.Application), result.Changed, nil
}

// GetApplicationDeleteImpact 返回应用删除前影响预览（步骤 190）：真实统计将被
// 立即失效/继续保留的数据范围，并给出当前是否可逻辑删除。预览只读；删除的最终
// 判定由 app.Service 按当前状态重新执行。页面层先复核 applications.update。
func (a *AppsAdapter) GetApplicationDeleteImpact(ctx context.Context, adminUserID,
	applicationID string) (ui.UIApplicationDeleteImpact, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIApplicationDeleteImpact{}, err
	}
	caller, err := a.appCaller(adminUserID, "")
	if err != nil {
		return ui.UIApplicationDeleteImpact{}, err
	}
	impact, err := a.opts.Apps.PreviewDeletion(ctx, caller, applicationID)
	if err != nil {
		return ui.UIApplicationDeleteImpact{}, mapAppsError(err)
	}
	return ui.UIApplicationDeleteImpact{
		Application:               a.toApplicationView(ctx, adminUserID, impact.Application),
		CanDelete:                 impact.CanDelete,
		BlockReason:               impact.BlockReason,
		MemberCount:               impact.MemberCount,
		ActiveMemberCount:         impact.ActiveMemberCount,
		RoleCount:                 impact.RoleCount,
		PermissionCount:           impact.PermissionCount,
		GroupCount:                impact.GroupCount,
		ActiveSessionCount:        impact.ActiveSessionCount,
		OAuthClientCount:          impact.OAuthClientCount,
		RefreshTokenFamilyCount:   impact.RefreshTokenFamilyCount,
		AuthorizationRequestCount: impact.AuthorizationRequestCount,
		CredentialCount:           impact.CredentialCount,
		InvitationCount:           impact.InvitationCount,
		WebhookEndpointCount:      impact.WebhookEndpointCount,
		AuditEventCount:           impact.AuditEventCount,
	}, nil
}

// DeleteApplication 对已停用应用执行逻辑删除（Changed=false 表示已删除，幂等成功）。
// 再次认证与显式确认由页面传输层在调用本方法前完成；本方法仍由领域服务重新鉴权
// （管理范围、状态机、行版本）并写关键审计。
func (a *AppsAdapter) DeleteApplication(ctx context.Context, adminUserID, applicationID string,
	expectedRowVersion int64, requestID string) (ui.UIApplicationView, bool, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIApplicationView{}, false, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIApplicationView{}, false, err
	}
	result, err := a.opts.Apps.DeleteApplication(ctx, caller, app.DeletionRequest{
		ApplicationID: applicationID, ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return ui.UIApplicationView{}, false, mapAppsError(err)
	}
	return a.toApplicationView(ctx, adminUserID, result.Application), result.Changed, nil
}

// toMemberView 转换成员公开视图（只有稳定用户 ID 与应用内资料）。
func toMemberView(record app.Membership) ui.UIAppMemberView {
	return ui.UIAppMemberView{UserID: record.UserID,
		DisplayName: record.Profile.DisplayName, Title: record.Profile.Title,
		Note: record.Profile.Note, Status: string(record.Status),
		RowVersion: record.RowVersion, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt}
}

// ListMembers 列出当前应用成员（只影响当前应用范围）。
func (a *AppsAdapter) ListMembers(ctx context.Context, adminUserID, applicationID string,
	query ui.UIAppMemberQuery) (ui.UIAppMemberPage, error) {
	if err := a.check(ctx, adminUserID, "applications.members", applicationID); err != nil {
		return ui.UIAppMemberPage{}, err
	}
	caller, err := a.appCaller(adminUserID, "")
	if err != nil {
		return ui.UIAppMemberPage{}, err
	}
	limit := query.Limit
	if limit <= 0 {
		limit = app.DefaultListLimit
	}
	if limit > app.MaxListLimit {
		limit = app.MaxListLimit
	}
	if query.Offset < 0 || query.Offset > app.MaxListOffset {
		return ui.UIAppMemberPage{}, appsErr("REQ_INVALID")
	}
	status := app.MembershipStatus(strings.TrimSpace(query.Status))
	if status != "" && !status.Valid() {
		return ui.UIAppMemberPage{}, appsErr("REQ_INVALID")
	}
	sortField := app.MemberSortField(strings.TrimSpace(query.Sort))
	if sortField == "" {
		sortField = app.MemberSortCreatedAt
	}
	if !sortField.Valid() {
		return ui.UIAppMemberPage{}, appsErr("REQ_INVALID")
	}
	result, err := a.opts.Apps.ListApplicationMembers(ctx, caller, app.MemberListRequest{
		ApplicationID: applicationID, Limit: limit, Offset: query.Offset,
		Status: status, Sort: sortField, Descending: query.Descending})
	if err != nil {
		return ui.UIAppMemberPage{}, mapAppsError(err)
	}
	page := ui.UIAppMemberPage{HasMore: result.HasMore,
		Members:    make([]ui.UIAppMemberView, 0, len(result.Members)),
		NextOffset: query.Offset + len(result.Members)}
	for _, record := range result.Members {
		page.Members = append(page.Members, toMemberView(record))
	}
	return page, nil
}

// AddMember 建立当前应用成员关系（目标必须是既有可用账户，不能是 root）。
func (a *AppsAdapter) AddMember(ctx context.Context, adminUserID, applicationID, userID string,
	profile ui.UIAppMemberProfile, requestID string) (ui.UIAppMemberView, error) {
	if err := a.check(ctx, adminUserID, "applications.members", applicationID); err != nil {
		return ui.UIAppMemberView{}, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIAppMemberView{}, err
	}
	record, err := a.opts.Apps.AddApplicationMember(ctx, caller, app.AddMemberRequest{
		ApplicationID: applicationID, UserID: userID,
		Profile: app.MemberProfile{DisplayName: profile.DisplayName,
			Title: profile.Title, Note: profile.Note}})
	if err != nil {
		return ui.UIAppMemberView{}, mapAppsError(err)
	}
	return toMemberView(record), nil
}

// UpdateMemberProfile 保存应用内成员资料（不回写全局账户资料）。
func (a *AppsAdapter) UpdateMemberProfile(ctx context.Context, adminUserID, applicationID,
	userID string, profile ui.UIAppMemberProfile, expectedRowVersion int64,
	requestID string) (ui.UIAppMemberView, error) {
	if err := a.check(ctx, adminUserID, "applications.members", applicationID); err != nil {
		return ui.UIAppMemberView{}, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIAppMemberView{}, err
	}
	record, err := a.opts.Apps.UpdateApplicationMemberProfile(ctx, caller,
		app.MemberProfileRequest{ApplicationID: applicationID, UserID: userID,
			Profile: app.MemberProfile{DisplayName: profile.DisplayName,
				Title: profile.Title, Note: profile.Note},
			ExpectedRowVersion: expectedRowVersion})
	if err != nil {
		return ui.UIAppMemberView{}, mapAppsError(err)
	}
	return toMemberView(record), nil
}

// SetMemberState 启用/停用当前应用成员关系（不改变全局账户与其他应用）。
func (a *AppsAdapter) SetMemberState(ctx context.Context, adminUserID, applicationID, userID string,
	enable bool, expectedRowVersion int64, requestID string) (ui.UIAppMemberView, bool, error) {
	if err := a.check(ctx, adminUserID, "applications.members", applicationID); err != nil {
		return ui.UIAppMemberView{}, false, err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIAppMemberView{}, false, err
	}
	request := app.MemberStatusRequest{ApplicationID: applicationID, UserID: userID,
		ExpectedRowVersion: expectedRowVersion}
	var result app.MemberStatusResult
	if enable {
		result, err = a.opts.Apps.EnableApplicationMember(ctx, caller, request)
	} else {
		result, err = a.opts.Apps.DisableApplicationMember(ctx, caller, request)
	}
	if err != nil {
		return ui.UIAppMemberView{}, false, mapAppsError(err)
	}
	return toMemberView(result.Membership), result.Changed, nil
}

// RemoveMember 移除当前应用成员关系（不删除全局账户或其他应用成员）。
func (a *AppsAdapter) RemoveMember(ctx context.Context, adminUserID, applicationID, userID string,
	expectedRowVersion int64, requestID string) error {
	if err := a.check(ctx, adminUserID, "applications.members", applicationID); err != nil {
		return err
	}
	caller, err := a.appCaller(adminUserID, requestID)
	if err != nil {
		return err
	}
	if err := a.opts.Apps.RemoveApplicationMember(ctx, caller, app.RemoveMemberRequest{
		ApplicationID: applicationID, UserID: userID,
		ExpectedRowVersion: expectedRowVersion}); err != nil {
		return mapAppsError(err)
	}
	return nil
}

// oauthSettings 把 oauthclient.Client 转换为脱敏视图。
func (a *AppsAdapter) oauthSettings(client oauthclient.Client) ui.UIOAuthSettings {
	settings := ui.UIOAuthSettings{Registered: true, ClientID: client.ClientID,
		ClientType:             string(client.ClientType),
		GrantTypes:             make([]string, 0, len(client.GrantTypes)),
		RedirectURIs:           append([]string{}, client.RedirectURIs...),
		PostLogoutRedirectURIs: append([]string{}, client.PostLogoutRedirectURIs...),
		Scopes:                 append([]string{}, client.Scopes...),
		Audiences:              append([]string{}, client.Audiences...),
		AuthMethods:            make([]string, 0, len(client.AuthMethods)),
		RequirePKCE:            client.RequirePKCE, RowVersion: client.RowVersion,
		CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
		// 当前没有资源服务器信任映射目录；页面必须显示“未核验”。
		AudienceTrustUnverified: true}
	for _, grant := range client.GrantTypes {
		settings.GrantTypes = append(settings.GrantTypes, string(grant))
	}
	for _, method := range client.AuthMethods {
		settings.AuthMethods = append(settings.AuthMethods, string(method))
	}
	return settings
}

// GetOAuthSettings 读取客户端安全设置；未登记返回 Registered=false（不是配置为
// “没有任何权限”）。
func (a *AppsAdapter) GetOAuthSettings(ctx context.Context, adminUserID,
	applicationID string) (ui.UIOAuthSettings, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIOAuthSettings{}, err
	}
	application, err := a.appForType(ctx, adminUserID, applicationID)
	if err != nil {
		return ui.UIOAuthSettings{}, err
	}
	caller, err := a.oauthCaller(adminUserID, "")
	if err != nil {
		return ui.UIOAuthSettings{}, err
	}
	client, err := a.opts.OAuth.GetClient(ctx, caller, applicationID)
	if err != nil {
		if errors.Is(err, oauthclient.ErrClientNotFound) {
			return ui.UIOAuthSettings{Registered: false, ClientID: applicationID,
				ClientType:              string(application.ClientType),
				AudienceTrustUnverified: true}, nil
		}
		return ui.UIOAuthSettings{}, mapAppsError(err)
	}
	return a.oauthSettings(client), nil
}

// appForType 读取应用记录（用于客户端类型展示；真实授权仍由各服务判定）。
func (a *AppsAdapter) appForType(ctx context.Context, adminUserID,
	applicationID string) (app.Application, error) {
	caller, err := a.appCaller(adminUserID, "")
	if err != nil {
		return app.Application{}, err
	}
	record, err := a.opts.Apps.GetApplication(ctx, caller, applicationID)
	if err != nil {
		return app.Application{}, mapAppsError(err)
	}
	return record, nil
}

// toRevealedSecret 转换一次展示的密钥明文。
func (a *AppsAdapter) toRevealedSecret(revealed oauthclient.RevealedClientSecret) ui.UIAppRevealedSecret {
	return ui.UIAppRevealedSecret{Info: a.toSecretInfo(revealed.Info), Secret: revealed.Secret}
}

// toSecretInfo 转换密钥非秘密元数据并派生展示状态（服务端按真实时间计算）。
func (a *AppsAdapter) toSecretInfo(info oauthclient.ClientSecretInfo) ui.UIAppSecretInfo {
	now := a.opts.Now().UTC()
	return ui.UIAppSecretInfo{ID: info.ID, Prefix: info.Prefix,
		CreatedAt: info.CreatedAt, ExpiresAt: info.ExpiresAt, RetireAt: info.RetireAt,
		RevokedAt: info.RevokedAt, Status: secretStatus(info, now)}
}

// secretStatus 按真实时间与元数据派生密钥状态（未知不默认“安全”）。
func secretStatus(info oauthclient.ClientSecretInfo, now time.Time) string {
	switch {
	case !info.RevokedAt.IsZero():
		return "revoked"
	case !info.ExpiresAt.IsZero() && !now.Before(info.ExpiresAt):
		return "expired"
	case !info.RetireAt.IsZero() && now.Before(info.RetireAt):
		return "retiring"
	case !info.RetireAt.IsZero():
		return "retired"
	case info.RetireAt.IsZero() && info.ExpiresAt.IsZero():
		return "unknown"
	default:
		return "active"
	}
}

// toCertificate 转换客户端公钥证书元数据。
func toCertificate(info oauthclient.ClientCertificateInfo) ui.UIAppCertificate {
	return ui.UIAppCertificate{ID: info.ID,
		FingerprintSHA256: info.FingerprintSHA256, Subject: info.Subject,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter,
		CreatedAt: info.CreatedAt, RevokedAt: info.RevokedAt}
}

// RegisterClient 首次登记客户端安全设置；秘密只在本次返回值出现一次。
func (a *AppsAdapter) RegisterClient(ctx context.Context, adminUserID, applicationID string,
	register ui.UIOAuthRegister, requestID string) (ui.UIOAuthRegisterResult, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIOAuthRegisterResult{}, err
	}
	application, err := a.appForType(ctx, adminUserID, applicationID)
	if err != nil {
		return ui.UIOAuthRegisterResult{}, err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIOAuthRegisterResult{}, err
	}
	requirePKCE := register.RequirePKCE
	result, err := a.opts.OAuth.RegisterClient(ctx, caller, oauthclient.RegisterRequest{
		ClientID: applicationID, ClientType: oauthclient.ClientType(application.ClientType),
		GrantTypes: register.GrantTypes, RedirectURIs: register.RedirectURIs,
		PostLogoutRedirectURIs: register.PostLogoutRedirectURIs, Scopes: register.Scopes,
		Audiences: register.Audiences, AuthMethods: register.AuthMethods,
		RequirePKCE: &requirePKCE, CertificatePEM: register.CertificatePEM,
		RequestID: requestID})
	if err != nil {
		return ui.UIOAuthRegisterResult{}, mapAppsError(err)
	}
	out := ui.UIOAuthRegisterResult{Settings: a.oauthSettings(result.Client)}
	if result.Secret != nil {
		secret := a.toRevealedSecret(*result.Secret)
		out.Secret = &secret
	}
	if result.Certificate != nil {
		certificate := toCertificate(*result.Certificate)
		out.Certificate = &certificate
	}
	return out, nil
}

// UpdateClientSettings 修改既有安全设置；身份验证方式与客户端类型不随本请求修改。
func (a *AppsAdapter) UpdateClientSettings(ctx context.Context, adminUserID, applicationID string,
	change ui.UIOAuthChange, expectedRowVersion int64,
	requestID string) (ui.UIOAuthSettings, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIOAuthSettings{}, err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIOAuthSettings{}, err
	}
	requirePKCE := change.RequirePKCE
	client, err := a.opts.OAuth.UpdateClientSettings(ctx, caller,
		oauthclient.UpdateSettingsRequest{ClientID: applicationID,
			GrantTypes: change.GrantTypes, RedirectURIs: change.RedirectURIs,
			PostLogoutRedirectURIs: change.PostLogoutRedirectURIs, Scopes: change.Scopes,
			Audiences: change.Audiences, RequirePKCE: &requirePKCE,
			ExpectedRowVersion: expectedRowVersion, RequestID: requestID})
	if err != nil {
		return ui.UIOAuthSettings{}, mapAppsError(err)
	}
	return a.oauthSettings(client), nil
}

// GetCredentials 读取当前应用客户端秘密/证书元数据（永不含明文）。
func (a *AppsAdapter) GetCredentials(ctx context.Context, adminUserID,
	applicationID string) (ui.UIAppCredentials, error) {
	if err := a.check(ctx, adminUserID, "applications.credentials.manage", applicationID); err != nil {
		return ui.UIAppCredentials{}, err
	}
	application, err := a.appForType(ctx, adminUserID, applicationID)
	if err != nil {
		return ui.UIAppCredentials{}, err
	}
	caller, err := a.oauthCaller(adminUserID, "")
	if err != nil {
		return ui.UIAppCredentials{}, err
	}
	credentials := ui.UIAppCredentials{ClientType: string(application.ClientType)}
	settings, settingsErr := a.opts.OAuth.GetClient(ctx, caller, applicationID)
	if settingsErr == nil {
		credentials.Registered = true
		for _, method := range settings.AuthMethods {
			credentials.AuthMethods = append(credentials.AuthMethods, string(method))
		}
	} else if !errors.Is(settingsErr, oauthclient.ErrClientNotFound) {
		return ui.UIAppCredentials{}, mapAppsError(settingsErr)
	}
	secrets, err := a.opts.OAuth.ListClientSecrets(ctx, caller, applicationID)
	if err != nil {
		if errors.Is(err, oauthclient.ErrClientNotFound) {
			return credentials, nil
		}
		return ui.UIAppCredentials{}, mapAppsError(err)
	}
	credentials.Registered = true
	for _, info := range secrets {
		credentials.Secrets = append(credentials.Secrets, a.toSecretInfo(info))
	}
	certificates, err := a.opts.OAuth.ListClientCertificates(ctx, caller, applicationID)
	if err != nil {
		if !errors.Is(err, oauthclient.ErrClientNotFound) {
			return ui.UIAppCredentials{}, mapAppsError(err)
		}
	} else {
		for _, info := range certificates {
			credentials.Certificates = append(credentials.Certificates,
				toCertificate(info))
		}
	}
	return credentials, nil
}

// RotateSecret 轮换客户端秘密；新明文只在本次返回值出现一次。
func (a *AppsAdapter) RotateSecret(ctx context.Context, adminUserID, applicationID,
	requestID string) (ui.UIAppRevealedSecret, error) {
	if err := a.check(ctx, adminUserID, "applications.credentials.manage", applicationID); err != nil {
		return ui.UIAppRevealedSecret{}, err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIAppRevealedSecret{}, err
	}
	revealed, err := a.opts.OAuth.RotateClientSecret(ctx, caller,
		oauthclient.RotateSecretRequest{ClientID: applicationID, RequestID: requestID})
	if err != nil {
		return ui.UIAppRevealedSecret{}, mapAppsError(err)
	}
	return a.toRevealedSecret(revealed), nil
}

// RevokeSecret 撤销指定客户端秘密；最后一个可用凭证由服务端拒绝。
func (a *AppsAdapter) RevokeSecret(ctx context.Context, adminUserID, applicationID, secretID,
	requestID string) error {
	if err := a.check(ctx, adminUserID, "applications.credentials.manage", applicationID); err != nil {
		return err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return err
	}
	if err := a.opts.OAuth.RevokeClientSecret(ctx, caller,
		oauthclient.RevokeSecretRequest{ClientID: applicationID, SecretID: secretID,
			RequestID: requestID}); err != nil {
		return mapAppsError(err)
	}
	return nil
}

// RegisterCertificate 登记客户端公钥证书；私钥材料由服务端拒绝。
func (a *AppsAdapter) RegisterCertificate(ctx context.Context, adminUserID, applicationID,
	certificatePEM, requestID string) (ui.UIAppCertificate, error) {
	if err := a.check(ctx, adminUserID, "applications.credentials.manage", applicationID); err != nil {
		return ui.UIAppCertificate{}, err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return ui.UIAppCertificate{}, err
	}
	info, err := a.opts.OAuth.RegisterClientCertificate(ctx, caller,
		oauthclient.CertificateRequest{ClientID: applicationID,
			CertificatePEM: certificatePEM, RequestID: requestID})
	if err != nil {
		return ui.UIAppCertificate{}, mapAppsError(err)
	}
	return toCertificate(info), nil
}

// RevokeCertificate 撤销指定客户端证书。
func (a *AppsAdapter) RevokeCertificate(ctx context.Context, adminUserID, applicationID,
	certificateID, requestID string) error {
	if err := a.check(ctx, adminUserID, "applications.credentials.manage", applicationID); err != nil {
		return err
	}
	caller, err := a.oauthCaller(adminUserID, requestID)
	if err != nil {
		return err
	}
	if err := a.opts.OAuth.RevokeClientCertificate(ctx, caller,
		oauthclient.CertificateRequest{ClientID: applicationID,
			CertificateID: certificateID, RequestID: requestID}); err != nil {
		return mapAppsError(err)
	}
	return nil
}

// GetManagedPolicy 读取应用真实托管管理 API 委托策略（受信系统只读通道）。写策略
// 由 SetManagedPolicy 在页面一次性强认证绑定后提交，不在本读取路径放行。
func (a *AppsAdapter) GetManagedPolicy(ctx context.Context, adminUserID,
	applicationID string) (ui.UIAppPolicyView, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIAppPolicyView{}, err
	}
	if a.opts.ManagedAPI == nil {
		return ui.UIAppPolicyView{State: "unavailable",
			Reason: "页面未装配受信策略读取通道（宿主未注入 managedapi 读取适配器）"}, nil
	}
	if err := a.opts.ManagedPolicyActor.Validate(); err != nil {
		return ui.UIAppPolicyView{State: "unavailable",
			Reason: "受信策略读取标识未配置或无效；未读取任何策略内容"}, nil
	}
	canWrite := a.canWriteManagedPolicy(ctx, adminUserID, applicationID)
	view, err := a.opts.ManagedAPI.GetPolicy(ctx, a.opts.ManagedPolicyActor, applicationID, "")
	if err != nil {
		switch {
		case errors.Is(err, managedapi.ErrPolicyDisabled):
			return ui.UIAppPolicyView{State: "not_configured",
				ApplicationID: applicationID, CanWrite: canWrite,
				Limits:  ui.UIAppPolicyLimits{MaxLimit: 20, MaxOffset: 100000, MaxBatch: 10},
				Catalog: managedPolicyCatalog(), FieldCatalog: managedPolicyFieldCatalog()}, nil
		case errors.Is(err, managedapi.ErrAccessDenied):
			return ui.UIAppPolicyView{State: "unavailable",
				Reason: "受信策略读取通道未获准读取该应用策略；未展示任何策略内容"}, nil
		default:
			return ui.UIAppPolicyView{}, mapAppsError(err)
		}
	}
	result := ui.UIAppPolicyView{State: "policy", ApplicationID: view.ApplicationID,
		RowVersion: view.RowVersion, UpdatedBy: view.UpdatedBy,
		Limits: ui.UIAppPolicyLimits{MaxLimit: view.Policy.Limits.MaxLimit,
			MaxOffset: view.Policy.Limits.MaxOffset, MaxBatch: view.Policy.Limits.MaxBatch},
		CanWrite: canWrite}
	result.Catalog = managedPolicyCatalog()
	result.FieldCatalog = managedPolicyFieldCatalog()
	appendOps := func(ids []string) []ui.UIAppPolicyOperation {
		operations := make([]ui.UIAppPolicyOperation, 0, len(ids))
		for _, id := range ids {
			item := ui.UIAppPolicyOperation{ID: id}
			if operation, ok := managedapi.LookupOperation(id); ok {
				item.Object = operation.ObjectType
				item.Write = operation.Write
				item.ServiceOK = operation.ServiceAllowed
			}
			operations = append(operations, item)
		}
		return operations
	}
	result.Allowed = appendOps(view.Policy.Operations.Allowed)
	result.ServiceAllowed = appendOps(view.Policy.Operations.ServiceAllowed)
	for _, scope := range view.Policy.Objects {
		result.Objects = append(result.Objects, ui.UIAppPolicyObject{Object: scope.Object,
			Mode: scope.Mode, Resources: append([]string{}, scope.Resources...)})
	}
	for _, fields := range view.Policy.Fields {
		result.Fields = append(result.Fields, ui.UIAppPolicyFields{Object: fields.Object,
			Read: append([]string{}, fields.Read...), Write: append([]string{}, fields.Write...)})
	}
	return result, nil
}

// canWriteManagedPolicy 用真实 PolicyAuthorizer 探测当前管理员是否具有策略写
// 受信资格：root/受信本地管理员的用户主体被允许；应用管理员/普通用户被拒绝。
// 该探测只返回能力位，不写任何内容；最终写仍由 SetPolicy 全部重新校验。
func (a *AppsAdapter) canWriteManagedPolicy(ctx context.Context, adminUserID,
	applicationID string) bool {
	if _, ok := a.opts.ManagedAPI.(ManagedPolicyWriterService); !ok {
		return false
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: adminUserID}
	_, err := a.opts.ManagedAPI.GetPolicy(ctx, actor, applicationID, "")
	return err == nil || errors.Is(err, managedapi.ErrPolicyDisabled)
}

// SetManagedPolicy 写入应用真实托管管理 API 委托策略（步骤 146）。页面先经过
// UIAccessManagement 强会话/CSRF 与一次性 reauth 绑定；本方法再重新校验管理员
// 管理权限，并由 managedapi.SetPolicy 做受信 PolicyAuthorizer、行版本、策略结构、
// 审计同事务与应用状态校验。错误以稳定 UIAppsError 返回，页面不伪造成功。
func (a *AppsAdapter) SetManagedPolicy(ctx context.Context, adminUserID, applicationID string,
	change ui.UIAppPolicyChange, expectedRowVersion int64, requestID,
	policyDigest string) (ui.UIAppPolicyView, error) {
	if err := a.check(ctx, adminUserID, "applications.update", applicationID); err != nil {
		return ui.UIAppPolicyView{}, err
	}
	writer, writable := a.opts.ManagedAPI.(ManagedPolicyWriterService)
	if a.opts.ManagedAPI == nil || !writable {
		return ui.UIAppPolicyView{}, appsErr("UNAVAILABLE")
	}
	if expectedRowVersion < 0 || requestID == "" ||
		policyDigest == "" || change.Digest() != policyDigest {
		return ui.UIAppPolicyView{}, appsErr("REQ_INVALID")
	}
	policy := managedapi.Policy{
		Version: 1,
		Operations: managedapi.PolicyOperations{
			Allowed:        append([]string{}, change.Allowed...),
			ServiceAllowed: append([]string{}, change.ServiceAllowed...),
		},
		Limits: managedapi.PolicyLimits{MaxLimit: change.Limits.MaxLimit,
			MaxOffset: change.Limits.MaxOffset, MaxBatch: change.Limits.MaxBatch},
	}
	for _, scope := range change.Objects {
		policy.Objects = append(policy.Objects, managedapi.ObjectScope{
			Object: scope.Object, Mode: scope.Mode,
			Resources: append([]string{}, scope.Resources...)})
	}
	for _, fields := range change.Fields {
		policy.Fields = append(policy.Fields, managedapi.ObjectFields{
			Object: fields.Object, Read: append([]string{}, fields.Read...),
			Write: append([]string{}, fields.Write...)})
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: adminUserID}
	view, err := writer.SetPolicy(ctx, actor, managedapi.SetPolicyRequest{
		ApplicationID: applicationID, Policy: policy,
		ExpectedRowVersion: expectedRowVersion, RequestID: requestID,
		ReauthBinding: policyDigest,
	})
	if err != nil {
		return ui.UIAppPolicyView{}, mapManagedPolicyError(err)
	}
	result := ui.UIAppPolicyView{State: "policy", ApplicationID: view.ApplicationID,
		RowVersion: view.RowVersion, UpdatedBy: view.UpdatedBy,
		Limits: ui.UIAppPolicyLimits{MaxLimit: view.Policy.Limits.MaxLimit,
			MaxOffset: view.Policy.Limits.MaxOffset, MaxBatch: view.Policy.Limits.MaxBatch},
		CanWrite: true}
	result.Catalog = managedPolicyCatalog()
	result.FieldCatalog = managedPolicyFieldCatalog()
	return result, nil
}
