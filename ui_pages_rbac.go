package login

// 步骤 69：角色、权限、委派与有效权限查询页面（ui.v1 兼容新增）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话+强认证新鲜度；页面不凭前端状态放行。
//   - 每次读/写由 UIRBACBackend 适配器在服务端重新构造可信 Caller、复核管理授权、
//     作用范围与数据范围（宿主注入）；越权/跨范围/root 保护一律 fail-closed。
//   - 页面只展示后端返回的真实语义：中文说明、生效范围、不能做什么、默认值与当前
//     实际值、来源（直接角色/组）与数据范围；缺数据时显示“未知/不可用”，不伪造 0。
//   - root 不是可分配角色：后端不返回 root 角色/root_only 可组合权限；页面不提供
//     该类选项，服务端仍会拒绝。
//   - 作用范围切换通过整页 GET 重新加载，旧作用范围的目标/选择不跨页保留；写操作
//     表单显式携带实际目标 ID，服务端重新读取并判定实际目标。
//   - 高风险写操作（停用权限、组合权限、角色分配）要求确认标记，但确认不是授权：
//     后端仍按敏感策略、委派 Guard 与数据范围重新判定，并返回可披露的拒绝原因。

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

// UIPageRBACOptions 是步骤 69 角色/权限/委派/有效权限页配置。
type UIPageRBACOptions struct {
	Backend UIRBACBackend
}

// UIRBACBackend 是角色、权限、委派与有效权限页面调用真实授权/目录服务的最小契约。
// 适配器负责可信 Caller、管理授权、作用范围与数据范围复核；页面层不实现授权。
type UIRBACBackend interface {
	ListScopes(ctx context.Context, adminID string) ([]UIRBACScope, error)
	ListRoles(ctx context.Context, adminID string, query UIRBACRoleQuery) (UIRBACRolePage, error)
	GetRole(ctx context.Context, adminID, roleID string) (UIRBACRoleDetail, error)
	CreateRole(ctx context.Context, adminID string, create UIRBACCreateRole,
		requestID string) (UIRBACRoleView, error)
	UpdateRole(ctx context.Context, adminID, roleID string, change UIRBACTextChange,
		requestID string) (UIRBACRoleView, error)
	SetRoleState(ctx context.Context, adminID, roleID string, enable bool,
		requestID string) (UIRBACRoleView, bool, error)
	ComposeRolePermission(ctx context.Context, adminID, roleID, permissionID string,
		add bool, requestID string) (UIRBACComposeResult, error)
	ListAssignments(ctx context.Context, adminID, roleID string) (UIRBACAssignments, error)
	AssignRole(ctx context.Context, adminID, roleID, targetKind, targetID, requestID string,
		assign bool) (UIRBACAssignResult, error)
	ListPermissions(ctx context.Context, adminID string,
		query UIRBACPermissionQuery) (UIRBACPermissionPage, error)
	GetPermission(ctx context.Context, adminID,
		permissionID string) (UIRBACPermissionDetail, error)
	UpdatePermission(ctx context.Context, adminID, permissionID string,
		change UIRBACTextChange, requestID string) (UIRBACPermissionView, error)
	SetPermissionState(ctx context.Context, adminID, permissionID string, enable bool,
		requestID string) (UIRBACPermissionView, bool, error)
	DelegationView(ctx context.Context, adminID, scopeID string, includeRevoked bool,
		limit, offset int) (UIRBACDelegationView, error)
	EffectivePermissions(ctx context.Context, adminID, subjectUserID, scopeID string,
		limit, offset int) (UIRBACEffectiveView, error)
	PresetDiff(ctx context.Context, adminID, scopeID string) (UIRBACPresetDiff, error)
}

// UIRBACError 是角色/权限页面适配层返回的稳定公开错误。
type UIRBACError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIRBACError) Error() string { return "角色权限页面操作失败: " + e.Code }

// UIRBACScope 是当前管理员可选的作用范围（系统或应用）。
type UIRBACScope struct {
	ScopeID         string
	Kind            string
	ApplicationID   string
	ApplicationName string
	Active          bool
}

// UIRBACRoleQuery 是角色列表筛选/分页。
type UIRBACRoleQuery struct {
	ScopeID string
	Enabled *bool
	Limit   int
	Offset  int
}

// UIRBACPermissionQuery 是权限目录筛选/分页。
type UIRBACPermissionQuery struct {
	ScopeID string
	Enabled *bool
	Limit   int
	Offset  int
}

// UIRBACTextChange 是可修改的直白文本（名称/说明/明确限制）。
type UIRBACTextChange struct {
	Name        string
	Description string
	Limits      string
}

// UIRBACCreateRole 是角色创建白名单（ID/scope 之外的机器标识由调用方显式给出）。
type UIRBACCreateRole struct {
	ScopeID     string
	Key         string
	Name        string
	Description string
	Limits      string
}

// UIRBACPermissionView 是权限目录/来源的公开视图。
type UIRBACPermissionView struct {
	PermissionID   string
	ScopeID        string
	ScopeKind      string
	ApplicationID  string
	AppContext     string
	Key            string
	Group          string
	Name           string
	Description    string
	Limits         string
	Builtin        bool
	RootOnly       bool
	Enabled        bool
	Implemented    bool
	RequiresReauth bool
	DefaultName    string
	DefaultSummary string
	DefaultScope   string
	DefaultLimits  string
	DefaultEnabled bool
	DefaultRoles   []string
}

// UIRBACRoleView 是角色视图（含默认值与当前实际权限）。
type UIRBACRoleView struct {
	ID                 string
	ScopeID            string
	ScopeKind          string
	ApplicationID      string
	AppContext         string
	Key                string
	Name               string
	Description        string
	Limits             string
	Builtin            bool
	Enabled            bool
	IsPreset           bool
	DefaultPermissions []UIRBACPermissionView
	CurrentPermissions []UIRBACPermissionView
	UserAssignments    int
	GroupAssignments   int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UIRBACRolePage 是角色分页结果。
type UIRBACRolePage struct {
	Roles      []UIRBACRoleView
	HasMore    bool
	NextOffset int
}

// UIRBACRoleDetail 是角色详情：角色、可组合权限、当前分配。
type UIRBACRoleDetail struct {
	Role        UIRBACRoleView
	Available   []UIRBACPermissionView
	Assignments UIRBACAssignments
	// PermissionCatalogUnavailable 表示当前管理员缺少 permissions.read，权限说明/
	// 默认值与可组合列表已降级隐藏；角色与分配等 roles.read 数据仍可读取（授权语义
	// 不变：缺少该权限时不会放行任何写操作或权限详情）。
	PermissionCatalogUnavailable bool
}

// UIRBACUserAssignment 是直接分配给用户的角色记录。
type UIRBACUserAssignment struct {
	UserID        string
	DataScope     string
	DataScopeText string
	AssignedBy    string
	CreatedAt     time.Time
}

// UIRBACGroupAssignment 是通过用户组间接获得的角色记录。
type UIRBACGroupAssignment struct {
	GroupID       string
	ScopeID       string
	DataScope     string
	DataScopeText string
	CreatedAt     time.Time
}

// UIRBACAssignments 是角色的用户/用户组分配快照。
type UIRBACAssignments struct {
	Users  []UIRBACUserAssignment
	Groups []UIRBACGroupAssignment
}

// UIRBACComposeResult 是角色组合权限改动前后的真实差异。
type UIRBACComposeResult struct {
	Action         string
	Added          []UIRBACPermissionView
	Removed        []UIRBACPermissionView
	Before         []UIRBACPermissionView
	After          []UIRBACPermissionView
	AffectedUsers  int
	AffectedGroups int
}

// UIRBACAssignResult 是角色分配/撤回的真实结果。
type UIRBACAssignResult struct {
	Action        string
	TargetKind    string
	TargetID      string
	DataScope     string
	DataScopeText string
	Changed       bool
}

// UIRBACPermissionPage 是权限目录分页结果。
type UIRBACPermissionPage struct {
	Permissions []UIRBACPermissionView
	HasMore     bool
	NextOffset  int
}

// UIRBACPermissionDetail 是权限详情（含默认授予角色说明）。
type UIRBACPermissionDetail struct {
	Permission   UIRBACPermissionView
	DefaultRoles []string
}

// UIRBACDelegatable 是当前实际可转授的权限。
type UIRBACDelegatable struct {
	PermissionID     string
	Key              string
	Name             string
	MaxDataScope     string
	MaxDataScopeText string
	AllowSelf        bool
	ExpiresAt        time.Time
	ExpiresAtSet     bool
}

// UIRBACGrant 是委派资格快照（可转授资格，不等于有效权限）。
type UIRBACGrant struct {
	ID                string
	DelegatorUserID   string
	ScopeID           string
	PermissionKey     string
	PermissionName    string
	MaxDataScope      string
	MaxDataScopeText  string
	AllowSelf         bool
	Active            bool
	AllowedUserCount  int
	AllowedGroupCount int
	ExpiresAt         time.Time
	ExpiresAtSet      bool
	RevokedAt         time.Time
	RevokedAtSet      bool
	CreatedAt         time.Time
}

// UIRBACDelegationView 是委派管理视图：可使用与可转授分开。
type UIRBACDelegationView struct {
	ScopeID        string
	ScopeKind      string
	Delegatable    []UIRBACDelegatable
	Grants         []UIRBACGrant
	GrantsHasMore  bool
	NextOffset     int
	IncludeRevoked bool
	// TrustedWriteRequired 表示签发/撤回只走受信本地/系统通道（页面只读）。
	TrustedWriteRequired bool
}

// UIRBACDataScope 是数据范围公开视图；Display 是后端直白中文说明（页面不直出
// 机器枚举或原始 JSON）。
type UIRBACDataScope struct {
	Mode      string
	Display   string
	Resources []string
	Legacy    bool
}

// UIRBACSource 是权限来源（直接角色或用户组角色）。
type UIRBACSource struct {
	Kind           string
	RoleID         string
	RoleKey        string
	RoleName       string
	GroupID        string
	GroupKey       string
	GroupName      string
	Included       bool
	ExcludedReason string
	AssignedBy     string
	DataScope      UIRBACDataScope
	CreatedAt      time.Time
}

// UIRBACEffectivePermission 是一条当前实际生效的权限及来源。
type UIRBACEffectivePermission struct {
	Key       string
	Name      string
	ScopeID   string
	DataScope UIRBACDataScope
	Sources   []UIRBACSource
}

// UIRBACEffectiveView 是有效权限查询结果（含被状态限制的原因）。
type UIRBACEffectiveView struct {
	SubjectUserID         string
	ScopeID               string
	ScopeKind             string
	AccountStatus         string
	AccountStatusText     string
	ApplicationStatus     string
	ApplicationStatusText string
	MembershipStatus      string
	MembershipStatusText  string
	DeniedCode            string
	DeniedReason          string
	DeniedReasonText      string
	Permissions           []UIRBACEffectivePermission
	HasMore               bool
	NextOffset            int
	SourceLimitReached    bool
}

// UIRBACPresetRoleDiff 是预设角色默认值与当前实际值的差异。
type UIRBACPresetRoleDiff struct {
	RoleKey            string
	Name               string
	RoleID             string
	Exists             bool
	Unchanged          bool
	Protected          bool
	AddPermissions     []UIRBACPermissionView
	RemovePermissions  []UIRBACPermissionView
	DefaultPermissions []UIRBACPermissionView
	CurrentPermissions []UIRBACPermissionView
}

// UIRBACPresetSummary 是预设差异汇总。
type UIRBACPresetSummary struct {
	RoleCount           int
	ChangedRoles        int
	MissingRoles        int
	MissingPermissions  int
	DisabledPermissions int
	AddPermissions      int
	RemovePermissions   int
}

// UIRBACPresetDiff 是“恢复预设”差异（只读展示；实际恢复由受信通道执行）。
type UIRBACPresetDiff struct {
	CatalogVersion    string
	ScopeID           string
	ScopeKind         string
	Available         bool
	UnavailableReason string
	Roles             []UIRBACPresetRoleDiff
	Summary           UIRBACPresetSummary
	// ExecutionRestricted 表示页面不提供恢复执行按钮：执行只走受信本地/系统通道。
	ExecutionRestricted bool
}

// newPageRBACPages 构造步骤 69 路由/处理器。
func newPageRBACPages(options UIPageRBACOptions) (*pageRBACPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("角色权限页面缺少后端适配器")
	}
	pages := &pageRBACPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &rbacPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.roles", Method: http.MethodGet, Path: "/admin/roles",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/roles"},
		{Name: "admin.role_create", Method: http.MethodGet, Path: "/admin/roles/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/role_create"},
		{Name: "admin.role_create.submit", Method: http.MethodPost,
			Path: "/admin/roles/create", Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/role_create"},
		{Name: "admin.role_detail", Method: http.MethodGet, Path: "/admin/roles/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/role_detail"},
		{Name: "admin.role_update", Method: http.MethodPost, Path: "/admin/roles/update",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/role_detail"},
		{Name: "admin.role_state", Method: http.MethodPost, Path: "/admin/roles/state",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/role_detail"},
		{Name: "admin.role_permissions", Method: http.MethodPost,
			Path: "/admin/roles/permissions", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/role_detail"},
		{Name: "admin.role_assignments", Method: http.MethodGet,
			Path: "/admin/roles/assignments", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/role_assignments"},
		{Name: "admin.role_assign", Method: http.MethodPost,
			Path: "/admin/roles/assignments", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/role_assignments"},
		{Name: "admin.permissions", Method: http.MethodGet, Path: "/admin/permissions",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/permissions"},
		{Name: "admin.permission_detail", Method: http.MethodGet,
			Path: "/admin/permissions/detail", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/permission_detail"},
		{Name: "admin.permission_update", Method: http.MethodPost,
			Path: "/admin/permissions/update", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/permission_detail"},
		{Name: "admin.permission_state", Method: http.MethodPost,
			Path: "/admin/permissions/state", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/permission_detail"},
		{Name: "admin.delegations", Method: http.MethodGet, Path: "/admin/delegations",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/delegations"},
		{Name: "admin.access_effective", Method: http.MethodGet,
			Path: "/admin/access/effective", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/access_effective"},
		{Name: "admin.preset_diff", Method: http.MethodGet, Path: "/admin/presets/diff",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/preset_diff"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageRBACPages 是角色权限页实现。
type pageRBACPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageRBACOptions
}

// rbacPageHandlers 实现角色权限页处理器。
type rbacPageHandlers struct {
	pages *pageRBACPages
}

// HandlePage 按路由分派。
func (h *rbacPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.roles":
		return h.roles(ctx, request, page)
	case "admin.role_create", "admin.role_create.submit":
		return h.roleCreate(ctx, request, page)
	case "admin.role_detail":
		return h.roleDetail(ctx, request, page)
	case "admin.role_update":
		return h.roleUpdate(ctx, request, page)
	case "admin.role_state":
		return h.roleState(ctx, request, page)
	case "admin.role_permissions":
		return h.roleCompose(ctx, request, page)
	case "admin.role_assignments":
		return h.roleAssignments(ctx, request, page)
	case "admin.role_assign":
		return h.roleAssign(ctx, request, page)
	case "admin.permissions":
		return h.permissions(ctx, request, page)
	case "admin.permission_detail":
		return h.permissionDetail(ctx, request, page)
	case "admin.permission_update":
		return h.permissionUpdate(ctx, request, page)
	case "admin.permission_state":
		return h.permissionState(ctx, request, page)
	case "admin.delegations":
		return h.delegations(ctx, request, page)
	case "admin.access_effective":
		return h.accessEffective(ctx, request, page)
	case "admin.preset_diff":
		return h.presetDiff(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// ===== 角色 =====

// roles 渲染角色列表（作用范围/启停筛选 + 分页）。
func (h *rbacPageHandlers) roles(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := UIRBACRoleQuery{ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")),
		Limit: 20}
	if raw := request.URL.Query().Get("enabled"); raw == "1" || raw == "0" {
		enabled := raw == "1"
		query.Enabled = &enabled
	}
	offset, ok := parseRBACOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	query.Offset = offset
	result, err := h.pages.options.Backend.ListRoles(ctx, page.Session.UserID, query)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.roles_load_failed"), nil
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"roles": result.Roles,
		"hasMore": result.HasMore, "nextOffset": result.NextOffset,
		"scopeID": query.ScopeID, "enabled": request.URL.Query().Get("enabled"),
		"scopes": scopes}}, nil
}

// roleCreate 创建自定义角色（机器键/scope 创建后不可变）。
func (h *rbacPageHandlers) roleCreate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if request.Method != http.MethodPost {
		scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
		if err != nil {
			return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"scopes": scopes,
			"scopeID": strings.TrimSpace(request.URL.Query().Get("scope_id"))}}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"scope_id", "role_key",
		"name", "description", "limits"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	create := UIRBACCreateRole{ScopeID: strings.TrimSpace(form.Get("scope_id")),
		Key: strings.TrimSpace(form.Get("role_key")), Name: strings.TrimSpace(form.Get("name")),
		Description: strings.TrimSpace(form.Get("description")),
		Limits:      strings.TrimSpace(form.Get("limits"))}
	if create.Name == "" || create.Key == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.role_required")}, nil
	}
	created, err := h.pages.options.Backend.CreateRole(ctx, page.Session.UserID, create,
		page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.role_create_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"role": created},
		RedirectPath: "/admin/roles/detail", RedirectQuery: url.Values{
			"role_id": {created.ID}, "status": {"created"}}}, nil
}

// roleDetail 渲染角色详情（默认/当前权限、可组合权限、分配影响）。
func (h *rbacPageHandlers) roleDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderRoleDetail(ctx, request, page, nil, nil)
}

// renderRoleDetail 读取角色详情并注入附加结果（改动前后/状态结果）。
func (h *rbacPageHandlers) renderRoleDetail(ctx context.Context, request *http.Request,
	page UIPageContext, extra map[string]any, status url.Values) (UIPageOutcome, error) {
	roleID := strings.TrimSpace(request.URL.Query().Get("role_id"))
	if roleID == "" && request.Method == http.MethodPost {
		roleID = strings.TrimSpace(request.FormValue("role_id"))
	}
	detail, err := h.pages.options.Backend.GetRole(ctx, page.Session.UserID, roleID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.role_load_failed"), nil
	}
	data := map[string]any{"role": detail.Role, "available": detail.Available,
		"assignments":                  detail.Assignments,
		"permissionCatalogUnavailable": detail.PermissionCatalogUnavailable,
		"status":                       request.URL.Query().Get("status")}
	if status != nil {
		if value := status.Get("status"); value != "" {
			data["status"] = value
		}
	}
	for key, value := range extra {
		data[key] = value
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	data["scopes"] = scopes
	return UIPageOutcome{Data: data}, nil
}

// roleUpdate 保存角色直白名称/说明/明确限制（不含机器键/范围）。
func (h *rbacPageHandlers) roleUpdate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"role_id", "name",
		"description", "limits"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	roleID := strings.TrimSpace(form.Get("role_id"))
	if roleID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	change := UIRBACTextChange{Name: strings.TrimSpace(form.Get("name")),
		Description: strings.TrimSpace(form.Get("description")),
		Limits:      strings.TrimSpace(form.Get("limits"))}
	updated, err := h.pages.options.Backend.UpdateRole(ctx, page.Session.UserID, roleID,
		change, page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, emptyRoleDetailData(),
			"page.admin.rbac.role_update_failed"), nil
	}
	return h.renderRoleDetail(ctx, request, page, map[string]any{"updated": updated},
		url.Values{"status": {"updated"}})
}

// roleState 启用/停用角色（停用需确认；停用后既有分配不再生效）。
func (h *rbacPageHandlers) roleState(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"role_id", "action",
		"confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	roleID := strings.TrimSpace(form.Get("role_id"))
	action := form.Get("action")
	if roleID == "" || (action != "enable" && action != "disable") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	if action == "disable" && form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.role_disable_confirm_required")}, nil
	}
	updated, changed, err := h.pages.options.Backend.SetRoleState(ctx, page.Session.UserID,
		roleID, action == "enable", page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, emptyRoleDetailData(),
			"page.admin.rbac.role_state_failed"), nil
	}
	return h.renderRoleDetail(ctx, request, page, map[string]any{"updated": updated,
		"stateChanged": changed}, url.Values{"status": {action}})
}

// roleCompose 向角色组合/移除权限，并展示改动前后的权限与受影响分配。
func (h *rbacPageHandlers) roleCompose(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"role_id",
		"permission_id", "action", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	roleID := strings.TrimSpace(form.Get("role_id"))
	permissionID := strings.TrimSpace(form.Get("permission_id"))
	action := form.Get("action")
	if roleID == "" || permissionID == "" || (action != "add" && action != "remove") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyRoleDetailData(),
			ErrorSummary: text("page.admin.rbac.compose_confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.ComposeRolePermission(ctx, page.Session.UserID,
		roleID, permissionID, action == "add", page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, emptyRoleDetailData(),
			"page.admin.rbac.compose_failed"), nil
	}
	return h.renderRoleDetail(ctx, request, page, map[string]any{"compose": result},
		url.Values{"status": {"composed"}})
}

// roleAssignments 渲染角色分配页（直接用户与用户组分开，含数据范围）。
func (h *rbacPageHandlers) roleAssignments(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderAssignments(ctx, request, page, nil)
}

// renderAssignments 读取角色与分配快照。
func (h *rbacPageHandlers) renderAssignments(ctx context.Context, request *http.Request,
	page UIPageContext, extra map[string]any) (UIPageOutcome, error) {
	roleID := strings.TrimSpace(request.URL.Query().Get("role_id"))
	if roleID == "" && request.Method == http.MethodPost {
		roleID = strings.TrimSpace(request.FormValue("role_id"))
	}
	detail, err := h.pages.options.Backend.GetRole(ctx, page.Session.UserID, roleID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.role_load_failed"), nil
	}
	assignments, err := h.pages.options.Backend.ListAssignments(ctx, page.Session.UserID, roleID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.assignments_load_failed"), nil
	}
	data := map[string]any{"role": detail.Role, "assignments": assignments,
		"status": request.URL.Query().Get("status")}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// roleAssign 分配/撤回角色到实际用户或用户组（确认绑定实际目标）。
func (h *rbacPageHandlers) roleAssign(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"role_id",
		"target_kind", "target_id", "action", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyAssignmentData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	roleID := strings.TrimSpace(form.Get("role_id"))
	targetKind := form.Get("target_kind")
	targetID := strings.TrimSpace(form.Get("target_id"))
	action := form.Get("action")
	if roleID == "" || targetID == "" ||
		(targetKind != "user" && targetKind != "group") ||
		(action != "assign" && action != "revoke") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyAssignmentData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: emptyAssignmentData(),
			ErrorSummary: text("page.admin.rbac.assign_confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.AssignRole(ctx, page.Session.UserID, roleID,
		targetKind, targetID, page.RequestID, action == "assign")
	if err != nil {
		return rbacErrorOutcome(err, emptyAssignmentData(),
			"page.admin.rbac.assign_failed"), nil
	}
	return h.renderAssignments(ctx, request, page, map[string]any{"assign": result})
}

// ===== 权限目录 =====

// permissions 渲染权限目录（作用范围/启停筛选 + 分页，应用同名权限带应用上下文）。
func (h *rbacPageHandlers) permissions(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := UIRBACPermissionQuery{
		ScopeID: strings.TrimSpace(request.URL.Query().Get("scope_id")), Limit: 20}
	if raw := request.URL.Query().Get("enabled"); raw == "1" || raw == "0" {
		enabled := raw == "1"
		query.Enabled = &enabled
	}
	offset, ok := parseRBACOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	query.Offset = offset
	result, err := h.pages.options.Backend.ListPermissions(ctx, page.Session.UserID, query)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.permissions_load_failed"), nil
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"permissions": result.Permissions,
		"hasMore": result.HasMore, "nextOffset": result.NextOffset,
		"scopeID": query.ScopeID, "enabled": request.URL.Query().Get("enabled"),
		"scopes": scopes}}, nil
}

// permissionDetail 渲染权限详情（说明、生效范围、不能做什么、默认/当前值）。
func (h *rbacPageHandlers) permissionDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderPermissionDetail(ctx, request, page, nil, nil)
}

// renderPermissionDetail 读取权限详情并注入附加结果。
func (h *rbacPageHandlers) renderPermissionDetail(ctx context.Context,
	request *http.Request, page UIPageContext, extra map[string]any,
	status url.Values) (UIPageOutcome, error) {
	permissionID := strings.TrimSpace(request.URL.Query().Get("permission_id"))
	if permissionID == "" && request.Method == http.MethodPost {
		permissionID = strings.TrimSpace(request.FormValue("permission_id"))
	}
	detail, err := h.pages.options.Backend.GetPermission(ctx, page.Session.UserID, permissionID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.permission_load_failed"), nil
	}
	data := map[string]any{"permission": detail.Permission,
		"defaultRoles": detail.DefaultRoles,
		"status":       request.URL.Query().Get("status")}
	if status != nil {
		if value := status.Get("status"); value != "" {
			data["status"] = value
		}
	}
	for key, value := range extra {
		data[key] = value
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	data["scopes"] = scopes
	return UIPageOutcome{Data: data}, nil
}

// permissionUpdate 修改自定义权限的直白名称/说明/明确限制（内置权限由后端拒绝）。
func (h *rbacPageHandlers) permissionUpdate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"permission_id", "name",
		"description", "limits"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         emptyPermissionDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	permissionID := strings.TrimSpace(form.Get("permission_id"))
	if permissionID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         emptyPermissionDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	change := UIRBACTextChange{Name: strings.TrimSpace(form.Get("name")),
		Description: strings.TrimSpace(form.Get("description")),
		Limits:      strings.TrimSpace(form.Get("limits"))}
	updated, err := h.pages.options.Backend.UpdatePermission(ctx, page.Session.UserID,
		permissionID, change, page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, emptyPermissionDetailData(),
			"page.admin.rbac.permission_update_failed"), nil
	}
	return h.renderPermissionDetail(ctx, request, page, map[string]any{"updated": updated},
		url.Values{"status": {"updated"}})
}

// permissionState 启用/停用权限（停用需确认；停用后角色组合不再生效）。
func (h *rbacPageHandlers) permissionState(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"permission_id",
		"action", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         emptyPermissionDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	permissionID := strings.TrimSpace(form.Get("permission_id"))
	action := form.Get("action")
	if permissionID == "" || (action != "enable" && action != "disable") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         emptyPermissionDetailData(),
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	if action == "disable" && form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			Data:         emptyPermissionDetailData(),
			ErrorSummary: text("page.admin.rbac.permission_disable_confirm_required")}, nil
	}
	updated, changed, err := h.pages.options.Backend.SetPermissionState(ctx,
		page.Session.UserID, permissionID, action == "enable", page.RequestID)
	if err != nil {
		return rbacErrorOutcome(err, emptyPermissionDetailData(),
			"page.admin.rbac.permission_state_failed"), nil
	}
	return h.renderPermissionDetail(ctx, request, page, map[string]any{"updated": updated,
		"stateChanged": changed}, url.Values{"status": {action}})
}

// ===== 委派 =====

// delegations 渲染委派管理：可使用与可转授分开，签发/撤回只走受信通道。
func (h *rbacPageHandlers) delegations(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	scopeID := strings.TrimSpace(request.URL.Query().Get("scope_id"))
	if scopeID == "" {
		scopeID = "system"
	}
	includeRevoked := request.URL.Query().Get("include_revoked") == "1"
	offset, ok := parseRBACOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	view, err := h.pages.options.Backend.DelegationView(ctx, page.Session.UserID, scopeID,
		includeRevoked, 20, offset)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.delegations_load_failed"), nil
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"delegation": view, "scopes": scopes,
		"scopeID": scopeID, "includeRevoked": includeRevoked}}, nil
}

// ===== 有效权限 =====

// accessEffective 查询指定主体在指定范围内的当前实际权限与来源。
func (h *rbacPageHandlers) accessEffective(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := request.URL.Query()
	subjectUserID := strings.TrimSpace(query.Get("subject_user_id"))
	scopeID := strings.TrimSpace(query.Get("scope_id"))
	data := map[string]any{"subjectUserID": subjectUserID, "scopeID": scopeID,
		"queried": false}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	data["scopes"] = scopes
	if subjectUserID == "" {
		// 未指定目标时只渲染查询表单，不猜测或列出他人权限。
		return UIPageOutcome{Data: data}, nil
	}
	if scopeID == "" {
		scopeID = "system"
		data["scopeID"] = scopeID
	}
	offset, ok := parseRBACOffset(query.Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.rbac.invalid")}, nil
	}
	view, err := h.pages.options.Backend.EffectivePermissions(ctx, page.Session.UserID,
		subjectUserID, scopeID, 20, offset)
	if err != nil {
		return rbacErrorOutcome(err, data, "page.admin.rbac.effective_failed"), nil
	}
	data["effective"] = view
	data["queried"] = true
	return UIPageOutcome{Data: data}, nil
}

// ===== 预设差异 =====

// presetDiff 展示“恢复预设”默认值与当前实际值的差异；执行仅受信通道。
func (h *rbacPageHandlers) presetDiff(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	scopeID := strings.TrimSpace(request.URL.Query().Get("scope_id"))
	if scopeID == "" {
		scopeID = "system"
	}
	diff, err := h.pages.options.Backend.PresetDiff(ctx, page.Session.UserID, scopeID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.preset_load_failed"), nil
	}
	scopes, err := h.pages.options.Backend.ListScopes(ctx, page.Session.UserID)
	if err != nil {
		return rbacErrorOutcome(err, nil, "page.admin.rbac.scopes_load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"diff": diff, "scopes": scopes,
		"scopeID": scopeID}}, nil
}

// ===== 辅助 =====

// parseRBACOffset 解析深分页上限内的非负偏移。
func parseRBACOffset(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 1_000_000 {
		return 0, false
	}
	return value, true
}

// emptyRoleDetailData 返回错误页可安全渲染的角色详情空数据（不伪造具体对象）。
func emptyRoleDetailData() map[string]any {
	return map[string]any{"role": UIRBACRoleView{},
		"available": []UIRBACPermissionView{}, "assignments": UIRBACAssignments{},
		"scopes": []UIRBACScope{}}
}

// emptyAssignmentData 返回错误页可安全渲染的分配页空数据。
func emptyAssignmentData() map[string]any {
	return map[string]any{"role": UIRBACRoleView{}, "assignments": UIRBACAssignments{},
		"scopes": []UIRBACScope{}}
}

// emptyPermissionDetailData 返回错误页可安全渲染的权限详情空数据。
func emptyPermissionDetailData() map[string]any {
	return map[string]any{"permission": UIRBACPermissionView{}, "defaultRoles": []string{},
		"scopes": []UIRBACScope{}}
}

// rbacErrorOutcome 把适配器错误映射为稳定状态/已翻译文案（只披露允许公开的原因）。
func rbacErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UIRBACError
	if errors.As(err, &publicErr) {
		outcome.ErrorCode = publicErr.Code
		switch publicErr.Code {
		case "ACCESS_DENIED", "RESOURCE_FORBIDDEN":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.rbac.common.forbidden")
		case "PERMISSION_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.rbac.common.permission_required")
		case "REAUTH_REQUIRED", "MFA_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.rbac.common.reauth_required")
		case "CONFLICT":
			outcome.ErrorSummary = text("page.admin.rbac.common.conflict")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorSummary = text("common.state.rate_limited")
		case "USER_DISABLED", "CLIENT_DISABLED", "APP_MEMBERSHIP_REQUIRED",
			"APP_SCOPE_MISMATCH":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.rbac.common.scope_unavailable")
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED", "AUTHZ_UNAVAILABLE":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorSummary = text("page.account.common.unavailable")
		case "INTERNAL_ERROR":
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorSummary = text("common.state.error")
		default:
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorSummary = text(fallbackKey)
		}
	}
	return outcome
}

// builtinRBACMessages 是角色权限页摘要使用的中文基线（模板静态文案仍走 i18n 键）。
var builtinRBACMessages = map[string]string{
	"page.admin.rbac.common.forbidden": "你没有执行该操作的权限，或管理强认证已过期；服务端已拒绝",
	"page.admin.rbac.common.permission_required": "缺少该权限的转授资格，或操作者当前不持有该权限；" +
		"拥有权限不等于可以转授",
	"page.admin.rbac.common.reauth_required":              "该操作需要重新完成强认证，请按提示重新验证",
	"page.admin.rbac.common.conflict":                     "数据已被其他操作修改，请重新读取后再试",
	"page.admin.rbac.common.scope_unavailable":            "当前作用范围或目标状态不可用（应用/成员/范围已停用或不匹配）",
	"page.admin.rbac.invalid":                             "请求参数无效",
	"page.admin.rbac.scopes_load_failed":                  "无法读取可管理作用范围，请稍后重试",
	"page.admin.rbac.roles_load_failed":                   "无法读取角色列表，请稍后重试",
	"page.admin.rbac.role_load_failed":                    "无法读取角色详情，请重新读取后再试",
	"page.admin.rbac.role_required":                       "请填写角色机器键与中文名称",
	"page.admin.rbac.role_create_failed":                  "创建角色未完成，请检查输入",
	"page.admin.rbac.role_update_failed":                  "保存角色资料未完成，请重新读取后再试",
	"page.admin.rbac.role_disable_confirm_required":       "停用角色会使其分配不再生效，请先确认影响",
	"page.admin.rbac.role_state_failed":                   "角色状态操作未完成",
	"page.admin.rbac.compose_confirm_required":            "请先确认本次权限组合改动的影响",
	"page.admin.rbac.compose_failed":                      "权限组合未完成；缺少转授资格或权限不可组合",
	"page.admin.rbac.assignments_load_failed":             "无法读取角色分配，请稍后重试",
	"page.admin.rbac.assign_confirm_required":             "请先确认分配目标、作用范围与权限影响",
	"page.admin.rbac.assign_failed":                       "角色分配未完成；目标不合格、自我提权或越权均会被拒绝",
	"page.admin.rbac.permissions_load_failed":             "无法读取权限目录，请稍后重试",
	"page.admin.rbac.permission_load_failed":              "无法读取权限详情",
	"page.admin.rbac.permission_update_failed":            "保存权限说明未完成（内置权限不可修改）",
	"page.admin.rbac.permission_disable_confirm_required": "停用权限会使其角色组合不再生效，请先确认影响",
	"page.admin.rbac.permission_state_failed":             "权限状态操作未完成",
	"page.admin.rbac.delegations_load_failed":             "无法读取委派资格与可转授权限",
	"page.admin.rbac.effective_failed":                    "无法查询该主体的有效权限；目标不存在或未获准查询",
	"page.admin.rbac.preset_load_failed":                  "无法读取预设差异",
}

func init() {
	for key, message := range builtinRBACMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}
