package login

// 步骤 68：用户管理、注册审核与用户组管理页面（ui.v1 兼容新增）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话+强认证新鲜度；页面不凭前端状态放行。
//   - 每次读/写由 UIAdminBackend 适配器在服务端重新构造可信 Caller、复核管理授权与
//     数据范围（宿主注入）；越权/跨范围/root 保护一律 fail-closed。
//   - 删除两阶段（请求删除→预览→完成），始终携带 ExpectedRowVersion；组删除影响
//     计数缺失时明确不精确，不写 0。
//   - 所有写操作单一 csrf_token + 服务端 request_id；重复提交/迟到响应不得二次写入。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UIPageAdminOptions 是步骤 68 管理页配置。
type UIPageAdminOptions struct {
	Backend UIAdminBackend
}

// UIAdminBackend 是管理页面调用真实管理服务的最小契约；适配器负责可信 Caller、
// 管理授权与数据范围复核。
type UIAdminBackend interface {
	ListUsers(ctx context.Context, adminID string, query UIAdminUserQuery) (UIAdminUserPage, error)
	CreateUser(ctx context.Context, adminID string, create UIAdminCreateUser) (UIAdminUserView, error)
	GetUser(ctx context.Context, adminID, userID string) (UIAdminUserView, error)
	UpdateUser(ctx context.Context, adminID, userID string, change UIProfileChange,
		expectedRowVersion int64, requestID string) (UIAdminUserView, error)
	SetUserState(ctx context.Context, adminID, userID, action string, expectedRowVersion int64,
		requestID string) (UIAdminUserView, bool, error)
	PreviewDeletion(ctx context.Context, adminID, userID string) (UIAdminDeletionPreview, error)
	CompleteDeletion(ctx context.Context, adminID, userID string, expectedRowVersion int64,
		requestID string) (UIAdminDeletionPreview, error)
	ListReviews(ctx context.Context, adminID string, limit, offset int) (UIAdminReviewPage, error)
	GetReview(ctx context.Context, adminID, userID string) (UIAdminReview, error)
	DecideReview(ctx context.Context, adminID, userID string, approve bool, reason, appID string,
		roles []string, requestID string) (UIAdminReviewDecision, error)
	ListGroups(ctx context.Context, adminID, scopeID string, limit, offset int) (UIAdminGroupPage, error)
	CreateGroup(ctx context.Context, adminID, scopeID, groupKey, name, description,
		requestID string) (UIAdminGroup, error)
	GetGroup(ctx context.Context, adminID, groupID string) (UIAdminGroup, error)
	UpdateGroup(ctx context.Context, adminID, groupID, name, description,
		requestID string) (UIAdminGroup, error)
	DeleteGroup(ctx context.Context, adminID, groupID, requestID string) error
	ListMembers(ctx context.Context, adminID, groupID string, limit, offset int) (UIAdminMemberPage, error)
	AddMembers(ctx context.Context, adminID, groupID string, userIDs []string,
		requestID string) (UIAdminMemberResult, error)
	RemoveMembers(ctx context.Context, adminID, groupID string, userIDs []string,
		requestID string) (UIAdminMemberResult, error)
	PrecheckImport(ctx context.Context, adminID string, content []byte) (UIAdminParseReport, error)
	StartImport(ctx context.Context, adminID string, content []byte, idempotencyKey,
		requestID string) (UIAdminBatchStart, error)
	StartExport(ctx context.Context, adminID string, options UIAdminExportOptions,
		requestID string) (UIAdminBatchStart, error)
	ListJobs(ctx context.Context, adminID, kind string, limit, offset int) (UIAdminBatchPage, error)
	GetJob(ctx context.Context, adminID, jobID string) (UIAdminBatchJob, error)
	ListRows(ctx context.Context, adminID, jobID string, limit, offset int) ([]UIAdminBatchRow, bool, error)
	ReportCSV(ctx context.Context, adminID, jobID string) ([]byte, bool, error)
	CancelJob(ctx context.Context, adminID, jobID, reason, requestID string) error
	RetryJob(ctx context.Context, adminID, jobID, requestID string) (UIAdminBatchJob, error)
}

// UIAdminError 是管理适配层返回的稳定公开错误。
type UIAdminError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIAdminError) Error() string { return "管理页面操作失败: " + e.Code }

// UIAdminUserView 是管理页用户公开视图（无 Email/Phone/IsRoot）。
type UIAdminUserView struct {
	UserID     string
	Username   string
	Nickname   string
	Biography  string
	Language   string
	Timezone   string
	Phone      string
	Status     string
	RowVersion int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UIAdminCreateUser 是创建用户白名单。
type UIAdminCreateUser struct {
	Username  string
	Nickname  string
	Biography string
	Language  string
	Timezone  string
}

// UIAdminUserQuery 是用户列表筛选/分页。
type UIAdminUserQuery struct {
	Status     string
	Sort       string
	Descending bool
	Limit      int
	Offset     int
}

// UIAdminUserPage 是分页结果（HasMore，无总数）。
type UIAdminUserPage struct {
	Users   []UIAdminUserView
	HasMore bool
}

// UIAdminDeletionPreview 是删除影响快照。
type UIAdminDeletionPreview struct {
	UserID             string
	Username           string
	Status             string
	RowVersion         int64
	SecurityVersion    int64
	IsRoot             bool
	AppMemberships     int
	UserRoles          int
	GroupMemberships   int
	OneTimeCredentials int
	OwnedApplications  int
	DeletedAt          time.Time
}

// UIAdminReview 是待审核账户视图。
type UIAdminReview struct {
	UserID       string
	Username     string
	Status       string
	ReviewStatus string
	Reason       string
	CreatedAt    time.Time
	NotifyState  string
	NotifyError  string
}

// UIAdminReviewPage 是待审核分页结果。
type UIAdminReviewPage struct {
	Reviews []UIAdminReview
	HasMore bool
}

// UIAdminReviewDecision 是审核真实结果（审核事实与通知状态分开）。
type UIAdminReviewDecision struct {
	Review    UIAdminReview
	Notified  bool
	ErrorCode string
}

// UIAdminGroup 是用户组视图。
type UIAdminGroup struct {
	ID          string
	ScopeID     string
	ScopeKind   string
	AppID       string
	GroupKey    string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UIAdminGroupPage 是组分页结果。
type UIAdminGroupPage struct {
	Groups  []UIAdminGroup
	HasMore bool
}

// UIAdminMember 是组成员视图。
type UIAdminMember struct {
	GroupID   string
	UserID    string
	CreatedAt time.Time
}

// UIAdminMemberPage 是成员分页结果。
type UIAdminMemberPage struct {
	Members []UIAdminMember
	HasMore bool
}

// UIAdminMemberResult 是成员原子批量结果。
type UIAdminMemberResult struct {
	Added   int
	Removed int
	Skipped int
}

// UIAdminParseError 是导入预检查错误（无原始行内容）。
type UIAdminParseError struct {
	Line   int
	Column string
	Code   string
	Reason string
}

// UIAdminParseReport 是 CSV 预检查结果。
type UIAdminParseReport struct {
	Headers      []string
	TotalRows    int
	RejectedRows int
	CanImport    bool
	Truncated    bool
	Errors       []UIAdminParseError
}

// UIAdminBatchStart 是创建批量任务结果。
type UIAdminBatchStart struct {
	JobID     string
	Kind      string
	State     string
	TotalRows int
	Duplicate bool
	Report    UIAdminParseReport
}

// UIAdminBatchJob 是批量任务状态快照。
type UIAdminBatchJob struct {
	JobID          string
	Kind           string
	State          string
	TotalRows      int
	CreatedCount   int
	SkippedCount   int
	ConflictCount  int
	FailedCount    int
	DeniedCount    int
	Truncated      bool
	ExportSHA256   string
	ExportRows     int
	ErrorCode      string
	TaskID         string
	InputAvailable bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UIAdminBatchRow 是逐行结果（不含原始行）。
type UIAdminBatchRow struct {
	RowNumber          int
	Action             string
	ErrorCode          string
	ReasonCode         string
	UsernameNormalized string
	UserID             string
}

// UIAdminBatchPage 是任务列表分页。
type UIAdminBatchPage struct {
	Jobs    []UIAdminBatchJob
	HasMore bool
}

// UIAdminExportOptions 是导出选项（字段只能从后端白名单减少）。
type UIAdminExportOptions struct {
	Fields          []string
	IncludeFreeText bool
	MaxRows         int
	IdempotencyKey  string
}

// newPageAdminPages 构造步骤 68 路由/处理器。
func newPageAdminPages(options UIPageAdminOptions) (*pageAdminPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("管理页面缺少后端适配器")
	}
	pages := &pageAdminPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &adminPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.users", Method: http.MethodGet, Path: "/admin/users",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/users"},
		{Name: "admin.user_create", Method: http.MethodGet, Path: "/admin/users/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/user_create"},
		{Name: "admin.user_create.submit", Method: http.MethodPost,
			Path: "/admin/users/create", Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/user_create"},
		{Name: "admin.user_detail", Method: http.MethodGet, Path: "/admin/users/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/user_detail"},
		{Name: "admin.user_update", Method: http.MethodPost, Path: "/admin/users/update",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/user_detail"},
		{Name: "admin.user_state", Method: http.MethodPost, Path: "/admin/users/state",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/user_detail"},
		{Name: "admin.user_delete_preview", Method: http.MethodGet,
			Path: "/admin/users/delete-preview", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/user_delete"},
		{Name: "admin.user_delete", Method: http.MethodPost, Path: "/admin/users/delete",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/user_detail"},
		{Name: "admin.reviews", Method: http.MethodGet, Path: "/admin/reviews",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/reviews"},
		{Name: "admin.review_detail", Method: http.MethodGet, Path: "/admin/reviews/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/review_detail"},
		{Name: "admin.review_decide", Method: http.MethodPost, Path: "/admin/reviews/decide",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/reviews"},
		{Name: "admin.groups", Method: http.MethodGet, Path: "/admin/groups",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/groups"},
		{Name: "admin.group_create", Method: http.MethodPost, Path: "/admin/groups/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/groups"},
		{Name: "admin.group_detail", Method: http.MethodGet, Path: "/admin/groups/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/group_detail"},
		{Name: "admin.group_update", Method: http.MethodPost, Path: "/admin/groups/update",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/group_detail"},
		{Name: "admin.group_members", Method: http.MethodPost, Path: "/admin/groups/members",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/group_detail"},
		{Name: "admin.group_delete", Method: http.MethodPost, Path: "/admin/groups/delete",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/groups"},
		{Name: "admin.user_import", Method: http.MethodGet, Path: "/admin/users/import",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/import"},
		{Name: "admin.user_import.submit", Method: http.MethodPost,
			Path: "/admin/users/import", Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/import"},
		{Name: "admin.user_export", Method: http.MethodGet, Path: "/admin/users/export",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/export"},
		{Name: "admin.user_export.submit", Method: http.MethodPost,
			Path: "/admin/users/export", Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/export"},
		{Name: "admin.user_batch", Method: http.MethodGet, Path: "/admin/users/batch",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/batch"},
		{Name: "admin.user_batch_detail", Method: http.MethodGet,
			Path: "/admin/users/batch/detail", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/batch_detail"},
		{Name: "admin.user_batch_action", Method: http.MethodPost,
			Path: "/admin/users/batch/action", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/batch_detail"},
		{Name: "admin.user_batch_report", Method: http.MethodGet,
			Path: "/admin/users/batch/report", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/batch_detail"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageAdminPages 是管理页实现。
type pageAdminPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAdminOptions
}

// adminPageHandlers 实现管理页处理器。
type adminPageHandlers struct {
	pages *pageAdminPages
}

// HandlePage 按路由分派。
func (h *adminPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.users":
		return h.users(ctx, request, page)
	case "admin.user_create", "admin.user_create.submit":
		return h.userCreate(ctx, request, page)
	case "admin.user_detail":
		return h.userDetail(ctx, request, page)
	case "admin.user_update":
		return h.userUpdate(ctx, request, page)
	case "admin.user_state":
		return h.userState(ctx, request, page)
	case "admin.user_delete_preview":
		return h.deletePreview(ctx, request, page)
	case "admin.user_delete":
		return h.deleteComplete(ctx, request, page)
	case "admin.reviews":
		return h.reviews(ctx, request, page)
	case "admin.review_detail":
		return h.reviewDetail(ctx, request, page)
	case "admin.review_decide":
		return h.reviewDecide(ctx, request, page)
	case "admin.groups", "admin.group_create":
		return h.groups(ctx, request, page)
	case "admin.group_detail", "admin.group_update", "admin.group_members":
		return h.groupDetail(ctx, request, page)
	case "admin.group_delete":
		return h.groupDelete(ctx, request, page)
	case "admin.user_import", "admin.user_import.submit":
		return h.userImport(ctx, request, page)
	case "admin.user_export", "admin.user_export.submit":
		return h.userExport(ctx, request, page)
	case "admin.user_batch":
		return h.userBatch(ctx, request, page)
	case "admin.user_batch_detail", "admin.user_batch_action":
		return h.userBatchDetail(ctx, request, page)
	case "admin.user_batch_report":
		return h.userBatchReport(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// users 渲染状态筛选+受控排序+分页列表。
func (h *adminPageHandlers) users(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := UIAdminUserQuery{Status: request.URL.Query().Get("status"),
		Sort: request.URL.Query().Get("sort"), Limit: 20,
		Descending: request.URL.Query().Get("desc") == "1"}
	if raw := request.URL.Query().Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 1000000 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.users.invalid")}, nil
		}
		query.Offset = offset
	}
	result, err := h.pages.options.Backend.ListUsers(ctx, page.Session.UserID, query)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed"), nil
	}
	nextOffset := query.Offset + len(result.Users)
	prevOffset := query.Offset - query.Limit
	if prevOffset < 0 {
		prevOffset = 0
	}
	return UIPageOutcome{Data: map[string]any{"users": result.Users,
		"hasMore": result.HasMore, "query": query, "nextOffset": nextOffset,
		"offset": query.Offset, "hasPrevious": query.Offset > 0,
		"prevOffset": prevOffset}}, nil
}

// userCreate 创建账户资料（五字段白名单，不设密码/角色/成员）。
func (h *adminPageHandlers) userCreate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: map[string]any{}}, nil
	}
	form, formErr := readPageForm(request, page.CSRFField, []string{"username", "nickname",
		"biography", "language", "timezone"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	username := strings.TrimSpace(form.Get("username"))
	if username == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	created, err := h.pages.options.Backend.CreateUser(ctx, page.Session.UserID,
		UIAdminCreateUser{Username: username, Nickname: form.Get("nickname"),
			Biography: form.Get("biography"), Language: form.Get("language"),
			Timezone: form.Get("timezone")})
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.create_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"created": created},
		RedirectPath: "/admin/users/detail", RedirectQuery: url.Values{"user_id": {created.UserID},
			"status": {"created"}}}, nil
}

// userDetail 渲染详情（编辑/状态/删除入口）。
func (h *adminPageHandlers) userDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := request.URL.Query().Get("user_id")
	view, err := h.pages.options.Backend.GetUser(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"user": view,
		"status": request.URL.Query().Get("status")}}, nil
}

// userUpdate 编辑白名单资料（ExpectedRowVersion）。
func (h *adminPageHandlers) userUpdate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := request.URL.Query().Get("user_id")
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id", "nickname",
		"biography", "language", "timezone", "phone", "row_version"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	if userID == "" {
		userID = form.Get("user_id")
	}
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if userID == "" || versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	change := UIProfileChange{}
	if values, ok := form["nickname"]; ok {
		change.Nickname = stringPointer(values[0])
	}
	if values, ok := form["biography"]; ok {
		change.Biography = stringPointer(values[0])
	}
	if values, ok := form["language"]; ok {
		change.Language = stringPointer(values[0])
	}
	if values, ok := form["timezone"]; ok {
		change.Timezone = stringPointer(values[0])
	}
	if values, ok := form["phone"]; ok {
		change.Phone = stringPointer(values[0])
	}
	updated, err := h.pages.options.Backend.UpdateUser(ctx, page.Session.UserID, userID,
		change, version, page.RequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.update_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"user": updated},
		RedirectPath:  "/admin/users/detail",
		RedirectQuery: url.Values{"user_id": {userID}, "status": {"updated"}}}, nil
}

// userState 执行禁用/启用/请求删除（独立确认 + 行版本）。
func (h *adminPageHandlers) userState(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id", "action",
		"row_version"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	userID, action := form.Get("user_id"), form.Get("action")
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if userID == "" || versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	switch action {
	case "disable", "enable", "request_delete":
	default:
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	updated, changed, err := h.pages.options.Backend.SetUserState(ctx,
		page.Session.UserID, userID, action, version, page.RequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.state_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"user": updated, "changed": changed},
		RedirectPath:  "/admin/users/detail",
		RedirectQuery: url.Values{"user_id": {userID}, "status": {action}}}, nil
}

// deletePreview 读取真实删除影响快照。
func (h *adminPageHandlers) deletePreview(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := request.URL.Query().Get("user_id")
	preview, err := h.pages.options.Backend.PreviewDeletion(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.delete_preview_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"preview": preview}}, nil
}

// deleteComplete 完成不可逆删除（版本+最新预览保护由服务端保证）。
func (h *adminPageHandlers) deleteComplete(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id", "row_version",
		"confirm_delete"})
	if formErr != nil || form.Get("confirm_delete") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.delete_confirm_required")}, nil
	}
	userID := form.Get("user_id")
	version, versionErr := parseRowVersion(form.Get("row_version"))
	if userID == "" || versionErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.users.invalid")}, nil
	}
	preview, err := h.pages.options.Backend.CompleteDeletion(ctx, page.Session.UserID,
		userID, version, page.RequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.users.delete_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"preview": preview, "deleted": true}}, nil
}

// reviews 列出待审核申请。
func (h *adminPageHandlers) reviews(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	offset := 0
	if raw := request.URL.Query().Get("offset"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 1000000 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.reviews.invalid")}, nil
		}
		offset = parsed
	}
	result, err := h.pages.options.Backend.ListReviews(ctx, page.Session.UserID, 20, offset)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.reviews.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"reviews": result.Reviews,
		"hasMore": result.HasMore, "nextOffset": offset + len(result.Reviews)}}, nil
}

// reviewDetail 显示单个待审核申请与决定表单。
func (h *adminPageHandlers) reviewDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	userID := request.URL.Query().Get("user_id")
	review, err := h.pages.options.Backend.GetReview(ctx, page.Session.UserID, userID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.reviews.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"review": review}}, nil
}

// reviewDecide 批准/拒绝注册（理由必填，服务端再判定）。
func (h *adminPageHandlers) reviewDecide(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"user_id", "decision",
		"reason", "app_id", "roles"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.reviews.invalid")}, nil
	}
	userID := form.Get("user_id")
	reason := strings.TrimSpace(form.Get("reason"))
	decision := form.Get("decision")
	if userID == "" || reason == "" || (decision != "approve" && decision != "reject") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.reviews.reason_required")}, nil
	}
	var roles []string
	for _, role := range strings.Split(form.Get("roles"), ",") {
		if trimmed := strings.TrimSpace(role); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	result, err := h.pages.options.Backend.DecideReview(ctx, page.Session.UserID, userID,
		decision == "approve", reason, strings.TrimSpace(form.Get("app_id")), roles,
		page.RequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.reviews.decide_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"decided": true, "review": result.Review,
		"notified": result.Notified, "errorCode": result.ErrorCode},
		RedirectPath: "/admin/reviews", RedirectQuery: url.Values{"status": {"decided"}}}, nil
}

// groups 列出/创建用户组。
func (h *adminPageHandlers) groups(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.RouteName == "admin.group_create" {
		if request.Method != http.MethodPost {
			return UIPageOutcome{StatusCode: http.StatusMethodNotAllowed,
				ErrorSummary: text("common.state.forbidden")}, nil
		}
		form, formErr := readPageForm(request, page.CSRFField, []string{"scope_id",
			"group_key", "name", "description"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.groups.invalid")}, nil
		}
		created, err := h.pages.options.Backend.CreateGroup(ctx, page.Session.UserID,
			strings.TrimSpace(form.Get("scope_id")), strings.TrimSpace(form.Get("group_key")),
			strings.TrimSpace(form.Get("name")), form.Get("description"), page.RequestID)
		if err != nil {
			return adminErrorOutcome(err, nil, "page.admin.groups.create_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"group": created},
			RedirectPath: "/admin/groups/detail", RedirectQuery: url.Values{"group_id": {created.ID}}}, nil
	}
	offset := 0
	if raw := request.URL.Query().Get("offset"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 1000000 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.groups.invalid")}, nil
		}
		offset = parsed
	}
	scopeID := strings.TrimSpace(request.URL.Query().Get("scope_id"))
	result, err := h.pages.options.Backend.ListGroups(ctx, page.Session.UserID, scopeID, 20, offset)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.groups.load_failed"), nil
	}
	prevOffset := offset - 20
	if prevOffset < 0 {
		prevOffset = 0
	}
	return UIPageOutcome{Data: map[string]any{"groups": result.Groups,
		"hasMore": result.HasMore, "scopeID": scopeID,
		"nextOffset": offset + len(result.Groups), "offset": offset,
		"hasPrevious": offset > 0, "prevOffset": prevOffset}}, nil
}

// groupDetail 显示组详情、更新名称/说明、成员分页与增删。
func (h *adminPageHandlers) groupDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.RouteName == "admin.group_update" {
		form, formErr := readPageForm(request, page.CSRFField, []string{"group_id", "name",
			"description"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.groups.invalid")}, nil
		}
		updated, err := h.pages.options.Backend.UpdateGroup(ctx, page.Session.UserID,
			form.Get("group_id"), strings.TrimSpace(form.Get("name")),
			form.Get("description"), page.RequestID)
		if err != nil {
			return adminErrorOutcome(err, nil, "page.admin.groups.update_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"group": updated},
			RedirectPath:  "/admin/groups/detail",
			RedirectQuery: url.Values{"group_id": {updated.ID}, "status": {"updated"}}}, nil
	}
	if page.RouteName == "admin.group_members" {
		form, formErr := readPageForm(request, page.CSRFField, []string{"group_id", "action",
			"user_ids"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.groups.invalid")}, nil
		}
		var userIDs []string
		for _, value := range strings.FieldsFunc(form.Get("user_ids"),
			func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == ';' }) {
			if value != "" {
				userIDs = append(userIDs, value)
			}
		}
		action := form.Get("action")
		if form.Get("group_id") == "" || len(userIDs) == 0 || len(userIDs) > 12 ||
			(action != "add" && action != "remove") {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.groups.members_invalid")}, nil
		}
		var result UIAdminMemberResult
		var err error
		if action == "add" {
			result, err = h.pages.options.Backend.AddMembers(ctx, page.Session.UserID,
				form.Get("group_id"), userIDs, page.RequestID)
		} else {
			result, err = h.pages.options.Backend.RemoveMembers(ctx, page.Session.UserID,
				form.Get("group_id"), userIDs, page.RequestID)
		}
		if err != nil {
			return adminErrorOutcome(err, nil, "page.admin.groups.members_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"memberResult": result},
			RedirectPath:  "/admin/groups/detail",
			RedirectQuery: url.Values{"group_id": {form.Get("group_id")}}}, nil
	}
	groupID := request.URL.Query().Get("group_id")
	group, err := h.pages.options.Backend.GetGroup(ctx, page.Session.UserID, groupID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.groups.load_failed"), nil
	}
	offset := 0
	if raw := request.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	members, err := h.pages.options.Backend.ListMembers(ctx, page.Session.UserID, groupID, 20, offset)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.groups.members_load_failed"), nil
	}
	prevOffset := offset - 20
	if prevOffset < 0 {
		prevOffset = 0
	}
	return UIPageOutcome{Data: map[string]any{"group": group, "members": members.Members,
		"hasMore": members.HasMore, "status": request.URL.Query().Get("status"),
		"nextOffset": offset + len(members.Members), "offset": offset,
		"hasPrevious": offset > 0, "prevOffset": prevOffset}}, nil
}

// groupDelete 删除组（硬删除，影响计数未知需明示）。
func (h *adminPageHandlers) groupDelete(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"group_id",
		"confirm_delete"})
	if formErr != nil || form.Get("confirm_delete") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.groups.delete_confirm_required")}, nil
	}
	groupID := form.Get("group_id")
	if groupID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.groups.invalid")}, nil
	}
	if err := h.pages.options.Backend.DeleteGroup(ctx, page.Session.UserID, groupID,
		page.RequestID); err != nil {
		return adminErrorOutcome(err, nil, "page.admin.groups.delete_failed"), nil
	}
	return UIPageOutcome{RedirectPath: "/admin/groups",
		RedirectQuery: url.Values{"status": {"deleted"}}}, nil
}

// ===== 辅助 =====

// adminErrorOutcome 把适配器错误映射为稳定状态/已翻译文案。
func adminErrorOutcome(err error, data any, fallbackKey string) UIPageOutcome {
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UIAdminError
	if errors.As(err, &publicErr) {
		switch publicErr.Code {
		case "ACCESS_DENIED", "RESOURCE_FORBIDDEN":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorCode = publicErr.Code
			outcome.ErrorSummary = text("page.admin.common.forbidden")
		case "REAUTH_REQUIRED", "MFA_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorCode = publicErr.Code
			outcome.ErrorSummary = text("page.admin.common.reauth_required")
		case "CONFLICT":
			outcome.ErrorCode = "CONFLICT"
			outcome.ErrorSummary = text("page.admin.common.conflict")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorCode = "RATE_LIMITED"
			outcome.ErrorSummary = text("common.state.rate_limited")
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED", "MAIL_DELIVERY_FAILED":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorCode = publicErr.Code
			outcome.ErrorSummary = text("page.account.common.unavailable")
		case "INTERNAL_ERROR":
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorCode = "INTERNAL_ERROR"
			outcome.ErrorSummary = text("common.state.error")
		default:
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorCode = publicErr.Code
		}
	}
	return outcome
}

// builtinAdminMessages 是管理页摘要使用的中文基线（模板静态文案仍走 i18n 键）。
var builtinAdminMessages = map[string]string{
	"page.admin.common.forbidden":               "你没有执行该管理操作的权限，或管理强认证已过期",
	"page.admin.common.reauth_required":         "该管理操作需要重新完成强认证，请按提示重新验证",
	"page.admin.common.conflict":                "数据已被其他操作修改，请重新读取后再试",
	"page.admin.users.load_failed":              "无法读取用户列表，请稍后重试",
	"page.admin.users.invalid":                  "用户请求参数无效",
	"page.admin.users.create_failed":            "创建用户未完成，请检查输入",
	"page.admin.users.update_failed":            "资料保存失败，请重新读取后再试",
	"page.admin.users.state_failed":             "状态操作未完成，请重新读取后再试",
	"page.admin.users.delete_preview_failed":    "无法读取删除影响，请稍后重试",
	"page.admin.users.delete_confirm_required":  "请先确认删除影响",
	"page.admin.users.delete_failed":            "删除未完成，请重新读取预览后再试",
	"page.admin.reviews.load_failed":            "无法读取审核列表，请稍后重试",
	"page.admin.reviews.invalid":                "审核请求参数无效",
	"page.admin.reviews.reason_required":        "请填写审核理由",
	"page.admin.reviews.decide_failed":          "审核未完成，请重新读取当前状态后再试",
	"page.admin.groups.load_failed":             "无法读取用户组，请稍后重试",
	"page.admin.groups.invalid":                 "用户组请求参数无效",
	"page.admin.groups.create_failed":           "创建用户组未完成",
	"page.admin.groups.update_failed":           "用户组更新未完成",
	"page.admin.groups.members_invalid":         "成员请求参数无效（需 1～12 个稳定用户 ID）",
	"page.admin.groups.members_failed":          "成员变更未完成",
	"page.admin.groups.members_load_failed":     "无法读取成员列表",
	"page.admin.groups.delete_confirm_required": "请先确认删除影响",
	"page.admin.groups.delete_failed":           "删除用户组未完成",
}

func init() {
	for key, message := range builtinAdminMessages {
		if _, exists := builtinAuthMessages[key]; !exists {
			builtinAuthMessages[key] = message
		}
	}
}

// userImport 处理 CSV 预检查与正式导入（multipart，内容不进日志）。
func (h *adminPageHandlers) userImport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if request.Method != http.MethodPost {
		return UIPageOutcome{Data: map[string]any{}}, nil
	}
	if err := request.ParseMultipartForm(5 << 20); err != nil && request.MultipartForm == nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.batch.invalid_file")}, nil
	}
	action := request.FormValue("action")
	content, readErr := readAdminUpload(request, "csv_file", 5<<20)
	if readErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.batch.invalid_file")}, nil
	}
	if action == "precheck" {
		report, err := h.pages.options.Backend.PrecheckImport(ctx, page.Session.UserID, content)
		if err != nil {
			return adminErrorOutcome(err, nil, "page.admin.batch.precheck_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"report": report}}, nil
	}
	if action != "start" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.batch.invalid_file")}, nil
	}
	key := strings.TrimSpace(request.FormValue("idempotency_key"))
	if len(key) < 8 || len(key) > 128 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.batch.invalid_key")}, nil
	}
	result, err := h.pages.options.Backend.StartImport(ctx, page.Session.UserID, content, key,
		page.RequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.batch.start_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"start": result},
		RedirectPath:  "/admin/users/batch/detail",
		RedirectQuery: url.Values{"job_id": {result.JobID}, "status": {"created"}}}, nil
}

// userExport 创建导出任务（不直接下载文件；服务器路径不外泄）。
func (h *adminPageHandlers) userExport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	allowedFields := []string{"user_id", "username", "nickname", "language", "timezone",
		"status", "created_at", "updated_at"}
	if request.Method != http.MethodGet {
		form, formErr := readPageForm(request, page.CSRFField, append([]string{
			"include_free_text", "max_rows", "idempotency_key"}, allowedFields...))
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.batch.invalid_options")}, nil
		}
		var fields []string
		for _, field := range allowedFields {
			if form.Get(field) != "" {
				fields = append(fields, field)
			}
		}
		maxRows := 0
		if raw := form.Get("max_rows"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 || parsed > 100000 {
				return UIPageOutcome{StatusCode: http.StatusBadRequest,
					ErrorSummary: text("page.admin.batch.invalid_options")}, nil
			}
			maxRows = parsed
		}
		key := strings.TrimSpace(form.Get("idempotency_key"))
		if len(key) < 8 || len(key) > 128 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.batch.invalid_key")}, nil
		}
		result, err := h.pages.options.Backend.StartExport(ctx, page.Session.UserID,
			UIAdminExportOptions{Fields: fields,
				IncludeFreeText: form.Get("include_free_text") != "", MaxRows: maxRows,
				IdempotencyKey: key}, page.RequestID)
		if err != nil {
			return adminErrorOutcome(err, nil, "page.admin.batch.start_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"start": result},
			RedirectPath:  "/admin/users/batch/detail",
			RedirectQuery: url.Values{"job_id": {result.JobID}, "status": {"created"}}}, nil
	}
	return UIPageOutcome{Data: map[string]any{"fields": allowedFields}}, nil
}

// userBatch 列出当前可管理批量任务。
func (h *adminPageHandlers) userBatch(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	offset := 0
	if raw := request.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 1000000 {
			offset = parsed
		}
	}
	kind := strings.TrimSpace(request.URL.Query().Get("kind"))
	result, err := h.pages.options.Backend.ListJobs(ctx, page.Session.UserID, kind, 20, offset)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.batch.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"jobs": result.Jobs, "hasMore": result.HasMore,
		"nextOffset": offset + len(result.Jobs), "kind": kind,
		"status": request.URL.Query().Get("status")}}, nil
}

// userBatchDetail 显示任务状态/计数/逐行结果，或执行取消/续跑。
func (h *adminPageHandlers) userBatchDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if page.RouteName == "admin.user_batch_action" {
		form, formErr := readPageForm(request, page.CSRFField, []string{"job_id", "action",
			"reason"})
		if formErr != nil {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.batch.invalid_options")}, nil
		}
		jobID := form.Get("job_id")
		switch form.Get("action") {
		case "cancel":
			reason := strings.TrimSpace(form.Get("reason"))
			if reason == "" || len(reason) > 64 {
				reason = "operator_cancel"
			}
			if err := h.pages.options.Backend.CancelJob(ctx, page.Session.UserID, jobID, reason,
				page.RequestID); err != nil {
				return adminErrorOutcome(err, nil, "page.admin.batch.cancel_failed"), nil
			}
			// 取消请求已接受：不本地标已取消，PRG 回详情由真实状态决定。
			return UIPageOutcome{RedirectPath: "/admin/users/batch/detail",
				RedirectQuery: url.Values{"job_id": {jobID}, "status": {"cancel_requested"}}}, nil
		case "retry":
			if _, err := h.pages.options.Backend.RetryJob(ctx, page.Session.UserID, jobID,
				page.RequestID); err != nil {
				return adminErrorOutcome(err, nil, "page.admin.batch.retry_failed"), nil
			}
			return UIPageOutcome{RedirectPath: "/admin/users/batch/detail",
				RedirectQuery: url.Values{"job_id": {jobID}, "status": {"retried"}}}, nil
		default:
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.batch.invalid_options")}, nil
		}
	}
	jobID := request.URL.Query().Get("job_id")
	job, err := h.pages.options.Backend.GetJob(ctx, page.Session.UserID, jobID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.batch.load_failed"), nil
	}
	rows, truncated, err := h.pages.options.Backend.ListRows(ctx, page.Session.UserID, jobID, 50, 0)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.batch.rows_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"job": job, "rows": rows,
		"rowsTruncated": truncated, "status": request.URL.Query().Get("status")}}, nil
}

// userBatchReport 受控下载逐行报告 CSV（附件，不泄露服务器路径/他人任务）。
func (h *adminPageHandlers) userBatchReport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	jobID := request.URL.Query().Get("job_id")
	data, truncated, err := h.pages.options.Backend.ReportCSV(ctx, page.Session.UserID, jobID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.batch.report_failed"), nil
	}
	headers := http.Header{}
	headers.Set("Content-Disposition", `attachment; filename="user_batch_report.csv"`)
	headers.Set("X-Report-Truncated", strconv.FormatBool(truncated))
	return UIPageOutcome{ContentType: "text/csv; charset=utf-8", Body: data,
		Headers: headers}, nil
}

// readAdminUpload 有界读取 multipart 文件字段内容。
func readAdminUpload(request *http.Request, field string, maxBytes int64) ([]byte, error) {
	file, _, err := request.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if readErr != nil || int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("文件超过允许大小")
	}
	return data, nil
}
