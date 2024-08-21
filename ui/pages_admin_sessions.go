package ui

// 步骤 187：管理员强制下线页面（系统管理 /admin/sessions）。
//
// 安全不变量：
//   - 路由全部 UIAccessManagement：宿主会话服务必须用真实 AuthorizeManagement
//     校验普通管理会话与强认证新鲜度；页面不信任任何前端自报身份/范围/权限。
//   - 页面只负责展示与参数编排。可撤销范围、sessions.revoke 权限、root/受保护
//     目标、强认证与敏感策略、真实撤销与审计全部由真实 session.Service 重新判定；
//     页面能力位与确认框只是交互辅助，不是授权。
//   - 确认 + 再次认证由宿主注入的 Reauth 回调完成（返回服务端已校验的认证事实）；
//     适配器把证据转换为 reauth 信号后交给领域服务，领域服务仍会重新评估策略。
//   - 明确区分“退出自己的会话”（安全中心 /account/sessions）与“管理员强制下线”；
//     页面常驻说明本操作只撤销身份会话，不撤销 OAuth 授权/刷新令牌族/第三方会话。
//   - 查询目标不存在时显示空态；撤销 0 条按幂等成功展示并明确“不代表发生了撤销”。

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// errUIAdminSessionsBackendMissing 表示页面缺少真实会话后端；构造期 fail-closed。
var errUIAdminSessionsBackendMissing = errors.New("管理员会话页面缺少后端适配器")

// UIPageAdminSessionsOptions 是步骤 187 管理员强制下线页配置。
type UIPageAdminSessionsOptions struct {
	Backend UIAdminSessionsBackend
	// Reauth 由宿主提供：页面已显式确认的动作交给真实再次认证/敏感策略链，
	// 返回服务端已校验的认证事实（不含秘密/令牌）。为 nil 时撤销入口 fail-closed
	// 拒绝，不渲染“可提交但永远失败”的假入口。
	Reauth func(ctx context.Context, userID string,
		binding UIAdminSessionActionBinding) (UIAdminSessionEvidence, error)
}

// UIAdminSessionEvidence 是页面再次认证回调返回的服务端认证事实。页面/适配器
// 不信任前端自报时间或强度；Strength 只允许 "strong"。
type UIAdminSessionEvidence struct {
	VerifiedAt time.Time
	Strength   string
	Complete   bool
	Confirmed  bool
}

// UIAdminSessionActionBinding 是页面动作与再次认证绑定的参数。适配器/领域服务
// 会以同一组目标与参数重新判定；确认框本身不是授权。
type UIAdminSessionActionBinding struct {
	Action          string
	ScopeAppID      string
	TargetUserID    string
	TargetSessionID string
	Reason          string
	RequestID       string
}

// UIAdminSessionsCapabilities 是服务端判定的页面能力位（只影响呈现）。
type UIAdminSessionsCapabilities struct {
	List   bool
	Revoke bool
}

// UIAdminSessionQuery 是会话查询条件。
type UIAdminSessionQuery struct {
	TargetUserID string
	ScopeAppID   string
	Page         int
	PageSize     int
}

// UIAdminSessionView 是一条公开会话摘要；不含会话秘密/CSRF/验证摘要。
type UIAdminSessionView struct {
	ID                string
	AppID             string
	Kind              string
	Reason            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RememberMe        bool
	Current           bool
	ClientUserAgent   string
	ClientAddress     string
}

// UIAdminSessionPage 是会话查询结果。
type UIAdminSessionPage struct {
	TargetUserID string
	ScopeAppID   string
	Sessions     []UIAdminSessionView
	Page         int
	PageSize     int
	Total        int64
	HasMore      bool
}

// UIAdminSessionRevokeAction 是强制下线动作。UserAll 表示撤销目标用户该范围内的
// 全部活动会话；Session 表示按会话 ID 撤销单条。Confirm 只表示页面已显式确认。
type UIAdminSessionRevokeAction struct {
	ScopeAppID      string
	TargetUserID    string
	TargetSessionID string
	Reason          string
	Confirm         bool
}

// UIAdminSessionRevokeResult 是真实撤销结果。Revoked=0 表示目标不存在/已失效/
// 超出范围，按幂等成功展示，不代表发生了撤销。
type UIAdminSessionRevokeResult struct {
	Revoked    int64
	ScopeAppID string
}

// UIAdminSessionsError 是页面适配层返回的稳定公开错误（不含底层消息）。
type UIAdminSessionsError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIAdminSessionsError) Error() string { return "管理员会话操作失败: " + e.Code }

// UIAdminSessionsBackend 是管理员会话页调用真实会话服务的最小契约。适配器负责
// 从请求取管理会话秘密、把页面证据转换为 reauth 信号、调用真实服务并映射错误；
// 页面层不实现授权。
type UIAdminSessionsBackend interface {
	Capabilities(ctx context.Context, request *http.Request,
		userID string) (UIAdminSessionsCapabilities, error)
	ListSessions(ctx context.Context, request *http.Request, userID string,
		query UIAdminSessionQuery) (UIAdminSessionPage, error)
	RevokeSessions(ctx context.Context, request *http.Request, userID string,
		action UIAdminSessionRevokeAction, evidence UIAdminSessionEvidence) (UIAdminSessionRevokeResult, error)
}

// newPageAdminSessionsPages 构造步骤 187 路由/处理器。
func newPageAdminSessionsPages(options UIPageAdminSessionsOptions) (*pageAdminSessionsPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, errUIAdminSessionsBackendMissing
	}
	pages := &pageAdminSessionsPages{
		handlers: map[string]UIPageHandler{},
		options:  options,
	}
	handler := &adminSessionsPageHandlers{pages: pages}
	for _, route := range []UIRoute{
		{Name: "admin.sessions", Method: http.MethodGet, Path: "/admin/sessions",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/sessions"},
		{Name: "admin.sessions.revoke", Method: http.MethodPost, Path: "/admin/sessions/revoke",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/sessions"},
	} {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageAdminSessionsPages 是管理员强制下线页实现。
type pageAdminSessionsPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAdminSessionsOptions
}

// adminSessionsPageHandlers 分发 GET 查询与 POST 撤销。
type adminSessionsPageHandlers struct {
	pages *pageAdminSessionsPages
}

// HandlePage 实现 UIPageHandler。
func (h *adminSessionsPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if request == nil || page.Session.UserID == "" {
		return adminSessionsErrorOutcome(http.StatusUnauthorized,
			"page.admin.sessions.session_expired"), nil
	}
	switch page.RouteName {
	case "admin.sessions":
		return h.list(ctx, request, page)
	case "admin.sessions.revoke":
		return h.revoke(ctx, request, page)
	default:
		return adminSessionsErrorOutcome(http.StatusNotFound,
			"page.admin.sessions.not_found"), nil
	}
}

// list 渲染查询表单与（填写目标用户后的）活动会话列表。
func (h *adminSessionsPageHandlers) list(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps, capsErr := h.pages.options.Backend.Capabilities(ctx, request, page.Session.UserID)
	if capsErr != nil {
		return adminSessionsErrorOutcome(http.StatusForbidden,
			"page.admin.sessions.access_denied"), nil
	}
	query := UIAdminSessionQuery{
		TargetUserID: strings.TrimSpace(queryValue(request, "target_user_id", 64)),
		ScopeAppID:   strings.TrimSpace(queryValue(request, "scope_app_id", 64)),
		Page:         queryIntValue(request, "page", 1, 1, 100000),
		PageSize:     queryIntValue(request, "page_size", 20, 1, 100),
	}
	data := map[string]any{
		"capabilities": caps,
		"targetUserID": query.TargetUserID,
		"scopeAppID":   query.ScopeAppID,
		"pageSize":     query.PageSize,
		"oauthNote":    true,
		"reauthReady":  h.pages.options.Reauth != nil,
	}
	if !caps.List {
		data["listUnavailable"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	if query.TargetUserID == "" {
		// 未填写目标用户：只展示查询表单，不探测/枚举任何用户会话。
		data["empty"] = true
		return UIPageOutcome{Data: data}, nil
	}
	result, err := h.pages.options.Backend.ListSessions(ctx, request, page.Session.UserID, query)
	if err != nil {
		return adminSessionsBackendErrorOutcome(err, data), nil
	}
	data["result"] = result
	data["hasSessions"] = len(result.Sessions) > 0
	data["empty"] = len(result.Sessions) == 0
	return UIPageOutcome{Data: data}, nil
}

// revoke 处理页面确认后的强制下线：显式确认 → 宿主再次认证 → 真实领域撤销。
func (h *adminSessionsPageHandlers) revoke(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"mode", "scope_app_id", "target_user_id", "target_session_id", "reason", "confirm"})
	if formErr != nil {
		return adminSessionsErrorOutcome(http.StatusBadRequest,
			"page.admin.sessions.invalid"), nil
	}
	mode := strings.TrimSpace(form.Get("mode"))
	scopeAppID := strings.TrimSpace(form.Get("scope_app_id"))
	targetUserID := strings.TrimSpace(form.Get("target_user_id"))
	targetSessionID := strings.TrimSpace(form.Get("target_session_id"))
	reason := strings.TrimSpace(form.Get("reason"))
	confirm := form.Get("confirm")
	if confirm != "yes" {
		return adminSessionsErrorOutcome(http.StatusBadRequest,
			"page.admin.sessions.confirm_required"), nil
	}
	if reason == "" || utf8.RuneCountInString(reason) > 256 {
		return adminSessionsErrorOutcome(http.StatusBadRequest,
			"page.admin.sessions.reason_required"), nil
	}
	switch mode {
	case "user":
		if targetUserID == "" || targetSessionID != "" {
			return adminSessionsErrorOutcome(http.StatusBadRequest,
				"page.admin.sessions.invalid"), nil
		}
	case "session":
		if targetSessionID == "" {
			return adminSessionsErrorOutcome(http.StatusBadRequest,
				"page.admin.sessions.invalid"), nil
		}
	default:
		return adminSessionsErrorOutcome(http.StatusBadRequest,
			"page.admin.sessions.invalid"), nil
	}
	if h.pages.options.Reauth == nil {
		return adminSessionsErrorOutcome(http.StatusServiceUnavailable,
			"page.admin.sessions.reauth_unavailable"), nil
	}
	binding := UIAdminSessionActionBinding{
		Action: "session.admin_revoke", ScopeAppID: scopeAppID,
		TargetUserID: targetUserID, TargetSessionID: targetSessionID,
		Reason: reason, RequestID: page.RequestID,
	}
	evidence, reauthErr := h.pages.options.Reauth(ctx, page.Session.UserID, binding)
	if reauthErr != nil || !validAdminSessionEvidence(evidence) {
		return adminSessionsErrorOutcome(http.StatusForbidden,
			"page.admin.sessions.reauth_required"), nil
	}
	result, err := h.pages.options.Backend.RevokeSessions(ctx, request, page.Session.UserID,
		UIAdminSessionRevokeAction{
			ScopeAppID: scopeAppID, TargetUserID: targetUserID,
			TargetSessionID: targetSessionID, Reason: reason, Confirm: true,
		}, evidence)
	data := map[string]any{
		"done":            true,
		"revoked":         result.Revoked,
		"noop":            result.Revoked == 0,
		"scopeAppID":      scopeAppID,
		"targetUserID":    targetUserID,
		"targetSessionID": targetSessionID,
		"confirm":         true,
	}
	if err != nil {
		return adminSessionsBackendErrorOutcome(err, data), nil
	}
	// 成功后尽量刷新目标列表；读取失败不影响已完成的撤销，只显示结果。
	refreshQuery := UIAdminSessionQuery{TargetUserID: targetUserID, ScopeAppID: scopeAppID,
		Page: 1, PageSize: 20}
	if refreshed, listErr := h.pages.options.Backend.ListSessions(ctx, request,
		page.Session.UserID, refreshQuery); listErr == nil {
		data["result"] = refreshed
		data["hasSessions"] = len(refreshed.Sessions) > 0
	}
	data["capabilities"], _ = h.pages.options.Backend.Capabilities(ctx, request, page.Session.UserID)
	return UIPageOutcome{Data: data}, nil
}

// validAdminSessionEvidence 只接受服务端回调返回的完整强认证事实；不信任何前端
// 自报时间或强度。证据不足时调用方按 REAUTH_REQUIRED 拒绝。
func validAdminSessionEvidence(evidence UIAdminSessionEvidence) bool {
	return evidence.Complete && evidence.Confirmed &&
		evidence.Strength == "strong" && !evidence.VerifiedAt.IsZero() &&
		!evidence.VerifiedAt.After(time.Now().Add(time.Minute))
}

// adminSessionsErrorOutcome 构造页面稳定错误摘要（不含内部细节）。
func adminSessionsErrorOutcome(status int, key string) UIPageOutcome {
	return UIPageOutcome{StatusCode: status, ErrorCode: key, ErrorSummary: text(key)}
}

// adminSessionsBackendErrorOutcome 把适配器稳定错误码映射为页面状态与摘要。
func adminSessionsBackendErrorOutcome(err error, data map[string]any) UIPageOutcome {
	status := http.StatusBadRequest
	key := "page.admin.sessions.load_failed"
	if typed, ok := err.(*UIAdminSessionsError); ok && typed != nil {
		switch typed.Code {
		case "ACCESS_DENIED":
			status, key = http.StatusForbidden, "page.admin.sessions.access_denied"
		case "REAUTH_REQUIRED", "MFA_REQUIRED":
			status, key = http.StatusForbidden, "page.admin.sessions.reauth_required"
		case "SESSION_EXPIRED":
			status, key = http.StatusUnauthorized, "page.admin.sessions.session_expired"
		case "CONFLICT":
			status, key = http.StatusConflict, "page.admin.sessions.conflict"
		case "RATE_LIMITED":
			status, key = http.StatusTooManyRequests, "page.admin.sessions.rate_limited"
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
			status, key = http.StatusServiceUnavailable, "page.admin.sessions.unavailable"
		case "REQ_INVALID":
			status, key = http.StatusBadRequest, "page.admin.sessions.invalid"
		}
	}
	return UIPageOutcome{StatusCode: status, ErrorCode: key, ErrorSummary: text(key), Data: data}
}

// queryValue 读取单值查询参数并限制长度（页面只解析，不做授权）。
func queryValue(request *http.Request, key string, maxBytes int) string {
	if request == nil {
		return ""
	}
	value := strings.TrimSpace(request.URL.Query().Get(key))
	if len(value) > maxBytes {
		return ""
	}
	return value
}

// queryIntValue 读取可选整数查询参数并限制范围；非法值回退默认值。
func queryIntValue(request *http.Request, key string, defaultValue, minValue, maxValue int) int {
	raw := queryValue(request, key, 16)
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue || value > maxValue {
		return defaultValue
	}
	return value
}
