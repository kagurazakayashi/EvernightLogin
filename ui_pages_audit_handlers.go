package login

// 步骤 74 审计与错误诊断页处理器：读取与写入都是显式服务端授权；页面把真实服务
// 返回的状态映射为中文说明，不渲染假进度、假成功或旧数据冒充的新结果。

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// auditPageHandlers 实现审计与错误诊断页处理器。
type auditPageHandlers struct {
	pages *pageAuditPages
}

// HandlePage 按路由分派。
func (h *auditPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "account.activity":
		return h.ownActivity(ctx, request, page)
	case "account.activity_detail":
		return h.ownActivityDetail(ctx, request, page)
	case "admin.audit":
		return h.list(ctx, request, page)
	case "admin.audit_detail":
		return h.detail(ctx, request, page)
	case "admin.audit_exports":
		return h.exports(ctx, request, page)
	case "admin.audit_export_create":
		return h.createExport(ctx, request, page)
	case "admin.audit_export_cancel":
		return h.cancelExport(ctx, request, page)
	case "admin.audit_export_download":
		return h.downloadExport(ctx, request, page)
	case "admin.error_codes":
		return h.errors(ctx, request, page)
	case "admin.audit_maintenance":
		return h.maintenance(ctx, request, page)
	case "admin.audit_maintenance_preview":
		return h.previewPurge(ctx, request, page)
	case "admin.audit_maintenance_start":
		return h.startPurge(ctx, request, page)
	case "admin.audit_maintenance_cancel":
		return h.cancelPurge(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// auditCapabilities 读取页面能力位；失败时全部 false（只影响呈现）。
func (h *auditPageHandlers) auditCapabilities(ctx context.Context,
	page UIPageContext) UIAuditCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UIAuditCapabilities{}
	}
	return caps
}

// recordPageDenial 尽力记录一次页面级拒绝（失败只影响留痕，不改变 403 结果）。
func (h *auditPageHandlers) recordPageDenial(ctx context.Context, page UIPageContext,
	reason string) {
	_ = h.pages.options.Backend.RecordDenial(ctx, page.Session.UserID, reason)
}

// checkAuditCSRF 校验页面表单安全令牌；失败即拒绝，不进入业务处理。
func (h *auditPageHandlers) checkAuditCSRF(ctx context.Context, request *http.Request,
	page UIPageContext, form url.Values) (UIPageOutcome, bool) {
	token := strings.TrimSpace(form.Get(page.CSRFField))
	if token == "" || page.CSRF == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(page.CSRF)) != 1 {
		h.recordPageDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.audit.common.csrf_invalid")}, false
	}
	if err := h.pages.options.ValidateCSRF(ctx, request, token); err != nil {
		h.recordPageDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.audit.common.csrf_invalid")}, false
	}
	return UIPageOutcome{}, true
}

// pageLocation 返回当前页面时区；未知时区回退 UTC。
func pageLocation(page UIPageContext) *time.Location {
	if page.TimeZone != "" {
		if location, err := time.LoadLocation(page.TimeZone); err == nil {
			return location
		}
	}
	return time.UTC
}

// auditPageLocation 返回审计页日期筛选使用的时区：优先受控 tz 参数（可加载的 IANA
// 名称，拒绝 Local），否则使用页面/会话时区。它让统计看板的同区间下钻在统计时区与
// 账户时区不同时仍按同一自然日解释日期，避免明细区间整体偏移。tz 只影响日期解释，
// 不改变任何授权或时间上界钳制。
func auditPageLocation(page UIPageContext, values url.Values) (*time.Location, string) {
	if values != nil {
		raw := strings.TrimSpace(values.Get("tz"))
		if raw != "" && raw != "Local" && len(raw) <= 64 {
			if location, err := time.LoadLocation(raw); err == nil {
				return location, raw
			}
		}
	}
	return pageLocation(page), page.TimeZone
}

// parseDateBound 解析 YYYY-MM-DD；empty 返回零值。
func parseDateBound(value string, location *time.Location) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, true
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, location)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// parseAuditFilter 从查询/表单解析白名单筛选；返回字段错误（有错误时不得查询）。
// 结束日期按“含当天”解释为上界（次日零点），但不得超过服务端当前时间：超出部分
// 钳制到 now+1 分钟（auditops 允许的上界），保证 `to=今天` 可查询当日记录而不被判
// 成“结束时间在未来”；列表、本人活动与导出创建共用本函数，范围一致。
func parseAuditFilter(values url.Values, location *time.Location,
	now time.Time) (UIAuditFilter, map[string]string) {
	fieldErrors := map[string]string{}
	filter := UIAuditFilter{
		AppID:      strings.TrimSpace(values.Get("app_id")),
		ActorID:    strings.TrimSpace(values.Get("actor_id")),
		Action:     strings.TrimSpace(values.Get("action")),
		ErrorCode:  strings.ToUpper(strings.TrimSpace(values.Get("error_code"))),
		RequestID:  strings.TrimSpace(values.Get("request_id")),
		TaskID:     strings.TrimSpace(values.Get("task_id")),
		TargetType: strings.TrimSpace(values.Get("target_type")),
		TargetID:   strings.TrimSpace(values.Get("target_id")),
	}
	if raw := strings.TrimSpace(values.Get("system_only")); raw == "1" || raw == "on" {
		filter.SystemOnly = true
	}
	if from, ok := parseDateBound(values.Get("from"), location); !ok {
		fieldErrors["from"] = text("page.admin.audit.filter.invalid_time")
	} else {
		filter.From = from
	}
	if to, ok := parseDateBound(values.Get("to"), location); !ok {
		fieldErrors["to"] = text("page.admin.audit.filter.invalid_time")
	} else if !to.IsZero() {
		end := to.Add(24 * time.Hour)
		if limit := now.Add(time.Minute); end.After(limit) {
			end = limit
		}
		filter.To = end
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && !filter.To.After(filter.From) {
		fieldErrors["to"] = text("page.admin.audit.filter.invalid_range")
	}
	outcome := strings.TrimSpace(values.Get("outcome"))
	if outcome != "" && outcome != "success" && outcome != "failure" && outcome != "denied" {
		fieldErrors["outcome"] = text("page.admin.audit.filter.invalid_value")
	}
	filter.Outcome = outcome
	actorType := strings.TrimSpace(values.Get("actor_type"))
	switch actorType {
	case "", "user", "system", "local_admin", "anonymous":
	default:
		fieldErrors["actor_type"] = text("page.admin.audit.filter.invalid_value")
	}
	filter.ActorType = actorType
	if filter.RequestID != "" {
		if err := ValidateRequestID(filter.RequestID); err != nil {
			fieldErrors["request_id"] = text("page.admin.audit.filter.invalid_request_id")
		}
	}
	if filter.TaskID != "" {
		if err := ValidateTaskID(filter.TaskID); err != nil {
			fieldErrors["task_id"] = text("page.admin.audit.filter.invalid_task_id")
		}
	}
	return filter, fieldErrors
}

// auditOrder 规范化排序白名单。
func auditOrder(raw string) string {
	switch strings.TrimSpace(raw) {
	case "occurred_asc":
		return "occurred_asc"
	default:
		return "occurred_desc"
	}
}

// parsePageWindow 解析分页边界；非法返回 false 并给出字段错误。
func parsePageWindow(values url.Values) (limit, offset int, ok bool) {
	limit = 20
	offset = 0
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, 0, false
		}
		limit = parsed
	}
	if raw := strings.TrimSpace(values.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 1_000_000 {
			return 0, 0, false
		}
		offset = parsed
	}
	return limit, offset, true
}

// auditSummary 由已裁剪的稳定字段生成一句直白说明（谁对什么执行了什么、结果如何）。
// 只使用受控字段与 中文结果/操作者标签，不拼接原始日志、SQL 或后端错误原文；
// 缺少稳定信息时给出中性说明，不编造具体原因。
func auditSummary(event UIAuditEventView) string {
	actor := text(event.ActorKindKey())
	if actor == "" {
		actor = "有操作者"
	}
	if event.ActorID != "" {
		actor += " " + event.ActorID
	}
	target := event.TargetType
	if target == "" {
		target = "记录"
	}
	if event.TargetID != "" {
		target += " " + event.TargetID
	}
	action := event.Action
	if action == "" {
		action = "未记录动作"
	}
	return actor + " 对 " + target + " 执行 " + action + "，结果：" + text(event.OutcomeKey())
}

// withAuditSummaries 为列表事件补齐直白说明。
func withAuditSummaries(events []UIAuditEventView) []UIAuditEventView {
	result := make([]UIAuditEventView, len(events))
	for index, event := range events {
		event.Summary = auditSummary(event)
		result[index] = event
	}
	return result
}

// paginationURLs 生成上一页/下一页站内链接，保留当前筛选与排序；无 hasMore 时
// 不显示下一页，不伪造总数或末页。
func paginationURLs(request *http.Request, hasMore bool, limit, offset int) (string, string) {
	base := request.URL.Path
	values := request.URL.Query()
	build := func(nextOffset int) string {
		cloned := url.Values{}
		for key, items := range values {
			if key == "offset" || key == "limit" {
				continue
			}
			for _, item := range items {
				cloned.Add(key, item)
			}
		}
		cloned.Set("limit", strconv.Itoa(limit))
		cloned.Set("offset", strconv.Itoa(nextOffset))
		return base + "?" + cloned.Encode()
	}
	previous := ""
	if offset > 0 {
		previous = build(offset - limit)
	}
	next := ""
	if hasMore {
		next = build(offset + limit)
	}
	return previous, next
}

// auditCursorFromQuery 解析稳定游标；游标与非零 offset 互斥、超长/非法格式由
// 调用方按筛选错误处理（服务端仍会二次校验游标内容）。
func auditCursorFromQuery(values url.Values) (string, bool) {
	cursor := strings.TrimSpace(values.Get("cursor"))
	if len(cursor) > 4096 {
		return "", false
	}
	if cursor != "" && strings.TrimSpace(values.Get("offset")) != "" {
		return "", false
	}
	return cursor, true
}

// paginationURLsWithCursor 在 offset 分页链接基础上支持服务端稳定游标：
// 游标存在时下一页使用 cursor 并移除 offset；游标分页没有可靠的上一页 offset 链接。
func paginationURLsWithCursor(request *http.Request, hasMore bool, limit, offset int,
	nextCursor string) (string, string) {
	previous, next := paginationURLs(request, hasMore, limit, offset)
	if nextCursor == "" {
		return previous, next
	}
	base := request.URL.Path
	values := request.URL.Query()
	cloned := url.Values{}
	for key, items := range values {
		if key == "offset" || key == "limit" || key == "cursor" {
			continue
		}
		for _, item := range items {
			cloned.Add(key, item)
		}
	}
	cloned.Set("limit", strconv.Itoa(limit))
	cloned.Set("cursor", nextCursor)
	return "", base + "?" + cloned.Encode()
}

// list 渲染授权范围内审计列表（筛选/排序/分页/请求与任务编号精确查询）。
func (h *auditPageHandlers) list(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "scopeID": UIAuditScopeSystem,
		"timezone": page.TimeZone, "filter": UIAuditFilter{}, "limit": 20,
		"offset": 0, "order": "occurred_desc", "events": []UIAuditEventView{},
		"filtered": false, "invalid": false, "forbidden": false,
		"retentionDays": 0, "retentionCutoff": time.Time{}, "retentionConfigured": false}
	if !caps.Read {
		h.recordPageDenial(ctx, page, "read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.common.forbidden")}, nil
	}
	values := request.URL.Query()
	location, timeZone := auditPageLocation(page, values)
	data["timezone"] = timeZone
	filter, fieldErrors := parseAuditFilter(values, location, h.pages.options.Now())
	limit, offset, pageOK := parsePageWindow(values)
	if !pageOK {
		fieldErrors["limit"] = text("page.admin.audit.filter.invalid_page")
	}
	cursor, cursorOK := auditCursorFromQuery(values)
	if !cursorOK {
		fieldErrors["cursor"] = text("page.admin.audit.filter.invalid_page")
	}
	if cursor != "" {
		offset = 0
	}
	data["filter"] = filter
	data["limit"], data["offset"], data["cursor"] = limit, offset, cursor
	data["order"] = auditOrder(values.Get("order"))
	data["filtered"] = !filter.Empty()
	// 回显已通过校验的日期筛选（筛选保持；导出表单也从这两个值继承时间范围）。
	data["fromValue"] = strings.TrimSpace(values.Get("from"))
	data["toValue"] = strings.TrimSpace(values.Get("to"))
	if len(fieldErrors) > 0 {
		data["invalid"] = true
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			FieldErrors: fieldErrors, ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.ListAudit(ctx, page.Session.UserID, UIAuditQuery{
		ScopeID: UIAuditScopeSystem, Filter: filter, Order: data["order"].(string),
		Limit: limit, Offset: offset, Cursor: cursor})
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.list.load_failed"), nil
	}
	data["events"] = withAuditSummaries(result.Events)
	data["hasMore"] = result.HasMore
	data["scopeKind"] = result.ScopeKind
	data["retentionDays"] = result.RetentionDays
	data["retentionConfigured"] = result.RetentionConfigured
	data["retentionCutoff"] = result.RetentionCutoff
	data["dataScope"] = result.DataScope
	data["updatedAt"] = time.Now().UTC()
	data["empty"] = len(result.Events) == 0
	data["prevURL"], data["nextURL"] = paginationURLsWithCursor(request, result.HasMore,
		limit, offset, result.NextCursor)
	return UIPageOutcome{Data: data}, nil
}

// ownActivity 渲染普通用户本人安全活动（只读本人记录，无他人/管理/清理入口）。
func (h *auditPageHandlers) ownActivity(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	location := pageLocation(page)
	values := request.URL.Query()
	data := map[string]any{"timezone": page.TimeZone, "filter": UIAuditFilter{},
		"limit": 20, "offset": 0, "order": "occurred_desc",
		"events": []UIAuditEventView{}, "forbidden": false,
		"retentionDays": 0, "retentionCutoff": time.Time{}}
	filter, fieldErrors := parseAuditFilter(values, location, h.pages.options.Now())
	limit, offset, pageOK := parsePageWindow(values)
	if !pageOK {
		fieldErrors["limit"] = text("page.admin.audit.filter.invalid_page")
	}
	cursor, cursorOK := auditCursorFromQuery(values)
	if !cursorOK {
		fieldErrors["cursor"] = text("page.admin.audit.filter.invalid_page")
	}
	if cursor != "" {
		offset = 0
	}
	data["filter"], data["limit"], data["offset"] = filter, limit, offset
	data["cursor"] = cursor
	data["order"] = auditOrder(values.Get("order"))
	data["filtered"] = !filter.Empty()
	data["fromValue"] = strings.TrimSpace(values.Get("from"))
	data["toValue"] = strings.TrimSpace(values.Get("to"))
	if len(fieldErrors) > 0 {
		data["invalid"] = true
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			FieldErrors: fieldErrors, ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.QueryOwnActivity(ctx, page.Session.UserID,
		UIAuditQuery{ScopeID: UIAuditScopeSystem, Filter: filter,
			Order: data["order"].(string), Limit: limit, Offset: offset, Cursor: cursor})
	if err != nil {
		return auditErrorOutcome(err, data, "page.account.activity.load_failed"), nil
	}
	data["events"] = withAuditSummaries(result.Events)
	data["dataScope"] = text("page.account.activity.scope_self")
	data["hasMore"] = result.HasMore
	data["retentionDays"] = result.RetentionDays
	data["retentionConfigured"] = result.RetentionConfigured
	data["retentionCutoff"] = result.RetentionCutoff
	data["updatedAt"] = time.Now().UTC()
	data["empty"] = len(result.Events) == 0
	data["prevURL"], data["nextURL"] = paginationURLsWithCursor(request, result.HasMore,
		limit, offset, result.NextCursor)
	return UIPageOutcome{Data: data}, nil
}

// ownActivityDetail 渲染本人单条安全活动详情；他人事件按不存在处理（服务端判定）。
func (h *auditPageHandlers) ownActivityDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	data := map[string]any{"timezone": page.TimeZone, "forbidden": false}
	eventID := strings.TrimSpace(request.URL.Query().Get("event_id"))
	if eventID == "" {
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			FieldErrors:  map[string]string{"event_id": text("page.admin.audit.filter.invalid_event_id")},
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	var occurredAtHint time.Time
	if raw := strings.TrimSpace(request.URL.Query().Get("occurred_at")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			occurredAtHint = parsed
		}
	}
	detail, err := h.pages.options.Backend.GetOwnActivity(ctx, page.Session.UserID, eventID,
		occurredAtHint)
	if err != nil {
		return auditErrorOutcome(err, data, "page.account.activity.load_failed"), nil
	}
	data["detail"] = detail
	return UIPageOutcome{Data: data}, nil
}

// detail 渲染单条审计事件详情与公开错误说明。
func (h *auditPageHandlers) detail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"forbidden": false}
	if !caps.Read {
		h.recordPageDenial(ctx, page, "read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.common.forbidden")}, nil
	}
	eventID := strings.TrimSpace(request.URL.Query().Get("event_id"))
	if eventID == "" {
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			FieldErrors:  map[string]string{"event_id": text("page.admin.audit.filter.invalid_event_id")},
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	var occurredAtHint time.Time
	if raw := strings.TrimSpace(request.URL.Query().Get("occurred_at")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			occurredAtHint = parsed
		}
	}
	detail, err := h.pages.options.Backend.GetAudit(ctx, page.Session.UserID, eventID,
		occurredAtHint)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.detail.load_failed"), nil
	}
	detail.Event.Summary = auditSummary(detail.Event)
	data["detail"] = detail
	data["scopeID"] = detail.ScopeID
	return UIPageOutcome{Data: data}, nil
}

// errors 渲染错误码检索（同一注册表/手册数据，公开说明与受限诊断分开）。
func (h *auditPageHandlers) errors(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "entries": []UIErrorEntry{},
		"searched": false, "forbidden": false}
	if !caps.Read {
		h.recordPageDenial(ctx, page, "error_catalog_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.common.forbidden")}, nil
	}
	query := UIErrorQuery{
		Code:     strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("code"))),
		Keyword:  strings.TrimSpace(request.URL.Query().Get("keyword")),
		Category: strings.TrimSpace(request.URL.Query().Get("category")),
	}
	data["code"], data["keyword"], data["category"] = query.Code, query.Keyword, query.Category
	if len(query.Keyword) > 128 {
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			FieldErrors:  map[string]string{"keyword": text("page.admin.audit.filter.invalid_value")},
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.SearchErrors(ctx, page.Session.UserID, query)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.errors.load_failed"), nil
	}
	data["entries"] = result.Entries
	data["unknownCode"] = result.UnknownCode
	data["searched"] = result.Searched
	data["empty"] = len(result.Entries) == 0 && result.UnknownCode == ""
	return UIPageOutcome{Data: data}, nil
}

// exports 渲染导出任务列表与详情（真实状态机）。
func (h *auditPageHandlers) exports(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderExports(ctx, request, page, "", map[string]any{})
}

// renderExports 读取导出任务列表（可附带刚提交/取消的结果）。
func (h *auditPageHandlers) renderExports(ctx context.Context, request *http.Request,
	page UIPageContext, exportID string, extra map[string]any) (UIPageOutcome, error) {
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"exports": []UIAuditExport{}, "forbidden": false, "limit": 20, "offset": 0}
	for key, value := range extra {
		data[key] = value
	}
	if !caps.Read {
		h.recordPageDenial(ctx, page, "read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.common.forbidden")}, nil
	}
	if exportID == "" {
		exportID = strings.TrimSpace(request.URL.Query().Get("export_id"))
	}
	if exportID != "" {
		export, err := h.pages.options.Backend.GetExport(ctx, page.Session.UserID, exportID)
		if err != nil {
			return auditErrorOutcome(err, data, "page.admin.audit.exports.load_failed"), nil
		}
		data["exportDetail"] = export
		data["downloadAvailable"] = export.State == "succeeded" && export.FileAvailable
	}
	limit, offset, ok := parsePageWindow(request.URL.Query())
	if !ok {
		return UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	state := strings.TrimSpace(request.URL.Query().Get("state"))
	switch state {
	case "", "queued", "running", "succeeded", "failed", "cancelled":
	default:
		state = ""
	}
	data["state"], data["limit"], data["offset"] = state, limit, offset
	pageResult, err := h.pages.options.Backend.ListExports(ctx, page.Session.UserID,
		UIAuditScopeSystem, state, limit, offset)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.exports.load_failed"), nil
	}
	data["exports"] = pageResult.Exports
	data["hasMore"] = pageResult.HasMore
	data["updatedAt"] = time.Now().UTC()
	data["prevURL"], data["nextURL"] = paginationURLs(request, pageResult.HasMore, limit, offset)
	return UIPageOutcome{Data: data}, nil
}

// createExport 创建真实异步导出任务；提交成功只表示已受理。
func (h *auditPageHandlers) createExport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if err := request.ParseForm(); err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	if outcome, ok := h.checkAuditCSRF(ctx, request, page, request.PostForm); !ok {
		return outcome, nil
	}
	format := strings.ToLower(strings.TrimSpace(request.PostForm.Get("format")))
	if format != "csv" && format != "json" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.export.invalid_format"),
			Data:         map[string]any{"capabilities": UIAuditCapabilities{}}}, nil
	}
	location, _ := auditPageLocation(page, request.PostForm)
	values := url.Values{"format": []string{format}}
	// 筛选编号使用独立字段名，避免与本次导出请求编号复用；导出动作的 request_id
	// 只取本请求由服务端生成的编号，绝不采用客户端表单值。
	for _, key := range []string{"from", "to", "tz", "app_id", "actor_type", "actor_id",
		"action", "outcome", "error_code", "task_id", "target_type", "target_id",
		"system_only", "order"} {
		if value := request.PostForm.Get(key); value != "" {
			values.Set(key, value)
		}
	}
	if value := strings.TrimSpace(request.PostForm.Get("filter_request_id")); value != "" {
		values.Set("request_id", value)
	}
	filter, fieldErrors := parseAuditFilter(values, location, h.pages.options.Now())
	if len(fieldErrors) > 0 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, FieldErrors: fieldErrors,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	// 导出动作编号只使用服务端编号：优先本请求上下文编号，缺失时由服务端生成新的
	// 随机编号；绝不采用客户端表单值（防止把任意 request_id 带入审计关联）。
	requestID := page.RequestID
	if requestID == "" {
		requestID = NewRequestID()
	}
	export, err := h.pages.options.Backend.CreateExport(ctx, page.Session.UserID,
		UIAuditExportRequest{ScopeID: UIAuditScopeSystem, Filter: filter,
			Order: auditOrder(values.Get("order")), Format: format, RequestID: requestID})
	if err != nil {
		return auditErrorOutcome(err, nil, "page.admin.audit.export.failed"), nil
	}
	return h.renderExports(ctx, request, page, export.ID, map[string]any{
		"submitted": true, "submittedTaskID": export.TaskID, "exportID": export.ID})
}

// cancelExport 请求取消导出任务；提交取消不等于实际取消。
func (h *auditPageHandlers) cancelExport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if err := request.ParseForm(); err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	if outcome, ok := h.checkAuditCSRF(ctx, request, page, request.PostForm); !ok {
		return outcome, nil
	}
	exportID := strings.TrimSpace(request.PostForm.Get("export_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if exportID == "" || reason == "" || len(reason) > 256 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.export.cancel_invalid")}, nil
	}
	export, err := h.pages.options.Backend.CancelExport(ctx, page.Session.UserID, exportID,
		reason, page.RequestID)
	if err != nil {
		return auditErrorOutcome(err, nil, "page.admin.audit.export.cancel_failed"), nil
	}
	return h.renderExports(ctx, request, page, "", map[string]any{
		"cancelRequested": true, "exportDetail": export, "downloadAvailable": false})
}

// downloadExport 下载受控导出产物；只在真实成功且当前权限仍有效时提供字节。
func (h *auditPageHandlers) downloadExport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	exportID := strings.TrimSpace(request.URL.Query().Get("export_id"))
	if exportID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.export.download_missing")}, nil
	}
	file, err := h.pages.options.Backend.DownloadExport(ctx, page.Session.UserID, exportID)
	if err != nil {
		return auditErrorOutcome(err, nil, "page.admin.audit.export.download_failed"), nil
	}
	headers := http.Header{}
	headers.Set("Content-Disposition", `attachment; filename="`+safeDownloadName(file.Name)+`"`)
	headers.Set("Content-Type", file.ContentType)
	return UIPageOutcome{StatusCode: http.StatusOK, ContentType: file.ContentType,
		Body: file.Body, Headers: headers}, nil
}

// safeDownloadName 只保留安全文件名字符，避免响应头注入与路径信息。
func safeDownloadName(name string) string {
	var builder strings.Builder
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' {
			builder.WriteRune(character)
		}
		if builder.Len() >= 96 {
			break
		}
	}
	if builder.Len() == 0 {
		return "audit_export"
	}
	return builder.String()
}

// maintenance 渲染 root 审计清理页（保留策略 + 只读预估 + 真实运行列表）。
func (h *auditPageHandlers) maintenance(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"forbidden": false, "runs": []UIPurgeRun{}, "limit": 20, "offset": 0,
		"retention": UIPurgeRetention{}}
	if !caps.Purge {
		h.recordPageDenial(ctx, page, "purge_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.forbidden")}, nil
	}
	limit, offset, ok := parsePageWindow(request.URL.Query())
	if !ok {
		limit, offset = 20, 0
	}
	contextResult, err := h.pages.options.Backend.PurgeContext(ctx, page.Session.UserID,
		UIAuditScopeSystem, limit, offset)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.maintenance.load_failed"), nil
	}
	data["retention"] = contextResult.Retention
	data["runs"] = contextResult.Runs
	data["hasMore"] = contextResult.HasMore
	data["limit"], data["offset"] = limit, offset
	data["updatedAt"] = time.Now().UTC()
	data["prevURL"], data["nextURL"] = paginationURLs(request, contextResult.HasMore, limit, offset)
	return UIPageOutcome{Data: data}, nil
}

// purgeRequest 解析清理预估/提交参数（时间、批次、上限、原因）。
func purgeRequest(values url.Values, page UIPageContext) (UIPurgeRequest, string, map[string]string) {
	fieldErrors := map[string]string{}
	request := UIPurgeRequest{ScopeID: UIAuditScopeSystem, BatchSize: 500, MaxRecords: 100_000}
	cutoff, ok := parseDateBound(values.Get("cutoff"), pageLocation(page))
	if !ok || cutoff.IsZero() {
		fieldErrors["cutoff"] = text("page.admin.audit.maintenance.invalid_cutoff")
	}
	request.Cutoff = cutoff
	if raw := strings.TrimSpace(values.Get("batch_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 5_000 {
			fieldErrors["batch_size"] = text("page.admin.audit.maintenance.invalid_batch")
		} else {
			request.BatchSize = parsed
		}
	}
	if raw := strings.TrimSpace(values.Get("max_records")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1_000_000 {
			fieldErrors["max_records"] = text("page.admin.audit.maintenance.invalid_max")
		} else {
			request.MaxRecords = parsed
		}
	}
	reason := strings.TrimSpace(values.Get("reason"))
	if reason == "" || len(reason) > 256 {
		fieldErrors["reason"] = text("page.admin.audit.maintenance.invalid_reason")
	}
	return request, reason, fieldErrors
}

// previewPurge 执行只读预估并渲染独立确认页；预估不是删除结果。
func (h *auditPageHandlers) previewPurge(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if err := request.ParseForm(); err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	if outcome, ok := h.checkAuditCSRF(ctx, request, page, request.PostForm); !ok {
		return outcome, nil
	}
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"retention": UIPurgeRetention{}}
	if !caps.Purge {
		h.recordPageDenial(ctx, page, "purge_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.forbidden")}, nil
	}
	purgeReq, reason, fieldErrors := purgeRequest(request.PostForm, page)
	if len(fieldErrors) > 0 {
		data["fieldErrors"] = fieldErrors
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  fieldErrors,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	preview, err := h.pages.options.Backend.PreviewPurge(ctx, page.Session.UserID, purgeReq)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.maintenance.preview_failed"), nil
	}
	data["retention"] = UIPurgeRetention{}
	if contextResult, contextErr := h.pages.options.Backend.PurgeContext(ctx,
		page.Session.UserID, UIAuditScopeSystem, 20, 0); contextErr == nil {
		data["retention"] = contextResult.Retention
	} else {
		data["retentionLoadFailed"] = true
	}
	data["confirm"] = true
	data["preview"] = preview
	data["reason"] = reason
	// 预估页不读取运行列表，避免把旧运行结果当作本次结果。
	return UIPageOutcome{Data: data}, nil
}

// startPurge 提交真实清理任务：确认摘要必须与服务端同参数一致，提交仍再次授权。
func (h *auditPageHandlers) startPurge(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if err := request.ParseForm(); err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	if outcome, ok := h.checkAuditCSRF(ctx, request, page, request.PostForm); !ok {
		return outcome, nil
	}
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"retention": UIPurgeRetention{}}
	if !caps.Purge {
		h.recordPageDenial(ctx, page, "purge_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.forbidden")}, nil
	}
	digest := strings.TrimSpace(request.PostForm.Get("digest"))
	if digest == "" {
		data["stalePreview"] = true
		return UIPageOutcome{StatusCode: http.StatusConflict, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.stale_preview")}, nil
	}
	purgeReq, reason, fieldErrors := purgeRequest(request.PostForm, page)
	if len(fieldErrors) > 0 {
		data["fieldErrors"] = fieldErrors
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  fieldErrors,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	run, err := h.pages.options.Backend.StartPurge(ctx, page.Session.UserID, purgeReq,
		digest, reason, page.RequestID)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.maintenance.start_failed"), nil
	}
	data["submitted"] = true
	data["run"] = run
	// 提交受理后重新读取真实运行列表；读取失败只标区域失败，不把提交结果当作完成。
	if contextResult, contextErr := h.pages.options.Backend.PurgeContext(ctx,
		page.Session.UserID, UIAuditScopeSystem, 20, 0); contextErr == nil {
		data["retention"] = contextResult.Retention
		data["runs"] = contextResult.Runs
	} else {
		data["runsLoadFailed"] = true
	}
	data["updatedAt"] = time.Now().UTC()
	return UIPageOutcome{Data: data}, nil
}

// cancelPurge 请求取消清理任务；取消请求被接受不等于实际取消。
func (h *auditPageHandlers) cancelPurge(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if err := request.ParseForm(); err != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.audit.filter.invalid_summary")}, nil
	}
	if outcome, ok := h.checkAuditCSRF(ctx, request, page, request.PostForm); !ok {
		return outcome, nil
	}
	caps := h.auditCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "timezone": page.TimeZone,
		"retention": UIPurgeRetention{}}
	if !caps.Purge {
		h.recordPageDenial(ctx, page, "purge_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.forbidden")}, nil
	}
	runID := strings.TrimSpace(request.PostForm.Get("run_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if runID == "" || reason == "" || len(reason) > 256 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: text("page.admin.audit.maintenance.cancel_invalid")}, nil
	}
	run, err := h.pages.options.Backend.CancelPurge(ctx, page.Session.UserID, runID, reason,
		page.RequestID)
	if err != nil {
		return auditErrorOutcome(err, data, "page.admin.audit.maintenance.cancel_failed"), nil
	}
	data["cancelRequested"] = true
	data["run"] = run
	if contextResult, contextErr := h.pages.options.Backend.PurgeContext(ctx,
		page.Session.UserID, UIAuditScopeSystem, 20, 0); contextErr == nil {
		data["retention"] = contextResult.Retention
		data["runs"] = contextResult.Runs
	} else {
		data["runsLoadFailed"] = true
	}
	return UIPageOutcome{Data: data}, nil
}

// ensure errors 包被使用（错误映射需要 errors.As）。
var _ = errors.As
