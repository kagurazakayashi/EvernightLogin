package login

// 步骤 72 敏感策略与安全通知页处理器：所有写操作都是显式 POST + 服务端重新授权；
// 页面把真实服务返回的状态/错误码映射为中文说明，不渲染假开关、假保存或静态成功。

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// securityPolicyPageHandlers 实现敏感策略/安全通知页处理器。
type securityPolicyPageHandlers struct {
	pages *pageSecurityPolicyPages
}

// securityPolicyKnownDomains 是目录支持的业务域（筛选白名单）。
var securityPolicyKnownDomains = []string{"password", "email", "mfa", "permission",
	"application", "backup", "audit", "session", "profile", "recovery"}

// HandlePage 按路由分派。
func (h *securityPolicyPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.security_policies":
		return h.list(ctx, request, page)
	case "admin.security_policy_detail":
		return h.detail(ctx, request, page)
	case "admin.security_policy_preview":
		return h.preview(ctx, request, page)
	case "admin.security_policy_save":
		return h.save(ctx, request, page)
	case "admin.security_policy_diff":
		return h.diff(ctx, request, page)
	case "admin.security_policy_restore_preview":
		return h.restorePreview(ctx, request, page)
	case "admin.security_policy_restore":
		return h.restore(ctx, request, page)
	case "admin.notification_mail":
		return h.notification(ctx, request, page)
	case "admin.notification_mail_template_preview":
		return h.templatePreview(ctx, request, page)
	case "admin.notification_mail_test":
		return h.testMail(ctx, request, page)
	case "admin.notification_mail_secret":
		return h.replaceSecret(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// securityPolicyCapabilities 读取页面能力位；失败时全部为 false（只影响呈现）。
func (h *securityPolicyPageHandlers) securityPolicyCapabilities(ctx context.Context,
	page UIPageContext) UISecurityPolicyCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UISecurityPolicyCapabilities{}
	}
	return caps
}

// checkPageCSRF 校验页面表单安全令牌：令牌必须等于本请求由宿主会话服务签发的一次性
// 页面令牌，并通过宿主提供的 ValidateCSRF（生产接 session.ValidateCSRFToken）。
// 页面层不依赖可能默认关闭的 transport CSRF 中间件；失败即拒绝，不进入业务处理。
func (h *securityPolicyPageHandlers) checkPageCSRF(ctx context.Context, request *http.Request,
	page UIPageContext, form url.Values) (UIPageOutcome, bool) {
	token := strings.TrimSpace(form.Get(page.CSRFField))
	if token == "" || page.CSRF == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(page.CSRF)) != 1 {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.csrf.invalid")}, false
	}
	if err := h.pages.options.ValidateCSRF(ctx, request, token); err != nil {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.csrf.invalid")}, false
	}
	return UIPageOutcome{}, true
}

// findSecurityPolicyOperation 在快照中按稳定 ID 查找操作。
func findSecurityPolicyOperation(snapshot UISecurityPolicySnapshot,
	operationID string) (UISecurityPolicyOperation, bool) {
	for _, operation := range snapshot.Operations {
		if operation.OperationID == operationID {
			return operation, true
		}
	}
	return UISecurityPolicyOperation{}, false
}

// ===== 目录列表 =====

// list 渲染敏感操作目录（业务域/来源/只看差异筛选；当前完整快照不分页）。
func (h *securityPolicyPageHandlers) list(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.securityPolicyCapabilities(ctx, page)
	if !caps.ReadPolicies {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.common.forbidden"),
			Data: map[string]any{"capabilities": caps, "forbidden": true,
				"empty": false, "noDiff": false}}, nil
	}
	snapshot, err := h.pages.options.Backend.Snapshot(ctx, page.Session.UserID,
		UISecurityPolicySystemScope)
	if err != nil {
		outcome := securityPolicyErrorOutcome(err, map[string]any{
			"capabilities": caps, "forbidden": false, "loadFailed": true,
			"snapshot": nil}, "page.admin.security_policy.load_failed")
		return outcome, nil
	}
	domain := strings.TrimSpace(request.URL.Query().Get("domain"))
	if domain != "" && !containsString(securityPolicyKnownDomains, domain) {
		domain = ""
	}
	source := strings.TrimSpace(request.URL.Query().Get("source"))
	if source != "default" && source != "override" && source != "application" {
		source = ""
	}
	onlyDiff := request.URL.Query().Get("only_diff") == "1"
	operations := make([]UISecurityPolicyOperation, 0, len(snapshot.Operations))
	for _, operation := range snapshot.Operations {
		if domain != "" && operation.Domain != domain {
			continue
		}
		if source != "" && operation.Source != source {
			continue
		}
		if onlyDiff && len(operation.ChangedFields) == 0 {
			continue
		}
		operations = append(operations, operation)
	}
	domainOptions := make([]map[string]string, 0, len(securityPolicyKnownDomains))
	for _, value := range securityPolicyKnownDomains {
		operation := UISecurityPolicyOperation{Domain: value}
		domainOptions = append(domainOptions, map[string]string{"value": value,
			"key": operation.DomainKey()})
	}
	filtered := domain != "" || source != "" || onlyDiff
	return UIPageOutcome{Data: map[string]any{
		"capabilities": caps, "snapshot": snapshot, "operations": operations,
		"domain": domain, "source": source, "onlyDiff": onlyDiff,
		"domainOptions": domainOptions,
		"filtered":      filtered, "forbidden": false,
		"noDiff":  snapshot.ChangedCount() == 0,
		"changed": snapshot.ChangedCount(),
		"total":   snapshot.OperationCount(),
	}}, nil
}

// ===== 单条详情 =====

// detail 渲染单条操作的三值对照、不可覆盖约束与 root 编辑表单。
func (h *securityPolicyPageHandlers) detail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	operationID, ok := safeSecurityPolicyValue(request.URL.Query().Get("operation"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.operation_unknown")}, nil
	}
	notice := request.URL.Query().Get("notice")
	return h.renderOperationDetail(ctx, page, operationID, notice, nil)
}

// renderOperationDetail 读取快照并渲染单条操作详情；extra 覆盖附加数据。
func (h *securityPolicyPageHandlers) renderOperationDetail(ctx context.Context,
	page UIPageContext, operationID, notice string,
	extra map[string]any) (UIPageOutcome, error) {
	caps := h.securityPolicyCapabilities(ctx, page)
	if !caps.ReadPolicies {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.common.forbidden"),
			Data:         map[string]any{"capabilities": caps, "forbidden": true}}, nil
	}
	snapshot, err := h.pages.options.Backend.Snapshot(ctx, page.Session.UserID,
		UISecurityPolicySystemScope)
	if err != nil {
		return securityPolicyErrorOutcome(err, map[string]any{
			"capabilities": caps, "forbidden": false},
			"page.admin.security_policy.load_failed"), nil
	}
	operation, found := findSecurityPolicyOperation(snapshot, operationID)
	if !found {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.security_policy.operation_unknown")}, nil
	}
	data := map[string]any{
		"capabilities": caps, "snapshot": snapshot, "operation": operation,
		"operationDomainKey": operation.DomainKey(), "operationSourceKey": operation.SourceKey(),
		"rows": securityPolicyFieldRows(operation, nil), "notice": notice,
		"showForm": caps.WritePolicies, "forbidden": false,
		"selfProtection":     operation.OperationID == "security.policy.change",
		"availableStrengths": snapshot.AvailableStrengths,
	}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// ===== 提交前预览 =====

// preview 校验并计算提交前预览（未执行），随后渲染确认表单。
func (h *securityPolicyPageHandlers) preview(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"operation_id", "expected_version", "sensitive", "reauth_required",
		"max_auth_age_seconds", "strength", "confirmation_required", "notification_required"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.invalid")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	operationID, ok := safeSecurityPolicyValue(form.Get("operation_id"))
	version, versionOK := parseExpectedVersion(form.Get("expected_version"))
	change, changeOK := parseSecurityPolicyValues(form)
	if !ok || !versionOK || !changeOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.invalid")}, nil
	}
	previewResult, err := h.pages.options.Backend.PreviewPolicy(ctx, page.Session.UserID,
		UISecurityPolicySystemScope, operationID, change)
	if err != nil {
		outcome := securityPolicyErrorOutcome(err, nil,
			"page.admin.security_policy.preview.invalid")
		return h.attachOperationDetail(ctx, page, operationID, outcome,
			map[string]any{"draft": change, "expectedVersion": version}), nil
	}
	caps := h.securityPolicyCapabilities(ctx, page)
	operation := UISecurityPolicyOperation{OperationID: previewResult.OperationID,
		Default: previewResult.Default, HasDefault: previewResult.HasDefault,
		Effective: previewResult.Current, ChangedFields: previewResult.ChangedFields}
	data := map[string]any{
		"capabilities": caps, "preview": previewResult, "operation": operation,
		"rows":  securityPolicyFieldRows(operation, &previewResult.Proposed),
		"draft": change, "expectedVersion": version,
		"selfProtection":  previewResult.SelfProtection,
		"strengthWarning": previewResult.StrengthWarning,
		"noChanges":       previewResult.NoChanges,
		"forbidden":       false,
	}
	return UIPageOutcome{Data: data}, nil
}

// save 在预览确认后执行真实策略写入（服务端重新检查 root/再次认证/版本/审计）。
func (h *securityPolicyPageHandlers) save(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"operation_id", "expected_version", "sensitive", "reauth_required",
		"max_auth_age_seconds", "strength", "confirmation_required",
		"notification_required", "confirm", "self_confirm", "preview_token"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.invalid")}, nil
	}
	operationID, ok := safeSecurityPolicyValue(form.Get("operation_id"))
	version, versionOK := parseExpectedVersion(form.Get("expected_version"))
	change, changeOK := parseSecurityPolicyValues(form)
	if !ok || !versionOK || !changeOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.invalid")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	previewToken := strings.TrimSpace(form.Get("preview_token"))
	if previewToken == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.required")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.save.confirm_required")}, nil
	}
	if operationID == "security.policy.change" && form.Get("self_confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.save.self_confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.SavePolicy(ctx, page.Session.UserID,
		UISecurityPolicySystemScope, operationID, change, version, previewToken, page.RequestID)
	if err != nil {
		if securityPolicyErrorCode(err) == "CONFLICT" {
			outcome, renderErr := h.renderOperationDetail(ctx, page, operationID, "",
				map[string]any{"draft": change, "expectedVersion": version,
					"conflict":        true,
					"conflictMessage": text("page.admin.security_policy.common.conflict")})
			if renderErr != nil {
				return UIPageOutcome{}, renderErr
			}
			outcome.StatusCode = http.StatusConflict
			return outcome, nil
		}
		outcome := securityPolicyErrorOutcome(err, nil,
			"page.admin.security_policy.save.failed")
		return h.attachOperationDetail(ctx, page, operationID, outcome,
			map[string]any{"draft": change, "expectedVersion": version}), nil
	}
	notice := "saved"
	if !result.Changed {
		notice = "unchanged"
	}
	return h.renderWrittenOperation(ctx, result.Snapshot, page, operationID, notice)
}

// renderWrittenOperation 用服务端返回的最新快照渲染写入结果（不回报拟提交值当生效值）。
func (h *securityPolicyPageHandlers) renderWrittenOperation(ctx context.Context,
	snapshot UISecurityPolicySnapshot, page UIPageContext, operationID,
	notice string) (UIPageOutcome, error) {
	operation, found := findSecurityPolicyOperation(snapshot, operationID)
	if !found {
		return UIPageOutcome{StatusCode: http.StatusConflict,
			ErrorSummary: text("page.admin.security_policy.common.conflict")}, nil
	}
	caps := h.securityPolicyCapabilities(ctx, page)
	return UIPageOutcome{Data: map[string]any{
		"capabilities": caps, "snapshot": snapshot, "operation": operation,
		"operationDomainKey": operation.DomainKey(), "operationSourceKey": operation.SourceKey(),
		"rows": securityPolicyFieldRows(operation, nil), "notice": notice,
		"showForm": caps.WritePolicies, "forbidden": false,
		"selfProtection":     operation.OperationID == "security.policy.change",
		"availableStrengths": snapshot.AvailableStrengths,
	}}, nil
}

// attachOperationDetail 在写入失败时尽量保留当前详情与未提交草稿。
func (h *securityPolicyPageHandlers) attachOperationDetail(ctx context.Context,
	page UIPageContext, operationID string, outcome UIPageOutcome,
	extra map[string]any) UIPageOutcome {
	caps := h.securityPolicyCapabilities(ctx, page)
	outcome.Data = map[string]any{"capabilities": caps, "forbidden": false}
	if snapshot, err := h.pages.options.Backend.Snapshot(ctx, page.Session.UserID,
		UISecurityPolicySystemScope); err == nil {
		if operation, found := findSecurityPolicyOperation(snapshot, operationID); found {
			outcome.Data = map[string]any{
				"capabilities": caps, "snapshot": snapshot, "operation": operation,
				"operationDomainKey": operation.DomainKey(),
				"operationSourceKey": operation.SourceKey(),
				"rows":               securityPolicyFieldRows(operation, nil),
				"showForm":           caps.WritePolicies, "forbidden": false,
				"selfProtection":     operation.OperationID == "security.policy.change",
				"availableStrengths": snapshot.AvailableStrengths,
			}
			for key, value := range extra {
				outcome.Data.(map[string]any)[key] = value
			}
		}
	}
	return outcome
}

// securityPolicyErrorCode 提取稳定公开错误码。
func securityPolicyErrorCode(err error) string {
	var publicErr *UISecurityPolicyError
	if errors.As(err, &publicErr) {
		return publicErr.Code
	}
	return ""
}

// ===== 覆盖与差异 =====

// diff 渲染当前作用域全部真实差异与应用声明分区。
func (h *securityPolicyPageHandlers) diff(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderDiff(ctx, page, "")
}

// renderDiff 读取快照并渲染差异页；notice 是成功后的一次性提示类别。
func (h *securityPolicyPageHandlers) renderDiff(ctx context.Context, page UIPageContext,
	notice string) (UIPageOutcome, error) {
	caps := h.securityPolicyCapabilities(ctx, page)
	if !caps.ReadPolicies {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.common.forbidden"),
			Data:         map[string]any{"capabilities": caps, "forbidden": true}}, nil
	}
	snapshot, err := h.pages.options.Backend.Snapshot(ctx, page.Session.UserID,
		UISecurityPolicySystemScope)
	if err != nil {
		return securityPolicyErrorOutcome(err, map[string]any{
			"capabilities": caps, "forbidden": false},
			"page.admin.security_policy.load_failed"), nil
	}
	affected := make([]map[string]any, 0)
	for _, operation := range snapshot.Operations {
		if operation.Source != "override" || len(operation.ChangedFields) == 0 {
			continue
		}
		affected = append(affected, map[string]any{"operation": operation,
			"rows": securityPolicyFieldRows(operation, nil)})
	}
	declared := make([]map[string]any, 0)
	for _, operation := range snapshot.Declared {
		declared = append(declared, map[string]any{"operation": operation,
			"rows": securityPolicyFieldRows(operation, nil)})
	}
	return UIPageOutcome{Data: map[string]any{
		"capabilities": caps, "snapshot": snapshot, "affected": affected,
		"declared": declared, "notice": notice, "forbidden": false,
		"changed": len(affected), "declaredCount": len(declared),
		"noDiff": len(affected) == 0,
	}}, nil
}

// ===== 恢复默认预览/确认 =====

// restorePreview 计算逐项/整体恢复的提交前预览（未执行）。
func (h *securityPolicyPageHandlers) restorePreview(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"mode", "operation_id"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.restore.preview_required")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	all, operationID, ok := parseRestoreTarget(form)
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.restore.preview_required")}, nil
	}
	return h.renderRestorePreview(ctx, page, all, operationID)
}

// parseRestoreTarget 解析恢复模式与操作 ID（one 必须有操作 ID）。
func parseRestoreTarget(form map[string][]string) (bool, string, bool) {
	mode := strings.TrimSpace(formValueFromMap(form, "mode"))
	switch mode {
	case "all":
		return true, "", true
	case "one":
		operationID, ok := safeSecurityPolicyValue(formValueFromMap(form, "operation_id"))
		return false, operationID, ok
	default:
		return false, "", false
	}
}

// formValueFromMap 读取单值表单字段。
func formValueFromMap(form map[string][]string, key string) string {
	values, ok := form[key]
	if !ok || len(values) != 1 {
		return ""
	}
	return values[0]
}

// renderRestorePreview 调用真实预览契约并渲染确认页。
func (h *securityPolicyPageHandlers) renderRestorePreview(ctx context.Context,
	page UIPageContext, all bool, operationID string) (UIPageOutcome, error) {
	caps := h.securityPolicyCapabilities(ctx, page)
	if !caps.ReadPolicies || !caps.WritePolicies {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.common.forbidden"),
			Data:         map[string]any{"capabilities": caps, "forbidden": true}}, nil
	}
	previewResult, err := h.pages.options.Backend.PreviewRestore(ctx, page.Session.UserID,
		UISecurityPolicySystemScope, operationID, all)
	if err != nil {
		return securityPolicyErrorOutcome(err, map[string]any{
			"capabilities": caps, "forbidden": false},
			"page.admin.security_policy.restore.preview_required"), nil
	}
	affected := make([]map[string]any, 0, len(previewResult.Operations))
	for _, operation := range previewResult.Operations {
		affected = append(affected, map[string]any{"operation": operation,
			"rows": securityPolicyFieldRows(operation, nil)})
	}
	declared := make([]map[string]any, 0, len(previewResult.Declared))
	for _, operation := range previewResult.Declared {
		declared = append(declared, map[string]any{"operation": operation})
	}
	return UIPageOutcome{Data: map[string]any{
		"capabilities": caps, "preview": previewResult, "affected": affected,
		"declared": declared, "all": all, "operationID": operationID,
		"affectedCount": len(affected), "selfProtection": previewResult.SelfProtection,
		"noChanges": previewResult.NoChanges, "forbidden": false,
	}}, nil
}

// restore 在确认后执行真实恢复（服务端重新检查 root/再次认证/版本/审计）。
func (h *securityPolicyPageHandlers) restore(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"mode", "operation_id", "expected_version", "affected_count", "self_protection",
		"confirm", "self_confirm", "preview_token"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.restore.preview_required")}, nil
	}
	all, operationID, targetOK := parseRestoreTarget(form)
	version, versionOK := parseExpectedVersion(form.Get("expected_version"))
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	previewToken := strings.TrimSpace(form.Get("preview_token"))
	if previewToken == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.preview.required")}, nil
	}
	if !targetOK || !versionOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.restore.preview_required")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.security_policy.restore.confirm_required")}, nil
	}
	// 重新计算预览，确认提交的实际范围/版本与用户看到的确认一致；范围或版本变化时
	// 旧确认与旧再次认证批准都失效，不能继续提交。
	previewResult, previewErr := h.pages.options.Backend.PreviewRestore(ctx, page.Session.UserID,
		UISecurityPolicySystemScope, operationID, all)
	if previewErr != nil {
		return securityPolicyErrorOutcome(previewErr, nil,
			"page.admin.security_policy.restore.preview_required"), nil
	}
	affectedCount, countErr := parseExpectedVersion(form.Get("affected_count"))
	selfProtection := form.Get("self_protection") == "1"
	if !countErr || previewResult.Version != version ||
		int64(len(previewResult.Operations)) != affectedCount ||
		previewResult.SelfProtection != selfProtection {
		outcome, renderErr := h.renderDiff(ctx, page, "stale")
		if renderErr != nil {
			return UIPageOutcome{}, renderErr
		}
		outcome.StatusCode = http.StatusConflict
		outcome.ErrorSummary = text("page.admin.security_policy.restore.stale")
		return outcome, nil
	}
	if selfProtection && form.Get("self_confirm") != "yes" {
		outcome, renderErr := h.renderRestorePreview(ctx, page, all, operationID)
		if renderErr != nil {
			return UIPageOutcome{}, renderErr
		}
		outcome.StatusCode = http.StatusBadRequest
		outcome.ErrorSummary = text("page.admin.security_policy.restore.self_confirm_required")
		return outcome, nil
	}
	result, err := h.pages.options.Backend.RestorePolicy(ctx, page.Session.UserID,
		UISecurityPolicySystemScope, operationID, all, version, previewToken, page.RequestID)
	if err != nil {
		if securityPolicyErrorCode(err) == "CONFLICT" {
			outcome, renderErr := h.renderDiff(ctx, page, "")
			if renderErr != nil {
				return UIPageOutcome{}, renderErr
			}
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.security_policy.common.conflict")
			return outcome, nil
		}
		return securityPolicyErrorOutcome(err, nil,
			"page.admin.security_policy.restore.confirm_required"), nil
	}
	notice := "restored"
	if !result.Changed {
		notice = "unchanged"
	}
	outcome, renderErr := h.renderDiff(ctx, page, notice)
	if renderErr != nil {
		return UIPageOutcome{}, renderErr
	}
	return outcome, nil
}

// ===== 安全通知设置 =====

// notification 渲染安全通知设置页（真实只读事实 + 受控动作）。
func (h *securityPolicyPageHandlers) notification(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	return h.renderNotification(ctx, page, nil)
}

// renderNotification 读取通知设置并渲染页面；extra 覆盖附加结果数据。
func (h *securityPolicyPageHandlers) renderNotification(ctx context.Context,
	page UIPageContext, extra map[string]any) (UIPageOutcome, error) {
	caps := h.securityPolicyCapabilities(ctx, page)
	settings, err := h.pages.options.Backend.NotificationSettings(ctx, page.Session.UserID)
	if err != nil {
		return securityPolicyErrorOutcome(err, map[string]any{
			"capabilities": caps, "forbidden": true},
			"page.admin.notification_mail.load_failed"), nil
	}
	if !settings.Capabilities.Read {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.security_policy.common.forbidden"),
			Data: map[string]any{"capabilities": caps, "settings": settings,
				"forbidden": true}}, nil
	}
	data := map[string]any{
		"capabilities": caps, "settings": settings, "forbidden": false,
		"templateKinds":  []string{"verification", "password_reset", "security_notice"},
		"idempotencyKey": newSecurityPolicyIdempotencyKey(),
	}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// templatePreview 用合成数据渲染模板（不保存、不发送）。
func (h *securityPolicyPageHandlers) templatePreview(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"kind"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.template.invalid")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	kind := strings.TrimSpace(form.Get("kind"))
	if kind != "verification" && kind != "password_reset" && kind != "security_notice" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.template.invalid")}, nil
	}
	previewResult, err := h.pages.options.Backend.PreviewTemplate(ctx, page.Session.UserID, kind)
	if err != nil {
		outcome := securityPolicyErrorOutcome(err, nil,
			"page.admin.notification_mail.template.preview_failed")
		return outcome, nil
	}
	return h.renderNotification(ctx, page, map[string]any{"templatePreview": previewResult,
		"previewKind": kind})
}

// testMail 处理“发送测试邮件”：必须用户明确指定目标，使用合成内容与已注入发送器。
func (h *securityPolicyPageHandlers) testMail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"recipient", "kind", "confirm", "idempotency_key"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.test.recipient_required")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	recipient := strings.TrimSpace(form.Get("recipient"))
	kind := strings.TrimSpace(form.Get("kind"))
	if recipient == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.test.recipient_required")}, nil
	}
	if kind != "verification" && kind != "password_reset" && kind != "security_notice" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.template.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.test.confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.SendTestMail(ctx, page.Session.UserID,
		recipient, kind, form.Get("idempotency_key"), page.RequestID)
	if err != nil {
		outcome := securityPolicyErrorOutcome(err, nil,
			"page.admin.notification_mail.test.failed")
		return h.attachNotification(ctx, page, outcome,
			map[string]any{"testRecipient": recipient, "testKind": kind}), nil
	}
	return h.renderNotification(ctx, page, map[string]any{"testResult": result,
		"testRecipient": "", "testKind": kind})
}

// attachNotification 在动作失败时保留真实设置上下文，不回声秘密。
func (h *securityPolicyPageHandlers) attachNotification(ctx context.Context,
	page UIPageContext, outcome UIPageOutcome, extra map[string]any) UIPageOutcome {
	settings, err := h.pages.options.Backend.NotificationSettings(ctx, page.Session.UserID)
	if err != nil {
		outcome.Data = map[string]any{"capabilities": UISecurityPolicyCapabilities{},
			"forbidden": false}
		return outcome
	}
	data := map[string]any{"capabilities": h.securityPolicyCapabilities(ctx, page),
		"settings": settings, "forbidden": false,
		"templateKinds":  []string{"verification", "password_reset", "security_notice"},
		"idempotencyKey": newSecurityPolicyIdempotencyKey()}
	for key, value := range extra {
		data[key] = value
	}
	outcome.Data = data
	return outcome
}

// replaceSecret 处理 SMTP 秘密替换：空值不修改；非空仅本次提交，失败不回显。
func (h *securityPolicyPageHandlers) replaceSecret(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"secret_password", "confirm", "idempotency_key"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.secret.invalid")}, nil
	}
	if rejected, ok := h.checkPageCSRF(ctx, request, page, form); !ok {
		return rejected, nil
	}
	caps := h.securityPolicyCapabilities(ctx, page)
	if !caps.ReplaceSecret {
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: text("page.admin.notification_mail.secret.unavailable")}, nil
	}
	newSecret := form.Get("secret_password")
	if newSecret == "" || len(newSecret) > 512 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.secret.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.notification_mail.secret.confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.ReplaceSMTPSecret(ctx, page.Session.UserID,
		newSecret, form.Get("idempotency_key"), page.RequestID)
	if err != nil {
		outcome := securityPolicyErrorOutcome(err, nil,
			"page.admin.notification_mail.secret.failed")
		return h.attachNotification(ctx, page, outcome, nil), nil
	}
	if result.Duplicate {
		return h.renderNotification(ctx, page, map[string]any{"secretDuplicate": true})
	}
	return h.renderNotification(ctx, page, map[string]any{"secretReplaced": result.Replaced})
}
