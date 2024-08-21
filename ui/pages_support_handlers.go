package ui

// 步骤 71 客服/人工恢复页处理器：所有写操作都是显式 POST + 服务端重新授权；
// 页面把真实服务返回的状态/错误码映射为中文说明，不渲染假审批、假发送或静态成功。

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// supportPageHandlers 实现客服/人工恢复页处理器。
type supportPageHandlers struct {
	pages *pageSupportPages
}

// HandlePage 按路由分派。
func (h *supportPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "support.cases":
		return h.list(ctx, request, page)
	case "support.case_create":
		return h.createForm(ctx, request, page)
	case "support.case_create.submit":
		return h.createSubmit(ctx, request, page)
	case "support.case_detail":
		return h.detail(ctx, request, page)
	case "support.case_reassign.submit":
		return h.reassignSubmit(ctx, request, page)
	case "support.case_transition.submit":
		return h.transitionSubmit(ctx, request, page)
	case "support.case_send.submit":
		return h.sendSubmit(ctx, request, page)
	case "support.recovery_create.submit":
		return h.recoveryCreateSubmit(ctx, request, page)
	case "support.recovery_request":
		return h.recoveryDetail(ctx, request, page)
	case "support.recovery_cancel.submit":
		return h.recoveryCancelSubmit(ctx, request, page)
	case "support.recovery_inbox":
		return h.recoveryInbox(ctx, request, page)
	case "support.recovery_approval":
		return h.recoveryApproval(ctx, request, page)
	case "support.recovery_approve.submit":
		return h.recoveryApproveSubmit(ctx, request, page)
	case "support.recovery_reject.submit":
		return h.recoveryRejectSubmit(ctx, request, page)
	case "support.recovery_execute":
		return h.recoveryExecuteConfirm(ctx, request, page)
	case "support.recovery_execute.submit":
		return h.recoveryExecuteSubmit(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// supportCapabilities 读取能力位；失败时全部为 false（只影响按钮呈现，服务端仍授权）。
func (h *supportPageHandlers) supportCapabilities(ctx context.Context,
	page UIPageContext) UISupportCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UISupportCapabilities{}
	}
	return caps
}

// ===== 求助单列表 =====

// list 渲染当前工作人员被指派的求助单（状态筛选 + HasMore 分页）。
func (h *supportPageHandlers) list(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	query := UISupportCaseQuery{Status: strings.TrimSpace(request.URL.Query().Get("status")), Limit: 20}
	offset, ok := supportParseOffset(request.URL.Query().Get("offset"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.cases.invalid_query")}, nil
	}
	query.Offset = offset
	result, err := h.pages.options.Backend.ListCases(ctx, page.Session.UserID, query)
	if err != nil {
		return supportErrorOutcome(err, nil, "page.support.cases.load_failed"), nil
	}
	caps := h.supportCapabilities(ctx, page)
	filtered := query.Status != ""
	return UIPageOutcome{Data: map[string]any{
		"cases": result.Cases, "hasMore": result.HasMore, "nextOffset": result.NextOffset,
		"status": query.Status, "offset": offset, "filtered": filtered,
		"capabilities": caps,
	}}, nil
}

// ===== 登记求助单 =====

// createForm 渲染登记表单与目标摘要读取结果（读取不改变任何状态）。
func (h *supportPageHandlers) createForm(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.supportCapabilities(ctx, page)
	data := map[string]any{"capabilities": caps, "targetID": "",
		"reason": strings.TrimSpace(request.URL.Query().Get("reason"))}
	targetID, ok := supportQueryValue(request.URL.Query().Get("target_user_id"))
	if ok {
		target, lookupErr := h.pages.options.Backend.LookupTarget(ctx, page.Session.UserID,
			targetID, page.RequestID)
		if lookupErr != nil {
			data["targetID"] = targetID
			return supportErrorOutcome(lookupErr, data, "page.support.case_create.lookup_failed"), nil
		}
		data["target"] = target
		data["targetID"] = targetID
	}
	return UIPageOutcome{Data: data}, nil
}

// createSubmit 处理“读取目标摘要”与“登记求助单”两个独立动作；创建仍由服务端重查。
func (h *supportPageHandlers) createSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"action", "target_user_id", "reason", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_create.invalid")}, nil
	}
	action := strings.TrimSpace(form.Get("action"))
	targetID, ok := supportQueryValue(form.Get("target_user_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_create.invalid")}, nil
	}
	if action == "lookup" {
		target, lookupErr := h.pages.options.Backend.LookupTarget(ctx, page.Session.UserID,
			targetID, page.RequestID)
		if lookupErr != nil {
			return supportErrorOutcome(lookupErr, map[string]any{
				"targetID": targetID, "reason": form.Get("reason"),
			}, "page.support.case_create.lookup_failed"), nil
		}
		return UIPageOutcome{Data: map[string]any{"target": target, "targetID": targetID,
			"reason": form.Get("reason")}}, nil
	}
	if action != "create" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_create.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_create.confirm_required")}, nil
	}
	reason := form.Get("reason")
	created, err := h.pages.options.Backend.CreateCase(ctx, page.Session.UserID,
		targetID, reason, page.RequestID)
	if err != nil {
		return supportErrorOutcome(err, map[string]any{"targetID": targetID, "reason": reason},
			"page.support.case_create.submit_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"created": created, "targetID": targetID,
		"reason": reason, "notice": "created"}}, nil
}

// ===== 求助单详情 =====

// detail 渲染求助单详情：目标最小资料、可用处理路径、分派/状态/发送与只追加历史。
func (h *supportPageHandlers) detail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caseID, ok := supportQueryValue(request.URL.Query().Get("case_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	outcome, err := h.renderCaseDetail(ctx, page, caseID, "", nil)
	if err != nil {
		return supportErrorOutcome(err, nil, "page.support.case_detail.load_failed"), nil
	}
	return outcome, nil
}

// renderCaseDetail 读取并渲染求助单详情；notice 是成功后的一次性提示类别。
func (h *supportPageHandlers) renderCaseDetail(ctx context.Context, page UIPageContext,
	caseID, notice string, extra map[string]any) (UIPageOutcome, error) {
	detail, err := h.pages.options.Backend.GetCase(ctx, page.Session.UserID, caseID)
	if err != nil {
		return UIPageOutcome{}, err
	}
	policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
	data := map[string]any{
		"case": detail.Case, "history": detail.History,
		"historyUnavailable": detail.HistoryUnavailable,
		"target":             detail.Target, "targetUnread": detail.TargetUnread,
		"capabilities": detail.Capabilities, "notice": notice,
		"policy": policy, "policyAvailable": policyErr == nil,
		"statusLabel":      supportCaseStatusLabel(detail.Case.Status),
		"terminal":         detail.Case.Status == "closed" || detail.Case.Status == "cancelled",
		"waitPeriodLabel":  supportDurationLabel(policy.WaitPeriodSeconds),
		"approvalTTLLabel": supportDurationLabel(policy.ApprovalTTLSeconds),
		"requestTTLLabel":  supportDurationLabel(policy.RequestTTLSeconds),
	}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// reassignSubmit 把工单转派给另一名当前具备客服资格的工作人员。
func (h *supportPageHandlers) reassignSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"case_id", "new_assignee_user_id", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	caseID, ok := supportQueryValue(form.Get("case_id"))
	newAssignee, assigneeOK := supportQueryValue(form.Get("new_assignee_user_id"))
	if !ok || !assigneeOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.confirm_required")}, nil
	}
	if _, err := h.pages.options.Backend.ReassignCase(ctx, page.Session.UserID, caseID,
		newAssignee, page.RequestID); err != nil {
		return h.caseActionErrorOutcome(ctx, page, caseID, err, "page.support.case_detail.action_failed"), nil
	}
	return h.renderCaseDetail(ctx, page, caseID, "reassigned", nil)
}

// transitionSubmit 变更工单状态（不能手工写 sent，终态不可再改）。
func (h *supportPageHandlers) transitionSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"case_id", "to_status", "note", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	caseID, ok := supportQueryValue(form.Get("case_id"))
	toStatus := strings.TrimSpace(form.Get("to_status"))
	if !ok || (toStatus != "manual_review" && toStatus != "closed" && toStatus != "cancelled") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.confirm_required")}, nil
	}
	if _, err := h.pages.options.Backend.TransitionCase(ctx, page.Session.UserID, caseID,
		toStatus, form.Get("note"), page.RequestID); err != nil {
		return h.caseActionErrorOutcome(ctx, page, caseID, err, "page.support.case_detail.action_failed"), nil
	}
	return h.renderCaseDetail(ctx, page, caseID, "transitioned", nil)
}

// sendSubmit 向目标此前已验证邮箱发起一次性找回入口（不显示链接/验证码）。
func (h *supportPageHandlers) sendSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"case_id", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	caseID, ok := supportQueryValue(form.Get("case_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.case_detail.confirm_required")}, nil
	}
	result, err := h.pages.options.Backend.SendReset(ctx, page.Session.UserID, caseID, page.RequestID)
	if err != nil {
		return h.caseActionErrorOutcome(ctx, page, caseID, err, "page.support.case_detail.action_failed"), nil
	}
	notice := "manual_review"
	if result.Sent {
		notice = "reset_sent"
	}
	return h.renderCaseDetail(ctx, page, caseID, notice, map[string]any{"sendResult": result})
}

// caseActionErrorOutcome 在动作失败时仍尽量渲染当前详情（不清空对象上下文）。
func (h *supportPageHandlers) caseActionErrorOutcome(ctx context.Context, page UIPageContext,
	caseID string, actionErr error, fallbackKey string) UIPageOutcome {
	outcome := supportErrorOutcome(actionErr, nil, fallbackKey)
	if detail, err := h.pages.options.Backend.GetCase(ctx, page.Session.UserID, caseID); err == nil {
		policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
		outcome.Data = map[string]any{
			"case": detail.Case, "history": detail.History,
			"historyUnavailable": detail.HistoryUnavailable,
			"target":             detail.Target, "targetUnread": detail.TargetUnread,
			"capabilities": detail.Capabilities,
			"policy":       policy, "policyAvailable": policyErr == nil,
			"statusLabel":      supportCaseStatusLabel(detail.Case.Status),
			"terminal":         detail.Case.Status == "closed" || detail.Case.Status == "cancelled",
			"waitPeriodLabel":  supportDurationLabel(policy.WaitPeriodSeconds),
			"approvalTTLLabel": supportDurationLabel(policy.ApprovalTTLSeconds),
			"requestTTLLabel":  supportDurationLabel(policy.RequestTTLSeconds),
		}
	}
	return outcome
}

// ===== 人工恢复：申请/详情/取消 =====

// recoveryCreateSubmit 登记人工恢复申请（证据摘要只提交一次，不落库明文）。
func (h *supportPageHandlers) recoveryCreateSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"target_user_id", "operation", "verification_basis", "verification_reference",
		"evidence_summary", "reason", "delivery", "support_case_id", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.invalid")}, nil
	}
	targetID, targetOK := supportQueryValue(form.Get("target_user_id"))
	operation := strings.TrimSpace(form.Get("operation"))
	if !targetOK || (operation != "password_reset" && operation != "mfa_reset") {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.confirm_required")}, nil
	}
	caseID := strings.TrimSpace(form.Get("support_case_id"))
	create := UISupportRecoveryCreate{
		TargetUserID: targetID, Operation: operation,
		VerificationBasis:     strings.TrimSpace(form.Get("verification_basis")),
		VerificationReference: strings.TrimSpace(form.Get("verification_reference")),
		EvidenceSummary:       form.Get("evidence_summary"),
		Reason:                form.Get("reason"),
		Delivery:              strings.TrimSpace(form.Get("delivery")),
		SupportCaseID:         caseID,
	}
	created, err := h.pages.options.Backend.CreateRecoveryRequest(ctx, page.Session.UserID,
		create, page.RequestID)
	if err != nil {
		return supportErrorOutcome(err, map[string]any{"targetID": targetID,
			"operation": operation, "supportCaseID": caseID},
			"page.support.recovery_request.create_failed"), nil
	}
	return h.renderRecoveryDetail(ctx, page, created.ID, "created", nil)
}

// recoveryDetail 渲染人工恢复申请详情（参与人/候选审批人按服务端授权读取）。
func (h *supportPageHandlers) recoveryDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	requestID, ok := supportQueryValue(request.URL.Query().Get("request_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.invalid")}, nil
	}
	return h.renderRecoveryDetail(ctx, page, requestID, "", nil)
}

// renderRecoveryDetail 读取并渲染人工恢复详情；notice 为成功后一次性提示类别。
func (h *supportPageHandlers) renderRecoveryDetail(ctx context.Context, page UIPageContext,
	requestID, notice string, extra map[string]any) (UIPageOutcome, error) {
	view, err := h.pages.options.Backend.GetRecoveryRequest(ctx, page.Session.UserID, requestID)
	if err != nil {
		return supportErrorOutcome(err, nil, "page.support.recovery_request.load_failed"), nil
	}
	caps := h.supportCapabilities(ctx, page)
	policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
	isInitiator := view.InitiatorUserID != "" && view.InitiatorUserID == page.Session.UserID
	isTarget := view.TargetUserID != "" && view.TargetUserID == page.Session.UserID
	executeBlocked := supportExecuteBlockedKey(policy, policyErr == nil, view, caps)
	data := map[string]any{
		"request": view, "capabilities": caps, "policy": policy,
		"policyAvailable": policyErr == nil, "notice": notice,
		"policyEnabled": policy.Enabled,
		"canExecute":    executeBlocked == "", "executeBlockedKey": executeBlocked,
		"staffID":     page.Session.UserID,
		"isInitiator": isInitiator, "isTarget": isTarget,
		"statusLabel":         supportRecoveryStatusLabel(view.Status),
		"operationLabel":      supportOperationLabel(view.Operation),
		"basisLabel":          supportBasisLabel(view.VerificationBasis),
		"deliveryLabel":       supportDeliveryLabel(view.Delivery),
		"waitPeriodLabel":     supportDurationLabel(policy.WaitPeriodSeconds),
		"approvalTTLLabel":    supportDurationLabel(policy.ApprovalTTLSeconds),
		"requestTTLLabel":     supportDurationLabel(policy.RequestTTLSeconds),
		"independentRequired": policy.RequireIndependentApproval,
		"terminal":            supportRecoveryTerminal(view.Status),
	}
	for key, value := range extra {
		data[key] = value
	}
	return UIPageOutcome{Data: data}, nil
}

// supportRecoveryTerminal 报告人工恢复状态是否为终态。
func supportRecoveryTerminal(status string) bool {
	switch status {
	case "completed", "rejected", "cancelled", "failed", "expired":
		return true
	default:
		return false
	}
}

// supportExecuteBlockedKey 返回执行被阻止的真实原因 i18n 键；空字符串表示可执行。
// 只用于页面呈现，最终执行仍由 manualrecovery 服务按申请/批准/等待期/内容绑定/
// 权限失败关闭地重新判定。
func supportExecuteBlockedKey(policy UISupportRecoveryPolicy, policyAvailable bool,
	view UISupportRecoveryView, caps UISupportCapabilities) string {
	switch {
	case !policyAvailable:
		return "page.support.recovery_request.policy_unavailable"
	case !policy.Enabled:
		return "page.support.recovery_request.not_enabled"
	case !caps.ExecuteRecovery:
		return "page.support.recovery_execute.denied"
	case view.Status != "approved":
		return "page.support.recovery_execute.not_approved"
	case !view.HasApproval:
		return "page.support.recovery_execute.not_approved"
	case !view.ContentConsistent:
		return "page.support.recovery_request.content_changed"
	default:
		return ""
	}
}

// recoveryCancelSubmit 由发起者取消待审批/已批准申请（必须填写理由）。
func (h *supportPageHandlers) recoveryCancelSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"request_id", "reason", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.invalid")}, nil
	}
	requestID, ok := supportQueryValue(form.Get("request_id"))
	reason := strings.TrimSpace(form.Get("reason"))
	if !ok || reason == "" || len(reason) > 200 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_request.confirm_required")}, nil
	}
	if err := h.pages.options.Backend.CancelRecovery(ctx, page.Session.UserID, requestID,
		reason, page.RequestID); err != nil {
		return h.recoveryActionErrorOutcome(ctx, page, requestID, err,
			"page.support.recovery_request.cancel_failed"), nil
	}
	return h.renderRecoveryDetail(ctx, page, requestID, "cancelled", nil)
}

// recoveryActionErrorOutcome 在动作失败时尽量保留申请上下文。
func (h *supportPageHandlers) recoveryActionErrorOutcome(ctx context.Context, page UIPageContext,
	requestID string, actionErr error, fallbackKey string) UIPageOutcome {
	outcome := supportErrorOutcome(actionErr, nil, fallbackKey)
	if view, err := h.pages.options.Backend.GetRecoveryRequest(ctx, page.Session.UserID, requestID); err == nil {
		caps := h.supportCapabilities(ctx, page)
		policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
		outcome.Data = map[string]any{
			"request": view, "capabilities": caps, "policy": policy,
			"policyAvailable": policyErr == nil, "staffID": page.Session.UserID,
			"isInitiator":         view.InitiatorUserID == page.Session.UserID,
			"isTarget":            view.TargetUserID == page.Session.UserID,
			"statusLabel":         supportRecoveryStatusLabel(view.Status),
			"operationLabel":      supportOperationLabel(view.Operation),
			"basisLabel":          supportBasisLabel(view.VerificationBasis),
			"deliveryLabel":       supportDeliveryLabel(view.Delivery),
			"waitPeriodLabel":     supportDurationLabel(policy.WaitPeriodSeconds),
			"approvalTTLLabel":    supportDurationLabel(policy.ApprovalTTLSeconds),
			"requestTTLLabel":     supportDurationLabel(policy.RequestTTLSeconds),
			"independentRequired": policy.RequireIndependentApproval,
			"terminal":            supportRecoveryTerminal(view.Status),
		}
	}
	return outcome
}

// ===== 独立审批 =====

// recoveryInbox 渲染审批/执行工作台：通过可选列表能力读取真实待办，逐条由服务端
// 判权；旧适配器未实现列表时明确显示不可用，不枚举 ID、不伪造条目。
func (h *supportPageHandlers) recoveryInbox(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.supportCapabilities(ctx, page)
	policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
	mode := strings.TrimSpace(request.URL.Query().Get("mode"))
	if mode == "" {
		mode = "pending_approval"
	}
	operation := strings.TrimSpace(request.URL.Query().Get("operation"))
	offset := 0
	if raw := strings.TrimSpace(request.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	data := map[string]any{
		"capabilities": caps, "policy": policy, "policyAvailable": policyErr == nil,
		"mode": mode, "operation": operation, "offset": offset,
		"mayApprove": caps.ApprovePassword || caps.ApproveMFA,
		"mayExecute": caps.ExecuteRecovery, "mayRequest": caps.RequestRecovery,
	}
	lister, ok := h.pages.options.Backend.(UISupportRecoveryLister)
	if !ok {
		data["listUnavailable"] = true
		return UIPageOutcome{Data: data}, nil
	}
	list, listErr := lister.ListRecoveryForPage(ctx, page.Session.UserID, mode, operation,
		offset, 20)
	if listErr != nil {
		// 制度关闭是真实状态，不是页面故障：显示关闭说明而不是错误页。
		if typed, ok := listErr.(*UISupportError); ok && typed != nil && typed.Code == "DISABLED" {
			data["listUnavailable"] = true
			return UIPageOutcome{Data: data}, nil
		}
		return supportErrorOutcome(listErr, data, "page.support.recovery_inbox.load_failed"), nil
	}
	data["items"] = list.Items
	data["hasMore"] = list.HasMore
	data["nextOffset"] = list.NextOffset
	return UIPageOutcome{Data: data}, nil
}

// recoveryApproval 渲染独立审批页：真正将执行的目标/操作/交付/等待期在批准表单之前。
func (h *supportPageHandlers) recoveryApproval(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	requestID, ok := supportQueryValue(request.URL.Query().Get("request_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.invalid")}, nil
	}
	view, err := h.pages.options.Backend.GetRecoveryRequest(ctx, page.Session.UserID, requestID)
	if err != nil {
		return supportErrorOutcome(err, nil, "page.support.recovery_approval.load_failed"), nil
	}
	caps := h.supportCapabilities(ctx, page)
	policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
	isInitiator := view.InitiatorUserID == page.Session.UserID
	isTarget := view.TargetUserID == page.Session.UserID
	canApproveByPermission := caps.ApprovePassword
	if view.Operation == "mfa_reset" {
		canApproveByPermission = caps.ApproveMFA
	}
	canApprove := policy.Enabled && view.Status == "pending_approval" && !isInitiator &&
		!isTarget && canApproveByPermission
	canReject := canApprove
	data := map[string]any{
		"request": view, "capabilities": caps, "policy": policy,
		"policyAvailable": policyErr == nil, "staffID": page.Session.UserID,
		"isInitiator": isInitiator, "isTarget": isTarget,
		"canApprove": canApprove, "canReject": canReject,
		"statusLabel":         supportRecoveryStatusLabel(view.Status),
		"operationLabel":      supportOperationLabel(view.Operation),
		"basisLabel":          supportBasisLabel(view.VerificationBasis),
		"deliveryLabel":       supportDeliveryLabel(view.Delivery),
		"waitPeriodLabel":     supportDurationLabel(policy.WaitPeriodSeconds),
		"approvalTTLLabel":    supportDurationLabel(policy.ApprovalTTLSeconds),
		"requestTTLLabel":     supportDurationLabel(policy.RequestTTLSeconds),
		"independentRequired": policy.RequireIndependentApproval,
	}
	return UIPageOutcome{Data: data}, nil
}

// recoveryApproveSubmit 批准申请（不执行；之后仍需等待期与服务端复核）。
func (h *supportPageHandlers) recoveryApproveSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"request_id", "note", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.invalid")}, nil
	}
	requestID, ok := supportQueryValue(form.Get("request_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.confirm_required")}, nil
	}
	approval, err := h.pages.options.Backend.ApproveRecovery(ctx, page.Session.UserID,
		requestID, form.Get("note"), page.RequestID)
	if err != nil {
		return h.recoveryActionErrorOutcome(ctx, page, requestID, err,
			"page.support.recovery_approval.approve_failed"), nil
	}
	return h.renderRecoveryDetail(ctx, page, requestID, "approved",
		map[string]any{"approval": approval, "hasApproval": true})
}

// recoveryRejectSubmit 由独立审批人拒绝申请（终态）。
func (h *supportPageHandlers) recoveryRejectSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{
		"request_id", "reason", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.invalid")}, nil
	}
	requestID, ok := supportQueryValue(form.Get("request_id"))
	reason := strings.TrimSpace(form.Get("reason"))
	if !ok || reason == "" || len(reason) > 200 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_approval.confirm_required")}, nil
	}
	if err := h.pages.options.Backend.RejectRecovery(ctx, page.Session.UserID, requestID,
		reason, page.RequestID); err != nil {
		return h.recoveryActionErrorOutcome(ctx, page, requestID, err,
			"page.support.recovery_approval.reject_failed"), nil
	}
	// 拒绝不写入批准记录；当前服务没有“拒绝人读取终态申请”的受控投影，因此这里只
	// 显示本次真实动作结果，并明确终态读取能力未提供，不伪造后续读取权限。
	return UIPageOutcome{Data: map[string]any{"action": "rejected", "requestID": requestID,
		"staffID": page.Session.UserID}}, nil
}

// ===== 执行 =====

// recoveryExecuteConfirm 渲染执行确认页：实际目标/操作/后果/时间窗口/确认不是授权。
func (h *supportPageHandlers) recoveryExecuteConfirm(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	requestID, ok := supportQueryValue(request.URL.Query().Get("request_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_execute.invalid")}, nil
	}
	view, err := h.pages.options.Backend.GetRecoveryRequest(ctx, page.Session.UserID, requestID)
	if err != nil {
		return supportErrorOutcome(err, nil, "page.support.recovery_execute.load_failed"), nil
	}
	caps := h.supportCapabilities(ctx, page)
	policy, policyErr := h.pages.options.Backend.RecoveryPolicy(ctx, page.Session.UserID)
	blockedKey := supportExecuteBlockedKey(policy, policyErr == nil, view, caps)
	canExecute := blockedKey == ""
	return UIPageOutcome{Data: map[string]any{
		"request": view, "capabilities": caps, "policy": policy,
		"policyAvailable": policyErr == nil, "staffID": page.Session.UserID,
		"canExecute": canExecute, "executeBlockedKey": blockedKey,
		"statusLabel":      supportRecoveryStatusLabel(view.Status),
		"operationLabel":   supportOperationLabel(view.Operation),
		"deliveryLabel":    supportDeliveryLabel(view.Delivery),
		"waitPeriodLabel":  supportDurationLabel(policy.WaitPeriodSeconds),
		"approvalTTLLabel": supportDurationLabel(policy.ApprovalTTLSeconds),
	}}, nil
}

// recoveryExecuteSubmit 提交一次性执行；失败/冲突时重新读取真实状态，绝不直接重试。
func (h *supportPageHandlers) recoveryExecuteSubmit(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	form, formErr := readPageForm(request, page.CSRFField, []string{"request_id", "confirm"})
	if formErr != nil {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_execute.invalid")}, nil
	}
	requestID, ok := supportQueryValue(form.Get("request_id"))
	if !ok {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_execute.invalid")}, nil
	}
	if form.Get("confirm") != "yes" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.support.recovery_execute.confirm_required")}, nil
	}
	execution, err := h.pages.options.Backend.ExecuteRecovery(ctx, page.Session.UserID,
		requestID, page.RequestID)
	if err == nil {
		outcome, renderErr := h.renderRecoveryDetail(ctx, page, requestID, "executed",
			map[string]any{"execution": execution, "hasExecution": true})
		if renderErr != nil {
			return supportErrorOutcome(renderErr, nil, "page.support.recovery_execute.failed"), nil
		}
		return outcome, nil
	}
	// 失败/冲突：重新读取真实状态；只有确认同一申请已完成时才显示幂等提示。
	if view, readErr := h.pages.options.Backend.GetRecoveryRequest(ctx, page.Session.UserID,
		requestID); readErr == nil {
		if view.Status == "completed" && view.HasExecution {
			outcome, renderErr := h.renderRecoveryDetail(ctx, page, requestID, "already_executed",
				map[string]any{"execution": view.Execution, "hasExecution": true})
			if renderErr == nil {
				return outcome, nil
			}
		}
		if view.Status == "executing" {
			outcome := supportErrorOutcome(err, nil, "page.support.recovery_execute.unknown")
			outcome.Data = map[string]any{"request": view, "staffID": page.Session.UserID,
				"statusLabel":    supportRecoveryStatusLabel(view.Status),
				"operationLabel": supportOperationLabel(view.Operation),
				"deliveryLabel":  supportDeliveryLabel(view.Delivery)}
			return outcome, nil
		}
	}
	return h.recoveryActionErrorOutcome(ctx, page, requestID, err,
		"page.support.recovery_execute.failed"), nil
}
