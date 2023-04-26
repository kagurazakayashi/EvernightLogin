// Package uiadminadapter 的步骤 71 补充：把客服求助、人工恢复申请与独立审批页面
// 公开契约接到真实 support/manualrecovery 服务。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的工作人员用户 ID，
// 每次都重新构造可信 Caller 并调用真实服务；功能权限、数据范围、目标保护、再次
// 认证与独立审批由领域服务判定；本包不实现放行、不缓存授权、不读取前端自报角色。
// 页面能力位只用于按钮呈现，且通过宿主注入的 Authorize 判定，不是授权证明。
package uiadminadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// SupportOptions 是客服页面适配器依赖。
type SupportOptions struct {
	Cases    *support.Service
	Recovery *manualrecovery.Service
	// Authorize 由宿主实现（authz + 管理强认证），用于判定页面能力位；为 nil 时
	// 能力位全部为 false（页面只呈现只读事实，写操作仍由领域服务授权）。
	Authorize func(ctx context.Context, staffUserID, action string) error
}

// SupportAdapter 实现 login.UISupportBackend。
type SupportAdapter struct {
	opts SupportOptions
}

// NewSupport 校验依赖并构造客服页面适配器。
func NewSupport(options SupportOptions) (*SupportAdapter, error) {
	if options.Cases == nil || options.Recovery == nil {
		return nil, fmt.Errorf("客服页面适配器缺少必需服务")
	}
	return &SupportAdapter{opts: options}, nil
}

var _ login.UISupportBackend = (*SupportAdapter)(nil)

// supportErr 构造稳定公开错误。
func supportErr(code string) error { return &login.UISupportError{Code: code} }

// supportCheck 判定页面能力位（失败按无能力处理，不影响真实服务授权）。
func (a *SupportAdapter) supportCheck(ctx context.Context, staffUserID, action string) bool {
	if a.opts.Authorize == nil || staffUserID == "" || !account.ValidUserID(staffUserID) {
		return false
	}
	return a.opts.Authorize(ctx, staffUserID, action) == nil
}

// supportMapError 把 support 领域错误映射为页面稳定错误码。
func supportMapError(err error) error {
	if err == nil {
		return nil
	}
	code := string(support.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &login.UISupportError{Code: code}
}

// recoveryMapError 把 manualrecovery 领域错误映射为页面稳定错误码。
func recoveryMapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, manualrecovery.ErrDisabled):
		return &login.UISupportError{Code: "DISABLED"}
	case errors.Is(err, manualrecovery.ErrSelfApproval):
		return &login.UISupportError{Code: "ACCESS_DENIED"}
	}
	code := string(manualrecovery.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &login.UISupportError{Code: code}
}

// Capabilities 返回当前工作人员的页面能力位（只影响呈现）。
func (a *SupportAdapter) Capabilities(ctx context.Context,
	staffUserID string) (login.UISupportCapabilities, error) {
	caps := login.UISupportCapabilities{
		ReadCases:       a.supportCheck(ctx, staffUserID, support.PermissionCasesRead),
		CreateCase:      a.supportCheck(ctx, staffUserID, support.PermissionCasesCreate),
		UpdateCase:      a.supportCheck(ctx, staffUserID, support.PermissionCasesUpdate),
		SendReset:       a.supportCheck(ctx, staffUserID, support.PermissionResetRequest),
		RequestRecovery: a.supportCheck(ctx, staffUserID, manualrecovery.PermissionRequest),
		ApprovePassword: a.supportCheck(ctx, staffUserID, manualrecovery.PermissionApprove),
		ApproveMFA:      a.supportCheck(ctx, staffUserID, manualrecovery.PermissionMFAApprove),
		ExecuteRecovery: a.supportCheck(ctx, staffUserID, manualrecovery.PermissionApprove),
	}
	return caps, nil
}

// supportCaller 构造客服可信调用者。
func supportCaller(staffUserID string) (support.Caller, error) {
	return support.UserCaller(staffUserID)
}

// ListCases 列出当前工作人员被指派的求助单。
func (a *SupportAdapter) ListCases(ctx context.Context, staffUserID string,
	query login.UISupportCaseQuery) (login.UISupportCasePage, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportCasePage{}, supportErr("ACCESS_DENIED")
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if query.Offset < 0 {
		return login.UISupportCasePage{}, supportErr("REQ_INVALID")
	}
	var statuses []support.CaseStatus
	if trimmed := strings.TrimSpace(query.Status); trimmed != "" {
		status := support.CaseStatus(trimmed)
		if !status.Valid() {
			return login.UISupportCasePage{}, supportErr("REQ_INVALID")
		}
		statuses = append(statuses, status)
	}
	page, err := a.opts.Cases.ListCases(ctx, caller, statuses, query.Offset, limit)
	if err != nil {
		return login.UISupportCasePage{}, supportMapError(err)
	}
	result := login.UISupportCasePage{HasMore: page.HasMore, NextOffset: page.NextOffset}
	for _, item := range page.Cases {
		result.Cases = append(result.Cases, supportCaseView(item))
	}
	return result, nil
}

// supportCaseView 转换求助单公开视图。
func supportCaseView(view support.CaseView) login.UISupportCaseView {
	return login.UISupportCaseView{
		ID: view.ID, TargetUserID: view.TargetUserID,
		TargetMaskedUsername: view.TargetMaskedUsername,
		TargetMaskedEmail:    view.TargetMaskedEmail,
		Reason:               view.Reason, Status: string(view.Status),
		AssigneeUserID: view.AssigneeUserID, CreatedByUserID: view.CreatedByUserID,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt, RowVersion: view.RowVersion,
	}
}

// supportTargetView 转换目标脱敏视图。
func supportTargetView(view support.TargetView) login.UISupportTargetView {
	return login.UISupportTargetView{
		UserID: view.UserID, MaskedUsername: view.MaskedUsername,
		MaskedEmail: view.MaskedEmail, Status: view.Status,
		HasPassword: view.HasPassword, HasVerifiedEmail: view.HasVerifiedEmail,
		CanRequestReset: view.CanRequestReset,
	}
}

// GetCase 读取求助单详情、追加式历史与实时目标摘要（目标读取失败不伪造数据）。
func (a *SupportAdapter) GetCase(ctx context.Context, staffUserID,
	caseID string) (login.UISupportCaseDetail, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportCaseDetail{}, supportErr("ACCESS_DENIED")
	}
	view, err := a.opts.Cases.GetCase(ctx, caller, caseID)
	if err != nil {
		return login.UISupportCaseDetail{}, supportMapError(err)
	}
	detail := login.UISupportCaseDetail{Case: supportCaseView(view)}
	history, historyErr := a.opts.Cases.ListEvents(ctx, caller, caseID, 0, 20)
	if historyErr != nil {
		detail.HistoryUnavailable = true
	} else {
		detail.History = login.UISupportHistoryPage{HasMore: history.HasMore, NextOffset: history.NextOffset}
		for _, event := range history.Events {
			detail.History.Events = append(detail.History.Events, login.UISupportEventView{
				Seq: event.Seq, Action: event.Action, ActorType: string(event.ActorType),
				ActorID: event.ActorID, FromStatus: string(event.FromStatus),
				ToStatus: string(event.ToStatus), Detail: event.Detail, CreatedAt: event.CreatedAt,
			})
		}
	}
	// 实时目标摘要仅用于核对；失败时标“当前渠道状态未读取”，不阻塞工单详情。
	target, targetErr := a.opts.Cases.LookupTarget(ctx, caller, view.TargetUserID, "")
	if targetErr != nil {
		detail.TargetUnread = true
	} else {
		detail.Target = supportTargetView(target)
	}
	caps, _ := a.Capabilities(ctx, staffUserID)
	detail.Capabilities = caps
	return detail, nil
}

// LookupTarget 按稳定用户 ID 读取获准普通账户的必要脱敏摘要。
func (a *SupportAdapter) LookupTarget(ctx context.Context, staffUserID, targetUserID,
	requestID string) (login.UISupportTargetView, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportTargetView{}, supportErr("ACCESS_DENIED")
	}
	view, err := a.opts.Cases.LookupTarget(ctx, caller, targetUserID, requestID)
	if err != nil {
		return login.UISupportTargetView{}, supportMapError(err)
	}
	return supportTargetView(view), nil
}

// CreateCase 登记求助单（不发送邮件、不批准恢复）。
func (a *SupportAdapter) CreateCase(ctx context.Context, staffUserID, targetUserID, reason,
	requestID string) (login.UISupportCaseView, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportCaseView{}, supportErr("ACCESS_DENIED")
	}
	view, err := a.opts.Cases.CreateCase(ctx, caller, support.CreateCaseRequest{
		TargetUserID: targetUserID, Reason: reason, RequestID: requestID})
	if err != nil {
		return login.UISupportCaseView{}, supportMapError(err)
	}
	return supportCaseView(view), nil
}

// ReassignCase 转派求助单。
func (a *SupportAdapter) ReassignCase(ctx context.Context, staffUserID, caseID,
	newAssigneeUserID, requestID string) (login.UISupportCaseView, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportCaseView{}, supportErr("ACCESS_DENIED")
	}
	view, err := a.opts.Cases.ReassignCase(ctx, caller, support.ReassignRequest{
		CaseID: caseID, NewAssigneeUserID: newAssigneeUserID, RequestID: requestID})
	if err != nil {
		return login.UISupportCaseView{}, supportMapError(err)
	}
	return supportCaseView(view), nil
}

// TransitionCase 变更求助单状态。
func (a *SupportAdapter) TransitionCase(ctx context.Context, staffUserID, caseID, toStatus,
	note, requestID string) (login.UISupportCaseView, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportCaseView{}, supportErr("ACCESS_DENIED")
	}
	view, err := a.opts.Cases.TransitionCase(ctx, caller, support.TransitionRequest{
		CaseID: caseID, ToStatus: support.CaseStatus(toStatus), Note: note, RequestID: requestID})
	if err != nil {
		return login.UISupportCaseView{}, supportMapError(err)
	}
	return supportCaseView(view), nil
}

// SendReset 向原已验证邮箱发起一次性找回入口。
func (a *SupportAdapter) SendReset(ctx context.Context, staffUserID, caseID,
	requestID string) (login.UISupportSendResult, error) {
	caller, err := supportCaller(staffUserID)
	if err != nil {
		return login.UISupportSendResult{}, supportErr("ACCESS_DENIED")
	}
	result, err := a.opts.Cases.SendReset(ctx, caller, support.SendRequest{
		CaseID: caseID, RequestID: requestID})
	if err != nil {
		return login.UISupportSendResult{}, supportMapError(err)
	}
	return login.UISupportSendResult{Sent: result.Sent, ManualReview: result.ManualReview,
		Status: string(result.Status)}, nil
}

// RecoveryPolicy 返回人工恢复制度的真实摘要；无任何客服/审批能力时拒绝读取。
func (a *SupportAdapter) RecoveryPolicy(ctx context.Context,
	staffUserID string) (login.UISupportRecoveryPolicy, error) {
	allowed := a.supportCheck(ctx, staffUserID, support.PermissionCasesRead) ||
		a.supportCheck(ctx, staffUserID, manualrecovery.PermissionRequest) ||
		a.supportCheck(ctx, staffUserID, manualrecovery.PermissionApprove) ||
		a.supportCheck(ctx, staffUserID, manualrecovery.PermissionMFAApprove)
	if !allowed {
		return login.UISupportRecoveryPolicy{}, supportErr("ACCESS_DENIED")
	}
	policy := a.opts.Recovery.PolicySummary()
	result := login.UISupportRecoveryPolicy{
		Enabled:                    policy.Enabled,
		WaitPeriodSeconds:          int64(policy.WaitPeriod / time.Second),
		ApprovalTTLSeconds:         int64(policy.ApprovalTTL / time.Second),
		RequestTTLSeconds:          int64(policy.RequestTTL / time.Second),
		RequireIndependentApproval: policy.RequireIndependentApproval,
	}
	for _, basis := range policy.VerificationBases {
		result.VerificationBases = append(result.VerificationBases, string(basis))
	}
	for _, delivery := range policy.DeliveryChannels {
		result.DeliveryChannels = append(result.DeliveryChannels, string(delivery))
	}
	return result, nil
}

// CreateRecoveryRequest 登记人工恢复申请。
func (a *SupportAdapter) CreateRecoveryRequest(ctx context.Context, staffUserID string,
	create login.UISupportRecoveryCreate, requestID string) (login.UISupportRecoveryView, error) {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return login.UISupportRecoveryView{}, supportErr("ACCESS_DENIED")
	}
	record, err := a.opts.Recovery.Create(ctx, caller, manualrecovery.CreateRequest{
		TargetUserID: create.TargetUserID, Operation: manualrecovery.OperationType(create.Operation),
		VerificationBasis:     manualrecovery.VerificationBasis(create.VerificationBasis),
		VerificationReference: create.VerificationReference,
		EvidenceSummary:       create.EvidenceSummary, Reason: create.Reason,
		Delivery:      manualrecovery.DeliveryChannel(create.Delivery),
		SupportCaseID: create.SupportCaseID, RequestID: requestID})
	if err != nil {
		return login.UISupportRecoveryView{}, recoveryMapError(err)
	}
	return a.recoveryView(ctx, staffUserID, record), nil
}

// GetRecoveryRequest 读取人工恢复申请：发起者/审批人走参与人通道，候选审批人走
// 受控待审批读取通道；随后补充批准与执行投影（读取失败不伪造数据）。
func (a *SupportAdapter) GetRecoveryRequest(ctx context.Context, staffUserID,
	requestID string) (login.UISupportRecoveryView, error) {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return login.UISupportRecoveryView{}, supportErr("ACCESS_DENIED")
	}
	// 统一受控读取：发起者/审批人/执行人/候选审批人一次判定，正常候选审批读取不会
	// 被记录成误导性的“参与人读取被拒”审计。
	record, err := a.opts.Recovery.GetRequestForPage(ctx, caller, requestID)
	if err != nil {
		return login.UISupportRecoveryView{}, recoveryMapError(err)
	}
	return a.recoveryView(ctx, staffUserID, record), nil
}

// recoveryView 组合申请/批准/执行投影（只显示真实读取到的数据）。
func (a *SupportAdapter) recoveryView(ctx context.Context, staffUserID string,
	record manualrecovery.RequestRecord) login.UISupportRecoveryView {
	view := login.UISupportRecoveryView{
		ID: record.ID, TargetUserID: record.TargetUserID,
		InitiatorUserID: record.InitiatorUserID, Operation: string(record.Operation),
		Status: string(record.Status), VerificationBasis: string(record.VerificationBasis),
		VerificationReference: record.VerificationReference,
		EvidenceRegistered:    len(record.EvidenceDigest) > 0,
		Reason:                record.Reason, Delivery: string(record.Delivery),
		DeliveryBound:         "unknown",
		ContentConsistent:     manualrecovery.ContentConsistent(record),
		TargetSecurityVersion: record.TargetSecurityVersion,
		TargetHighPrivilege:   record.TargetHighPrivilege,
		SupportCaseID:         record.SupportCaseID, RowVersion: record.RowVersion,
		ExpiresAt: record.ExpiresAt, ClosedReason: record.ClosedReason,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		HistoryUnavailable: true,
	}
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return view
	}
	// 待审批阶段还没有批准/执行记录；候选审批人也不具备读取它们的历史资格，
	// 直接跳过可避免产生无意义的拒绝审计。
	if record.Status == manualrecovery.StatusPendingApproval {
		return view
	}
	if approval, found, approvalErr := a.opts.Recovery.GetApproval(ctx, caller, record.ID); approvalErr == nil && found {
		view.Approval = login.UISupportApprovalView{
			ID: approval.ID, ApproverUserID: approval.ApproverUserID,
			Status: string(approval.Status), ApprovedAt: approval.ApprovedAt,
			NotBefore: approval.NotBefore, ExpiresAt: approval.ExpiresAt,
			InvalidatedReason: approval.InvalidatedReason,
		}
		view.HasApproval = true
	}
	if execution, found, executionErr := a.opts.Recovery.GetExecution(ctx, caller, record.ID); executionErr == nil && found {
		view.Execution = login.UISupportExecutionView{
			ID: execution.ID, ExecutorUserID: execution.ExecutorUserID,
			Status: execution.Status, SessionsRevoked: execution.SessionsRevoked,
			FactorsReset: execution.FactorsReset, CredentialIssued: execution.ResetCredentialIssued,
			Notification: execution.NotificationState, ErrorCode: execution.ErrorCode,
			StartedAt: execution.StartedAt, FinishedAt: execution.FinishedAt,
		}
		view.HasExecution = true
	}
	return view
}

// ApproveRecovery 批准申请（不执行）。
func (a *SupportAdapter) ApproveRecovery(ctx context.Context, staffUserID, requestID, note,
	traceID string) (login.UISupportApprovalView, error) {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return login.UISupportApprovalView{}, supportErr("ACCESS_DENIED")
	}
	approval, err := a.opts.Recovery.Approve(ctx, caller, manualrecovery.ApproveRequest{
		RequestID: requestID, Note: note, TraceID: traceID})
	if err != nil {
		return login.UISupportApprovalView{}, recoveryMapError(err)
	}
	return login.UISupportApprovalView{
		ID: approval.ID, ApproverUserID: approval.ApproverUserID, Status: string(approval.Status),
		ApprovedAt: approval.ApprovedAt, NotBefore: approval.NotBefore,
		ExpiresAt: approval.ExpiresAt, InvalidatedReason: approval.InvalidatedReason,
	}, nil
}

// RejectRecovery 拒绝申请。
func (a *SupportAdapter) RejectRecovery(ctx context.Context, staffUserID, requestID, reason,
	traceID string) error {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return supportErr("ACCESS_DENIED")
	}
	if err := a.opts.Recovery.Reject(ctx, caller, manualrecovery.RejectRequest{
		RequestID: requestID, Reason: reason, TraceID: traceID}); err != nil {
		return recoveryMapError(err)
	}
	return nil
}

// CancelRecovery 由发起者取消申请。
func (a *SupportAdapter) CancelRecovery(ctx context.Context, staffUserID, requestID, reason,
	traceID string) error {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return supportErr("ACCESS_DENIED")
	}
	if err := a.opts.Recovery.Cancel(ctx, caller, requestID, traceID, reason); err != nil {
		return recoveryMapError(err)
	}
	return nil
}

// ExecuteRecovery 执行一次性受控恢复（服务端唯一认领与复核）。
func (a *SupportAdapter) ExecuteRecovery(ctx context.Context, staffUserID, requestID,
	traceID string) (login.UISupportExecutionView, error) {
	caller, err := manualrecovery.UserCaller(staffUserID)
	if err != nil {
		return login.UISupportExecutionView{}, supportErr("ACCESS_DENIED")
	}
	result, err := a.opts.Recovery.Execute(ctx, caller, manualrecovery.ExecuteRequest{
		RequestID: requestID, TraceID: traceID})
	if err != nil {
		return login.UISupportExecutionView{}, recoveryMapError(err)
	}
	notification := "unknown"
	if result.NotificationSent {
		notification = "sent"
	}
	return login.UISupportExecutionView{
		ID: result.ExecutionID, ExecutorUserID: staffUserID, Status: string(result.Status),
		SessionsRevoked: result.SessionsRevoked, FactorsReset: result.FactorsReset,
		CredentialIssued: result.CredentialIssued, Notification: notification,
	}, nil
}
