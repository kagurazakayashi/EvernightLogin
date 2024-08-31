package manualrecovery

// 步骤 71 补充的受控只读投影：独立审批工作台需要的“候选审批人读取待审批申请”、
// 批准时间窗口与执行结果读取，以及页面展示真实制度值所需的制度摘要。
//
// 安全不变量：
//   - 读取同样要求流程已启用（Enabled=false 一律拒绝），并要求调用者是真实工作人员。
//   - 候选审批人读取只对**当前待审批**的申请开放，且调用者不得是发起者或目标本人；
//     资格由注入的 StaffAuthorizer.AuthorizeApproval 按当前权限实时判定（fail-closed）。
//   - 参与人（发起者、当前/历史审批人）读取批准与执行记录沿用 GetRequest 的授权语义。
//   - 所有拒绝都写失败审计；返回的投影不包含证据明文、密码、验证码、凭证或 token。
//   - 这些方法只读，不改变申请状态、不创建批准、不触发执行或通知。

import (
	"context"
	"fmt"
)

// PolicySummary 返回已解析默认值的制度副本，供页面显示当前真实等待期/有效期与
// 允许的核验依据/交付方式；不含任何密钥、密钥环或内部实现细节。
func (s *Service) PolicySummary() Policy { return s.policy }

// ContentConsistent 报告持久化申请记录的内容摘要是否与当前字段一致；页面据此
// 显示“内容绑定一致/已变化”，但批准是否有效仍以服务端最终判定为准。
func ContentConsistent(record RequestRecord) bool {
	return bytesEqual(contentDigest(record), record.ContentDigest)
}

// GetRequestForApproval 供尚未参与审批、但当前具备该操作类型审批资格的工作人员
// 读取**待审批**申请（独立审批页的受控详情读取契约）。
//
// 与 GetRequest 的区别：GetRequest 只允许发起者与历史/当前审批人读取；本方法在
// 申请仍为 pending_approval 时允许候选审批人读取，但明确拒绝发起者与目标本人，
// 并实时复核候选审批人当前资格；申请一旦离开待审批状态即不再向候选审批人开放。
func (s *Service) GetRequestForApproval(ctx context.Context, caller Caller, requestID string) (RequestRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "approval_read"); err != nil {
		return RequestRecord{}, err
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return RequestRecord{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return RequestRecord{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID,
			"not_found", string(CodeChallengeInvalid), "")
		return RequestRecord{}, ErrRequestNotFound
	}
	if record.Status != StatusPendingApproval {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
			"not_pending_approval", string(CodeChallengeInvalid), "")
		return RequestRecord{}, ErrRequestClosed
	}
	if caller.actor.ID == record.InitiatorUserID || caller.actor.ID == record.TargetUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
			"self_approval_read", string(CodeAccessDenied), "")
		return RequestRecord{}, ErrSelfApproval
	}
	if err := s.opts.Staff.AuthorizeApproval(ctx, caller.actor.ID, record.TargetUserID,
		scopeSystem, record.Operation); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
			"approver_not_qualified", string(CodeOf(s.mapAuthzError(err))), "")
		return RequestRecord{}, s.mapAuthzError(err)
	}
	return record, nil
}

// GetApproval 返回申请最近一次批准（active 或历史），供页面显示真实批准人、批准
// 时间、最早执行时间与批准到期时间。
func (s *Service) GetApproval(ctx context.Context, caller Caller, requestID string) (ApprovalRecord, bool, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "get_approval"); err != nil {
		return ApprovalRecord{}, false, err
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return ApprovalRecord{}, false, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return ApprovalRecord{}, false, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID,
			"not_found", string(CodeChallengeInvalid), "")
		return ApprovalRecord{}, false, ErrRequestNotFound
	}
	// 参与人、真实执行人与“已批准申请当前具备执行资格者”可读取批准时间窗口；
	// 不命中时才写一条失败审计，避免正常执行人读取被记为参与人读取被拒。
	allowed := caller.actor.ID == record.InitiatorUserID
	if !allowed {
		approval, active, approvalErr := s.opts.Store.GetActiveApproval(ctx, record.ID)
		allowed = approvalErr == nil && active && approval.ApproverUserID == caller.actor.ID
	}
	if !allowed {
		historical, historyErr := s.opts.Store.ApproverHistory(ctx, record.ID, caller.actor.ID)
		allowed = historyErr == nil && historical
	}
	if !allowed {
		allowed = s.callerIsExecutor(ctx, caller, record.ID)
	}
	if !allowed && record.Status == StatusApproved {
		allowed = s.opts.Staff.AuthorizeExecution(ctx, caller.actor.ID, record.TargetUserID,
			record.Operation) == nil
	}
	if !allowed {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
			"read_not_authorized", string(CodeAccessDenied), "")
		return ApprovalRecord{}, false, ErrAccessDenied
	}
	approval, approvalFound, approvalErr := s.opts.Store.GetLatestApproval(ctx, requestID)
	if approvalErr != nil {
		return ApprovalRecord{}, false, ErrStoreUnavailable
	}
	return approval, approvalFound, nil
}

// GetExecution 返回申请的执行记录（若已开始执行），供重复执行提示与完成结果展示。
// 步骤 265：返回前按稳定业务去重键投影通知的实际投递状态（Notification 字段），
// 让参与人/执行人可受权查询排队、发送后端接受、失败、取消等真实状态。
func (s *Service) GetExecution(ctx context.Context, caller Caller, requestID string) (ExecutionRecord, bool, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "get_execution"); err != nil {
		return ExecutionRecord{}, false, err
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return ExecutionRecord{}, false, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return ExecutionRecord{}, false, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID,
			"not_found", string(CodeChallengeInvalid), "")
		return ExecutionRecord{}, false, ErrRequestNotFound
	}
	if err := s.checkParticipant(ctx, caller, record); err != nil &&
		!s.callerIsExecutor(ctx, caller, record.ID) {
		return ExecutionRecord{}, false, err
	}
	execution, executionFound, executionErr := s.opts.Store.GetExecution(ctx, requestID)
	if executionErr != nil {
		return ExecutionRecord{}, false, ErrStoreUnavailable
	}
	if executionFound {
		execution.Notification = s.projectNotificationDelivery(ctx, execution)
	}
	return execution, executionFound, nil
}

// GetExecutionNotification 返回执行通知的受权只读视图（步骤 265）：业务通知状态 +
// 从 mailer 投递记录投影的实际投递状态（queued/sending/succeeded/failed/cancelled）。
// 授权语义与 GetExecution 完全一致：只有申请参与人或真实执行人可读；未开始执行时
// found=false。读取不修改任何状态。
func (s *Service) GetExecutionNotification(ctx context.Context, caller Caller,
	requestID string) (NotificationDeliveryView, bool, error) {
	execution, found, err := s.GetExecution(ctx, caller, requestID)
	if err != nil {
		return NotificationDeliveryView{}, false, err
	}
	if !found {
		return NotificationDeliveryView{}, false, nil
	}
	return execution.Notification, true, nil
}

// callerIsExecutor 报告调用者是否为该申请真实执行记录的执行人（只读执行结果所需）。
func (s *Service) callerIsExecutor(ctx context.Context, caller Caller, requestID string) bool {
	execution, found, err := s.opts.Store.GetExecution(ctx, requestID)
	return err == nil && found && execution.ExecutorUserID == caller.actor.ID
}

// checkParticipant 判定调用者是否为申请参与人（发起者、当前 active 批准人或历史
// 审批人）；不通过时写失败审计并返回 ErrAccessDenied。
func (s *Service) checkParticipant(ctx context.Context, caller Caller, record RequestRecord) error {
	if caller.actor.ID == record.InitiatorUserID {
		return nil
	}
	approval, approvalFound, approvalErr := s.opts.Store.GetActiveApproval(ctx, record.ID)
	if approvalErr == nil && approvalFound && approval.ApproverUserID == caller.actor.ID {
		return nil
	}
	if historical, historyErr := s.opts.Store.ApproverHistory(ctx, record.ID, caller.actor.ID); historyErr == nil && historical {
		return nil
	}
	s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
		"read_not_authorized", string(CodeAccessDenied), "")
	return ErrAccessDenied
}

// GetRequestForExecution 供本次执行的执行人读取其已认领执行的申请（executing/
// completed/failed），用于执行结果页与重复执行提示；只对真实执行记录的执行人开放。
func (s *Service) GetRequestForExecution(ctx context.Context, caller Caller, requestID string) (RequestRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "execution_read"); err != nil {
		return RequestRecord{}, err
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return RequestRecord{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return RequestRecord{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID,
			"not_found", string(CodeChallengeInvalid), "")
		return RequestRecord{}, ErrRequestNotFound
	}
	execution, executionFound, executionErr := s.opts.Store.GetExecution(ctx, requestID)
	if executionErr != nil {
		return RequestRecord{}, ErrStoreUnavailable
	}
	if !executionFound || execution.ExecutorUserID != caller.actor.ID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
			"not_executor", string(CodeAccessDenied), "")
		return RequestRecord{}, ErrAccessDenied
	}
	return record, nil
}

// GetRequestForPage 是页面详情/审批详情的统一受控只读入口：允许发起者、当前/历史
// 审批人与真实执行人读取；对仍处于待审批的申请，还允许当前具备该操作类型审批资格
// 的候选审批人读取（拒绝目标本人）。所有未命中分支只在最后写一条失败审计，避免正常
// 候选审批读取被记录成“参与人读取被拒”的误导性审计。只读，不创建批准、不改变状态。
func (s *Service) GetRequestForPage(ctx context.Context, caller Caller, requestID string) (RequestRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "page_read"); err != nil {
		return RequestRecord{}, err
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return RequestRecord{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return RequestRecord{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID,
			"not_found", string(CodeChallengeInvalid), "")
		return RequestRecord{}, ErrRequestNotFound
	}
	if caller.actor.ID == record.InitiatorUserID {
		return record, nil
	}
	if approval, active, approvalErr := s.opts.Store.GetActiveApproval(ctx, requestID); approvalErr == nil &&
		active && approval.ApproverUserID == caller.actor.ID {
		return record, nil
	}
	if historical, historyErr := s.opts.Store.ApproverHistory(ctx, requestID, caller.actor.ID); historyErr == nil && historical {
		return record, nil
	}
	if execution, executed, executionErr := s.opts.Store.GetExecution(ctx, requestID); executionErr == nil &&
		executed && execution.ExecutorUserID == caller.actor.ID {
		return record, nil
	}
	if record.Status == StatusPendingApproval && caller.actor.ID != record.TargetUserID {
		if err := s.opts.Staff.AuthorizeApproval(ctx, caller.actor.ID, record.TargetUserID,
			scopeSystem, record.Operation); err == nil {
			return record, nil
		}
	}
	// 已批准、等待执行的申请：当前具备执行资格的工作人员需要读取确认页（执行前仍由
	// Execute 复核等待期、批准有效期、内容绑定与目标状态）。
	if record.Status == StatusApproved && caller.actor.ID != record.TargetUserID {
		if err := s.opts.Staff.AuthorizeExecution(ctx, caller.actor.ID, record.TargetUserID,
			record.Operation); err == nil {
			return record, nil
		}
	}
	s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID,
		"read_not_authorized", string(CodeAccessDenied), "")
	return RequestRecord{}, ErrAccessDenied
}
