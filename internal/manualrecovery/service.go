package manualrecovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// Options 是人工恢复服务的显式依赖；核心依赖缺失一律拒绝构造（fail-closed）。
type Options struct {
	Store Store
	Audit AuditRecorder
	// Reauth 是步骤 38/39 敏感策略执行器；申请/审批/执行都必须经近期强认证与操作绑定。
	Reauth reauth.OperationRunner
	// Staff 按内部 authz 判定工作人员功能权限与数据范围；实现必须 fail-closed。
	Staff StaffAuthorizer
	// Targets 读取目标账户状态与 root/实际高权限标记（实时只读）。
	Targets TargetGuard
	// Executor 是宿主提供的受控恢复执行器（实际密码/MFA 恢复与凭证/会话失效）。
	Executor Executor
	// Notifier 发送完成/失败通知（既有渠道）；nil 表示未装配，只记录状态。
	Notifier Notifier
	// NotificationsQueued 表示 Notifier 走可靠投递队列（步骤 197）：通知成功仅代表
	// enqueue 已受理，记录 state=queued 而不是 sent；真实送达/失败以投递任务为准。
	NotificationsQueued bool
	// Deliveries 是只读投递记录查询（步骤 265）：非空时读取执行结果会按稳定业务去重键
	// 投影通知的实际投递状态（queued/sending/succeeded/failed/cancelled）；nil 时只显示
	// 业务通知状态。它不做授权判断，调用方必须先完成自身业务授权。
	Deliveries mailer.DeliveryLookup
	// Policy 是 root/宿主显式配置的人工恢复制度；零值表示默认关闭。
	Policy Policy
	// OperationGuard 是宿主的操作类型可用性校验（步骤 188）：例如 Passkey 未启用时
	// 拒绝 mfa_reset 申请/执行，避免恢复后无法重绑。nil 表示不额外限制。
	OperationGuard func(operation OperationType) error
	Now            func() time.Time
	Random         io.Reader
	Logger         *slog.Logger
}

// Service 是人工恢复申请/独立审批/受控执行服务。构造后不可变、可并发使用；不启动
// 协程、不直接签发会话或凭证（由宿主执行器完成并撤销旧凭证）。
type Service struct {
	opts   Options
	policy Policy
	now    func() time.Time
	random io.Reader
	logger *slog.Logger
}

// New 校验依赖与策略并构造服务。核心依赖为空（含 typed-nil）或策略非法时返回错误；
// 策略关闭时服务仍会构造，但所有阶段都返回 ErrDisabled（框架与拒绝行为可用）。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 人工恢复存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Reauth) {
		return nil, fmt.Errorf("%w: 敏感策略执行器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Staff) {
		return nil, fmt.Errorf("%w: 工作人员授权器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Targets) {
		return nil, fmt.Errorf("%w: 目标账户读取器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Executor) {
		return nil, fmt.Errorf("%w: 受控恢复执行器为空", ErrOptionsInvalid)
	}
	policyCopy := options.Policy.resolve()
	if err := policyCopy.Validate(); err != nil {
		return nil, err
	}
	// 启用人工恢复必须装配通知渠道：成功/失败都必须向既有渠道告知，不能静默完成。
	if policyCopy.Enabled && isNilInterface(options.Notifier) {
		return nil, fmt.Errorf("%w: 启用人工恢复必须注入通知适配器", ErrOptionsInvalid)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, policy: policyCopy, now: now, random: random, logger: logger}, nil
}

// isNilInterface 检测 nil 接口与 typed nil 指针。
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// clockNow 返回统一截断到 UTC 毫秒的当前时间。
func (s *Service) clockNow() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

// Enabled 报告人工恢复流程是否已由 root/宿主显式启用。
func (s *Service) Enabled() bool { return s.policy.Enabled }

// CreateRequest 是发起人工恢复申请的请求。EvidenceSummary 是核验证据摘要文本
// （由发起者填写，服务只保存其 SHA-256，不落库明文、不写日志/审计）。
type CreateRequest struct {
	TargetUserID          string
	Operation             OperationType
	VerificationBasis     VerificationBasis
	VerificationReference string
	EvidenceSummary       string
	Reason                string
	Delivery              DeliveryChannel
	SupportCaseID         string
	RequestID             string
}

// Create 发起人工恢复申请：要求近期强认证、发起者具备 recovery.request 数据范围、
// 目标为 active 的普通账户（root 与实际高权限账户拒绝），并绑定固定内容摘要。
func (s *Service) Create(ctx context.Context, caller Caller, request CreateRequest) (RequestRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "create"); err != nil {
		return RequestRecord{}, err
	}
	if err := validateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "invalid_request_id", string(CodeReqInvalid), "")
		return RequestRecord{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.validateCreateRequest(request); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "invalid_request", string(CodeOf(err)), request.RequestID)
		return RequestRecord{}, err
	}
	if s.opts.OperationGuard != nil {
		if guardErr := s.opts.OperationGuard(request.Operation); guardErr != nil {
			s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "operation_disallowed", string(CodeAccessDenied), request.RequestID)
			return RequestRecord{}, fmt.Errorf("%w: %v", ErrAccessDenied, guardErr)
		}
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationRequest, map[string]string{
		"target_user_id":         request.TargetUserID,
		"operation_type":         string(request.Operation),
		"verification_basis":     string(request.VerificationBasis),
		"verification_reference": request.VerificationReference,
		"evidence_digest":        digestHex(digestString(request.EvidenceSummary))[:16],
		"delivery_channel":       string(request.Delivery),
		"support_case_id":        request.SupportCaseID,
	}, "发起人工核验恢复申请", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return RequestRecord{}, err
	}
	if err := s.opts.Staff.AuthorizeRequest(ctx, caller.actor.ID, request.TargetUserID, request.Operation); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "staff_not_authorized", string(CodeOf(s.mapAuthzError(err))), request.RequestID)
		return RequestRecord{}, s.mapAuthzError(err)
	}
	target, err := s.loadTarget(ctx, request.TargetUserID, request.RequestID, caller.actor)
	if err != nil {
		return RequestRecord{}, err
	}
	if target.DeliveryFingerprint == "" {
		s.recordFailure(ctx, caller.actor, ActionDenied, "user", request.TargetUserID, "delivery_channel_unavailable", string(CodeUserDisabled), request.RequestID)
		return RequestRecord{}, ErrTargetUnavailable
	}
	requestID, err := newDomainID(s.random, requestIDPrefix)
	if err != nil {
		return RequestRecord{}, err
	}
	now := s.clockNow()
	record := RequestRecord{
		ID: requestID, TargetUserID: request.TargetUserID, InitiatorUserID: caller.actor.ID,
		Operation: request.Operation, Status: StatusPendingApproval,
		VerificationBasis:     request.VerificationBasis,
		VerificationReference: request.VerificationReference,
		EvidenceDigest:        digestString(request.EvidenceSummary),
		Reason:                request.Reason, Delivery: request.Delivery,
		DeliveryFingerprint:   target.DeliveryFingerprint,
		TargetSecurityVersion: target.SecurityVersion,
		TargetHighPrivilege:   target.HighPrivilege,
		SupportCaseID:         request.SupportCaseID,
		ExpiresAt:             now.Add(s.policy.RequestTTL),
		RowVersion:            1, CreatedAt: now, UpdatedAt: now,
	}
	record.ContentDigest = contentDigest(record)
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionRequested,
			Target:    audit.Target{Type: "manual_recovery_request", ID: requestID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "target_user_id", After: request.TargetUserID},
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "verification_basis", After: string(record.VerificationBasis)},
				{Field: "delivery_channel", After: string(record.Delivery)},
				{Field: "delivery_fingerprint", After: record.DeliveryFingerprint},
				{Field: "target_security_version", After: fmt.Sprint(record.TargetSecurityVersion)},
				{Field: "expires_at", After: record.ExpiresAt.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode:   "manual_recovery.request_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.InsertRequestTx(txCtx, tx, record)
	}); err != nil {
		return RequestRecord{}, mapStoreError(err)
	}
	s.notifySensitive(ctx, guard)
	s.logger.Info("人工恢复申请已创建", "request_id", requestID, "target_user_id", request.TargetUserID,
		"operation_type", string(record.Operation))
	return record, nil
}

// ApproveRequest 是独立审批请求。
type ApproveRequest struct {
	RequestID string
	Note      string
	TraceID   string
}

// Approve 由独立审批人批准申请：不得为发起者/目标本人，必须满足近期强认证与当前
// 审批功能权限；批准绑定请求内容摘要、操作类型与等待期/有效期。
func (s *Service) Approve(ctx context.Context, caller Caller, request ApproveRequest) (ApprovalRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "approve"); err != nil {
		return ApprovalRecord{}, err
	}
	if err := validateRequestID(request.TraceID); err != nil {
		return ApprovalRecord{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !validText(request.Note, 200, false) {
		return ApprovalRecord{}, fmt.Errorf("%w: 审批说明过长或含控制字符", ErrInvalidRequest)
	}
	if !validDomainID(request.RequestID, requestIDPrefix) {
		return ApprovalRecord{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, err := s.loadRequest(ctx, request.RequestID, caller.actor, "approve")
	if err != nil {
		return ApprovalRecord{}, err
	}
	now := s.clockNow()
	if record.Status != StatusPendingApproval {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "not_pending_approval", string(CodeConflict), request.TraceID)
		return ApprovalRecord{}, ErrRequestClosed
	}
	if !now.Before(record.ExpiresAt) {
		s.expireRequest(ctx, caller.actor, record, "request_expired", request.TraceID)
		return ApprovalRecord{}, ErrRequestClosed
	}
	if caller.actor.ID == record.InitiatorUserID || caller.actor.ID == record.TargetUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "self_approval", string(CodeAccessDenied), request.TraceID)
		return ApprovalRecord{}, ErrSelfApproval
	}
	if !bytesEqual(contentDigest(record), record.ContentDigest) {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "content_mismatch", string(CodeConflict), request.TraceID)
		return ApprovalRecord{}, ErrContentChanged
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationApprove, map[string]string{
		"request_id":     record.ID,
		"target_user_id": record.TargetUserID,
		"operation_type": string(record.Operation),
		"content_digest": digestHex(record.ContentDigest),
	}, "审批人工核验恢复申请", request.TraceID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "reauth_rejected", string(CodeOf(err)), request.TraceID)
		return ApprovalRecord{}, err
	}
	if err := s.opts.Staff.AuthorizeApproval(ctx, caller.actor.ID, record.TargetUserID, scopeSystem, record.Operation); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "approver_not_qualified", string(CodeOf(s.mapAuthzError(err))), request.TraceID)
		return ApprovalRecord{}, s.mapAuthzError(err)
	}
	target, err := s.loadTarget(ctx, record.TargetUserID, request.TraceID, caller.actor)
	if err != nil {
		return ApprovalRecord{}, err
	}
	if target.SecurityVersion != record.TargetSecurityVersion || target.HighPrivilege != record.TargetHighPrivilege ||
		target.DeliveryFingerprint != record.DeliveryFingerprint {
		if err := s.failPendingRequest(ctx, caller.actor, record, "target_changed", request.TraceID); err != nil {
			return ApprovalRecord{}, err
		}
		return ApprovalRecord{}, ErrContentChanged
	}
	approvalID, err := newDomainID(s.random, approvalIDPrefix)
	if err != nil {
		return ApprovalRecord{}, err
	}
	approval := ApprovalRecord{
		ID: approvalID, RequestID: record.ID, ApproverUserID: caller.actor.ID,
		Operation: record.Operation, ContentDigest: append([]byte(nil), record.ContentDigest...),
		Status: ApprovalActive, ApprovedAt: now,
		NotBefore: now.Add(s.policy.WaitPeriod), ExpiresAt: now.Add(s.policy.ApprovalTTL),
		RowVersion: 1,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionApproved,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: request.TraceID,
			Changes: []audit.FieldChange{
				{Field: "approval_id", After: approvalID},
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "target_user_id", After: record.TargetUserID},
				{Field: "not_before", After: approval.NotBefore.UTC().Format(time.RFC3339)},
				{Field: "approval_expires_at", After: approval.ExpiresAt.UTC().Format(time.RFC3339)},
			},
		},
		FailureReasonCode:   "manual_recovery.approve_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if err := s.opts.Store.InsertApprovalTx(txCtx, tx, approval); err != nil {
			return err
		}
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID,
			StatusPendingApproval, StatusApproved, "", now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}); err != nil {
		return ApprovalRecord{}, mapStoreError(err)
	}
	s.notifySensitive(ctx, guard)
	s.logger.Info("人工恢复申请已批准", "request_id", record.ID, "approval_id", approvalID,
		"approver_user_id", caller.actor.ID)
	return approval, nil
}

// RejectRequest 是审批人拒绝申请。
type RejectRequest struct {
	RequestID string
	Reason    string
	TraceID   string
}

// Reject 由独立审批人拒绝申请（终态）；拒绝理由有界且不含敏感明文。
func (s *Service) Reject(ctx context.Context, caller Caller, request RejectRequest) error {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "reject"); err != nil {
		return err
	}
	if err := validateRequestID(request.TraceID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !validText(request.Reason, 200, true) {
		return fmt.Errorf("%w: 拒绝理由长度或内容无效", ErrInvalidRequest)
	}
	if !validDomainID(request.RequestID, requestIDPrefix) {
		return fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, err := s.loadRequest(ctx, request.RequestID, caller.actor, "reject")
	if err != nil {
		return err
	}
	if record.Status != StatusPendingApproval {
		return ErrRequestClosed
	}
	if caller.actor.ID == record.InitiatorUserID || caller.actor.ID == record.TargetUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "self_rejection", string(CodeAccessDenied), request.TraceID)
		return ErrSelfApproval
	}
	if _, err := s.authorizeSensitive(ctx, caller, OperationApprove, map[string]string{
		"request_id": record.ID, "target_user_id": record.TargetUserID,
		"operation_type": string(record.Operation), "decision": "reject",
	}, "拒绝人工核验恢复申请", request.TraceID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "reauth_rejected", string(CodeOf(err)), request.TraceID)
		return err
	}
	if err := s.opts.Staff.AuthorizeApproval(ctx, caller.actor.ID, record.TargetUserID, scopeSystem, record.Operation); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "approver_not_qualified", string(CodeOf(s.mapAuthzError(err))), request.TraceID)
		return s.mapAuthzError(err)
	}
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionRejected,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: request.TraceID,
			Changes: []audit.FieldChange{
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "reason", After: "rejected_by_approver"},
			},
		},
		FailureReasonCode:   "manual_recovery.reject_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID,
			StatusPendingApproval, StatusRejected, "rejected_by_approver", now)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRequestClosed
		}
		return nil
	}); err != nil {
		return mapStoreError(err)
	}
	s.logger.Info("人工恢复申请已拒绝", "request_id", record.ID, "approver_user_id", caller.actor.ID)
	return nil
}

// Cancel 由发起者取消尚未执行的申请（终态），已有 active 批准一并失效。
func (s *Service) Cancel(ctx context.Context, caller Caller, requestID, traceID, reason string) error {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "cancel"); err != nil {
		return err
	}
	if err := validateRequestID(traceID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !validText(reason, 200, true) {
		return fmt.Errorf("%w: 取消理由长度或内容无效", ErrInvalidRequest)
	}
	if !validDomainID(requestID, requestIDPrefix) {
		return fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, err := s.loadRequest(ctx, requestID, caller.actor, "cancel")
	if err != nil {
		return err
	}
	if record.InitiatorUserID != caller.actor.ID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "not_initiator", string(CodeAccessDenied), traceID)
		return ErrAccessDenied
	}
	if record.Status != StatusPendingApproval && record.Status != StatusApproved {
		return ErrRequestClosed
	}
	now := s.clockNow()
	approval, approvalFound, approvalErr := s.opts.Store.GetActiveApproval(ctx, record.ID)
	if approvalErr != nil {
		return ErrStoreUnavailable
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCancelled,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: traceID,
			Changes: []audit.FieldChange{
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "reason", After: "cancelled_by_initiator"},
			},
		},
		FailureReasonCode:   "manual_recovery.cancel_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if approvalFound {
			if _, err := s.opts.Store.FinishApprovalTx(txCtx, tx, approval.ID, ApprovalInvalidated, "request_cancelled", now); err != nil {
				return err
			}
		}
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID, record.Status, StatusCancelled, "cancelled_by_initiator", now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}); err != nil {
		return mapStoreError(err)
	}
	s.logger.Info("人工恢复申请已取消", "request_id", record.ID, "initiator_user_id", caller.actor.ID)
	return nil
}

// ExecuteRequest 是执行请求。
type ExecuteRequest struct {
	RequestID string
	TraceID   string
}

// Execute 在批准通过、等待期已满且批准未过期时执行一次性受控恢复。
//
// 执行前重新校验：请求/批准内容摘要、审批人当前资格、目标状态（active、非 root/
// 实际高权限、安全版本未变化）；任一不满足都 fail-closed 并使批准失效。执行权通过
// 条件更新（approved→executing）唯一分配，双执行竞争只有一个成功；执行器故障时
// 记录失败并通知既有渠道，不宣称成功；最终审计提交失败时尽力补偿执行器副作用。
func (s *Service) Execute(ctx context.Context, caller Caller, request ExecuteRequest) (ExecutionResult, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "execute"); err != nil {
		return ExecutionResult{}, err
	}
	if err := validateRequestID(request.TraceID); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !validDomainID(request.RequestID, requestIDPrefix) {
		return ExecutionResult{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, err := s.loadRequest(ctx, request.RequestID, caller.actor, "execute")
	if err != nil {
		return ExecutionResult{}, err
	}
	if caller.actor.ID == record.TargetUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "target_cannot_execute", string(CodeAccessDenied), request.TraceID)
		return ExecutionResult{}, ErrAccessDenied
	}
	if record.Status != StatusApproved {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "not_approved", string(CodeConflict), request.TraceID)
		return ExecutionResult{}, ErrRequestClosed
	}
	approval, found, err := s.opts.Store.GetActiveApproval(ctx, record.ID)
	if err != nil {
		return ExecutionResult{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "no_active_approval", string(CodeConflict), request.TraceID)
		return ExecutionResult{}, ErrApprovalExpired
	}
	// 步骤 188 Q1 三权分离：执行人不得是发起者或审批人（目标本人已在上面拒绝）。
	if caller.actor.ID == record.InitiatorUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "executor_is_initiator", string(CodeAccessDenied), request.TraceID)
		return ExecutionResult{}, ErrAccessDenied
	}
	if caller.actor.ID == approval.ApproverUserID {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "executor_is_approver", string(CodeAccessDenied), request.TraceID)
		return ExecutionResult{}, ErrAccessDenied
	}
	if s.opts.OperationGuard != nil {
		if guardErr := s.opts.OperationGuard(record.Operation); guardErr != nil {
			s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "operation_disallowed", string(CodeAccessDenied), request.TraceID)
			return ExecutionResult{}, fmt.Errorf("%w: %v", ErrAccessDenied, guardErr)
		}
	}
	now := s.clockNow()
	// 内容替换检测：申请内容摘要与批准绑定的摘要必须一致。
	currentDigest := contentDigest(record)
	if !bytesEqual(currentDigest, record.ContentDigest) || !bytesEqual(approval.ContentDigest, record.ContentDigest) ||
		approval.Operation != record.Operation {
		denyErr := s.failRequest(ctx, caller.actor, record, approval, "content_changed", request.TraceID)
		if denyErr != nil {
			return ExecutionResult{}, denyErr
		}
		return ExecutionResult{}, ErrContentChanged
	}
	// 过期批准：批准失效，申请回到待审批（需重新独立审批）。
	if !now.Before(approval.ExpiresAt) {
		if err := s.invalidateApprovalAndReopen(ctx, caller.actor, record, approval, "approval_expired", request.TraceID); err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{}, ErrApprovalExpired
	}
	// 等待期：未到可执行时间直接拒绝（不消耗批准）。
	if now.Before(approval.NotBefore) {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "approval_not_yet_valid", string(CodeConflict), request.TraceID)
		return ExecutionResult{}, ErrApprovalNotYetValid
	}
	// 审批人当前资格：权限被撤销则批准无效，回到待审批。
	if err := s.opts.Staff.AuthorizeApproval(ctx, approval.ApproverUserID, record.TargetUserID, scopeSystem, record.Operation); err != nil {
		if reopenErr := s.invalidateApprovalAndReopen(ctx, caller.actor, record, approval, "approver_no_longer_qualified", request.TraceID); reopenErr != nil {
			return ExecutionResult{}, reopenErr
		}
		return ExecutionResult{}, ErrApproverUnqualified
	}
	if _, err := s.authorizeSensitive(ctx, caller, OperationExecute, map[string]string{
		"request_id":     record.ID,
		"approval_id":    approval.ID,
		"target_user_id": record.TargetUserID,
		"operation_type": string(record.Operation),
		"content_digest": digestHex(record.ContentDigest),
	}, "执行人工核验恢复", request.TraceID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "reauth_rejected", string(CodeOf(err)), request.TraceID)
		return ExecutionResult{}, err
	}
	if err := s.opts.Staff.AuthorizeExecution(ctx, caller.actor.ID, record.TargetUserID, record.Operation); err != nil {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", record.ID, "executor_not_authorized", string(CodeOf(s.mapAuthzError(err))), request.TraceID)
		return ExecutionResult{}, s.mapAuthzError(err)
	}
	// 目标状态与版本必须与申请时一致；变为 root/高权限或被禁用时 fail-closed。
	target, err := s.loadTarget(ctx, record.TargetUserID, request.TraceID, caller.actor)
	if err != nil {
		_ = s.failRequest(ctx, caller.actor, record, approval, "target_unavailable", request.TraceID)
		return ExecutionResult{}, err
	}
	if target.SecurityVersion != record.TargetSecurityVersion || target.HighPrivilege != record.TargetHighPrivilege ||
		target.DeliveryFingerprint != record.DeliveryFingerprint {
		_ = s.failRequest(ctx, caller.actor, record, approval, "target_changed", request.TraceID)
		return ExecutionResult{}, ErrContentChanged
	}
	// 申请自身有效期：批准可能晚于申请创建，批准窗口可能超出申请生命周期；以更早
	// 的申请过期时间为准，过期后不得执行（同时 claim SQL 内再校验一次防竞态）。
	if !now.Before(record.ExpiresAt) {
		if err := s.expireApprovedRequest(ctx, caller.actor, record, approval, "request_expired", request.TraceID); err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{}, ErrRequestClosed
	}
	executionID, err := newDomainID(s.random, executionIDPrefix)
	if err != nil {
		return ExecutionResult{}, err
	}
	execution := ExecutionRecord{
		ID: executionID, RequestID: record.ID, ApprovalID: approval.ID,
		ExecutorUserID: caller.actor.ID, Operation: record.Operation, Status: "running",
		NotificationState: "pending", StartedAt: now,
	}
	// 唯一执行权：条件更新 approved→executing 并插入 execution（同事务）。再次写入
	// 校验过的摘要作为事务内条件（防止检查后被并发改写）。
	claim := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionExecutionStarted,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: request.TraceID,
			Changes: []audit.FieldChange{
				{Field: "execution_id", After: executionID},
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "target_user_id", After: record.TargetUserID},
			},
		},
		FailureReasonCode:   "manual_recovery.execution_claim_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	claimed := false
	if err := s.opts.Audit.ExecuteCritical(ctx, claim, func(txCtx context.Context, tx audit.Tx) error {
		ok, claimErr := s.opts.Store.ClaimExecutionTx(txCtx, tx, record, execution, now)
		if claimErr != nil {
			return claimErr
		}
		claimed = ok
		if !ok {
			return ErrExecutionConflict
		}
		return nil
	}); err != nil {
		if errors.Is(err, ErrExecutionConflict) {
			return ExecutionResult{}, ErrExecutionConflict
		}
		return ExecutionResult{}, mapStoreError(err)
	}
	if !claimed {
		return ExecutionResult{}, ErrExecutionConflict
	}
	command := ExecutionCommand{
		RequestID: record.ID, ExecutionID: executionID, TargetUserID: record.TargetUserID,
		Operation: record.Operation, Delivery: record.Delivery, RequestTraceID: request.TraceID,
	}
	outcome, executeErr := s.opts.Executor.Execute(ctx, command)
	if executeErr != nil {
		s.logger.Warn("人工恢复执行器失败", "request_id", record.ID, "operation_type", string(record.Operation))
		failErr := s.finishExecution(ctx, caller.actor, record, approval, execution, "failed", StatusFailed,
			NotificationStatePending, outcome)
		s.notifyFailed(ctx, record)
		if failErr != nil {
			return ExecutionResult{}, errors.Join(ErrExecutionFailed, failErr)
		}
		return ExecutionResult{}, ErrExecutionFailed
	}
	// 先提交“恢复已完成”的最终审计与状态，再发送通知：通知失败不能早于事实，
	// 也不会出现“已通知完成但数据库未完成”的不一致。
	finishErr := s.finishExecution(ctx, caller.actor, record, approval, execution, "succeeded", StatusCompleted,
		"pending", outcome)
	if finishErr != nil {
		// 最终审计/状态提交失败：尽力补偿执行器副作用，绝不宣称成功。
		if compensateErr := s.opts.Executor.Compensate(ctx, command); compensateErr != nil {
			s.logger.Warn("人工恢复补偿失败", "request_id", record.ID, "error_category", "compensate_failed")
		}
		return ExecutionResult{}, finishErr
	}
	notification := s.notifyCompleted(ctx, record)
	s.logger.Info("人工恢复已执行完成", "request_id", record.ID, "execution_id", executionID,
		"operation_type", string(record.Operation), "sessions_revoked", outcome.SessionsRevoked,
		"notification_state", notification.State)
	return ExecutionResult{
		RequestID: record.ID, ExecutionID: executionID, Status: StatusCompleted,
		Operation: record.Operation, SessionsRevoked: outcome.SessionsRevoked,
		FactorsReset: outcome.FactorsReset, CredentialIssued: outcome.ResetCredentialIssued,
		NotificationSent:  notification.State == NotificationStateSent,
		NotificationState: notification.State,
		Notification:      notification,
	}, nil
}

// GetRequest 返回申请视图；只有发起者与该申请的审批人（active 批准或已批准历史）可读。
func (s *Service) GetRequest(ctx context.Context, caller Caller, requestID string) (RequestRecord, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireEnabled(ctx, caller, "get"); err != nil {
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
		return RequestRecord{}, ErrRequestNotFound
	}
	if caller.actor.ID == record.InitiatorUserID {
		return record, nil
	}
	approval, approvalFound, approvalErr := s.opts.Store.GetActiveApproval(ctx, requestID)
	if approvalErr == nil && approvalFound && approval.ApproverUserID == caller.actor.ID {
		return record, nil
	}
	if historical, historyErr := s.opts.Store.ApproverHistory(ctx, requestID, caller.actor.ID); historyErr == nil && historical {
		return record, nil
	}
	s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery_request", requestID, "read_not_authorized", string(CodeAccessDenied), "")
	return RequestRecord{}, ErrAccessDenied
}

// ===== 内部辅助 =====

// requireEnabled 统一处理“默认关闭”拒绝并写失败审计。
func (s *Service) requireEnabled(ctx context.Context, caller Caller, stage string) error {
	if !caller.IsUser() {
		return ErrAccessDenied
	}
	if !s.policy.Enabled {
		s.recordFailure(ctx, caller.actor, ActionDenied, "manual_recovery", "disabled",
			"manual_recovery_disabled", string(CodeAccessDenied), "")
		return ErrDisabled
	}
	_ = stage
	return nil
}

// validateCreateRequest 校验申请字段（不读取目标）。
func (s *Service) validateCreateRequest(request CreateRequest) error {
	if !account.ValidUserID(request.TargetUserID) {
		return fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	if !request.Operation.Valid() {
		return fmt.Errorf("%w: 操作类型无效", ErrInvalidRequest)
	}
	if !request.VerificationBasis.Valid() {
		return fmt.Errorf("%w: 核验依据无效", ErrInvalidRequest)
	}
	if !s.policy.basisAllowed(request.VerificationBasis) {
		return fmt.Errorf("%w: 核验依据不在 root 配置允许范围内", ErrInvalidRequest)
	}
	if !request.Delivery.Valid() || !s.policy.deliveryAllowed(request.Delivery) {
		return fmt.Errorf("%w: 交付方式不在 root 配置允许范围内", ErrInvalidRequest)
	}
	if !validReference(request.VerificationReference) {
		return fmt.Errorf("%w: 外部核验记录编号无效", ErrInvalidRequest)
	}
	if !validText(request.EvidenceSummary, maxSummaryBytes, true) {
		return fmt.Errorf("%w: 证据摘要为空或含控制字符", ErrInvalidRequest)
	}
	if !validText(request.Reason, maxReasonBytes, true) {
		return fmt.Errorf("%w: 申请原因长度或内容无效", ErrInvalidRequest)
	}
	if request.SupportCaseID != "" && !validReference(request.SupportCaseID) {
		return fmt.Errorf("%w: 支持工单编号无效", ErrInvalidRequest)
	}
	return nil
}

// loadRequest 读取申请并记录读取失败；notFound 时写失败审计。
func (s *Service) loadRequest(ctx context.Context, requestID string, actor audit.Actor, stage string) (RequestRecord, error) {
	if !validDomainID(requestID, requestIDPrefix) {
		return RequestRecord{}, fmt.Errorf("%w: 申请编号无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetRequest(ctx, requestID)
	if err != nil {
		return RequestRecord{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, actor, ActionDenied, "manual_recovery_request", requestID, "not_found", string(CodeChallengeInvalid), "")
		return RequestRecord{}, ErrRequestNotFound
	}
	if record.Status.Terminal() && stage != "get" {
		return RequestRecord{}, ErrRequestClosed
	}
	return record, nil
}

// loadTarget 读取并校验目标账户：必须 active 且为普通账户（root/实际高权限拒绝）。
func (s *Service) loadTarget(ctx context.Context, targetUserID, traceID string, actor audit.Actor) (TargetState, error) {
	target, err := s.opts.Targets.LoadTarget(ctx, targetUserID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionDenied, "user", targetUserID, "target_load_failed", string(CodeOf(s.mapAuthzError(err))), traceID)
		return TargetState{}, s.mapAuthzError(err)
	}
	if target.UserID != targetUserID || !account.ValidUserID(target.UserID) {
		s.recordFailure(ctx, actor, ActionDenied, "user", targetUserID, "target_invalid", string(CodeAccessDenied), traceID)
		return TargetState{}, ErrAccessDenied
	}
	if target.IsRoot || target.HighPrivilege {
		s.recordFailure(ctx, actor, ActionDenied, "user", targetUserID, "target_protected", string(CodeSupportTargetProtected), traceID)
		return TargetState{}, ErrTargetProtected
	}
	if !target.Active || target.SecurityVersion <= 0 {
		s.recordFailure(ctx, actor, ActionDenied, "user", targetUserID, "target_unavailable", string(CodeUserDisabled), traceID)
		return TargetState{}, ErrTargetUnavailable
	}
	return target, nil
}

// authorizeSensitive 调用步骤 38/39 敏感策略执行器；未满足强认证/操作绑定时拒绝。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID string,
	params map[string]string, description, traceID string) (*reauth.Result, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return nil, ErrAccessDenied
	}
	result, err := s.opts.Reauth.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeSystem, OperationID: operationID, TargetType: "user",
		TargetID: params["target_user_id"], Params: params,
		Description: description, RequestID: traceID,
	})
	if err != nil {
		return nil, s.mapReauthError(err)
	}
	return &result, nil
}

// notifySensitive 是执行后告知（尽力而为，失败不回滚）。
func (s *Service) notifySensitive(ctx context.Context, result *reauth.Result) {
	if result == nil || isNilInterface(s.opts.Reauth) {
		return
	}
	if err := s.opts.Reauth.NotifyOutcome(ctx, *result, reauth.OutcomeSuccess); err != nil {
		s.logger.Warn("人工恢复敏感操作告知未完成", "error_category", "notify_failed")
	}
}

// mapReauthError 把再次认证领域错误映射为人工恢复领域错误。
func (s *Service) mapReauthError(err error) error {
	switch {
	case errors.Is(err, reauth.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, reauth.ErrMFARequired):
		return ErrMFARequired
	case errors.Is(err, reauth.ErrPolicyUnavailable):
		return ErrAuthzUnavailable
	case errors.Is(err, reauth.ErrStoreUnavailable):
		return ErrStoreUnavailable
	case errors.Is(err, reauth.ErrAuditUnavailable):
		return ErrAuditUnavailable
	default:
		return ErrReauthRequired
	}
}

// mapAuthzError 把授权器错误映射为人工恢复领域错误。
func (s *Service) mapAuthzError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrAuthzUnavailable) ||
		errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrTargetProtected) ||
		errors.Is(err, ErrTargetUnavailable) {
		return err
	}
	return ErrAccessDenied
}

// mapStoreError 把存储/审计错误映射为稳定领域错误。
func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuditUnavailable), errors.Is(err, audit.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, ErrContentChanged), errors.Is(err, ErrExecutionConflict),
		errors.Is(err, ErrApprovalExpired), errors.Is(err, ErrRequestClosed):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return ErrStoreUnavailable
	default:
		return ErrStoreUnavailable
	}
}

// recordFailure 写失败审计（独立事务）；审计不可用只写日志，不改变拒绝结论。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, targetType, targetID,
	reason string, errorCode string, traceID string) {
	event := audit.Event{
		Actor: actor, Action: action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: audit.OutcomeFailure, ErrorCode: errorCode, ReasonCode: reason,
		RequestID: validTrace(traceID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("人工恢复失败审计写入失败", "action", action, "reason", reason,
			"error_category", "audit_unavailable")
	}
}

// validTrace 返回可写审计的请求编号（非法值置空）。
func validTrace(traceID string) string {
	if validateRequestID(traceID) == nil {
		return traceID
	}
	return ""
}

// expireRequest 把过期申请迁移为 expired 并写失败审计。
func (s *Service) expireRequest(ctx context.Context, actor audit.Actor, record RequestRecord, reason, traceID string) {
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: ActionDenied,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: validTrace(traceID),
			Changes:   []audit.FieldChange{{Field: "status", Before: string(record.Status), After: string(StatusExpired)}},
		},
		FailureReasonCode: "manual_recovery.expire_failed",
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID, record.Status, StatusExpired, reason, now)
		return err
	}); err != nil {
		s.logger.Warn("人工恢复申请过期迁移失败", "request_id", record.ID)
	}
	s.recordFailure(ctx, actor, ActionDenied, "manual_recovery_request", record.ID, reason, string(CodeChallengeInvalid), traceID)
}

// invalidateApprovalAndReopen 使批准失效并把申请退回待审批（审批人撤销/批准过期）。
func (s *Service) invalidateApprovalAndReopen(ctx context.Context, actor audit.Actor, record RequestRecord,
	approval ApprovalRecord, reason, traceID string) error {
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: ActionDenied,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: validTrace(traceID),
			Changes: []audit.FieldChange{
				{Field: "approval_status", Before: string(ApprovalActive), After: string(ApprovalInvalidated)},
				{Field: "request_status", Before: string(StatusApproved), After: string(StatusPendingApproval)},
				{Field: "reason", After: reason},
			},
		},
		FailureReasonCode: "manual_recovery.invalidate_approval_failed",
	}
	return mapStoreError(s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, err := s.opts.Store.FinishApprovalTx(txCtx, tx, approval.ID, ApprovalInvalidated, reason, now); err != nil {
			return err
		}
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID,
			StatusApproved, StatusPendingApproval, reason, now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}))
}

// expireApprovedRequest 使过期申请与其批准同时失效并留审计（批准窗口超出申请生命
// 周期时执行前拒绝）：批准 invalidated、申请 approved→expired。
func (s *Service) expireApprovedRequest(ctx context.Context, actor audit.Actor, record RequestRecord,
	approval ApprovalRecord, reason, traceID string) error {
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: ActionDenied,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: validTrace(traceID),
			Changes: []audit.FieldChange{
				{Field: "request_status", Before: string(StatusApproved), After: string(StatusExpired)},
				{Field: "approval_status", After: string(ApprovalInvalidated)},
				{Field: "reason", After: reason},
			},
		},
		FailureReasonCode: "manual_recovery.expire_approved_failed",
	}
	return mapStoreError(s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, err := s.opts.Store.FinishApprovalTx(txCtx, tx, approval.ID, ApprovalInvalidated, reason, now); err != nil {
			return err
		}
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID, StatusApproved, StatusExpired, reason, now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}))
}

// failPendingRequest 在审批前发现目标/交付地址变化时把待审批申请置为失败并留审计。
func (s *Service) failPendingRequest(ctx context.Context, actor audit.Actor, record RequestRecord,
	reason, traceID string) error {
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: ActionDenied,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: validTrace(traceID),
			Changes: []audit.FieldChange{
				{Field: "request_status", Before: string(record.Status), After: string(StatusFailed)},
				{Field: "reason", After: reason},
			},
		},
		FailureReasonCode: "manual_recovery.fail_pending_failed",
	}
	return mapStoreError(s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID, record.Status, StatusFailed, reason, now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}))
}

// failRequest 使批准失效并把申请置为失败终态（目标变化/内容替换/执行前故障）。
func (s *Service) failRequest(ctx context.Context, actor audit.Actor, record RequestRecord,
	approval ApprovalRecord, reason, traceID string) error {
	now := s.clockNow()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: ActionExecutionFail,
			Target:    audit.Target{Type: "manual_recovery_request", ID: record.ID},
			RequestID: validTrace(traceID),
			Changes: []audit.FieldChange{
				{Field: "request_status", Before: string(record.Status), After: string(StatusFailed)},
				{Field: "approval_status", After: string(ApprovalInvalidated)},
				{Field: "reason", After: reason},
			},
		},
		FailureReasonCode: "manual_recovery.fail_request_failed",
	}
	return mapStoreError(s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if _, err := s.opts.Store.FinishApprovalTx(txCtx, tx, approval.ID,
			ApprovalInvalidated, reason, now); err != nil {
			return err
		}
		updated, err := s.opts.Store.TransitionRequestTx(txCtx, tx, record.ID,
			StatusApproved, StatusFailed, reason, now)
		if err != nil {
			return err
		}
		if !updated {
			return ErrRequestClosed
		}
		return nil
	}))
}

// finishExecution 在审计事务内完成执行/请求/批准状态并写成功或失败审计。
func (s *Service) finishExecution(ctx context.Context, actor audit.Actor, record RequestRecord,
	approval ApprovalRecord, execution ExecutionRecord, executionStatus string, requestStatus Status,
	notificationState string, outcome ExecutionOutcome) error {
	now := s.clockNow()
	errorCode := ""
	action := ActionExecution
	if requestStatus == StatusFailed {
		action = ActionExecutionFail
		errorCode = string(CodeInternalError)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: action,
			Target: audit.Target{Type: "manual_recovery_request", ID: record.ID},
			Changes: []audit.FieldChange{
				{Field: "execution_id", After: execution.ID},
				{Field: "operation_type", After: string(record.Operation)},
				{Field: "sessions_revoked", After: fmt.Sprint(outcome.SessionsRevoked)},
				{Field: "factors_reset", After: fmt.Sprint(outcome.FactorsReset)},
				{Field: "reset_credential_issued", After: fmt.Sprint(outcome.ResetCredentialIssued)},
				{Field: "notification_state", After: notificationState},
			},
		},
		FailureReasonCode:   "manual_recovery.finish_execution_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapStoreError(err))) },
	}
	approvalStatus := ApprovalConsumed
	if requestStatus == StatusFailed {
		approvalStatus = ApprovalInvalidated
	}
	finishErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		finished, err := s.opts.Store.FinishExecutionTx(txCtx, tx, record.ID, execution.ID, approval.ID,
			executionStatus, requestStatus, approvalStatus, outcome, errorCode, notificationState, now)
		if err != nil {
			return err
		}
		if !finished {
			return ErrExecutionConflict
		}
		return nil
	})
	if finishErr != nil {
		return mapStoreError(finishErr)
	}
	return nil
}

// notifyCompleted 发送完成通知并返回回执/投递投影；失败只记录状态，不回滚已完成的恢复
// （步骤 265：通知器不再丢弃 Enqueue 返回的投递关联）。
func (s *Service) notifyCompleted(ctx context.Context, record RequestRecord) NotificationDeliveryView {
	return s.deliverExecutionNotification(ctx, record, NotificationCompleted)
}

// notifyFailed 尽力通知既有渠道执行失败（由宿主决定渠道），不改执行结果；同样记录
// 通知状态与投递关联，且绝不把失败执行标记为恢复成功（步骤 265）。
func (s *Service) notifyFailed(ctx context.Context, record RequestRecord) NotificationDeliveryView {
	return s.deliverExecutionNotification(ctx, record, NotificationFailed)
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// bytesEqual 常量时间比较摘要，避免按内容提前返回泄露比较信息。
func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(left, right) == 1
}
