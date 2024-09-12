package support

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// 领域错误哨兵（补齐需再次验证/强认证的分类）。
var (
	ErrReauthRequired = errors.New("需要完成近期强认证")
	ErrMFARequired    = errors.New("需要完成两步验证")
)

// Options 是客服求助单服务依赖；所有依赖缺失都视为构造失败（fail-closed）。
type Options struct {
	Store           Store
	Audit           AuditRecorder
	Authorizer      Authorizer
	TargetProtector TargetProtector
	// Sensitive 是步骤 38/39 敏感策略执行前校验契约（生产 *reauth.Service）；
	// 客服登记/更新/发起找回都必须经它判定近期强认证与操作绑定，缺失时拒绝构造。
	Sensitive   reauth.OperationRunner
	ResetSender ResetSender
	// SendRate 是客服发起找回的账户维度+全局预算限流；零值使用
	// DefaultSendRatePolicy（单客服 10 分钟 5 次、全局每小时 100 次）。
	SendRate SendRatePolicy
	Now      func() time.Time
	Random   io.Reader
	Logger   *slog.Logger
}

// Service 是客服求助单服务。构造后不可变，不启动协程、不签发会话。
type Service struct {
	opts          Options
	sendRate      SendRatePolicy
	staffLimiter  *ratelimit.Limiter
	globalLimiter *ratelimit.Limiter
}

// New 校验依赖并构造服务；任何依赖为空（含 typed-nil）都返回错误。
func New(options Options) (*Service, error) {
	if isNilDependency(options.Store) {
		return nil, fmt.Errorf("%w: 求助单存储为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Authorizer) {
		return nil, fmt.Errorf("%w: 客服授权器为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.TargetProtector) {
		return nil, fmt.Errorf("%w: 高权限目标识别器为空", ErrOptionsInvalid)
	}
	if isNilDependency(options.Sensitive) {
		return nil, fmt.Errorf("%w: 敏感策略执行器为空（客服操作必须满足强认证）", ErrOptionsInvalid)
	}
	if isNilDependency(options.ResetSender) {
		return nil, fmt.Errorf("%w: 找回发送服务为空", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	sendRate := options.SendRate.resolve()
	if err := sendRate.validate(); err != nil {
		return nil, err
	}
	staffLimiter, err := ratelimit.New(ratelimit.Options{
		Policy: ratelimit.Policy{Limit: sendRate.StaffLimit, Window: sendRate.StaffWindow},
		Now:    options.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 客服找回限流器构造失败", ErrOptionsInvalid)
	}
	globalLimiter, err := ratelimit.New(ratelimit.Options{
		Policy: ratelimit.Policy{Limit: sendRate.GlobalLimit, Window: sendRate.GlobalWindow},
		Now:    options.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 全局找回限流器构造失败", ErrOptionsInvalid)
	}
	return &Service{opts: options, sendRate: sendRate,
		staffLimiter: staffLimiter, globalLimiter: globalLimiter}, nil
}

// CreateCaseRequest 是登记求助单请求。Reason 是不可信自由文本，只保存不执行。
type CreateCaseRequest struct {
	TargetUserID string
	Reason       string
	RequestID    string
}

// ReassignRequest 是把求助单指派给另一名客服工作人员的请求。
type ReassignRequest struct {
	CaseID            string
	NewAssigneeUserID string
	RequestID         string
}

// TransitionRequest 是变更求助单状态请求（关闭/取消等）。
type TransitionRequest struct {
	CaseID    string
	ToStatus  CaseStatus
	Note      string
	RequestID string
}

// SendRequest 是向求助单目标的原已验证邮箱发起找回的请求。
type SendRequest struct {
	CaseID    string
	RequestID string
}

// SendResult 是发起找回的结果；不包含链接、验证码、收件地址或 token。
type SendResult struct {
	// Sent 表示已交给找回服务并成功投递一次性入口。
	Sent bool
	// ManualReview 表示缺少可用验证渠道，只能转入人工核验待处理。
	ManualReview bool
	// Status 是动作后的求助单状态。
	Status CaseStatus
}

// CreateCase 登记求助单：客服必须在分配范围内且满足强认证；目标必须是普通
// 可用账户，高权限账户（root/实际高权限）拒绝普通客服处理。登记本身不发送邮件。
func (s *Service) CreateCase(ctx context.Context, caller Caller, request CreateCaseRequest) (CaseView, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return CaseView{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "invalid_request_id", string(CodeReqInvalid), "")
		return CaseView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", "", "invalid_target", string(CodeReqInvalid), request.RequestID)
		return CaseView{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	reason, ok := validReason(request.Reason)
	if !ok {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "invalid_reason", string(CodeReqInvalid), request.RequestID)
		return CaseView{}, fmt.Errorf("%w: 求助原因长度或内容无效", ErrInvalidRequest)
	}
	if request.TargetUserID == caller.actor.ID {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "self_target", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCaseCreate, "user",
		request.TargetUserID, map[string]string{
			"target_user_id": request.TargetUserID,
			"reason_sha256":  reasonDigest(reason),
			"request_id":     request.RequestID,
		}, "登记客服求助单", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	scope, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesCreate)
	if err != nil {
		return CaseView{}, err
	}
	if !scope.Allows(request.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "out_of_scope", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	target, err := s.loadTarget(ctx, request.TargetUserID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "target_load_failed", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	if err := s.checkTarget(ctx, target); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", request.TargetUserID, "target_rejected", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	caseID, err := newID(s.opts.Random, "sup_", 16)
	if err != nil {
		return CaseView{}, err
	}
	now := s.now()
	record := CaseRecord{
		ID: caseID, TargetUserID: target.UserID, TargetUsername: target.Username,
		CreatedByUserID: caller.actor.ID, AssigneeUserID: caller.actor.ID,
		TargetMaskedEmail: maskEmail(target.VerifiedEmail), Reason: reason,
		Status: StatusPendingVerification, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	event := EventRecord{
		ID: mustNewEventID(s.opts.Random), CaseID: caseID, Action: ActionCaseCreated,
		Actor: caller.actor, ToStatus: StatusPendingVerification,
		Detail: "登记求助单", CreatedAt: now,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCaseCreated,
			Target:    audit.Target{Type: "support_case", ID: caseID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "target_user_id", After: target.UserID},
				{Field: "reason_sha256", After: reasonDigest(reason)},
				{Field: "status", After: string(StatusPendingVerification)},
			},
		},
		FailureReasonCode:   "support.case.create_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateCaseTx(txCtx, tx, record, event)
	}); err != nil {
		return CaseView{}, mapCriticalError(err)
	}
	s.notifySensitive(ctx, guard)
	return viewOf(record), nil
}

// GetCase 读取分配给自己的求助单。查看他人工单统一拒绝且不泄露存在性，并写失败审计。
func (s *Service) GetCase(ctx context.Context, caller Caller, caseID string) (CaseView, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireCaseID(caseID); err != nil {
		return CaseView{}, err
	}
	record, err := s.loadOwnedCase(ctx, caller, caseID, ActionCaseDenied, "")
	if err != nil {
		return CaseView{}, err
	}
	return viewOf(record), nil
}

// ListCases 分页列出分配给自己的求助单；普通工作人员不能列出他人求助单。
// 系统调用者可按查询条件列出（供受控管理装配），但同样只返回脱敏视图。
// 该入口保持既有签名；带搜索的调用方使用 ListCasesPage。
func (s *Service) ListCases(ctx context.Context, caller Caller, statuses []CaseStatus, offset, limit int) (CasePage, error) {
	return s.ListCasesPage(ctx, caller, CaseListRequest{Statuses: statuses, Offset: offset, Limit: limit})
}

// ListCasesPage 分页列出求助单，支持可选的有界字面搜索（编号/原因）。普通工作人员
// 仍强制 AssigneeUserID=本人；搜索在授权范围过滤之后执行，不搜索脱敏邮箱/用户名，
// 避免向无权调用者泄露隐藏字段的匹配存在性。搜索文本/字段非法返回 REQ_INVALID。
func (s *Service) ListCasesPage(ctx context.Context, caller Caller, request CaseListRequest) (CasePage, error) {
	ctx = normalizeContext(ctx)
	statuses := request.Statuses
	offset, limit := request.Offset, request.Limit
	if !validStatusFilter(statuses) {
		return CasePage{}, fmt.Errorf("%w: 状态筛选含未知状态", ErrInvalidRequest)
	}
	if offset < 0 || offset > MaxListOffset {
		return CasePage{}, fmt.Errorf("%w: 偏移量无效", ErrInvalidRequest)
	}
	if limit <= 0 {
		limit = DefaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	searchText, searchFields, err := normalizeCaseSearch(request.Search, request.SearchFields)
	if err != nil {
		return CasePage{}, err
	}
	query := CaseQuery{Statuses: statuses, Limit: limit, Offset: offset,
		Search: searchText, SearchFields: searchFields}
	if caller.IsUser() {
		if _, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesRead); err != nil {
			s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", "", "list_denied", string(CodeOf(err)), "")
			return CasePage{}, err
		}
		query.AssigneeUserID = caller.actor.ID
	} else if caller.actor.Type != audit.ActorSystem {
		return CasePage{}, ErrAccessDenied
	}
	records, hasMore, err := s.opts.Store.ListCases(ctx, query)
	if err != nil {
		return CasePage{}, mapStoreError(err)
	}
	views := make([]CaseView, 0, len(records))
	for _, record := range records {
		views = append(views, viewOf(record))
	}
	page := CasePage{Cases: views, HasMore: hasMore}
	if hasMore {
		page.NextOffset = offset + len(views)
	}
	return page, nil
}

// ListEvents 读取分配给自己的求助单的处理历史；他人工单拒绝。
func (s *Service) ListEvents(ctx context.Context, caller Caller, caseID string, offset, limit int) (HistoryPage, error) {
	ctx = normalizeContext(ctx)
	if err := s.requireCaseID(caseID); err != nil {
		return HistoryPage{}, err
	}
	if offset < 0 || offset > MaxListOffset {
		return HistoryPage{}, fmt.Errorf("%w: 偏移量无效", ErrInvalidRequest)
	}
	if limit <= 0 {
		limit = DefaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	if _, err := s.loadOwnedCase(ctx, caller, caseID, ActionCaseDenied, ""); err != nil {
		return HistoryPage{}, err
	}
	events, hasMore, err := s.opts.Store.ListEvents(ctx, caseID, offset, limit)
	if err != nil {
		return HistoryPage{}, mapStoreError(err)
	}
	page := HistoryPage{Events: make([]EventView, 0, len(events)), HasMore: hasMore}
	for _, event := range events {
		page.Events = append(page.Events, eventViewOf(event))
	}
	if hasMore {
		page.NextOffset = offset + len(events)
	}
	return page, nil
}

// LookupTarget 在负责范围内定位普通用户并返回必要脱敏资料；不含邮箱明文、密码/
// MFA/凭证信息。高权限账户返回 SUPPORT_TARGET_PROTECTED，未授权范围/不存在统一拒绝。
func (s *Service) LookupTarget(ctx context.Context, caller Caller, targetUserID, requestID string) (TargetView, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return TargetView{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", targetUserID, "invalid_request_id", string(CodeReqInvalid), "")
		return TargetView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(targetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", "", "invalid_target", string(CodeReqInvalid), requestID)
		return TargetView{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	scope, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesCreate)
	if err != nil {
		return TargetView{}, err
	}
	if !scope.Allows(targetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", targetUserID, "out_of_scope", string(CodeAccessDenied), requestID)
		return TargetView{}, ErrAccessDenied
	}
	target, err := s.loadTarget(ctx, targetUserID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", targetUserID, "target_load_failed", string(CodeOf(err)), requestID)
		return TargetView{}, err
	}
	if err := s.checkTarget(ctx, target); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "user", targetUserID, "target_rejected", string(CodeOf(err)), requestID)
		return TargetView{}, err
	}
	return TargetView{
		UserID: target.UserID, MaskedUsername: maskUsername(target.Username),
		MaskedEmail: maskEmail(target.VerifiedEmail), Status: target.Status,
		HasPassword: target.HasPassword, HasVerifiedEmail: target.HasVerifiedEmail,
		CanRequestReset: target.HasPassword && target.HasVerifiedEmail,
	}, nil
}

// ReassignCase 把分配给自己的求助单转给另一名具备客服资格的工作人员。变更绑定
// 强认证、目标与操作参数；记录真实操作者、行版本条件更新与处理历史，审计不可覆盖。
func (s *Service) ReassignCase(ctx context.Context, caller Caller, request ReassignRequest) (CaseView, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return CaseView{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "invalid_request_id", string(CodeReqInvalid), "")
		return CaseView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.requireCaseID(request.CaseID); err != nil {
		return CaseView{}, err
	}
	if !account.ValidUserID(request.NewAssigneeUserID) {
		return CaseView{}, fmt.Errorf("%w: 新指派客服标识无效", ErrInvalidRequest)
	}
	record, err := s.loadCaseForUpdate(ctx, caller, request.CaseID, request.RequestID)
	if err != nil {
		return CaseView{}, err
	}
	if record.TargetUserID == request.NewAssigneeUserID {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "assign_to_target", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCaseUpdate, "support_case",
		request.CaseID, map[string]string{
			"case_id":              request.CaseID,
			"target_user_id":       record.TargetUserID,
			"new_assignee_user_id": request.NewAssigneeUserID,
			"request_id":           request.RequestID,
		}, "变更客服求助单指派", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	scope, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesUpdate)
	if err != nil {
		return CaseView{}, err
	}
	if !scope.Allows(record.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_out_of_scope", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	newAssigneeScope, err := s.staffScope(ctx, request.NewAssigneeUserID, PermissionCasesRead)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "assignee_ineligible", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	if !newAssigneeScope.Allows(record.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "assignee_out_of_scope", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	// 目标在登记后可能已获得更高权限：转派前重新按实际权限识别，高权限目标拒绝。
	target, err := s.loadTarget(ctx, record.TargetUserID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_load_failed", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	if err := s.checkTarget(ctx, target); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_rejected", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	if request.NewAssigneeUserID == record.AssigneeUserID {
		// 幂等：指派未变化，不递增版本、不写处理历史，返回当前脱敏视图。
		return viewOf(record), nil
	}
	now := s.now()
	event := EventRecord{
		ID: mustNewEventID(s.opts.Random), CaseID: request.CaseID, Action: ActionCaseAssigned,
		Actor: caller.actor, FromStatus: record.Status, ToStatus: record.Status,
		Detail: "转派", CreatedAt: now,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCaseAssigned,
			Target:    audit.Target{Type: "support_case", ID: request.CaseID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "assignee_user_id", Before: record.AssigneeUserID, After: request.NewAssigneeUserID},
			},
		},
		FailureReasonCode:   "support.case.assign_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateCaseTx(txCtx, tx, CaseUpdate{
			CaseID: request.CaseID, ExpectedVersion: record.RowVersion,
			SetAssignee: request.NewAssigneeUserID, UpdatedAt: now, Event: event,
		})
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		return nil
	}); err != nil {
		return CaseView{}, mapCriticalError(err)
	}
	if !updated {
		return CaseView{}, ErrVersionConflict
	}
	record.AssigneeUserID = request.NewAssigneeUserID
	record.RowVersion++
	record.UpdatedAt = now
	s.notifySensitive(ctx, guard)
	return viewOf(record), nil
}

// TransitionCase 变更分配给自己的求助单状态（关闭/取消等）。只允许状态机中列出的
// 迁移；终态不可再变更。并发变更通过行版本条件更新保证只有一个成功。
func (s *Service) TransitionCase(ctx context.Context, caller Caller, request TransitionRequest) (CaseView, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return CaseView{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "invalid_request_id", string(CodeReqInvalid), "")
		return CaseView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.requireCaseID(request.CaseID); err != nil {
		return CaseView{}, err
	}
	if !request.ToStatus.Valid() {
		return CaseView{}, fmt.Errorf("%w: 目标状态无效", ErrInvalidRequest)
	}
	// `sent` 只能由 SendReset 在真实投递成功后内部写入；人工状态迁移不得伪造
	// “已发送”（否则会把未投递的找回入口当作已完成恢复）。
	if request.ToStatus == StatusSent {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "manual_sent_forbidden", string(CodeReqInvalid), request.RequestID)
		return CaseView{}, fmt.Errorf("%w: 不允许人工迁移到 sent", ErrInvalidRequest)
	}
	note, ok := validNote(request.Note)
	if !ok {
		return CaseView{}, fmt.Errorf("%w: 处理说明长度或内容无效", ErrInvalidRequest)
	}
	record, err := s.loadCaseForUpdate(ctx, caller, request.CaseID, request.RequestID)
	if err != nil {
		return CaseView{}, err
	}
	if request.ToStatus == record.Status {
		return viewOf(record), nil
	}
	if !allowedTransition(record.Status, request.ToStatus) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "invalid_transition", string(CodeConflict), request.RequestID)
		return CaseView{}, ErrCaseClosed
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationCaseUpdate, "support_case",
		request.CaseID, map[string]string{
			"case_id":        request.CaseID,
			"target_user_id": record.TargetUserID,
			"to_status":      string(request.ToStatus),
			"request_id":     request.RequestID,
		}, "变更客服求助单状态", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return CaseView{}, err
	}
	scope, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesUpdate)
	if err != nil {
		return CaseView{}, err
	}
	if !scope.Allows(record.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_out_of_scope", string(CodeAccessDenied), request.RequestID)
		return CaseView{}, ErrAccessDenied
	}
	now := s.now()
	event := EventRecord{
		ID: mustNewEventID(s.opts.Random), CaseID: request.CaseID, Action: ActionCaseStatusChanged,
		Actor: caller.actor, FromStatus: record.Status, ToStatus: request.ToStatus,
		Detail: validDetail(note), CreatedAt: now,
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: ActionCaseStatusChanged,
			Target:    audit.Target{Type: "support_case", ID: request.CaseID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "status", Before: string(record.Status), After: string(request.ToStatus)},
			},
		},
		FailureReasonCode:   "support.case.status_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	updated := false
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateCaseTx(txCtx, tx, CaseUpdate{
			CaseID: request.CaseID, ExpectedVersion: record.RowVersion,
			SetStatus: request.ToStatus, UpdatedAt: now, Event: event,
		})
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		return nil
	}); err != nil {
		return CaseView{}, mapCriticalError(err)
	}
	if !updated {
		return CaseView{}, ErrVersionConflict
	}
	record.Status = request.ToStatus
	record.RowVersion++
	record.UpdatedAt = now
	s.notifySensitive(ctx, guard)
	return viewOf(record), nil
}

// SendReset 向求助单目标**此前已验证的邮箱**发起一次性密码找回入口。只允许原验证
// 邮箱，客服拿不到链接/验证码，也不能指定新密码；发送本身不修改密码、不解除 MFA、
// 不签发会话。缺少可用验证渠道时只转入人工核验待处理（manual_review），不以客服
// 确认直接恢复。重复发起由找回服务按目标用户有界限流。
func (s *Service) SendReset(ctx context.Context, caller Caller, request SendRequest) (SendResult, error) {
	ctx = normalizeContext(ctx)
	if !caller.IsUser() {
		return SendResult{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "invalid_request_id", string(CodeReqInvalid), "")
		return SendResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.requireCaseID(request.CaseID); err != nil {
		return SendResult{}, err
	}
	record, err := s.loadCaseForUpdate(ctx, caller, request.CaseID, request.RequestID)
	if err != nil {
		return SendResult{}, err
	}
	guard, err := s.authorizeSensitive(ctx, caller, OperationResetSend, "support_case",
		request.CaseID, map[string]string{
			"case_id":        request.CaseID,
			"target_user_id": record.TargetUserID,
			"request_id":     request.RequestID,
		}, "向原验证邮箱发起密码找回", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "reauth_rejected", string(CodeOf(err)), request.RequestID)
		return SendResult{}, err
	}
	updateScope, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesUpdate)
	if err != nil {
		return SendResult{}, err
	}
	resetScope, err := s.staffScope(ctx, caller.actor.ID, PermissionResetRequest)
	if err != nil {
		return SendResult{}, err
	}
	if !updateScope.Allows(record.TargetUserID) || !resetScope.Allows(record.TargetUserID) {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_out_of_scope", string(CodeAccessDenied), request.RequestID)
		return SendResult{}, ErrAccessDenied
	}
	// 找回发送的客服账户维度 + 全局发起预算限流：防止单个账户重复触发或全局批量
	// 触发邮件。超限写失败审计并返回 RATE_LIMITED，不读取/修改目标状态。
	if decision := s.staffLimiter.Allow(caller.actor.ID); !decision.Allowed {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "send_rate_limited_staff", string(CodeRateLimited), request.RequestID)
		return SendResult{}, ErrRateLimited
	}
	if decision := s.globalLimiter.Allow("global"); !decision.Allowed {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "send_rate_limited_global", string(CodeRateLimited), request.RequestID)
		return SendResult{}, ErrRateLimited
	}
	target, err := s.loadTarget(ctx, record.TargetUserID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_load_failed", string(CodeOf(err)), request.RequestID)
		return SendResult{}, err
	}
	if err := s.checkTarget(ctx, target); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "target_rejected", string(CodeOf(err)), request.RequestID)
		return SendResult{}, err
	}
	// 缺少已验证邮箱/密码：只能转人工核验待处理，不尝试找回、不宣称已完成。
	if !target.HasVerifiedEmail || !target.HasPassword {
		status, err := s.moveToManualReview(ctx, caller, record, "无可用验证渠道", request.RequestID)
		if err != nil {
			return SendResult{}, err
		}
		s.notifySensitive(ctx, guard)
		return SendResult{ManualReview: true, Status: status}, nil
	}
	if _, err := s.sendReset(ctx, record, request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", request.CaseID, "reset_send_failed", string(CodeOf(err)), request.RequestID)
		return SendResult{}, err
	}
	now := s.now()
	event := EventRecord{
		ID: mustNewEventID(s.opts.Random), CaseID: request.CaseID, Action: ActionCaseResetRequested,
		Actor: caller.actor, FromStatus: record.Status, ToStatus: StatusSent,
		Detail: "已向原已验证邮箱发起找回", CreatedAt: now,
	}
	status, err := s.updateStatus(ctx, caller, record, StatusSent, event, audit.Event{
		Actor: caller.actor, Action: ActionCaseResetRequested,
		Target:    audit.Target{Type: "support_case", ID: request.CaseID},
		RequestID: validRequestID(request.RequestID),
		Changes: []audit.FieldChange{
			{Field: "status", Before: string(record.Status), After: string(StatusSent)},
			{Field: "recipient", After: record.TargetMaskedEmail},
		},
	}, "support.case.reset_failed", request.RequestID)
	if err != nil {
		return SendResult{}, err
	}
	s.notifySensitive(ctx, guard)
	return SendResult{Sent: true, Status: status}, nil
}

// ===== 内部辅助 =====

// sendReset 调用找回服务的受信通道；错误映射为客服领域既有错误。
func (s *Service) sendReset(ctx context.Context, record CaseRecord, requestID string) (bool, error) {
	result, err := s.opts.ResetSender.SendResetForSupport(ctx, passwordreset.SupportResetRequest{
		TargetUserID: record.TargetUserID, RequestID: requestID,
	})
	if err != nil {
		switch {
		case errors.Is(err, passwordreset.ErrRateLimited):
			return false, ErrRateLimited
		case errors.Is(err, passwordreset.ErrMailFailed):
			return false, ErrMailFailed
		case errors.Is(err, passwordreset.ErrAccountDisabled):
			return false, ErrTargetUnavailable
		case errors.Is(err, passwordreset.ErrAccessDenied):
			return false, ErrTargetProtected
		case errors.Is(err, passwordreset.ErrStoreUnavailable):
			return false, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
		case errors.Is(err, passwordreset.ErrNoPassword), errors.Is(err, passwordreset.ErrNoVerifiedEmail):
			return false, ErrTargetUnavailable
		default:
			return false, ErrInternal
		}
	}
	return result.Delivered, nil
}

// moveToManualReview 把缺少验证渠道的求助单转入人工核验待处理状态并写审计。
func (s *Service) moveToManualReview(ctx context.Context, caller Caller, record CaseRecord, note, requestID string) (CaseStatus, error) {
	now := s.now()
	event := EventRecord{
		ID: mustNewEventID(s.opts.Random), CaseID: record.ID, Action: ActionCaseManualReview,
		Actor: caller.actor, FromStatus: record.Status, ToStatus: StatusManualReview,
		Detail: validDetail(note), CreatedAt: now,
	}
	status, err := s.updateStatus(ctx, caller, record, StatusManualReview, event, audit.Event{
		Actor: caller.actor, Action: ActionCaseManualReview,
		Target:    audit.Target{Type: "support_case", ID: record.ID},
		RequestID: validRequestID(requestID),
		Changes: []audit.FieldChange{
			{Field: "status", Before: string(record.Status), After: string(StatusManualReview)},
			{Field: "reason", After: "no_verified_channel"},
		},
	}, "support.case.manual_review_failed", requestID)
	if err != nil {
		return "", err
	}
	return status, nil
}

// updateStatus 在审计事务内做行版本条件状态迁移并追加处理历史。
func (s *Service) updateStatus(ctx context.Context, caller Caller, record CaseRecord,
	toStatus CaseStatus, event EventRecord, template audit.Event, failureReason, requestID string) (CaseStatus, error) {
	critical := audit.CriticalRequest{
		Event:               template,
		FailureReasonCode:   failureReason,
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	updated := false
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateCaseTx(txCtx, tx, CaseUpdate{
			CaseID: record.ID, ExpectedVersion: record.RowVersion,
			SetStatus: toStatus, UpdatedAt: s.now(), Event: event,
		})
		if updateErr != nil {
			return updateErr
		}
		updated = ok
		return nil
	})
	if err != nil {
		return "", mapCriticalError(err)
	}
	if !updated {
		return "", ErrVersionConflict
	}
	return toStatus, nil
}

// loadOwnedCase 读取并校验求助单归属；不存在或不属于调用者统一 ACCESS_DENIED，
// 不泄露他人求助单存在性，并写失败审计。
func (s *Service) loadOwnedCase(ctx context.Context, caller Caller, caseID, action, requestID string) (CaseRecord, error) {
	record, err := s.loadCase(ctx, caseID)
	if err != nil {
		return CaseRecord{}, err
	}
	if caller.IsUser() {
		if record.AssigneeUserID != caller.actor.ID {
			s.recordFailure(ctx, caller.actor, action, "support_case", caseID, "not_assignee", string(CodeAccessDenied), requestID)
			return CaseRecord{}, ErrAccessDenied
		}
		if _, err := s.staffScope(ctx, caller.actor.ID, PermissionCasesRead); err != nil {
			s.recordFailure(ctx, caller.actor, action, "support_case", caseID, "read_denied", string(CodeOf(err)), requestID)
			return CaseRecord{}, err
		}
		return record, nil
	}
	if caller.actor.Type != audit.ActorSystem {
		return CaseRecord{}, ErrAccessDenied
	}
	return record, nil
}

// loadCaseForUpdate 读取本人被指派且未终结的求助单。
func (s *Service) loadCaseForUpdate(ctx context.Context, caller Caller, caseID, requestID string) (CaseRecord, error) {
	record, err := s.loadOwnedCase(ctx, caller, caseID, ActionCaseDenied, requestID)
	if err != nil {
		return CaseRecord{}, err
	}
	if record.Status.Terminal() {
		s.recordFailure(ctx, caller.actor, ActionCaseDenied, "support_case", caseID, "case_closed", string(CodeConflict), requestID)
		return CaseRecord{}, ErrCaseClosed
	}
	return record, nil
}

func (s *Service) loadCase(ctx context.Context, caseID string) (CaseRecord, error) {
	record, found, err := s.opts.Store.GetCase(ctx, caseID)
	if err != nil {
		return CaseRecord{}, mapStoreError(err)
	}
	if !found {
		return CaseRecord{}, ErrAccessDenied
	}
	return record, nil
}

// loadTarget 读取目标普通用户快照；不存在统一 ACCESS_DENIED。
func (s *Service) loadTarget(ctx context.Context, userID string) (TargetSnapshot, error) {
	target, found, err := s.opts.Store.LookupTarget(ctx, userID)
	if err != nil {
		return TargetSnapshot{}, mapStoreError(err)
	}
	if !found {
		return TargetSnapshot{}, ErrAccessDenied
	}
	return target, nil
}

// checkTarget 拒绝不可用、root 或实际高权限目标；识别失败按高权限拒绝（fail-closed）。
func (s *Service) checkTarget(ctx context.Context, target TargetSnapshot) error {
	if target.IsRoot {
		return ErrTargetProtected
	}
	if target.Status != "active" {
		return ErrTargetUnavailable
	}
	protected, err := s.opts.TargetProtector.Protected(ctx, target.UserID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
	if protected {
		return ErrTargetProtected
	}
	return nil
}

// staffScope 取得工作人员在指定功能权限上的数据范围。
func (s *Service) staffScope(ctx context.Context, staffUserID, permissionKey string) (StaffScope, error) {
	scope, err := s.opts.Authorizer.AuthorizeStaff(ctx, staffUserID, permissionKey)
	if err != nil {
		switch {
		case errors.Is(err, ErrAccessDenied):
			return StaffScope{}, ErrAccessDenied
		case errors.Is(err, ErrAuthzUnavailable):
			return StaffScope{}, err
		default:
			return StaffScope{}, fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
		}
	}
	return scope, nil
}

// authorizeSensitive 执行步骤 38/39 敏感策略判定并绑定操作/目标/服务端参数摘要。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID, targetType,
	targetID string, params map[string]string, description, requestID string) (reauth.Result, error) {
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: targetType, TargetID: targetID,
		Params: params, Description: description, RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, mapReauthError(err)
	}
	return result, nil
}

// notifySensitive 发送/记录执行后安全告知；失败只记日志，不回滚已成功变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("客服操作安全告知未完成", "error", err)
	}
}

// recordFailure 写拒绝/失败审计（独立事务）；审计失败不改变拒绝结果。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, targetType, targetID,
	reason, code, requestID string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{
		Actor: actor, Action: action, Outcome: audit.OutcomeDenied,
		Target:    audit.Target{Type: targetType, ID: targetID},
		ErrorCode: code, ReasonCode: safeToken(reason), RequestID: validRequestID(requestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("客服操作失败审计写入失败", "error", err)
	}
}

// requireCaseID 校验求助单 ID 格式（sup_ + 32 位十六进制）。
func (s *Service) requireCaseID(caseID string) error {
	if !validCaseID(caseID) {
		return fmt.Errorf("%w: 求助单标识无效", ErrInvalidRequest)
	}
	return nil
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func viewOf(record CaseRecord) CaseView {
	return CaseView{
		ID: record.ID, ApplicationID: record.ApplicationID, TargetUserID: record.TargetUserID,
		TargetMaskedUsername: maskUsername(record.TargetUsername),
		TargetMaskedEmail:    record.TargetMaskedEmail,
		Reason:               record.Reason, Status: record.Status,
		AssigneeUserID: record.AssigneeUserID, CreatedByUserID: record.CreatedByUserID,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, RowVersion: record.RowVersion,
	}
}

func eventViewOf(event EventRecord) EventView {
	return EventView{
		ID: event.ID, CaseID: event.CaseID, Seq: event.Seq, Action: event.Action,
		ActorType: event.Actor.Type, ActorID: event.Actor.ID,
		FromStatus: event.FromStatus, ToStatus: event.ToStatus,
		Detail: event.Detail, CreatedAt: event.CreatedAt,
	}
}

// allowedTransition 是求助单状态机允许的人工迁移（发送动作由服务内部迁移到 sent/
// manual_review）。终态无出边。
func allowedTransition(from, to CaseStatus) bool {
	switch from {
	case StatusPendingVerification:
		// sent 只能由 SendReset 内部在真实投递后写入，不接受人工迁移。
		return to == StatusManualReview || to == StatusClosed || to == StatusCancelled
	case StatusSent:
		return to == StatusManualReview || to == StatusClosed || to == StatusCancelled
	case StatusManualReview:
		return to == StatusClosed || to == StatusCancelled
	default:
		return false
	}
}

func validCaseID(value string) bool {
	if len(value) != 4+32 || !strings.HasPrefix(value, "sup_") {
		return false
	}
	for index := 4; index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func newID(random io.Reader, prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// mustNewEventID 生成历史事件 ID；随机源不可用时返回空串由存储列拒绝（不会静默）。
func mustNewEventID(random io.Reader) string {
	id, err := newID(random, "sce_", 16)
	if err != nil {
		return ""
	}
	return id
}

func validRequestID(value string) string {
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func mapReauthError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, reauth.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, reauth.ErrMFARequired):
		return fmt.Errorf("%w: %w", ErrMFARequired, err)
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrConfirmationRequired),
		errors.Is(err, reauth.ErrAuthenticationFailed), errors.Is(err, reauth.ErrChallengeInvalid),
		errors.Is(err, reauth.ErrChallengeExpired), errors.Is(err, reauth.ErrAttemptsExceeded),
		errors.Is(err, reauth.ErrApprovalInvalid), errors.Is(err, reauth.ErrApprovalExpired),
		errors.Is(err, reauth.ErrApprovalConsumed), errors.Is(err, reauth.ErrRateLimited):
		return fmt.Errorf("%w: %w", ErrReauthRequired, err)
	default:
		return fmt.Errorf("%w: %w", ErrAuthzUnavailable, err)
	}
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrStoreUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// ErrInternal 是未分类内部故障的投影（不建议直接返回给调用方）。
var ErrInternal = errors.New("客服求助单内部故障")

// isNilDependency 识别 typed-nil 依赖。
func isNilDependency(value any) bool {
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
