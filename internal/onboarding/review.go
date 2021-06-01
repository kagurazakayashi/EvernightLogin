package onboarding

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// ScopedManagementAuthorizer 是带应用/角色范围参数的管理强认证契约。实现必须按
// 目标应用与即将分配的角色判定调用者是否有权批准；未实现该扩展时，普通用户不能
// 通过审核授予 system 作用域角色（只能走受信 system/local_admin 通道）。
type ScopedManagementAuthorizer interface {
	AuthorizeManagementScope(ctx context.Context, caller Caller, appID string, roles []Role) error
}

// ScopedManagementAuthorizerFunc 是范围管理授权的函数适配器。
type ScopedManagementAuthorizerFunc func(ctx context.Context, caller Caller, appID string, roles []Role) error

// AuthorizeManagementScope 实现 ScopedManagementAuthorizer。
func (f ScopedManagementAuthorizerFunc) AuthorizeManagementScope(ctx context.Context, caller Caller, appID string, roles []Role) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, appID, roles)
}

// ListPendingReviews 列出待审核注册账户（需管理强认证/受信管理通道）。
func (s *Service) ListPendingReviews(ctx context.Context, caller Caller, query ReviewQuery) (ReviewQueryResult, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorizeManagement(ctx, caller); err != nil {
		return ReviewQueryResult{}, err
	}
	if query.Limit == 0 {
		query.Limit = DefaultListLimit
	}
	if query.Limit < 1 || query.Limit > MaxListLimit || query.Offset < 0 {
		return ReviewQueryResult{}, fmt.Errorf("%w: 分页参数无效", ErrInvalidRequest)
	}
	result, err := s.opts.Store.ListPendingReviews(ctx, query)
	if err != nil {
		return ReviewQueryResult{}, ErrStoreUnavailable
	}
	return result, nil
}

// GetReview 读取单个账户的审核状态（需管理强认证/受信管理通道）。
func (s *Service) GetReview(ctx context.Context, caller Caller, userID string) (ReviewUser, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorizeManagement(ctx, caller); err != nil {
		return ReviewUser{}, err
	}
	if !account.ValidUserID(userID) {
		return ReviewUser{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	review, found, err := s.opts.Store.GetReviewUser(ctx, userID)
	if err != nil {
		return ReviewUser{}, ErrStoreUnavailable
	}
	if !found {
		return ReviewUser{}, ErrReviewNotFound
	}
	return review, nil
}

// ApproveRegistration 批准注册申请：在同一审计事务内把 pending 账户改为 active，
// 可选加入应用成员并分配角色，然后发送结果通知。
func (s *Service) ApproveRegistration(ctx context.Context, caller Caller, request ReviewRequest) (ReviewResult, error) {
	return s.decideRegistration(ctx, caller, request, true)
}

// RejectRegistration 拒绝注册申请：在同一审计事务内把 pending 账户改为 disabled
// 并记录理由，然后发送结果通知。
func (s *Service) RejectRegistration(ctx context.Context, caller Caller, request ReviewRequest) (ReviewResult, error) {
	return s.decideRegistration(ctx, caller, request, false)
}

// decideRegistration 是批准/拒绝的共同实现。
func (s *Service) decideRegistration(ctx context.Context, caller Caller, request ReviewRequest, approve bool) (ReviewResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return ReviewResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.UserID) {
		return ReviewResult{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if len([]rune(request.Reason)) > 500 {
		return ReviewResult{}, fmt.Errorf("%w: 审核理由过长", ErrInvalidRequest)
	}
	// 申请人不能批准/拒绝自己的注册（只约束普通用户身份；受信系统通道不受此限）。
	if caller.actor.Type == audit.ActorUser && caller.actor.ID == request.UserID {
		return ReviewResult{}, ErrSelfApproval
	}
	var appID string
	var roles []Role
	var err error
	if approve {
		appID = strings.TrimSpace(request.AppID)
		if appID != "" && !app.ValidApplicationID(appID) {
			return ReviewResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
		}
		roles, err = normalizeRoles(request.Roles, appID)
		if err != nil {
			return ReviewResult{}, err
		}
	}
	if err := s.authorizeReviewScope(ctx, caller, approve, appID, roles); err != nil {
		return ReviewResult{}, err
	}
	now := s.now()
	action := "registration.approve"
	if !approve {
		action = "registration.reject"
	}
	decided := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    action,
			Target:    audit.Target{Type: "user", ID: request.UserID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "decision", Before: "pending", After: map[bool]string{true: "approved", false: "rejected"}[approve]},
				{Field: "reason", After: maskText(request.Reason)},
			},
		},
		FailureReasonCode: "registration.decision_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		review, found, err := s.opts.Store.LoadReviewUserTx(txCtx, tx, request.UserID)
		if err != nil {
			return err
		}
		if !found {
			return ErrReviewNotFound
		}
		if review.Status != account.StatusPending {
			return ErrReviewStateConflict
		}
		if approve && appID != "" {
			status, found, err := s.opts.Store.AppStatusTx(txCtx, tx, appID)
			if err != nil {
				return err
			}
			if !found || !appActive(appID, status) {
				return ErrInvitationNotAcceptable
			}
		}
		// 批准会写入应用成员并分配角色：在应用范围内按审核者当前权限复核目标用户
		// 既有权限 ∪ 新分配角色权限（与邀请接受同一口径，防止借审批绕过转授限制）。
		if approve && (appID != "" || len(roles) > 0) {
			reader, ok := s.opts.Store.(RoleAssignableReader)
			if !ok {
				return fmt.Errorf("%w: 存储不支持角色可分配性检查", ErrOptionsInvalid)
			}
			if err := reader.RoleAssignableTx(txCtx, tx, roles); err != nil {
				return err
			}
			scopeID := appID
			if scopeID == "" {
				scopeID = "system"
			}
			permissions, err := s.opts.Store.RolePermissionsTx(txCtx, tx, roles)
			if err != nil {
				return err
			}
			existingRefs, err := reader.MemberEffectivePermissionRefsTx(txCtx, tx, scopeID, request.UserID)
			if err != nil {
				return err
			}
			transferRefs := unionPermissionRefs(existingRefs, flattenRolePermissions(roles, permissions))
			if err := s.opts.Guard.CheckAssignment(txCtx, tx, caller.actor, scopeID,
				transferRefs, delegation.Target{Kind: delegation.TargetUser, ID: request.UserID}); err != nil {
				return fmt.Errorf("%w: 审核者当前无权完成该批准（含目标既有权限）", ErrAccessDenied)
			}
		}
		ok, err := s.opts.Store.DecideReviewTx(txCtx, tx, ReviewDecision{
			UserID:    request.UserID,
			Approve:   approve,
			Reason:    request.Reason,
			AppID:     appID,
			Roles:     roles,
			Actor:     caller.actor,
			Now:       now,
			RequestID: request.RequestID,
		})
		if err != nil {
			return err
		}
		decided = ok
		if !ok {
			return ErrReviewStateConflict
		}
		return nil
	})
	if err != nil {
		return ReviewResult{}, mapCriticalError(err)
	}
	if !decided {
		return ReviewResult{}, ErrReviewStateConflict
	}
	review, found, err := s.opts.Store.GetReviewUser(ctx, request.UserID)
	if err != nil || !found {
		return ReviewResult{}, ErrStoreUnavailable
	}
	result := ReviewResult{Review: review}
	email, hasEmail, err := s.opts.Store.NotificationEmail(ctx, request.UserID)
	if err != nil {
		return ReviewResult{}, ErrStoreUnavailable
	}
	decisionText := "approve"
	if !approve {
		decisionText = "reject"
	}
	if s.opts.Mailer == nil || !hasEmail {
		result.Notified = false
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.recordReviewNotify(ctx, request.UserID, NotifyFailed, result.ErrorCode)
		return result, nil
	}
	noticeErr := s.opts.Mailer.SendReviewDecision(ctx, ReviewEmail{
		UserID:     request.UserID,
		Recipient:  email,
		Decision:   decisionText,
		Reason:     maskText(request.Reason),
		OccurredAt: now,
		SupportURL: s.opts.SupportURL,
		AppName:    s.opts.AppName,
		RequestID:  request.RequestID,
	})
	if noticeErr != nil {
		result.Notified = false
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.recordReviewNotify(ctx, request.UserID, NotifyFailed, result.ErrorCode)
		return result, nil
	}
	result.Notified = true
	s.recordReviewNotify(ctx, request.UserID, NotifySent, "")
	return result, nil
}

// authorizeManagement 校验管理访问：注入强认证授权器优先；未注入时仅受信系统/本地管理员。
func (s *Service) authorizeManagement(ctx context.Context, caller Caller) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if s.opts.ManagementAuth != nil {
		return s.opts.ManagementAuth.AuthorizeManagement(ctx, caller)
	}
	if caller.actor.Type == audit.ActorSystem || caller.actor.Type == audit.ActorLocalAdmin {
		return nil
	}
	return ErrManagementAuthRequired
}

// recordReviewNotify 记录审核通知结果；失败只写运行日志。
func (s *Service) recordReviewNotify(ctx context.Context, userID string, state NotifyState, code string) {
	if err := s.opts.Store.MarkReviewNotify(context.WithoutCancel(ctx), userID, state, code, s.now()); err != nil {
		s.opts.Logger.Warn("记录审核通知状态失败", "user_id", userID)
	}
}

// authorizeReviewScope 在基础管理强认证之上校验审核范围：优先使用带应用/角色参数
// 的 ScopedManagementAuthorizer；未实现扩展时普通用户不得通过审核授予 system
// 作用域角色（防止绕过角色/应用范围的强认证限制）。
func (s *Service) authorizeReviewScope(ctx context.Context, caller Caller, approve bool, appID string, roles []Role) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if scoped, ok := s.opts.ManagementAuth.(ScopedManagementAuthorizer); ok {
		return scoped.AuthorizeManagementScope(ctx, caller, appID, roles)
	}
	if err := s.authorizeManagement(ctx, caller); err != nil {
		return err
	}
	if approve && caller.actor.Type == audit.ActorUser && appID == "" && len(roles) > 0 {
		return fmt.Errorf("%w: 未配置范围管理授权时不能授予系统作用域角色", ErrAccessDenied)
	}
	return nil
}
