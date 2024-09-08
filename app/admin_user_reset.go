package app

// 步骤 257：直接重置他人密码的公开 Go 门面。
//
// 与找回密码（邮件链接）、ManualRecovery 人工审批、本人改密是不同路径：持有独立权限
// users.password.reset.other 的操作者凭“本次操作绑定的两步验证证明”直接设置目标新密码，
// 不需要目标旧密码、目标确认或另一个管理员审批。本门面固定执行：
//  1. 真实用户管理会话（AdminSession；LocalAdmin 无用户两步因素拒绝）+ authz 内核判定
//     系统范围独立权限；操作者不能是目标本人（本人改密走 Passwords.ChangeOwnPassword）。
//  2. 目标校验与密码策略/历史/哈希准备（internal/authn.PrepareAdminReset）：目标必须
//     存在、active、非 root、**已有密码凭证**（无密码账户拒绝，不把重置权限扩成添加密码）；
//     弱密码/历史复用/哈希资源失败发生在写事务之前，不消费证明、不修改数据。
//  3. 两步验证证明（步骤 255 契约）：证明绑定操作者、会话、操作、目标 UserID 与本次
//     **新口令的不可逆密封意图**（服务端 AES-GCM 保存，不落明文/不做无密钥摘要）；换目标/
//     换新口令/换会话/重放均拒绝。
//  4. 一致提交（同一审计事务）：证明消费（含 tx 内会话/账户/权限终检）+ 写入新密码、
//     历史、must_change=true、security_version+1 + 作废 pending 找回入口并撤销其凭证 +
//     OAuth 撤销 outbox + 关键审计 admin.direct_password_reset；任一步失败整体回滚
//     （证明不烧毁，可重新准备后重试；成功后重放不再二次执行）。
//  5. 提交后 best-effort：撤销目标活动会话（安全版本已保证旧会话/旧刷新凭证失效）、向
//     目标已验证邮箱入队“发生密码重置”的告知；失败不回滚已成功重置，也不宣称已送达。
//  6. 受保护目标：root 目标拒绝（root 密码只走本人流程/本地应急）；root 作为操作者按
//     252 权限内核语义执行成功（不绕过 authz、不跳过证明）。
//
// 频率限制（进程内 5 次/分，操作者+目标）仅作防滥用辅助，不是授权依据；多实例不共享。
// 成功只返回脱敏结果，不回显新密码或哈希；本文件不签发会话、不解除 MFA/Passkey。

import (
	"context"
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

const (
	// directPasswordResetPermissionKey 是直接重置他人密码的独立权限键（步骤 254 注册表）。
	directPasswordResetPermissionKey = "users.password.reset.other"
	// directPasswordResetLimit 是进程内防滥用窗口上限（非授权依据）。
	directPasswordResetLimit = 5
	// directPasswordResetWindow 是防滥用窗口。
	directPasswordResetWindow = time.Minute
)

// AdminResetUserPasswordRequest 是直接重置他人密码的请求。
type AdminResetUserPasswordRequest struct {
	// Caller 必须是真实用户管理会话（AdminSession）；LocalAdmin 拒绝。
	Caller AdminCaller
	// TargetUserID 是被管理目标用户稳定 ID（不能是操作者本人，也不能是 root）。
	TargetUserID string
	// NewPassword 是操作者提交的新口令；只用于策略/哈希与 255 密封意图，不落明文。
	NewPassword string
	// Reason 是本次直接管理理由（写入关键审计；长度受限、去控制字符）。
	Reason string
	// ProofToken 是步骤 255 目标绑定操作证明（一次性、短时有效，绑定本次新口令意图）。
	ProofToken string
	// RequestID 用于关联调用、领域审计与稳定错误；空值统一生成。
	RequestID string
}

// AdminPasswordResetResult 是直接重置密码的脱敏结果（不含密码/哈希/种子）。
type AdminPasswordResetResult struct {
	UserID            string
	SecurityVersion   int64
	PasswordChangedAt time.Time
	// MustChange 恒为 true：目标下次登录进入受限改密流程。
	MustChange bool
	// SessionsRevoked 是提交后 best-effort 撤销的活动会话数量（安全版本已保证失效）。
	SessionsRevoked int64
	// OldResetRequestsCancelled/OldResetCredentialsRevoked 是同一事务内旧找回入口失效结果。
	OldResetRequestsCancelled  int64
	OldResetCredentialsRevoked int64
	OutboxEventID              string
}

// DirectPasswordManagementService 是管理员直接重置他人密码的公开门面。
type DirectPasswordManagementService interface {
	// ResetUserPassword 凭独立权限 + 本次两步验证证明直接设置目标新密码。
	ResetUserPassword(ctx context.Context,
		request AdminResetUserPasswordRequest) (AdminPasswordResetResult, error)
}

// DirectPasswordManagement 返回直接重置口令门面；依赖未装配时调用返回明确配置错误。
func (r *Runtime) DirectPasswordManagement() DirectPasswordManagementService {
	return &directPasswordManagementFacade{r: r}
}

type directPasswordManagementFacade struct{ r *Runtime }

// directPasswordResetRateLimiter 是进程级共享防滥用窗口（非授权依据，多实例不共享）。
var directPasswordResetRateLimiter = newDirectRenameLimiter(
	directPasswordResetLimit, directPasswordResetWindow)

// directResetErrorCode 把 authn 直接重置错误投影为既有公开错误码；其他领域错误回退到
// 步骤 256 的证明/资料映射。必须按错误归属判定（两个 CodeOf 对未知错误都会回退
// INTERNAL_ERROR）。
func directResetErrorCode(err error) string {
	authnSentinels := []error{
		authn.ErrOptionsInvalid, authn.ErrInvalidRequest, authn.ErrWeakPassword,
		authn.ErrPasswordReused, authn.ErrUserNotFound, authn.ErrAccessDenied,
		authn.ErrRecoveryStateConflict, authn.ErrStoreUnavailable,
		authn.ErrNotInitialized, authn.ErrSetupStateConflict,
	}
	for _, sentinel := range authnSentinels {
		if errors.Is(err, sentinel) {
			return string(authn.CodeOf(err))
		}
	}
	return directManagementErrorCode(err)
}

// ResetUserPassword 实现直接重置他人密码（详见类型与文件头安全链路）。
func (f *directPasswordManagementFacade) ResetUserPassword(ctx context.Context,
	request AdminResetUserPasswordRequest) (AdminPasswordResetResult, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return AdminPasswordResetResult{}, err
	}
	services := r.coreServices()
	managed := r.managedServices()
	gate := r.securityGate()
	if services == nil || services.Authn == nil || managed == nil || managed.Checker == nil {
		return AdminPasswordResetResult{}, configError("直接重置密码依赖未装配", requestID)
	}
	if gate == nil || gate.Reauth == nil {
		return AdminPasswordResetResult{}, configError("敏感操作闸门未装配", requestID)
	}
	effects, effectsErr := serverapp.NewDirectPasswordResetEffects(r.base)
	if effectsErr != nil {
		return AdminPasswordResetResult{}, configError("直接重置附带效果未装配", requestID)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return AdminPasswordResetResult{}, mapDomainError("目标用户标识无效",
			string(login.CodeReqInvalid), requestID)
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > authn.MaxPasswordBytes {
		return AdminPasswordResetResult{}, mapDomainError("新口令长度无效",
			string(login.CodeReqInvalid), requestID)
	}
	reason := sanitizeDirectReason(request.Reason)
	if reason == "" {
		return AdminPasswordResetResult{}, mapDomainError("直接管理操作必须填写理由",
			string(login.CodeReqInvalid), requestID)
	}
	if len(request.ProofToken) == 0 {
		return AdminPasswordResetResult{}, mapDomainError("缺少本次操作的两步验证证明",
			string(login.CodeTokenInvalid), requestID)
	}
	operatorID, sessionID, identityErr :=
		(&directUserManagementFacade{r: r}).directManagementIdentity(ctx,
			request.Caller, requestID)
	if identityErr != nil {
		return AdminPasswordResetResult{}, identityErr
	}
	if request.TargetUserID == operatorID {
		return AdminPasswordResetResult{}, mapDomainError("本人改密请使用本人受控改密流程",
			string(login.CodeReqInvalid), requestID)
	}
	if !directPasswordResetRateLimiter.allow(operatorID+"|"+request.TargetUserID,
		r.runtimeNow()) {
		return AdminPasswordResetResult{}, mapDomainError("直接重置口令请求过于频繁",
			string(login.CodeRateLimited), requestID)
	}
	// 授权：真实 authz 内核判定系统范围独立权限。
	authzCaller, callerErr := authz.UserCaller(operatorID)
	if callerErr != nil {
		return AdminPasswordResetResult{}, configError("构造授权调用者失败", requestID)
	}
	decision, checkErr := managed.Checker.Check(ctx, authzCaller, authz.CheckRequest{
		SubjectUserID: operatorID, ScopeID: "system",
		Permissions: []string{directPasswordResetPermissionKey}, Mode: authz.ModeAll,
	})
	if checkErr != nil {
		return AdminPasswordResetResult{}, mapDomainError("权限判定不可用",
			"AUTHZ_UNAVAILABLE", requestID)
	}
	if !decision.Allowed {
		return AdminPasswordResetResult{}, mapDomainError("未授予直接重置他人密码的权限",
			string(login.CodeAccessDenied), requestID)
	}
	// 领域准备：目标状态/root/无密码拒绝 + 密码策略/历史复用 + Argon2 哈希（事务外）。
	preparedReset, prepareResetErr := services.Authn.PrepareAdminReset(ctx,
		authn.AdminResetRequest{TargetUserID: request.TargetUserID,
			NewPassword: request.NewPassword, RequestID: requestID, Reason: reason})
	if prepareResetErr != nil {
		if errors.Is(prepareResetErr, authn.ErrUserNotFound) {
			if replaced, ok := notFoundWhen(prepareResetErr, authn.ErrUserNotFound,
				"user", requestID); ok {
				return AdminPasswordResetResult{}, replaced
			}
		}
		return AdminPasswordResetResult{}, mapDomainError("直接重置口令校验失败",
			directResetErrorCode(prepareResetErr), requestID)
	}
	// 证明核对：绑定目标与本次新口令密封意图（换目标/换口令/换会话/重放拒绝）。
	reauthCaller, reauthErr := reauth.UserCaller(operatorID)
	if reauthErr != nil {
		return AdminPasswordResetResult{}, configError("构造再次认证调用者失败", requestID)
	}
	preparedProof, prepareProofErr := gate.Reauth.PrepareProof(ctx, reauthCaller,
		reauth.ConsumeProofRequest{
			ProofToken: request.ProofToken, ScopeID: "system",
			OperationID: policy.OperationDirectPasswordReset, TargetType: "user",
			TargetID:  request.TargetUserID,
			SessionID: sessionID,
			Intent: &reauth.Intent{Kind: reauth.IntentPassword,
				Password: request.NewPassword},
			RequestID: requestID,
		})
	if prepareProofErr != nil {
		return AdminPasswordResetResult{}, mapDomainError(
			"直接重置口令两步验证证明无效或已失效",
			directManagementErrorCode(prepareProofErr), requestID)
	}
	// 关键提交：证明消费 + 密码/历史/安全版本 + 旧找回失效 + OAuth 撤销 outbox + 审计。
	var applied authn.AdminResetResult
	var invalidation serverapp.DirectResetLinkInvalidation
	var approvalID string
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: operatorID},
			Action:    "admin.direct_password_reset",
			Target:    audit.Target{Type: "user", ID: request.TargetUserID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "reason", After: reason},
				{Field: "must_change", After: "true"},
				{Field: "security_version_change", After: "password_direct_admin_reset"},
				{Field: "permission", After: directPasswordResetPermissionKey},
				{Field: "target_user_id", After: request.TargetUserID},
			},
		},
		FailureReasonCode: "admin.direct_password_reset_failed",
		FailureErrorCodeFor: func(err error) string {
			return directResetErrorCode(err)
		},
	}
	err = r.base.Audit.ExecuteCritical(ctx, critical,
		func(txCtx context.Context, tx audit.Tx) error {
			consumed, consumeErr := gate.Reauth.ConsumePreparedProofTx(txCtx, tx,
				reauthCaller, preparedProof)
			if consumeErr != nil {
				return consumeErr
			}
			approvalID = consumed.ApprovalID
			resetResult, resetErr := services.Authn.ApplyAdminResetTx(txCtx, tx,
				preparedReset)
			if resetErr != nil {
				return resetErr
			}
			applied = resetResult
			invalidated, invalidateErr := effects.InvalidatePriorResetLinksTx(txCtx, tx,
				request.TargetUserID, requestID)
			if invalidateErr != nil {
				return invalidateErr
			}
			invalidation = invalidated
			return nil
		})
	if err != nil {
		return AdminPasswordResetResult{}, mapDomainError("直接重置口令失败",
			directResetErrorCode(err), requestID)
	}
	// 提交后 best-effort：撤销活动会话（安全版本已保证旧凭证失效，失败不回滚）。
	sessionsRevoked := int64(0)
	if revoked, revokeErr := effects.RevokeSessionsAfterCommit(ctx,
		request.TargetUserID); revokeErr != nil {
		r.logger.Warn("直接重置口令后会話撤销失败（安全版本已使旧会话失效）",
			"error", revokeErr)
	} else {
		sessionsRevoked = revoked
	}
	// 提交后 best-effort：安全告知（只告知发生重置；失败不回滚、不宣称送达）。
	f.notifyDirectPasswordReset(ctx, requestID, approvalID, request.TargetUserID)
	return AdminPasswordResetResult{
		UserID: applied.UserID, SecurityVersion: applied.SecurityVersion,
		PasswordChangedAt: applied.PasswordChangedAt, MustChange: applied.MustChange,
		SessionsRevoked:            sessionsRevoked,
		OldResetRequestsCancelled:  invalidation.CancelledRequests,
		OldResetCredentialsRevoked: invalidation.RevokedCredentials,
		OutboxEventID:              invalidation.OutboxEventID,
	}, nil
}

// notifyDirectPasswordReset 入队“发生密码重置”的安全告知（去重键由证明批准 ID 派生）；
// 失败只记录可诊断日志/失败审计，不影响已成功业务。
func (f *directPasswordManagementFacade) notifyDirectPasswordReset(ctx context.Context,
	requestID, approvalID, targetUserID string) {
	r := f.r
	notifier, err := serverapp.NewDirectManagementNotifier(r.base.Deps)
	if err != nil || notifier == nil {
		r.logger.Warn("直接重置口令安全告知未装配", "error", err)
		return
	}
	dedupKey := "admin-direct-password-reset:" + approvalID
	receipt, notifyErr := notifier.Notify(ctx, serverapp.DirectManagementNotice{
		TargetUserID: targetUserID, OperationLabel: "管理员重置了你的登录口令",
		OccurredAt: r.runtimeNow(), DedupKey: dedupKey, RequestID: requestID,
	})
	if notifyErr != nil {
		r.logger.Warn("直接重置口令安全告知未完成",
			"state", receipt.State, "error", notifyErr)
		if auditErr := r.base.Audit.RecordFailure(ctx, audit.Event{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "direct-user-management"},
			Action:  "admin.direct_password_reset_notify_failed",
			Target:  audit.Target{Type: "user", ID: targetUserID},
			Outcome: audit.OutcomeFailure, ErrorCode: "MAIL_DELIVERY_FAILED",
			RequestID: requestID,
			Changes:   []audit.FieldChange{{Field: "state", After: receipt.State}},
		}); auditErr != nil {
			r.logger.Warn("直接重置口令告知失败审计写入失败", "error", auditErr)
		}
		return
	}
	r.logger.Info("直接重置口令安全告知已入可靠投递队列",
		"delivery_id", receipt.DeliveryID, "duplicate", receipt.Duplicate)
}

var _ DirectPasswordManagementService = (*directPasswordManagementFacade)(nil)
