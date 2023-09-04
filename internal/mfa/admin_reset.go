// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mfa

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AdminResetRequest 是受控管理员重置 MFA 因素的请求；只能由已通过独立审批与真实
// 管理强认证的宿主执行器调用，不暴露给普通用户或未审批的 HTTP/CLI 入口。
type AdminResetRequest struct {
	TargetUserID string
	Reason       string
	RequestID    string
}

// AdminResetResult 是管理员重置结果摘要（不含秘密/验证码/恢复链接）。
type AdminResetResult struct {
	EmailFactorsRemoved    int
	TOTPFactorsRemoved     int
	PasskeyCredentialsGone int
	RecoveryGroupsRevoked  int
	SecurityVersion        int64
}

// AdminFactorResetBackend 由宿主安全域实现：在 mfa 审计事务内完成 TOTP/Passkey/
// 恢复代码/安全版本处理；mfa 本身只负责邮件因素与统一审计/边界校验。
type AdminFactorResetBackend interface {
	// CheckAdminResetTarget 再次校验目标仍为可恢复普通账户（非 root/高权限/禁用），
	// 防止批准后目标状态变化。
	CheckAdminResetTarget(ctx context.Context, targetUserID string) error
	// ResetTOTP 在事务内停用目标 TOTP 因素，返回受影响行数。
	ResetTOTP(ctx context.Context, tx audit.Tx, targetUserID string, now time.Time) (int, error)
	// RevokePasskeys 在事务内撤销目标 Passkey 凭证，返回受影响行数。
	RevokePasskeys(ctx context.Context, tx audit.Tx, targetUserID, reason string, now time.Time) (int, error)
	// RevokeRecoveryGroups 在事务内作废目标活动恢复代码组，返回受影响组数。
	RevokeRecoveryGroups(ctx context.Context, tx audit.Tx, targetUserID string, now time.Time) (int, error)
	// IncrementSecurityVersion 在事务内递增目标安全版本，使既有会话失效。
	IncrementSecurityVersion(ctx context.Context, tx audit.Tx, targetUserID string, now time.Time) (int64, error)
}

// AdminResetFactors 是步骤 152 的最小受控 MFA 重置 API：仅接受 system 调用者
// （由人工恢复执行器在独立审批/等待期/强认证之后构造），先校验目标保护，再在同一
// 审计事务中移除邮件因素、停用 TOTP、撤销 Passkey/恢复代码并递增安全版本。
//
// 安全边界：不接受普通用户 caller；不在本方法内撤销会话（由执行器通过真实会话服务
// 完成并记录数量）；任何依赖失败整体回滚，不伪造部分成功；返回结果不含秘密。
func (s *Service) AdminResetFactors(ctx context.Context, caller Caller,
	request AdminResetRequest) (AdminResetResult, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || caller.actor.Type != audit.ActorSystem {
		return AdminResetResult{}, ErrAccessDenied
	}
	if isNil(s.opts.AdminResetBackend) {
		return AdminResetResult{}, fmt.Errorf("%w: 未装配 MFA 管理员重置后端", ErrOptionsInvalid)
	}
	if s.opts.AdminResetTargetGuard == nil {
		return AdminResetResult{}, fmt.Errorf("%w: 未装配 MFA 管理员重置目标保护", ErrOptionsInvalid)
	}
	target := strings.TrimSpace(request.TargetUserID)
	if !account.ValidUserID(target) {
		return AdminResetResult{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return AdminResetResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" || len(reason) > 200 {
		return AdminResetResult{}, fmt.Errorf("%w: 重置原因无效", ErrInvalidRequest)
	}
	if err := s.opts.AdminResetTargetGuard(ctx, target); err != nil {
		return AdminResetResult{}, err
	}
	now := s.now()
	result := AdminResetResult{}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "mfa.admin_reset",
			Target:    audit.Target{Type: "user", ID: target},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "reason", After: reason},
				{Field: "factor_scope", After: "email,totp,passkey,recovery"},
			},
		},
		FailureReasonCode:   "mfa.admin_reset_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if removed, removeErr := s.opts.Store.RemoveFactorTx(txCtx, tx, target, FactorEmail); removeErr != nil {
			return removeErr
		} else if removed {
			result.EmailFactorsRemoved = 1
		}
		removedTOTP, err := s.opts.AdminResetBackend.ResetTOTP(txCtx, tx, target, now)
		if err != nil {
			return err
		}
		result.TOTPFactorsRemoved = removedTOTP
		revokedPasskeys, err := s.opts.AdminResetBackend.RevokePasskeys(txCtx, tx, target, reason, now)
		if err != nil {
			return err
		}
		result.PasskeyCredentialsGone = revokedPasskeys
		revokedGroups, err := s.opts.AdminResetBackend.RevokeRecoveryGroups(txCtx, tx, target, now)
		if err != nil {
			return err
		}
		result.RecoveryGroupsRevoked = revokedGroups
		securityVersion, err := s.opts.AdminResetBackend.IncrementSecurityVersion(txCtx, tx, target, now)
		if err != nil {
			return err
		}
		result.SecurityVersion = securityVersion
		// 步骤 188：人工恢复重置 MFA 后在同一事务内登记“强制重新绑定强因素”，
		// 登录将只得到受限初始化会话，完成 Passkey 绑定后才清除。
		if marker, ok := s.opts.AdminResetBackend.(interface {
			MarkRebindRequiredTx(ctx context.Context, tx audit.Tx, userID, sourceRequestID string, now time.Time) error
		}); ok {
			if markErr := marker.MarkRebindRequiredTx(txCtx, tx, target, request.RequestID, now); markErr != nil {
				return markErr
			}
		}
		return nil
	})
	if err != nil {
		return AdminResetResult{}, mapCriticalError(err)
	}
	return result, nil
}
