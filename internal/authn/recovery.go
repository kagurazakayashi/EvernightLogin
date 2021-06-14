package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// ActionPasswordRecoveryReset 是“经一次性找回凭证验证后重置密码”的审计动作。
const ActionPasswordRecoveryReset Action = "password.recovery_reset"

// RecoveryResetRequest 是邮件找回流程在原子消费一次性凭证后调用密码重置的请求。
//
// 安全边界：本方法不经过 SensitiveRunner（凭证消费本身就是授权证明），因此只能由
// 受信内部服务在完成凭证验证后调用；调用者必须是 system 角色。它仍执行密码策略、
// 历史复用检查、安全版本递增与审计，且不修改 MFA/Passkey 等其他认证因素。
type RecoveryResetRequest struct {
	// UserID 是目标普通账户稳定 ID；root 拒绝。
	UserID string
	// NewPassword 是新明文密码；只用于本次处理，不保存、不记录。
	NewPassword string
	// RequestID 可选，写入审计用于关联。
	RequestID string
	// Reason 是受限原因类别（例如 password_reset），写入审计变更字段。
	Reason string
}

// ResetPasswordForRecovery 在找回凭证已验证并原子消费后重置密码：
//   - 只允许 system 调用者；普通用户/管理员走 SetPassword 的完整敏感策略路径。
//   - 账户必须存在、active、非 root 且已有密码凭证；无密码账户拒绝，不允许找回
//     流程自动添加密码。
//   - 仍使用密码策略与历史复用检查；安全版本在存储事务内递增，旧会话因版本不匹配
//     失效；MFA 等其他因素不被清除。
//   - 不发送安全告知（由找回服务在事务外发送，且不含密码/凭证）。
func (s *Service) ResetPasswordForRecovery(ctx context.Context, caller Caller,
	request RecoveryResetRequest) (SetPasswordResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SetPasswordResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return SetPasswordResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.UserID) {
		return SetPasswordResult{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > MaxPasswordBytes {
		return SetPasswordResult{}, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	if err := caller.actor.Validate(); err != nil {
		return SetPasswordResult{}, ErrAccessDenied
	}
	if caller.actorKind() != audit.ActorSystem {
		return SetPasswordResult{}, fmt.Errorf("%w: 找回重置只允许受信系统组件", ErrAccessDenied)
	}
	user, found, err := s.store.FindUserByID(ctx, request.UserID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "查询找回目标账户", err)
	}
	if !found {
		return SetPasswordResult{}, ErrUserNotFound
	}
	if user.IsRoot {
		return SetPasswordResult{}, fmt.Errorf("%w: root 密码只能通过本地受控初始化流程重置", ErrAccessDenied)
	}
	if user.Status != account.StatusActive {
		return SetPasswordResult{}, fmt.Errorf("%w: 账户当前不可用", ErrAccessDenied)
	}
	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "读取找回目标密码凭证", err)
	}
	if !credentialFound {
		// 无密码账户不得被找回流程自动添加密码；需要额外的受控授权流程。
		return SetPasswordResult{}, fmt.Errorf("%w: 账户未设置密码，找回流程不能自动添加密码", ErrAccessDenied)
	}
	if err := s.checkPasswordPolicy(request.NewPassword, user); err != nil {
		return SetPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionPasswordRecoveryReset,
			user.UserID, reasonWeakPassword, CodeOf(err), err)
	}
	if err := s.checkPasswordReuse(ctx, user.UserID, credential, request.NewPassword); err != nil {
		if contextFailure(err) {
			return SetPasswordResult{}, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return SetPasswordResult{}, s.passwordWorkFailure(ctx, caller,
				ActionPasswordRecoveryReset, user.UserID, err)
		}
		return SetPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionPasswordRecoveryReset,
			user.UserID, reasonPasswordReused, CodeOf(err), err)
	}
	newHash, err := s.hashPassword(ctx, request.NewPassword)
	if err != nil {
		if contextFailure(err) {
			return SetPasswordResult{}, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return SetPasswordResult{}, s.passwordWorkFailure(ctx, caller,
				ActionPasswordRecoveryReset, user.UserID, err)
		}
		return SetPasswordResult{}, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	now := s.clockNow()
	event := audit.Event{
		Actor: caller.actor, Action: string(ActionPasswordRecoveryReset),
		Target: audit.Target{Type: "user", ID: user.UserID}, Outcome: audit.OutcomeSuccess,
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "security_version_change", After: "password_recovery_reset"},
			{Field: "reason", After: safeRecoveryReason(request.Reason)},
			{Field: "argon2_params", After: s.params.String()},
			{Field: "history_limit", After: strconv.Itoa(s.policy.HistoryLimit)},
		},
	}
	critical := audit.CriticalRequest{
		Event: event, FailureReasonCode: "password_recovery_reset_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var changeResult PasswordChangeResult
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		result, setErr := s.store.SetPassword(txCtx, tx, PasswordChange{
			UserID: user.UserID, PasswordHash: newHash, MustChange: false,
			HistoryLimit: s.policy.HistoryLimit, Now: now,
		})
		if setErr != nil {
			return setErr
		}
		changeResult = result
		return nil
	})
	if err != nil {
		return SetPasswordResult{}, mapCriticalError(err)
	}
	s.logger.Info("密码已通过找回流程重置", "user_id", user.UserID,
		"security_version", changeResult.SecurityVersion)
	return SetPasswordResult{
		UserID: user.UserID, SecurityVersion: changeResult.SecurityVersion,
		PasswordChangedAt: changeResult.ChangedAt, HistoryLimit: s.policy.HistoryLimit,
	}, nil
}

// safeRecoveryReason 把原因类别限制为短的安全 ASCII 标识，避免审计注入。
func safeRecoveryReason(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "password_reset"
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '-' {
			continue
		}
		return "password_reset"
	}
	return value
}
