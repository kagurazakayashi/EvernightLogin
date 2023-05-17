// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package serverapp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// manualRecoveryPolicyFromConfig 把根配置转换为领域制度；配置层已做边界校验，
// 服务构造会再次 Validate（双重 fail-closed）。RequireIndependentApproval 固定 true。
func manualRecoveryPolicyFromConfig(cfg login.ManualRecoveryConfig) manualrecovery.Policy {
	bases := make([]manualrecovery.VerificationBasis, 0, len(cfg.VerificationBases))
	for _, basis := range cfg.VerificationBases {
		bases = append(bases, manualrecovery.VerificationBasis(strings.TrimSpace(basis)))
	}
	deliveries := make([]manualrecovery.DeliveryChannel, 0, len(cfg.DeliveryChannels))
	for _, delivery := range cfg.DeliveryChannels {
		deliveries = append(deliveries, manualrecovery.DeliveryChannel(strings.TrimSpace(delivery)))
	}
	return manualrecovery.Policy{
		Enabled:                    cfg.Enabled,
		VerificationBases:          bases,
		DeliveryChannels:           deliveries,
		WaitPeriod:                 time.Duration(cfg.WaitPeriodSeconds) * time.Second,
		ApprovalTTL:                time.Duration(cfg.ApprovalTTLSeconds) * time.Second,
		RequestTTL:                 time.Duration(cfg.RequestTTLSeconds) * time.Second,
		RequireIndependentApproval: true,
	}
}

// manualRecoveryMFAAdminBackend 实现 mfa.AdminFactorResetBackend：在 mfa 的审计事务
// 内完成 TOTP/Passkey/恢复代码/安全版本处理，并在重置前复核目标保护。
type manualRecoveryMFAAdminBackend struct {
	store   *storagesqlite.Store
	targets manualRecoveryTargets
}

// CheckAdminResetTarget 实现 mfa.AdminFactorResetBackend。
func (b manualRecoveryMFAAdminBackend) CheckAdminResetTarget(ctx context.Context, targetUserID string) error {
	if b.store == nil {
		return errors.New("MFA 重置目标保护缺少存储")
	}
	target, err := b.targets.LoadTarget(ctx, targetUserID)
	if err != nil {
		return mfa.ErrAccessDenied
	}
	if !target.Active || target.IsRoot || target.HighPrivilege {
		return mfa.ErrAccessDenied
	}
	return nil
}

// ResetTOTP 实现 mfa.AdminFactorResetBackend：停用 active/pending 绑定。
func (b manualRecoveryMFAAdminBackend) ResetTOTP(ctx context.Context, tx audit.Tx,
	targetUserID string, now time.Time) (int, error) {
	result, err := tx.ExecContext(ctx,
		`UPDATE totp_bindings SET status='disabled',updated_at_ms=?
		 WHERE user_id=? AND status IN('active','pending')`,
		now.UTC().UnixMilli(), targetUserID)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

// RevokePasskeys 实现 mfa.AdminFactorResetBackend：撤销全部未撤销 Passkey 凭证。
func (b manualRecoveryMFAAdminBackend) RevokePasskeys(ctx context.Context, tx audit.Tx,
	targetUserID, reason string, now time.Time) (int, error) {
	result, err := tx.ExecContext(ctx,
		`UPDATE webauthn_credentials SET revoked_at_ms=?,revoked_reason=?,updated_at_ms=?
		 WHERE user_id=? AND revoked_at_ms IS NULL`,
		now.UTC().UnixMilli(), truncateReason(reason), now.UTC().UnixMilli(), targetUserID)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

// RevokeRecoveryGroups 实现 mfa.AdminFactorResetBackend：作废 active 恢复代码组。
func (b manualRecoveryMFAAdminBackend) RevokeRecoveryGroups(ctx context.Context, tx audit.Tx,
	targetUserID string, now time.Time) (int, error) {
	result, err := tx.ExecContext(ctx,
		`UPDATE recovery_code_groups SET status='revoked',invalidated_at_ms=?
		 WHERE user_id=? AND status='active'`,
		now.UTC().UnixMilli(), targetUserID)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

// IncrementSecurityVersion 实现 mfa.AdminFactorResetBackend。
func (b manualRecoveryMFAAdminBackend) IncrementSecurityVersion(ctx context.Context, tx audit.Tx,
	targetUserID string, now time.Time) (int64, error) {
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET security_version=security_version+1,updated_at_ms=? WHERE id=?`,
		now.UTC().UnixMilli(), targetUserID); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT security_version FROM users WHERE id=?`, targetUserID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return 0, errors.New("目标用户不存在")
	}
	var version int64
	if err := rows.Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

// truncateReason 截断数据库 revoked_reason 长度（不包含秘密）。
func truncateReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 200 {
		return reason[:200]
	}
	return reason
}

// manualRecoveryExecutor 是真实人工恢复执行器：密码恢复复用受信找回服务向已验证
// 邮箱交付；MFA 恢复调用受控 mfa.AdminResetFactors；两者最后都撤销全部目标会话。
type manualRecoveryExecutor struct {
	passwordReset *passwordreset.Service
	mfa           *mfa.Service
	sessions      *session.Service
	targets       manualRecoveryTargets
}

// Execute 实现 manualrecovery.Executor。
func (e manualRecoveryExecutor) Execute(ctx context.Context,
	command manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	if e.sessions == nil {
		return manualrecovery.ExecutionOutcome{}, errors.New("人工恢复执行器缺少会话服务")
	}
	if command.Operation == manualrecovery.OperationPasswordReset && e.passwordReset == nil {
		return manualrecovery.ExecutionOutcome{}, errors.New("密码恢复执行器缺少找回服务")
	}
	if command.Operation == manualrecovery.OperationMFAReset && e.mfa == nil {
		return manualrecovery.ExecutionOutcome{}, errors.New("MFA 恢复执行器缺少 MFA 服务")
	}
	target, err := e.targets.LoadTarget(ctx, command.TargetUserID)
	if err != nil {
		return manualrecovery.ExecutionOutcome{}, fmt.Errorf("目标账户不可用: %w", err)
	}
	if !target.Active || target.IsRoot || target.HighPrivilege {
		return manualrecovery.ExecutionOutcome{}, errors.New("目标账户受保护或不可恢复")
	}
	switch command.Operation {
	case manualrecovery.OperationPasswordReset:
		// 先确认真实投递可用并交付一次性入口；这一步失败时不能撤销会话造成锁定。
		result, deliverErr := e.passwordReset.SendResetForSupport(ctx,
			passwordreset.SupportResetRequest{TargetUserID: command.TargetUserID,
				RequestID: command.RequestTraceID})
		if deliverErr != nil {
			return manualrecovery.ExecutionOutcome{}, fmt.Errorf("密码找回交付失败: %w", deliverErr)
		}
		if !result.Delivered {
			return manualrecovery.ExecutionOutcome{}, errors.New("密码找回邮件未交付")
		}
		revoked, revokeErr := e.sessions.RevokeAllForUser(ctx, command.TargetUserID,
			"manual_recovery_password_reset")
		if revokeErr != nil {
			return manualrecovery.ExecutionOutcome{}, fmt.Errorf("撤销目标会话失败: %w", revokeErr)
		}
		return manualrecovery.ExecutionOutcome{
			Summary:         "一次性密码找回入口已交付到目标已验证邮箱；旧会话已撤销",
			SessionsRevoked: int(revoked), ResetCredentialIssued: true,
		}, nil
	case manualrecovery.OperationMFAReset:
		caller, callerErr := mfa.SystemCaller("manual-recovery-executor")
		if callerErr != nil {
			return manualrecovery.ExecutionOutcome{}, callerErr
		}
		_, resetErr := e.mfa.AdminResetFactors(ctx, caller, mfa.AdminResetRequest{
			TargetUserID: command.TargetUserID,
			Reason:       "人工核验恢复（独立审批执行）",
			RequestID:    command.RequestTraceID,
		})
		if resetErr != nil {
			return manualrecovery.ExecutionOutcome{}, fmt.Errorf("MFA 因素重置失败: %w", resetErr)
		}
		revoked, revokeErr := e.sessions.RevokeAllForUser(ctx, command.TargetUserID,
			"manual_recovery_mfa_reset")
		if revokeErr != nil {
			// 因素已重置但会话撤销失败：返回错误让服务记录失败/部分执行，不能假装成功。
			return manualrecovery.ExecutionOutcome{}, fmt.Errorf("MFA 已重置但撤销目标会话失败: %w", revokeErr)
		}
		return manualrecovery.ExecutionOutcome{
			Summary:         "MFA 因素/恢复代码已重置，Passkey 已撤销，目标会话已撤销；用户需重新登录并重绑",
			SessionsRevoked: int(revoked), FactorsReset: true,
		}, nil
	default:
		return manualrecovery.ExecutionOutcome{}, manualrecovery.ErrInvalidRequest
	}
}

// Compensate 实现 manualrecovery.Executor。本执行器的成功步骤是“交付入口/重置因素+
// 撤销会话”，不可安全回滚（不能恢复已撤销凭证或已投递邮件）；返回 nil 表示不产生
// 伪造成功，只由服务把最终审计失败记录为 failed/补偿不可用。
func (e manualRecoveryExecutor) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	return nil
}

// manualRecoveryNotifier 通过真实邮件发送器向目标既有已验证邮箱发送完成/失败告知。
type manualRecoveryNotifier struct {
	sender  mailer.Sender
	store   *storagesqlite.Store
	from    mailer.Address
	appName string
}

// Notify 实现 manualrecovery.Notifier；不含链接、密码、验证码或秘密。
func (n manualRecoveryNotifier) Notify(ctx context.Context, notification manualrecovery.Notification) error {
	if n.sender == nil || n.store == nil {
		return errors.New("人工恢复通知邮件发送器未装配")
	}
	var email string
	if err := n.store.DB().QueryRowContext(ctx,
		`SELECT email_normalized FROM user_emails
		 WHERE user_id=? AND verified_at_ms IS NOT NULL
		 ORDER BY updated_at_ms DESC LIMIT 1`, notification.TargetUserID).Scan(&email); err != nil {
		return errors.New("读取目标已验证邮箱失败")
	}
	if strings.TrimSpace(email) == "" {
		return errors.New("目标没有已验证邮箱")
	}
	subject := n.appName + " 人工恢复状态更新"
	body := "你的账户人工恢复申请已处理。若这不是你发起的请求，请立即联系管理员。"
	if notification.Kind == manualrecovery.NotificationFailed {
		subject = n.appName + " 人工恢复未完成"
		body = "你的账户人工恢复申请未完成；账户状态未被伪造为已恢复，请联系管理员。"
	}
	message := mailer.Message{From: n.from,
		To: []mailer.Address{{Spec: email}}, Subject: subject, TextBody: body}
	return n.sender.Send(ctx, message)
}

// 编译期确认适配器满足领域契约。
var (
	_ mfa.AdminFactorResetBackend = manualRecoveryMFAAdminBackend{}
	_ manualrecovery.Executor     = manualRecoveryExecutor{}
	_ manualrecovery.Notifier     = manualRecoveryNotifier{}
)
