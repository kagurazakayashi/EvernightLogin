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
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// manualRecoveryRebindMethods 把人工恢复制度配置的“允许重绑因素类别”解析为领域
// 方法列表（步骤 209）。passkey 只有真正启用 Passkey 时才可用；totp 作为显式的
// 非抗钓鱼类别，仅在配置明确列出时提供。列表为空表示没有可用重绑方式，申请/执行
// mfa_reset 必须 fail-closed 拒绝，避免“恢复后无法重绑”把账户锁死。
func manualRecoveryRebindMethods(cfg login.ManualRecoveryConfig,
	passkeyEnabled bool) ([]authfact.Method, error) {
	methods := make([]authfact.Method, 0, len(cfg.RebindMethods))
	seen := make(map[authfact.Method]bool, len(cfg.RebindMethods))
	for _, raw := range cfg.RebindMethods {
		var method authfact.Method
		switch strings.TrimSpace(raw) {
		case "passkey":
			if !passkeyEnabled {
				continue
			}
			method = authfact.MethodPasskey
		case "totp":
			method = authfact.MethodTOTP
		default:
			return nil, fmt.Errorf("未知重绑方法类别 %q", raw)
		}
		if seen[method] {
			continue
		}
		seen[method] = true
		methods = append(methods, method)
	}
	return methods, nil
}

// rebindMethodSummary 返回可展示/审计的重绑方法类别摘要（不含秘密）。
func rebindMethodSummary(methods []authfact.Method) string {
	if len(methods) == 0 {
		return "无"
	}
	parts := make([]string, 0, len(methods))
	for _, method := range methods {
		switch method {
		case authfact.MethodPasskey, authfact.MethodSecurityKey:
			parts = append(parts, "Passkey")
		case authfact.MethodTOTP:
			parts = append(parts, "TOTP")
		default:
			parts = append(parts, string(method))
		}
	}
	return strings.Join(parts, "/")
}

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
	// rebindMethods 是人工恢复 MFA 重置后受限初始化允许绑定的强因素类别（步骤
	// 209）：passkey（Passkey 启用时）与显式配置的 totp。空列表表示恢复后无法
	// 重新绑定，执行器 fail-closed 拒绝，避免把账户锁死。
	rebindMethods []authfact.Method
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
	if command.Operation == manualrecovery.OperationMFAReset && len(e.rebindMethods) == 0 {
		return manualrecovery.ExecutionOutcome{},
			errors.New("没有可用的强因素重绑方法：拒绝 MFA 恢复（避免恢复后无法重绑）")
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
			Summary: fmt.Sprintf(
				"MFA 因素/恢复代码已重置，旧 Passkey 已撤销，目标会话已撤销；用户需重新登录并在受限初始化中绑定新的强因素（%s）",
				rebindMethodSummary(e.rebindMethods)),
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

// manualRecoveryNotifier 通过可靠投递队列（步骤 197）或直接发送器向目标既有已验证
// 邮箱发送完成/失败告知；不含链接、密码、验证码或秘密。
type manualRecoveryNotifier struct {
	sender     mailer.Sender
	deliveries mailer.DeliveryEnqueuer
	store      *storagesqlite.Store
	from       mailer.Address
	appName    string
	supportURL string
}

// Notify 实现 manualrecovery.Notifier；不含链接、密码、验证码或秘密。
func (n manualRecoveryNotifier) Notify(ctx context.Context, notification manualrecovery.Notification) error {
	if n.store == nil || (n.deliveries == nil && n.sender == nil) {
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
	event := "人工恢复已完成"
	if notification.Kind == manualrecovery.NotificationFailed {
		subject = n.appName + " 人工恢复未完成"
		body = "你的账户人工恢复申请未完成；账户状态未被伪造为已恢复，请联系管理员。"
		event = "人工恢复未完成"
	}
	if n.deliveries != nil {
		caller, callerErr := mailer.SystemCaller("manual-recovery")
		if callerErr != nil {
			return errors.New("构造人工恢复通知投递身份失败")
		}
		key := "manual-recovery-" + notification.RequestID + "-" + string(notification.Kind)
		if len(key) < 8 {
			return errors.New("人工恢复通知幂等键无效")
		}
		if len(key) > 128 {
			return errors.New("人工恢复通知幂等键超长")
		}
		if _, enqueueErr := n.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
			Caller: caller, IdempotencyKey: key, Kind: mailer.KindSecurityNotice,
			Recipient: email,
			Data: mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: &mailer.SecurityNoticeData{
				Event: event, OccurredAt: notification.OccurredAt.UTC().Format(time.RFC3339),
				ClientInfo: "人工恢复", AppName: n.appName, SupportURL: n.supportURL,
			}},
			RequestID: notification.RequestID,
		}); enqueueErr != nil {
			return errors.New("人工恢复通知入队失败")
		}
		return nil
	}
	message := mailer.Message{From: n.from,
		To: []mailer.Address{{Spec: email}}, Subject: subject, TextBody: body}
	return n.sender.Send(ctx, message)
}

// MarkRebindRequiredTx 实现 mfa 管理员重置事务内的可选标记：MFA 恢复成功后登记
// 强制重新绑定需求（步骤 188）。写入与因素重置/安全版本递增同事务。
func (b manualRecoveryMFAAdminBackend) MarkRebindRequiredTx(ctx context.Context, tx audit.Tx,
	userID, sourceRequestID string, now time.Time) error {
	if tx == nil || b.store == nil {
		return errors.New("强制重绑写入缺少事务或存储")
	}
	if userID == "" || sourceRequestID == "" {
		return errors.New("强制重绑写入参数无效")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mfa_rebind_requirements(
user_id,required_at_ms,reason_code,source_request_id,cleared_at_ms)
VALUES(?,?,?,?,NULL)
ON CONFLICT(user_id) DO UPDATE SET required_at_ms=excluded.required_at_ms,
reason_code=excluded.reason_code,source_request_id=excluded.source_request_id,cleared_at_ms=NULL`,
		userID, now.UTC().UnixMilli(), "manual_recovery_mfa_reset", sourceRequestID)
	return err
}

// 编译期确认适配器满足领域契约。
var (
	_ mfa.AdminFactorResetBackend = manualRecoveryMFAAdminBackend{}
	_ manualrecovery.Executor     = manualRecoveryExecutor{}
	_ manualrecovery.Notifier     = manualRecoveryNotifier{}
)
