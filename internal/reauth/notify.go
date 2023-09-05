package reauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// notifyOutcome 实现安全告知：只向已验证邮箱发送；无邮箱/未配置/失败/限频记录状态
// 与原因，不改变业务结果。成功告知按策略 NotificationRequired，失败高风险告知按
// 敏感操作触发并受频次限制。
func (s *Service) notifyOutcome(ctx context.Context, result Result, outcome Outcome) error {
	if result.UserID == "" {
		// 没有可告知的用户主体（例如系统级操作）：不发送也不写告知记录（无收件主体），
		// 不当作失败；此行为与 NotificationSuppressed 状态区分，后者未在本路径使用。
		return nil
	}
	decision := result.Decision
	if outcome == OutcomeSuccess {
		if !decision.NotificationRequired {
			return nil
		}
	} else {
		// 失败高风险告知只对敏感操作触发，并受窗口内频次限制，避免邮件轰炸。
		if !decision.Sensitive {
			return nil
		}
		key := result.UserID + "|" + result.OperationID
		if !s.failureLimiter.allow(key, s.now()) {
			return s.recordNotification(ctx, result, outcome, NotificationRateLimited,
				"failure_notice_rate_limited", nil)
		}
	}
	if s.opts.Deliveries == nil && (isNil(s.opts.Mailer) || s.opts.FromAddress == "") {
		return s.recordNotification(ctx, result, outcome, NotificationNotConfigured,
			"mailer_not_configured", ErrNotificationFailed)
	}
	address, found, err := s.opts.Store.VerifiedEmail(ctx, result.UserID)
	if err != nil {
		return s.recordNotification(ctx, result, outcome, NotificationFailed,
			"verified_email_lookup_failed", ErrStoreUnavailable)
	}
	if !found || address == "" {
		// 未验证邮箱不是可靠安全渠道：记录原因，不把通知当成功。
		return s.recordNotification(ctx, result, outcome, NotificationNoVerifiedEmail,
			"no_verified_email", ErrNotificationFailed)
	}
	username, _, err := s.opts.Store.Username(ctx, result.UserID)
	if err != nil {
		return s.recordNotification(ctx, result, outcome, NotificationFailed,
			"username_lookup_failed", ErrStoreUnavailable)
	}
	event := result.Description
	if event == "" {
		event = result.OperationID
	}
	if outcome == OutcomeFailure {
		event = "敏感操作失败：" + event
	}
	event = truncateText(event, 120)
	notice := &mailer.SecurityNoticeData{
		DisplayName: username,
		Event:       event,
		OccurredAt:  s.now().UTC().Format(time.RFC3339),
		ClientInfo:  "身份服务敏感操作审核",
		AppName:     s.opts.AppName,
		SupportURL:  s.opts.SupportURL,
	}
	// 步骤 197：可靠队列优先。enqueue 成功只记 queued（已受理，不是已送达）；
	// 真实送达/失败由 mailer 投递记录与 mail_delivery 任务终态体现。
	if s.opts.Deliveries != nil {
		caller, callerErr := mailer.SystemCaller("reauth")
		if callerErr != nil {
			return s.recordNotification(ctx, result, outcome, NotificationFailed,
				"delivery_enqueue_failed", ErrNotificationFailed, "delivery_enqueue_failed")
		}
		if _, enqueueErr := s.opts.Deliveries.Enqueue(ctx, mailer.EnqueueRequest{
			Caller: caller, IdempotencyKey: securityNoticeKey(result, outcome),
			Kind: mailer.KindSecurityNotice, Recipient: address,
			Data:      mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: notice},
			RequestID: result.RequestID,
		}); enqueueErr != nil {
			// 入队失败不回滚已完成的业务操作，只记录失败状态与稳定原因。
			return s.recordNotification(ctx, result, outcome, NotificationFailed,
				"delivery_enqueue_failed", fmt.Errorf("%w: %w", ErrNotificationFailed, enqueueErr),
				"delivery_enqueue_failed")
		}
		return s.recordNotification(ctx, result, outcome, NotificationQueued, "", nil)
	}
	content, renderErr := s.opts.Templates.Render(mailer.RenderRequest{
		Kind: mailer.KindSecurityNotice, Notice: notice,
	})
	if renderErr != nil {
		return s.recordNotification(ctx, result, outcome, NotificationFailed,
			"notice_render_failed", ErrNotificationFailed)
	}
	from, fromErr := mailer.ParseAddress(s.opts.FromAddress)
	to, toErr := mailer.ParseAddress(address)
	if fromErr != nil || toErr != nil {
		return s.recordNotification(ctx, result, outcome, NotificationFailed,
			"address_invalid", ErrNotificationFailed)
	}
	message := mailer.Message{
		From: from, To: []mailer.Address{to},
		Subject: content.Subject, TextBody: content.TextBody,
	}
	sendErr := s.opts.Mailer.Send(ctx, message)
	if sendErr != nil {
		errorCode := "delivery_failed"
		var sendFailure *mailer.SendError
		if errors.As(sendErr, &sendFailure) && sendFailure.Code != "" {
			errorCode = sendFailure.Code
		}
		// 投递失败不回滚已完成的业务操作，只记录状态与稳定错误码。
		return s.recordNotification(ctx, result, outcome, NotificationFailed,
			"delivery_failed", fmt.Errorf("%w: %w", ErrNotificationFailed, sendErr), errorCode)
	}
	return s.recordNotification(ctx, result, outcome, NotificationSent, "", nil)
}

// recordNotification 持久化告知结果并写审计（审计失败只记录日志，不改变告知状态）。
func (s *Service) recordNotification(ctx context.Context, result Result, outcome Outcome,
	state NotificationState, reason string, failure error, extraCode ...string) error {
	errorCode := ""
	if failure != nil {
		errorCode = string(CodeOf(mapCriticalError(failure)))
	}
	if len(extraCode) > 0 && extraCode[0] != "" {
		errorCode = extraCode[0]
	}
	record := NotificationRecord{
		ID: "", UserID: result.UserID, OperationID: result.OperationID,
		TargetType: result.TargetType, TargetID: result.TargetID,
		Outcome: outcome, State: state, ErrorCode: errorCode,
		ReasonCode: safeReason(reason), CreatedAt: s.now(),
	}
	if (state == NotificationSent || state == NotificationQueued) && record.ReasonCode != "" {
		record.ReasonCode = ""
	}
	notificationID, idErr := newDatabaseID(s.opts.Random, "ntf_")
	if idErr != nil {
		return idErr
	}
	record.ID = notificationID
	// 收件地址只保存脱敏值；通知状态本身不含邮箱明文。
	if state == NotificationSent || state == NotificationQueued || state == NotificationFailed {
		if address, found, err := s.opts.Store.VerifiedEmail(ctx, result.UserID); err == nil && found {
			record.RecipientMasked = maskAddress(address)
		}
	}
	if err := s.opts.Store.InsertNotification(ctx, record); err != nil {
		return fmt.Errorf("%w: 记录告知状态失败: %v", ErrStoreUnavailable, err)
	}
	auditOutcome := audit.OutcomeSuccess
	if state != NotificationSent && state != NotificationQueued {
		auditOutcome = audit.OutcomeFailure
	}
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "reauth.notifier"},
		Action:  "security.notice",
		Target:  audit.Target{Type: "user", ID: result.UserID},
		Outcome: auditOutcome, ErrorCode: errorCode,
		ReasonCode: record.ReasonCode,
		Changes: []audit.FieldChange{
			{Field: "operation_id", After: safeValue(result.OperationID)},
			{Field: "outcome", After: string(outcome)},
			{Field: "state", After: string(state)},
		},
	}
	var auditErr error
	if auditOutcome == audit.OutcomeSuccess {
		auditErr = s.opts.Audit.Record(ctx, event)
	} else {
		auditErr = s.opts.Audit.RecordFailure(ctx, event)
	}
	if auditErr != nil {
		s.opts.Logger.Warn("安全告知审计写入失败", "error", auditErr)
	}
	switch state {
	case NotificationSent, NotificationQueued:
		return nil
	case NotificationNoVerifiedEmail:
		return fmt.Errorf("%w: %s", ErrNotificationFailed, "无已验证邮箱")
	case NotificationNotConfigured:
		return fmt.Errorf("%w: %s", ErrNotificationFailed, "未配置发送器")
	case NotificationRateLimited:
		return fmt.Errorf("%w: %s", ErrNotificationFailed, "告知频次受限")
	default:
		if failure != nil {
			return failure
		}
		return ErrNotificationFailed
	}
}

// truncateText 按码点截断事件名，避免模板内联字段超限。
func truncateText(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes])
}

// securityNoticeKey 构造队列幂等键：优先用请求编号绑定业务实例；请求编号缺失时
// 用用户/操作/目标摘要；最终长度裁剪到 mailer 允许的 8～128 字节。
func securityNoticeKey(result Result, outcome Outcome) string {
	key := "security-notice-" + result.RequestID + "-" + string(outcome)
	if len(result.RequestID) == 0 || len(key) < 8 {
		sum := sha256.Sum256([]byte(result.UserID + "|" + result.OperationID + "|" + result.TargetID))
		key = "security-notice-" + hex.EncodeToString(sum[:8]) + "-" + string(outcome)
	}
	if len(key) > 128 {
		sum := sha256.Sum256([]byte(key))
		key = "security-notice-" + hex.EncodeToString(sum[:16])
	}
	return key
}
