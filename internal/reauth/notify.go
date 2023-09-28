package reauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// notifyOutcome 实现安全告知：只向已验证邮箱发送；无邮箱/未配置/失败/限频记录状态
// 与原因，不改变业务结果。成功告知按策略 NotificationRequired，失败高风险告知按
// 敏感操作触发并受频次限制。
//
// 步骤 210：走可靠投递队列时，告知主记录保存稳定业务去重键与投递记录标识；读取
// 通知时投影投递记录当前状态，区分排队/投递中/发送后端已接受/失败/取消。入队成功
// 只代表“已受理”，不代表用户已读或最终送达；通知失败永远不回滚已成功业务。
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
	// 步骤 197/210：可靠队列优先。enqueue 成功只记 queued（已受理，不是已送达）；
	// 真实送达/失败由 mailer 投递记录与 mail_delivery 任务终态体现。
	if s.opts.Deliveries != nil {
		return s.notifyViaQueue(ctx, result, outcome, address, notice)
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

// notifyViaQueue 把安全告知写入可靠投递队列，并按“主记录 → 入队 → 关联回写”
// 的可恢复顺序执行：
//
//  1. 先幂等写告知主记录（state=queued，尚无 delivery_id）。主记录写失败时**不**
//     入队，避免产生无法按用户查询、无法追溯的“孤儿邮件”；
//  2. 用稳定业务去重键作为邮件入队幂等键调用 mailer.Enqueue；重试/重启/重复回调
//     命中同一投递记录（不会产生第二封邮件）；
//  3. 回写 delivery_id。回写失败时投递仍在可靠队列中，主记录保留 queued+去重键：
//     读取路径可凭去重键回看投递终态，同一业务事件的重试会再次幂等命中同一投递并
//     补写关联，因此不丢结果、也不把“已入队”夸成成功。
//
// 任一阶段失败都不回滚已完成的业务操作，只记录告知状态与稳定原因。
func (s *Service) notifyViaQueue(ctx context.Context, result Result, outcome Outcome,
	address string, notice *mailer.SecurityNoticeData) error {
	dedupKey := securityNoticeKey(result, outcome)
	intent := NotificationRecord{
		UserID: result.UserID, OperationID: result.OperationID,
		TargetType: result.TargetType, TargetID: result.TargetID,
		Outcome: outcome, State: NotificationQueued,
		RecipientMasked: maskAddress(address), CreatedAt: s.now(),
		DedupKey: dedupKey,
	}
	if err := s.upsertNotification(ctx, &intent); err != nil {
		return err
	}
	caller, callerErr := mailer.SystemCaller("reauth")
	if callerErr != nil {
		failed := intent
		s.markNotificationFailed(ctx, &failed, "delivery_enqueue_failed")
		return fmt.Errorf("%w: %s", ErrNotificationFailed, "delivery_enqueue_failed")
	}
	enqueued, enqueueErr := s.opts.Deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller: caller, IdempotencyKey: dedupKey,
		Kind: mailer.KindSecurityNotice, Recipient: address,
		Data:      mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: notice},
		RequestID: result.RequestID,
	})
	if enqueueErr != nil {
		// 入队失败不回滚已完成的业务操作；主记录收敛为 failed + 稳定原因，重试可再看。
		failed := intent
		s.markNotificationFailed(ctx, &failed, "delivery_enqueue_failed")
		return fmt.Errorf("%w: %w", ErrNotificationFailed, enqueueErr)
	}
	linked := intent
	linked.DeliveryID = enqueued.Record.ID
	if err := s.upsertNotification(ctx, &linked); err != nil {
		// 邮件已在可靠队列中；主记录保留 queued + 去重键，读取时按幂等键回看投递终态。
		s.opts.Logger.Warn("安全告知投递关联回写失败（告知已入可靠队列，可按去重键回看终态）",
			"error", err, "delivery_id", enqueued.Record.ID)
		s.auditNotification(ctx, result, outcome, linked, "delivery_link_failed", audit.OutcomeFailure)
		return err
	}
	s.auditNotification(ctx, result, outcome, linked, "", audit.OutcomeSuccess)
	return nil
}

// markNotificationFailed 把告知主记录收敛为 failed 并写审计；回写失败只记日志，
// 不掩盖原始失败原因、也不改变业务结果。
func (s *Service) markNotificationFailed(ctx context.Context, record *NotificationRecord,
	reasonCode string) {
	record.State = NotificationFailed
	record.ErrorCode = reasonCode
	record.ReasonCode = reasonCode
	if err := s.upsertNotification(ctx, record); err != nil {
		s.opts.Logger.Warn("安全告知失败状态回写失败", "error", err)
	}
	s.auditNotification(ctx, Result{UserID: record.UserID, OperationID: record.OperationID,
		TargetType: record.TargetType, TargetID: record.TargetID}, record.Outcome,
		*record, "", audit.OutcomeFailure)
}

// recordNotification 持久化一次性告知结果并写审计（审计失败只记录日志，不改变告知状态）。
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
		UserID: result.UserID, OperationID: result.OperationID,
		TargetType: result.TargetType, TargetID: result.TargetID,
		Outcome: outcome, State: state, ErrorCode: errorCode,
		ReasonCode: safeReason(reason), CreatedAt: s.now(),
	}
	if (state == NotificationSent || state == NotificationQueued) && record.ReasonCode != "" {
		record.ReasonCode = ""
	}
	// 收件地址只保存脱敏值；通知状态本身不含邮箱明文。
	if state == NotificationSent || state == NotificationQueued || state == NotificationFailed {
		if address, found, err := s.opts.Store.VerifiedEmail(ctx, result.UserID); err == nil && found {
			record.RecipientMasked = maskAddress(address)
		}
	}
	if err := s.upsertNotification(ctx, &record); err != nil {
		return err
	}
	auditOutcome := audit.OutcomeSuccess
	if state != NotificationSent && state != NotificationQueued {
		auditOutcome = audit.OutcomeFailure
	}
	s.auditNotification(ctx, result, outcome, record, "", auditOutcome)
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

// upsertNotification 生成主记录 ID（如缺失）并幂等写入告知主记录。
// 失败统一映射为 ErrStoreUnavailable；调用方决定是否继续业务（本领域从不回滚业务）。
func (s *Service) upsertNotification(ctx context.Context, record *NotificationRecord) error {
	if record.ID == "" {
		notificationID, idErr := newDatabaseID(s.opts.Random, "ntf_")
		if idErr != nil {
			return idErr
		}
		record.ID = notificationID
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = s.now()
	}
	if err := s.opts.Store.UpsertNotification(ctx, *record); err != nil {
		return fmt.Errorf("%w: 记录告知状态失败: %v", ErrStoreUnavailable, err)
	}
	return nil
}

// auditNotification 写安全审计；审计失败只记录日志，不改变告知状态/业务结果。
// reasonOverride 非空时用于标记回写/关联失败，且不让它覆盖主记录本身的稳定原因。
func (s *Service) auditNotification(ctx context.Context, result Result, outcome Outcome,
	record NotificationRecord, reasonOverride string, auditOutcome audit.Outcome) {
	reasonCode := record.ReasonCode
	if reasonOverride != "" {
		reasonCode = reasonOverride
	}
	changes := []audit.FieldChange{
		{Field: "operation_id", After: safeValue(result.OperationID)},
		{Field: "outcome", After: string(outcome)},
		{Field: "state", After: string(record.State)},
	}
	if record.DeliveryID != "" {
		changes = append(changes, audit.FieldChange{Field: "delivery_id", After: record.DeliveryID})
	}
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "reauth.notifier"},
		Action:  "security.notice",
		Target:  audit.Target{Type: "user", ID: record.UserID},
		Outcome: auditOutcome, ErrorCode: record.ErrorCode,
		ReasonCode: reasonCode,
		Changes:    changes,
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
}

// truncateText 按码点截断事件名，避免模板内联字段超限。
func truncateText(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes])
}

// securityNoticeKey 构造稳定业务去重键：同一业务事件（同一用户、操作实例、目标、
// 结果）的重试/服务重启/重复回调得到同一键；不同用户、不同操作、不同目标、不同
// 结果得到不同键。键同时作为邮件入队幂等键（8～128 字节约束内），因此同一事件
// 不会产生第二封邮件，也不会串到别的用户或另一封邮件。
//
// 业务实例标识优先使用一次性批准 ID（approval 路径天然唯一）；direct 路径没有
// 独立实例 ID，使用本次执行的 RequestID。两者都缺失时退化为用户/操作/目标/结果
// 摘要（同一操作类型可能合并，属明确的降级边界，调用方应始终提供 RequestID）。
func securityNoticeKey(result Result, outcome Outcome) string {
	instance := strings.TrimSpace(result.ApprovalID)
	if instance == "" {
		instance = strings.TrimSpace(result.RequestID)
	}
	fingerprint := strings.Join([]string{
		result.UserID, result.OperationID, result.TargetType, result.TargetID,
		string(outcome), instance,
	}, "|")
	sum := sha256.Sum256([]byte(fingerprint))
	return "security-notice-" + hex.EncodeToString(sum[:16])
}
