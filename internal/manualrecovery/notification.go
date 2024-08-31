// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package manualrecovery

// 人工恢复通知的可靠投递关联（步骤 265）。
//
// 背景与边界：
//   - 步骤 197 让人工恢复通知可以走 mailer 可靠投递队列，但通知器丢弃了 Enqueue 的
//     返回值：申请/执行结果只记录 queued/sent/failed，无法在受权读取时回看“排队、
//     发送后端已接受、失败、取消”的实际投递状态，也无法证明重复触发不会产生第二封。
//   - 步骤 265 复用 reauth 安全告知（步骤 210）的“稳定业务去重键 + 投递关联 + 读取时
//     投影”机制，但不改持久化结构：去重键由申请编号与通知类别确定性生成，既作为邮件
//     入队幂等键，也让读取路径只要拿到申请就能反查同一条投递记录。因此“关联”不是一次
//     可能失败的写入，回写失败问题自然消失；通知状态写入失败时仍可按去重键回看终态。
//   - 通知状态与恢复结果严格分离：通知失败只记录通知状态/审计，不回滚已完成的恢复，
//     也绝不把失败的执行标记为成功、或把成功的执行改记为失败。
//   - 入队成功只代表“已受理/排队”，mailer.DeliverySucceeded 只代表发送后端已接受，
//     都不能夸大为用户已读或最终送达收件箱。

import (
	"context"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// 人工恢复通知状态（持久化在 manual_recovery_executions.notification_state）。
const (
	// NotificationStatePending 表示执行已结束但尚未尝试发送通知。
	NotificationStatePending = "pending"
	// NotificationStateQueued 表示通知已进入可靠投递队列（已受理，不代表已送达）。
	NotificationStateQueued = "queued"
	// NotificationStateSent 表示直接发送路径已确认交给发送后端（队列路径不写该状态）。
	NotificationStateSent = "sent"
	// NotificationStateFailed 表示通知发送/入队失败（不影响恢复结果的业务终态）。
	NotificationStateFailed = "failed"
	// NotificationStateNotConfigured 表示未装配通知器，未尝试发送。
	NotificationStateNotConfigured = "not_configured"
)

// NotificationReceipt 是回执式通知器返回的投递关联（步骤 265）。
//
// State 使用本文件的 NotificationState* 常量；DeliveryID/DedupKey 在走可靠队列时非空，
// Duplicate 表示入队幂等命中既有投递（本次没有创建第二封邮件）。直接发送路径没有投递
// 记录，DeliveryID 为空、State=sent。
type NotificationReceipt struct {
	State      string
	DeliveryID string
	DedupKey   string
	Duplicate  bool
}

// ReceiptNotifier 是能返回投递关联回执的通知器扩展契约。Service 优先使用它；未实现时
// 退回 Notifier 并按 NotificationsQueued 语义记录状态（兼容既有宿主与测试实现）。
type ReceiptNotifier interface {
	NotifyWithReceipt(ctx context.Context, notification Notification) (NotificationReceipt, error)
}

// NotificationDeliveryView 是“通知业务状态 + 实际投递状态”的可受权只读投影（步骤 265）。
//
// State 是人工恢复领域记录的通知状态（pending/queued/sent/failed/not_configured），
// 只代表业务侧的尝试结果；Matched/Delivery* 是从 mailer 投递记录按稳定业务去重键
// 投影出来的当前实际状态，随投递重试/重启恢复变化，不是本领域数据库快照。
//   - Matched=false 表示当前没有关联到投递记录（直接发送、未配置、入队前失败或历史
//     记录），不能当作已送达。
//   - DeliveryState 的 queued/sending 表示仍在队列/发送中；succeeded 只表示发送后端
//     已接受；failed/cancelled 表示终态失败/取消。
//   - Duplicate=true 表示最近一次通知尝试命中业务去重键（没有新建第二封邮件）。
type NotificationDeliveryView struct {
	Kind              NotificationKind
	State             string
	ErrorCode         string
	DedupKey          string
	Duplicate         bool
	DeliveryID        string
	Matched           bool
	DeliveryState     mailer.DeliveryState
	DeliveryErrorCode string
	DeliveryTaskID    string
	DeliveryUpdatedAt time.Time
}

// notificationDedupPrefix 是人工恢复通知去重键前缀（与 mailer 幂等键长度约束一致）。
const notificationDedupPrefix = "manual-recovery-"

// maxNotificationDedupKeyBytes 是去重键上限（mailer 幂等键 8～128 字节）。
const maxNotificationDedupKeyBytes = 128

// NotificationDedupKey 生成稳定业务去重键（步骤 265）：同一申请 + 同一通知类别的
// 重试/服务重启/重复回调得到同一键；不同申请或完成/失败通知得到不同键。它同时作为
// 邮件入队幂等键，因此同一业务事件不会产生第二封邮件，读取路径也能据此反查投递记录。
func NotificationDedupKey(requestID string, kind NotificationKind) string {
	return notificationDedupPrefix + strings.TrimSpace(requestID) + "-" + string(kind)
}

// ValidNotificationDedupKey 报告去重键是否满足 mailer 幂等键约束（8～128 字节）。
func ValidNotificationDedupKey(key string) bool {
	return len(key) >= 8 && len(key) <= maxNotificationDedupKeyBytes
}

// notificationKindForExecutionStatus 把执行终态映射为通知类别；未终结（running）时
// 没有对应通知。
func notificationKindForExecutionStatus(status string) (NotificationKind, bool) {
	switch status {
	case "succeeded":
		return NotificationCompleted, true
	case "failed":
		return NotificationFailed, true
	}
	return "", false
}

// withDelivery 把投递记录字段填入视图；调用方负责保证去重键已设置。
func (view NotificationDeliveryView) withDelivery(record mailer.Record) NotificationDeliveryView {
	view.Matched = true
	view.DeliveryID = record.ID
	view.DeliveryState = record.State
	view.DeliveryErrorCode = record.LastErrorCode
	view.DeliveryTaskID = record.TaskID
	view.DeliveryUpdatedAt = record.UpdatedAt
	if view.DedupKey == "" {
		view.DedupKey = record.IdempotencyKey
	}
	return view
}

// projectNotificationDelivery 按申请编号 + 通知类别构造去重键，并从投递记录投影当前
// 实际状态。Deliveries 未装配或查询失败时只返回业务通知状态（不报错、不改变结果），
// 避免读取路径因投递存储故障而失败。
func (s *Service) projectNotificationDelivery(ctx context.Context,
	execution ExecutionRecord) NotificationDeliveryView {
	view := NotificationDeliveryView{State: execution.NotificationState}
	kind, ok := notificationKindForExecutionStatus(execution.Status)
	if !ok || execution.RequestID == "" {
		return view
	}
	view.Kind = kind
	view.DedupKey = NotificationDedupKey(execution.RequestID, kind)
	return s.projectDeliveryInto(ctx, view)
}

// projectDeliveryInto 在视图已有去重键时补投递记录投影。Deliveries 未装配、去重键
// 无效或查询失败时保持业务状态、不报错。
func (s *Service) projectDeliveryInto(ctx context.Context,
	view NotificationDeliveryView) NotificationDeliveryView {
	if s.opts.Deliveries == nil || !ValidNotificationDedupKey(view.DedupKey) {
		return view
	}
	record, found, err := s.opts.Deliveries.LookupDeliveryByIdempotencyKey(ctx, view.DedupKey)
	if err != nil {
		s.logger.Warn("人工恢复通知投递状态投影失败（只保留业务通知状态）",
			"error_category", "delivery_lookup_failed")
		return view
	}
	if !found {
		return view
	}
	return view.withDelivery(record)
}

// deliverExecutionNotification 发送一次执行结果通知并返回“回执 + 当前投递投影”。
//
// 契约：
//   - 通知失败只记录通知状态与失败审计，返回 State=failed；绝不回滚业务结果。
//   - 回执式通知器优先；否则退回 Notifier，并按 NotificationsQueued 决定 queued/sent。
//   - 通知状态写入使用 SetNotificationState（独立事务、不改变执行/申请状态）；写入
//     失败只记日志——读取路径仍可按稳定去重键回看投递终态。
func (s *Service) deliverExecutionNotification(ctx context.Context, record RequestRecord,
	kind NotificationKind) NotificationDeliveryView {
	view := NotificationDeliveryView{Kind: kind, State: NotificationStateNotConfigured,
		DedupKey: NotificationDedupKey(record.ID, kind)}
	if isNilInterface(s.opts.Notifier) {
		return view
	}
	notification := Notification{
		Kind: kind, RequestID: record.ID,
		TargetUserID: record.TargetUserID, Operation: record.Operation, OccurredAt: s.clockNow(),
	}
	var receipt NotificationReceipt
	var notifyErr error
	if receiptNotifier, ok := s.opts.Notifier.(ReceiptNotifier); ok {
		receipt, notifyErr = receiptNotifier.NotifyWithReceipt(ctx, notification)
	} else {
		notifyErr = s.opts.Notifier.Notify(ctx, notification)
		if notifyErr == nil {
			receipt.State = NotificationStateSent
			if s.opts.NotificationsQueued {
				receipt.State = NotificationStateQueued
			}
		}
	}
	if notifyErr != nil {
		s.logger.Warn("人工恢复通知发送失败", "request_id", record.ID, "kind", string(kind))
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "manual-recovery-service"},
			ActionNotification, "manual_recovery_request", record.ID,
			"notification_failed", string(CodeMailDeliveryFailed), "")
		s.persistNotificationState(ctx, record.ID, NotificationStateFailed)
		view.State = NotificationStateFailed
		view.ErrorCode = "notification_failed"
		return s.projectDeliveryInto(ctx, view)
	}
	if receipt.State == "" {
		// 回执式通知器未声明状态时按“已入队受理”处理，不能当成 sent。
		receipt.State = NotificationStateQueued
	}
	view.State = receipt.State
	if receipt.DedupKey != "" && ValidNotificationDedupKey(receipt.DedupKey) {
		view.DedupKey = receipt.DedupKey
	}
	view.DeliveryID = receipt.DeliveryID
	view.Duplicate = receipt.Duplicate
	view = s.projectDeliveryInto(ctx, view)
	s.persistNotificationState(ctx, record.ID, view.State)
	s.auditNotification(ctx, record, view, audit.OutcomeSuccess)
	return view
}

// persistNotificationState 记录通知状态（独立事务）；失败只记日志，不影响业务结果，
// 读取路径仍可按去重键回看投递终态。
func (s *Service) persistNotificationState(ctx context.Context, requestID, state string) {
	if state == "" {
		return
	}
	if err := s.opts.Store.SetNotificationState(ctx, requestID, state); err != nil {
		s.logger.Warn("人工恢复通知状态写入失败（可按业务去重键回看投递终态）",
			"request_id", requestID, "state", state)
	}
}

// auditNotification 记录通知结果审计（含投递关联，不含收件地址/正文/链接）。审计失败
// 只记日志，不改变通知状态或业务结果。
func (s *Service) auditNotification(ctx context.Context, record RequestRecord,
	view NotificationDeliveryView, outcome audit.Outcome) {
	changes := []audit.FieldChange{
		{Field: "notification_state", After: view.State},
		{Field: "notification_kind", After: string(view.Kind)},
		{Field: "dedup_key", After: view.DedupKey},
	}
	if view.DeliveryID != "" {
		changes = append(changes, audit.FieldChange{Field: "delivery_id", After: view.DeliveryID})
	}
	if view.Matched {
		changes = append(changes, audit.FieldChange{Field: "delivery_state", After: string(view.DeliveryState)})
	}
	if view.Duplicate {
		changes = append(changes, audit.FieldChange{Field: "delivery_duplicate", After: "true"})
	}
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "manual-recovery-service"},
		Action:  ActionNotification,
		Target:  audit.Target{Type: "manual_recovery_request", ID: record.ID},
		Outcome: outcome,
		Changes: changes,
	}
	var err error
	if outcome == audit.OutcomeSuccess {
		err = s.opts.Audit.Record(ctx, event)
	} else {
		err = s.opts.Audit.RecordFailure(ctx, event)
	}
	if err != nil {
		s.logger.Warn("人工恢复通知审计写入失败", "request_id", record.ID)
	}
}
