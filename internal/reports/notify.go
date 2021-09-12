package reports

// 本文件实现报告生成结果通知的受控契约（步骤 79）：生成完成/失败/取消时，宿主
// 注入的 Notifier 可向报告所有者发送“仅带受认证页面入口”的通知。通知只是附属
// 结果：发送失败/未配置不改变报告真实状态，也不把通知失败写成生成失败。
//
// 安全不变量：
//   - 通知只包含报告编号、状态、格式与受认证页面路由名；不包含短期下载令牌、
//     产物宿主路径、原始审计内容或敏感明细。
//   - 接收人由宿主按计划/报告所有者解析，并自行确认已验证渠道与当前权限；本包
//     不保存或猜测邮箱地址。
//   - 通知失败只记录告警；报告终态、历史与产物在下发通知前已经提交，不会被回滚。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 报告通知结果类别。
const (
	// NotificationFinished 表示报告已成功生成（可下载入口仍需登录与再次鉴权）。
	NotificationFinished = "finished"
	// NotificationFailed 表示报告生成失败（含超时/失权），通知不替代页面状态。
	NotificationFailed = "failed"
	// NotificationCancelled 表示报告确实被取消（取消请求不等于实际取消）。
	NotificationCancelled = "cancelled"
)

// ReportNotification 是发送给宿主的报告结果通知（只含受控字段）。
type ReportNotification struct {
	Kind       string
	ReportID   string
	PlanID     string
	Name       string
	ScopeID    string
	State      string
	ErrorCode  string
	Formats    []Format
	Owner      audit.Actor
	CreatedAt  time.Time
	FinishedAt time.Time
	ExpiresAt  time.Time
	// AuthenticatedEntry 是宿主必须提供的“需要登录且每次重新授权”的页面路由名；
	// 通知正文只能是该入口加报告编号，不能是短期令牌或公开链接。
	AuthenticatedEntry string
	// Note 是可展示给接收者的短说明（不含秘密）。
	Note string
}

// Notifier 是宿主注入的报告结果通知契约。实现必须按所有者解析已验证渠道并
// 自行做权限/隐私检查；发送失败必须返回错误，但调用方只记录告警、不回滚报告。
type Notifier interface {
	NotifyReport(ctx context.Context, notification ReportNotification) error
}

// notifyReportResult 在报告终态提交后尽力发送通知；失败只告警，不改变报告状态。
func (s *Service) notifyReportResult(ctx context.Context, reportID string) {
	if isNil(s.opts.Notifier) {
		return
	}
	record, found := s.get(reportID)
	if !found {
		return
	}
	kind := ""
	switch record.State {
	case StateSucceeded:
		kind = NotificationFinished
	case StateFailed:
		kind = NotificationFailed
	case StateCancelled:
		kind = NotificationCancelled
	default:
		return
	}
	note := "报告已完成，可在管理页面登录后重新验证并下载。"
	if kind == NotificationFailed {
		note = "报告生成失败，请查看任务详情与错误说明；历史状态以服务端为准。"
	}
	if kind == NotificationCancelled {
		note = "报告已取消，不会生成可下载产物。"
	}
	notification := ReportNotification{
		Kind: kind, ReportID: record.ID, PlanID: record.PlanID, Name: record.Name,
		ScopeID: record.ScopeID, State: record.State, ErrorCode: record.ErrorCode,
		Formats: append([]Format(nil), record.Formats...), Owner: record.RequestedBy,
		CreatedAt: record.CreatedAt, FinishedAt: record.FinishedAt,
		ExpiresAt:          record.ExpiresAt,
		AuthenticatedEntry: "admin.report_download", Note: note,
	}
	if err := s.opts.Notifier.NotifyReport(ctx, notification); err != nil {
		s.opts.Logger.Warn("报告结果通知发送失败",
			"report_id", reportID, "kind", kind, "reason", "notify_failed")
	}
}

// validateNotifierOptions 拒绝 typed-nil 通知实现，避免调用时 panic。
func validateNotifierOptions(notifier Notifier) error {
	if notifier != nil && isNil(notifier) {
		return fmt.Errorf("%w: 通知依赖为 typed-nil", ErrOptionsInvalid)
	}
	return nil
}
