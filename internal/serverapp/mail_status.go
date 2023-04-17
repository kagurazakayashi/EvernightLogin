package serverapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// mailNotificationService 是步骤 139 的通知状态聚合实现。
//
// 只读、脱敏：不返回 SMTP 主机/账号/密码/完整发件地址/收件人/正文。真实
// 投递模式下本地捕获测试一律拒绝（不会真实外发）。
type mailNotificationService struct {
	runtime  *MailRuntime
	delivery *mailer.DeliveryService
}

// newMailNotificationService 构造通知状态服务；runtime 可为 nil（未装配）。
func newMailNotificationService(runtime *MailRuntime, taskRuntime *TaskRuntime) *mailNotificationService {
	service := &mailNotificationService{runtime: runtime}
	if taskRuntime != nil {
		service.delivery = taskRuntime.mailer
	}
	return service
}

// NotificationStatus 实现 adminapi.NotificationService。
func (s *mailNotificationService) NotificationStatus(ctx context.Context, _ account.Caller) (adminapi.NotificationStatus, error) {
	status := adminapi.NotificationStatus{
		Enabled:      false,
		LocalCapture: false,
		Channels:     []string{"email"},
		DeliveryMode: "disabled",
		Note:         "生产邮件发送未启用：邮件能力以明确错误拒绝，不访问网络",
	}
	if s.runtime == nil || !s.runtime.Enabled {
		return status, nil
	}
	status.Enabled = true
	status.DeliveryMode = "smtp"
	status.TLSMode = s.runtime.TLSMode
	status.FromDomain = mailDomain(s.runtime.From.Spec)
	status.AppName = s.runtime.AppDisplayName()
	status.LocalCapture = s.runtime.TLSMode == "none"
	status.Note = "生产邮件发送已启用（TLS 不降级；发送成功仅代表服务器已接受）"
	if s.delivery != nil {
		deliveryStatus, err := s.delivery.Status(ctx)
		if err != nil {
			return adminapi.NotificationStatus{}, fmt.Errorf("读取投递状态失败: %w", err)
		}
		if deliveryStatus.Known {
			counts := make(map[string]int, len(deliveryStatus.Counts))
			for state, count := range deliveryStatus.Counts {
				counts[string(state)] = count
			}
			status.DeliveryCounts = counts
		}
		status.LastErrorCodes = append([]string(nil), deliveryStatus.RecentErrorCodes...)
	}
	return status, nil
}

// TestNotification 只允许本地捕获器模式；139 不提供真实外发测试入口。
func (s *mailNotificationService) TestNotification(context.Context, account.Caller, string) (adminapi.NotificationTestResult, error) {
	if s.runtime == nil || !s.runtime.Enabled || s.runtime.TLSMode != "none" {
		return adminapi.NotificationTestResult{}, errors.New("真实邮件投递模式禁止执行通知测试（不会真实外发）")
	}
	return adminapi.NotificationTestResult{}, errors.New("本地邮件捕获器尚未装配，通知测试被禁用")
}
