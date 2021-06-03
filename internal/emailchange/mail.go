package emailchange

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// EmailSender 是验证邮件与旧邮箱安全告知的发送契约。
type EmailSender interface {
	SendVerification(ctx context.Context, message VerificationEmail) error
	SendSecurityNotice(ctx context.Context, message SecurityNoticeEmail) error
}

// VerificationEmail 是发送到新邮箱的验证入口（含一次性链接，只用于邮件正文）。
type VerificationEmail struct {
	RequestID       string
	Recipient       string
	VerificationURL string
	ExpiresIn       string
	AppName         string
	RequestIDLog    string
}

// SecurityNoticeEmail 是发送到旧已验证邮箱的安全告知；不含令牌或校验链接。
type SecurityNoticeEmail struct {
	RequestID  string
	Recipient  string
	Event      string
	OccurredAt string
	AppName    string
	SupportURL string
}

// DeliveryEnqueuer 是 internal/mailer.DeliveryService 的可注入子集。
type DeliveryEnqueuer interface {
	Enqueue(ctx context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error)
}

// DeliveryEmailSender 基于 internal/mailer 可靠投递发送验证与告知邮件。
type DeliveryEmailSender struct {
	deliveries DeliveryEnqueuer
	appName    string
}

// NewDeliveryEmailSender 构造投递适配器。
func NewDeliveryEmailSender(deliveries DeliveryEnqueuer, appName string) (*DeliveryEmailSender, error) {
	if deliveries == nil {
		return nil, fmt.Errorf("%w: 邮件投递服务为空", ErrOptionsInvalid)
	}
	if strings.TrimSpace(appName) == "" || len([]rune(appName)) > 100 {
		return nil, fmt.Errorf("%w: 邮件服务名称无效", ErrOptionsInvalid)
	}
	return &DeliveryEmailSender{deliveries: deliveries, appName: appName}, nil
}

// SendVerification 幂等入队新地址验证邮件。
func (s *DeliveryEmailSender) SendVerification(ctx context.Context, message VerificationEmail) error {
	caller, err := mailer.SystemCaller("emailchange")
	if err != nil {
		return fmt.Errorf("%w: 无法构造投递身份", ErrOptionsInvalid)
	}
	appName := message.AppName
	if strings.TrimSpace(appName) == "" {
		appName = s.appName
	}
	_, err = s.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: "email-change-verify-" + message.RequestID,
		Kind:           mailer.KindVerification,
		Recipient:      message.Recipient,
		Data: mailer.RenderRequest{Kind: mailer.KindVerification, Verification: &mailer.VerificationData{
			DisplayName: "用户", VerifyURL: message.VerificationURL,
			ExpiresIn: message.ExpiresIn, AppName: appName,
		}},
		RequestID: message.RequestIDLog,
	})
	if err != nil {
		return fmt.Errorf("%w: 无法入队验证邮件", ErrMailUnavailable)
	}
	return nil
}

// SendSecurityNotice 幂等入队旧邮箱安全告知（不含令牌/链接）。
func (s *DeliveryEmailSender) SendSecurityNotice(ctx context.Context, message SecurityNoticeEmail) error {
	caller, err := mailer.SystemCaller("emailchange")
	if err != nil {
		return fmt.Errorf("%w: 无法构造投递身份", ErrOptionsInvalid)
	}
	appName := message.AppName
	if strings.TrimSpace(appName) == "" {
		appName = s.appName
	}
	_, err = s.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: "email-change-notice-" + message.RequestID,
		Kind:           mailer.KindSecurityNotice,
		Recipient:      message.Recipient,
		Data: mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: &mailer.SecurityNoticeData{
			DisplayName: "用户", Event: message.Event, OccurredAt: message.OccurredAt,
			ClientInfo: "邮箱变更流程", AppName: appName, SupportURL: message.SupportURL,
		}},
	})
	if err != nil {
		return fmt.Errorf("%w: 无法入队安全告知", ErrMailUnavailable)
	}
	return nil
}
