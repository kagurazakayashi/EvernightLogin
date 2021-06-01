package onboarding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// EmailSender 是邀请/审核通知的发送契约。生产实现基于 internal/mailer 可靠投递；
// 测试可用捕获替身。返回错误表示通知未交给发送方，不会回滚主事务。
type EmailSender interface {
	SendInvitation(ctx context.Context, message InvitationEmail) error
	SendReviewDecision(ctx context.Context, message ReviewEmail) error
}

// InvitationEmail 是邀请邮件渲染数据。AcceptanceURL 含一次性令牌，只用于邮件正文，
// 不得写入日志、审计或数据库。
type InvitationEmail struct {
	InvitationID  string
	Recipient     string
	DisplayName   string
	AcceptanceURL string
	ExpiresAt     time.Time
	ExpiresIn     string
	InviterName   string
	AppID         string
	AppName       string
	RequestID     string
}

// ReviewEmail 是注册审核结果通知数据（不含密码、令牌或邀请入口）。
type ReviewEmail struct {
	UserID     string
	Recipient  string
	Decision   string
	Reason     string
	OccurredAt time.Time
	SupportURL string
	AppName    string
	RequestID  string
}

// DeliveryEnqueuer 是 internal/mailer.DeliveryService 的可注入子集。
type DeliveryEnqueuer interface {
	Enqueue(ctx context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error)
}

// DeliveryEmailSender 把邀请/审核通知交给 internal/mailer 可靠投递。
type DeliveryEmailSender struct {
	deliveries DeliveryEnqueuer
	appName    string
}

// NewDeliveryEmailSender 构造投递适配器。
func NewDeliveryEmailSender(deliveries DeliveryEnqueuer, appName string) (*DeliveryEmailSender, error) {
	if isNil(deliveries) {
		return nil, fmt.Errorf("%w: 邮件投递服务为空", ErrOptionsInvalid)
	}
	if strings.TrimSpace(appName) == "" || len([]rune(appName)) > 100 {
		return nil, fmt.Errorf("%w: 邮件服务名称无效", ErrOptionsInvalid)
	}
	return &DeliveryEmailSender{deliveries: deliveries, appName: appName}, nil
}

// SendInvitation 幂等入队邀请邮件（验证模板 + 一次性接受入口）。
func (s *DeliveryEmailSender) SendInvitation(ctx context.Context, message InvitationEmail) error {
	caller, err := mailer.SystemCaller("onboarding")
	if err != nil {
		return fmt.Errorf("%w: 无法构造投递身份", ErrOptionsInvalid)
	}
	appName := message.AppName
	if strings.TrimSpace(appName) == "" {
		appName = s.appName
	}
	_, err = s.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: "invitation-" + message.InvitationID,
		Kind:           mailer.KindVerification,
		Recipient:      message.Recipient,
		Data: mailer.RenderRequest{
			Kind: mailer.KindVerification,
			Verification: &mailer.VerificationData{
				DisplayName: message.DisplayName,
				VerifyURL:   message.AcceptanceURL,
				ExpiresIn:   message.ExpiresIn,
				AppName:     appName,
			},
		},
		RequestID: message.RequestID,
	})
	if err != nil {
		return fmt.Errorf("%w: 无法入队邀请邮件", ErrMailUnavailable)
	}
	return nil
}

// SendReviewDecision 幂等入队审核结果通知（安全告知模板，不含令牌/入口）。
func (s *DeliveryEmailSender) SendReviewDecision(ctx context.Context, message ReviewEmail) error {
	caller, err := mailer.SystemCaller("onboarding")
	if err != nil {
		return fmt.Errorf("%w: 无法构造投递身份", ErrOptionsInvalid)
	}
	appName := message.AppName
	if strings.TrimSpace(appName) == "" {
		appName = s.appName
	}
	event := "注册审核结果：批准"
	if message.Decision == "reject" {
		event = "注册审核结果：拒绝"
	}
	_, err = s.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: "review-" + message.UserID + "-" + message.Decision,
		Kind:           mailer.KindSecurityNotice,
		Recipient:      message.Recipient,
		Data: mailer.RenderRequest{
			Kind: mailer.KindSecurityNotice,
			Notice: &mailer.SecurityNoticeData{
				DisplayName: "用户",
				Event:       event,
				OccurredAt:  message.OccurredAt.UTC().Format(time.RFC3339),
				ClientInfo:  "管理员审核",
				AppName:     appName,
				SupportURL:  message.SupportURL,
			},
		},
		RequestID: message.RequestID,
	})
	if err != nil {
		return fmt.Errorf("%w: 无法入队审核通知", ErrMailUnavailable)
	}
	return nil
}
