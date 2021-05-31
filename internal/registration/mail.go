package registration

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// VerificationSender 是验证邮件发送契约。生产实现基于 internal/mailer 的可靠
// 投递服务；测试可以使用捕获替身。实现返回错误表示邮件没有交给发送后端，调用方
// 只会记录“未发送”状态，不会把邮箱标记为已验证。
type EmailSender interface {
	SendEmailVerification(ctx context.Context, message EmailMessage) error
}

// EmailMessage 是一封邮箱验证邮件的渲染数据。VerificationURL 含一次性令牌，
// 只用于邮件正文；调用方与实现都不得把它写入日志、审计或数据库。
type EmailMessage struct {
	// UserID 是目标账户稳定 ID，仅用于日志关联与投递归属，不写入公开日志。
	UserID string
	// Recipient 是收件邮箱显示值。
	Recipient string
	// DisplayName 是邮件称呼，取自昵称或用户名。
	DisplayName string
	// VerificationURL 是一次性验证入口链接（含令牌明文）。
	VerificationURL string
	// ExpiresAt 是入口失效时间（UTC）。
	ExpiresAt time.Time
	// ExpiresIn 是供邮件正文显示的有效期文本。
	ExpiresIn string
	// AppName 是邮件模板中的服务名称。
	AppName string
	// CredentialID 是一次性凭证 ID，用作幂等键，不含秘密。
	CredentialID string
	// RequestID 可选，透传到投递审计。
	RequestID string
}

// DeliveryEnqueuer 是 internal/mailer.DeliveryService 的可注入子集，便于测试。
type DeliveryEnqueuer interface {
	Enqueue(ctx context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error)
}

// DeliveryEmailSender 把邮箱验证入口交给 internal/mailer 的可靠投递服务。
//
// 载荷只包含模板数据（含一次性链接）并加密落库；本适配器不记录链接，幂等键使用
// 一次性凭证 ID，重复发送同一凭证不会重复入队。
type DeliveryEmailSender struct {
	deliveries DeliveryEnqueuer
	appName    string
}

// NewDeliveryEmailSender 构造投递适配器。deliveries 为空或应用名为空时返回
// ErrOptionsInvalid。
func NewDeliveryEmailSender(deliveries DeliveryEnqueuer, appName string) (*DeliveryEmailSender, error) {
	if isNilInterface(deliveries) {
		return nil, fmt.Errorf("%w: 邮件投递服务为空", ErrOptionsInvalid)
	}
	if strings.TrimSpace(appName) == "" || len([]rune(appName)) > 100 {
		return nil, fmt.Errorf("%w: 邮件服务名称无效", ErrOptionsInvalid)
	}
	return &DeliveryEmailSender{deliveries: deliveries, appName: appName}, nil
}

// SendEmailVerification 幂等入队一封验证邮件。实现只依赖投递服务的公开接口，
// 不自行渲染或发送，投递失败由投递服务状态与受控重试处理。
func (s *DeliveryEmailSender) SendEmailVerification(ctx context.Context, message EmailMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.deliveries == nil {
		return fmt.Errorf("%w: 邮件投递服务为空", ErrOptionsInvalid)
	}
	appName := message.AppName
	if strings.TrimSpace(appName) == "" {
		appName = s.appName
	}
	caller, err := mailer.SystemCaller("registration")
	if err != nil {
		return fmt.Errorf("%w: 无法构造投递身份", ErrOptionsInvalid)
	}
	expiresIn := message.ExpiresIn
	if strings.TrimSpace(expiresIn) == "" {
		expiresIn = formatDuration(time.Until(message.ExpiresAt))
	}
	_, err = s.deliveries.Enqueue(ctx, mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: "email-verify-" + message.CredentialID,
		Kind:           mailer.KindVerification,
		Recipient:      message.Recipient,
		Data: mailer.RenderRequest{
			Kind: mailer.KindVerification,
			Verification: &mailer.VerificationData{
				DisplayName: message.DisplayName,
				VerifyURL:   message.VerificationURL,
				ExpiresIn:   expiresIn,
				AppName:     appName,
			},
		},
		RequestID: message.RequestID,
	})
	if err != nil {
		return fmt.Errorf("%w: 无法入队验证邮件", ErrMailUnavailable)
	}
	return nil
}

// verificationURLProblem 校验验证入口基础地址；返回空字符串表示合法。
func verificationURLProblem(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "验证入口地址不能为空"
	}
	if len(value) > 2048 {
		return "验证入口地址超过 2048 字节"
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return "验证入口地址包含空白或控制字符"
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "验证入口地址不是合法 URL"
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "验证入口地址只允许 http/https"
	}
	if parsed.Host == "" {
		return "验证入口地址缺少主机名"
	}
	if parsed.User != nil {
		return "验证入口地址不得包含用户名/口令"
	}
	if parsed.Fragment != "" {
		return "验证入口地址不得包含片段"
	}
	return ""
}
