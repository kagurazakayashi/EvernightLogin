package serverapp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
)

// 页面路径常量与 WebUI 实际注册路由保持一致；集中在这里避免多处硬编码漂移。
const (
	pagePathEmailVerify       = "/email/verify"
	pagePathEmailChangeVerify = "/email/change/verify"
	pagePathPasswordReset     = "/login/reset-password"
	pagePathSupport           = "/support"
)

// MailURLBases 是邮件中使用的公开页面基址（步骤 140/141）。
type MailURLBases struct {
	VerifyEmail   string
	ChangeEmail   string
	PasswordReset string
	Support       string
}

// buildMailURLs 由 server.public_base_url + server.path_prefix 生成邮件页面基址。
// 仅当 mail.enabled 时要求 public_base_url 为非空绝对 http(s) URL；纯本地开发
// 允许 http 回环地址，生产应使用 https（配置校验/反向代理负责 TLS）。
func buildMailURLs(cfg login.Config) (MailURLBases, error) {
	if !cfg.Mail.Enabled {
		return MailURLBases{}, nil
	}
	base := strings.TrimSpace(cfg.Server.PublicBaseURL)
	if base == "" {
		return MailURLBases{}, fmt.Errorf("mail.enabled=true 时必须配置 server.public_base_url 以生成邮件链接")
	}
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return MailURLBases{}, fmt.Errorf("server.public_base_url 必须是绝对 http(s) URL（mail.enabled=true）")
	}
	base = strings.TrimSuffix(base, "/") + cfg.Server.PathPrefix
	return MailURLBases{
		VerifyEmail:   base + pagePathEmailVerify,
		ChangeEmail:   base + pagePathEmailChangeVerify,
		PasswordReset: base + pagePathPasswordReset,
		Support:       base + pagePathSupport,
	}, nil
}

// lazyRegistrationMailer 在注册服务构造时尚无任务运行时，延迟到实际发送时取
// 真实 mailer.DeliveryService；未装配邮件时以 registration.ErrMailUnavailable
// 明确失败，绝不伪造发送成功。
type lazyRegistrationMailer struct {
	provider func() *mailer.DeliveryService
	appName  string
}

// SendEmailVerification 实现 registration.EmailSender。
func (s *lazyRegistrationMailer) SendEmailVerification(ctx context.Context, message registration.EmailMessage) error {
	if s == nil || s.provider == nil {
		return fmt.Errorf("%w: 邮件投递服务未装配", registration.ErrMailUnavailable)
	}
	deliveries := s.provider()
	if deliveries == nil {
		return fmt.Errorf("%w: 邮件投递服务未装配", registration.ErrMailUnavailable)
	}
	adapter, err := registration.NewDeliveryEmailSender(deliveries, s.appName)
	if err != nil {
		return fmt.Errorf("%w: %v", registration.ErrMailUnavailable, err)
	}
	return adapter.SendEmailVerification(ctx, message)
}

// mustMailTemplates 返回默认邮件模板集；构建期失败属装配错误（模板为内置常量）。
func mustMailTemplates() *mailer.TemplateSet {
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		return nil
	}
	return templates
}

// validateMailRegistration 在启动期校验邮件与注册邮箱验证的组合约束：
// 要求邮箱验证但没有邮件能力、或启用邮件但公开链接基址非法，都直接失败。
func validateMailRegistration(cfg login.Config) error {
	if cfg.Registration.RequireEmailVerification && !cfg.Mail.Enabled {
		return fmt.Errorf("CONFIG_INVALID: registration.require_email_verification=true 但 mail.enabled=false；" +
			"请配置邮件传输或关闭注册邮箱验证")
	}
	if cfg.Mail.Enabled {
		if _, err := buildMailURLs(cfg); err != nil {
			return fmt.Errorf("CONFIG_INVALID: %w", err)
		}
	}
	return nil
}
