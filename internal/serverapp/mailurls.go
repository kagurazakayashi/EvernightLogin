package serverapp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
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
//
// 步骤 211 健壮性修复：不再对完整 URL 做字符串后缀判断（可能把 "https://host/foo"
// 误判为已含 "/foo"，或对 "https://host/foo" + "/bar" 产生意外拼接），而是先
// url.Parse，再在**解析后的路径**上规范化拼接 prefix：
//   - base 路径为空时追加 prefix；
//   - base 路径已等于 prefix（允许尾斜杠）时不重复追加；
//   - base 路径以完整路径段结尾于 prefix（如反代额外父路径）时同样不重复追加；
//   - prefix 为空时保留 base 自带路径。
//
// 配置校验（Config.Validate）仍要求 public_base_url 的路径与 path_prefix 完全一致，
// 因此这里只处理合法组合的尾斜杠/幂等拼接；非法组合由启动校验拒绝，不把配置错误
// 当成可利用缺陷。查询串、片段与 userinfo 在这里也拒绝（防御性，不生成含糊链接）。
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
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return MailURLBases{}, fmt.Errorf("server.public_base_url 不能包含用户信息、查询串或片段")
	}
	prefix, prefixErr := transport.NormalizePrefix(cfg.Server.PathPrefix)
	if prefixErr != nil {
		return MailURLBases{}, fmt.Errorf("server.path_prefix 非法: %w", prefixErr)
	}
	basePath := strings.TrimSuffix(parsed.Path, "/")
	if basePath == "/" {
		basePath = ""
	}
	switch {
	case prefix == "":
		// 根路径部署：保留 base 自带路径（一致性由配置校验负责）。
	case basePath == "":
		basePath = prefix
	case basePath == prefix:
		// 已包含前缀，不重复追加。
	case pathHasSuffixPrefix(basePath, prefix):
		// 形如 /parent/prefix：已以完整路径段包含前缀，不重复追加。
	default:
		basePath = strings.TrimSuffix(basePath, "/") + prefix
	}
	origin := parsed.Scheme + "://" + parsed.Host
	baseURL := origin + basePath
	return MailURLBases{
		VerifyEmail:   baseURL + pagePathEmailVerify,
		ChangeEmail:   baseURL + pagePathEmailChangeVerify,
		PasswordReset: baseURL + pagePathPasswordReset,
		Support:       baseURL + pagePathSupport,
	}, nil
}

// pathHasSuffixPrefix 报告 path 是否以“完整路径段”结尾于 prefix（例如 /a/idp 对
// /idp 为真，/mydp 对 /dp 为假），避免字符串后缀误判造成重复前缀。
func pathHasSuffixPrefix(path, prefix string) bool {
	if prefix == "" || path == prefix {
		return prefix != ""
	}
	// prefix 已由 transport.NormalizePrefix 规范化（以 "/" 开头、无尾斜杠），
	// 因此对解析后的 Path 做 HasSuffix 即可判定“已以完整路径段包含 prefix”，
	// 不会再出现对整串 URL 判断时的 host/查询串误判。
	return strings.HasSuffix(path, prefix)
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
