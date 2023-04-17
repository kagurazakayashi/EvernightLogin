package serverapp

import (
	"fmt"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// MailRuntime 是步骤 139 装配的真实邮件发送运行时。
//
// enabled=false 时 Sender 为 nil，业务侧继续使用显式“未配置发送器”语义
// （永久失败、不访问网络、不伪造成功）；enabled=true 时 Sender 是真实 SMTP
// 发送器，密码按需从受保护来源读取并在每次认证后清零字节副本，信任根只追加
// 系统根、不提供关闭证书校验的入口。
type MailRuntime struct {
	// Enabled 表示真实发送通道是否可用。
	Enabled bool
	// Sender 是真实发送器；nil 表示未配置。
	Sender mailer.Sender
	// From 是发件地址（未配置时使用合法的占位地址）。
	From mailer.Address
	// AppName 是邮件品牌名。
	AppName string
	// TLSMode 是 starttls|implicit|none。
	TLSMode string
}

// BuildMailRuntime 根据有效配置构造邮件运行时。
//
// mail.enabled=false 时不读取密码/证书、不建立网络连接；enabled=true 时配置
// 不完整、秘密来源不可读或信任根无效都返回错误（启动失败），绝不降级为未配置
// 或明文发送。
func BuildMailRuntime(cfg login.Config) (*MailRuntime, error) {
	appName := strings.TrimSpace(cfg.Mail.AppName)
	if appName == "" {
		appName = "EvernightLogin"
	}
	runtime := &MailRuntime{
		From:    mailer.Address{Spec: notificationFromAddress},
		AppName: appName,
		TLSMode: strings.TrimSpace(cfg.Mail.SMTP.TLSMode),
	}
	if runtime.TLSMode == "" {
		runtime.TLSMode = string(mailer.TLSModeStartTLS)
	}
	if !cfg.Mail.Enabled {
		return runtime, nil
	}
	trustedRoots, err := mailer.LoadTrustedRoots(cfg.Mail.SMTP.TrustedRoots)
	if err != nil {
		return nil, fmt.Errorf("加载邮件信任根失败: %w", err)
	}
	var provider func() ([]byte, error)
	if cfg.Mail.SMTP.Password.Kind != "" {
		source := cfg.Mail.SMTP.Password
		provider = func() ([]byte, error) {
			secret, loadErr := source.Load()
			if loadErr != nil {
				return nil, loadErr
			}
			return secret.Value(), nil
		}
		// 启动时只做一次可读性探测并立即清零，避免“配置看起来启用、首次发送
		// 才发现秘密不可读”的带病运行；探测副本不长期保存。
		probe, probeErr := provider()
		if probeErr != nil {
			return nil, fmt.Errorf("读取邮件 SMTP 密码失败: %w", probeErr)
		}
		for i := range probe {
			probe[i] = 0
		}
	}
	options := mailer.SMTPOptions{
		Addr:                strings.TrimSpace(cfg.Mail.SMTP.Addr),
		Host:                strings.TrimSpace(cfg.Mail.SMTP.Host),
		TLSMode:             mailer.TLSMode(runtime.TLSMode),
		TrustedRoots:        trustedRoots,
		Username:            strings.TrimSpace(cfg.Mail.SMTP.Username),
		Timeout:             time.Duration(cfg.Mail.SMTP.TimeoutSeconds) * time.Second,
		AllowPlaintextLocal: cfg.Mail.SMTP.AllowPlaintextLocal,
		PasswordProvider:    provider,
	}
	sender, err := mailer.NewSMTPSender(options)
	if err != nil {
		return nil, fmt.Errorf("构造邮件 SMTP 发送器失败: %w", err)
	}
	runtime.Enabled = true
	runtime.Sender = sender
	runtime.From = mailer.Address{Spec: strings.TrimSpace(cfg.Mail.From.Address)}
	return runtime, nil
}

// SenderOrDisabled 返回真实发送器；未配置时返回显式“未配置”发送器（发送永久
// 失败、不访问网络），绝不返回 nil 让调用方误判成功。
func (m *MailRuntime) SenderOrDisabled() mailer.Sender {
	if m != nil && m.Sender != nil {
		return m.Sender
	}
	return disabledMailSender()
}

// FromAddress 返回发件地址；未配置时返回合法占位地址。
func (m *MailRuntime) FromAddress() mailer.Address {
	if m != nil && m.From.Spec != "" {
		return m.From
	}
	return mailer.Address{Spec: notificationFromAddress}
}

// AppDisplayName 返回邮件品牌名；未配置时使用产品默认名。
func (m *MailRuntime) AppDisplayName() string {
	if m != nil && strings.TrimSpace(m.AppName) != "" {
		return strings.TrimSpace(m.AppName)
	}
	return "EvernightLogin"
}

// mailDomain 返回地址的域名部分，仅用于诊断日志（不记录完整地址）。
func mailDomain(spec string) string {
	if index := strings.LastIndex(spec, "@"); index >= 0 && index+1 < len(spec) {
		return spec[index+1:]
	}
	return ""
}
