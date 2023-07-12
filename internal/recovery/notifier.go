package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// MailNotifier 是恢复流程安全告知的生产实现：复用 internal/mailer 的安全告知模板，
// 只向用户最近一个已验证邮箱发送，不包含恢复代码、验证摘要或会话秘密。
//
// 装配说明：真实外发必须由宿主指定发送器（SMTP/本地捕获器）与发件地址；测试可
// 使用 internal/mailtest 外部 EvernightMail 夹具验证内容，不得把测试收件器装配进生产路径。
type MailNotifier struct {
	store      Store
	sender     mailer.Sender
	templates  *mailer.TemplateSet
	from       mailer.Address
	appName    string
	supportURL string
	logger     *slog.Logger
}

// NewMailNotifier 构造邮件安全告知器。store/sender/发件地址缺失或非法时拒绝构造。
func NewMailNotifier(store Store, sender mailer.Sender, fromAddress, appName, supportURL string) (*MailNotifier, error) {
	if isNilInterface(store) {
		return nil, fmt.Errorf("%w: 告知存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(sender) {
		return nil, fmt.Errorf("%w: 邮件发送接口为空", ErrOptionsInvalid)
	}
	from, err := mailer.ParseAddress(fromAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: 发件地址无效", ErrOptionsInvalid)
	}
	if strings.TrimSpace(appName) == "" {
		return nil, fmt.Errorf("%w: 应用名称为空", ErrOptionsInvalid)
	}
	support, err := url.Parse(strings.TrimSpace(supportURL))
	if err != nil || (support.Scheme != "https" && support.Scheme != "http") || support.Host == "" || support.User != nil {
		return nil, fmt.Errorf("%w: 支持入口必须是合法的 http/https 地址", ErrOptionsInvalid)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		return nil, fmt.Errorf("%w: 默认邮件模板不可用", ErrOptionsInvalid)
	}
	return &MailNotifier{
		store:      store,
		sender:     sender,
		templates:  templates,
		from:       from,
		appName:    appName,
		supportURL: support.String(),
		logger:     slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}, nil
}

// Notify 渲染并发送一条安全告知；没有已验证邮箱、渲染失败或投递失败都返回
// ErrNotificationFailed（调用方不回滚已完成的恢复，但必须写失败审计）。
func (n *MailNotifier) Notify(ctx context.Context, notification Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	address, found, err := n.store.VerifiedEmail(ctx, notification.UserID)
	if err != nil {
		return fmt.Errorf("%w: 读取已验证邮箱失败", ErrNotificationFailed)
	}
	if !found || address == "" {
		return fmt.Errorf("%w: 账户没有已验证邮箱", ErrNotificationFailed)
	}
	recipient, err := mailer.ParseAddress(address)
	if err != nil {
		return fmt.Errorf("%w: 收件地址无效", ErrNotificationFailed)
	}
	displayName := strings.TrimSpace(notification.Username)
	if displayName == "" {
		displayName = "用户"
	}
	occurredAt := notification.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	content, err := n.templates.Render(mailer.RenderRequest{
		Kind: mailer.KindSecurityNotice,
		Notice: &mailer.SecurityNoticeData{
			DisplayName: displayName,
			Event:       notification.Event,
			OccurredAt:  occurredAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			AppName:     n.appName,
			SupportURL:  n.supportURL,
		},
	})
	if err != nil {
		return fmt.Errorf("%w: 安全告知模板渲染失败", ErrNotificationFailed)
	}
	message := mailer.Message{
		From:     n.from,
		To:       []mailer.Address{recipient},
		Subject:  content.Subject,
		TextBody: content.TextBody,
	}
	if err := n.sender.Send(ctx, message); err != nil {
		return fmt.Errorf("%w: %v", ErrNotificationFailed, err)
	}
	n.logger.Info("恢复安全告知已发送", "kind", string(notification.Kind), "user_id", notification.UserID)
	return nil
}

// discardWriter 是默认丢弃日志输出。
type discardWriter struct{}

// Write 实现 io.Writer，丢弃全部输出。
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// 编译期断言：MailNotifier 实现 Notifier。
var _ Notifier = (*MailNotifier)(nil)
