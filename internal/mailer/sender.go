package mailer

import (
	"context"
)

// Sender 是可注入的邮件发送接口。真实 SMTP 适配与其他发送后端（测试捕获器、
// 队列）都实现该接口；业务代码只依赖接口，不直接依赖网络实现。
//
// 语义：Send 成功只代表发送后端接受了这封邮件，不代表收件人最终看到；外部邮件
// 系统不保证恰好一次送达，重复调用可能产生重复邮件，调用方必须用幂等键去重。
type Sender interface {
	// Send 发送已构建好的邮件。必须响应 ctx 取消与期限；返回 *SendError 时
	// 调用方可区分可重试与不可重试失败。
	Send(ctx context.Context, message Message) error
}

// SenderFunc 把函数适配为 Sender，便于测试与组合。
type SenderFunc func(ctx context.Context, message Message) error

// Send 实现 Sender。nil SenderFunc 按"未配置发送器"失败，而不是静默成功。
func (f SenderFunc) Send(ctx context.Context, message Message) error {
	if f == nil {
		return newSendError(FailurePermanent, CodeUnavailable, ErrNotConfigured)
	}
	return f(ctx, message)
}

var _ Sender = SenderFunc(nil)
