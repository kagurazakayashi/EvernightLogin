package mailer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// 发送失败分类代码（内部原因码，不占用根包公开错误码注册表）。服务层可把它们
// 写入任务 failure_reason 或投递记录 last_error_code；不得包含正文、链接、验证码。
const (
	// CodeInvalidMessage 表示消息构建/地址/模板校验失败（不可重试）。
	CodeInvalidMessage = "MAIL_INVALID_MESSAGE"
	// CodeAddressRejected 表示收件地址非法或被服务端拒绝（不可重试）。
	CodeAddressRejected = "MAIL_ADDRESS_REJECTED"
	// CodeAuthFailed 表示认证缺失/失败（不可重试，需要修正配置）。
	CodeAuthFailed = "MAIL_AUTH_FAILED"
	// CodeTLSFailed 表示 TLS 配置或握手失败（不可重试）。
	CodeTLSFailed = "MAIL_TLS_FAILED"
	// CodeTimeout 表示连接/读写超时（可重试）。
	CodeTimeout = "MAIL_SEND_TIMEOUT"
	// CodeUnavailable 表示网络不可达/连接被拒绝/临时 4xx（可重试）。
	CodeUnavailable = "MAIL_SEND_UNAVAILABLE"
	// CodeRejected 表示服务端永久拒绝（5xx，不可重试）。
	CodeRejected = "MAIL_SEND_REJECTED"
	// CodeCancelled 表示发送因调用方取消而中止（可重试，由任务调度决定）。
	CodeCancelled = "MAIL_SEND_CANCELLED"
	// CodeQueueFailed 表示投递记录已创建但任务入队失败；记录被标记 failed 供
	// 诊断与受控重试，不会留下无主 queued 记录。
	CodeQueueFailed = "MAIL_QUEUE_FAILED"
)

// FailureKind 是发送失败分类。
type FailureKind string

const (
	// FailureNone 表示成功（仅用于记录零值）。
	FailureNone FailureKind = ""
	// FailureTransient 表示临时失败，可受控重试。
	FailureTransient FailureKind = "transient"
	// FailurePermanent 表示永久失败，不应重试。
	FailurePermanent FailureKind = "permanent"
)

// 领域错误哨兵。详细原因通过 *SendError 携带，错误文本不包含正文或凭据。
var (
	// ErrInvalidMessage 表示消息或地址不合法。
	ErrInvalidMessage = errors.New("mailer: 消息无效")
	// ErrTemplateInvalid 表示模板不存在、变量缺失或渲染结果不安全。
	ErrTemplateInvalid = errors.New("mailer: 模板无效")
	// ErrOptionsInvalid 表示发送器/投递服务选项不合法。
	ErrOptionsInvalid = errors.New("mailer: 选项无效")
	// ErrNotConfigured 表示缺少真实发送能力（未配置 SMTP 适配）。
	ErrNotConfigured = errors.New("mailer: 未配置发送器")
	// ErrDeliveryNotFound 表示投递记录不存在。
	ErrDeliveryNotFound = errors.New("mailer: 投递记录不存在")
	// ErrDeliveryConflict 表示投递状态不允许当前操作（例如对已完成投递重试）。
	ErrDeliveryConflict = errors.New("mailer: 投递状态冲突")
	// ErrAccessDenied 表示调用者无权查询或重试投递。
	ErrAccessDenied = errors.New("mailer: 无权限")
	// ErrStoreUnavailable 表示投递存储不可用。
	ErrStoreUnavailable = errors.New("mailer: 投递存储不可用")
)

// SendError 是带分类与稳定代码的发送错误。
//
// 它只携带分类、代码与底层错误（底层错误可能包含 SMTP 状态码文本），绝不携带
// 邮件正文、链接、验证码或认证口令；日志与审计应只记录 Code/Kind。
type SendError struct {
	Kind FailureKind
	Code string
	Err  error
}

// Error 实现 error。
func (e *SendError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("mailer: %s", e.Code)
	}
	return fmt.Sprintf("mailer: %s: %v", e.Code, e.Err)
}

// Unwrap 支持 errors.Is/As 检查底层错误。
func (e *SendError) Unwrap() error { return e.Err }

// Retryable 报告该错误是否可重试。
func (e *SendError) Retryable() bool { return e != nil && e.Kind == FailureTransient }

// newSendError 构造带分类的发送错误。
func newSendError(kind FailureKind, code string, err error) *SendError {
	return &SendError{Kind: kind, Code: code, Err: err}
}

// IsRetryable 报告错误链中的发送错误是否可重试。非 *SendError 的错误按可重试
// 处理（保守：让任务重试上限决定），便于把底层网络错误交给上层分类。
func IsRetryable(err error) bool {
	var target *SendError
	if errors.As(err, &target) {
		return target.Retryable()
	}
	return true
}

// CodeOf 返回错误链中的发送失败代码；没有时返回空字符串。
func CodeOf(err error) string {
	var target *SendError
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

// KindOf 返回错误链中的发送失败分类。
func KindOf(err error) FailureKind {
	var target *SendError
	if errors.As(err, &target) {
		return target.Kind
	}
	return FailureNone
}

// classifySendError 把底层错误归类为稳定的发送错误。调用方在 SMTP 适配层使用，
// 保证投递任务能可靠区分"可重试"与"不可重试"。
func classifySendError(err error) error {
	if err == nil {
		return nil
	}
	var sendErr *SendError
	if errors.As(err, &sendErr) {
		return sendErr
	}
	// 调用方取消/超时：超时按临时失败，取消按可重试（是否重试由任务调度决定）。
	if errors.Is(err, context.DeadlineExceeded) {
		return newSendError(FailureTransient, CodeTimeout, err)
	}
	if errors.Is(err, context.Canceled) {
		return newSendError(FailureTransient, CodeCancelled, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return newSendError(FailureTransient, CodeTimeout, err)
	}
	// SMTP 状态码：4xx 临时、5xx 永久。
	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		switch {
		case protoErr.Code >= 400 && protoErr.Code < 500:
			return newSendError(FailureTransient, CodeUnavailable, err)
		case protoErr.Code == 535 || protoErr.Code == 534 || protoErr.Code == 530:
			return newSendError(FailurePermanent, CodeAuthFailed, err)
		default:
			return newSendError(FailurePermanent, CodeRejected, err)
		}
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "x509") || strings.Contains(lower, "tls") || strings.Contains(lower, "certificate"):
		return newSendError(FailurePermanent, CodeTLSFailed, err)
	case strings.Contains(lower, "auth"):
		return newSendError(FailurePermanent, CodeAuthFailed, err)
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "connection reset") || strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "broken pipe"):
		return newSendError(FailureTransient, CodeUnavailable, err)
	}
	// 未知错误按临时失败处理，但重试次数受任务上限约束。
	return newSendError(FailureTransient, CodeUnavailable, err)
}
