package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// problem 是传输层内部错误：统一错误码、HTTP 状态与公开说明。公开说明只由
// 固定文本或根包已脱敏的 AppError 消息填充，绝不包含内部原因、堆栈或请求内容。
type problem struct {
	status     int
	code       string
	message    string
	cause      error
	retryAfter time.Duration
}

// newProblem 构造传输层错误；message 会再次压缩为单行并截断。
func newProblem(status int, code, message string) *problem {
	return &problem{status: status, code: code, message: sanitizeMessage(message)}
}

// newRateLimitedProblem 构造 429 限流错误；Retry-After 与 error JSON 的
// retry_after_seconds 都来自同一个等待建议（至少 1 秒，避免客户端立即重试）。
func newRateLimitedProblem(retryAfter time.Duration, message string) *problem {
	if retryAfter <= 0 {
		retryAfter = time.Second
	}
	return &problem{
		status:     http.StatusTooManyRequests,
		code:       "RATE_LIMITED",
		message:    sanitizeMessage(message),
		retryAfter: retryAfter,
	}
}

// timeoutProblem 是请求处理超过期限时的统一 504 响应。
func timeoutProblem() *problem {
	return newProblem(http.StatusGatewayTimeout, "INTERNAL_ERROR", "请求处理超时")
}

// Error 返回单行诊断文本，仅用于内部日志与错误链，不直接写响应。
func (p *problem) Error() string {
	if p == nil {
		return ""
	}
	return p.code + ": " + p.message
}

// Unwrap 返回内部原因，供受限诊断使用；公开响应不输出。
func (p *problem) Unwrap() error {
	if p == nil {
		return nil
	}
	return p.cause
}

// internalProblem 是未分类内部故障的统一响应；不包含任何原始错误文本。
func internalProblem() *problem {
	return newProblem(http.StatusInternalServerError, "INTERNAL_ERROR", "服务发生未预期错误")
}

// sanitizeMessage 把公开说明压成单行：控制字符替换为空格、折叠空白、限制长度，
// 防止响应或日志注入。
func sanitizeMessage(message string) string {
	var builder strings.Builder
	builder.Grow(len(message))
	previousSpace := false
	for _, character := range message {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if character == ' ' {
			if previousSpace {
				continue
			}
			previousSpace = true
		} else {
			previousSpace = false
		}
		builder.WriteRune(character)
		if builder.Len() >= maxErrorMessageBytes {
			break
		}
	}
	return strings.TrimSpace(builder.String())
}

// errorPayload 是统一错误响应正文；字段与错误码手册的返回约定一致，OAuth 协议
// 响应不会使用该结构。
type errorPayload struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	RequestID         string `json:"request_id"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// responseWriter 包装 http.ResponseWriter，记录状态、字节数与错误码，供访问日志
// 与 panic 恢复判断是否已写出响应。
type responseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
	errorCode   string
	logPath     string
}

// newResponseWriter 包装原始 ResponseWriter。
func newResponseWriter(writer http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: writer}
}

// WriteHeader 只允许第一次写状态生效，避免处理程序重复写导致 net/http 警告。
func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

// Write 写出响应并累计字节数；未显式写状态时按 200 处理。
func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytes += int64(written)
	return written, err
}

// Unwrap 暴露底层 ResponseWriter，兼容 http.NewResponseController 等标准用法。
func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Status 返回已写出的状态；尚未写出时返回 0。
func (w *responseWriter) Status() int {
	return w.status
}

// SetErrorCode 记录本次响应对应的稳定错误码，用于访问日志。
func (w *responseWriter) SetErrorCode(code string) {
	w.errorCode = code
}

// writeProblem 写出统一业务错误 JSON。若响应已开始写出则不再改写，避免把部分
// 响应与错误 JSON 拼接。
func writeProblem(w *responseWriter, requestID string, p *problem) {
	if p == nil {
		p = internalProblem()
	}
	if w.wroteHeader {
		return
	}
	status := p.status
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	payload := errorPayload{Code: p.code, Message: p.message, RequestID: requestID}
	if p.retryAfter > 0 {
		seconds := int((p.retryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		payload.RetryAfterSeconds = seconds
	}
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"code":"INTERNAL_ERROR","message":"服务发生未预期错误","request_id":""}`)
	}
	header := w.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	if payload.RetryAfterSeconds > 0 {
		header.Set("Retry-After", strconv.Itoa(payload.RetryAfterSeconds))
	}
	w.SetErrorCode(p.code)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeClientClosed 记录客户端已断开请求：不写响应正文，只写状态供访问日志统计。
func writeClientClosed(w *responseWriter) {
	if w.wroteHeader {
		return
	}
	w.WriteHeader(clientClosedStatus)
}

// problemFromError 把处理程序返回的错误映射为统一 problem。已带传输层 problem
// 的原样返回；context 取消保留语义；其他错误一律 500，不向响应泄露原始文本。
func problemFromError(ctx context.Context, err error) *problem {
	if err == nil {
		return nil
	}
	var existing *problem
	if errors.As(err, &existing) {
		return existing
	}
	if errors.Is(err, context.Canceled) {
		if ctx != nil && ctx.Err() != nil {
			return &problem{status: clientClosedStatus, code: "REQ_INVALID", message: "客户端已取消请求"}
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newProblem(http.StatusGatewayTimeout, "INTERNAL_ERROR", "请求处理超时")
	}
	return internalProblem()
}

// logInternalError 记录未分类内部错误：只记录错误码与请求编号，不记录可能含
// 秘密或用户输入的原始错误文本、堆栈或请求内容。
func logInternalError(logger *slog.Logger, requestID, path string) {
	if logger == nil {
		return
	}
	logger.Error("HTTP 请求处理失败", "request_id", requestID, "uri_stem", path)
}
