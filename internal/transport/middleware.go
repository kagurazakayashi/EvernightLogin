package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
)

// tryAcquire 尝试占用一个并发处理槽位；失败时返回 nil,false，调用方立即返回
// 429，不排队等待，避免慢客户端把连接与 goroutine 堆积在信号量前。
func (p *protection) tryAcquire() (func(), bool) {
	if p == nil || p.semaphore == nil {
		return func() {}, true
	}
	select {
	case p.semaphore <- struct{}{}:
		return func() {
			select {
			case <-p.semaphore:
			default:
				// 防御性分支：只有异常重复释放才会走到；不 panic。
			}
		}, true
	default:
		return nil, false
	}
}

// clientIP 返回可信客户端地址；没有防护配置时只用于访问日志，绝不信任转发头。
func (h *handler) clientIP(request *http.Request) string {
	if request == nil {
		return "-"
	}
	if h.protection != nil {
		return h.protection.clientIP(request)
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

// setResponseDeadline 设置响应写超时。不支持的 ResponseWriter（如 httptest 记录
// 器）返回错误时忽略；请求处理期限仍由 context 控制。
func (h *handler) setResponseDeadline(writer http.ResponseWriter, timeout time.Duration) {
	if writer == nil || timeout <= 0 {
		return
	}
	controller := http.NewResponseController(writer)
	_ = controller.SetWriteDeadline(time.Now().Add(timeout))
}

// checkRateLimit 对单个维度做限流判定；nil 限流器表示该维度禁用。
func (h *handler) checkRateLimit(limiter *ratelimit.Limiter, key string) *problem {
	if limiter == nil {
		return nil
	}
	decision := limiter.Allow(key)
	if decision.Allowed {
		return nil
	}
	return newRateLimitedProblem(decision.RetryAfter, "请求过于频繁，请稍后重试")
}

// checkIdentityRateLimits 在身份建立后按已认证用户与应用维度限流。匿名请求没有
// 可信身份，只受地址与接口维度约束，绝不读取客户端自填 user_id 作为键。
func (h *handler) checkIdentityRateLimits(ctx context.Context) *problem {
	if h.protection == nil {
		return nil
	}
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return nil
	}
	switch identity.Kind {
	case "user":
		if problem := h.checkRateLimit(h.protection.rateLimits.user, "user:"+identity.SubjectID); problem != nil {
			return problem
		}
		if identity.AppID != "" {
			if problem := h.checkRateLimit(h.protection.rateLimits.application, "app:"+identity.AppID); problem != nil {
				return problem
			}
		}
	case "application":
		appID := identity.AppID
		if appID == "" {
			appID = identity.SubjectID
		}
		if problem := h.checkRateLimit(h.protection.rateLimits.application, "app:"+appID); problem != nil {
			return problem
		}
	}
	return nil
}

// checkExpensiveBudget 对标记为昂贵的接口消耗独立预算。键优先使用可信用户或
// 应用身份，匿名请求使用可信客户端地址；不信任请求头中的身份。
func (h *handler) checkExpensiveBudget(ctx context.Context, clientIP string) *problem {
	if h.protection == nil || h.protection.rateLimits.expensive == nil {
		return nil
	}
	key := "ip:" + clientIP
	if identity, ok := IdentityFromContext(ctx); ok {
		switch identity.Kind {
		case "user":
			key = "user:" + identity.SubjectID
		case "application":
			appID := identity.AppID
			if appID == "" {
				appID = identity.SubjectID
			}
			key = "app:" + appID
		case "system":
			key = "system:" + identity.SubjectID
		}
	}
	return h.checkRateLimit(h.protection.rateLimits.expensive, "expensive:"+key)
}

// maxBufferedResponseBytes 是响应超时保护允许缓冲的最大响应体。当前 Handler 只
// 输出小型 JSON；超过上限视为内部错误，避免恶意/错误处理程序把响应缓冲当内存
// 放大手段。未来流式端点需要独立的响应路径，不能使用本缓冲。
const maxBufferedResponseBytes = 1 << 20

// bufferedResponseWriter 是响应超时保护使用的内存响应。只有内部处理 goroutine
// 写入，主 goroutine 在结果通道同步后才读取，因此无需额外锁。
type bufferedResponseWriter struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        bytes.Buffer
	overflow    bool
}

// newBufferedResponseWriter 构造空的内存响应。
func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

// Header 返回响应头。
func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

// WriteHeader 只记录第一次状态。
func (w *bufferedResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
}

// Write 追加响应体并执行大小上限。
func (w *bufferedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.body.Len()+len(data) > maxBufferedResponseBytes {
		w.overflow = true
		return 0, fmt.Errorf("响应超过缓冲上限")
	}
	return w.body.Write(data)
}

// serveResult 是内部处理 goroutine 的结果。
type serveResult struct {
	problem *problem
	inner   *responseWriter
}

// copyTo 把内存响应复制到真实 ResponseWriter；复制后外层 tracker 负责访问日志。
func (w *bufferedResponseWriter) copyTo(outer *responseWriter) {
	for name, values := range w.header {
		outer.Header()[name] = append([]string(nil), values...)
	}
	if w.wroteHeader {
		outer.WriteHeader(w.status)
	}
	if w.body.Len() > 0 {
		_, _ = outer.Write(w.body.Bytes())
	}
}

// serveWithTimeout 在独立 goroutine 中执行处理链，并在墙钟期限到达时丢弃尚未
// 完成的响应、返回 504。处理器必须响应 context 才能真正释放 goroutine；忽略
// 取消的处理器在返回前仍会占用 goroutine（但响应与访问日志已按超时处理）。
func (h *handler) serveWithTimeout(ctx context.Context, outer *responseWriter, request *http.Request, timeout time.Duration) *problem {
	innerBuffer := newBufferedResponseWriter()
	inner := newResponseWriter(innerBuffer)
	resultCh := make(chan serveResult, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				h.logger.Error("HTTP 请求处理发生 panic", "request_id", RequestIDFromContext(ctx))
				resultCh <- serveResult{problem: internalProblem(), inner: inner}
			}
		}()
		resultCh <- serveResult{problem: h.serve(ctx, inner, request), inner: inner}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result.inner == nil {
			return internalProblem()
		}
		if innerBuffer.overflow {
			return internalProblem()
		}
		if result.problem != nil && !result.inner.wroteHeader {
			innerBuffer.copyHeadersTo(outer)
			return result.problem
		}
		innerBuffer.copyTo(outer)
		return nil
	case <-timer.C:
		return timeoutProblem()
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return timeoutProblem()
		}
		return &problem{status: clientClosedStatus, code: "REQ_INVALID", message: "客户端已取消请求"}
	}
}

// copyHeadersTo 只复制响应头，不复制状态与正文；用于处理程序在写出响应前失败
// 时保留 CORS 等中间件已设置的响应头。
func (w *bufferedResponseWriter) copyHeadersTo(outer *responseWriter) {
	for name, values := range w.header {
		outer.Header()[name] = append([]string(nil), values...)
	}
}
