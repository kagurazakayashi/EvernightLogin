package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// route 是一条固定路由。生产 Handler 只注册健康与 OpenAPI 两条路由；其他路由
// 只能由同包测试构造器通过 Options.extraRoutes 注入，公开构造函数无法注册。
type route struct {
	method           string
	path             string
	requiresIdentity bool
	handle           func(ctx context.Context, w *responseWriter, r *http.Request) error
}

// handler 是传输层 Handler 实现；构造后不再修改，可被并发使用。
type handler struct {
	prefix            string
	maxBodyBytes      int64
	codeIndex         map[string]ErrorCodeInfo
	routes            []route
	resolveIdentity   ResolveIdentityFunc
	logger            *slog.Logger
	accessLog         *accessLog
	now               func() time.Time
	newRequestID      func() string
	validateRequestID func(string) error
	openAPIDocument   []byte
	protection        *protection
	uiHandler         http.Handler
	uiCSP             string
}

// New 构造传输层 Handler。生产实例只注册健康与 OpenAPI 路由，不注册任何测试
// 或未鉴权管理路由。
func New(options Options) (http.Handler, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	h, err := newHandler(normalized)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// newHandler 装配 Handler，并生成一次 OpenAPI 文档。options.extraRoutes 仅用于
// 同包测试。
func newHandler(options Options) (*handler, error) {
	document, err := buildOpenAPIDocument(options.Prefix, options.ErrorCodes, options.Version)
	if err != nil {
		return nil, err
	}
	if err := validateOpenAPIDocument(document); err != nil {
		return nil, err
	}
	protection, err := newProtection(options.Protection, options.Now)
	if err != nil {
		return nil, err
	}
	codeIndex := make(map[string]ErrorCodeInfo, len(options.ErrorCodes))
	for _, code := range options.ErrorCodes {
		codeIndex[code.Code] = code
	}
	// 传输层固定使用的错误码必须存在于注册表投影中，避免响应出现未登记码。
	for _, required := range []string{"REQ_INVALID", "INTERNAL_ERROR", "AUTH_FAILED", "ACCESS_DENIED", "RATE_LIMITED"} {
		if _, ok := codeIndex[required]; !ok {
			return nil, fmt.Errorf("错误码注册表缺少传输层必需错误码 %s", required)
		}
	}
	h := &handler{
		prefix:            options.Prefix,
		maxBodyBytes:      options.MaxBodyBytes,
		codeIndex:         codeIndex,
		resolveIdentity:   options.ResolveIdentity,
		logger:            options.Logger,
		now:               options.Now,
		newRequestID:      options.NewRequestID,
		validateRequestID: options.ValidateRequestID,
		openAPIDocument:   document,
		protection:        protection,
	}
	if options.UI != nil {
		h.uiHandler = options.UI.Handler
		h.uiCSP = options.UI.PageContentSecurityPolicy
	}
	h.accessLog = newAccessLog(options.AccessLogWriter, func(err error) {
		if options.OnAccessLogError != nil {
			options.OnAccessLogError(err)
			return
		}
		h.logger.Error("HTTP 访问日志写入失败", "error_category", "access_log_write_failed")
	})
	h.routes = []route{
		{method: http.MethodGet, path: routePath(h.prefix, healthSuffix), handle: h.handleHealth},
		{method: http.MethodGet, path: routePath(h.prefix, openAPISuffix), handle: h.handleOpenAPI},
	}
	h.routes = append(h.routes, options.extraRoutes...)
	return h, nil
}

// handleHealth 返回固定最小健康响应；不读配置、不探数据库、不输出密钥或版本。
func (h *handler) handleHealth(_ context.Context, w *responseWriter, _ *http.Request) error {
	header := w.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(healthBody))
	return err
}

// ServeHTTP 是 Handler 入口：建立请求编号、应用安全头、并发/期限保护、恢复
// panic、执行路由与限流/CORS/CSRF 检查，并写访问日志。
func (h *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	started := h.now().UTC()
	tracker := newResponseWriter(writer)
	requestID := h.resolveRequestID(request)
	tracker.Header().Set("X-Request-ID", requestID)
	ctx := WithRequestID(request.Context(), requestID)
	request = request.WithContext(ctx)
	logPath := sanitizeLogPath(request.URL.EscapedPath())
	tracker.logPath = logPath
	clientIP := h.clientIP(request)
	if h.protection != nil {
		h.protection.applySecurityHeaders(tracker.Header())
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			// 只记录消息模板与请求编号；不把 panic 值、请求内容或堆栈写入日志
			// 或响应，避免泄露秘密。
			h.logger.Error("HTTP 请求处理发生 panic", "request_id", requestID)
			if !tracker.wroteHeader {
				writeProblem(tracker, requestID, internalProblem())
			}
		}
		status := tracker.Status()
		if status == 0 {
			if request.Context().Err() != nil {
				status = clientClosedStatus
			} else {
				status = http.StatusOK
			}
		}
		finished := h.now().UTC()
		h.accessLog.log(accessEntry{
			started:       started,
			finished:      finished,
			remoteAddr:    clientIP,
			method:        request.Method,
			path:          tracker.logPath,
			status:        status,
			responseBytes: tracker.bytes,
			requestBytes:  contentLengthOrUnknown(request),
			protocol:      request.Proto,
			userAgent:     request.UserAgent(),
			referer:       request.Referer(),
			requestID:     requestID,
			errorCode:     tracker.errorCode,
		})
	}()

	var requestProblem *problem
	if h.protection == nil {
		requestProblem = h.serve(ctx, tracker, request)
	} else if release, acquired := h.protection.tryAcquire(); !acquired {
		requestProblem = newRateLimitedProblem(time.Second, "并发请求过多，请稍后重试")
	} else {
		defer release()
		requestCtx, cancel := context.WithTimeout(ctx, h.protection.requestTimeout)
		defer cancel()
		request = request.WithContext(requestCtx)
		h.setResponseDeadline(tracker, h.protection.requestTimeout)
		requestProblem = h.serveWithTimeout(requestCtx, tracker, request, h.protection.requestTimeout)
	}
	if requestProblem != nil {
		if requestProblem.status == clientClosedStatus {
			writeClientClosed(tracker)
			return
		}
		if requestProblem.status >= http.StatusInternalServerError && requestProblem.code == "INTERNAL_ERROR" {
			logInternalError(h.logger, requestID, tracker.logPath)
		}
		writeProblem(tracker, requestID, requestProblem)
	}
}

// serve 执行路径校验、路由匹配、身份建立与处理程序调用。
func (h *handler) serve(ctx context.Context, tracker *responseWriter, request *http.Request) *problem {
	if request.ContentLength > h.maxBodyBytes {
		return newProblem(http.StatusRequestEntityTooLarge, "REQ_INVALID", "请求体超过允许的大小")
	}
	// 统一包装请求体，让所有处理程序都受同一上限约束；超限在读取时映射为 413。
	request.Body = http.MaxBytesReader(tracker, request.Body, h.maxBodyBytes)

	path, pathProblem := canonicalRequestPath(request)
	if pathProblem != nil {
		return pathProblem
	}
	tracker.logPath = sanitizeLogPath(path)
	clientIP := h.clientIP(request)
	if h.protection != nil {
		if problem := h.checkRateLimit(h.protection.rateLimits.clientIP, "ip:"+clientIP); problem != nil {
			return problem
		}
	}
	if isOAuthReservedPath(h.prefix, path) {
		// OAuth/OIDC 标准响应空间保留：不使用统一业务错误信封，也不做 CORS
		// 预检重写，避免把保留协议路径伪装成普通 API 路由。
		http.NotFound(tracker, request)
		return nil
	}
	if h.uiHandler != nil && h.isUIRequestPath(path) {
		// HTML 页面：复用同一客户端 IP 限流（上方已执行）、CSRF 中间件与请求编号；
		// 页面自己建立会话，不经过 API IdentityResolver；不使用 API CORS 头，显式
		// 写入页面 CSP（覆盖 API 默认 CSP）后交给页面处理器。
		if h.protection != nil {
			if problem := h.checkRateLimit(h.protection.rateLimits.endpoint,
				request.Method+" "+path); problem != nil {
				return problem
			}
			if problem := h.protection.csrf.check(ctx, request); problem != nil {
				return problem
			}
		}
		if h.uiCSP != "" {
			tracker.Header().Set("Content-Security-Policy", h.uiCSP)
		}
		h.uiHandler.ServeHTTP(tracker, request)
		if ctx.Err() == context.DeadlineExceeded {
			return timeoutProblem()
		}
		return nil
	}
	if h.protection != nil {
		if handled, corsProblem := h.protection.cors.handlePreflight(tracker, request); handled {
			return corsProblem
		}
		origin, corsProblem := h.protection.cors.checkOrigin(request)
		if corsProblem != nil {
			return corsProblem
		}
		h.protection.cors.writeActualHeaders(tracker.Header(), origin)
	}

	var allowedMethods []string
	var matched *route
	for index := range h.routes {
		candidate := &h.routes[index]
		if candidate.path != path {
			continue
		}
		if candidate.method != request.Method {
			allowedMethods = append(allowedMethods, candidate.method)
			continue
		}
		matched = candidate
		break
	}
	if matched == nil {
		if len(allowedMethods) > 0 {
			tracker.Header().Set("Allow", strings.Join(allowedMethods, ", "))
			return newProblem(http.StatusMethodNotAllowed, "REQ_INVALID", "请求方法不受支持")
		}
		return newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
	}
	if h.protection != nil {
		if problem := h.checkRateLimit(h.protection.rateLimits.endpoint, request.Method+" "+path); problem != nil {
			return problem
		}
	}
	// GET 只读端点不接受请求体：已知长度或 chunked 都拒绝，避免把大体积请求体
	// 带进不需要它的处理路径。
	if matched.method == http.MethodGet && (request.ContentLength > 0 || len(request.TransferEncoding) > 0) {
		return newProblem(http.StatusBadRequest, "REQ_INVALID", "该接口不接受请求体")
	}
	if matched.requiresIdentity {
		identity, identityProblem := h.resolveRequestIdentity(ctx, request)
		if identityProblem != nil {
			return identityProblem
		}
		ctx = WithIdentity(ctx, identity)
		request = request.WithContext(ctx)
	}
	if h.protection != nil {
		if problem := h.checkIdentityRateLimits(ctx); problem != nil {
			return problem
		}
		if problem := h.protection.csrf.check(ctx, request); problem != nil {
			return problem
		}
		if h.protection.isExpensivePath(path) {
			if problem := h.checkExpensiveBudget(ctx, clientIP); problem != nil {
				return problem
			}
		}
	}
	if err := matched.handle(ctx, tracker, request); err != nil {
		if errors.Is(err, context.Canceled) && request.Context().Err() != nil {
			return &problem{status: clientClosedStatus, code: "REQ_INVALID", message: "客户端已取消请求"}
		}
		return problemFromError(ctx, err)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return timeoutProblem()
	}
	return nil
}

// resolveRequestID 返回本次请求编号：合法且唯一的客户端 X-Request-ID 可复用，
// 否则生成新编号。客户端编号只用于关联排障，绝不参与授权判断；非法值不会被
// 回显到响应或日志。
func (h *handler) resolveRequestID(request *http.Request) string {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 {
		candidate := strings.TrimSpace(values[0])
		if len(candidate) <= 64 && h.validateRequestID(candidate) == nil {
			return candidate
		}
	}
	return h.newRequestID()
}

// isOAuthReservedPath 报告路径是否落在保留的 OAuth/OIDC 协议空间。
func isOAuthReservedPath(prefix, path string) bool {
	reserved := routePath(prefix, OAuthReservedPrefix)
	return path == reserved || strings.HasPrefix(path, reserved+"/")
}

// sanitizeLogPath 把路径限制为可安全写入访问日志的 ASCII 文本；非 ASCII 或控制
// 字符按字段转义规则处理，避免日志注入。
func sanitizeLogPath(path string) string {
	if path == "" {
		return "-"
	}
	return w3cToken(path, maxAccessLogValueBytes)
}

// isUIRequestPath 报告路径是否应交给页面处理器：固定 API 路由（健康/OpenAPI 等，
// 含方法不匹配场景）优先保持 JSON 语义；OAuth/OIDC 保留路径在此之前已返回 404；
// 其余路径在挂载页面处理器时视为 HTML 路径（未知页面由页面处理器渲染 404）。
func (h *handler) isUIRequestPath(path string) bool {
	for index := range h.routes {
		if h.routes[index].path == path {
			return false
		}
	}
	return true
}
