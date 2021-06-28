package tokenauthz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// DefaultMaxBodyBytes 是联合授权判定 HTTP 请求体的默认上限：令牌最长
// token.MaxTokenBytes，加上有界的权限列表与请求标识仍有充足余量。
const DefaultMaxBodyBytes = 64 * 1024

// ResourceServiceAuthenticator 在可信边界验证 HTTP 调用者身份并解析为资源服务
// 上下文（例如 mTLS 客户端证书映射、客户端凭证认证或受信反向代理身份头），
// 不能从请求体/查询参数里的 app_id、audience 自述身份。实现必须 fail-closed：
// 未认证返回错误，绝不返回零值身份按默认放行。
type ResourceServiceAuthenticator interface {
	AuthenticateResourceService(ctx context.Context, request *http.Request) (ResourceService, error)
}

// HTTPOptions 是联合授权判定 HTTP 端点依赖。
type HTTPOptions struct {
	// Service 是已构造的判定服务；必填。
	Service *Service
	// Authenticator 是可信调用者认证器；必填（nil 时拒绝构造，不允许匿名判定）。
	Authenticator ResourceServiceAuthenticator
	// MaxBodyBytes 是请求体上限，0 使用 DefaultMaxBodyBytes；越界拒绝构造。
	MaxBodyBytes int64
	Logger       *slog.Logger
}

// HTTPHandler 是独立于标准 Token Introspection 的扩展授权判定 HTTP 端点。
// 它是标准 net/http Handler，由宿主挂载到自己的路由/中间件（本包不注册业务全局
// 路由、不启动监听）。处理完成后总是返回 JSON；请求成功处理（含业务拒绝）为
// HTTP 200，调用者认证失败/参数错误/依赖不可用按 4xx/5xx 返回统一错误信封。
type HTTPHandler struct {
	service          *Service
	auth             ResourceServiceAuthenticator
	maxBody          int64
	logger           *slog.Logger
	newRequestIDFunc func() (string, error)
}

// NewHTTPHandler 校验依赖并构造 HTTP 端点。
func NewHTTPHandler(options HTTPOptions) (*HTTPHandler, error) {
	if options.Service == nil {
		return nil, fmt.Errorf("%w: 判定服务为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Authenticator) {
		return nil, fmt.Errorf("%w: 调用者认证器为空（不允许匿名判定）", ErrOptionsInvalid)
	}
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	if maxBody < 1024 || maxBody > 1024*1024 {
		return nil, fmt.Errorf("%w: 请求体上限必须在 1KB～1MB 之间", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = options.Service.logger
	}
	handler := &HTTPHandler{
		service: options.Service, auth: options.Authenticator,
		maxBody: maxBody, logger: logger,
		newRequestIDFunc: func() (string, error) { return newRequestID(options.Service.random) },
	}
	return handler, nil
}

// handlerRequest 是 HTTP 请求体白名单；app_id/audience 等身份字段不允许出现，
// 未知字段一律拒绝（避免客户端用未识别字段自称身份）。
type handlerRequest struct {
	AccessToken    string   `json:"access_token"`
	Permissions    []string `json:"permissions"`
	Mode           string   `json:"mode,omitempty"`
	ResourceID     string   `json:"resource_id,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

// handlerError 是协议/调用失败统一错误信封。
type handlerError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id"`
}

// ServeHTTP 实现 http.Handler。
func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := h.resolveRequestID(request)
	header := writer.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Request-ID", requestID)
	if request.Method != http.MethodPost {
		header.Set("Allow", http.MethodPost)
		h.writeError(writer, http.StatusMethodNotAllowed, CodeReqInvalid, requestID)
		return
	}
	if request.ContentLength > h.maxBody {
		h.writeError(writer, http.StatusRequestEntityTooLarge, CodeReqInvalid, requestID)
		return
	}
	// 先建立可信调用者身份（只依赖传输层认证材料，不读取请求体），再解析业务
	// 请求体；认证失败的调用者不应从参数校验差异获得额外信息。
	service, err := h.auth.AuthenticateResourceService(request.Context(), request)
	if err != nil {
		// 调用者认证失败写匿名失败审计（不含请求内容/凭证），响应保持通用信息。
		h.service.recordCallerRejection(request.Context(), "http_authenticator_failed")
		h.writeError(writer, http.StatusUnauthorized, CodeClientAuthFailed, requestID)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, h.maxBody)
	payload, err := decodeHandlerRequest(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.writeError(writer, http.StatusRequestEntityTooLarge, CodeReqInvalid, requestID)
			return
		}
		h.writeError(writer, http.StatusBadRequest, CodeReqInvalid, requestID)
		return
	}
	decision, err := h.service.Decide(request.Context(), service, Request{
		AccessToken:    payload.AccessToken,
		Permissions:    payload.Permissions,
		Mode:           authz.Mode(strings.TrimSpace(payload.Mode)),
		ResourceID:     payload.ResourceID,
		RequestID:      requestID,
		RequiredScopes: payload.RequiredScopes,
	})
	if err != nil {
		h.writeServiceError(writer, request, requestID, err)
		return
	}
	h.writeJSON(writer, http.StatusOK, decision)
}

// resolveRequestID 复用合法的客户端 X-Request-ID（只用于关联排障，绝不参与
// 授权判断），否则生成新编号；非法值不回显。
func (h *HTTPHandler) resolveRequestID(request *http.Request) string {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 {
		candidate := strings.TrimSpace(values[0])
		if len(candidate) <= maxRequestIDBytes && candidate == values[0] &&
			account.ValidateRequestID(candidate) == nil {
			return candidate
		}
	}
	requestID, err := h.newRequestIDFunc()
	if err != nil || requestID == "" {
		// 随机源故障时使用固定稳定编号占位，保证每个响应仍有 request_id；
		// 判定本身仍会因无法生成编号/依赖不可用而拒绝或失败。
		return requestIDPrefix + "unavailable"
	}
	return requestID
}

// decodeHandlerRequest 严格解析请求体：拒绝未知字段、重复字段、超大输入与尾随
// 内容；空请求体按参数错误处理。
func decodeHandlerRequest(body io.Reader) (handlerRequest, error) {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var payload handlerRequest
	if err := decoder.Decode(&payload); err != nil {
		return handlerRequest{}, fmt.Errorf("%w: 请求体不是合法 JSON: %w", ErrInvalidRequest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return handlerRequest{}, fmt.Errorf("%w: 请求体包含多余内容", ErrInvalidRequest)
	}
	return payload, nil
}

// writeServiceError 把判定服务错误映射为对应 HTTP 状态与统一错误信封。
func (h *HTTPHandler) writeServiceError(writer http.ResponseWriter, request *http.Request,
	requestID string, err error) {
	if errors.Is(err, context.Canceled) && request.Context().Err() != nil {
		// 客户端已断开：不写响应正文。
		return
	}
	status := http.StatusInternalServerError
	code := CodeInternalError
	switch {
	case errors.Is(err, ErrInvalidRequest):
		status, code = http.StatusBadRequest, CodeReqInvalid
	case errors.Is(err, ErrCallerUntrusted):
		status, code = http.StatusForbidden, CodeAccessDenied
	case errors.Is(err, ErrUnavailable):
		status, code = http.StatusServiceUnavailable, CodeAuthzUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		status, code = http.StatusGatewayTimeout, CodeInternalError
	}
	if status >= http.StatusInternalServerError {
		h.logger.Warn("联合授权判定 HTTP 处理失败", "request_id", requestID,
			"error_category", "internal_error")
	}
	h.writeError(writer, status, code, requestID)
}

// writeError 写统一错误信封。
func (h *HTTPHandler) writeError(writer http.ResponseWriter, status int, code ErrorCode,
	requestID string) {
	message := MessageOf(code)
	if message == "" {
		message = MessageOf(CodeInternalError)
		code = CodeInternalError
	}
	h.writeJSON(writer, status, handlerError{Code: code, Message: message, RequestID: requestID})
}

// writeJSON 写 JSON 响应；编码失败时退化为固定 500 信封。
func (h *HTTPHandler) writeJSON(writer http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"code":"INTERNAL_ERROR","message":"服务发生未预期错误","request_id":""}`)
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
