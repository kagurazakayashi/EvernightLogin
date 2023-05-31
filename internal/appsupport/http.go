package appsupport

// 应用受限客服 HTTP 传输：/api/app/v1/support。认证只用 OAuth 用户委托 Access Token
// （Authorization: Bearer）；app_id/操作者均来自 TokenValidator，不接受 header/query/
// 路径自报。本 API 只创建人工升级申请，不提供改密/MFA/恢复链接/审批执行。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

const (
	// DefaultBasePath 是应用客服 API 默认挂载前缀。
	DefaultBasePath = "/api/app/v1/support"
	// DefaultMaxBodyBytes 是请求体上限（32 KiB）。
	DefaultMaxBodyBytes int64 = 32 * 1024
)

// HTTPOptions 构造应用客服 HTTP Handler。
type HTTPOptions struct {
	Service      *Service
	BasePath     string
	MaxBodyBytes int64
	Logger       *slog.Logger
	Random       io.Reader
}

// HTTPHandler 是应用客服 API handler。
type HTTPHandler struct {
	service      *Service
	basePath     string
	maxBodyBytes int64
	logger       *slog.Logger
	random       io.Reader
}

// NewHTTPHandler 校验依赖并构造 handler。
func NewHTTPHandler(options HTTPOptions) (*HTTPHandler, error) {
	if options.Service == nil {
		return nil, errors.New("应用客服 handler 缺少 service")
	}
	basePath := strings.TrimSpace(options.BasePath)
	if basePath == "" {
		basePath = DefaultBasePath
	}
	if !strings.HasPrefix(basePath, "/") || strings.HasSuffix(basePath, "/") ||
		strings.Contains(basePath, "//") {
		return nil, errors.New("应用客服 API 前缀非法")
	}
	maxBody := options.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	if maxBody > 1<<20 {
		return nil, errors.New("应用客服请求体上限过大")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &HTTPHandler{service: options.Service, basePath: basePath,
		maxBodyBytes: maxBody, logger: options.Logger, random: options.Random}, nil
}

// BasePath 返回挂载前缀。
func (h *HTTPHandler) BasePath() string { return h.basePath }

type successEnvelope struct {
	RequestID  string `json:"request_id"`
	APIVersion string `json:"api_version"`
	Data       any    `json:"data,omitempty"`
}

type errorEnvelope struct {
	RequestID  string `json:"request_id"`
	APIVersion string `json:"api_version"`
	Error      struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}

type createCasePayload struct {
	TargetUserID string `json:"target_user_id"`
	Reason       string `json:"reason"`
}

// ServeHTTP 处理 Bearer Token、版本/request_id、严格 JSON 与路由。
func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := h.requestID(request)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if requestID == "" {
		h.writeError(writer, "", http.StatusBadRequest, "REQ_INVALID", "请求编号非法")
		return
	}
	if strings.TrimSpace(request.Header.Get("X-Evernight-API-Version")) != "v1" {
		h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "缺少或不支持的 API 版本")
		return
	}
	if values := request.URL.Query(); len(values) > 0 {
		for key := range values {
			if strings.EqualFold(key, "app_id") || strings.EqualFold(key, "application_id") {
				h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID",
					"应用标识只能来自访问令牌")
				return
			}
		}
	}
	token, ok := bearerToken(request)
	if !ok {
		h.writeError(writer, requestID, http.StatusUnauthorized, "ACCESS_DENIED", "缺少访问令牌")
		return
	}
	route, ok := h.parsePath(request.URL.Path)
	if !ok {
		h.writeError(writer, requestID, http.StatusNotFound, "REQ_INVALID", "不存在的应用客服路由")
		return
	}
	switch route.action {
	case "collection":
		switch request.Method {
		case http.MethodGet:
			offset, limit := 0, 20
			if raw := strings.TrimSpace(request.URL.Query().Get("offset")); raw != "" {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed < 0 {
					h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "offset 非法")
					return
				}
				offset = parsed
			}
			if raw := strings.TrimSpace(request.URL.Query().Get("limit")); raw != "" {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed < 1 {
					h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "limit 非法")
					return
				}
				limit = parsed
			}
			cases, hasMore, err := h.service.ListCases(request.Context(), token, offset, limit)
			if err != nil {
				h.writeServiceError(writer, requestID, err)
				return
			}
			h.writeSuccess(writer, requestID, map[string]any{"cases": cases, "has_more": hasMore})
		case http.MethodPost:
			body, err := readJSONBody(request, h.maxBodyBytes)
			if err != nil {
				h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "请求体缺失或过大")
				return
			}
			var payload createCasePayload
			if err := decodeStrict(body, &payload); err != nil {
				h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID",
					"请求体只允许 target_user_id 与 reason，且不接受密码/MFA/恢复材料")
				return
			}
			view, err := h.service.CreateCase(request.Context(), token, CreateCaseRequest{
				TargetUserID: payload.TargetUserID, Reason: payload.Reason, RequestID: requestID})
			if err != nil {
				h.writeServiceError(writer, requestID, err)
				return
			}
			h.writeSuccess(writer, requestID, view)
		default:
			h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "方法不允许")
		}
	case "get":
		if request.Method != http.MethodGet {
			h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "方法不允许")
			return
		}
		view, err := h.service.GetCase(request.Context(), token, route.caseID)
		if err != nil {
			h.writeServiceError(writer, requestID, err)
			return
		}
		h.writeSuccess(writer, requestID, view)
	case "approve":
		h.writeError(writer, requestID, http.StatusForbidden, "PERMISSION_REQUIRED",
			"全局恢复审批/执行必须由系统 recovery.approve 完成，应用管理员不能自批")
	default:
		h.writeError(writer, requestID, http.StatusNotFound, "REQ_INVALID", "不存在的应用客服路由")
	}
}

type routeInfo struct {
	action string
	caseID string
}

func (h *HTTPHandler) parsePath(path string) (routeInfo, bool) {
	if !strings.HasPrefix(path, h.basePath+"/") || strings.Contains(path, "//") ||
		strings.HasSuffix(path, "/") {
		return routeInfo{}, false
	}
	relative := strings.TrimPrefix(path, h.basePath+"/")
	parts := strings.Split(relative, "/")
	if len(parts) == 1 && parts[0] == "cases" {
		return routeInfo{action: "collection"}, true
	}
	if len(parts) >= 2 && parts[0] == "cases" && parts[1] != "" {
		switch len(parts) {
		case 2:
			return routeInfo{action: "get", caseID: parts[1]}, true
		case 3:
			if parts[2] == "approve" {
				return routeInfo{action: "approve", caseID: parts[1]}, true
			}
		}
	}
	return routeInfo{}, false
}

func bearerToken(request *http.Request) (string, bool) {
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(authorization[len("bearer "):])
	if token == "" || len(token) > 8192 {
		return "", false
	}
	return token, true
}

func (h *HTTPHandler) requestID(request *http.Request) string {
	value := strings.TrimSpace(request.Header.Get("X-Request-Id"))
	if value == "" {
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(h.random, buffer); err != nil {
			return ""
		}
		value = "req_" + hex.EncodeToString(buffer)
	}
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func (h *HTTPHandler) writeSuccess(writer http.ResponseWriter, requestID string, data any) {
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(successEnvelope{RequestID: requestID,
		APIVersion: "v1", Data: data})
}

func (h *HTTPHandler) writeServiceError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, ErrIdentityUnavailable):
		h.writeError(writer, requestID, http.StatusUnauthorized, "ACCESS_DENIED", "访问令牌或客服身份不可用")
	case errors.Is(err, ErrAccessDenied):
		h.writeError(writer, requestID, http.StatusForbidden, "ACCESS_DENIED", "当前客服主体无权执行该操作")
	case errors.Is(err, ErrGlobalApprovalOnly):
		h.writeError(writer, requestID, http.StatusForbidden, "PERMISSION_REQUIRED",
			"全局恢复审批/执行必须由系统 recovery.approve 完成")
	case errors.Is(err, ErrInvalidRequest):
		h.writeError(writer, requestID, http.StatusBadRequest, "REQ_INVALID", "请求参数未通过校验")
	default:
		h.writeError(writer, requestID, http.StatusServiceUnavailable, "INTERNAL_ERROR", "应用客服暂时不可用")
	}
}

func (h *HTTPHandler) writeError(writer http.ResponseWriter, requestID string, status int,
	code, message string) {
	writer.WriteHeader(status)
	envelope := errorEnvelope{RequestID: requestID, APIVersion: "v1"}
	envelope.Error.Code = code
	envelope.Error.Message = message
	_ = json.NewEncoder(writer).Encode(envelope)
}

func readJSONBody(request *http.Request, limit int64) ([]byte, error) {
	if request.Body == nil {
		return nil, errors.New("empty body")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil || int64(len(body)) > limit || len(body) == 0 {
		return nil, errors.New("invalid body")
	}
	return body, nil
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("extra json")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
