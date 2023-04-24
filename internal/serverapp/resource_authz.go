package serverapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	"github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
)

// resourceAuthorizeHandler 实现扩展联合判定端点（非标准 OAuth）：
// 调用方必须是已登记受信资源服务的 confidential OAuth 客户端（Basic secret 或
// 已验证 TLS 客户端证书），请求体中的 app_id/audience 只能作为“从登记白名单中
// 选择”的提示，绝不能作为身份或权限来源。
type resourceAuthorizeHandler struct {
	registry *resourceRegistry
	oauth    *oauthclient.Service
	service  *tokenauthz.Service
	now      func() time.Time
}

type resourceAuthorizeRequest struct {
	AccessToken    string   `json:"access_token"`
	Permissions    []string `json:"permissions"`
	Mode           string   `json:"mode,omitempty"`
	ResourceID     string   `json:"resource_id,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
	Audience       string   `json:"audience,omitempty"`
}

type resourceAuthorizeError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

const maxResourceAuthorizeBody = 64 << 10

// buildResourceAuthorizeHandler 构造联合判定处理器；未登记资源服务时返回 nil。
func buildResourceAuthorizeHandler(deps Deps, registry *resourceRegistry,
	oauth *oauthclient.Service, tokenService *token.Service, flow *oauthflow.Service,
	tokenClients token.ClientSource, permissions *authz.Service) (http.Handler, error) {
	if registry == nil || len(registry.byClient) == 0 {
		return nil, nil
	}
	if oauth == nil || tokenService == nil || flow == nil || tokenClients == nil || permissions == nil {
		return nil, fmt.Errorf("联合判定缺少客户端/令牌/撤销/权限依赖")
	}
	service, err := tokenauthz.New(tokenauthz.Options{
		Verifier: tokenService, Clients: tokenClients, Revocations: flow,
		Permissions: permissions, ServicePrincipals: failClosedServicePrincipals{},
		Audit: deps.Audit, Logger: deps.Logger, Now: deps.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("构造联合判定服务失败: %w", err)
	}
	return &resourceAuthorizeHandler{registry: registry, oauth: oauth,
		service: service, now: deps.Now}, nil
}

func (h *resourceAuthorizeHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := login.NewRequestID()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Request-ID", requestID)
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeResourceError(writer, http.StatusMethodNotAllowed, "REQ_INVALID", "只支持 POST", requestID)
		return
	}
	clientID, secret, ok := request.BasicAuth()
	if !ok || strings.TrimSpace(clientID) == "" || secret == "" {
		writeResourceError(writer, http.StatusUnauthorized, "CLIENT_AUTH_FAILED", "资源服务认证失败", requestID)
		return
	}
	identity, err := h.oauth.VerifyClientSecret(request.Context(), clientID, secret)
	if err != nil {
		writeResourceError(writer, http.StatusUnauthorized, "CLIENT_AUTH_FAILED", "资源服务认证失败", requestID)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxResourceAuthorizeBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload resourceAuthorizeRequest
	if err := decoder.Decode(&payload); err != nil {
		if errors.Is(err, io.EOF) {
			writeResourceError(writer, http.StatusBadRequest, "REQ_INVALID", "请求体为空", requestID)
			return
		}
		writeResourceError(writer, http.StatusBadRequest, "REQ_INVALID", "请求体无效或包含未知字段", requestID)
		return
	}
	if payload.AccessToken == "" || len(payload.Permissions) == 0 {
		writeResourceError(writer, http.StatusBadRequest, "REQ_INVALID", "access_token 与 permissions 必填", requestID)
		return
	}
	entry, err := h.registry.resolve(identity.ClientID, payload.Audience)
	if err != nil {
		writeResourceError(writer, http.StatusForbidden, "ACCESS_DENIED", "调用方不是该 audience 的受信资源服务", requestID)
		return
	}
	resourceService, err := tokenauthz.NewResourceService(entry.ServiceID, entry.ClientID, entry.Audience)
	if err != nil {
		writeResourceError(writer, http.StatusInternalServerError, "INTERNAL_ERROR", "资源身份构造失败", requestID)
		return
	}
	decision, err := h.service.Decide(request.Context(), resourceService, tokenauthz.Request{
		AccessToken: payload.AccessToken, Permissions: payload.Permissions,
		Mode: authz.Mode(strings.TrimSpace(payload.Mode)), ResourceID: payload.ResourceID,
		RequestID: requestID, RequiredScopes: payload.RequiredScopes,
	})
	if err != nil {
		switch {
		case errors.Is(err, tokenauthz.ErrInvalidRequest):
			writeResourceError(writer, http.StatusBadRequest, "REQ_INVALID", "请求内容无效", requestID)
		case errors.Is(err, tokenauthz.ErrUnavailable):
			writeResourceError(writer, http.StatusServiceUnavailable, "AUTHZ_UNAVAILABLE",
				"暂时无法判定访问权限", requestID)
		default:
			writeResourceError(writer, http.StatusInternalServerError, "INTERNAL_ERROR", "判定失败", requestID)
		}
		return
	}
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(decision)
}

func writeResourceError(writer http.ResponseWriter, status int, code, message, requestID string) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(resourceAuthorizeError{
		Code: code, Message: message, RequestID: requestID,
	})
}

// failClosedServicePrincipals 表示服务身份（client_credentials）的业务权限模型
// 尚未由宿主策略提供：任何权限要求都拒绝，不把持有服务令牌当作自动授权。
type failClosedServicePrincipals struct{}

func (failClosedServicePrincipals) AuthorizeServicePrincipal(context.Context,
	tokenauthz.ResourceService, tokenauthz.ServicePrincipal,
	tokenauthz.ServicePermissionRequest) (tokenauthz.ServicePrincipalDecision, error) {
	return tokenauthz.ServicePrincipalDecision{Allow: false, Code: tokenauthz.CodeAccessDenied,
		Reason: "service_principal_not_configured"}, nil
}

var _ = context.Background
