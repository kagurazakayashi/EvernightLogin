package protocolapi

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
)

// 扫码登录端点的 JSON 请求/响应结构。二维码载荷只含一次性请求标识；领取绑定
// 只在创建/重新生成响应中出现一次，后续请求由原发起端原样带回。所有请求都要求
// Content-Type: application/json、拒绝未知字段与超限体积。
type qrBeginRequest struct {
	// ClientID 是目标应用；QRClientID 已配置时该字段可省略或必须与配置一致。
	ClientID string `json:"client_id,omitempty"`
	// Scopes 只用于确认页展示，不是令牌授权范围。
	Scopes []string `json:"scopes,omitempty"`
}

type qrClaimRequest struct {
	RequestID   string `json:"request_id"`
	ClaimSecret string `json:"claim_secret"`
}

type qrDecisionRequest struct {
	RequestID       string `json:"request_id"`
	ExpectedVersion int64  `json:"expected_version"`
	Approve         bool   `json:"approve"`
	// CSRFToken 仅在浏览器 Cookie 会话时需要（与 X-CSRF-Token 头等价的显式字段）。
	CSRFToken string `json:"csrf_token,omitempty"`
}

type qrBeginResponse struct {
	RequestID           string `json:"request_id"`
	QRPayload           string `json:"qr_payload"`
	ClaimSecret         string `json:"claim_secret"`
	ExpiresAt           string `json:"expires_at"`
	Version             int64  `json:"version"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

type qrStatusResponse struct {
	RequestID         string `json:"request_id"`
	Status            string `json:"status"`
	ExpiresAt         string `json:"expires_at"`
	Version           int64  `json:"version"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

type qrClaimResponse struct {
	Status    string `json:"status"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	AppID     string `json:"app_id,omitempty"`
	ExpiresAt string `json:"expires_at"`
}

type qrPromptResponse struct {
	RequestID       string   `json:"request_id"`
	ClientID        string   `json:"client_id"`
	ApplicationName string   `json:"application_name"`
	ClientType      string   `json:"client_type"`
	Status          string   `json:"status"`
	Scopes          []string `json:"scopes"`
	RequesterAgent  string   `json:"requester_user_agent,omitempty"`
	CreatedAt       string   `json:"created_at"`
	ExpiresAt       string   `json:"expires_at"`
	Version         int64    `json:"version"`
	Warning         string   `json:"warning"`
}

// resolveQRClientID 决定本次扫码请求的目标应用：宿主可用 QRClientID 固定它，防止
// 浏览器把扫码登录当作任意应用的会话通道；未固定时使用请求值，最终边界仍是
// qrlogin 服务的应用白名单。
func (s *Server) resolveQRClientID(writer http.ResponseWriter, request *http.Request,
	requestID, requested string) (string, bool) {
	configured := strings.TrimSpace(s.opts.QRClientID)
	requested = strings.TrimSpace(requested)
	if configured == "" {
		return requested, true
	}
	if requested != "" && requested != configured {
		s.logRejected(request, requestID, "qr_client_mismatch")
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return "", false
	}
	return configured, true
}

// qrScopes 返回本次请求展示的 scope：请求值优先，否则使用宿主配置。
func (s *Server) qrScopes(requested []string) []string {
	if len(requested) > 0 {
		return append([]string(nil), requested...)
	}
	return append([]string(nil), s.opts.QRScopes...)
}

// remoteAddress 返回 TCP 对端地址（不读取 X-Forwarded-For 等可伪造头）。该值仅
// 用于确认页展示与审计，不是授权依据。
func remoteAddress(request *http.Request) string {
	if request == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

// timeText 把时间格式化为 UTC RFC3339（空值返回空串）。
func timeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// handleQRRequest 处理 POST /oauth/qr/request：匿名发起端创建一次短时请求，响应中
// 一次性返回领取绑定（claim_secret）。二维码载荷只含 request_id，不含任何令牌、
// 会话秘密或领取绑定。
func (s *Server) handleQRRequest(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	var body qrBeginRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	clientID, ok := s.resolveQRClientID(writer, request, requestID, body.ClientID)
	if !ok {
		return
	}
	result, err := s.opts.QRLogin.Begin(request.Context(), qrlogin.BeginRequest{
		ClientID: clientID, Scopes: s.qrScopes(body.Scopes), RequestID: requestID,
		Requester: qrlogin.RequesterInfo{UserAgent: request.UserAgent(),
			Address: remoteAddress(request)},
	})
	if err != nil {
		s.writeQRProblem(writer, request, requestID, err)
		return
	}
	payload := qrBeginResponse{
		RequestID: result.RequestID, QRPayload: result.QRPayload,
		ClaimSecret: result.ClaimSecret.Reveal(), ExpiresAt: timeText(result.ExpiresAt),
		Version: result.Version, PollIntervalSeconds: result.PollIntervalSeconds,
	}
	header := writer.Header()
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerPragma, headerNoCache)
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// parseClaimRequest 解析领取绑定并换成服务层类型；格式非法按请求无效拒绝。
func parseClaimRequest(body qrClaimRequest) (qrlogin.ClaimedRequest, bool) {
	claimSecret, err := qrlogin.ClaimSecretFromString(body.ClaimSecret)
	if err != nil || strings.TrimSpace(body.RequestID) == "" {
		return qrlogin.ClaimedRequest{}, false
	}
	return qrlogin.ClaimedRequest{ClaimSecret: claimSecret, RequestID: body.RequestID}, true
}

// handleQRStatus 处理 POST /oauth/qr/status：只有同时持有请求标识与领取绑定的原
// 发起端能查询状态；服务端强制最小查询间隔（RetryAfterSeconds）。
func (s *Server) handleQRStatus(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	var body qrClaimRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	claimed, ok := parseClaimRequest(body)
	if !ok {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	claimed.AuditRequestID = requestID
	status, err := s.opts.QRLogin.Status(request.Context(), claimed)
	if err != nil {
		s.writeQRProblem(writer, request, requestID, err)
		return
	}
	payload := qrStatusResponse{RequestID: body.RequestID, Status: status.Status,
		ExpiresAt: timeText(status.ExpiresAt), Version: status.Version,
		RetryAfterSeconds: status.RetryAfterSeconds}
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// handleQRClaim 处理 POST /oauth/qr/claim：只有已批准、未过期、未被领取且持有正确
// 领取绑定的原发起端能领取；成功时把目标应用会话写入 HttpOnly Cookie，JSON 正文
// 只返回会话标识与到期时间，绝不返回会话秘密或任何 Token。
func (s *Server) handleQRClaim(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	var body qrClaimRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	claimed, ok := parseClaimRequest(body)
	if !ok {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	claimed.AuditRequestID = requestID
	issued, err := s.opts.QRLogin.Claim(request.Context(), claimed)
	if err != nil {
		s.writeQRProblem(writer, request, requestID, err)
		return
	}
	cookie, cookieErr := s.opts.Sessions.NewCookie(issued)
	if cookieErr != nil {
		s.logFailure(request, requestID, "session_cookie_failed")
		writeProblem(writer, request, http.StatusInternalServerError, codeInternalError, requestID, "")
		return
	}
	setCookie(writer, cookie)
	writer.Header().Set(headerCacheControl, headerNoStore)
	payload := qrClaimResponse{Status: qrlogin.QueryClaimed, UserID: issued.Session.UserID,
		SessionID: issued.Session.ID, AppID: issued.Session.AppID,
		ExpiresAt: timeText(issued.Session.AbsoluteExpiresAt)}
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// handleQRCancel 处理 POST /oauth/qr/cancel：原发起端取消仍待确认/已批准的请求。
func (s *Server) handleQRCancel(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	var body qrClaimRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	claimed, ok := parseClaimRequest(body)
	if !ok {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	claimed.AuditRequestID = requestID
	status, err := s.opts.QRLogin.Cancel(request.Context(), claimed)
	if err != nil {
		s.writeQRProblem(writer, request, requestID, err)
		return
	}
	writeJSON(writer, http.StatusOK, requestID, qrStatusResponse{RequestID: body.RequestID,
		Status: status.Status, ExpiresAt: timeText(status.ExpiresAt), Version: status.Version,
		RetryAfterSeconds: status.RetryAfterSeconds})
}

// handleQRRegenerate 处理 POST /oauth/qr/regenerate：同一审计事务内取消旧请求并
// 创建新请求；旧二维码/旧领取绑定立即失效，新领取绑定只在本响应出现一次。
func (s *Server) handleQRRegenerate(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	var body qrClaimRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	claimed, ok := parseClaimRequest(body)
	if !ok {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	claimed.AuditRequestID = requestID
	result, err := s.opts.QRLogin.Regenerate(request.Context(), claimed)
	if err != nil {
		s.writeQRProblem(writer, request, requestID, err)
		return
	}
	payload := qrBeginResponse{RequestID: result.RequestID, QRPayload: result.QRPayload,
		ClaimSecret: result.ClaimSecret.Reveal(), ExpiresAt: timeText(result.ExpiresAt),
		Version: result.Version, PollIntervalSeconds: result.PollIntervalSeconds}
	writer.Header().Set(headerCacheControl, headerNoStore)
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// sessionSecretOrProblem 读取会话秘密；缺失时写 401 自定义错误信封。
func (s *Server) sessionSecretOrProblem(writer http.ResponseWriter, request *http.Request,
	requestID string) (string, bool) {
	secret, ok := s.opts.Sessions.SessionSecretFromRequest(request)
	if !ok || secret == "" {
		writeProblem(writer, request, http.StatusUnauthorized, codeAuthFailed, requestID, "")
		return "", false
	}
	return secret, true
}

// promptResponse 把确认端可见上下文转换为 JSON（不含任何秘密）。
func promptResponse(prompt qrlogin.Prompt) qrPromptResponse {
	return qrPromptResponse{RequestID: prompt.RequestID, ClientID: prompt.ClientID,
		ApplicationName: prompt.ApplicationName, ClientType: prompt.ClientType,
		Status: prompt.Status, Scopes: append([]string(nil), prompt.Scopes...),
		RequesterAgent: prompt.Requester.UserAgent, CreatedAt: timeText(prompt.CreatedAt),
		ExpiresAt: timeText(prompt.ExpiresAt), Version: prompt.Version,
		Warning: prompt.Warning}
}

// handleQRPrompt 处理 GET /oauth/qr/prompt?request_id=...：确认端（已登录 APP/浏览器）
// 用真实完整会话读取待确认请求的受控上下文。不存在的请求统一返回同一错误，避免
// 探测他人请求状态。
func (s *Server) handleQRPrompt(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodGet {
		writer.Header().Set(headerAllow, http.MethodGet)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	secret, ok := s.sessionSecretOrProblem(writer, request, requestID)
	if !ok {
		return
	}
	values := request.URL.Query()
	qrRequestID, err := singleParam(values, "request_id")
	if err != nil || strings.TrimSpace(qrRequestID) == "" {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	prompt, describeErr := s.opts.QRLogin.Describe(request.Context(), qrlogin.PromptRequest{
		SessionSecret: secret, RequestID: qrRequestID, AuditRequestID: requestID})
	if describeErr != nil {
		s.writeQRProblem(writer, request, requestID, describeErr)
		return
	}
	writeJSON(writer, http.StatusOK, requestID, promptResponse(prompt))
}

// handleQRDecision 处理 POST /oauth/qr/decision：确认端批准/拒绝。批准前服务层会按
// 敏感策略要求近期认证并绑定用户/会话/安全版本快照；浏览器 Cookie 会话必须提供
// 会话绑定 CSRF 令牌（Bearer 会话不存在环境凭据，不需要 CSRF）。
func (s *Server) handleQRDecision(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, http.MethodPost)
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	secret, ok := s.sessionSecretOrProblem(writer, request, requestID)
	if !ok {
		return
	}
	var body qrDecisionRequest
	if !s.readJSONBody(writer, request, requestID, &body) {
		return
	}
	if body.RequestID == "" {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid, requestID, "")
		return
	}
	// 状态修改端点（扫码批准/拒绝）按纵深防御要求：缺少 Origin/Referer 直接拒绝，
	// 不同源拒绝；Cookie 会话还必须额外通过会话绑定 CSRF 校验。两者不可互相替代。
	if err := s.sameOrigin(request, true); err != nil {
		s.logRejected(request, requestID, "origin_rejected")
		writeProblem(writer, request, http.StatusForbidden, codeAccessDenied, requestID, "")
		return
	}
	if s.cookieSession(request) {
		if strings.TrimSpace(body.CSRFToken) == "" {
			writeProblem(writer, request, http.StatusForbidden, codeAccessDenied, requestID, "")
			return
		}
		if err := s.opts.Sessions.ValidateCSRFToken(request.Context(), request,
			body.CSRFToken); err != nil {
			s.logRejected(request, requestID, "csrf_token_invalid")
			writeProblem(writer, request, http.StatusForbidden, codeAccessDenied, requestID, "")
			return
		}
	}
	decideRequest := qrlogin.DecideRequest{SessionSecret: secret, RequestID: body.RequestID,
		ExpectedVersion: body.ExpectedVersion, AuditRequestID: requestID}
	var prompt qrlogin.Prompt
	var decideErr error
	decisionCtx := s.withSessionReauthSignals(request.Context(), secret)
	if body.Approve {
		prompt, decideErr = s.opts.QRLogin.Approve(decisionCtx, decideRequest)
	} else {
		prompt, decideErr = s.opts.QRLogin.Deny(decisionCtx, decideRequest)
	}
	if decideErr != nil {
		s.writeQRProblem(writer, request, requestID, decideErr)
		return
	}
	writeJSON(writer, http.StatusOK, requestID, promptResponse(prompt))
}
