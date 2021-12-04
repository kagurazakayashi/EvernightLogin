package protocolapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// handleToken 处理 POST /oauth/token：authorization_code、refresh_token、
// client_credentials 与设备码 grant 全部交给 internal/oauthflow 的真实服务执行；
// 本函数只做标准表单解析、客户端认证材料解包与标准 JSON 响应。令牌明文只在响应
// 体出现一次，绝不写日志/审计/其他响应头。
func (s *Server) handleToken(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		s.writeOAuthMethodNotAllowed(writer, request, requestID, http.MethodPost)
		return
	}
	form, ok := s.readForm(writer, request, requestID)
	if !ok {
		return
	}
	client, ok := s.resolveClientAuth(writer, request, form, requestID)
	if !ok {
		return
	}
	grantType, err := singleParam(form, "grant_type")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 grant_type")
		return
	}
	if strings.TrimSpace(grantType) == "" {
		s.writeOAuthInvalidRequest(writer, request, requestID, "缺少 grant_type")
		return
	}
	code, err := singleParam(form, "code")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 code")
		return
	}
	redirectURI, err := singleParam(form, "redirect_uri")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 redirect_uri")
		return
	}
	codeVerifier, err := singleParam(form, "code_verifier")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 code_verifier")
		return
	}
	refreshToken, err := singleParam(form, "refresh_token")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 refresh_token")
		return
	}
	deviceCode, err := singleParam(form, "device_code")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 device_code")
		return
	}
	response, exchangeErr := s.opts.OAuth.Exchange(request.Context(), oauthflow.ExchangeRequest{
		GrantType: grantType, Code: code, RedirectURI: redirectURI,
		ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		ClientCertificatePEM: client.CertificatePEM, CodeVerifier: codeVerifier,
		DeviceCode: deviceCode, Scope: listParam(form, "scope"),
		Resource: listParam(form, "resource"), RequestID: requestID,
		RefreshToken: refreshToken,
	})
	if exchangeErr != nil {
		s.writeOAuthError(writer, request, requestID, oauthServiceError(exchangeErr))
		return
	}
	payload := map[string]any{
		"access_token": response.AccessToken.Reveal(),
		"token_type":   TokenTypeBearer,
		"expires_in":   response.ExpiresIn,
	}
	if response.Scope != "" {
		payload["scope"] = response.Scope
	}
	if response.RefreshToken.IsSet() {
		payload["refresh_token"] = response.RefreshToken.Reveal()
	}
	if response.IDToken.IsSet() {
		payload["id_token"] = response.IDToken.Reveal()
	}
	header := writer.Header()
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerPragma, headerNoCache)
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// handleUserInfo 处理 GET/POST /oauth/userinfo：只从 Authorization: Bearer 读取
// 访问令牌（拒绝把令牌放查询串/请求体，避免进入 URL 与访问日志）。字段按 scope
// 裁剪与在线撤销检查由 internal/oidc 完成。
func (s *Server) handleUserInfo(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		writer.Header().Set(headerAllow, "GET, POST")
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	if request.URL.Query().Get("access_token") != "" {
		// RFC 6750 允许 URI 查询传令牌，但那会让令牌进入 URL/访问日志；本项目
		// 明确拒绝，客户端必须使用 Authorization: Bearer。
		s.writeUserInfoError(writer, request, requestID, "invalid_request",
			"访问令牌只能通过 Authorization: Bearer 传递", http.StatusBadRequest)
		return
	}
	accessToken, ok := s.bearerToken(request)
	if !ok {
		s.writeUserInfoError(writer, request, requestID, "invalid_token",
			"缺少或非法的访问令牌", http.StatusUnauthorized)
		return
	}
	info, err := s.opts.OIDC.UserInfo(request.Context(), accessToken)
	if err != nil {
		protocolErr := oidcServiceError(err)
		s.logRejected(request, requestID, "userinfo_"+protocolErr.Code)
		s.writeUserInfoError(writer, request, requestID, protocolErr.Code,
			protocolErr.Description, protocolErr.Status)
		return
	}
	writeJSON(writer, http.StatusOK, requestID, info)
}

// writeUserInfoError 写 RFC 6750 错误响应（含 Bearer 认证挑战）。
func (s *Server) writeUserInfoError(writer http.ResponseWriter, request *http.Request,
	requestID, code, description string, status int) {
	if status < 400 || status > 599 {
		status = http.StatusUnauthorized
	}
	challenge := "Bearer"
	switch code {
	case "invalid_token", "insufficient_scope", "invalid_request":
		// 认证挑战头保持纯 ASCII：描述只放在 JSON 正文，避免非 ASCII 头值被
		// 中间代理拒绝或产生响应头注入风险。
		challenge = `Bearer error="` + code + `"`
	}
	writer.Header().Set(headerWwwAuth, challenge)
	writeJSON(writer, status, requestID, map[string]string{
		"error": code, "error_description": description})
}

// handleRevoke 处理 POST /oauth/revoke（RFC 7009）：客户端认证后只撤销自己的令牌；
// 未知/已撤销令牌也返回 200，避免令牌存在性枚举。成功响应为空正文。
func (s *Server) handleRevoke(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		s.writeOAuthMethodNotAllowed(writer, request, requestID, http.MethodPost)
		return
	}
	form, ok := s.readForm(writer, request, requestID)
	if !ok {
		return
	}
	client, ok := s.resolveClientAuth(writer, request, form, requestID)
	if !ok {
		return
	}
	if client.ClientID == "" {
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "invalid_client", Description: "缺少客户端身份", HTTPStatus: http.StatusUnauthorized})
		return
	}
	tokenValue, err := singleParam(form, "token")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 token")
		return
	}
	tokenTypeHint, err := singleParam(form, "token_type_hint")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 token_type_hint")
		return
	}
	revokeErr := s.opts.OAuth.RevokeToken(request.Context(), oauthflow.RevokeTokenRequest{
		ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		ClientCertificatePEM: client.CertificatePEM, Token: tokenValue,
		TokenTypeHint: tokenTypeHint, RequestID: requestID,
	})
	if revokeErr != nil {
		s.writeOAuthError(writer, request, requestID, oauthServiceError(revokeErr))
		return
	}
	writer.Header().Set(headerCacheControl, headerNoStore)
	writer.Header().Set(headerNosniff, "nosniff")
	if requestID != "" {
		writer.Header().Set(headerRequestID, requestID)
	}
	writer.WriteHeader(http.StatusOK)
}

// introspectionResponse 是 RFC 7662 状态查询响应；只在 active=true 时填充元数据，
// 主体标识只在服务层授权披露（ShowSubject）时出现。
type introspectionResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Audience  any    `json:"aud,omitempty"`
	Subject   string `json:"sub,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// handleIntrospect 处理 POST /oauth/introspect（RFC 7662）。调用者必须是经过客户端
// 认证的资源服务/客户端；ResourceServerClientID 只来自认证结果，绝不接受参数自称。
func (s *Server) handleIntrospect(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodPost {
		s.writeOAuthMethodNotAllowed(writer, request, requestID, http.MethodPost)
		return
	}
	form, ok := s.readForm(writer, request, requestID)
	if !ok {
		return
	}
	client, ok := s.resolveClientAuth(writer, request, form, requestID)
	if !ok {
		return
	}
	if client.ClientID == "" || (client.ClientSecret == "" && client.CertificatePEM == "") {
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "invalid_client", Description: "状态查询必须完成客户端身份验证",
			HTTPStatus: http.StatusUnauthorized})
		return
	}
	identity, authErr := s.verifyClientIdentity(request.Context(), client.ClientID,
		client.ClientSecret, client.CertificatePEM)
	if authErr != nil || identity.ClientID != client.ClientID {
		s.logRejected(request, requestID, "introspect_client_auth_failed")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "invalid_client", Description: "客户端身份验证失败",
			HTTPStatus: http.StatusUnauthorized})
		return
	}
	tokenValue, err := singleParam(form, "token")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 token")
		return
	}
	tokenTypeHint, err := singleParam(form, "token_type_hint")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 token_type_hint")
		return
	}
	audience, err := singleParam(form, "audience")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 audience")
		return
	}
	if audience == "" {
		// 兼容 RFC 8707 风格的 resource 参数（单个值）；多个视为无效。
		audience, err = singleParam(form, "resource")
		if err != nil {
			s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 resource")
			return
		}
	}
	inspection, inspectErr := s.opts.OAuth.InspectToken(request.Context(),
		oauthflow.TokenInspectRequest{Token: tokenValue, TokenTypeHint: tokenTypeHint,
			Audience: audience, ResourceServerClientID: identity.ClientID, RequestID: requestID})
	if inspectErr != nil {
		s.writeOAuthError(writer, request, requestID, oauthServiceError(inspectErr))
		return
	}
	response := introspectionResponse{Active: inspection.Active}
	if inspection.Active {
		response.TokenType = inspection.TokenType
		response.ClientID = inspection.ClientID
		response.Scope = inspection.Scope
		response.Subject = inspection.Subject
		if len(inspection.Audience) == 1 {
			response.Audience = inspection.Audience[0]
		} else if len(inspection.Audience) > 1 {
			response.Audience = append([]string(nil), inspection.Audience...)
		}
		if !inspection.IssuedAt.IsZero() {
			response.IssuedAt = inspection.IssuedAt.Unix()
		}
		if !inspection.ExpiresAt.IsZero() {
			response.ExpiresAt = inspection.ExpiresAt.Unix()
		}
	}
	writeJSON(writer, http.StatusOK, requestID, response)
}

// verifyClientIdentity 用真实客户端认证服务验证 secret/证书；证书必须来自已完成
// 验证的 TLS 链（见 verifiedClientCertificatePEM），不接受未验证证书当身份。
func (s *Server) verifyClientIdentity(ctx context.Context, clientID, clientSecret,
	certificatePEM string) (oauthclient.ClientIdentity, error) {
	if s.opts.ClientAuth == nil {
		return oauthclient.ClientIdentity{}, oauthclient.ErrClientAuthFailed
	}
	if clientSecret != "" {
		return s.opts.ClientAuth.VerifyClientSecret(ctx, clientID, clientSecret)
	}
	return s.opts.ClientAuth.VerifyClientCertificate(ctx, clientID, certificatePEM)
}
