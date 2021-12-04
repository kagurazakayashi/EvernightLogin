package protocolapi

import (
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// handleDeviceAuthorization 处理 POST /oauth/device_authorization（RFC 8628）。
// 设备码与人工短码只在本响应中出现一次；明文不写日志/审计/普通存储（服务层只存
// 摘要）。保密客户端必须完成客户端认证，公开客户端只需 client_id。
func (s *Server) handleDeviceAuthorization(writer http.ResponseWriter, request *http.Request) {
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
	response, beginErr := s.opts.OAuth.BeginDeviceAuthorization(request.Context(),
		oauthflow.DeviceAuthorizationRequest{
			ClientID: client.ClientID, ClientSecret: client.ClientSecret,
			ClientCertificatePEM: client.CertificatePEM,
			Scope:                listParam(form, "scope"), Resource: listParam(form, "resource"),
			RequestID: requestID,
		})
	if beginErr != nil {
		s.writeOAuthError(writer, request, requestID, oauthServiceError(beginErr))
		return
	}
	payload := map[string]any{
		"device_code":               response.DeviceCode.Reveal(),
		"user_code":                 response.UserCode.Reveal(),
		"verification_uri":          response.VerificationURI,
		"verification_uri_complete": response.VerificationURIComplete,
		"expires_in":                response.ExpiresIn,
		"interval":                  response.Interval,
	}
	header := writer.Header()
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerPragma, headerNoCache)
	writeJSON(writer, http.StatusOK, requestID, payload)
}

// handleDeviceCancel 处理 POST /oauth/device/cancel（本包扩展）。必须绑定申请时的
// 同一 client_id（保密客户端还需客户端认证）；取消只影响该请求，不改变用户授权。
func (s *Server) handleDeviceCancel(writer http.ResponseWriter, request *http.Request) {
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
	deviceCode, err := singleParam(form, "device_code")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 device_code")
		return
	}
	cancelErr := s.opts.OAuth.CancelDeviceAuthorization(request.Context(),
		oauthflow.DeviceCancelRequest{
			DeviceCode: deviceCode, ClientID: client.ClientID,
			ClientSecret: client.ClientSecret, ClientCertificatePEM: client.CertificatePEM,
			RequestID: requestID,
		})
	if cancelErr != nil {
		s.writeOAuthError(writer, request, requestID, oauthServiceError(cancelErr))
		return
	}
	writer.Header().Set(headerCacheControl, headerNoStore)
	writer.Header().Set(headerNosniff, "nosniff")
	if requestID != "" {
		writer.Header().Set(headerRequestID, requestID)
	}
	writer.WriteHeader(http.StatusNoContent)
}
