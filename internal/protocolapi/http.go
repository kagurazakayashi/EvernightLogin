package protocolapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
)

// 稳定错误码字面值：全部复用根包既有错误码注册表，本包不新增码。协议标准端点
// 使用 RFC 6749/6750/7009/7662/8628 的 error/error_description；自定义扫码端点
// 使用项目统一错误信封 {code,message,request_id}。
const (
	codeReqInvalid       = "REQ_INVALID"
	codeAuthFailed       = "AUTH_FAILED"
	codeAccessDenied     = "ACCESS_DENIED"
	codeChallengeInvalid = "CHALLENGE_INVALID"
	codeConflict         = "CONFLICT"
	codeRateLimited      = "RATE_LIMITED"
	codeClientDisabled   = "CLIENT_DISABLED"
	codeDBUnavailable    = "DB_UNAVAILABLE"
	codeAuditWriteFailed = "AUDIT_WRITE_FAILED"
	codeInternalError    = "INTERNAL_ERROR"
	codeTokenInvalid     = "TOKEN_INVALID"
	codeUserDisabled     = "USER_DISABLED"
	codeClientAuthFailed = "CLIENT_AUTH_FAILED"
)

// errorMessages 是稳定错误码的公开中文说明（单行、不含内部细节）。
var errorMessages = map[string]string{
	codeReqInvalid:       "请求参数无效",
	codeAuthFailed:       "身份验证失败",
	codeAccessDenied:     "请求未获准",
	codeChallengeInvalid: "请求不存在或已失效",
	codeConflict:         "请求状态已变化",
	codeRateLimited:      "请求过于频繁",
	codeClientDisabled:   "客户端所属应用不可用",
	codeDBUnavailable:    "服务暂时不可用",
	codeAuditWriteFailed: "关键操作未能可靠记录",
	codeInternalError:    "服务发生未预期错误",
	codeTokenInvalid:     "访问令牌无效",
	codeUserDisabled:     "账户当前不可用",
	codeClientAuthFailed: "客户端身份验证失败",
}

// messageOf 返回错误码的公开说明；未知码回退为内部错误说明。
func messageOf(code string) string {
	if message, ok := errorMessages[code]; ok {
		return message
	}
	return errorMessages[codeInternalError]
}

// maxBearerTokenBytes 是 UserInfo 接受的 Bearer 令牌长度上限（JWT/不透明令牌均有界）。
const maxBearerTokenBytes = 16 * 1024

// maxClientSecretBytes/maxClientIDBytes 是客户端认证参数长度上限。
const (
	maxClientIDBytes     = 128
	maxClientSecretBytes = 1024
)

// 公共响应头。
const (
	headerNoStore      = "no-store"
	headerNoCache      = "no-cache"
	headerContentJSON  = "application/json; charset=utf-8"
	headerContentHTML  = "text/html; charset=utf-8"
	headerContentType  = "Content-Type"
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"
	headerRequestID    = "X-Request-ID"
	headerAllow        = "Allow"
	headerRetryAfter   = "Retry-After"
	headerWwwAuth      = "WWW-Authenticate"
	headerLocation     = "Location"
	headerNosniff      = "X-Content-Type-Options"
)

// errDuplicateParameter 表示同一 OAuth 参数出现多次（RFC 6749 要求拒绝）。
var errDuplicateParameter = errors.New("重复的协议参数")

// problemEnvelope 是自定义/非标准端点的统一错误信封。
type problemEnvelope struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// writeJSON 写 JSON 响应并设置通用安全头。value 必须是已脱敏的数据结构；调用方
// 绝不能把 token.Token 等脱敏类型直接放进来（它们会被序列化为 [REDACTED]）。
func writeJSON(writer http.ResponseWriter, status int, requestID string, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"code":"INTERNAL_ERROR","message":"服务发生未预期错误","request_id":""}`)
	}
	header := writer.Header()
	header.Set(headerContentType, headerContentJSON)
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerNosniff, "nosniff")
	if requestID != "" {
		header.Set(headerRequestID, requestID)
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

// writeProblem 写统一错误信封（自定义端点与传输层拒绝使用）。
func writeProblem(writer http.ResponseWriter, request *http.Request, status int, code, requestID, detail string) {
	_ = request
	message := messageOf(code)
	if detail != "" {
		message = detail
	}
	writeJSON(writer, status, requestID, problemEnvelope{
		Code: code, Message: message, RequestID: requestID})
}

// writeOAuthError 写 RFC 6749 标准错误响应。basicChallenge 为真（客户端尝试了
// HTTP Basic 认证）时附带 Basic 认证挑战，符合 RFC 6749 5.2。
func (s *Server) writeOAuthError(writer http.ResponseWriter, request *http.Request,
	requestID string, protocolErr *oauthflow.OAuthError) {
	if protocolErr == nil {
		protocolErr = &oauthflow.OAuthError{Code: "server_error",
			Description: "授权服务暂时不可用", HTTPStatus: http.StatusInternalServerError}
	}
	status := protocolErr.HTTPStatus
	if status < 400 || status > 599 {
		status = http.StatusBadRequest
	}
	header := writer.Header()
	if protocolErr.RetryAfter > 0 {
		seconds := int64(protocolErr.RetryAfter.Round(1e9) / 1e9)
		if seconds < 1 {
			seconds = 1
		}
		header.Set(headerRetryAfter, strconv.FormatInt(seconds, 10))
	}
	if status == http.StatusUnauthorized && protocolErr.Code == "invalid_client" &&
		request != nil && len(request.Header.Values("Authorization")) > 0 {
		header.Set(headerWwwAuth, `Basic realm="oauth-token"`)
	}
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerPragma, headerNoCache)
	s.logRejected(request, requestID, protocolErr.Code)
	writeJSON(writer, status, requestID, protocolErr.Body())
}

// writeOAuthInvalidRequest 是常用 invalid_request 的简写。
func (s *Server) writeOAuthInvalidRequest(writer http.ResponseWriter, request *http.Request,
	requestID, description string) {
	s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
		Code: "invalid_request", Description: description, HTTPStatus: http.StatusBadRequest})
}

// writeOAuthMethodNotAllowed 写 405 标准协议错误并设置 Allow 头。
func (s *Server) writeOAuthMethodNotAllowed(writer http.ResponseWriter, request *http.Request,
	requestID, allow string) {
	writer.Header().Set(headerAllow, allow)
	s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
		Code: "invalid_request", Description: "不支持的 HTTP 方法",
		HTTPStatus: http.StatusMethodNotAllowed})
}

// logRejected 记录协议拒绝的运行日志：只含端点/请求编号/稳定错误码，绝不含请求
// 参数、令牌、授权码或内部错误文本。
func (s *Server) logRejected(request *http.Request, requestID, category string) {
	if s == nil || s.logger == nil {
		return
	}
	endpoint := ""
	if request != nil && request.URL != nil {
		endpoint = request.URL.Path
	}
	s.logger.Warn("协议端点拒绝请求", "endpoint", endpoint, "category", category,
		"request_id", requestID)
}

// logFailure 记录服务层内部失败（同样只记类别，不记细节）。
func (s *Server) logFailure(request *http.Request, requestID, category string) {
	if s == nil || s.logger == nil {
		return
	}
	endpoint := ""
	if request != nil && request.URL != nil {
		endpoint = request.URL.Path
	}
	s.logger.Error("协议端点处理失败", "endpoint", endpoint, "category", category,
		"request_id", requestID)
}

// readForm 严格读取 application/x-www-form-urlencoded 请求体（标准协议端点使用）。
// 不接受 JSON/multipart、不接受无 Content-Type、不允许超过上限的请求体。
func (s *Server) readForm(writer http.ResponseWriter, request *http.Request,
	requestID string) (url.Values, bool) {
	contentType := request.Header.Get(headerContentType)
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		s.writeOAuthInvalidRequest(writer, request, requestID,
			"请求必须使用 application/x-www-form-urlencoded")
		return nil, false
	}
	if request.ContentLength > s.opts.MaxBodyBytes {
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "invalid_request", Description: "请求体过大",
			HTTPStatus: http.StatusRequestEntityTooLarge})
		return nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, s.opts.MaxBodyBytes)
	if err := request.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
				Code: "invalid_request", Description: "请求体过大",
				HTTPStatus: http.StatusRequestEntityTooLarge})
			return nil, false
		}
		s.writeOAuthInvalidRequest(writer, request, requestID, "请求体不是合法表单")
		return nil, false
	}
	if request.PostForm == nil {
		request.PostForm = url.Values{}
	}
	return request.PostForm, true
}

// singleParam 读取唯一参数值；出现多次返回 errDuplicateParameter（RFC 6749 要求
// 拒绝重复参数），缺失返回空串。
func singleParam(values url.Values, name string) (string, error) {
	items, ok := values[name]
	if !ok || len(items) == 0 {
		return "", nil
	}
	if len(items) > 1 {
		return "", fmt.Errorf("%w: %s", errDuplicateParameter, name)
	}
	return items[0], nil
}

// listParam 把可重复/空格分隔的参数展开为去空白的列表。
func listParam(values url.Values, name string) []string {
	items := values[name]
	if len(items) == 0 {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		for _, field := range strings.Fields(item) {
			result = append(result, field)
		}
	}
	return result
}

// resolvedClient 是本包从 HTTP 请求解析出的客户端认证材料。它只是传输层材料，
// 最终认证由 internal/oauthflow 内部调用 oauthclient 验证完成。
type resolvedClient struct {
	ClientID       string
	ClientSecret   string
	CertificatePEM string
	UsedBasic      bool
}

// resolveClientAuth 解析客户端认证材料：优先 RFC 6749 的 client_secret_basic，
// 其次 client_secret_post，最后是已完成 TLS 验证的客户端证书（tls_client_auth）。
// 同一请求不得混用多种认证方式；同参数重复出现按 invalid_request 拒绝。
func (s *Server) resolveClientAuth(writer http.ResponseWriter, request *http.Request,
	values url.Values, requestID string) (resolvedClient, bool) {
	var result resolvedClient
	authorization := request.Header.Values("Authorization")
	if len(authorization) > 1 {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 Authorization 头")
		return result, false
	}
	if len(authorization) == 1 {
		clientID, clientSecret, err := parseBasicCredentials(authorization[0])
		if err != nil {
			s.logRejected(request, requestID, "invalid_client_auth")
			s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
				Code: "invalid_client", Description: "客户端身份验证失败",
				HTTPStatus: http.StatusUnauthorized})
			return result, false
		}
		result.ClientID = clientID
		result.ClientSecret = clientSecret
		result.UsedBasic = true
	}
	formClientID, err := singleParam(values, "client_id")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 client_id")
		return result, false
	}
	formSecret, err := singleParam(values, "client_secret")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的 client_secret")
		return result, false
	}
	if result.UsedBasic {
		// RFC 6749 5.2 与 2.3.1：一次请求只能使用一种客户端认证方式。表单里可以
		// 重复声明同一 client_id（必须一致），但不能再带 client_secret。
		if formSecret != "" {
			s.writeOAuthInvalidRequest(writer, request, requestID, "客户端认证方式重复")
			return result, false
		}
		if formClientID != "" && formClientID != result.ClientID {
			s.writeOAuthInvalidRequest(writer, request, requestID, "client_id 与认证身份不一致")
			return result, false
		}
	} else {
		result.ClientID = formClientID
		result.ClientSecret = formSecret
	}
	if result.ClientSecret == "" {
		result.CertificatePEM = verifiedClientCertificatePEM(request)
	}
	return result, true
}

// parseBasicCredentials 解析 RFC 7617 Basic 认证头；按 RFC 6749 2.3.1 对
// client_id/client_secret 先做 form-urlencoding 再拼接，因此这里要先 url 解码。
func parseBasicCredentials(header string) (string, string, error) {
	scheme, encoded, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", fmt.Errorf("不是 Basic 认证")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", fmt.Errorf("Basic 认证内容不是合法 base64")
	}
	clientID, clientSecret, found := strings.Cut(string(decoded), ":")
	if !found || clientID == "" {
		return "", "", fmt.Errorf("Basic 认证缺少 client_id")
	}
	unescapedID, err := url.QueryUnescape(clientID)
	if err != nil {
		return "", "", fmt.Errorf("client_id 编码无效")
	}
	unescapedSecret, err := url.QueryUnescape(clientSecret)
	if err != nil {
		return "", "", fmt.Errorf("client_secret 编码无效")
	}
	if len(unescapedID) > maxClientIDBytes || len(unescapedSecret) > maxClientSecretBytes {
		return "", "", fmt.Errorf("客户端认证材料过长")
	}
	return unescapedID, unescapedSecret, nil
}

// verifiedClientCertificatePEM 返回已完成 TLS 验证的客户端叶子证书 PEM。只采信
// VerifiedChains 非空的证书：RequestClientCert 模式下未验证的证书一律不当身份。
func verifiedClientCertificatePEM(request *http.Request) string {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 {
		return ""
	}
	chain := request.TLS.VerifiedChains[0]
	if len(chain) == 0 || chain[0] == nil {
		return ""
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw})
	return string(encoded)
}

// bearerToken 从 Authorization: Bearer 头读取访问令牌；出于安全考虑不接受查询
// 参数或请求体传递令牌（避免令牌进入 URL/访问日志）。返回空串表示缺少令牌。
func (s *Server) bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) == 0 {
		return "", false
	}
	if len(values) > 1 {
		return "", false
	}
	scheme, tokenValue, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" || len(tokenValue) > maxBearerTokenBytes {
		return "", false
	}
	return tokenValue, true
}

// cookieSession 判断请求是否携带浏览器会话 Cookie（用于决定是否强制 CSRF）。
func (s *Server) cookieSession(request *http.Request) bool {
	if request == nil {
		return false
	}
	_, err := request.Cookie(s.cookieName)
	return err == nil
}

// errOriginMissing 表示状态修改请求既没有 Origin 也没有 Referer。对使用浏览器
// 会话 Cookie 的状态修改端点，本包按纵深防御要求 **fail-closed**：不把“缺少来源
// 头”交给宿主 CSRF 中间件兜底，而是直接拒绝（宿主仍必须配置 Origin/CSRF 中间件，
// 两者不可互相替代）。
var errOriginMissing = errors.New("缺少来源头")

// sameOrigin 校验状态修改请求的来源：优先 Origin，其次 Referer；存在时必须与
// issuer 完全同源。requireHeader 为真（浏览器会话状态修改端点）时，两者都缺失也
// 视为失败；为假时保留给纯服务端调用（当前未使用）。返回错误类别稳定，不含请求
// 内容；调用方只据此写 403，不向客户端回显错误文本。
func (s *Server) sameOrigin(request *http.Request, requireHeader bool) error {
	if request == nil {
		return errors.New("缺少请求")
	}
	if origins := request.Header.Values("Origin"); len(origins) > 0 {
		if len(origins) != 1 {
			return errors.New("重复的 Origin")
		}
		return compareOrigin(origins[0], s.issuerOrigin)
	}
	if referers := request.Header.Values("Referer"); len(referers) > 0 {
		if len(referers) != 1 {
			return errors.New("重复的 Referer")
		}
		parsed, err := url.Parse(referers[0])
		if err != nil || parsed.Host == "" {
			return errors.New("Referer 无效")
		}
		return compareOrigin(parsed.Scheme+"://"+parsed.Host, s.issuerOrigin)
	}
	if requireHeader {
		return errOriginMissing
	}
	return nil
}

// compareOrigin 比较两个 origin 是否完全一致（scheme 与 host 均不区分大小写）。
func compareOrigin(left, right string) error {
	if left == "" {
		return errors.New("来源为空")
	}
	parsed, err := url.Parse(left)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") {
		return errors.New("来源无效")
	}
	normalized := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
	if normalized != strings.ToLower(right) {
		return errors.New("来源与签发方不同源")
	}
	return nil
}

// redirectTo 执行 303 重定向。只允许站内相对路径或 http/https 绝对地址，拒绝
// javascript:/data: 等危险 scheme 与带凭据地址，避免开放重定向与脚本注入。
func (s *Server) redirectTo(writer http.ResponseWriter, request *http.Request,
	requestID, location string) {
	if err := validateRedirectTarget(location); err != nil {
		s.logFailure(request, requestID, "redirect_target_invalid")
		writeProblem(writer, request, http.StatusInternalServerError, codeInternalError, requestID, "")
		return
	}
	writer.Header().Set(headerLocation, location)
	writer.Header().Set(headerCacheControl, headerNoStore)
	writer.Header().Set(headerNosniff, "nosniff")
	if requestID != "" {
		writer.Header().Set(headerRequestID, requestID)
	}
	writer.WriteHeader(http.StatusSeeOther)
}

// validateRedirectTarget 校验重定向目标。OAuth 重定向地址已由服务层按客户端登记
// 配置校验；这里再做传输层防线：必须是 http/https 绝对地址或站内绝对路径。
func validateRedirectTarget(location string) error {
	if location == "" || len(location) > 4096 {
		return errors.New("重定向地址无效")
	}
	for index := 0; index < len(location); index++ {
		character := location[index]
		if character < 0x20 || character == 0x7f {
			return errors.New("重定向地址包含控制字符")
		}
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return errors.New("重定向地址无法解析")
	}
	if parsed.User != nil {
		return errors.New("重定向地址不得包含凭据")
	}
	switch parsed.Scheme {
	case "https", "http":
		if parsed.Host == "" {
			return errors.New("重定向地址缺少主机")
		}
		return nil
	case "":
		if !strings.HasPrefix(parsed.Path, "/") {
			return errors.New("站内重定向必须是绝对路径")
		}
		return nil
	default:
		return errors.New("不支持的重定向 scheme")
	}
}

// oauthServiceError 把领域错误分类为安全的协议错误，绝不把内部错误文本回显给
// 客户端。无法识别的错误一律归为 temporarily_unavailable（依赖失败默认拒绝）。
func oauthServiceError(err error) *oauthflow.OAuthError {
	var protocolErr *oauthflow.OAuthError
	if errors.As(err, &protocolErr) {
		return protocolErr
	}
	switch {
	case errors.Is(err, oauthflow.ErrInvalidRequest):
		return &oauthflow.OAuthError{Code: "invalid_request", Description: "请求参数无效",
			HTTPStatus: http.StatusBadRequest}
	case errors.Is(err, oauthflow.ErrStoreUnavailable):
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "授权服务暂时不可用", HTTPStatus: http.StatusServiceUnavailable}
	case errors.Is(err, oauthflow.ErrAuditUnavailable):
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "关键操作未能可靠记录", HTTPStatus: http.StatusServiceUnavailable}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationInvalid):
		return &oauthflow.OAuthError{Code: "invalid_request", Description: "请求参数无效",
			HTTPStatus: http.StatusBadRequest}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationNotFound):
		return &oauthflow.OAuthError{Code: "invalid_grant", Description: "设备授权请求无效",
			HTTPStatus: http.StatusBadRequest}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationAccessDenied):
		return &oauthflow.OAuthError{Code: "access_denied", Description: "请求未获准",
			HTTPStatus: http.StatusForbidden}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationReauthRequired):
		return &oauthflow.OAuthError{Code: "access_denied", Description: "需要重新验证身份",
			HTTPStatus: http.StatusForbidden}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationRateLimited):
		return &oauthflow.OAuthError{Code: "slow_down", Description: "请求过于频繁",
			HTTPStatus: http.StatusTooManyRequests, RetryAfter: 5}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationConflict):
		return &oauthflow.OAuthError{Code: "invalid_grant", Description: "设备授权请求状态已变化",
			HTTPStatus: http.StatusConflict}
	case errors.Is(err, oauthflow.ErrDeviceAuthorizationNotConfigured):
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "设备码能力未启用", HTTPStatus: http.StatusServiceUnavailable}
	case errors.Is(err, oauthflow.ErrDeviceUserCodeKeyUnavailable):
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "设备码能力未启用", HTTPStatus: http.StatusServiceUnavailable}
	case errors.Is(err, context.DeadlineExceeded):
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "授权服务暂时不可用", HTTPStatus: http.StatusGatewayTimeout}
	default:
		return &oauthflow.OAuthError{Code: "temporarily_unavailable",
			Description: "授权服务暂时不可用", HTTPStatus: http.StatusServiceUnavailable}
	}
}

// oidcServiceError 把 UserInfo 错误映射为 RFC 6750 错误响应。未知错误统一归为
// server_error，不回显内部细节。
func oidcServiceError(err error) *oidc.ProtocolError {
	var protocolErr *oidc.ProtocolError
	if errors.As(err, &protocolErr) {
		return protocolErr
	}
	switch {
	case errors.Is(err, oidc.ErrTokenInvalid):
		return &oidc.ProtocolError{Code: "invalid_token", Description: "访问令牌无效",
			Status: http.StatusUnauthorized}
	case errors.Is(err, oidc.ErrInsufficientScope):
		return &oidc.ProtocolError{Code: "insufficient_scope", Description: "访问令牌缺少所需 scope",
			Status: http.StatusForbidden}
	case errors.Is(err, oidc.ErrInvalidRequest):
		return &oidc.ProtocolError{Code: "invalid_request", Description: "请求参数无效",
			Status: http.StatusBadRequest}
	case errors.Is(err, oidc.ErrUserUnavailable):
		return &oidc.ProtocolError{Code: "invalid_token", Description: "账户当前不可用",
			Status: http.StatusUnauthorized}
	default:
		return &oidc.ProtocolError{Code: "server_error", Description: "身份服务暂时不可用",
			Status: http.StatusServiceUnavailable}
	}
}

// qrProblem 把扫码登录领域错误映射为 HTTP 状态与既有错误码；不泄露请求状态细节。
func qrProblem(err error) (int, string) {
	code := string(qrlogin.CodeOf(err))
	switch code {
	case string(qrlogin.CodeReqInvalid):
		return http.StatusBadRequest, codeReqInvalid
	case string(qrlogin.CodeAuthFailed):
		return http.StatusUnauthorized, codeAuthFailed
	case string(qrlogin.CodeAccessDenied):
		return http.StatusForbidden, codeAccessDenied
	case string(qrlogin.CodeChallengeInvalid):
		return http.StatusGone, codeChallengeInvalid
	case string(qrlogin.CodeConflict):
		return http.StatusConflict, codeConflict
	case string(qrlogin.CodeRateLimited):
		return http.StatusTooManyRequests, codeRateLimited
	case string(qrlogin.CodeClientDisabled):
		return http.StatusForbidden, codeClientDisabled
	case string(qrlogin.CodeDBUnavailable):
		return http.StatusServiceUnavailable, codeDBUnavailable
	case string(qrlogin.CodeAuditWriteFailed):
		return http.StatusServiceUnavailable, codeAuditWriteFailed
	default:
		return http.StatusInternalServerError, codeInternalError
	}
}

// writeQRProblem 写扫码端点统一错误信封。
func (s *Server) writeQRProblem(writer http.ResponseWriter, request *http.Request,
	requestID string, err error) {
	status, code := qrProblem(err)
	if status >= http.StatusInternalServerError {
		s.logFailure(request, requestID, "qr_service_unavailable")
	} else {
		s.logRejected(request, requestID, code)
	}
	writeProblem(writer, request, status, code, requestID, "")
}

// readJSONBody 严格读取 JSON 请求体：要求 application/json、拒绝未知字段与尾随
// 内容、限制体积。自定义扫码端点使用。
func (s *Server) readJSONBody(writer http.ResponseWriter, request *http.Request,
	requestID string, destination any) bool {
	contentType := request.Header.Get(headerContentType)
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		writeProblem(writer, request, http.StatusUnsupportedMediaType, codeReqInvalid,
			requestID, "请求必须使用 application/json")
		return false
	}
	if request.ContentLength > s.opts.MaxBodyBytes {
		writeProblem(writer, request, http.StatusRequestEntityTooLarge, codeReqInvalid,
			requestID, "请求体过大")
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, s.opts.MaxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeProblem(writer, request, http.StatusRequestEntityTooLarge, codeReqInvalid,
				requestID, "请求体过大")
			return false
		}
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid,
			requestID, "请求体不是合法 JSON")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeProblem(writer, request, http.StatusBadRequest, codeReqInvalid,
			requestID, "请求体包含多余内容")
		return false
	}
	return true
}

// setCookie 投递浏览器 Cookie。
func setCookie(writer http.ResponseWriter, cookie *http.Cookie) {
	if cookie == nil {
		return
	}
	http.SetCookie(writer, cookie)
}
