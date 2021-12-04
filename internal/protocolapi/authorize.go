package protocolapi

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// consentPageData 是最小同意页的数据；全部字段来自服务端校验后的请求或会话派生
// 值，页面渲染时由 html/template 转义，不拼接原始 HTML。
type consentPageData struct {
	ClientID     string
	Scopes       []string
	Audiences    []string
	RedirectURI  string
	ExpiresAt    string
	StatePresent bool
	RequestID    string
	CSRFToken    string
	FormAction   string
}

// consentTemplate 是最小、无外部资源、无脚本的授权确认页。它不追求完整前端体验：
// 生产页面可替换为宿主的受主题页面，但必须保留服务端 CSRF 与会话校验。
const consentTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>授权确认</title>
<style>
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; }
main { max-width: 32rem; margin: 3rem auto; padding: 0 1.25rem; line-height: 1.6; }
h1 { font-size: 1.35rem; }
ul { padding-left: 1.25rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1rem; }
dt { color: #666; }
dd { margin: 0; overflow-wrap: anywhere; }
.actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
button { font: inherit; padding: .6rem 1.1rem; border-radius: .5rem; border: 1px solid #888; cursor: pointer; }
button[name="decision"][value="approve"] { background: #0b57d0; border-color: #0b57d0; color: #fff; }
.muted { color: #666; font-size: .9rem; }
</style>
</head>
<body>
<main>
<h1>授权确认</h1>
<p>应用 <strong>{{.ClientID}}</strong> 请求以你的身份访问其登记的能力。</p>
<dl>
<dt>申请的权限</dt><dd><ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul></dd>
<dt>目标资源</dt><dd><ul>{{range .Audiences}}<li>{{.}}</li>{{end}}</ul></dd>
<dt>回调地址</dt><dd>{{.RedirectURI}}</dd>
<dt>本次确认有效期</dt><dd>{{.ExpiresAt}}</dd>
{{if .StatePresent}}<dt>请求状态</dt><dd>已携带 state（将在回调中原样返回）</dd>{{end}}
</dl>
<form method="post" action="{{.FormAction}}">
<input type="hidden" name="request_id" value="{{.RequestID}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<div class="actions">
<button type="submit" name="decision" value="approve">同意授权</button>
<button type="submit" name="decision" value="deny">拒绝</button>
</div>
</form>
<p class="muted">只在你本人发起的登录中同意。拒绝不会修改任何其他安全设置；不进行任何选择并关闭页面等同于未批准。</p>
</main>
</body>
</html>
`

// consentRenderer 预编译同意页模板（构造后只读、可并发使用）。
type consentRenderer struct {
	template   *template.Template
	formAction string
}

// newConsentRenderer 构造同意页渲染器；模板解析失败属于程序错误，直接 panic 让
// 单元测试暴露（常量模板不应失败）。
func newConsentRenderer(basePath string) *consentRenderer {
	return &consentRenderer{
		template:   template.Must(template.New("consent").Parse(consentTemplate)),
		formAction: basePath + PathAuthorize,
	}
}

// render 渲染同意页 HTML。
func (r *consentRenderer) render(data consentPageData) ([]byte, error) {
	var buffer bytes.Buffer
	if err := r.template.Execute(&buffer, data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// handleAuthorize 分发授权端点：GET 展示最小同意页，POST 提交同意/拒绝决定。
// 两种方法都要求真实浏览器会话 Cookie（或 Bearer 会话）；未登录时返回受控错误
// （配置了 LoginPath 时跳转登录页），绝不自动批准。
func (s *Server) handleAuthorize(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		s.handleAuthorizeGet(writer, request)
	case http.MethodPost:
		s.handleAuthorizeDecision(writer, request)
	default:
		requestID := s.requestID(request)
		writer.Header().Set(headerAllow, "GET, POST")
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
	}
}

// handleAuthorizeGet 校验授权请求并创建待确认记录后渲染最小同意页。
func (s *Server) handleAuthorizeGet(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	sessionSecret, hasSession := s.opts.Sessions.SessionSecretFromRequest(request)
	if !hasSession || sessionSecret == "" {
		s.redirectToLogin(writer, request, requestID)
		return
	}
	values := request.URL.Query()
	authorizeRequest, parseErr := parseAuthorizeQuery(values, requestID)
	if parseErr != nil {
		s.logRejected(request, requestID, "invalid_authorize_parameter")
		s.writeOAuthInvalidRequest(writer, request, requestID, "授权请求参数无效")
		return
	}
	prompt, err := s.opts.OAuth.BeginAuthorization(request.Context(), sessionSecret,
		authorizeRequest)
	if err != nil {
		s.writeAuthorizeError(writer, request, requestID, err)
		return
	}
	csrfSecret, err := s.opts.Sessions.IssuePageCSRFToken(request.Context(), sessionSecret)
	if err != nil {
		s.logFailure(request, requestID, "csrf_issue_failed")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "temporarily_unavailable", Description: "授权服务暂时不可用",
			HTTPStatus: http.StatusServiceUnavailable})
		return
	}
	page, renderErr := s.consent.render(consentPageData{
		ClientID: prompt.ClientID, Scopes: prompt.Scopes, Audiences: prompt.Audiences,
		RedirectURI: prompt.RedirectURI, ExpiresAt: prompt.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		StatePresent: prompt.StatePresent, RequestID: prompt.RequestID,
		CSRFToken: csrfSecret.Reveal(), FormAction: s.consent.formAction,
	})
	if renderErr != nil {
		s.logFailure(request, requestID, "consent_render_failed")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "server_error", Description: "授权确认页暂时不可用",
			HTTPStatus: http.StatusInternalServerError})
		return
	}
	header := writer.Header()
	header.Set(headerContentType, headerContentHTML)
	header.Set(headerCacheControl, headerNoStore)
	header.Set(headerNosniff, "nosniff")
	header.Set("Referrer-Policy", "same-origin")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "+
			"base-uri 'none'; frame-ancestors 'none'")
	if requestID != "" {
		header.Set(headerRequestID, requestID)
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(page)
}

// handleAuthorizeDecision 处理同意页提交。要求同一真实会话、同源来源与会话绑定
// CSRF 令牌；批准后由服务层原子签发授权码并返回标准重定向。
func (s *Server) handleAuthorizeDecision(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	form, ok := s.readForm(writer, request, requestID)
	if !ok {
		return
	}
	sessionSecret, hasSession := s.opts.Sessions.SessionSecretFromRequest(request)
	if !hasSession || sessionSecret == "" {
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "access_denied", Description: "需要登录后重新发起授权",
			HTTPStatus: http.StatusUnauthorized})
		return
	}
	if err := s.sameOrigin(request, true); err != nil {
		s.logRejected(request, requestID, "origin_rejected")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "access_denied", Description: "请求来源无效",
			HTTPStatus: http.StatusForbidden})
		return
	}
	csrfToken, err := singleParam(form, "csrf_token")
	if err != nil || csrfToken == "" {
		s.writeOAuthInvalidRequest(writer, request, requestID, "缺少或重复的 CSRF 令牌")
		return
	}
	if err := s.opts.Sessions.ValidateCSRFToken(request.Context(), request, csrfToken); err != nil {
		s.logRejected(request, requestID, "csrf_token_invalid")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "access_denied", Description: "CSRF 校验失败，请重新发起授权",
			HTTPStatus: http.StatusForbidden})
		return
	}
	confirmationID, err := singleParam(form, "request_id")
	if err != nil || strings.TrimSpace(confirmationID) == "" {
		s.writeOAuthInvalidRequest(writer, request, requestID, "缺少或重复的授权确认编号")
		return
	}
	decision, err := singleParam(form, "decision")
	if err != nil {
		s.writeOAuthInvalidRequest(writer, request, requestID, "重复的决定参数")
		return
	}
	approve, valid := parseConsentDecision(decision)
	if !valid {
		s.writeOAuthInvalidRequest(writer, request, requestID, "未知的授权决定")
		return
	}
	result, decideErr := s.opts.OAuth.DecideAuthorization(request.Context(), sessionSecret,
		oauthflow.DecideRequest{RequestID: confirmationID, Approve: approve,
			DecisionRequestID: requestID})
	if decideErr != nil {
		s.writeAuthorizeError(writer, request, requestID, decideErr)
		return
	}
	if !result.RedirectURL.IsSet() {
		s.logFailure(request, requestID, "authorize_redirect_missing")
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "server_error", Description: "授权服务暂时不可用",
			HTTPStatus: http.StatusInternalServerError})
		return
	}
	s.redirectTo(writer, request, requestID, result.RedirectURL.Reveal())
}

// parseConsentDecision 解析同意页决定值；未知值拒绝。
func parseConsentDecision(value string) (bool, bool) {
	switch strings.TrimSpace(value) {
	case "approve", "yes", "true", "1":
		return true, true
	case "deny", "no", "false", "0":
		return false, true
	default:
		return false, false
	}
}

// parseAuthorizeQuery 把授权请求查询参数转换为服务层请求；重复参数按 invalid_request
// 拒绝（RFC 6749 不允许同一参数多次出现）。所有语义校验仍由服务层重新执行。
func parseAuthorizeQuery(values url.Values, requestID string) (oauthflow.AuthorizeRequest, error) {
	clientID, err := singleParam(values, "client_id")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	redirectURI, err := singleParam(values, "redirect_uri")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	responseType, err := singleParam(values, "response_type")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	state, err := singleParam(values, "state")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	nonce, err := singleParam(values, "nonce")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	codeChallenge, err := singleParam(values, "code_challenge")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	codeChallengeMethod, err := singleParam(values, "code_challenge_method")
	if err != nil {
		return oauthflow.AuthorizeRequest{}, err
	}
	return oauthflow.AuthorizeRequest{
		ClientID: clientID, RedirectURI: redirectURI, ResponseType: responseType,
		Scope: listParam(values, "scope"), Resource: listParam(values, "resource"),
		State: state, Nonce: nonce, CodeChallenge: codeChallenge,
		CodeChallengeMethod: codeChallengeMethod, RequestID: requestID,
	}, nil
}

// writeAuthorizeError 输出授权端点错误：服务层明确给出“已验证合法回调”时按标准
// 错误重定向返回；否则以 JSON 协议错误返回，绝不重定向到未验证地址。
func (s *Server) writeAuthorizeError(writer http.ResponseWriter, request *http.Request,
	requestID string, err error) {
	protocolErr := oauthServiceError(err)
	if location, redirectable := protocolErr.RedirectLocation(); redirectable {
		s.logRejected(request, requestID, protocolErr.Code)
		s.redirectTo(writer, request, requestID, location)
		return
	}
	s.writeOAuthError(writer, request, requestID, protocolErr)
}

// redirectToLogin 在未登录时返回受控错误：配置了 LoginPath 则 303 到登录页并携带
// 相对 return_to（同源站内路径，登录页负责再次校验），否则返回 401 标准协议错误。
// 本包不在未登录时自动继续授权，也不创建待确认请求。
func (s *Server) redirectToLogin(writer http.ResponseWriter, request *http.Request,
	requestID string) {
	s.logRejected(request, requestID, "login_required")
	if s.opts.LoginPath == "" {
		s.writeOAuthError(writer, request, requestID, &oauthflow.OAuthError{
			Code: "access_denied", Description: "需要登录后重新发起授权",
			HTTPStatus: http.StatusUnauthorized})
		return
	}
	returnTo := request.URL.RequestURI()
	if !strings.HasPrefix(returnTo, "/") || strings.Contains(returnTo, "\r") ||
		strings.Contains(returnTo, "\n") || len(returnTo) > 2048 {
		returnTo = s.routePath(PathAuthorize)
	}
	location := s.opts.LoginPath + "?return_to=" + url.QueryEscape(returnTo)
	s.redirectTo(writer, request, requestID, location)
}
