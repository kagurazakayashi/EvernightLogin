package loginte2e

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// 最小同意页的隐藏字段（与 internal/protocolapi 内置同意页模板一致）。页面内容
// 不可信且不能复用：工具只从中取这两个服务端生成值，然后按协议重新提交。
var (
	requestIDFieldPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	csrfFieldPattern      = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
)

// consentPage 是从同意页解析出的隐藏字段。CSRF 令牌只放内存、只回填到本次表单。
type consentPage struct {
	RequestID string
	CSRFToken string
}

// authorizationResult 是同意/拒绝决定后的回调参数。Code 是秘密：只放内存，绝不
// 进入报告；错误文本不回显完整回调地址。
type authorizationResult struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

// authorizeParams 是构造授权请求所需参数。
type authorizeParams struct {
	State         string
	Nonce         string
	CodeChallenge string
	CodeMethod    string
}

// authorizeQuery 构造授权请求查询参数。code_challenge 只提交 S256（工具从不使用
// plain）；resource 默认使用 issuer。
func (r *Runner) authorizeQuery(params authorizeParams) url.Values {
	values := url.Values{
		"client_id":     {r.client.cfg.ClientID},
		"redirect_uri":  {r.client.cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {params.State},
		"nonce":         {params.Nonce},
	}
	if len(r.client.cfg.Scopes) > 0 {
		values.Set("scope", strings.Join(r.client.cfg.Scopes, " "))
	}
	if resources := r.resourceList(); len(resources) > 0 {
		values.Set("resource", strings.Join(resources, " "))
	}
	if params.CodeChallenge != "" {
		values.Set("code_challenge", params.CodeChallenge)
	}
	if params.CodeMethod != "" {
		values.Set("code_challenge_method", params.CodeMethod)
	}
	return values
}

// authorizeGet 带上已登录会话请求授权端点，返回原始响应。不跟随重定向。
func (r *Runner) authorizeGet(ctx context.Context, query url.Values) (*httpResult, error) {
	return r.client.do(ctx, "GET", pathAuthorize+"?"+query.Encode(), requestOptions{
		bearer: r.client.cfg.SessionSecret})
}

// redirectParams 校验 303 回调并把 Location 查询参数解析为安全结构。回调地址必须
// 以配置的 redirect_uri 开头（服务端只允许登记地址）；不匹配时不回显 Location。
func (r *Runner) redirectParams(result *httpResult) (url.Values, error) {
	location := result.location()
	if location == "" {
		return nil, fmt.Errorf("服务端未返回重定向地址")
	}
	if !strings.HasPrefix(location, r.client.cfg.RedirectURI) {
		return nil, fmt.Errorf("服务端重定向到未登记回调（与 --redirect-uri 前缀不一致）")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("回调地址无法解析")
	}
	return parsed.Query(), nil
}

// beginConsent 请求同意页并解析隐藏字段。服务端未展示同意页（未登录/会话无效/
// 受限会话/跳转登录页）时返回 skip 错误，因为这是环境前置条件而不是测试失败。
func (r *Runner) beginConsent(ctx context.Context, query url.Values) (*consentPage, error) {
	result, err := r.authorizeGet(ctx, query)
	if err != nil {
		return nil, err
	}
	switch {
	case result.Status == 200:
		contentType := result.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/html") {
			return nil, fmt.Errorf("同意页 Content-Type 应为 text/html，实际 %q", contentType)
		}
		page := &consentPage{
			RequestID: firstMatch(requestIDFieldPattern, result.Body),
			CSRFToken: firstMatch(csrfFieldPattern, result.Body),
		}
		if page.RequestID == "" || page.CSRFToken == "" {
			return nil, fmt.Errorf("同意页缺少 request_id 或 csrf_token 隐藏字段")
		}
		return page, nil
	case result.Status == 303:
		query, parseErr := r.redirectParams(result)
		if parseErr != nil {
			return nil, parseErr
		}
		if code := query.Get("error"); code != "" {
			return nil, skipf("服务端未展示同意页：%s（会话无效/受限或需要重新登录）", code)
		}
		return nil, skipf("服务端跳转到登录页：工具不支持交互式登录，请用 --session-cookie-file 提供有效会话")
	case result.Status == 401:
		return nil, skipf("服务端要求登录后才能授权（HTTP 401）：请提供有效会话")
	default:
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("同意页请求返回意外状态 HTTP %d", result.Status)
	}
}

// submitConsent 提交同意/拒绝决定；必须带同源 Origin 与会话绑定 CSRF 令牌。
func (r *Runner) submitConsent(ctx context.Context, page *consentPage, approve bool) (url.Values, error) {
	decision := "deny"
	if approve {
		decision = "approve"
	}
	result, err := r.client.do(ctx, "POST", pathAuthorize, requestOptions{
		bearer: r.client.cfg.SessionSecret,
		form: url.Values{
			"request_id": {page.RequestID},
			"csrf_token": {page.CSRFToken},
			"decision":   {decision},
		},
		// 状态修改端点必须带同源 Origin/Referer；缺失会被服务端 fail-closed 拒绝。
		originIssuer: true,
	})
	if err != nil {
		return nil, err
	}
	if result.Status != 303 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("同意提交应为 303，实际 HTTP %d", result.Status)
	}
	return r.redirectParams(result)
}

// obtainAuthorizationCode 走完整授权码流程（GET 同意页 → POST 批准）并返回授权码。
// 授权码与 verifier 都是秘密，只放在返回值里。
type authorizationCode struct {
	Code     string
	State    string
	Nonce    string
	Verifier string
}

func (r *Runner) obtainAuthorizationCode(ctx context.Context) (*authorizationCode, error) {
	if err := r.requireRedirect(); err != nil {
		return nil, err
	}
	if err := r.requireSession(); err != nil {
		return nil, err
	}
	pkce, err := NewPKCE()
	if err != nil {
		return nil, err
	}
	state, err := NewState()
	if err != nil {
		return nil, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	query := r.authorizeQuery(authorizeParams{State: state, Nonce: nonce,
		CodeChallenge: pkce.Challenge, CodeMethod: PKCEMethodS256})
	page, err := r.beginConsent(ctx, query)
	if err != nil {
		return nil, err
	}
	parameters, err := r.submitConsent(ctx, page, true)
	if err != nil {
		return nil, err
	}
	if protocolError := parameters.Get("error"); protocolError != "" {
		return nil, fmt.Errorf("同意后被服务端拒绝：%s %s", protocolError,
			parameters.Get("error_description"))
	}
	code := parameters.Get("code")
	if code == "" {
		return nil, fmt.Errorf("批准后的回调缺少授权码")
	}
	if returnedState := parameters.Get("state"); returnedState != state {
		return nil, fmt.Errorf("回调 state 与请求不一致（可能被串用/重放）")
	}
	return &authorizationCode{Code: code, State: state, Nonce: nonce, Verifier: pkce.Verifier}, nil
}

// runAuthCodeSuite 验证授权端点 + 同意页 + PKCE。
func (r *Runner) runAuthCodeSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireRedirect(); err != nil {
		r.skipSuite("缺少 --client-id/--redirect-uri：" + safeDetail(err))
		return nil
	}

	// 负例：plain PKCE 必须被拒绝（重定向错误或 JSON 协议错误）。
	r.run("pkce_plain_rejected", func() error {
		state, err := NewState()
		if err != nil {
			return err
		}
		query := url.Values{
			"client_id": {r.client.cfg.ClientID}, "redirect_uri": {r.client.cfg.RedirectURI},
			"response_type": {"code"}, "state": {state},
			"scope":                 {strings.Join(r.client.cfg.Scopes, " ")},
			"resource":              {strings.Join(r.resourceList(), " ")},
			"code_challenge":        {ChallengeForVerifier("plain-test-verifier")},
			"code_challenge_method": {"plain"},
		}
		return r.expectAuthorizeRejected(ctx, query, "invalid_request")
	})

	// 负例：缺少 PKCE 必须被拒绝。
	r.run("pkce_missing_rejected", func() error {
		state, err := NewState()
		if err != nil {
			return err
		}
		query := url.Values{
			"client_id": {r.client.cfg.ClientID}, "redirect_uri": {r.client.cfg.RedirectURI},
			"response_type": {"code"}, "state": {state},
			"scope":    {strings.Join(r.client.cfg.Scopes, " ")},
			"resource": {strings.Join(r.resourceList(), " ")},
		}
		return r.expectAuthorizeRejected(ctx, query, "invalid_request")
	})

	// 需要已登录会话的用例。
	if err := r.requireSession(); err != nil {
		r.run("consent_page_rendered", func() error { return err })
		r.run("approve_issues_code", func() error { return err })
		r.run("deny_returns_access_denied", func() error { return err })
		return nil
	}

	r.run("consent_page_rendered", func() error {
		pkce, err := NewPKCE()
		if err != nil {
			return err
		}
		state, err := NewState()
		if err != nil {
			return err
		}
		nonce, err := NewNonce()
		if err != nil {
			return err
		}
		query := r.authorizeQuery(authorizeParams{State: state, Nonce: nonce,
			CodeChallenge: pkce.Challenge, CodeMethod: PKCEMethodS256})
		_, err = r.beginConsent(ctx, query)
		return err
	})

	r.run("approve_issues_code", func() error {
		code, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		if len(code.Code) < 16 {
			return fmt.Errorf("授权码长度异常")
		}
		return nil
	})

	r.run("deny_returns_access_denied", func() error {
		pkce, err := NewPKCE()
		if err != nil {
			return err
		}
		state, err := NewState()
		if err != nil {
			return err
		}
		nonce, err := NewNonce()
		if err != nil {
			return err
		}
		query := r.authorizeQuery(authorizeParams{State: state, Nonce: nonce,
			CodeChallenge: pkce.Challenge, CodeMethod: PKCEMethodS256})
		page, err := r.beginConsent(ctx, query)
		if err != nil {
			return err
		}
		parameters, err := r.submitConsent(ctx, page, false)
		if err != nil {
			return err
		}
		if got := parameters.Get("error"); got != "access_denied" {
			return fmt.Errorf("拒绝授权后回调 error 应为 access_denied，实际 %q", got)
		}
		if parameters.Get("code") != "" {
			return fmt.Errorf("拒绝授权后回调不应包含授权码")
		}
		if returnedState := parameters.Get("state"); returnedState != state {
			return fmt.Errorf("拒绝回调 state 与请求不一致")
		}
		return nil
	})
	return nil
}

// expectAuthorizeRejected 断言授权请求被拒绝（303 重定向错误或 JSON 协议错误），
// 且错误码为期望值；不把完整回调地址写进错误细节。
func (r *Runner) expectAuthorizeRejected(ctx context.Context, query url.Values,
	wantCode string) error {
	result, err := r.authorizeGet(ctx, query)
	if err != nil {
		return err
	}
	switch result.Status {
	case 303:
		parameters, parseErr := r.redirectParams(result)
		if parseErr != nil {
			return parseErr
		}
		if got := parameters.Get("error"); got != wantCode {
			return fmt.Errorf("期望回调 error=%s，实际 %q", wantCode, got)
		}
		return nil
	case 400, 403:
		problem, ok := result.problem().(*HTTPError)
		if !ok || problem.Code == "" {
			return fmt.Errorf("拒绝响应缺少稳定错误码")
		}
		if problem.Code != wantCode && problem.Code != "REQ_INVALID" &&
			problem.Code != "ACCESS_DENIED" {
			return fmt.Errorf("期望错误码 %s，实际 %v", wantCode, problem)
		}
		return nil
	default:
		return fmt.Errorf("期望授权请求被拒绝（303/400/403），实际 HTTP %d", result.Status)
	}
}

// firstMatch 返回正则第一个分组匹配；无匹配返回空串。
func firstMatch(pattern *regexp.Regexp, payload []byte) string {
	match := pattern.FindSubmatch(payload)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}
