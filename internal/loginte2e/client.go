package loginte2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 与被测服务共享的固定路径。这里刻意不 import internal/protocolapi 与
// internal/adminapi：命令行工具不应把整个服务端领域装配进二进制；契约一致性由
// 单元测试 contract_test.go 用那两个包的导出常量做相等断言守护。
const (
	pathDiscovery           = "/.well-known/openid-configuration"
	pathJWKS                = "/jwks"
	pathAuthorize           = "/oauth/authorize"
	pathToken               = "/oauth/token"
	pathUserInfo            = "/oauth/userinfo"
	pathRevoke              = "/oauth/revoke"
	pathIntrospect          = "/oauth/introspect"
	pathDeviceAuthorization = "/oauth/device_authorization"
	pathDeviceCancel        = "/oauth/device/cancel"
	pathQRRequest           = "/oauth/qr/request"
	pathQRStatus            = "/oauth/qr/status"
	pathQRClaim             = "/oauth/qr/claim"
	pathQRCancel            = "/oauth/qr/cancel"
	pathQRPrompt            = "/oauth/qr/prompt"
	pathQRDecision          = "/oauth/qr/decision"
	defaultAdminBasePath    = "/admin/v1"
)

// Client 是面向一个运行中服务的测试客户端。构造后只读、可并发使用；所有请求
// 默认不跟随重定向（协议断言需要检查 3xx 与 Location），响应正文有大小上限。
type Client struct {
	cfg       Config
	base      *url.URL
	baseText  string
	http      *http.Client
	transport *http.Transport
	now       func() time.Time
	// issuerCache 保存 Discovery 返回的 issuer（只读、非敏感），供同源请求头与
	// 端点核对使用；同一 Client 不应并发运行多个套件。
	issuerCache string
	// jwksCache 保存最近一次拉取的 JWKS 原文（公开数据），供 ID Token 验签复用。
	jwksCache []byte
}

// 单个响应正文上限；协议响应远小于该值，避免被异常服务拖垮测试进程。
const maxResponseBytes = 4 << 20

// httpResult 是一次 HTTP 响应的只读快照。令牌/授权码等一次性明文只在调用方
// 的局部变量里出现，不进入这个结构以外的长期状态，也不进入报告。
type httpResult struct {
	Method string
	Path   string
	Status int
	Header http.Header
	Body   []byte
}

// requestOptions 是内部请求选项。bearer 是敏感字段，只放请求头。
type requestOptions struct {
	form         url.Values
	jsonBody     any
	bearer       string
	originIssuer bool
}

// New 校验配置、构造严格 TLS 的 HTTP 客户端。网络连接按需建立，不探测服务。
func New(cfg Config) (*Client, error) {
	normalized := cfg.withDefaults()
	if err := normalized.validate(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(normalized.Server)
	if err != nil {
		return nil, fmt.Errorf("%w: server 地址无法解析", ErrConfigInvalid)
	}
	transport, err := normalized.newTransport()
	if err != nil {
		return nil, err
	}
	client := &Client{cfg: normalized, base: parsed, baseText: normalized.Server,
		transport: transport, now: normalized.Now}
	client.http = &http.Client{
		Transport: transport,
		Timeout:   normalized.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// 协议验收必须观察 303 与 Location（授权码/错误都在里面），不自动跟随。
			return http.ErrUseLastResponse
		},
	}
	return client, nil
}

// Close 释放连接池；工具调用结束后应显式调用。
func (c *Client) Close() {
	if c == nil || c.transport == nil {
		return
	}
	c.transport.CloseIdleConnections()
}

// Config 返回客户端实际使用的规范化配置副本（敏感字段原样返回，调用方不得打印）。
func (c *Client) Config() Config { return c.cfg.clone() }

// ServerBase 返回被测服务基础地址（含部署路径前缀，无尾斜杠）。
func (c *Client) ServerBase() string { return c.baseText }

// url 把固定协议路径拼到服务基础地址后。
func (c *Client) url(path string) string { return c.baseText + path }

// do 执行一次 HTTP 请求。path 必须是站内固定路径（本包常量），绝不接受外部输入。
func (c *Client) do(ctx context.Context, method, path string, opts requestOptions) (*httpResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var body io.Reader
	contentType := ""
	switch {
	case opts.jsonBody != nil:
		encoded, err := json.Marshal(opts.jsonBody)
		if err != nil {
			return nil, fmt.Errorf("%w: 构造 JSON 请求失败", ErrConfigInvalid)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	case opts.form != nil:
		body = strings.NewReader(opts.form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	request, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求失败", ErrConfigInvalid)
	}
	request.Header.Set("Accept", "application/json, text/html;q=0.9")
	request.Header.Set("User-Agent", "login-loginte2e/1 (test-only)")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if opts.originIssuer && c.origin() != "" {
		request.Header.Set("Origin", c.origin())
	}
	if opts.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+opts.bearer)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s 请求失败: %s", ErrUnavailable, method, path,
			networkErrorText(err))
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	payload, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, fmt.Errorf("%w: 读取 %s %s 响应失败", ErrUnavailable, method, path)
	}
	if len(payload) > maxResponseBytes {
		return nil, fmt.Errorf("%w: %s %s 响应超过 %d 字节", ErrUnavailable, method, path,
			maxResponseBytes)
	}
	return &httpResult{Method: method, Path: path, Status: response.StatusCode,
		Header: response.Header, Body: payload}, nil
}

// doAbsolute 执行一个绝对地址请求，但**只允许与被测服务同源**：设备确认页等
// 宿主页面地址由用户提供，绝不能把会话秘密/CSRF 令牌发送到其他主机。
func (c *Client) doAbsolute(ctx context.Context, method, absoluteURL string,
	opts requestOptions) (*httpResult, error) {
	parsed, err := url.Parse(absoluteURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("%w: 页面地址不是合法绝对地址", ErrConfigInvalid)
	}
	if parsed.Scheme != c.base.Scheme || !strings.EqualFold(parsed.Host, c.base.Host) {
		return nil, fmt.Errorf("%w: 页面地址必须与被测服务同源（不允许把会话秘密发往其他主机）",
			ErrConfigInvalid)
	}
	return c.doAbsoluteAt(ctx, method, parsed, opts)
}

// doAbsoluteAt 用已解析地址构造请求：路径与查询串保留，不带外部主机。
func (c *Client) doAbsoluteAt(ctx context.Context, method string, target *url.URL,
	opts requestOptions) (*httpResult, error) {
	var body io.Reader
	contentType := ""
	switch {
	case opts.jsonBody != nil:
		encoded, err := json.Marshal(opts.jsonBody)
		if err != nil {
			return nil, fmt.Errorf("%w: 构造 JSON 请求失败", ErrConfigInvalid)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	case opts.form != nil:
		body = strings.NewReader(opts.form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求失败", ErrConfigInvalid)
	}
	request.Header.Set("Accept", "text/html, application/json;q=0.9")
	request.Header.Set("User-Agent", "login-loginte2e/1 (test-only)")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if opts.originIssuer && c.origin() != "" {
		request.Header.Set("Origin", c.origin())
	}
	if opts.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+opts.bearer)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s 请求失败: %s", ErrUnavailable, method,
			target.EscapedPath(), networkErrorText(err))
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("%w: 读取响应失败", ErrUnavailable)
	}
	if len(payload) > maxResponseBytes {
		return nil, fmt.Errorf("%w: 响应超过 %d 字节", ErrUnavailable, maxResponseBytes)
	}
	return &httpResult{Method: method, Path: target.EscapedPath(),
		Status: response.StatusCode, Header: response.Header, Body: payload}, nil
}

// networkErrorText 提取网络错误的安全描述：去掉 net/http 包对完整 URL 的回显，// 避免把查询串里的 state/nonce/授权码等写进报告。
func networkErrorText(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "请求超时"
	}
	return err.Error()
}

// origin 返回 issuer 的 scheme://host（用于状态修改端点的同源校验请求头）。
func (c *Client) origin() string {
	issuer := c.cfg.ExpectedIssuer
	if issuer == "" {
		if c.issuerCache != "" {
			issuer = c.issuerCache
		} else {
			return ""
		}
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// 状态码辅助。
func (r *httpResult) isSuccess() bool { return r.Status >= 200 && r.Status < 300 }

// decodeJSON 严格解码响应 JSON（多余内容会被拒绝，避免把错误页当成功解析）。
func (r *httpResult) decodeJSON(target any) error {
	decoder := json.NewDecoder(bytes.NewReader(r.Body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s %s 响应不是合法 JSON（HTTP %d）", r.Method, r.Path, r.Status)
	}
	return nil
}

// location 返回 Location 响应头（只在该响应确实是重定向时使用）。
func (r *httpResult) location() string { return strings.TrimSpace(r.Header.Get("Location")) }

// HTTPError 是被测服务返回的稳定错误。它只含状态码、稳定错误码与公开消息，
// 不含响应正文原文或任何凭据。
type HTTPError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

// Error 实现 error。
func (e *HTTPError) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("HTTP %d", e.StatusCode)}
	if e.Code != "" {
		parts = append(parts, e.Code)
	}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	if e.RequestID != "" {
		parts = append(parts, "request_id="+e.RequestID)
	}
	return strings.Join(parts, " ")
}

// problem 在响应是 4xx/5xx 时返回 *HTTPError，否则返回 nil。解析顺序：
// RFC 6749 的 {error,error_description}、项目统一信封 {code,message,request_id}、
// 管理 API 的 {ok:false,code,message,request_id}。
func (r *httpResult) problem() error {
	if r.Status < 400 {
		return nil
	}
	failure := &HTTPError{StatusCode: r.Status}
	var oauthEnvelope struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	var problemEnvelope struct {
		OK        *bool  `json:"ok"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	// 先按标准 OAuth 错误解析，再按统一信封解析；同一响应允许只有一个。
	if json.Unmarshal(r.Body, &oauthEnvelope) == nil && oauthEnvelope.Error != "" {
		failure.Code = oauthEnvelope.Error
		failure.Message = oauthEnvelope.ErrorDescription
		failure.RequestID = r.Header.Get("X-Request-ID")
		if failure.Message == "" {
			failure.Message = r.Header.Get("WWW-Authenticate")
		}
		return failure
	}
	if json.Unmarshal(r.Body, &problemEnvelope) == nil && problemEnvelope.Code != "" {
		failure.Code = problemEnvelope.Code
		failure.Message = problemEnvelope.Message
		failure.RequestID = problemEnvelope.RequestID
		if failure.RequestID == "" {
			failure.RequestID = r.Header.Get("X-Request-ID")
		}
		return failure
	}
	failure.RequestID = r.Header.Get("X-Request-ID")
	failure.Message = fmt.Sprintf("HTTP %d（响应不是已知错误信封）", r.Status)
	return failure
}

// expectStatus 断言状态码；不一致时返回带安全细节的错误。
func (r *httpResult) expectStatus(want int) error {
	if r.Status != want {
		if problem := r.problem(); problem != nil {
			return fmt.Errorf("期望 HTTP %d，实际 %v", want, problem)
		}
		return fmt.Errorf("期望 HTTP %d，实际 HTTP %d", want, r.Status)
	}
	return nil
}

// expectProblem 断言响应是 4xx/5xx 且错误码在允许集合内（空集合表示任意稳定错误码）。
func (r *httpResult) expectProblem(wantStatus int, allowCodes ...string) (*HTTPError, error) {
	if r.isSuccess() {
		return nil, fmt.Errorf("期望被拒绝，实际 HTTP %d", r.Status)
	}
	problem, ok := r.problem().(*HTTPError)
	if !ok || problem == nil {
		return nil, fmt.Errorf("期望稳定错误信封，实际 HTTP %d", r.Status)
	}
	if wantStatus != 0 && r.Status != wantStatus {
		return problem, fmt.Errorf("期望 HTTP %d，实际 %v", wantStatus, problem)
	}
	if len(allowCodes) > 0 {
		allowed := false
		for _, code := range allowCodes {
			if code == problem.Code {
				allowed = true
				break
			}
		}
		if !allowed {
			return problem, fmt.Errorf("错误码不在允许集合 %v 内：%v", allowCodes, problem)
		}
	}
	return problem, nil
}

// nowTime 返回测试客户端时钟。
func (c *Client) nowTime() time.Time { return c.now().UTC() }

// issuerCache 保存 Discovery 返回的 issuer（只读、非敏感），供同源头与端点核对。
// 放在 Client 上避免把 issuer 反复作为参数传递。
func (c *Client) cachedIssuer() string { return c.issuerCache }
