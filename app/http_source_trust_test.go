package app

// 步骤 208 HTTP 宿主/反向代理测试：
//   - 用短小的反向代理 + 宿主测试服务器验证“跨应用会话、受限/无会话、伪造来源”在
//     真实 HTTP 边界上的行为，与 Direct Go 调用判定一致；
//   - 反向代理覆盖客户端伪造的 X-Forwarded-For，宿主只信任代理标记的“真实客户端
//     地址”；伪造转发头不能生成新的限流键；
//   - 宿主从不读取 HTTP 参数声称的 LocalAdmin/调用者身份，授权只来自会话与权限内核。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// step208RemoteIP 从 host:port 形式的 RemoteAddr 提取 IP 文本。
func step208RemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// step208HTTPCode 读取 AppError 的稳定错误码文本；非 AppError 返回空。
func step208HTTPCode(err error) string {
	if err == nil {
		return ""
	}
	if appError, ok := login.AsAppError(err); ok {
		return string(appError.Code())
	}
	return ""
}

// TestHostServerAndReverseProxyTrustedSource 验证 HTTP 宿主在反向代理后的会话授权
// 与来源限流行为（伪造转发头无效、代理标记的真实来源生效）。
func TestHostServerAndReverseProxyTrustedSource(t *testing.T) {
	const proxySecret = "step208-trusted-proxy"
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 30, 0, 0, time.UTC))
	evidence := setupStep208Evidence(t, ctx, clock, t.TempDir(), testConfig())
	runtime := evidence.runtime
	loginResult := step208Login(t, ctx, runtime, "member208", "K8$wR3!nB6@yF1#v", "")

	// 宿主测试服务器：只用显式可信来源与真实会话判定，不读取客户端自填身份。
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := step208RemoteIP(r.RemoteAddr)
		if r.Header.Get("X-Step208-Proxy") == proxySecret {
			source = strings.TrimSpace(r.Header.Get("X-Real-Client-IP"))
		}
		switch r.URL.Path {
		case "/authorize":
			decision, err := runtime.Sessions().Authorize(r.Context(), SessionAccessRequest{
				SessionSecret: []byte(r.Header.Get("X-Session-Secret")),
				AppID:         r.URL.Query().Get("app"),
				Permissions:   []string{r.URL.Query().Get("permission")},
				RequestID:     r.Header.Get("X-Request-ID")})
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "error:"+step208HTTPCode(err))
				return
			}
			_, _ = io.WriteString(w, fmt.Sprintf("%t|%s", decision.Allowed, decision.Code))
		case "/reset-validate":
			err := runtime.PasswordReset().ValidateTokenWithSource(r.Context(),
				ValidatePasswordResetTokenRequest{
					Token: r.URL.Query().Get("token"), ClientIP: source,
					RequestID: r.Header.Get("X-Request-ID")})
			code := step208HTTPCode(err)
			w.Header().Set("X-Error-Code", code)
			_, _ = io.WriteString(w, code)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()

	// 短小反向代理：覆盖客户端伪造的转发头，只把真实客户端地址交给宿主。
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := step208RemoteIP(r.RemoteAddr)
		forwarded := r.Clone(r.Context())
		forwarded.RequestURI = ""
		forwarded.URL.Scheme = "http"
		forwarded.URL.Host = strings.TrimPrefix(backend.URL, "http://")
		forwarded.Header.Set("X-Step208-Proxy", proxySecret)
		forwarded.Header.Set("X-Real-Client-IP", clientIP)
		forwarded.Header.Set("X-Forwarded-For", clientIP)
		response, err := http.DefaultClient.Do(forwarded)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxy.Close()

	call := func(path, query, sessionSecret string) (status int, body string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, proxy.URL+path+"?"+query, nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		if sessionSecret != "" {
			request.Header.Set("X-Session-Secret", sessionSecret)
		}
		request.Header.Set("X-Request-ID", login.NewRequestID())
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("HTTP 请求失败: %v", err)
		}
		defer func() { _ = response.Body.Close() }()
		payload, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			t.Fatalf("读取响应失败: %v", err)
		}
		return response.StatusCode, string(payload)
	}

	// 跨应用：会话有效但访问应用 B 的权限判定必须拒绝。
	status, body := call("/authorize",
		"app="+evidence.appA.ID+"&permission=invoice.read", string(loginResult.SessionSecret))
	if status != http.StatusOK || !strings.HasPrefix(body, "true|") {
		t.Fatalf("HTTP 应用 A 授权应允许: status=%d body=%q", status, body)
	}
	status, body = call("/authorize",
		"app="+evidence.appB.ID+"&permission=invoice.read", string(loginResult.SessionSecret))
	if status != http.StatusOK || strings.HasPrefix(body, "true|") || !strings.Contains(body, "|") {
		t.Fatalf("HTTP 跨应用授权应拒绝: status=%d body=%q", status, body)
	}

	// 无会话 + 自称 LocalAdmin 的 HTTP 参数/头：仍按无会话拒绝，参数不能自称管理员。
	request, err := http.NewRequest(http.MethodGet,
		proxy.URL+"/authorize?app="+evidence.appA.ID+
			"&permission=invoice.read&caller=local_admin&local_admin=true", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	request.Header.Set("X-Local-Admin", "true")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	unauthorized, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(unauthorized), string(login.CodeAuthFailed)) {
		t.Fatalf("HTTP 参数不能自称管理员: status=%d body=%q",
			response.StatusCode, string(unauthorized))
	}

	// 伪造来源：客户端每次轮换 X-Forwarded-For，代理覆盖为真实客户端地址；宿主按
	// 同一来源计数，第 Limit+1 次必须被限流（若信任伪造头则每次都是新键，永不限流）。
	for index := 0; index < passwordResetValidateSourceLimit; index++ {
		request, err := http.NewRequest(http.MethodGet,
			proxy.URL+"/reset-validate?token=invalid-http-"+fmt.Sprint(index), nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		// 客户端伪造的转发头：代理必须覆盖，宿主不得据此分桶。
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", index+1))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("HTTP 请求失败: %v", err)
		}
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if string(payload) != string(login.CodeChallengeInvalid) {
			t.Fatalf("第 %d 次预检查 code = %q，期望 CHALLENGE_INVALID",
				index+1, string(payload))
		}
	}
	limitedBody := ""
	for attempt := 0; attempt < 3; attempt++ {
		request, err := http.NewRequest(http.MethodGet,
			proxy.URL+"/reset-validate?token=invalid-http-limited", nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", attempt+1))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("HTTP 请求失败: %v", err)
		}
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		limitedBody = string(payload)
		if limitedBody == string(login.CodeRateLimited) {
			break
		}
	}
	if limitedBody != string(login.CodeRateLimited) {
		t.Fatalf("伪造转发头绕过了来源限流: 最终 code=%q", limitedBody)
	}

	// 可信代理标记的另一个真实来源拥有独立预算，说明限流键确实来自可信来源。
	if err := runtime.PasswordReset().ValidateTokenWithSource(ctx,
		ValidatePasswordResetTokenRequest{Token: "invalid-other-source",
			ClientIP: "198.51.100.200"}); !login.IsErrorCode(err, login.CodeChallengeInvalid) {
		t.Fatalf("不同可信来源应独立预算，实际 %v", err)
	}
}
