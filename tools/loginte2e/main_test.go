package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 本文件守护命令行契约：套件清单、稳定退出码、JSON 报告结构与错误路径。
// 真正的协议行为由 internal/loginte2e 的测试覆盖（含真实 protocolapi/adminapi）。

// TestListSuites 验证 --list-suites 输出全部套件并以 0 退出。
func TestListSuites(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--list-suites"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("--list-suites 退出码 = %d，期望 0（stderr=%s）", code, stderr.String())
	}
	output := stdout.String()
	for _, suite := range []string{"discovery", "jwks", "authcode", "token", "device",
		"qr", "adminapi", "all"} {
		if !strings.Contains(output, suite) {
			t.Fatalf("套件清单缺少 %s：%s", suite, output)
		}
	}
}

// TestUsageErrors 验证参数错误映射为 ExitUsage(2)。
func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"discovery", "token"},
		{"not-a-suite"},
		{"discovery", "--server", "not-a-url"},
		{"discovery", "--server", "http://192.0.2.1:8080"},
		{"discovery", "--session-cookie-file", "definitely-not-exists"},
		{"discovery", "--admin-session-file", "definitely-not-exists"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != exitUsage() {
			t.Fatalf("参数 %v 退出码 = %d，期望 %d（stderr=%s）", args, code,
				exitUsage(), stderr.String())
		}
	}
}

// exitUsage 返回配置/用法错误的退出码（避免测试直接依赖常量实现）。
func exitUsage() int { return 2 }

// TestUnreachableServerJSON 验证目标不可达（连接失败）时输出可解析 JSON 报告并退出 3。
func TestUnreachableServerJSON(t *testing.T) {
	// 先监听后立刻关闭：端口不可连接，模拟服务未启动。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
	}))
	server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"discovery", "--server", server.URL, "--json"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("不可达目标退出码 = %d，期望 3（stderr=%s stdout=%s）", code,
			stderr.String(), stdout.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("--json 输出不是合法 JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := report["results"]; !ok {
		t.Fatalf("JSON 报告缺少 results 字段")
	}
	if _, ok := report["error"]; !ok {
		t.Fatalf("运行失败时 JSON 报告应包含 error 字段")
	}
	if strings.Contains(stdout.String(), "eyJ") {
		t.Fatalf("JSON 报告不应包含令牌")
	}
}

// TestServerWithoutDiscoveryIsFailure 验证“能连接但端点未启用”是真实失败（退出 1），
// 不伪装成环境不可用。
func TestServerWithoutDiscoveryIsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		http.NotFound(writer, request)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"discovery", "--server", server.URL, "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("未启用协议端点的服务退出码 = %d，期望 1（stderr=%s）", code, stderr.String())
	}
}

// TestDiscoveryAgainstStubServer 验证 CLI 能把真实 HTTP 响应转成用例结果。
func TestDiscoveryAgainstStubServer(t *testing.T) {
	const issuer = "https://issuer.example.test"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"issuer":"` + issuer + `",` +
				`"authorization_endpoint":"` + issuer + `/oauth/authorize",` +
				`"token_endpoint":"` + issuer + `/oauth/token",` +
				`"userinfo_endpoint":"` + issuer + `/oauth/userinfo",` +
				`"jwks_uri":"` + issuer + `/jwks",` +
				`"revocation_endpoint":"` + issuer + `/oauth/revoke",` +
				`"scopes_supported":["openid","profile"],` +
				`"response_types_supported":["code"],"response_modes_supported":["query"],` +
				`"grant_types_supported":["authorization_code","refresh_token","client_credentials"],` +
				`"subject_types_supported":["pairwise"],` +
				`"id_token_signing_alg_values_supported":["ES256"],` +
				`"token_endpoint_auth_methods_supported":["none","client_secret_post"],` +
				`"code_challenge_methods_supported":["S256"],` +
				`"claims_parameter_supported":false,"request_parameter_supported":false,` +
				`"request_uri_parameter_supported":false}`))
		case "/jwks":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256",` +
				`"kid":"k1","use":"sig","alg":"ES256","x":"a","y":"b"}]}`))
		case "/oauth/authorize":
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"error":"access_denied"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"discovery", "--server", server.URL, "--json"}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("discovery 退出码 = %d，期望 0（全部通过）或 1（部分失败）: %s %s",
			code, stdout.String(), stderr.String())
	}
	var report struct {
		Suite   string `json:"suite"`
		Results []struct {
			Suite  string `json:"suite"`
			Case   string `json:"case"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("JSON 报告非法: %v", err)
	}
	if report.Suite != "discovery" {
		t.Fatalf("报告套件 = %q", report.Suite)
	}
	if len(report.Results) == 0 {
		t.Fatalf("discovery 未产生任何用例")
	}
}
