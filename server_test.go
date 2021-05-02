package login

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// freeListenAddr 返回一个当前空闲的 127.0.0.1 端口地址。
func freeListenAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("探测空闲端口失败：%v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// freeIPv6ListenAddr 返回一个当前空闲的 [::1] 端口地址；IPv6 不可用时跳过。
func freeIPv6ListenAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 回环不可用：%v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// testServerConfig 返回可监听的测试配置。
func testServerConfig(t *testing.T, listenAddr string) Config {
	t.Helper()
	cfg := Default()
	cfg.Server.ListenAddr = listenAddr
	cfg.Server.ShutdownTimeoutSeconds = 5
	cfg.Logging.Level = LogLevelError
	return cfg
}

// startTestServer 构造 Handler、Server 与 Instance 并启动。
func startTestServer(t *testing.T, cfg Config, handler http.Handler) (*Instance, *Server, []net.Addr) {
	t.Helper()
	server, err := NewServer(ServerOptions{Config: cfg, Handler: handler})
	if err != nil {
		t.Fatalf("构造监听服务失败：%v", err)
	}
	instance, err := New(Options{
		Config:     &cfg,
		Components: []BackgroundComponent{server},
		LogOutput:  io.Discard,
	})
	if err != nil {
		t.Fatalf("构造实例失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("启动实例失败：%v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = instance.Close(closeCtx)
	})
	return instance, server, server.Addrs()
}

// request 发送带指定 Host 与请求头的请求，返回状态码与正文。
func request(t *testing.T, client *http.Client, url, host string, headers map[string]string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求失败：%v", err)
	}
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求 %s 失败：%v", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("读取响应失败：%v", err)
	}
	return response.StatusCode, string(body)
}

// decodeErrorCode 解析统一错误 JSON 的错误码。
func decodeErrorCode(t *testing.T, body string) string {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("响应不是统一错误 JSON：%q", body)
	}
	return payload.Code
}

func TestNewServerValidation(t *testing.T) {
	validHandler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatalf("构造 Handler 失败：%v", err)
	}
	cases := []struct {
		name    string
		options ServerOptions
	}{
		{name: "缺少处理程序", options: ServerOptions{Config: Default()}},
		{name: "零值配置", options: ServerOptions{Handler: validHandler}},
		{
			name: "前缀与配置不一致",
			options: func() ServerOptions {
				cfg := testServerConfig(t, freeListenAddr(t))
				cfg.Server.PathPrefix = "/login"
				return ServerOptions{Config: cfg, Handler: validHandler, Prefix: ""}
			}(),
		},
		{
			name: "公开地址路径与前缀不一致",
			options: func() ServerOptions {
				cfg := testServerConfig(t, freeListenAddr(t))
				cfg.Server.PublicBaseURL = "https://login.example.com/login"
				return ServerOptions{Config: cfg, Handler: validHandler}
			}(),
		},
		{
			name: "非回环明文监听未声明 TLS 终止代理",
			options: func() ServerOptions {
				cfg := testServerConfig(t, "0.0.0.0:8080")
				return ServerOptions{Config: cfg, Handler: validHandler}
			}(),
		},
		{
			name: "TLS 终止代理模式缺少可信代理",
			options: func() ServerOptions {
				cfg := testServerConfig(t, "0.0.0.0:8080")
				cfg.Server.TLSProxyMode = true
				cfg.Server.PublicBaseURL = "https://login.example.com"
				return ServerOptions{Config: cfg, Handler: validHandler}
			}(),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewServer(test.options); err == nil {
				t.Fatal("非法选项应被拒绝")
			} else if appError, ok := AsAppError(err); !ok || appError.Code() != CodeConfigInvalid {
				t.Fatalf("错误应为 CONFIG_INVALID：%v", err)
			}
		})
	}
}

func TestServerServesViaInstanceAndReleasesPort(t *testing.T) {
	cfg := testServerConfig(t, freeListenAddr(t))
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatalf("构造 Handler 失败：%v", err)
	}
	server, err := NewServer(ServerOptions{Config: cfg, Handler: handler})
	if err != nil {
		t.Fatalf("构造监听服务失败：%v", err)
	}
	if len(server.Addrs()) != 0 {
		t.Fatal("未启动时不应有绑定地址")
	}
	instance, err := New(Options{Config: &cfg, Components: []BackgroundComponent{server}, LogOutput: io.Discard})
	if err != nil {
		t.Fatalf("构造实例失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	if instance.State() != StateRunning {
		t.Fatalf("实例状态 = %s", instance.State())
	}
	addrs := server.Addrs()
	if len(addrs) != 1 {
		t.Fatalf("绑定地址数量 = %d", len(addrs))
	}
	boundAddr := addrs[0].String()
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + boundAddr

	status, body := request(t, client, baseURL+"/healthz", boundAddr, nil)
	if status != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("健康检查响应 = %d %q", status, body)
	}
	// 未鉴权业务接口仍然不开放：任意业务路径都是 404 统一错误。
	status, body = request(t, client, baseURL+"/admin/users", boundAddr, nil)
	if status != http.StatusNotFound || decodeErrorCode(t, body) != "REQ_INVALID" {
		t.Fatalf("未注册业务接口响应 = %d %q", status, body)
	}
	status, body = request(t, client, baseURL+"/login/healthz", boundAddr, nil)
	if status != http.StatusNotFound {
		t.Fatalf("无前缀时子路径应 404，实际 %d %q", status, body)
	}

	client.CloseIdleConnections()
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	if err := instance.Close(closeCtx); err != nil {
		t.Fatalf("关闭实例失败：%v", err)
	}
	if instance.State() != StateClosed {
		t.Fatalf("关闭后状态 = %s", instance.State())
	}
	if len(server.Addrs()) != 0 {
		t.Fatal("关闭后不应保留绑定地址")
	}
	assertPortReleased(t, boundAddr)
}

// assertPortReleased 在有界重试内确认端口可以重新绑定。
func assertPortReleased(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			_ = listener.Close()
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("关闭后端口未释放：%v", lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestServerHostValidation(t *testing.T) {
	cfg := testServerConfig(t, freeListenAddr(t))
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, addrs := startTestServer(t, cfg, handler)
	boundAddr := addrs[0].String()
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + boundAddr

	status, body := request(t, client, baseURL+"/healthz", "evil.example.com", nil)
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("不可信 Host 状态 = %d，期望 421：%q", status, body)
	}
	if code := decodeErrorCode(t, body); code != "REQ_INVALID" {
		t.Fatalf("不可信 Host 错误码 = %q", code)
	}
	// 回环开发默认允许 localhost 与回环 IP。
	for _, host := range []string{"localhost", "127.0.0.1:" + portOf(t, addrs[0].String())} {
		status, body := request(t, client, baseURL+"/healthz", host, nil)
		if status != http.StatusOK {
			t.Fatalf("Host %q 应允许，实际 %d %q", host, status, body)
		}
	}
}

// portOf 从 host:port 文本中取出端口文本。
func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析监听地址 %q 失败：%v", addr, err)
	}
	return port
}

func TestServerSubPathPrefix(t *testing.T) {
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.PathPrefix = "/login"
	handler, err := NewHTTPHandler(HTTPOptions{Prefix: "/login"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{Config: cfg, Handler: handler, Prefix: "/login"})
	if err != nil {
		t.Fatalf("构造监听服务失败：%v", err)
	}
	instance, err := New(Options{Config: &cfg, Components: []BackgroundComponent{server}, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = instance.Close(closeCtx)
	})
	boundAddr := server.Addrs()[0].String()
	baseURL := "http://" + boundAddr
	client := &http.Client{Timeout: 5 * time.Second}
	if status, body := request(t, client, baseURL+"/login/healthz", boundAddr, nil); status != http.StatusOK {
		t.Fatalf("子路径健康检查 = %d %q", status, body)
	}
	if status, _ := request(t, client, baseURL+"/healthz", boundAddr, nil); status != http.StatusNotFound {
		t.Fatalf("非前缀路径应 404，实际 %d", status)
	}
}

func TestServerTrustedProxyChainUsesVerifiedClientAddress(t *testing.T) {
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TrustedProxies = []string{"127.0.0.1"}
	handler, err := NewHTTPHandler(HTTPOptions{Protection: &HTTPProtectionOptions{
		TrustedProxies: cfg.Server.TrustedProxies,
		RateLimit: RateLimitOptions{
			ClientIP: RateLimitPolicy{Limit: 1, Window: time.Minute},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, addrs := startTestServer(t, cfg, handler)
	boundAddr := addrs[0].String()
	baseURL := "http://" + boundAddr
	client := &http.Client{Timeout: 5 * time.Second}

	first := map[string]string{"X-Forwarded-For": "198.51.100.7, 203.0.113.9"}
	if status, body := request(t, client, baseURL+"/healthz", boundAddr, first); status != http.StatusOK {
		t.Fatalf("首个代理链请求 = %d %q", status, body)
	}
	// 链最右侧的可信客户端地址相同：命中同一限流桶。
	second := map[string]string{"X-Forwarded-For": "198.51.100.8, 203.0.113.9"}
	if status, _ := request(t, client, baseURL+"/healthz", boundAddr, second); status != http.StatusTooManyRequests {
		t.Fatalf("同一可信客户端链应触发限流，实际 %d", status)
	}
	// 换一个可信客户端地址后是新的桶，可以继续访问。
	third := map[string]string{"X-Forwarded-For": "198.51.100.8, 203.0.113.10"}
	if status, body := request(t, client, baseURL+"/healthz", boundAddr, third); status != http.StatusOK {
		t.Fatalf("新的可信客户端地址应允许，实际 %d %q", status, body)
	}
}

func TestServerIgnoresForwardingHeadersFromUntrustedPeer(t *testing.T) {
	cfg := testServerConfig(t, freeListenAddr(t))
	// 只有 10.0.0.0/8 是可信代理；测试连接来自回环地址，因此所有转发头必须被忽略。
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	handler, err := NewHTTPHandler(HTTPOptions{Protection: &HTTPProtectionOptions{
		TrustedProxies: cfg.Server.TrustedProxies,
		RateLimit: RateLimitOptions{
			ClientIP: RateLimitPolicy{Limit: 1, Window: time.Minute},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, addrs := startTestServer(t, cfg, handler)
	boundAddr := addrs[0].String()
	baseURL := "http://" + boundAddr
	client := &http.Client{Timeout: 5 * time.Second}

	if status, body := request(t, client, baseURL+"/healthz", boundAddr,
		map[string]string{"X-Forwarded-For": "198.51.100.7"}); status != http.StatusOK {
		t.Fatalf("首个请求 = %d %q", status, body)
	}
	// 伪造不同的 X-Forwarded-For 不能换到新的限流桶。
	if status, _ := request(t, client, baseURL+"/healthz", boundAddr,
		map[string]string{"X-Forwarded-For": "198.51.100.8"}); status != http.StatusTooManyRequests {
		t.Fatalf("伪造转发头不应改变限流键，实际 %d", status)
	}
}

func TestServerPartialListenFailureRollsBack(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占用端口失败：%v", err)
	}
	defer occupied.Close()
	occupiedAddr := occupied.Addr().String()

	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.ExtraListenAddrs = []string{occupiedAddr}
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{Config: cfg, Handler: handler})
	if err != nil {
		t.Fatalf("构造监听服务失败：%v", err)
	}
	instance, err := New(Options{Config: &cfg, Components: []BackgroundComponent{server}, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err == nil {
		t.Fatal("第二个地址被占用时应启动失败")
	}
	if instance.State() != StateClosed {
		t.Fatalf("启动失败后实例状态 = %s，期望 closed", instance.State())
	}
	if len(server.Addrs()) != 0 {
		t.Fatal("启动失败后不应保留绑定地址")
	}
	assertPortReleased(t, cfg.Server.ListenAddr)
}

func TestServerIPv6Listen(t *testing.T) {
	listenAddr := freeIPv6ListenAddr(t)
	cfg := testServerConfig(t, listenAddr)
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, addrs := startTestServer(t, cfg, handler)
	bound := addrs[0].String()
	client := &http.Client{Timeout: 5 * time.Second}
	status, body := request(t, client, "http://"+bound+"/healthz", bound, nil)
	if status != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("IPv6 监听响应 = %d %q", status, body)
	}
}
