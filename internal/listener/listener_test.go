package listener

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
)

// mustAddress 解析允许临时端口的监听地址。
func mustAddress(t *testing.T, raw string) netpolicy.ListenAddress {
	t.Helper()
	address, err := netpolicy.ParseListenAddress(raw, true)
	if err != nil {
		t.Fatalf("解析监听地址 %q 失败：%v", raw, err)
	}
	return address
}

// testHandler 返回固定响应的处理程序。
func testHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
}

// portOf 返回已绑定地址的端口。
func portOf(t testing.TB, address net.Addr) int {
	t.Helper()
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		t.Fatalf("绑定地址不是 TCPAddr：%T", address)
	}
	return tcpAddress.Port
}

// get 发起一次 GET 请求，返回状态与正文。
func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	response, err := client.Get(url)
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

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("缺少监听地址应被拒绝")
	}
	if _, err := New(Options{Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")}}); err == nil {
		t.Error("缺少处理程序应被拒绝")
	}
	address := mustAddress(t, "127.0.0.1:0")
	if _, err := New(Options{Addresses: []netpolicy.ListenAddress{address, address}, Handler: testHandler("ok")}); err == nil {
		t.Error("重复监听地址应被拒绝")
	}
}

func TestStartServeAndCloseReleasesPort(t *testing.T) {
	address := mustAddress(t, "127.0.0.1:0")
	server, err := New(Options{Addresses: []netpolicy.ListenAddress{address}, Handler: testHandler("ok")})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	bound := server.Addrs()
	if len(bound) != 1 {
		t.Fatalf("绑定地址数量 = %d", len(bound))
	}
	boundAddr := bound[0].String()
	client := &http.Client{Timeout: 5 * time.Second}
	status, body := get(t, client, "http://"+boundAddr+"/")
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("响应 = %d %q", status, body)
	}
	if err := server.Close(ctx); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}
	if err := server.Close(ctx); err != nil {
		t.Fatalf("重复关闭应安全：%v", err)
	}
	if err := server.Start(ctx); err != ErrClosed {
		t.Fatalf("关闭后启动错误 = %v，期望 ErrClosed", err)
	}

	client.CloseIdleConnections()
	// 关闭后端口必须可以重新绑定。Windows 上已有连接可能短暂占用端口，
	// 因此做有界重试而不是把同机时序波动判成失败。
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		listener, err := net.Listen("tcp", boundAddr)
		if err == nil {
			_ = listener.Close()
			lastErr = nil
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("关闭后端口未释放：%v", lastErr)
	}
}

func TestStartTwiceAndCloseBeforeStart(t *testing.T) {
	server, err := New(Options{Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")}, Handler: testHandler("ok")})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("启动前关闭应安全：%v", err)
	}
	if err := server.Start(context.Background()); err != ErrClosed {
		t.Fatalf("启动前关闭后 Start 错误 = %v，期望 ErrClosed", err)
	}

	second, err := New(Options{Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")}, Handler: testHandler("ok")})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	defer second.Close(context.Background())
	if err := second.Start(context.Background()); err != ErrAlreadyStarted {
		t.Fatalf("重复启动错误 = %v，期望 ErrAlreadyStarted", err)
	}
}

func TestPartialListenFailureRollsBack(t *testing.T) {
	// 先占用一个地址，另一个地址使用系统分配的临时端口并通过重新绑定确认已释放。
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占用端口失败：%v", err)
	}
	defer occupied.Close()
	occupiedAddr := occupied.Addr().String()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("探测空闲端口失败：%v", err)
	}
	freeAddr := probe.Addr().String()
	_ = probe.Close()

	server, err := New(Options{
		Addresses: []netpolicy.ListenAddress{mustAddress(t, freeAddr), mustAddress(t, occupiedAddr)},
		Handler:   testHandler("ok"),
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}
	startErr := server.Start(context.Background())
	if startErr == nil {
		server.Close(context.Background())
		t.Fatal("第二个地址被占用时应启动失败")
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("启动失败后关闭应安全：%v", err)
	}
	if again := server.Start(context.Background()); again != ErrClosed {
		t.Fatalf("启动失败后再次启动错误 = %v，期望 ErrClosed", again)
	}

	// 第一个地址必须在回滚时被关闭，不能残留监听。
	listener, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Fatalf("回滚后第一个地址仍被占用：%v", err)
	}
	_ = listener.Close()
}

func TestMultipleAddressesIPv6(t *testing.T) {
	addresses := []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0"), mustAddress(t, "[::1]:0")}
	server, err := New(Options{Addresses: addresses, Handler: testHandler("dual")})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}
	if err := server.Start(context.Background()); err != nil {
		// 运行环境没有可用 IPv6 回环时跳过，而不是把失败说成通过。
		t.Skipf("IPv6 回环不可用：%v", err)
	}
	defer server.Close(context.Background())
	bound := server.Addrs()
	if len(bound) != 2 {
		t.Fatalf("绑定地址数量 = %d，期望 2", len(bound))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, address := range bound {
		url := fmt.Sprintf("http://%s/", address.String())
		status, body := get(t, client, url)
		if status != http.StatusOK || body != "dual" {
			t.Errorf("%s 响应 = %d %q", url, status, body)
		}
	}
}

func TestCloseWithDeadline(t *testing.T) {
	server, err := New(Options{Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")}, Handler: testHandler("ok")})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}
}
