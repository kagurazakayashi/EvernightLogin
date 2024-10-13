package listener

// 关闭稳定性回归：已 accept 但尚未读请求（StateNew）的连接不得阻塞优雅关闭。
// 这类连接在真实环境中可能来自慢客户端、端口探测/安全软件；net/http 的 Shutdown
// 不会把它们当作空闲连接关闭，若不主动清理会一直等到读超时/关闭期限。

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
)

// waitForNewConnection 等待跟踪表出现至少一个 StateNew 连接。
func waitForNewConnection(t *testing.T, server *Server, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		server.connMu.Lock()
		count := 0
		for _, state := range server.connStates {
			if state == http.StateNew {
				count++
			}
		}
		server.connMu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s 内未观察到 StateNew 连接", timeout)
}

// TestCloseClosesHalfOpenNewConnections 验证关闭会主动清理 StateNew 连接并快速返回。
func TestCloseClosesHalfOpenNewConnections(t *testing.T) {
	server, err := New(Options{
		Addresses:       []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")},
		Handler:         testHandler("ok"),
		ShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	addr := server.Addrs()[0].String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("建立半开连接失败：%v", err)
	}
	defer conn.Close()
	waitForNewConnection(t, server, 2*time.Second)

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("含未读新连接的关闭应成功，实际错误：%v", err)
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("关闭被未读新连接阻塞，耗时 %s", elapsed)
	}
	// 连接应已被服务端关闭：后续读取应得到 EOF/错误，而不是继续挂起。
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, readErr := conn.Read(buffer); readErr == nil {
		t.Fatal("未读新连接在关闭后仍可读，期望已被服务端关闭")
	}
}

// TestCloseRepeatedAndNewConnectionTracking 验证重复关闭幂等且不 panic。
func TestCloseRepeatedAndNewConnectionTracking(t *testing.T) {
	server, err := New(Options{
		Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")},
		Handler:   testHandler("ok"),
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("启动失败：%v", err)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("首次关闭失败：%v", err)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("重复关闭应幂等：%v", err)
	}
	if summary := server.connectionStateSummary(); summary != "无活动连接" {
		t.Fatalf("关闭后连接跟踪未清空：%s", summary)
	}
}
