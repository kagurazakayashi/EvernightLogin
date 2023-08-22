package app

// 邮件装配测试（步骤 181）：真实邮件配置由共享运行时装配，但打开运行时不会建立
// SMTP 连接、不会真实外发；邮件实际发送只在业务触发时按配置目标进行（本步骤的
// TOTP/恢复代码流程不依赖邮件）。真实本地 EvernightMail 收发流程由步骤 197 验收。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestMailConfigAssembledWithoutNetworkOnOpen 验证启用真实邮件配置时：
//   - 共享装配接受合法 SMTP 配置（sender 真实构造）；
//   - 打开运行时不会连接 SMTP 目标（未触发发送就不外发）。
func TestMailConfigAssembledWithoutNetworkOnOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("创建本地 SMTP 监听失败: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Mail.SMTP.TLSMode = "starttls"
	cfg.Mail.SMTP.TimeoutSeconds = 10
	cfg.Mail.From.Address = "no-reply@evernight-login.invalid"
	cfg.Server.PublicBaseURL = "http://127.0.0.1:8080"
	runtime, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "mail-assembly-test", Now: time.Now,
	})
	if err != nil {
		t.Fatalf("合法邮件配置应装配成功: %v", err)
	}
	defer runtime.Close(context.Background())
	// 打开运行时只构造 sender，不建立连接；若收到连接说明发生了隐式外发。
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Now().Add(300 * time.Millisecond))
	}
	connection, acceptErr := listener.Accept()
	if acceptErr == nil {
		_ = connection.Close()
		t.Fatal("打开运行时时不得建立 SMTP 连接（不真实外发）")
	}
	var netErr net.Error
	if !errors.As(acceptErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("本地 SMTP 监听异常: %v", acceptErr)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
