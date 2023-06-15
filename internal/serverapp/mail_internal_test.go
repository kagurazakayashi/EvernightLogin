package serverapp

import (
	"os"
	"path/filepath"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

var mailerMessage = mailer.Message{From: mailer.Address{Spec: "a@example.test"}, To: []mailer.Address{{Spec: "b@example.test"}}, Subject: "t", TextBody: "x"}

// TestBuildMailRuntimeDisabled 覆盖：关闭时不读取秘密/信任根、Sender 为 nil。
func TestBuildMailRuntimeDisabled(t *testing.T) {
	cfg := login.Default()
	cfg.Mail.Enabled = false
	cfg.Mail.SMTP.Password = login.SecretSource{Kind: login.SecretSourceFile, Name: filepath.Join(t.TempDir(), "missing")}
	cfg.Mail.SMTP.TrustedRoots = []string{filepath.Join(t.TempDir(), "missing.pem")}
	runtime, err := BuildMailRuntime(cfg)
	if err != nil {
		t.Fatalf("关闭邮件不应因缺失秘密/信任根失败: %v", err)
	}
	if runtime.Enabled || runtime.Sender != nil {
		t.Fatalf("关闭邮件时不应构造发送器: %+v", runtime)
	}
	if err := runtime.SenderOrDisabled().Send(t.Context(), mailerMessage); err == nil {
		t.Fatal("未配置发送器必须显式失败")
	}
}

// TestBuildMailRuntimeEnabledFailClosed 覆盖：启用时秘密不可读/信任根无效启动失败。
func TestBuildMailRuntimeEnabledFailClosed(t *testing.T) {
	cfg := login.Default()
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = "127.0.0.1:2525"
	cfg.Mail.SMTP.Username = "mailer"
	cfg.Mail.SMTP.Password = login.SecretSource{Kind: login.SecretSourceFile, Name: filepath.Join(t.TempDir(), "missing")}
	cfg.Mail.From.Address = "no-reply@evernight-login.invalid"
	if _, err := BuildMailRuntime(cfg); err == nil {
		t.Fatal("秘密不可读时启用邮件应启动失败")
	}
	cfg.Mail.SMTP.Password = login.SecretSource{}
	cfg.Mail.SMTP.Username = ""
	badRoot := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(badRoot, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Mail.SMTP.TrustedRoots = []string{badRoot}
	if _, err := BuildMailRuntime(cfg); err == nil {
		t.Fatal("无效信任根应启动失败")
	}
}

// TestBuildMailRuntimeEnabled 覆盖：合法启用配置构造真实 sender（不建立网络）。
func TestBuildMailRuntimeEnabled(t *testing.T) {
	cfg := login.Default()
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = "127.0.0.1:2525"
	cfg.Mail.SMTP.TLSMode = "starttls"
	cfg.Mail.SMTP.TimeoutSeconds = 10
	cfg.Mail.From.Address = "no-reply@evernight-login.invalid"
	runtime, err := BuildMailRuntime(cfg)
	if err != nil {
		t.Fatalf("合法启用配置应构造成功: %v", err)
	}
	if !runtime.Enabled || runtime.Sender == nil {
		t.Fatal("启用时应构造真实 sender")
	}
	if runtime.FromAddress().Spec != "no-reply@evernight-login.invalid" {
		t.Fatalf("发件地址不符: %+v", runtime.FromAddress())
	}
}
