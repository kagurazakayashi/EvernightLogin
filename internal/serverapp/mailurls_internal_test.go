package serverapp

import (
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// TestBuildMailURLs 覆盖：未启用邮件返回零值；启用时要求绝对 http(s) 公开地址；
// 基址由 public_base_url + path_prefix + 固定页面路径组成。
func TestBuildMailURLs(t *testing.T) {
	cfg := login.Default()
	if urls, err := buildMailURLs(cfg); err != nil || urls.VerifyEmail != "" {
		t.Fatalf("mail disabled 应返回零值: %+v %v", urls, err)
	}
	cfg.Mail.Enabled = true
	if _, err := buildMailURLs(cfg); err == nil {
		t.Fatal("mail enabled 缺少 public_base_url 应失败")
	}
	cfg.Server.PublicBaseURL = "login.example.test"
	if _, err := buildMailURLs(cfg); err == nil {
		t.Fatal("相对/缺少 scheme 的公开地址应失败")
	}
	cfg.Server.PublicBaseURL = "https://login.example.test/"
	cfg.Server.PathPrefix = "/base"
	urls, err := buildMailURLs(cfg)
	if err != nil {
		t.Fatalf("合法公开地址失败: %v", err)
	}
	for field, want := range map[string]string{
		"verify":  "https://login.example.test/base/email/verify",
		"change":  "https://login.example.test/base/email/change/verify",
		"reset":   "https://login.example.test/base/login/reset-password",
		"support": "https://login.example.test/base/support",
	} {
		var got string
		switch field {
		case "verify":
			got = urls.VerifyEmail
		case "change":
			got = urls.ChangeEmail
		case "reset":
			got = urls.PasswordReset
		case "support":
			got = urls.Support
		}
		if got != want {
			t.Fatalf("%s URL = %q，期望 %q", field, got, want)
		}
	}
}

// TestValidateMailRegistration 覆盖：要求邮箱验证但无邮件启动失败；有邮件但
// 公开地址非法也失败；关闭组合通过。
func TestValidateMailRegistration(t *testing.T) {
	cfg := login.Default()
	cfg.Registration.RequireEmailVerification = true
	if err := validateMailRegistration(cfg); err == nil || !strings.Contains(err.Error(), "mail.enabled") {
		t.Fatalf("无邮件却要求邮箱验证应失败: %v", err)
	}
	cfg.Mail.Enabled = true
	if err := validateMailRegistration(cfg); err == nil {
		t.Fatal("启用邮件但缺少公开地址应失败")
	}
	cfg.Server.PublicBaseURL = "https://login.example.test"
	if err := validateMailRegistration(cfg); err != nil {
		t.Fatalf("合法组合应通过: %v", err)
	}
	cfg.Mail.Enabled = false
	cfg.Registration.RequireEmailVerification = false
	if err := validateMailRegistration(cfg); err != nil {
		t.Fatalf("默认关闭组合应通过: %v", err)
	}
}
