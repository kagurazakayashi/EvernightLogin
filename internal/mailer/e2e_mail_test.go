package mailer_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// TestMailE2EReal 是步骤 139 的真实 EvernightMail 夹具回归；缺省跳过，由
// scripts/e2e-mail-delivery.ps1 设置 MAIL_E2E_* 环境变量后执行。
// 覆盖：STARTTLS 信任测试 CA 发送成功；错误凭据永久认证失败；错误信任根 TLS
// 失败且不降级为明文。
func TestMailE2EReal(t *testing.T) {
	addr := os.Getenv("MAIL_E2E_ADDR")
	if addr == "" {
		t.Skip("未设置 MAIL_E2E_ADDR，跳过真实 Mail 夹具用例")
	}
	caFile := os.Getenv("MAIL_E2E_CA")
	user := os.Getenv("MAIL_E2E_USER")
	password := os.Getenv("MAIL_E2E_PASSWORD")
	if caFile == "" || user == "" || password == "" {
		t.Fatal("MAIL_E2E_CA/USER/PASSWORD 必须同时设置")
	}
	roots, err := mailer.LoadTrustedRoots([]string{caFile})
	if err != nil {
		t.Fatalf("加载测试 CA 失败: %v", err)
	}
	message := mailer.Message{
		From: mailer.Address{Spec: "tester@mail.final.test"}, To: []mailer.Address{{Spec: "tester@mail.final.test"}},
		Subject: "step139 e2e", TextBody: "装配真实发送回归",
	}
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: addr, TLSMode: mailer.TLSModeStartTLS, TrustedRoots: roots,
		Username: user, Password: password, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造发送器失败: %v", err)
	}
	if err := sender.Send(context.Background(), message); err != nil {
		t.Fatalf("真实 STARTTLS 发送失败: %v", err)
	}

	// 错误凭据：必须永久失败且归类 MAIL_AUTH_FAILED，不能静默成功或无限重试。
	badAuth, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: addr, TLSMode: mailer.TLSModeStartTLS, TrustedRoots: roots,
		Username: user, Password: "definitely-wrong", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造错误凭据发送器: %v", err)
	}
	err = badAuth.Send(context.Background(), message)
	if err == nil || mailer.CodeOf(err) != mailer.CodeAuthFailed || mailer.IsRetryable(err) {
		t.Fatalf("错误凭据应永久认证失败, 实际 %v (code=%q)", err, mailer.CodeOf(err))
	}

	// 错误信任根（系统池）：TLS 握手失败，必须归类 MAIL_TLS_FAILED 且不降级明文。
	noRoots, err := mailer.LoadTrustedRoots(nil)
	if err != nil {
		t.Fatalf("系统根池: %v", err)
	}
	badTLS, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: addr, TLSMode: mailer.TLSModeStartTLS, TrustedRoots: noRoots,
		Username: user, Password: password, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造错误信任根发送器: %v", err)
	}
	err = badTLS.Send(context.Background(), message)
	if err == nil || mailer.CodeOf(err) != mailer.CodeTLSFailed || mailer.IsRetryable(err) {
		t.Fatalf("错误信任根应永久 TLS 失败且不降级, 实际 %v (code=%q)", err, mailer.CodeOf(err))
	}
}
