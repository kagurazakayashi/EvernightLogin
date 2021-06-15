package passwordreset_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// TestSendResetForSupport 覆盖受信客服通道发起找回：只向原已验证邮箱发送、
// 不修改密码/安全版本（原密码仍有效）、不返回链接、写成功审计且不含 token。
func TestSendResetForSupport(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	result, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-support-reset"})
	if err != nil {
		t.Fatalf("客服发起找回: %v", err)
	}
	if !result.Delivered {
		t.Fatal("应返回已投递")
	}
	if token := env.waitToken(); token == "" {
		t.Fatal("原已验证邮箱未收到找回入口")
	}
	// 发送找回入口不等改密：密码哈希、安全版本、密码服务调用数都不变。
	var passwordHash string
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT password_hash FROM password_credentials WHERE user_id=?`, userID).Scan(&passwordHash); err != nil {
		t.Fatalf("读取密码哈希: %v", err)
	}
	if passwordHash == "" {
		t.Error("密码哈希不应为空")
	}
	if env.pass.resetCalls != 0 || env.pass.changeCalls != 0 {
		t.Errorf("找回发送不应调用密码服务: reset=%d change=%d", env.pass.resetCalls, env.pass.changeCalls)
	}
	var securityVersion int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&securityVersion); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	if securityVersion != 1 {
		t.Errorf("安全版本 = %d，期望保持 1（发送不使原密码失效）", securityVersion)
	}
	if count := env.count(
		`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_requested' AND outcome='success'`,
	); count != 1 {
		t.Errorf("成功审计数 = %d，期望 1", count)
	}
	// 审计不得包含找回链接或 token。
	rows, err := env.raw.DB().QueryContext(env.ctx, `SELECT COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		if strings.Contains(detail, "token=") || strings.Contains(detail, "prq_") {
			t.Error("审计泄露找回入口")
		}
	}
}

// TestSendResetForSupportRateLimitAndIneligible 覆盖重复发起限流与不可找回目标：
// 超限返回 RATE_LIMITED；root/禁用/无密码/无已验证邮箱分别拒绝且不发送邮件。
func TestSendResetForSupportRateLimitAndIneligible(t *testing.T) {
	env := newTestEnv(t, func(options *passwordreset.Options) {
		options.SupportRatePolicy = passwordreset.SupportRatePolicy{Limit: 1, Window: time.Hour}
	})
	env.now = time.Now().UTC()
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-rate-1"}); err != nil {
		t.Fatalf("首次发起: %v", err)
	}
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-rate-2"}); !errors.Is(err, passwordreset.ErrRateLimited) {
		t.Fatalf("重复发起错误 = %v，期望 ErrRateLimited", err)
	}
	// 禁用账户。
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: otherUserID, RequestID: "req-disabled"}); !errors.Is(err, passwordreset.ErrAccountDisabled) {
		t.Fatalf("禁用账户错误 = %v，期望 ErrAccountDisabled", err)
	}
	// root 账户。
	const rootID = "usr_00000000000000000000000000000009"
	const rootOnlyEmailID = "usr_0000000000000000000000000000000a"
	env.seedUser(rootID, "rootuser", "active", true)
	env.seedEmail(rootID, "root@example.com")
	env.seedPassword(rootID)
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: rootID, RequestID: "req-root"}); !errors.Is(err, passwordreset.ErrAccessDenied) {
		t.Fatalf("root 目标错误 = %v，期望 ErrAccessDenied", err)
	}
	// 无密码账户。
	env.seedUser(rootOnlyEmailID, "nopassword", "active", false)
	env.seedEmail(rootOnlyEmailID, "nopass@example.com")
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: rootOnlyEmailID, RequestID: "req-nopass"}); !errors.Is(err, passwordreset.ErrNoPassword) {
		t.Fatalf("无密码账户错误 = %v，期望 ErrNoPassword", err)
	}
	// 无已验证邮箱账户。
	const noEmailID = "usr_0000000000000000000000000000000b"
	env.seedUser(noEmailID, "noemail", "active", false)
	env.seedPassword(noEmailID)
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: noEmailID, RequestID: "req-noemail"}); !errors.Is(err, passwordreset.ErrAccountDisabled) {
		t.Fatalf("无邮箱账户错误 = %v，期望 ErrAccountDisabled（无可用找回目标）", err)
	}
	if env.count(`SELECT COUNT(*) FROM password_reset_requests`) != 1 {
		t.Errorf("找回请求数 = %d，期望只有首次成功", env.count(`SELECT COUNT(*) FROM password_reset_requests`))
	}
}
