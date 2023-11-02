package app

// 步骤 222：认证因素与安全中心公开门面测试。
//   - 因素清单脱敏（TOTP/邮件/Passkey/恢复代码/强因素状态）；
//   - TOTP 撤销必须验证当前验证码（错误/空验证码拒绝），成功后可重新绑定；
//   - 受限会话不能读取/操作因素；非法会话拒绝；
//   - Passkey 注册 ceremony 选项可公开取得，伪造响应 fail-closed，不产生凭证；
//   - 未绑定凭证时 Passkey 免密码登录开始统一失败（不泄露账户存在性）；
//   - 邮件通道未配置时邮件因素启用失败，不伪造成功；恢复代码概览只读脱敏。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// mfaPublicRuntime 打开默认测试运行时。
func mfaPublicRuntime(t *testing.T) (*Runtime, *testClock) {
	t.Helper()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC))
	cfg := testConfig()
	return openTestRuntime(t, Options{Config: &cfg, Now: clock.Now}), clock
}

// TestMFAPublicFactorListAndTOTPRemoval 覆盖 TOTP 清单、TOTP 撤销与受限会话拒绝。
func TestMFAPublicFactorListAndTOTPRemoval(t *testing.T) {
	ctx := context.Background()
	runtime, clock := mfaPublicRuntime(t)
	const username = "mfa-public-user"
	const password = "M7$kQ2!vN9@xR4#t"
	_, session, totpSecret := setupUserWithTOTP(t, runtime, clock, username, password)

	list, err := runtime.MFA().List(ctx, MFAFactorListRequest{
		SessionSecret: session, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("因素清单: %v", err)
	}
	if len(list.TOTP) != 1 || list.TOTP[0].Status != "active" {
		t.Fatalf("TOTP 清单 = %+v", list.TOTP)
	}
	if list.EmailActive || !list.StrongFactorBound {
		t.Fatalf("因素状态 = %+v，期望邮件未启用且强因素已绑定", list)
	}
	if len(list.Passkeys) != 0 {
		t.Fatalf("默认配置不应有 Passkey: %+v", list.Passkeys)
	}

	// 已绑定 TOTP 后再次登录得到受限会话；受限会话不能读取因素或撤销绑定。
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !restricted.Restricted || restricted.SecondFactor == nil {
		t.Fatalf("第二次登录应为受限会话: %+v err=%v", restricted, err)
	}
	if _, err := runtime.MFA().List(ctx, MFAFactorListRequest{
		SessionSecret: restricted.SessionSecret,
		RequestID:     login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("受限会话读取因素错误 = %v，期望 ACCESS_DENIED", err)
	}
	if err := runtime.MFA().RemoveTOTP(ctx, MFATOTPRemoveRequest{
		SessionSecret: restricted.SessionSecret, Code: "123456",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("受限会话撤销 TOTP 错误 = %v，期望 ACCESS_DENIED", err)
	}

	// 错误/空验证码不能撤销（证明持有因素，不是任意会话即可删除）。
	if err := runtime.MFA().RemoveTOTP(ctx, MFATOTPRemoveRequest{
		SessionSecret: session, Code: "000000",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误 TOTP 验证码不应撤销绑定")
	}
	if err := runtime.MFA().RemoveTOTP(ctx, MFATOTPRemoveRequest{
		SessionSecret: session, Code: "",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("空验证码不应撤销绑定")
	}
	// 错误尝试后推进一个 TOTP 时间步，避免与绑定确认时使用的验证码重放冲突。
	clock.Advance(30 * time.Second)
	code := currentTOTP(t, clock, totpSecret)
	if err := runtime.MFA().RemoveTOTP(ctx, MFATOTPRemoveRequest{
		SessionSecret: session, Code: code,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("正确验证码撤销 TOTP: %v", err)
	}
	// 撤销强因素会递增安全版本并撤销既有会话：旧会话必须立即失效。
	if _, err := runtime.MFA().List(ctx, MFAFactorListRequest{
		SessionSecret: session, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("撤销 TOTP 后旧会话必须失效")
	}
	// 因素已移除：重新登录直接得到完整会话，再读取清单确认无 active TOTP。
	relogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || relogin.Restricted {
		t.Fatalf("移除 TOTP 后重新登录: %+v err=%v", relogin, err)
	}
	after, err := runtime.MFA().List(ctx, MFAFactorListRequest{
		SessionSecret: relogin.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("撤销后因素清单: %v", err)
	}
	for _, binding := range after.TOTP {
		if binding.Status == "active" {
			t.Fatalf("撤销后仍存在 active TOTP: %+v", binding)
		}
	}

	// 恢复代码只读概览：无活动组时不伪造代码数量。
	inventory, err := runtime.MFA().RecoveryCodes(ctx, MFARecoveryCodesRequest{
		SessionSecret: relogin.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("恢复代码概览: %v", err)
	}
	if inventory.HasActiveGroup || inventory.CodesRemaining != 0 {
		t.Fatalf("初始恢复代码概览 = %+v", inventory)
	}

	// 非法会话秘密：统一会话错误，不返回因素。
	if _, err := runtime.MFA().List(ctx, MFAFactorListRequest{
		SessionSecret: []byte("invalid-session-secret"),
		RequestID:     login.NewRequestID()}); err == nil {
		t.Fatal("非法会话秘密不应读取因素")
	}
}

// TestMFAPublicPasskeyCeremonyAndEmailFailClosed 覆盖 Passkey 注册 ceremony 选项、
// 伪造响应拒绝、免密码登录统一失败与邮件通道未配置的失败路径。
func TestMFAPublicPasskeyCeremonyAndEmailFailClosed(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC))
	cfg := testConfig()
	cfg.Passkey.Enabled = true
	cfg.Passkey.RPID = "login.example.test"
	cfg.Passkey.RPDisplayName = "EvernightLogin Test"
	cfg.Passkey.AllowedOrigins = []string{"https://login.example.test"}
	cfg.Passkey.UserVerification = "required"
	runtime := openTestRuntime(t, Options{Config: &cfg, Now: clock.Now})

	const username = "mfa-passkey-user"
	const password = "P8$mW3!qT6@zK1#v"
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: username, Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	session, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || session.Restricted {
		t.Fatalf("初始登录: %+v err=%v", session, err)
	}
	if _, err := runtime.MFA().ListPasskeys(ctx, MFAPasskeyListRequest{
		SessionSecret: session.SessionSecret,
		RequestID:     login.NewRequestID()}); err != nil {
		t.Fatalf("列出空 Passkey 列表: %v", err)
	}

	// 注册 ceremony：返回一次性 publicKey 选项与用途，不包含任何秘密。
	start, err := runtime.MFA().BeginPasskeyRegistration(ctx, MFAPasskeyRegisterBeginRequest{
		SessionSecret: session.SessionSecret, Purpose: "both",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始 Passkey 注册: %v", err)
	}
	if start.CeremonyID == "" || len(start.PublicKey) == 0 || start.RPID != cfg.Passkey.RPID ||
		start.Purpose != "both" {
		t.Fatalf("注册 ceremony 结果 = %+v", start)
	}
	// 伪造认证器响应：fail-closed，且不产生凭证。
	if _, err := runtime.MFA().FinishPasskeyRegistration(ctx,
		MFAPasskeyRegisterFinishRequest{
			SessionSecret: session.SessionSecret, CeremonyID: start.CeremonyID,
			Response: []byte(`{"id":"fake","type":"public-key"}`),
			Name:     "伪造凭证", Password: password,
			RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("伪造 Passkey 注册响应必须被拒绝")
	}
	credentials, err := runtime.MFA().ListPasskeys(ctx, MFAPasskeyListRequest{
		SessionSecret: session.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil || len(credentials) != 0 {
		t.Fatalf("失败注册后凭证列表 = %+v err=%v", credentials, err)
	}
	// 非法用途在开始阶段拒绝。
	if _, err := runtime.MFA().BeginPasskeyRegistration(ctx,
		MFAPasskeyRegisterBeginRequest{
			SessionSecret: session.SessionSecret, Purpose: "bogus",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法 Passkey 用途错误 = %v，期望 REQ_INVALID", err)
	}
	// 无凭证的免密码登录：统一失败，不区分账户存在性。
	if _, err := runtime.MFA().BeginPasskeyLogin(ctx, MFAPasskeyLoginBeginRequest{
		Username: username, AppID: "", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("无 Passkey 凭证时登录开始必须失败")
	}
	if _, err := runtime.MFA().BeginPasskeyLogin(ctx, MFAPasskeyLoginBeginRequest{
		Username: "no-such-user-step222", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("不存在账户的 Passkey 登录开始必须失败")
	}
	// 撤销不存在的凭证：拒绝。
	if err := runtime.MFA().RemovePasskey(ctx, MFAPasskeyRemoveRequest{
		SessionSecret: session.SessionSecret,
		CredentialID:  "cred_00000000000000000000000000000222",
		Password:      password, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("撤销不存在的 Passkey 凭证必须失败")
	}

	// 邮件因素：本用户没有已验证邮箱/邮件通道，启用必须失败而不是返回假成功。
	if _, err := runtime.MFA().BeginEmailEnrollment(ctx, MFAEmailEnrollBeginRequest{
		SessionSecret: session.SessionSecret,
		RequestID:     login.NewRequestID()}); err == nil {
		t.Fatal("无已验证邮箱/邮件通道时邮件因素启用必须失败")
	}
	if err := runtime.MFA().RemoveEmail(ctx, MFAEmailRemoveRequest{
		SessionSecret: session.SessionSecret,
		RequestID:     login.NewRequestID()}); err == nil {
		t.Fatal("未启用邮件因素时移除必须失败")
	}
	if user.ID == "" {
		t.Fatal("用户 ID 为空")
	}
}
