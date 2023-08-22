package app

// 认证与安全门面测试（步骤 181）：真实临时 SQLite + 真实领域服务（authn/mfa/totp/
// recovery/reauth/session），不使用伪造强认证结果；TOTP 码由确定性时钟按 RFC 6238
// 计算（等价于用户的验证器 App），不是测试替身。

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// testClock 是可推进的确定性时钟；所有领域服务与 TOTP 计算共用它。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// newTestClock 返回固定起点的可推进时钟。
func newTestClock(at time.Time) *testClock { return &testClock{now: at} }

// Now 实现 func() time.Time。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进测试时钟（TOTP 时间步 30 秒）。
func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// currentTOTP 用绑定返回的种子按服务端默认参数计算当前验证码（模拟验证器 App）。
func currentTOTP(t *testing.T, clock *testClock, encodedSecret string) string {
	t.Helper()
	secret, err := totp.DecodeSecret(encodedSecret)
	if err != nil {
		t.Fatalf("解码 TOTP 种子失败: %v", err)
	}
	code, _, err := totp.GenerateCode(secret, clock.Now(), totp.DefaultPeriodSeconds,
		totp.DefaultDigits)
	if err != nil {
		t.Fatalf("生成 TOTP 验证码失败: %v", err)
	}
	return code
}

// setupUserWithTOTP 创建普通用户并完成真实 TOTP 绑定（敏感操作 mfa.add 需要近期
// 密码验证），返回用户 ID、完整会话秘密与 TOTP 种子（种子只用于测试内计算验证码）。
func setupUserWithTOTP(t *testing.T, runtime *Runtime, clock *testClock,
	username, password string) (userID string, sessionSecret []byte, totpSecret string) {
	t.Helper()
	ctx := context.Background()
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: username, Password: password, Nickname: username,
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}
	if loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("无因素账户首次登录应签发完整会话: %+v", loginResult)
	}
	// 错误密码必须被真实再次认证拒绝（不能仅凭已有会话绑定新因素）。
	if _, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: "Wrong!Passw0rd",
		RequestID: login.NewRequestID(),
	}); err == nil {
		t.Fatal("错误密码不应通过敏感操作再次认证")
	}
	start, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: loginResult.SessionSecret, Password: password,
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("开始绑定 TOTP 失败: %v", err)
	}
	if start.Secret == "" || start.BindingID == "" || start.OTPAuthURL == "" {
		t.Fatalf("TOTP 绑定结果不完整: %+v", start)
	}
	code := currentTOTP(t, clock, start.Secret)
	binding, err := runtime.Security().ConfirmTOTPBinding(ctx, TOTPBindingConfirmRequest{
		SessionSecret: loginResult.SessionSecret, BindingID: start.BindingID,
		Code: code, RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("确认 TOTP 绑定失败: %v", err)
	}
	if binding.Status != "active" {
		t.Fatalf("TOTP 绑定状态 = %q，期望 active", binding.Status)
	}
	return user.ID, loginResult.SessionSecret, start.Secret
}

// TestPasswordLoginTOTPSecondFactorAndSensitiveReauth 验证：密码登录 -> 受限状态 ->
// 错误因素拒绝 -> 正确 TOTP 补充验证 -> 完整会话；敏感操作再次认证与能力状态。
func TestPasswordLoginTOTPSecondFactorAndSensitiveReauth(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC))
	cfg := testConfig()
	runtime := openTestRuntime(t, Options{Config: &cfg, Now: clock.Now})
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	userID, _, totpSecret := setupUserWithTOTP(t, runtime, clock, "alice", "K8$wR3!nB6@yF1#v")

	// 下一个时间步登录：密码第一步后必须是受限会话 + TOTP 挑战。
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("密码第一步失败: %v", err)
	}
	if !restricted.Restricted || restricted.SecondFactor == nil ||
		restricted.SecondFactor.FactorType != "totp" {
		t.Fatalf("TOTP 账户登录必须返回受限状态与 TOTP 挑战: %+v", restricted)
	}
	if len(restricted.SessionSecret) == 0 || restricted.SecondFactor.AttemptToken == nil {
		t.Fatal("受限会话秘密或尝试令牌缺失")
	}
	// 错误因素拒绝：不能升级为完整会话，且失败原因不泄露内部信息。
	_, err = runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          "000000", RequestID: login.NewRequestID(),
	})
	if err == nil {
		t.Fatal("错误 TOTP 验证码不应通过")
	}
	if code, _ := login.ErrorCodeOf(err); code != login.CodeChallengeInvalid &&
		code != login.CodeAuthFailed {
		t.Fatalf("错误验证码应返回 CHALLENGE_INVALID/AUTH_FAILED，实际 %v", code)
	}
	// 正确 TOTP 验证码完成第二步，签发完整会话。
	verified, err := runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          currentTOTP(t, clock, totpSecret),
		RequestID:     login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("正确 TOTP 未通过第二步: %v", err)
	}
	if verified.UserID != userID || len(verified.SessionSecret) == 0 ||
		verified.Method != "totp" {
		t.Fatalf("第二步结果异常: %+v", verified)
	}
	// 能力状态：TOTP 已启用、强因素已绑定、Passkey 关闭但 TOTP 能力保留。
	status, err := runtime.Security().Status(ctx, SecurityStatusRequest{
		SessionSecret: verified.SessionSecret})
	if err != nil {
		t.Fatalf("读取安全状态失败: %v", err)
	}
	if !status.TOTPActive || !status.StrongFactorBound {
		t.Fatalf("TOTP/强因素状态异常: %+v", status)
	}
	if status.PasskeyEnabled {
		t.Fatalf("默认配置 Passkey 应关闭: %+v", status)
	}
}

// TestRecoveryCodesRequireStrongAuthAndRestrictedRecovery 验证：生成恢复代码需要
// 近期强认证；恢复代码只替代第二步并进入受限恢复会话（不能访问业务）。
func TestRecoveryCodesRequireStrongAuthAndRestrictedRecovery(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC))
	cfg := testConfig()
	runtime := openTestRuntime(t, Options{Config: &cfg, Now: clock.Now})
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	userID, fullSecret, totpSecret := setupUserWithTOTP(t, runtime, clock, "bob",
		"N4!rT8#xW2@qL6$z")
	// 只有密码、没有 TOTP：强认证要求必须 fail-closed。
	clock.Advance(30 * time.Second)
	if _, err := runtime.Security().GenerateRecoveryCodes(ctx, RecoveryCodesRequest{
		SessionSecret: fullSecret, Password: "N4!rT8#xW2@qL6$z",
		RequestID: login.NewRequestID(),
	}); err == nil {
		t.Fatal("已绑定强因素的账户生成恢复代码必须要求近期强认证")
	}
	codes, err := runtime.Security().GenerateRecoveryCodes(ctx, RecoveryCodesRequest{
		SessionSecret: fullSecret, Password: "N4!rT8#xW2@qL6$z",
		TOTPCode:  currentTOTP(t, clock, totpSecret),
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("密码+TOTP 生成恢复代码失败: %v", err)
	}
	if len(codes.Codes) < 5 {
		t.Fatalf("恢复代码数量异常: %d", len(codes.Codes))
	}
	// 下一步时间步登录，使用恢复代码替代第二步。
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "bob", Password: "N4!rT8#xW2@qL6$z", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("密码第一步失败: %v", err)
	}
	if !restricted.Restricted || restricted.SecondFactor == nil {
		t.Fatalf("恢复前应为受限状态: %+v", restricted)
	}
	// 错误恢复代码被拒绝。
	if _, err := runtime.Auth().BeginRecovery(ctx, BeginRecoveryRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		RecoveryCode:  "00000000-0000-0000-0000-000000000000",
		RequestID:     login.NewRequestID(),
	}); err == nil {
		t.Fatal("错误恢复代码不应进入受限恢复会话")
	}
	recoverySession, err := runtime.Auth().BeginRecovery(ctx, BeginRecoveryRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		RecoveryCode:  codes.Codes[0],
		RequestID:     login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("恢复代码未进入受限恢复会话: %v", err)
	}
	if recoverySession.UserID != userID || len(recoverySession.SessionSecret) == 0 {
		t.Fatalf("受限恢复会话结果异常: %+v", recoverySession)
	}
	if recoverySession.CodesRemaining != len(codes.Codes)-1 {
		t.Fatalf("恢复代码剩余 = %d，期望 %d", recoverySession.CodesRemaining, len(codes.Codes)-1)
	}
	if len(recoverySession.AllowedMethods) != 1 || recoverySession.AllowedMethods[0] != "passkey" {
		t.Fatalf("强认证要求下只允许 Passkey 重绑: %+v", recoverySession.AllowedMethods)
	}
	// 受限恢复会话不能访问业务（读取安全状态属于完整会话操作）。
	_, err = runtime.Security().Status(ctx, SecurityStatusRequest{
		SessionSecret: recoverySession.SessionSecret})
	if !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("受限恢复会话不应访问完整会话操作，实际错误 %v", err)
	}
	status, err := runtime.Auth().RecoveryStatus(ctx, RecoveryStatusRequest{
		SessionSecret: recoverySession.SessionSecret})
	if err != nil {
		t.Fatalf("读取受限恢复状态失败: %v", err)
	}
	if status.RequiredStrength != "strong" || status.CodesRemaining != len(codes.Codes)-1 {
		t.Fatalf("受限恢复状态异常: %+v", status)
	}
}

// TestConfigVariantsKeepTOTPAndRejectRegistration 验证：关闭注册只影响自助注册
// （已有账户仍可登录）；默认关闭 Passkey 不影响 TOTP；启用但未绑定 Passkey 也不
// 阻塞已有密码登录。
func TestConfigVariantsKeepTOTPAndRejectRegistration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clock := newTestClock(time.Date(2026, 11, 23, 5, 0, 0, 0, time.UTC))
	cfg := testConfig()
	databasePath := dir + "/login.db"
	masterKeyPath := dir + "/master.key"
	openWithConfig := func(config login.Config) *Runtime {
		t.Helper()
		runtime, err := Open(ctx, Options{Config: &config, DatabasePath: databasePath,
			MasterKeyFile: masterKeyPath, CreateMasterKey: true, Migrate: true,
			OperatorID: "config-variant-test", Now: clock.Now})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = runtime.Close(context.Background()) })
		return runtime
	}
	first := openWithConfig(cfg)
	if _, err := first.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if _, err := first.Users().Create(ctx, CreateUserRequest{
		Username: "carol", Password: "P3@dF7$hJ1%kM5&n",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("关闭第一个运行时失败: %v", err)
	}

	// 关闭自助注册：已有账户仍可登录，但公开创建入口 reject。
	closedRegistration := first.Config()
	closedRegistration.Registration.Enabled = false
	second := openWithConfig(closedRegistration)
	if _, err := second.Users().Create(ctx, CreateUserRequest{
		Username: "dave", Password: "Q6#zX2!cV8@bN4%m",
		RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		t.Fatalf("关闭注册后公开创建入口应返回 CONFIG_INVALID，实际 %v", err)
	}
	if _, err := second.Auth().Login(ctx, LoginRequest{
		Username: "carol", Password: "P3@dF7$hJ1%kM5&n", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("关闭注册不应影响已有账户登录: %v", err)
	}

	// 启用 Passkey（未绑定凭证）：密码登录不受影响，TOTP 能力仍保留。
	passkeyEnabled := closedRegistration
	passkeyEnabled.Passkey.Enabled = true
	passkeyEnabled.Passkey.RPID = "example.com"
	passkeyEnabled.Passkey.AllowedOrigins = []string{"https://example.com"}
	passkeyEnabled.Passkey.UserVerification = "required"
	third := openWithConfig(passkeyEnabled)
	thirdLogin, err := third.Auth().Login(ctx, LoginRequest{
		Username: "carol", Password: "P3@dF7$hJ1%kM5&n", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Passkey 启用时密码登录失败: %v", err)
	}
	if thirdLogin.Restricted {
		t.Fatalf("未绑定任何第二因素的用户不应被要求第二步: %+v", thirdLogin)
	}
	status, err := third.Security().Status(ctx, SecurityStatusRequest{
		SessionSecret: thirdLogin.SessionSecret})
	if err != nil {
		t.Fatalf("读取安全状态失败: %v", err)
	}
	if !status.PasskeyEnabled || status.PasskeyCount != 0 {
		t.Fatalf("Passkey 状态异常: %+v", status)
	}
	if status.TOTPActive {
		t.Fatalf("carol 未绑定 TOTP: %+v", status)
	}
}
