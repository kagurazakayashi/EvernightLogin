package serverapp

// 步骤 188 Q7 组件级集成证据：真实 OpenBase（SQLite/authn/mfa）+ 重绑状态。
// 真实 Passkey ceremony 无法在本测试环境自动完成，这里用真实 MFA 管理员重置写入
// 重绑需求，验证“登录受限 → 清除需求 → 完整登录”的状态机；Passkey 绑定的真实
// 浏览器 ceremony 仍属未测（见 step188-dev.md）。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// TestStep188RebindForcesRestrictedLogin 验证 MFA 重置后的重绑需求使真实登录受限，
// 清除需求后才恢复完整登录；目标不是 root/高权账户。
func TestStep188RebindForcesRestrictedLogin(t *testing.T) {
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	const targetID = "usr_000000000000000000000000000000f1"
	nowMS := testNow.UnixMilli()
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, targetID, "rebind-target", "rebind-target", nowMS, nowMS); err != nil {
		t.Fatalf("插入用户: %v", err)
	}
	systemCaller, err := authn.SystemCaller("rebind-e2e")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	const password = "Hx4!bW8#Tq3@Zn7"
	setCtx := reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: testNow,
		Strength: policy.StrengthStrong, Complete: true, Confirmed: true})
	if _, err := base.Services.Authn.SetPassword(setCtx, systemCaller, authn.SetPasswordRequest{
		TargetUserID: targetID, NewPassword: password,
		RequestID: "req-rebind-initial"}); err != nil {
		t.Fatalf("设置初始密码: %v", err)
	}
	// 正常登录应完整。
	normal, err := base.Services.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: "rebind-target", Password: password, ClientIP: "127.0.0.1",
		RequestID: "req-rebind-login-1"})
	if err != nil || normal.Outcome != authn.OutcomeComplete {
		t.Fatalf("初始登录应完整: %v/%v", err, normal.Outcome)
	}
	// 真实 MFA 管理员重置（写同事务重绑需求）。
	mfaCaller, err := mfa.SystemCaller("rebind-e2e")
	if err != nil {
		t.Fatalf("MFA 系统调用者: %v", err)
	}
	if _, err := base.Security.MFA.AdminResetFactors(ctx, mfaCaller, mfa.AdminResetRequest{
		TargetUserID: targetID, Reason: "人工恢复 MFA 重置（测试）",
		RequestID: "req-rebind-reset"}); err != nil {
		t.Fatalf("MFA 管理员重置: %v", err)
	}
	// 登录必须受限并要求强认证初始化。
	restricted, err := base.Services.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: "rebind-target", Password: password, ClientIP: "127.0.0.1",
		RequestID: "req-rebind-login-2"})
	if err != nil {
		t.Fatalf("受限登录不应返回错误: %v", err)
	}
	if restricted.Outcome == authn.OutcomeComplete {
		t.Fatalf("重绑需求存在时登录不应完整: %+v", restricted)
	}
	foundSetup := false
	for _, step := range restricted.RequiredSteps {
		if step == authn.StepStrongAuthSetup {
			foundSetup = true
		}
	}
	if !foundSetup {
		t.Fatalf("受限登录缺少强认证初始化步骤: %+v", restricted.RequiredSteps)
	}
	// 清除重绑需求（等价于 Passkey 初始化完成后的清除）→ 登录恢复完整。
	rebind := mfaRebindRequirementStore{store: base.Store, audit: base.Deps.Audit, logger: base.Deps.Logger}
	if err := rebind.ClearRebindRequirement(ctx, targetID, "req-rebind-clear"); err != nil {
		t.Fatalf("清除重绑需求: %v", err)
	}
	restored, err := base.Services.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: "rebind-target", Password: password, ClientIP: "127.0.0.1",
		RequestID: "req-rebind-login-3"})
	if err != nil || restored.Outcome != authn.OutcomeComplete {
		t.Fatalf("清除需求后登录应完整: %v/%v", err, restored.Outcome)
	}
}
