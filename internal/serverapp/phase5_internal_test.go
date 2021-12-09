package serverapp

// 敏感操作链路内部测试：真实 policy + reauth + 审计 + SQLite（不启动监听、
// 不真实外发）。覆盖通过 / 拒绝 / 过期事实 / 强认证不可满足 / 告知失败留痕。

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// newSecurityGateTestEnv 构造真实服务的敏感操作闸门。
func newSecurityGateTestEnv(t *testing.T, strongAvailable bool) (*SecurityGate, Deps) {
	t.Helper()
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	cfg := login.Default()
	cfg.Database.Path = "unused.db"
	deps := Deps{
		Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return testNow },
	}
	sensitive := &sensitiveRelay{}
	presence := &strongFactorRelay{}
	services, err := BuildServicesWithHooks(deps, SecurityHooks{
		Sensitive: sensitive, StrongPresence: presence})
	if err != nil {
		t.Fatalf("构造服务失败: %v", err)
	}
	gate, err := BuildSecurityGate(deps, services.BootstrapStore, services.Authn, strongAvailable)
	if err != nil {
		t.Fatalf("构造敏感操作闸门失败: %v", err)
	}
	sensitive.Set(gate.Reauth)
	// 真实用户行：敏感操作告知记录与用户主体存在外键约束。
	now := testNow.UnixMilli()
	if _, err := store.DB().ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'测试用户','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		"usr_00000000000000000000000000000001", "gate-user", "gate-user", now, now); err != nil {
		t.Fatalf("插入测试用户失败: %v", err)
	}
	return gate, deps
}

// freshSignals 构造页面适配器在真实 reauth 挑战通过后合成的可信信号。
func freshSignals(now time.Time) reauth.Signals {
	return reauth.Signals{
		VerifiedAt: now, Strength: policy.StrengthPassword,
		Complete: true, Confirmed: true,
	}
}

// TestReauthGatePassesWithFreshSignals 验证携带真实近期验证事实的敏感操作通过。
func TestReauthGatePassesWithFreshSignals(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	caller, err := reauth.UserCaller("usr_00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("构造调用者失败: %v", err)
	}
	ctx := reauth.WithSignals(context.Background(), freshSignals(testNow))
	result, err := gate.Reauth.Authorize(ctx, caller, reauth.Request{
		ScopeID: "system", OperationID: "password.change",
		TargetType: "user", TargetID: "usr_00000000000000000000000000000001",
		Description: "修改密码",
	})
	if err != nil {
		t.Fatalf("近期验证事实应通过敏感策略: %v", err)
	}
	if result.Method != "direct" {
		t.Fatalf("通过方式 = %q，期望 direct", result.Method)
	}
}

// TestReauthGateRejectsWithoutSignals 验证缺少验证事实时 fail-closed。
func TestReauthGateRejectsWithoutSignals(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	caller, _ := reauth.UserCaller("usr_00000000000000000000000000000001")
	_, err := gate.Reauth.Authorize(context.Background(), caller, reauth.Request{
		ScopeID: "system", OperationID: "password.change",
		TargetType: "user", TargetID: "usr_00000000000000000000000000000001",
	})
	if err == nil {
		t.Fatal("缺少验证事实的敏感操作必须被拒绝")
	}
	var code = reauth.CodeOf(err)
	if code != reauth.CodeReauthRequired && code != reauth.CodeMFARequired {
		t.Fatalf("拒绝错误码 = %q，期望 REAUTH_REQUIRED/MFA_REQUIRED", code)
	}
}

// TestReauthGateRejectsStaleSignals 验证过期验证事实被拒绝。
func TestReauthGateRejectsStaleSignals(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	caller, _ := reauth.UserCaller("usr_00000000000000000000000000000001")
	stale := freshSignals(testNow.Add(-2 * time.Hour))
	_, err := gate.Reauth.Authorize(reauth.WithSignals(context.Background(), stale), caller,
		reauth.Request{ScopeID: "system", OperationID: "password.change",
			TargetType: "user", TargetID: "usr_00000000000000000000000000000001"})
	if err == nil {
		t.Fatal("过期验证事实必须被拒绝")
	}
}

// TestReauthGateStrongRequirementFailsClosed 验证强认证不可满足时的策略操作失败，
// 不会降级为密码强度。
func TestReauthGateStrongRequirementFailsClosed(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	caller, _ := reauth.UserCaller("usr_00000000000000000000000000000001")
	_, err := gate.Reauth.Authorize(
		reauth.WithSignals(context.Background(), freshSignals(testNow)), caller,
		reauth.Request{ScopeID: "system", OperationID: "application.credential.rotate",
			TargetType: "application", TargetID: "app_00000000000000000000000000000001"})
	if err == nil {
		t.Fatal("需要强认证但强认证不可用时必须拒绝")
	}
}

// TestReauthNotifyFailureRecordedWithoutExternalSend 验证安全告知在未配置真实
// 发送器时以明确失败留痕（不真实外发、不伪造成功）。
func TestReauthNotifyFailureRecordedWithoutExternalSend(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	caller, _ := reauth.UserCaller("usr_00000000000000000000000000000001")
	result, err := gate.Reauth.Authorize(
		reauth.WithSignals(context.Background(), freshSignals(testNow)), caller,
		reauth.Request{ScopeID: "system", OperationID: "password.change",
			TargetType: "user", TargetID: "usr_00000000000000000000000000000001"})
	if err != nil {
		t.Fatalf("通过路径失败: %v", err)
	}
	notifyErr := gate.Reauth.NotifyOutcome(context.Background(), result, reauth.OutcomeSuccess)
	if notifyErr == nil {
		t.Fatal("未配置真实邮件发送器时安全告知必须返回明确失败")
	}
	if !errors.Is(notifyErr, reauth.ErrNotificationFailed) {
		t.Fatalf("告知失败原因 = %v，期望 ErrNotificationFailed", notifyErr)
	}
}

// TestSecurityPolicyReauthRequiresManagementFact 验证敏感策略页写入在没有真实
// 管理会话强认证事实时 fail-closed。
func TestSecurityPolicyReauthRequiresManagementFact(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, true)
	err := gate.SecurityPolicyReauth(context.Background(),
		"usr_00000000000000000000000000000001",
		login.UISecurityPolicyActionBinding{Action: "policy.save"})
	if err == nil {
		t.Fatal("缺少管理会话强认证事实时必须拒绝策略写入再次认证")
	}
}

// TestPolicyWriteApprovalBoundToOneChange 验证敏感策略写批准绑定一次具体变更：
// 写之前必须授权（否则 finish 失败且记录清理、不残留批准）、版本/摘要不一致拒绝、
// 信号只发放一次、结束后重放拒绝。
func TestPolicyWriteApprovalBoundToOneChange(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, true)
	userID := "usr_00000000000000000000000000000001"
	digestA := policyWriteDigest("policy.save", "system", "password.change", 3, "change-a")
	digestB := policyWriteDigest("policy.save", "system", "password.change", 4, "change-b")

	// 未授权就结束：拒绝并清理，不能残留可复用批准。
	if err := gate.beginPolicyWriteLocked(userID, "policy.save", "system",
		"password.change", 3, digestA); err != nil {
		t.Fatalf("登记 A 失败: %v", err)
	}
	if err := gate.finishPolicyWrite(userID, digestA); err == nil {
		t.Fatal("未授权（未真实再次认证）的策略写不得完成")
	}
	if _, err := gate.issuePolicyWriteSignals(userID, securityPolicyOperationID); err == nil {
		t.Fatal("未授权时不得向 policy.Set 发放信号")
	}
	// 记录已清理：重新登记可用，说明 finish 失败不残留批准。
	if err := gate.beginPolicyWriteLocked(userID, "policy.save", "system",
		"password.change", 3, digestA); err != nil {
		t.Fatalf("finish 失败后应无残留记录，重新登记失败: %v", err)
	}
	// 非 root 调用 authorizePolicyWrite 必须拒绝；摘要/版本不一致同样拒绝。
	if err := gate.authorizePolicyWrite(context.Background(), userID, "policy.save",
		"system", "password.change", 3, digestA); err == nil {
		t.Fatal("非 root 不得授权策略写")
	}
	if err := gate.authorizePolicyWrite(context.Background(), userID, "policy.save",
		"system", "password.change", 4, digestB); err == nil {
		t.Fatal("版本/摘要与登记不一致时不得授权（批准 A 不能用于 B）")
	}
	// 仍无法发放信号/完成：批准未被授权且摘要不匹配。
	if _, err := gate.issuePolicyWriteSignals(userID, securityPolicyOperationID); err == nil {
		t.Fatal("未授权变更不得发放信号")
	}
	gate.abortPolicyWrite(userID)
	// 结束后重放：旧批准不再可用。
	if _, err := gate.issuePolicyWriteSignals(userID, securityPolicyOperationID); err == nil {
		t.Fatal("已清理的批准不得重放")
	}
	if err := gate.finishPolicyWrite(userID, digestA); err == nil {
		t.Fatal("已清理记录重复 finish 必须拒绝")
	}
}

// TestManagementFactExpires 验证管理强认证事实 30 秒窗口过期后必须重新授权。
func TestManagementFactExpires(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, true)
	userID := "usr_00000000000000000000000000000001"
	gate.recordManagementFact(userID, testNow)
	if _, ok := gate.takeManagementFact(userID); !ok {
		t.Fatal("刚登记的管理强认证事实应可用")
	}
	// 一次性消费：再次取用失败。
	if _, ok := gate.takeManagementFact(userID); ok {
		t.Fatal("管理强认证事实必须一次性消费")
	}
	// 窗口过期：把登记时间推早 31 秒后不可用。
	gate.recordManagementFact(userID, testNow)
	gate.mu.Lock()
	fact := gate.management[userID]
	fact.recordedAt = time.Now().Add(-31 * time.Second)
	gate.management[userID] = fact
	gate.mu.Unlock()
	if _, ok := gate.takeManagementFact(userID); ok {
		t.Fatal("超过 30 秒窗口的管理强认证事实必须失效")
	}
	if managementFactTTL != 30*time.Second {
		t.Fatalf("managementFactTTL = %s，期望 30s", managementFactTTL)
	}
}
