package serverapp

// 步骤 189：系统权限管理页再次认证回调的内部测试。使用真实 policy + reauth +
// 审计 + SQLite（不启动监听、不真实外发），验证管理强认证事实缺失/过期、动作名
// 非白名单时 fail-closed，新鲜事实通过真实敏感策略链。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// rbacReauthTestUserID 是闸门测试环境预置的真实用户 ID。
const rbacReauthTestUserID = "usr_00000000000000000000000000000001"

// TestRBACPageReauthFailClosed 覆盖再认证回调的 fail-closed 语义与真实策略通过路径。
func TestRBACPageReauthFailClosed(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	ctx := context.Background()
	// 缺少管理强认证事实：拒绝。
	if err := rbacPageReauth(ctx, gate, rbacReauthTestUserID, "permission.create",
		"system", "req-1"); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("缺少管理事实的再认证 = %v", err)
	}
	// 动作名不在白名单：拒绝且不消耗事实。
	gate.recordManagementFact(rbacReauthTestUserID, testNow)
	if err := rbacPageReauth(ctx, gate, rbacReauthTestUserID, "permission.forge",
		"system", "req-2"); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("非白名单动作的再认证 = %v", err)
	}
	// 过期强认证事实：真实 policy 链按 permission.catalog.change 的近期强认证要求拒绝。
	gate.recordManagementFact(rbacReauthTestUserID, testNow.Add(-10*time.Minute))
	if err := rbacPageReauth(ctx, gate, rbacReauthTestUserID, "permission.delete",
		"perm_00000000000000000000000000000000", "req-3"); err == nil {
		t.Fatal("过期管理强认证事实必须被拒绝")
	}
	// 新鲜强认证事实：通过真实 policy/reauth 链。
	gate.recordManagementFact(rbacReauthTestUserID, testNow)
	if err := rbacPageReauth(ctx, gate, rbacReauthTestUserID, "permission.state.builtin",
		"perm_00000000000000000000000000000000", "req-4"); err != nil {
		t.Fatalf("新鲜管理强认证事实应通过: %v", err)
	}
	// 非法用户 ID：拒绝。
	if err := rbacPageReauth(ctx, gate, "bad id", "permission.create", "system",
		"req-5"); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("非法用户再认证 = %v", err)
	}
	// 依赖未装配：拒绝（不 panic、不放行）。
	if err := rbacPageReauth(ctx, &SecurityGate{}, rbacReauthTestUserID,
		"permission.create", "system", "req-6"); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("闸门未装配再认证 = %v", err)
	}
}
