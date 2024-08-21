package serverapp

// 步骤 190：应用逻辑删除再次认证回调的内部测试。使用真实 policy + reauth + 审计 +
// SQLite（不启动监听、不真实外发），验证管理强认证事实缺失/过期时 fail-closed，
// 新鲜事实通过真实 application.delete 敏感策略。

import (
	"context"
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"testing"
	"time"
)

// appDeleteTestApplicationID 是格式合法的测试应用 ID。
const appDeleteTestApplicationID = "app_00000000000000000000000000000001"

// TestApplicationDeleteReauthFailClosed 覆盖应用删除再次认证回调的 fail-closed 语义
// 与真实策略通过路径。
func TestApplicationDeleteReauthFailClosed(t *testing.T) {
	gate, _ := newSecurityGateTestEnv(t, false)
	ctx := context.Background()
	binding := ui.UIAppDeleteBinding{ApplicationID: appDeleteTestApplicationID,
		ExpectedRowVersion: 3, RequestID: "req-del-1"}
	// 缺少管理强认证事实：拒绝。
	if err := applicationDeleteReauth(ctx, gate, rbacReauthTestUserID, binding); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("缺少管理事实的应用删除再认证 = %v", err)
	}
	// 非法目标/行版本：拒绝（不能绑定空目标）。
	badBinding := ui.UIAppDeleteBinding{ApplicationID: "bad-id", ExpectedRowVersion: 0}
	if err := applicationDeleteReauth(ctx, gate, rbacReauthTestUserID, badBinding); !errors.Is(err, reauth.ErrInvalidRequest) {
		t.Fatalf("非法绑定的应用删除再认证 = %v", err)
	}
	// 过期强认证事实：真实策略链按 application.delete 的近期强认证要求拒绝。
	gate.recordManagementFact(rbacReauthTestUserID, testNow.Add(-10*time.Minute))
	if err := applicationDeleteReauth(ctx, gate, rbacReauthTestUserID, binding); err == nil {
		t.Fatal("过期管理强认证事实必须被拒绝")
	}
	// 新鲜强认证事实：通过真实 policy/reauth 链。
	gate.recordManagementFact(rbacReauthTestUserID, testNow)
	if err := applicationDeleteReauth(ctx, gate, rbacReauthTestUserID, binding); err != nil {
		t.Fatalf("新鲜管理强认证事实应通过: %v", err)
	}
	// 闸门依赖未装配：拒绝（不 panic、不放行）。
	if err := applicationDeleteReauth(ctx, &SecurityGate{}, rbacReauthTestUserID,
		binding); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("未装配闸门的应用删除再认证 = %v", err)
	}
}
