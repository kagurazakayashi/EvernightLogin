package policy_test

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// TestSelfServiceOperationsRegistered 验证步骤 67 自助敏感操作已登记、已实现、
// 使用近期主密码强度且仅作用于本人（不含管理员强制下线语义）。
func TestSelfServiceOperationsRegistered(t *testing.T) {
	catalog := policy.DefaultCatalog()
	for _, id := range []string{"session.revoke.self", "oauth.authorization.revoke.self",
		"mfa.remove"} {
		operation, found := catalog.Lookup(id)
		if !found {
			t.Fatalf("自助敏感操作未登记: %s", id)
		}
		if !operation.Implemented {
			t.Errorf("操作 %s 应标记为已实现", id)
		}
		if !operation.Default.Sensitive || !operation.Default.ReauthRequired ||
			operation.Default.Strength != policy.StrengthPassword ||
			operation.Default.MaxAuthAgeSeconds <= 0 {
			t.Errorf("操作 %s 策略应为近期主密码再次验证: %+v", id, operation.Default)
		}
		if id == "session.revoke.self" && operation.RootOnly {
			t.Errorf("自助退出会话不应为 root 专属")
		}
	}
	// 管理员强制下线仍保持独立、非自助语义。
	admin, found := catalog.Lookup("session.revoke.other")
	if !found || admin.Name == "退出自己的会话" {
		t.Fatal("管理员强制下线操作定义被混淆")
	}
}
