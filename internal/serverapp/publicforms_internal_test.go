package serverapp

import (
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// TestPublicFormPathsIncludeMFAAndPasswordReset 回归步骤 140/141 真实 serve 发现
// 的 CSRF 公开表单白名单缺口：只合并认证页映射会让 /login/forgot-password、
// /login/reset-password、第二因素等匿名表单被当作会话表单校验而恒 403。
func TestPublicFormPathsIncludeMFAAndPasswordReset(t *testing.T) {
	paths := publicFormPaths("/base")
	mfa := login.UIPageMFAPublicFormPaths("/base")
	if len(mfa) == 0 {
		t.Fatal("MFA 公开表单映射为空")
	}
	for path, purpose := range mfa {
		got, ok := paths[path]
		if !ok {
			t.Fatalf("公开表单缺少 %s", path)
		}
		if got != purpose {
			t.Fatalf("%s 用途 = %q，期望 %q", path, got, purpose)
		}
	}
	account := login.UIPageAccountPublicFormPaths("/base")
	if len(account) == 0 {
		t.Fatal("账户公开表单映射为空")
	}
	for path, purpose := range account {
		if paths[path] != purpose {
			t.Fatalf("账户公开表单 %s 用途不符: %q", path, paths[path])
		}
	}
	auth := login.UIPageAuthPublicFormPaths("/base")
	for path, purpose := range auth {
		if paths[path] != purpose {
			t.Fatalf("认证公开表单 %s 用途不符", path)
		}
	}
}
