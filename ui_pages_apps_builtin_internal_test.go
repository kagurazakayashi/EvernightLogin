package login

import "testing"

func TestAppsBuiltinMessagesRegistered(t *testing.T) {
	if _, ok := builtinAuthMessages["page.admin.applications.common.permission_required"]; !ok {
		t.Fatalf("缺少权限拒绝文案注册")
	}
}
