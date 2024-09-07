package permission_test

// 步骤 262：权限目录列表有界字面搜索（名称/机器标识）。复用 internal/search
// 规范化与转义；搜索在可见范围过滤之后执行，内置/root_only 保护不变。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

// createNamedPermission 用指定名称创建系统自定义权限。
func (e *testEnv) createNamedPermission(key, name string) permission.Permission {
	e.t.Helper()
	record, err := e.service.CreatePermission(context.Background(), e.system, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: key, Name: name,
		Description: "说明 " + name, Limits: "限制 " + name,
	})
	if err != nil {
		e.t.Fatalf("创建权限 %q 失败: %v", key, err)
	}
	return record
}

// TestPermissionListSearch 验收权限名称/键的字面搜索与范围隔离。
func TestPermissionListSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createNamedPermission("test.audit.read", "审计查看")
	env.createNamedPermission("test.support.helper", "Support Helper")
	env.createNamedPermission("test.percent.role", "100%审计")
	env.createNamedPermission("test.quote.role", "o'brien [组]")
	// 两个应用范围同名权限：应用管理员搜索不得跨应用枚举。
	appAdmin, err := permission.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}
	for _, scopeID := range []string{appOne, appTwo} {
		if _, err := env.service.CreatePermission(ctx, env.system, permission.CreateRequest{
			ScopeID: scopeID, Key: "shared.read", Name: "跨应用权限", Description: "说明",
			Limits: "限制",
		}); err != nil {
			t.Fatalf("创建应用权限失败: %v", err)
		}
	}
	list := func(caller permission.Caller, request permission.ListRequest) []string {
		t.Helper()
		result, err := env.service.ListPermissions(ctx, caller, request)
		if err != nil {
			t.Fatalf("ListPermissions(%+v): %v", request.Search, err)
		}
		names := make([]string, 0, len(result.Permissions))
		for _, item := range result.Permissions {
			names = append(names, item.Name)
		}
		return names
	}
	assertExactly := func(label string, got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: 结果 = %v，期望 %v", label, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("%s: 结果 = %v，期望 %v", label, got, want)
			}
		}
	}
	assertExactly("中文", list(env.system, permission.ListRequest{Limit: 20, Search: "审计",
		Sort: permission.SortName}),
		"100%审计", "审计查看")
	// 大小写折叠：SUPPORT 命中名称 Support Helper 与 key test.support.helper 是同一条。
	assertExactly("大小写", list(env.system, permission.ListRequest{Limit: 20, Search: "SUPPORT"}),
		"Support Helper")
	// 通配符与方言特殊字符按字面。
	assertExactly("百分号字面", list(env.system, permission.ListRequest{Limit: 20, Search: "%"}),
		"100%审计")
	assertExactly("单引号字面", list(env.system, permission.ListRequest{Limit: 20, Search: "'"}),
		"o'brien [组]")
	assertExactly("方括号字面", list(env.system, permission.ListRequest{Limit: 20, Search: "["}),
		"o'brien [组]")
	// 字段白名单：只搜 key 不命中仅中文名称的权限；只搜 name 命 name。
	if got := list(env.system, permission.ListRequest{Limit: 20, Search: "审计",
		SearchFields: []permission.PermissionSearchField{permission.PermissionSearchKey}}); len(got) != 0 {
		t.Fatalf("只搜 key 不应命中中文名称: %v", got)
	}
	assertExactly("只搜 name", list(env.system, permission.ListRequest{Limit: 20, Search: "support",
		SearchFields: []permission.PermissionSearchField{permission.PermissionSearchName}}),
		"Support Helper")
	// 空搜索保持原列表（系统操作者可管理全部范围，与权限总数一致）。
	wantTotal := env.queryInt(`SELECT COUNT(*) FROM permissions`)
	if got := list(env.system, permission.ListRequest{Limit: 100, Search: "  "}); len(got) != wantTotal {
		t.Fatalf("空搜索结果数 = %d，期望 %d", len(got), wantTotal)
	}
	// 非法字段/超长搜索拒绝。
	if _, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 20, Search: "x", SearchFields: []permission.PermissionSearchField{"description"},
	}); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("非法字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 20, Search: strings.Repeat("a", 65),
	}); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 应用范围隔离：应用一管理员只返回应用一范围的同名权限。
	appResult, err := env.service.ListPermissions(ctx, appAdmin, permission.ListRequest{
		ScopeID: appOne, Limit: 20, Search: "跨应用"})
	if err != nil {
		t.Fatalf("应用管理员搜索失败: %v", err)
	}
	if len(appResult.Permissions) != 1 || appResult.Permissions[0].ScopeID != appOne {
		t.Fatalf("应用一搜索结果 = %+v", appResult.Permissions)
	}
	if _, err := env.service.ListPermissions(ctx, appAdmin, permission.ListRequest{
		ScopeID: appTwo, Limit: 20, Search: "跨应用",
	}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("跨应用搜索错误 = %v，期望 ErrAccessDenied", err)
	}
}
