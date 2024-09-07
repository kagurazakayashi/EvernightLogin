package role_test

// 步骤 262：角色列表有界字面搜索。复用 internal/search 的规范化与转义约定，
// 在调��方可管理范围之后过滤；不因搜索泄露其他应用范围的角色。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// TestRoleListSearch 验收角色名称/机器标识的字面搜索与范围隔离。
func TestRoleListSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createRole(role.ScopeSystem, "audit-helper", "审计助手")
	env.createRole(role.ScopeSystem, "support-helper", "Support Helper")
	env.createRole(role.ScopeSystem, "percent-role", "100%审计")
	env.createRole(role.ScopeSystem, "quote-role", "o'brien [组]")
	// 两个应用范围同名角色：应用管理员搜索不得跨应用枚举。
	env.createAppRole(testApplicationOne, "shared-role", "共享角色")
	env.createAppRole(testApplicationTwo, "shared-role", "共享角色")

	list := func(caller role.Caller, request role.ListRequest) role.ListResult {
		t.Helper()
		result, err := env.service.ListRoles(ctx, caller, request)
		if err != nil {
			t.Fatalf("ListRoles(%+v): %v", request.Search, err)
		}
		return result
	}
	names := func(result role.ListResult) []string {
		values := make([]string, 0, len(result.Roles))
		for _, item := range result.Roles {
			values = append(values, item.Name)
		}
		return values
	}
	assertContains := func(label string, got []string, want ...string) {
		t.Helper()
		set := make(map[string]struct{}, len(got))
		for _, value := range got {
			set[value] = struct{}{}
		}
		for _, value := range want {
			if _, ok := set[value]; !ok {
				t.Fatalf("%s: 结果 %v 缺少 %q", label, got, value)
			}
		}
	}

	// 中文名称子串。
	assertContains("中文", names(list(env.system, role.ListRequest{Limit: 20, Search: "审计"})),
		"审计助手", "100%审计")
	// 大小写折叠 + 机器标识子串：AUDIT 命中名称与 role_key。
	assertContains("大小写", names(list(env.system, role.ListRequest{Limit: 20, Search: "AUDIT"})),
		"审计助手")
	// 通配符与方言特殊字符按字面。
	assertContains("百分号字面", names(list(env.system, role.ListRequest{Limit: 20, Search: "%"})),
		"100%审计")
	assertContains("单引号字面", names(list(env.system, role.ListRequest{Limit: 20, Search: "'"})),
		"o'brien [组]")
	assertContains("方括号字面", names(list(env.system, role.ListRequest{Limit: 20, Search: "["})),
		"o'brien [组]")
	// 字段白名单：只搜机器标识时不命中仅中文名称的角色。
	keyOnly := list(env.system, role.ListRequest{Limit: 20, Search: "审计",
		SearchFields: []role.RoleSearchField{role.RoleSearchKey}})
	if len(keyOnly.Roles) != 0 {
		t.Fatalf("只搜 key 不应命中中文名称: %v", names(keyOnly))
	}
	nameOnly := list(env.system, role.ListRequest{Limit: 20, Search: "helper",
		SearchFields: []role.RoleSearchField{role.RoleSearchName}})
	if len(nameOnly.Roles) != 1 || nameOnly.Roles[0].Key != "support-helper" {
		t.Fatalf("只搜 name 结果 = %v", names(nameOnly))
	}
	// 空搜索保持原列表（系统操作者可管理全部范围，与角色总数一致）。
	wantTotal := env.queryInt(`SELECT COUNT(*) FROM roles`)
	if result := list(env.system, role.ListRequest{Limit: 100, Search: "  "}); len(result.Roles) != wantTotal {
		t.Fatalf("空搜索结果数 = %d，期望 %d", len(result.Roles), wantTotal)
	}
	// 无匹配。
	if result := list(env.system, role.ListRequest{Limit: 20, Search: "不存在"}); len(result.Roles) != 0 {
		t.Fatalf("无匹配结果 = %v", names(result))
	}
	// 非法字段/超长搜索拒绝。
	if _, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 20, Search: "x", SearchFields: []role.RoleSearchField{"description"},
	}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("非法字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 20, Search: strings.Repeat("a", 65),
	}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}

	// 应用范围隔离：应用一管理员搜索“共享角色”只返回应用一范围的角色。
	appOneAdmin := env.appAdminCaller(testApplicationOne, testUserActive)
	appResult := list(appOneAdmin, role.ListRequest{ScopeID: testApplicationOne, Limit: 20, Search: "共享"})
	if len(appResult.Roles) != 1 || appResult.Roles[0].ScopeID != testApplicationOne {
		t.Fatalf("应用一搜索范围 = %+v", appResult.Roles)
	}
	// 不带 ScopeID 也只会返回可管理范围（应用一），不是全局。
	allScopes := list(appOneAdmin, role.ListRequest{Limit: 20, Search: "共享"})
	if len(allScopes.Roles) != 1 || allScopes.Roles[0].ScopeID != testApplicationOne {
		t.Fatalf("应用一全范围搜索 = %+v", allScopes.Roles)
	}
	// 显式请求应用二范围仍拒绝。
	if _, err := env.service.ListRoles(ctx, appOneAdmin, role.ListRequest{
		ScopeID: testApplicationTwo, Limit: 20, Search: "共享",
	}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("跨应用搜索错误 = %v，期望 ErrAccessDenied", err)
	}

	// 禁用过滤与搜索组合保持：停用一个角色后 Enabled=false 才命中。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE roles SET enabled=0 WHERE scope_id='system' AND role_key='support-helper'`); err != nil {
		t.Fatalf("停用角色夹具失败: %v", err)
	}
	disabledFlag := false
	disabledResult := list(env.system, role.ListRequest{Limit: 20, Search: "helper",
		Enabled: &disabledFlag})
	if len(disabledResult.Roles) != 1 || disabledResult.Roles[0].Key != "support-helper" {
		t.Fatalf("搜索+禁用过滤结果 = %v", names(disabledResult))
	}

	// 审计编号：列表读取审计保留调用者请求编号。
	caller, err := env.system.WithRequestID("req-role-search-262")
	if err != nil {
		t.Fatalf("构造带请求编号调用者失败: %v", err)
	}
	if _, err := env.service.ListRoles(ctx, caller, role.ListRequest{Limit: 5, Search: "helper"}); err != nil {
		t.Fatalf("带请求编号搜索失败: %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND request_id=?`,
		string(role.ActionListRoles), "req-role-search-262"); got != 1 {
		t.Fatalf("role.list 审计请求编号记录 = %d，期望 1", got)
	}
}
