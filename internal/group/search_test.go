package group_test

// 步骤 262：用户组列表有界字面搜索（名称/机器标识）。复用 internal/search；
// 搜索在可管理范围之后执行，应用管理员不因搜索跨应用枚举用户组。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

// createSearchGroup 用指定名称创建用户组。
func (e *testEnv) createSearchGroup(scopeID, key, name string) group.Group {
	e.t.Helper()
	record, err := e.service.CreateGroup(context.Background(), e.system, group.CreateRequest{
		ScopeID: scopeID, GroupKey: key, Name: name, Description: "说明 " + name,
	})
	if err != nil {
		e.t.Fatalf("创建用户组 %q 失败: %v", key, err)
	}
	return record
}

// TestGroupListSearch 验收用户组名称/机器标识的字面搜索与范围隔离。
func TestGroupListSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createSearchGroup(group.ScopeSystem, "audit-team", "审计组")
	env.createSearchGroup(group.ScopeSystem, "support-team", "Support Group")
	env.createSearchGroup(group.ScopeSystem, "percent-team", "100%组")
	env.createSearchGroup(group.ScopeSystem, "quote-team", "o'brien [组]")
	env.createSearchGroup(appOne, "shared-team", "跨应用组")
	env.createSearchGroup(appTwo, "shared-team", "跨应用组")

	list := func(caller group.Caller, request group.ListRequest) []string {
		t.Helper()
		result, err := env.service.ListGroups(ctx, caller, request)
		if err != nil {
			t.Fatalf("ListGroups(%+v): %v", request.Search, err)
		}
		names := make([]string, 0, len(result.Groups))
		for _, item := range result.Groups {
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
	assertExactly("中文", list(env.system, group.ListRequest{Limit: 20, Search: "审计"}),
		"审计组")
	// 大小写折叠：SUPPORT 命中名称与 group_key。
	assertExactly("大小写", list(env.system, group.ListRequest{Limit: 20, Search: "SUPPORT"}),
		"Support Group")
	// 通配符/单引号/方括号按字面。
	assertExactly("百分号字面", list(env.system, group.ListRequest{Limit: 20, Search: "%"}),
		"100%组")
	assertExactly("单引号字面", list(env.system, group.ListRequest{Limit: 20, Search: "'"}),
		"o'brien [组]")
	assertExactly("方括号字面", list(env.system, group.ListRequest{Limit: 20, Search: "["}),
		"o'brien [组]")
	// 字段白名单。
	if got := list(env.system, group.ListRequest{Limit: 20, Search: "审计",
		SearchFields: []group.GroupSearchField{group.GroupSearchKey}}); len(got) != 0 {
		t.Fatalf("只搜 key 不应命中中文名称: %v", got)
	}
	assertExactly("只搜 name", list(env.system, group.ListRequest{Limit: 20, Search: "support",
		SearchFields: []group.GroupSearchField{group.GroupSearchName}}), "Support Group")
	// 空搜索保持原列表。
	wantTotal := env.queryInt(`SELECT COUNT(*) FROM user_groups`)
	if got := list(env.system, group.ListRequest{Limit: 100, Search: "  "}); len(got) != wantTotal {
		t.Fatalf("空搜索结果数 = %d，期望 %d", len(got), wantTotal)
	}
	// 非法字段/超长拒绝。
	if _, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 20, Search: "x", SearchFields: []group.GroupSearchField{"description"},
	}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("非法字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListGroups(ctx, env.system, group.ListRequest{
		Limit: 20, Search: strings.Repeat("a", 65),
	}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 应用范围隔离：应用一管理员只返回应用一范围的同名组。
	if err := env.authorizer.AssignApplicationAdmin(appOne, adminOne); err != nil {
		t.Fatalf("分配应用管理员失败: %v", err)
	}
	appAdmin, err := group.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}
	appResult, err := env.service.ListGroups(ctx, appAdmin, group.ListRequest{
		ScopeID: appOne, Limit: 20, Search: "跨应用"})
	if err != nil {
		t.Fatalf("应用管理员搜索失败: %v", err)
	}
	if len(appResult.Groups) != 1 || appResult.Groups[0].ScopeID != appOne {
		t.Fatalf("应用一搜索结果 = %+v", appResult.Groups)
	}
	if _, err := env.service.ListGroups(ctx, appAdmin, group.ListRequest{
		ScopeID: appTwo, Limit: 20, Search: "跨应用",
	}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("跨应用搜索错误 = %v，期望 ErrAccessDenied", err)
	}
}
