package app_test

// 步骤 262：应用列表有界字面搜索（名称/描述）。复用 internal/search；
// 搜索在可管理范围之后执行，应用管理员不因搜索枚举未分配应用；状态/删除过滤不变。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// createNamedApp 创建指定名称/描述的应用（负责人为已插入的可用账户）。
func (e *testEnv) createNamedApp(name, description string) app.Application {
	e.t.Helper()
	record, err := e.service.CreateApplication(context.Background(), e.system, app.CreateRequest{
		Name: name, Description: description, ClientType: app.ClientTypeConfidential,
		OwnerUserID: testOwnerOne,
	})
	if err != nil {
		e.t.Fatalf("创建应用 %q 失败: %v", name, err)
	}
	return record
}

// TestApplicationListSearch 验收应用名称/描述的字面搜索与范围隔离。
func TestApplicationListSearch(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	alpha := env.createNamedApp("Alpha应用", "处理订单的应用")
	env.createNamedApp("Beta应用", "100%审计用应用")
	env.createNamedApp("Gamma应用", "o'brien [组] 用应用")

	search := func(caller app.Caller, request app.ListRequest) []string {
		t.Helper()
		request.Limit = 20
		result, err := env.service.ListApplications(ctx, caller, request)
		if err != nil {
			t.Fatalf("ListApplications(%+v): %v", request.Search, err)
		}
		names := make([]string, 0, len(result.Applications))
		for _, item := range result.Applications {
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
	// 名称子串 + 大小写折叠。
	assertExactly("名称", search(env.system, app.ListRequest{Search: "alpha"}), "Alpha应用")
	// 全角 NFKC 折半角。
	assertExactly("全角", search(env.system, app.ListRequest{Search: "ＡＬＰＨＡ"}), "Alpha应用")
	// 描述字段匹配（名称不含“订单”）。
	assertExactly("描述", search(env.system, app.ListRequest{Search: "订单"}), "Alpha应用")
	// 通配符/单引号/方括号按字面。
	assertExactly("百分号字面", search(env.system, app.ListRequest{Search: "%"}),
		"Beta应用")
	assertExactly("单引号字面", search(env.system, app.ListRequest{Search: "'"}), "Gamma应用")
	assertExactly("方括号字面", search(env.system, app.ListRequest{Search: "["}), "Gamma应用")
	// 字段白名单：只搜描述时名称命中消失。
	if got := search(env.system, app.ListRequest{Search: "alpha",
		SearchFields: []app.ApplicationSearchField{app.ApplicationSearchDescription}}); len(got) != 0 {
		t.Fatalf("只搜描述不应命中名称: %v", got)
	}
	assertExactly("只搜描述", search(env.system, app.ListRequest{Search: "订单",
		SearchFields: []app.ApplicationSearchField{app.ApplicationSearchDescription}}), "Alpha应用")
	// 空搜索保持原列表。
	wantTotal := env.queryInt(`SELECT COUNT(*) FROM applications WHERE deleted_at_ms IS NULL`)
	if got := search(env.system, app.ListRequest{Search: "  "}); len(got) != wantTotal {
		t.Fatalf("空搜索结果数 = %d，期望 %d", len(got), wantTotal)
	}
	// 非法字段/超长拒绝。
	if _, err := env.service.ListApplications(ctx, env.system, app.ListRequest{
		Limit: 20, Search: "x", SearchFields: []app.ApplicationSearchField{"owner"},
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("非法字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListApplications(ctx, env.system, app.ListRequest{
		Limit: 20, Search: strings.Repeat("a", 65),
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 状态过滤与搜索组合：启用后再停用应用，active 搜索不命中、disabled 命中。
	if _, err := env.service.EnableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: alpha.ID, ExpectedRowVersion: alpha.RowVersion,
	}); err != nil {
		t.Fatalf("启用应用失败: %v", err)
	}
	enabled, err := env.service.GetApplication(ctx, env.system, alpha.ID)
	if err != nil {
		t.Fatalf("读取启用后的应用失败: %v", err)
	}
	if _, err := env.service.DisableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: alpha.ID, ExpectedRowVersion: enabled.RowVersion,
	}); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	if got := search(env.system, app.ListRequest{Search: "alpha", Status: app.StatusActive}); len(got) != 0 {
		t.Fatalf("状态过滤后仍命中已停用应用: %v", got)
	}
	assertExactly("状态过滤", search(env.system, app.ListRequest{Search: "alpha",
		Status: app.StatusDisabled}), "Alpha应用")
	// 应用管理员范围隔离：只分配 Alpha 时搜索“应用”只返回 Alpha。
	if err := env.authorizer.AssignApplicationAdmin(alpha.ID, testAppAdmin); err != nil {
		t.Fatalf("分配应用管理员失败: %v", err)
	}
	adminCaller := env.userCaller(testAppAdmin)
	assertExactly("应用管理员范围", search(adminCaller, app.ListRequest{Search: "应用"}),
		"Alpha应用")
}
