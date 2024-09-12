package support_test

// 步骤 263：客服工单列表有界字面搜索（编号/原因）。只搜索可见字段，不搜索脱敏
// 邮箱/用户名；搜索在 staffScope+Assignee 授权范围之后执行。

import (
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// TestCaseListSearch 验收工单编号/原因的字面搜索、跨客服隔离与边界。
func TestCaseListSearch(t *testing.T) {
	env := newTestEnv(t, nil)
	own := env.createCase(t, staffOne, targetA, "用户来电求助：忘记密码 100%")
	env.createCase(t, staffOne, targetA, "o'brien [组] 申请改名")
	// 另一客服的工单：搜索不能跨分工返回。
	env.createCase(t, staffTwo, targetB, "用户来电求助：重复主题")

	search := func(caller support.Caller, request support.CaseListRequest) support.CasePage {
		t.Helper()
		page, err := env.svc.ListCasesPage(env.ctx, caller, request)
		if err != nil {
			t.Fatalf("ListCasesPage(%+v): %v", request.Search, err)
		}
		return page
	}
	assertIDs := func(label string, page support.CasePage, want ...string) {
		t.Helper()
		if len(page.Cases) != len(want) {
			t.Fatalf("%s: 结果数 = %d，期望 %d（%+v）", label, len(page.Cases), len(want), page.Cases)
		}
		for index := range want {
			if page.Cases[index].ID != want[index] {
				t.Fatalf("%s: 结果 = %+v，期望 ID %s", label, page.Cases, want[index])
			}
		}
	}

	staffCaller := env.caller(t, staffOne)
	// 中文原因子串。
	page := search(staffCaller, support.CaseListRequest{Search: "忘记密码", Limit: 10})
	assertIDs("中文", page, own.ID)
	// 编号子串（ID 是稳定 sup_ 前缀）。
	page = search(staffCaller, support.CaseListRequest{Search: own.ID[:8], Limit: 10})
	assertIDs("编号", page, own.ID)
	// 通配符与方言特殊字符按字面。
	page = search(staffCaller, support.CaseListRequest{Search: "%", Limit: 10})
	assertIDs("百分号字面", page, own.ID)
	page = search(staffCaller, support.CaseListRequest{Search: "'", Limit: 10})
	if len(page.Cases) != 1 || page.Cases[0].ID == own.ID {
		t.Fatalf("单引号字面结果 = %+v", page.Cases)
	}
	// 只搜编号：原因命中不返回。
	page = search(staffCaller, support.CaseListRequest{Search: "忘记密码", Limit: 10,
		SearchFields: []support.CaseSearchField{support.CaseSearchID}})
	if len(page.Cases) != 0 {
		t.Fatalf("只搜编号不应命中原因: %+v", page.Cases)
	}
	// 空搜索保持本人原列表（2 条，不含他人工单）。
	page = search(staffCaller, support.CaseListRequest{Search: "  ", Limit: 10})
	if len(page.Cases) != 2 {
		t.Fatalf("空搜索结果数 = %d，期望 2", len(page.Cases))
	}
	// 跨客服隔离：staffTwo 搜“忘记密码”只得到自己的工单（无匹配）。
	other := search(env.caller(t, staffTwo), support.CaseListRequest{Search: "忘记密码", Limit: 10})
	if len(other.Cases) != 0 {
		t.Fatalf("跨客服搜索泄漏结果: %+v", other.Cases)
	}
	// 非法字段/超长拒绝；不搜索隐藏邮箱/用户名字段。
	if _, err := env.svc.ListCasesPage(env.ctx, staffCaller, support.CaseListRequest{
		Search: "x", SearchFields: []support.CaseSearchField{"email"}, Limit: 10,
	}); !errors.Is(err, support.ErrInvalidRequest) {
		t.Fatalf("邮箱字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.svc.ListCasesPage(env.ctx, staffCaller, support.CaseListRequest{
		Search: "x", SearchFields: []support.CaseSearchField{"username"}, Limit: 10,
	}); !errors.Is(err, support.ErrInvalidRequest) {
		t.Fatalf("用户名搜索字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.svc.ListCasesPage(env.ctx, staffCaller, support.CaseListRequest{
		Search: strings.Repeat("a", 65), Limit: 10,
	}); !errors.Is(err, support.ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
}
