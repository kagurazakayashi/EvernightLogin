package ui_test

// 步骤 263：客服工单与历史报告列表页有界搜索接线契约测试（新文件）。
// 覆盖：搜索参数回显、渐进增强模块声明、页面可渲染。

import (
	"net/http"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// TestSupportCasesListSearchPage 验收客服工单列表搜索回显与模块声明。
func TestSupportCasesListSearchPage(t *testing.T) {
	ui := newSupportTestUI(t, newSupportFakeBackend(), supportTestStaffID)
	page := serveSupportPage(ui, http.MethodGet, "/support/cases?search=sup_abc", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("客服工单列表页 = %d", page.Code)
	}
	body := supportBody(page)
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="sup_abc"`) {
		t.Fatal("工单列表缺少搜索回显")
	}
	if !strings.Contains(body, `data-ln-module="list-search"`) {
		t.Fatal("工单列表缺少渐进增强搜索模块声明")
	}
	if !strings.Contains(body, `data-ln-list-status`) {
		t.Fatal("工单列表缺少搜索状态提示区域")
	}
}

// TestReportHistoryListSearchPage 验收历史报告列表搜索回显。
func TestReportHistoryListSearchPage(t *testing.T) {
	env := newReportsPageEnv(t)
	page := env.get("/admin/reports?search=%E6%AF%8F%E6%97%A5")
	if page.Code != http.StatusOK {
		t.Fatalf("历史报告列表页 = %d", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="每日"`) {
		t.Fatal("历史报告列表缺少搜索回显")
	}
}

// TestSupportCasesSearchPaginationKeepsFilter 覆盖审计 LOW-1：工单列表“下一页”链接
// 必须携带 search，否则静默丢失筛选。
func TestSupportCasesSearchPaginationKeepsFilter(t *testing.T) {
	backend := newSupportFakeBackend()
	backend.hasMore = true
	backend.cases = []login.UISupportCaseView{{ID: "sup_1", Reason: "忘记密码",
		Status: "pending_verification"}}
	ui := newSupportTestUI(t, backend, supportTestStaffID)
	page := serveSupportPage(ui, http.MethodGet, "/support/cases?search=sup_abc", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("工单列表页 = %d", page.Code)
	}
	body := supportBody(page)
	if !strings.Contains(body, "search=sup_abc") || !strings.Contains(body, "offset=20") {
		t.Fatalf("下一页链接未携带搜索条件: %s", body)
	}
}

// TestReportHistorySearchPaginationKeepsFilter 覆盖审计 LOW-1：历史报告游标翻页链接
// 必须携带 search，且第二页仍把 search 传给后端（游标指纹一致，不返回 REQ_INVALID）。
func TestReportHistorySearchPaginationKeepsFilter(t *testing.T) {
	env := newReportsPageEnv(t)
	env.backend.history.HasMore = true
	env.backend.history.NextCursor = "cur_search_263"
	first := env.get("/admin/reports?search=%E6%AF%8F%E6%97%A5")
	if first.Code != http.StatusOK {
		t.Fatalf("历史报告列表页 = %d", first.Code)
	}
	body := first.Body.String()
	if !strings.Contains(body, "search=%E6%AF%8F%E6%97%A5") ||
		!strings.Contains(body, "cursor=cur_search_263") {
		t.Fatalf("下一页链接未携带搜索/游标: %s", body)
	}
	second := env.get("/admin/reports?search=%E6%AF%8F%E6%97%A5&cursor=cur_search_263")
	if second.Code != http.StatusOK {
		t.Fatalf("历史报告第二页 = %d body=%s", second.Code, second.Body.String())
	}
	if env.backend.lastHistoryQuery.Search != "每日" {
		t.Fatalf("第二页后端收到的搜索 = %q", env.backend.lastHistoryQuery.Search)
	}
}
