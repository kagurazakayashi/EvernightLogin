package serverapp

// 步骤 217：应用范围列表路由的路径参数与分页查询参数单元测试。
//   - applications/{application_id}/roles|groups 的路径参数必须取倒数第二段，不能把
//     末段（roles/groups）误当作应用 ID；
//   - 应用/成员列表的排序白名单与 216 统一分页解析保持一致（非法字段 REQ_INVALID）。

import (
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

func TestAdminApplicationPathParam(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/admin/applications/app_00000000000000000000000000000001/roles",
			"app_00000000000000000000000000000001"},
		{"/admin/applications/app_00000000000000000000000000000002/groups/",
			"app_00000000000000000000000000000002"},
		{"/applications/onlyone", ""},
	}
	for _, testCase := range cases {
		request := httptest.NewRequest("GET", testCase.path, nil)
		if got := adminApplicationPathParam(request); got != testCase.want {
			t.Fatalf("路径 %q 应用 ID = %q，期望 %q", testCase.path, got, testCase.want)
		}
	}
}

func TestParseAdminListQueryApplicationSortWhitelist(t *testing.T) {
	for _, sortField := range []string{"created_at", "updated_at", "name", "id"} {
		request := httptest.NewRequest("GET", "/admin/applications?sort="+sortField, nil)
		if _, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "id"); err != nil {
			t.Fatalf("应用列表合法排序 %q 被拒绝: %v", sortField, err)
		}
	}
	for _, sortField := range []string{"client_secret", "owner_email"} {
		request := httptest.NewRequest("GET", "/admin/applications?sort="+sortField, nil)
		if _, err := parseAdminListQuery(request, "created_at", "updated_at", "name", "id"); err == nil {
			t.Fatalf("应用列表非法排序 %q 应返回 REQ_INVALID", sortField)
		} else if domainError, ok := err.(*adminapi.DomainError); !ok ||
			domainError.Code != "REQ_INVALID" {
			t.Fatalf("非法排序错误 = %v，期望 REQ_INVALID", err)
		}
	}
	// 应用成员列表白名单：user_id 可用，跨域资料字段不可用。
	request := httptest.NewRequest("GET", "/admin/applications/x/members?sort=user_id", nil)
	if _, err := parseAdminListQuery(request, "created_at", "updated_at", "user_id"); err != nil {
		t.Fatalf("成员列表合法排序被拒绝: %v", err)
	}
	request = httptest.NewRequest("GET", "/admin/applications/x/members?sort=email", nil)
	if _, err := parseAdminListQuery(request, "created_at", "updated_at", "user_id"); err == nil {
		t.Fatal("成员列表非法排序应返回 REQ_INVALID")
	}
}
