package serverapp

// 步骤 216：管理 HTTP 列表分页查询参数解析（limit/offset/sort/desc）单元测试。
// 契约：缺省 limit=20/offset=0；显式非法值返回 REQ_INVALID；sort 必须在白名单内；
// desc 只接受 0/1/false/true；响应元数据 next_offset=offset+返回条数。

import (
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

func TestParseAdminListQueryDefaultsAndValid(t *testing.T) {
	request := httptest.NewRequest("GET", "/admin/users", nil)
	page, err := parseAdminListQuery(request, "created_at", "name")
	if err != nil {
		t.Fatalf("默认参数失败: %v", err)
	}
	if page.Limit != 20 || page.Offset != 0 || page.Sort != "" || page.Descending {
		t.Fatalf("默认分页 = %+v", page)
	}

	request = httptest.NewRequest("GET",
		"/admin/users?limit=7&offset=14&sort=name&desc=true", nil)
	page, err = parseAdminListQuery(request, "created_at", "name")
	if err != nil {
		t.Fatalf("合法参数失败: %v", err)
	}
	if page.Limit != 7 || page.Offset != 14 || page.Sort != "name" || !page.Descending {
		t.Fatalf("合法分页 = %+v", page)
	}
	result := page.result([]map[string]any{{"id": "1"}, {"id": "2"}}, true)
	if result["has_more"] != true || result["limit"] != 7 || result["offset"] != 14 ||
		result["next_offset"] != 16 || result["sort"] != "name" || result["desc"] != true {
		t.Fatalf("分页响应 = %+v", result)
	}
}

func TestParseAdminListQueryRejectsInvalid(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"limit 非数字", "/admin/users?limit=abc"},
		{"limit 为 0", "/admin/users?limit=0"},
		{"limit 超上限", "/admin/users?limit=101"},
		{"offset 为负", "/admin/users?offset=-1"},
		{"offset 超上限", "/admin/users?offset=1000001"},
		{"sort 不在白名单", "/admin/users?sort=password_hash"},
		{"desc 非法", "/admin/users?desc=yes"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", testCase.target, nil)
			if _, err := parseAdminListQuery(request, "created_at", "name"); err == nil {
				t.Fatal("非法参数应返回错误")
			} else if domainError, ok := err.(*adminapi.DomainError); !ok ||
				domainError.Code != "REQ_INVALID" {
				t.Fatalf("非法参数错误 = %v，期望 REQ_INVALID 领域错误", err)
			}
		})
	}
}
