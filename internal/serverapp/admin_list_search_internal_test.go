package serverapp

// 步骤 261：管理 HTTP 列表搜索参数解析契约测试。契约：
//   - search 为空表示不过滤；按 internal/search 规范化（NFKC + 大小写折叠）；
//   - search 超长/含控制字符 → REQ_INVALID 领域错误，不静默截断；
//   - search_fields 为逗号分隔白名单，未知字段（如 email/phone，需独立字段可见
//     权限）→ REQ_INVALID；空字段使用默认用户名+昵称。

import (
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

func TestParseAdminListSearchDefaultsAndNormalization(t *testing.T) {
	request := httptest.NewRequest("GET", "/admin/v1/users", nil)
	searchText, fields, err := parseAdminListSearch(request)
	if err != nil {
		t.Fatalf("缺省搜索参数失败: %v", err)
	}
	if searchText != "" {
		t.Fatalf("缺省搜索文本 = %q，期望空", searchText)
	}
	if len(fields) != 2 || fields[0] != account.UserSearchUsername ||
		fields[1] != account.UserSearchNickname {
		t.Fatalf("缺省搜索字段 = %v，期望 username+nickname", fields)
	}

	// 全角/大小写输入按同一字面折叠；显式字段白名单原样校验。
	request = httptest.NewRequest("GET",
		"/admin/v1/users?search=%EF%BC%A1%EF%BC%AC%EF%BC%A9%EF%BC%A3%EF%BC%A5&search_fields=username", nil)
	searchText, fields, err = parseAdminListSearch(request)
	if err != nil {
		t.Fatalf("合法搜索参数失败: %v", err)
	}
	if searchText != "alice" {
		t.Fatalf("规范化搜索文本 = %q，期望 alice", searchText)
	}
	if len(fields) != 1 || fields[0] != account.UserSearchUsername {
		t.Fatalf("搜索字段 = %v，期望仅 username", fields)
	}
	// 重复字段去重。
	request = httptest.NewRequest("GET",
		"/admin/v1/users?search=alice&search_fields=username,nickname,username", nil)
	_, fields, err = parseAdminListSearch(request)
	if err != nil {
		t.Fatalf("重复字段失败: %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("重复字段未去重: %v", fields)
	}
}

func TestParseAdminListSearchRejectsInvalid(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"搜索超长", "/admin/v1/users?search=" + repeatASCII(65)},
		{"搜索含换行", "/admin/v1/users?search=a%0Ab"},
		{"未知字段", "/admin/v1/users?search=x&search_fields=password_hash"},
		{"邮箱字段", "/admin/v1/users?search=x&search_fields=email"},
		{"电话字段", "/admin/v1/users?search=x&search_fields=phone"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", testCase.target, nil)
			_, _, err := parseAdminListSearch(request)
			if err == nil {
				t.Fatal("非法搜索参数应返回错误")
			}
			domainError, ok := err.(*adminapi.DomainError)
			if !ok || domainError.Code != "REQ_INVALID" {
				t.Fatalf("非法搜索参数错误 = %v，期望 REQ_INVALID 领域错误", err)
			}
		})
	}
}

// repeatASCII 返回 n 个 'a'（测试超长输入，不引入额外依赖）。
func repeatASCII(n int) string {
	buffer := make([]byte, n)
	for index := range buffer {
		buffer[index] = 'a'
	}
	return string(buffer)
}
