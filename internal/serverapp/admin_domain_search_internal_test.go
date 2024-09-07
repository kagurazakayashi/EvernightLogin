package serverapp

// 步骤 262：领域列表搜索参数解析契约测试（新文件，避免改 261 审计中的路由文件）。

import (
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

func TestParseAdminDomainSearch(t *testing.T) {
	// 缺省：空搜索文本、空字段（领域默认）。
	request := httptest.NewRequest("GET", "/admin/v1/roles", nil)
	searchText, fields, err := parseAdminDomainSearch(request)
	if err != nil || searchText != "" || len(fields) != 0 {
		t.Fatalf("缺省解析 = (%q,%v,%v)", searchText, fields, err)
	}
	// 全角/大小写折叠 + 逗号字段拆分与去空。
	request = httptest.NewRequest("GET",
		"/admin/v1/roles?search=%EF%BC%A1%EF%BC%B5%EF%BC%A4%EF%BC%A9%EF%BC%B4&search_fields=name,%20key,", nil)
	searchText, fields, err = parseAdminDomainSearch(request)
	if err != nil {
		t.Fatalf("合法解析失败: %v", err)
	}
	if searchText != "audit" {
		t.Fatalf("规范化搜索文本 = %q，期望 audit", searchText)
	}
	if len(fields) != 2 || fields[0] != "name" || fields[1] != "key" {
		t.Fatalf("字段拆分 = %v", fields)
	}
	// 超长/控制字符 → REQ_INVALID 领域错误。
	for _, target := range []string{
		"/admin/v1/roles?search=" + repeatASCIISearch(65),
		"/admin/v1/roles?search=a%0Ab",
	} {
		request = httptest.NewRequest("GET", target, nil)
		if _, _, err := parseAdminDomainSearch(request); err == nil {
			t.Fatalf("%s 应返回错误", target)
		} else if domainError, ok := err.(*adminapi.DomainError); !ok ||
			domainError.Code != "REQ_INVALID" {
			t.Fatalf("%s 错误 = %v，期望 REQ_INVALID", target, err)
		}
	}
}

// repeatASCIISearch 生成 n 个 'a'，用于超长输入测试（不引入额外依赖）。
func repeatASCIISearch(n int) string {
	buffer := make([]byte, n)
	for index := range buffer {
		buffer[index] = 'a'
	}
	return string(buffer)
}
