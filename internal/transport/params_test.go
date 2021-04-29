package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestNormalizePrefix 验证固定路径前缀的严格校验。
func TestNormalizePrefix(t *testing.T) {
	valid := []struct{ input, want string }{
		{"", ""},
		{"/api", "/api"},
		{"/api/v1", "/api/v1"},
		{"/login", "/login"},
	}
	for _, testCase := range valid {
		got, err := NormalizePrefix(testCase.input)
		if err != nil || got != testCase.want {
			t.Fatalf("NormalizePrefix(%q) = %q, %v；期望 %q", testCase.input, got, err, testCase.want)
		}
	}
	invalid := []string{
		"/", "/api/", "api", "//api", "/api//v1", "/./api", "/a/../b",
		`/api\x`, "/a?b", "/a#b", "/%61pi", "/中文", strings.Repeat("/a", MaxPrefixBytes),
	}
	for _, prefix := range invalid {
		if _, err := NormalizePrefix(prefix); err == nil {
			t.Fatalf("非法前缀 %q 应被拒绝", prefix)
		}
	}
}

// TestNormalizeTextParam 验证文本参数规范化。
func TestNormalizeTextParam(t *testing.T) {
	cases := []struct {
		name       string
		value      string
		allowUnic  bool
		maxBytes   int
		wantValue  string
		wantReject bool
	}{
		{"去空白", "  alice  ", true, 64, "alice", false},
		{"空值", "   ", true, 64, "", false},
		{"允许 Unicode", "张三", true, 64, "张三", false},
		{"拒绝 Unicode", "张三", false, 64, "", true},
		{"拒绝换行", "a\nb", true, 64, "", true},
		{"拒绝 TAB 中间", "a\tb", true, 64, "", true},
		{"拒绝控制字符", "a\x01b", true, 64, "", true},
		{"超长", strings.Repeat("a", 65), true, 64, "", true},
		{"非法 UTF-8", string([]byte{0xff, 0xfe}), true, 64, "", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, problem := normalizeTextParam("name", testCase.value, testCase.maxBytes, testCase.allowUnic)
			if testCase.wantReject {
				if problem == nil {
					t.Fatalf("应被拒绝，实际 %q", got)
				}
				if strings.Contains(problem.message, testCase.value) {
					t.Fatalf("错误信息不应回显参数值: %q", problem.message)
				}
				return
			}
			if problem != nil || got != testCase.wantValue {
				t.Fatalf("结果 = %q, %v；期望 %q", got, problem, testCase.wantValue)
			}
		})
	}
}

// TestNormalizeIdentifierParam 验证稳定标识只接受受限 ASCII 字符集。
func TestNormalizeIdentifierParam(t *testing.T) {
	if got, problem := normalizeIdentifierParam("id", " user-1.a_b ", 64); problem != nil || got != "user-1.a_b" {
		t.Fatalf("合法标识 = %q, %v", got, problem)
	}
	for _, value := range []string{"a b", "中文", "a/b", "a\\b", strings.Repeat("a", 65)} {
		if _, problem := normalizeIdentifierParam("id", value, 64); problem == nil {
			t.Fatalf("非法标识 %q 应被拒绝", value)
		}
	}
}

// TestSingleQueryValue 验证重复参数被拒绝，缺省返回空值。
func TestSingleQueryValue(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?name=a", nil)
	if got, problem := singleQueryValue(request, "name", 64, true); problem != nil || got != "a" {
		t.Fatalf("单值参数 = %q, %v", got, problem)
	}
	if got, problem := singleQueryValue(request, "missing", 64, true); problem != nil || got != "" {
		t.Fatalf("缺省参数 = %q, %v", got, problem)
	}
	duplicated := httptest.NewRequest(http.MethodGet, "/?name=a&name=b", nil)
	if _, problem := singleQueryValue(duplicated, "name", 64, true); problem == nil {
		t.Fatal("重复查询参数应被拒绝")
	}
}

// TestSingleHeaderValue 验证重复请求头被拒绝。
func TestSingleHeaderValue(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Tenant", "tenant-1")
	if got, problem := singleHeaderValue(request, "X-Tenant", 64, true); problem != nil || got != "tenant-1" {
		t.Fatalf("单值请求头 = %q, %v", got, problem)
	}
	request.Header.Add("X-Tenant", "tenant-2")
	if _, problem := singleHeaderValue(request, "X-Tenant", 64, true); problem == nil {
		t.Fatal("重复请求头应被拒绝")
	}
}

// TestDecodeJSONBodyCharset 验证 JSON 内容类型与字符集边界。
func TestDecodeJSONBodyCharset(t *testing.T) {
	cases := []struct {
		contentType string
		wantStatus  int
	}{
		{"application/json", 0},
		{"application/json; charset=utf-8", 0},
		{"application/json; charset=UTF-8", 0},
		{"application/json; charset=latin1", http.StatusUnsupportedMediaType},
		{"text/json", http.StatusUnsupportedMediaType},
		{"", http.StatusUnsupportedMediaType},
	}
	for _, testCase := range cases {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
		if testCase.contentType != "" {
			request.Header.Set("Content-Type", testCase.contentType)
		}
		var input struct {
			Name string `json:"name"`
		}
		problem := decodeJSONBody(request, &input)
		if testCase.wantStatus == 0 {
			if problem != nil {
				t.Fatalf("%q 应被接受: %v", testCase.contentType, problem)
			}
			continue
		}
		if problem == nil || problem.status != testCase.wantStatus {
			t.Fatalf("%q 状态 = %v，期望 %d", testCase.contentType, problem, testCase.wantStatus)
		}
	}
}

// TestSafeParamName 验证参数名净化，避免攻击者控制的名称进入公开错误。
func TestSafeParamName(t *testing.T) {
	cases := map[string]string{
		"name":                   "name",
		"name with ":             "namewith",
		"user-id_1.0":            "user-id_1.0",
		"中文":                     "参数",
		"":                       "参数",
		strings.Repeat("a", 100): strings.Repeat("a", 32),
	}
	for input, want := range cases {
		if got := safeParamName(input); got != want {
			t.Fatalf("safeParamName(%q) = %q，期望 %q", input, got, want)
		}
	}
}

// TestSanitizeMessage 验证公开错误说明去控制字符与长度限制。
func TestSanitizeMessage(t *testing.T) {
	if got := sanitizeMessage("line1\nline2\ttab"); got != "line1 line2 tab" {
		t.Fatalf("sanitizeMessage = %q", got)
	}
	long := sanitizeMessage(strings.Repeat("长", maxErrorMessageBytes+50))
	if len([]rune(long)) > maxErrorMessageBytes {
		t.Fatalf("超长说明未被截断: %d", len([]rune(long)))
	}
}

// TestCanonicalRequestPathRejectsEncodedPath 验证编码路径不会被当作普通路径。
func TestCanonicalRequestPathRejectsEncodedPath(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL = &url.URL{Path: "/healthz", RawPath: "/%68ealthz"}
	if _, problem := canonicalRequestPath(request); problem == nil {
		t.Fatal("百分号编码路径应被拒绝")
	}
}
