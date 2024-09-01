package search_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// TestNormalizeQuery 验收搜索输入规范化：空输入不搜索、全角/大小写按同一字面
// 折叠、中文原样、首尾空白去除、超长/控制字符拒绝。
func TestNormalizeQuery(t *testing.T) {
	valid := []struct {
		name string
		raw  string
		want string
	}{
		{name: "空输入", raw: "", want: ""},
		{name: "只有空白", raw: " \t ", want: ""},
		{name: "大小写折叠", raw: "Alice", want: "alice"},
		{name: "全角折半角", raw: "ＡＬＩＣＥ", want: "alice"},
		{name: "全角与半角混合", raw: " Ｂob42 ", want: "bob42"},
		{name: "中文", raw: "  张三  ", want: "张三"},
		{name: "特殊字符字面保留", raw: `%_\[!'"`, want: `%_\[!'"`},
	}
	for _, testCase := range valid {
		result, err := search.NormalizeQuery(testCase.raw)
		if err != nil {
			t.Fatalf("%s: 规范化失败: %v", testCase.name, err)
		}
		if result != testCase.want {
			t.Fatalf("%s: 规范化 = %q，期望 %q", testCase.name, result, testCase.want)
		}
	}
	invalid := []struct {
		name string
		raw  string
	}{
		{name: "超长", raw: strings.Repeat("a", search.MaxQueryRunes+1)},
		{name: "换行", raw: "a\nb"},
		{name: "制表符", raw: "a\tb"},
		{name: "零宽字符", raw: "a\u200bb"},
		{name: "非法 UTF-8", raw: string([]byte{0xff, 0xfe})},
	}
	for _, testCase := range invalid {
		if _, err := search.NormalizeQuery(testCase.raw); !errors.Is(err, search.ErrInvalidQuery) {
			t.Fatalf("%s: 错误 = %v，期望 ErrInvalidQuery", testCase.name, err)
		}
	}
}

// TestEscapeLikeLiteral 验收 LIKE 通配符与方言特殊字符都按字面处理：`%`、`_`、
// `\`、`[`、`]`、ESCAPE 字符自身、单引号都不能改变匹配语义。
func TestEscapeLikeLiteral(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "普通字符不变", raw: "alice", want: "alice"},
		{name: "百分号", raw: "100%", want: "100!%"},
		{name: "下划线", raw: "a_b", want: "a!_b"},
		{name: "反斜杠保持原样", raw: `a\b`, want: `a\b`},
		{name: "方括号", raw: "[abc]", want: "![abc!]"},
		{name: "ESCAPE 字符自身", raw: "a!b", want: "a!!b"},
		{name: "单引号不转义", raw: "o'brien", want: "o'brien"},
		{name: "组合", raw: `%_\[]!'`, want: `!%!_\![!]!!'`},
	}
	for _, testCase := range cases {
		if result := search.EscapeLike(testCase.raw); result != testCase.want {
			t.Fatalf("%s: EscapeLike(%q) = %q，期望 %q",
				testCase.name, testCase.raw, result, testCase.want)
		}
	}
	// ESCAPE 字符必须是方言都支持的普通字符，且不能是反斜杠（MySQL 字符串转义差异）。
	if search.EscapeChar != '!' {
		t.Fatalf("ESCAPE 字符 = %q，期望 '!'", search.EscapeChar)
	}
	// LIKE 模式只做拼接：首尾 % 是模式符号，其余字面已被转义；空输入不生成模式。
	if got := search.ContainsPattern("alice"); got != "%alice%" {
		t.Fatalf("ContainsPattern = %q", got)
	}
	if got := search.ContainsPattern("100%"); got != "%100!%%" {
		t.Fatalf("ContainsPattern(含%%) = %q", got)
	}
	if got := search.ContainsPattern(""); got != "" {
		t.Fatalf("空输入不应生成 LIKE 模式，实际 %q", got)
	}
	if got := search.PrefixPattern("alice"); got != "alice%" {
		t.Fatalf("PrefixPattern = %q", got)
	}
}
