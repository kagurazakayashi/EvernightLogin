package apidoc

import (
	"strings"
	"testing"
)

// TestFirstSentence 校验摘要提取只取第一句并去掉换行。
func TestFirstSentence(t *testing.T) {
	cases := []struct{ input, want string }{
		{"第一句。第二句。", "第一句"},
		{"标题；后续", "标题"},
		{"第一行\n第二行", "第一行"},
		{"没有标点", "没有标点"},
		{"", ""},
	}
	for _, testCase := range cases {
		if got := firstSentence(testCase.input); got != testCase.want {
			t.Errorf("firstSentence(%q) = %q，期望 %q", testCase.input, got, testCase.want)
		}
	}
}

// TestSingleLine 校验多行文本折叠为单行（表格单元格用）。
func TestSingleLine(t *testing.T) {
	if got := singleLine("  a\n b\tc  "); got != "a b c" {
		t.Errorf("singleLine = %q，期望 %q", got, "a b c")
	}
}

// TestEscapeCell 校验表格单元格转义竖线并折叠空白。
func TestEscapeCell(t *testing.T) {
	if got := escapeCell("a | b\nc"); got != `a \| b c` {
		t.Errorf("escapeCell = %q", got)
	}
}

// TestMarkdownTable 校验确定性表格输出（表头/分隔行/转义）。
func TestMarkdownTable(t *testing.T) {
	table := markdownTable([]string{"列 A", "列 B"}, [][]string{{"x|y", "多行\n内容"}})
	want := "| 列 A | 列 B |\n|---|---|\n| x\\|y | 多行 内容 |\n"
	if table != want {
		t.Errorf("markdownTable = %q，期望 %q", table, want)
	}
}

// TestCodeBlock 校验围栏代码块与末尾空行处理。
func TestCodeBlock(t *testing.T) {
	if got := codeBlock("go", "line1\nline2\n"); got != "```go\nline1\nline2\n```\n" {
		t.Errorf("codeBlock = %q", got)
	}
	if got := codeBlock("go", "\r\nline\r\n"); got != "```go\nline\n```\n" {
		t.Errorf("codeBlock CRLF = %q", got)
	}
}

// TestJoinBlocks 校验块连接、末尾单个换行和空块跳过。
func TestJoinBlocks(t *testing.T) {
	got := string(joinBlocks("# a\n", "", "# b\n\n"))
	want := "# a\n\n# b\n"
	if got != want {
		t.Errorf("joinBlocks = %q，期望 %q", got, want)
	}
}

// TestBoolMarkAndClassLabel 校验机器值的中文呈现。
func TestBoolMarkAndClassLabel(t *testing.T) {
	if boolMark(true) != "是" || boolMark(false) != "否" {
		t.Error("boolMark 输出不符合预期")
	}
	if classLabel("restart-required") != "重启生效" || classLabel("hot-reloadable") != "重载生效" {
		t.Error("classLabel 输出不符合预期")
	}
	if classLabel("custom") != "custom" {
		t.Error("classLabel 未保留未知分类原值")
	}
}

// TestJoinCodeAndPipes 校验代码列表与普通列表的空值呈现。
func TestJoinCodeAndPipes(t *testing.T) {
	if got := joinCode([]string{"a", "b"}); got != "`a`、`b`" {
		t.Errorf("joinCode = %q", got)
	}
	if joinCode(nil) != "-" || joinPipes(nil) != "-" {
		t.Error("空列表应呈现为 -")
	}
}

// TestUniqueSorted 校验排序去重（判定结果顺序稳定）。
func TestUniqueSorted(t *testing.T) {
	got := uniqueSorted([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("uniqueSorted = %v，期望 %v", got, want)
	}
}

// TestMarkdownLinkTargets 校验站内链接提取：跳过外链/锚点，去掉片段。
func TestMarkdownLinkTargets(t *testing.T) {
	content := []byte("[a](errors.md) [b](https://x) [c](#sec) [d](http-api.md#x) [e](../guide/a.md \"标题\")")
	targets := markdownLinkTargets(content)
	want := []string{"errors.md", "http-api.md", "../guide/a.md"}
	if strings.Join(targets, "|") != strings.Join(want, "|") {
		t.Errorf("markdownLinkTargets = %v，期望 %v", targets, want)
	}
}

// TestDiffExcerpt 校验差异定位信息包含首个不同行。
func TestDiffExcerpt(t *testing.T) {
	got := diffExcerpt([]byte("a\nb\nc"), []byte("a\nB\nc"))
	if !strings.Contains(got, "第 2 行") || !strings.Contains(got, "b") || !strings.Contains(got, "B") {
		t.Errorf("diffExcerpt 未定位首个不同行：%q", got)
	}
	lines := diffExcerpt([]byte("a"), []byte("a\nb"))
	if !strings.Contains(lines, "行数不同") {
		t.Errorf("diffExcerpt 未报告行数差异：%q", lines)
	}
}
