package setupconsole

// WS5 反馈的 6 个行为缺口（G1–G6）定向回归。

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// G1：plain 模式动态输出不得包含 ESC/控制字符。
func TestG1PlainOutputSanitized(t *testing.T) {
	var output bytes.Buffer
	report := ConfigReport{Path: "/tmp/\x1b[31mbad.yaml", Summary: "摘要\x1b[2J",
		Issues: []ConfigIssue{{Kind: "yaml-syntax", Detail: "详情\x07", Suggestion: "建议\x1b[0m"}}}
	printConfigReportPlain(&output, report)
	detection := Detection{Kind: StateConfigInvalid, Summary: "状态\x1b[31m",
		ConfigPath: "/x/\x1b[2J", DatabasePath: "/d/\x07",
		Details: []string{"细节\x1b[1m"}, Issues: []ConfigIssue{{Kind: "k\x1b", Detail: "d\x07",
			Suggestion: "s\x1b"}}}
	printDetectionPlain(&output, detection)
	text := output.String()
	if strings.ContainsAny(text, "\x1b\x07") {
		t.Fatalf("plain 输出包含控制字符: %q", text)
	}
	// RunPlain 回显路径同样清洗。
	input := strings.NewReader("path /tmp/\x1b[31mevil\nstatus\nquit\n")
	var runOutput bytes.Buffer
	RunPlain(context.Background(), input, &runOutput, "")
	if strings.ContainsAny(runOutput.String(), "\x1b\x07") {
		t.Fatalf("RunPlain 输出包含控制字符: %q", runOutput.String())
	}
}

// G2：CJK/emoji 按显示宽度占 2 列，20 列画布不溢出、不拆宽字符。
func TestG2CanvasDisplayWidth(t *testing.T) {
	canvas := NewCanvas(20, 8)
	canvas.Text(0, 1, strings.Repeat("中", 20))
	if width := displayWidth(canvas.rowText(1)); width > 20 {
		t.Fatalf("宽字符行显示宽度 = %d，超过画布 20 列", width)
	}
	if count := utf8.RuneCountInString(canvas.rowText(1)); count > 10 {
		t.Fatalf("20 列只能放 10 个宽字符，实际 %d", count)
	}
	canvas.Clear()
	canvas.Center(2, "中文标题")
	text := canvas.rowText(2)
	if displayWidth(text) > 20 || !strings.Contains(text, "中文标题") {
		t.Fatalf("居中宽字符异常: %q", text)
	}
	// emoji（宽 2）不拆开。
	canvas.Clear()
	canvas.Text(19, 3, "🙂")
	if strings.Contains(canvas.rowText(3), "🙂") {
		t.Fatal("宽 emoji 在最后一列被拆开放置")
	}
}

// G3：单行单元格内的 \n/\r/\t 转空格，不破坏帧布局。
func TestG3CanvasSingleLine(t *testing.T) {
	canvas := NewCanvas(30, 6)
	canvas.Text(0, 1, "a\nb\rc\td")
	row := canvas.rowText(1)
	if strings.ContainsAny(row, "\n\r\t") || !strings.Contains(row, "a b c d") {
		t.Fatalf("单行文本破坏布局: %q", row)
	}
}

// G4：F1（ESC O P / ESC [11~）可解析并打开帮助。
func TestG4F1Help(t *testing.T) {
	for _, input := range [][]byte{[]byte("\x1bOP"), []byte("\x1b[11~")} {
		terminal := NewANSITerminal(bytes.NewReader(input), io.Discard)
		key, err := terminal.ReadKey()
		if err != nil || key.Kind != KeyF1 {
			t.Fatalf("F1 序列解析失败: %v %v", key.Kind, err)
		}
	}
	scripted := newFakeTerminal(Key{Kind: KeyF1}, Key{Kind: KeyEsc},
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey())
	app := NewApp(scripted, "x.yaml", nil)
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("F1 帮助流程: %v", err)
	}
	joined := strings.Join(scripted.frames, "\n")
	if !strings.Contains(joined, "本控制台用于本地维护") {
		t.Fatal("F1 未打开帮助画面")
	}
}

// G5：ESC 不吞后续字节；bracketed paste 被识别并消费。
func TestG5EscapeAndBracketedPaste(t *testing.T) {
	terminal := NewANSITerminal(bytes.NewReader([]byte("\x1bq")), io.Discard)
	first, err := terminal.ReadKey()
	if err != nil || first.Kind != KeyEsc {
		t.Fatalf("ESC 后跟普通字符应返回 Esc: %v %v", first.Kind, err)
	}
	second, err := terminal.ReadKey()
	if err != nil || second.Kind != KeyRune || second.Rune != 'q' {
		t.Fatalf("ESC 吞掉了后续字符: %v %v", second, err)
	}
	pasteTerminal := NewANSITerminal(bytes.NewReader(
		[]byte("before\x1b[200~粘贴内容\x1b[201~after")), io.Discard)
	// 读到 before 的 6 个字符后是粘贴事件。
	for index := 0; index < len("before"); index++ {
		key, err := pasteTerminal.ReadKey()
		if err != nil || key.Kind != KeyRune {
			t.Fatalf("粘贴前字符读取失败: %v %v", key, err)
		}
	}
	paste, err := pasteTerminal.ReadKey()
	if err != nil || paste.Kind != KeyPaste || paste.Text != "粘贴内容" {
		t.Fatalf("bracketed paste 解析失败: %+v err=%v", paste, err)
	}
	tail, err := pasteTerminal.ReadKey()
	if err != nil || tail.Rune != 'a' {
		t.Fatalf("粘贴后输入被破坏: %+v err=%v", tail, err)
	}
}

// G6：非法 UTF-8 单字节返回 KeyUnknown 并消费，不让 UI 以为输入结束。
func TestG6InvalidUTF8Consumed(t *testing.T) {
	terminal := NewANSITerminal(bytes.NewReader([]byte{0xff, 0xfe, 'a'}), io.Discard)
	first, err := terminal.ReadKey()
	if err != nil || first.Kind != KeyUnknown {
		t.Fatalf("非法字节应返回 KeyUnknown: %v %v", first.Kind, err)
	}
	second, err := terminal.ReadKey()
	if err != nil || second.Kind != KeyUnknown {
		t.Fatalf("第二个非法字节应返回 KeyUnknown: %v %v", second.Kind, err)
	}
	third, err := terminal.ReadKey()
	if err != nil || third.Kind != KeyRune || third.Rune != 'a' {
		t.Fatalf("非法字节后正常输入被破坏: %+v %v", third, err)
	}
}

// TestCanvasFiltersC1Controls 验证 C1 控制字符（如 U+009B CSI）不会进入画布输出（SEC INFO-2）。
func TestCanvasFiltersC1Controls(t *testing.T) {
	canvas := NewCanvas(40, 6)
	canvas.Text(0, 1, "a\u009b31mb\u0085c")
	row := canvas.rowText(1)
	for _, forbidden := range []rune{'\u009b', '\u0085'} {
		if strings.ContainsRune(row, forbidden) {
			t.Fatalf("画布输出包含 C1 控制字符 %U: %q", forbidden, row)
		}
	}
	if !strings.Contains(row, "a") || !strings.Contains(row, "31mb") {
		t.Fatalf("C1 清洗丢失正常文本: %q", row)
	}
}
