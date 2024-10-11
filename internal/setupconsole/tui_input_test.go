package setupconsole

// 步骤298（WS5 测试侧）：输入解析、非 TTY 简化模式、宽字符/控制字符/超长文本安全呈现
// 与终端尺寸回退的定向测试。
//
// 缺口测试（名称带 _Gap）记录当前需要 WS1 修改的实际问题：默认 Skip 并写明最小复现，
// 待 WS1 修复后由对应步骤取消 Skip 并保留断言；不把未实现行为写成通过。

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// replayKeys 用原始字节回放并收集按键，直到 EOF 或错误。
func replayKeys(raw string) ([]Key, error) {
	terminal := NewANSITerminal(strings.NewReader(raw), io.Discard)
	var keys []Key
	for {
		key, err := terminal.ReadKey()
		if err != nil {
			return keys, err
		}
		keys = append(keys, key)
	}
}

// TestReplayANSIKeySequences 覆盖方向键/Tab/Enter/Esc/编辑键/控制键/宽字符解析。
func TestReplayANSIKeySequences(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []Key
	}{
		{"arrows", "\x1b[A\x1b[B\x1b[C\x1b[D", []Key{
			{Kind: KeyUp}, {Kind: KeyDown}, {Kind: KeyRight}, {Kind: KeyLeft}}},
		{"home-end", "\x1b[H\x1b[F", []Key{{Kind: KeyHome}, {Kind: KeyEnd}}},
		{"page", "\x1b[5~\x1b[6~", []Key{{Kind: KeyPageUp}, {Kind: KeyPageDown}}},
		{"tab-enter-esc", "\t\r\x1b", []Key{
			{Kind: KeyTab}, {Kind: KeyEnter}, {Kind: KeyEsc}}},
		{"backspace", "\x7f\x08", []Key{{Kind: KeyBackspace}, {Kind: KeyBackspace}}},
		{"ctrl", "\x03\x04\x13\x0f", []Key{
			{Kind: KeyCtrlC}, {Kind: KeyCtrlD}, {Kind: KeyCtrlS}, {Kind: KeyCtrlO}}},
		{"wide-cjk", "中", []Key{{Kind: KeyRune, Rune: '中'}}},
		{"emoji", "🙂", []Key{{Kind: KeyRune, Rune: '🙂'}}},
		{"ascii", "aZ9", []Key{
			{Kind: KeyRune, Rune: 'a'}, {Kind: KeyRune, Rune: 'Z'}, {Kind: KeyRune, Rune: '9'}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			keys, err := replayKeys(testCase.raw)
			if err != io.EOF {
				t.Fatalf("回放 %q 结束错误 = %v，期望 io.EOF", testCase.raw, err)
			}
			if len(keys) != len(testCase.want) {
				t.Fatalf("回放 %q 按键数 = %d，期望 %d：%+v", testCase.raw, len(keys),
					len(testCase.want), keys)
			}
			for index := range keys {
				if keys[index] != testCase.want[index] {
					t.Fatalf("回放 %q 第 %d 键 = %+v，期望 %+v", testCase.raw, index,
						keys[index], testCase.want[index])
				}
			}
		})
	}
}

// TestReplayPasteDoesNotInsertControlChars 粘贴内容中的 ANSI/控制序列不得作为控制字符
// 进入输入文本（可以表现为可忽略/Unknown 序列或可见但已清洗的字符）。
func TestReplayPasteDoesNotInsertControlChars(t *testing.T) {
	keys, err := replayKeys("ab\x1b[31mcd")
	if err != io.EOF {
		t.Fatalf("回放结束错误 = %v，期望 io.EOF", err)
	}
	if len(keys) == 0 {
		t.Fatal("粘贴输入未产生任何按键")
	}
	for _, key := range keys {
		if key.Kind == KeyRune && (key.Rune < 0x20 || key.Rune == 0x7f) {
			t.Fatalf("粘贴输入产生控制字符按键：%+v", key)
		}
	}
}

// TestReplayLongPasteBoundedByCanvas 回放超长粘贴：输入不被截断（由界面决定上限），
// 但渲染必须按画布宽度有界、不得 panic。
func TestReplayLongPasteBoundedByCanvas(t *testing.T) {
	longText := strings.Repeat("a", 4000)
	raw := "\x1b[B\x1b[B\r" + longText + "\r" + "\x03"
	var detected string
	detect := func(_ context.Context, options DetectOptions) Detection {
		detected = options.ConfigPath
		return Detection{Kind: StateNoConfig, ConfigPath: options.ConfigPath}
	}
	terminal := newReplayTerminal(raw)
	if err := runReplayApp(t, terminal, "", detect, nil); err != nil {
		t.Fatalf("超长粘贴 Run: %v", err)
	}
	if len([]rune(detected)) != len(longText) {
		t.Fatalf("超长粘贴输入长度 = %d，期望 %d", len([]rune(detected)), len(longText))
	}
	for index, frame := range terminal.frames {
		if runes := maxVisibleRunes(frame); runes > 100 {
			t.Fatalf("帧 %d 可见 rune 数 %d 超过画布宽度 100", index, runes)
		}
	}
}

// TestCanvasControlTextSafe 覆盖外来 ANSI/控制字符/超长文本进入画布后的安全呈现。
func TestCanvasControlTextSafe(t *testing.T) {
	canvas := NewCanvas(40, 10)
	canvas.Text(0, 0, "\x1b[31mred\x1b[0m\x07\x00text")
	canvas.Text(0, 1, strings.Repeat("x", 5000))
	frame := canvas.Render()
	lines := visibleLines(frame)
	if len(lines) == 0 {
		t.Fatal("画布未渲染任何可见行")
	}
	for index, line := range lines {
		if strings.ContainsAny(line, "\x1b\x00\x07") {
			t.Fatalf("可见行 %d 含原始 ANSI/控制字符: %q", index, line)
		}
		if width := displayColumns(line); width > 40 {
			t.Fatalf("可见行 %d 显示宽度 %d 超过画布 40 列", index, width)
		}
	}
}

// TestNonTTYSizeFallback 非 TTY 终端尺寸回退 80x24（简化模式不依赖真实窗口）。
func TestNonTTYSizeFallback(t *testing.T) {
	terminal := NewANSITerminal(bytes.NewReader(nil), io.Discard)
	width, height := terminal.Size()
	if width != 80 || height != 24 {
		t.Fatalf("非 TTY 尺寸 = %dx%d，期望 80x24", width, height)
	}
}

// TestPlainModeDoesNotEnterFullScreen 非 TTY 简化模式不输出备用屏幕/隐藏光标控制序列。
func TestPlainModeDoesNotEnterFullScreen(t *testing.T) {
	input := "help\npath /tmp/login-test.yaml\n"
	var output bytes.Buffer
	result := RunPlain(context.Background(), strings.NewReader(input), &output,
		"/tmp/login-test.yaml")
	if result.ExitCode != 0 {
		t.Fatalf("简化模式退出码 = %d，期望 0", result.ExitCode)
	}
	text := output.String()
	if strings.Contains(text, "\x1b[?1049h") || strings.Contains(text, "\x1b[?25l") {
		t.Fatalf("简化模式输出了全屏控制序列：%q", text)
	}
	for _, want := range []string{"简化文本模式", "命令：", "配置路径已设置为"} {
		if !strings.Contains(text, want) {
			t.Fatalf("简化模式输出缺少 %q：%s", want, text)
		}
	}
}

// TestPlainModeUnknownCommandAndEOF 未知命令给出提示，EOF 正常退出且无控制序列。
func TestPlainModeUnknownCommandAndEOF(t *testing.T) {
	var output bytes.Buffer
	result := RunPlain(context.Background(), strings.NewReader("bogus\n"), &output, "")
	if result.ExitCode != 0 {
		t.Fatalf("EOF 退出码 = %d，期望 0", result.ExitCode)
	}
	if !strings.Contains(output.String(), "未知命令") {
		t.Fatalf("未知命令未提示：%s", output.String())
	}
	if strings.ContainsAny(output.String(), "\x1b\x00\x07") {
		t.Fatalf("简化模式输出含控制字符：%q", output.String())
	}
}

// TestANSITerminalF1Parsing F1（ESC O P）解析为 KeyF1，App 绑定到帮助画面。
func TestANSITerminalF1Parsing(t *testing.T) {
	keys, err := replayKeys("\x1bOP")
	if err != io.EOF {
		t.Fatalf("回放结束错误 = %v，期望 io.EOF", err)
	}
	if len(keys) != 1 || keys[0].Kind != KeyF1 {
		t.Fatalf("F1 序列解析 = %+v，期望单个 KeyF1", keys)
	}
	// App 层：F1 打开帮助，Ctrl-C 退出；画面必须恢复终端。
	terminal := newReplayTerminal("\x1bOP\x03")
	if err := runReplayApp(t, terminal, "f1.yaml", nil, nil); err != nil {
		t.Fatalf("F1 帮助 Run: %v", err)
	}
	if !strings.Contains(visibleText(terminal.frames), "本控制台用于本地维护") {
		t.Fatalf("F1 未打开帮助画面：%s", visibleText(terminal.frames))
	}
	if terminal.closeCalls != 1 {
		t.Fatalf("Close 调用 = %d，期望 1", terminal.closeCalls)
	}
}

// TestANSITerminalInvalidUTF8Consumed 非法 UTF-8 起始字节应安全消费为 KeyUnknown，
// 不得让 UI 因读取错误退出；后续合法 ASCII 仍可继续读取。
func TestANSITerminalInvalidUTF8Consumed(t *testing.T) {
	keys, err := replayKeys("\xffa")
	if err != io.EOF {
		t.Fatalf("回放结束错误 = %v，期望 io.EOF", err)
	}
	if len(keys) != 2 {
		t.Fatalf("非法字节后按键 = %+v，期望 2 个", keys)
	}
	if keys[0].Kind != KeyUnknown {
		t.Fatalf("非法 UTF-8 起始字节 = %+v，期望 KeyUnknown", keys[0])
	}
	if keys[1].Kind != KeyRune || keys[1].Rune != 'a' {
		t.Fatalf("非法字节后的 ASCII = %+v，期望 Rune 'a'", keys[1])
	}
}

// TestANSITerminalEscapeDoesNotSwallowNext ESC 后跟普通字符时只返回 Esc，字符留给下一次读取。
func TestANSITerminalEscapeDoesNotSwallowNext(t *testing.T) {
	keys, err := replayKeys("\x1bq")
	if err != io.EOF {
		t.Fatalf("回放结束错误 = %v，期望 io.EOF", err)
	}
	want := []Key{{Kind: KeyEsc}, {Kind: KeyRune, Rune: 'q'}}
	if len(keys) != len(want) || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("ESC+q 解析 = %+v，期望 %+v", keys, want)
	}
}

// TestANSITerminalBracketedPaste bracketed paste 被识别并作为一次 KeyPaste 文本交付，
// 不把标记/控制序列拆成导航键或普通字符插入。
func TestANSITerminalBracketedPaste(t *testing.T) {
	keys, err := replayKeys("\x1b[200~粘贴内容\x1b[201~")
	if err != io.EOF {
		t.Fatalf("回放结束错误 = %v，期望 io.EOF", err)
	}
	if len(keys) != 1 || keys[0].Kind != KeyPaste || keys[0].Text != "粘贴内容" {
		t.Fatalf("bracketed paste 解析 = %+v，期望单个 KeyPaste Text=粘贴内容", keys)
	}
}

// TestPlainOutputSanitizesANSI 简化模式回显/诊断输出不得包含 ANSI/控制字符。
func TestPlainOutputSanitizesANSI(t *testing.T) {
	var output bytes.Buffer
	_ = RunPlain(context.Background(),
		strings.NewReader("path /tmp/\x1b[31mred.yaml\n"), &output, "")
	if strings.ContainsAny(output.String(), "\x1b\x00\x07") {
		t.Fatalf("简化模式输出含未清洗控制字符：%q", output.String())
	}
}

// TestCanvasCJKDisplayWidth 画布必须按显示宽度（CJK 宽 2）截断，20 列不写出 40 列。
func TestCanvasCJKDisplayWidth(t *testing.T) {
	canvas := NewCanvas(20, 6)
	canvas.Text(0, 0, strings.Repeat("中", 20))
	if width := maxVisibleColumns(canvas.Render()); width > 20 {
		t.Fatalf("CJK 文本可见宽度 %d 超过画布 20 列", width)
	}
}

// TestCanvasSingleLineNewlineTab 单行单元格中的 \n/\r/\t 必须转空格，不得破坏帧行布局。
func TestCanvasSingleLineNewlineTab(t *testing.T) {
	canvas := NewCanvas(40, 10)
	canvas.Text(0, 0, "a\nb\tc")
	lines := visibleLines(canvas.Render())
	// 渲染器会裁掉尾部空行；关键是控制空白不得在帧内制造额外行或残留控制字符。
	if len(lines) == 0 || len(lines) > canvas.Height() {
		t.Fatalf("可见行数 = %d，期望 1..%d（控制空白不得破坏帧布局）", len(lines), canvas.Height())
	}
	first := lines[0]
	if !strings.Contains(first, "a b c") {
		t.Fatalf("控制空白应转为空格且保持单行，首行 = %q", first)
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\n\r\t\x00\x07") {
			t.Fatalf("可见行含控制字符：%q", line)
		}
	}
}
