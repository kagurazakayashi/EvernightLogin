package setupconsole

// 步骤277/278：终端解析/画布/全屏状态机/配置修复画面与简化文本模式定向测试。
// 使用脚本化内存终端验证按键、画面内容、退出后恢复终端调用；不依赖真实 TTY。

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTerminal 是脚本化内存终端。
type fakeTerminal struct {
	size       [2]int
	keys       []Key
	index      int
	frames     []string
	initCalls  int
	closeCalls int
}

func newFakeTerminal(keys ...Key) *fakeTerminal {
	return &fakeTerminal{size: [2]int{100, 34}, keys: keys}
}

func (f *fakeTerminal) Init() error      { f.initCalls++; return nil }
func (f *fakeTerminal) Close() error     { f.closeCalls++; return nil }
func (f *fakeTerminal) Size() (int, int) { return f.size[0], f.size[1] }
func (f *fakeTerminal) Write(frame string) error {
	f.frames = append(f.frames, frame)
	return nil
}
func (f *fakeTerminal) ReadKey() (Key, error) {
	if f.index >= len(f.keys) {
		return Key{}, io.EOF
	}
	key := f.keys[f.index]
	f.index++
	return key, nil
}

func runeKey(value rune) Key { return Key{Kind: KeyRune, Rune: value} }
func downKey() Key           { return Key{Kind: KeyDown} }
func enterKey() Key          { return Key{Kind: KeyEnter} }
func escKey() Key            { return Key{Kind: KeyEsc} }
func upKey() Key             { return Key{Kind: KeyUp} }
func ctrlSKey() Key          { return Key{Kind: KeyCtrlS} }
func ctrlOKey() Key          { return Key{Kind: KeyCtrlO} }

// TestAppStatusFlowAndTerminalRestore 覆盖主菜单→状态检测→帮助→退出与终端恢复。
func TestAppStatusFlowAndTerminalRestore(t *testing.T) {
	detectCalls := 0
	detect := func(ctx context.Context, options DetectOptions) Detection {
		detectCalls++
		return Detection{Kind: StateNoConfig, ConfigPath: options.ConfigPath,
			Summary: "配置不存在（测试）"}
	}
	terminal := newFakeTerminal(
		enterKey(), // 检查实例状态（默认光标在 index 0）
		escKey(),
		downKey(), downKey(), downKey(), downKey(), enterKey(), // 帮助（index 4）
		escKey(),
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey(), // 退出（index 5）
	)
	app := NewApp(terminal, "test-login.yaml", detect)
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("运行控制台: %v", err)
	}
	if terminal.initCalls != 1 || terminal.closeCalls != 1 {
		t.Fatalf("Init/Close 调用次数 = %d/%d，期望 1/1",
			terminal.initCalls, terminal.closeCalls)
	}
	if detectCalls != 1 {
		t.Fatalf("检测调用次数 = %d，期望 1", detectCalls)
	}
	joined := strings.Join(terminal.frames, "\n")
	for _, want := range []string{"本地维护控制台", "检查实例状态", "状态：",
		"帮助", "退出"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("画面缺少内容 %q", want)
		}
	}
}

// TestAppPathSelection 覆盖路径输入、取消与重新检测。
func TestAppPathSelection(t *testing.T) {
	detect := func(ctx context.Context, options DetectOptions) Detection {
		return Detection{Kind: StateConfigInvalid, ConfigPath: options.ConfigPath,
			Summary: "配置错误（测试）",
			Issues:  []ConfigIssue{{Kind: "yaml-syntax", Line: 3, Detail: "缩进错误", Suggestion: "修复缩进"}}}
	}
	terminal := newFakeTerminal(
		downKey(), downKey(), downKey(), enterKey(), // 进入路径选择（index 3）
		runeKey('a'), runeKey('/'), runeKey('b'), Key{Kind: KeyBackspace},
		escKey(),                                    // 取消返回
		downKey(), downKey(), downKey(), enterKey(), // 再次进入
		runeKey('c'), enterKey(), // 输入 c 并检测
		escKey(),                                                          // 返回主菜单
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey(), // 退出
	)
	app := NewApp(terminal, "", detect)
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("运行控制台: %v", err)
	}
	joined := strings.Join(terminal.frames, "\n")
	if !strings.Contains(joined, "输入 login.yaml 配置路径") {
		t.Fatal("缺少路径输入画面")
	}
	if !strings.Contains(joined, "yaml-syntax") || !strings.Contains(joined, "修复缩进") {
		t.Fatal("状态画面缺少配置诊断/修复建议")
	}
}

// TestAppConfigRepairFlow 覆盖坏配置诊断→编辑→另存为→原文件不变。
func TestAppConfigRepairFlow(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	original := "server:\n  unknown_field: 1\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("写入坏配置: %v", err)
	}
	savePath := filepath.Join(dir, "login.repaired.yaml")
	terminal := newFakeTerminal(
		downKey(), enterKey(), // 修复/编辑配置（index 1）
		runeKey('e'),                                  // 进入编辑
		Key{Kind: KeyEnd}, runeKey(' '), runeKey('#'), // 行尾加注释（不改变语义）
		ctrlSKey(),   // 验证（仍无效，展示诊断）
		runeKey('s'), // 另存为
	)
	for _, character := range savePath {
		terminal.keys = append(terminal.keys, runeKey(character))
	}
	terminal.keys = append(terminal.keys,
		enterKey(),                                                        // 另存为
		escKey(),                                                          // 返回主菜单
		downKey(), downKey(), downKey(), downKey(), downKey(), enterKey()) // 退出（index 5）
	app := NewApp(terminal, configPath, nil)
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("运行控制台: %v", err)
	}
	originalData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("原文件不可读: %v", err)
	}
	if string(originalData) != original {
		t.Fatal("修复流程自动覆盖了原坏文件（禁止）")
	}
	saved, statErr := os.ReadFile(savePath)
	if statErr != nil {
		t.Fatalf("另存为文件不存在: %v", statErr)
	}
	if !strings.Contains(string(saved), "unknown_field") {
		t.Fatalf("另存草稿丢失未知字段: %q", string(saved))
	}
	joined := strings.Join(terminal.frames, "\n")
	if !strings.Contains(joined, "另存为") || !strings.Contains(joined, "编辑草稿") {
		t.Fatal("配置修复画面内容缺失")
	}
}

// TestANSITerminalKeyParsing 验证方向键/编辑键/Enter/Esc/Ctrl 键解析。
func TestANSITerminalKeyParsing(t *testing.T) {
	input := []byte("\x1b[A\x1b[B\x1b[C\x1b[D\r\t\x7f\x1b[5~\x1b[6~\x13\x0f\x1bq")
	terminal := NewANSITerminal(bytes.NewReader(input), io.Discard)
	want := []KeyKind{KeyUp, KeyDown, KeyRight, KeyLeft, KeyEnter, KeyTab,
		KeyBackspace, KeyPageUp, KeyPageDown, KeyCtrlS, KeyCtrlO, KeyEsc}
	for index, expected := range want {
		key, err := terminal.ReadKey()
		if err != nil {
			t.Fatalf("第 %d 个按键读取失败: %v", index, err)
		}
		if key.Kind != expected {
			t.Fatalf("第 %d 个按键 = %v，期望 %v", index, key.Kind, expected)
		}
	}
}

// TestSanitizeDisplay 验证控制字符不会成为终端指令。
func TestSanitizeDisplay(t *testing.T) {
	dirty := "正常\x1b[31m红色\x07\x00文本"
	clean := sanitizeDisplay(dirty)
	if strings.ContainsAny(clean, "\x1b\x07\x00") {
		t.Fatalf("清洗后仍含控制字符: %q", clean)
	}
	if !strings.Contains(clean, "正常") || !strings.Contains(clean, "文本") {
		t.Fatalf("清洗丢失正常文本: %q", clean)
	}
}

// TestCanvasRenderNoControlInjection 验证画布不输出未清洗数据。
func TestCanvasRenderNoControlInjection(t *testing.T) {
	canvas := NewCanvas(60, 12)
	canvas.Text(1, 1, "x\x1b[2Jy")
	if strings.Contains(canvas.Render(), "\x1b[2J") {
		t.Fatal("画布渲染包含未清洗的清除屏幕序列")
	}
}

// TestRunPlainStatusAndExit 验证简化文本模式命令与退出，配置诊断与全屏同源。
func TestRunPlainStatusAndExit(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("server: [\n"), 0o600); err != nil {
		t.Fatalf("写入坏配置: %v", err)
	}
	input := strings.NewReader("help\npath " + badPath + "\nstatus\nvalidate\nquit\n")
	var output bytes.Buffer
	result := RunPlain(context.Background(), input, &output, "")
	if result.ConfigPath != badPath {
		t.Fatalf("简化模式配置路径 = %q", result.ConfigPath)
	}
	text := output.String()
	for _, want := range []string{"简化文本模式", "命令：", "配置路径已设置为",
		"状态：", "摘要：", "建议："} {
		if !strings.Contains(text, want) {
			t.Fatalf("简化模式输出缺少 %q：%s", want, text)
		}
	}
}

// TestANSITerminalInitCloseOnPipe 验证非 TTY 读写流也能安全 Init/Close（不 panic）。
func TestANSITerminalInitCloseOnPipe(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()
	defer inputWriter.Close()
	var output bytes.Buffer
	terminal := NewANSITerminal(inputReader, &output)
	if err := terminal.Init(); err != nil {
		t.Fatalf("非 TTY 初始化失败: %v", err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatalf("非 TTY 关闭失败: %v", err)
	}
	if !strings.Contains(output.String(), "\x1b[?1049h") ||
		!strings.Contains(output.String(), "\x1b[?1049l") {
		t.Fatal("终端未写入备用屏幕进入/退出序列")
	}
}
