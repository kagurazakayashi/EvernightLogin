package setupconsole

// 步骤298（WS5 测试侧）：输入事件回放与终端模型测试框架。
//
// 目的：用脚本化字节输入驱动真实 ANSITerminal 与 App 状态机，验证界面流程，而不是
// 只测业务函数。框架提供：
//   - replayTerminal：真实按键解析（ANSITerminal.ReadKey）+ 帧记录 + 尺寸变化 + 错误注入；
//   - visibleLines：去除渲染器 ANSI 控制序列后的可见行（用于断言界面内容/宽度）；
//   - runReplayApp：构造 App、回放输入、返回退出错误与记录；
//   - displayColumns：按东亚宽字符（CJK/emoji 宽 2）估算显示列宽，用于窄屏/宽字符断言。
//
// 测试序列只使用合成输入，不包含真实秘密；不启动真实 TTY/伪终端（Windows 可用的
// 伪终端在后续 WS5 299 构建验证中补充，本文件只覆盖可复现的终端模型）。

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

// replayTerminal 是脚本化字节输入的内存终端模型。
// 它只复用 ANSITerminal 的按键解析；Init/Close 由 App 调用并计数，帧写入被记录。
type replayTerminal struct {
	parser     *ANSITerminal
	frames     []string
	sizes      [][2]int
	sizeIndex  int
	initCalls  int
	closeCalls int
	initErr    error
	closeErr   error
	writeErr   error
}

// newReplayTerminal 用原始输入字节构造终端模型。
func newReplayTerminal(rawInput string, sizes ...[2]int) *replayTerminal {
	terminal := &replayTerminal{
		parser: NewANSITerminal(strings.NewReader(rawInput), io.Discard),
	}
	if len(sizes) == 0 {
		sizes = [][2]int{{100, 34}}
	}
	terminal.sizes = sizes
	return terminal
}

// Init 记录进入全屏调用（不写真实终端）。
func (r *replayTerminal) Init() error {
	r.initCalls++
	return r.initErr
}

// Close 记录恢复终端调用。
func (r *replayTerminal) Close() error {
	r.closeCalls++
	return r.closeErr
}

// Size 按预置尺寸序列返回；用完后停在最后一组，模拟窗口缩放。
func (r *replayTerminal) Size() (int, int) {
	if len(r.sizes) == 0 {
		return 80, 24
	}
	size := r.sizes[r.sizeIndex]
	if r.sizeIndex < len(r.sizes)-1 {
		r.sizeIndex++
	}
	return size[0], size[1]
}

// Write 记录一帧。
func (r *replayTerminal) Write(frame string) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.frames = append(r.frames, frame)
	return nil
}

// ReadKey 使用真实 ANSI 解析器读取脚本化输入。
func (r *replayTerminal) ReadKey() (Key, error) { return r.parser.ReadKey() }

// frameANSI 是渲染器允许的 ANSI 控制序列（光标归位/清行）；断言可见内容前先移除。
var frameANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// visibleLines 去掉渲染器 ANSI 控制序列并按行返回可见文本。
func visibleLines(frame string) []string {
	clean := frameANSI.ReplaceAllString(frame, "")
	clean = strings.ReplaceAll(clean, "\r\n", "\n")
	clean = strings.TrimRight(clean, "\n")
	if clean == "" {
		return nil
	}
	return strings.Split(clean, "\n")
}

// visibleText 返回所有帧的可见文本（用换行连接）。
func visibleText(frames []string) string {
	var builder strings.Builder
	for _, frame := range frames {
		builder.WriteString(strings.Join(visibleLines(frame), "\n"))
		builder.WriteString("\n")
	}
	return builder.String()
}

// displayColumns 估算字符串在终端上的显示列宽：CJK/全角/emoji 近似 2 列，其余 1 列。
// 这是测试模型的近似口径，不替代真实终端的 wcwidth 实现。
func displayColumns(text string) int {
	width := 0
	for _, r := range text {
		switch {
		case r >= 0x1100 && r <= 0x115f, // Hangul Jamo
			r >= 0x2e80 && r <= 0xa4cf, // CJK 部首/汉字/日文/韩文
			r >= 0xac00 && r <= 0xd7a3, // Hangul
			r >= 0xf900 && r <= 0xfaff, // CJK 兼容汉字
			r >= 0xfe30 && r <= 0xfe4f, // CJK 兼容形式
			r >= 0xff00 && r <= 0xff60, // 全角
			r >= 0xffe0 && r <= 0xffe6,
			r >= 0x1f300 && r <= 0x1faff, // emoji 常见区
			r >= 0x20000 && r <= 0x3fffd:
			width += 2
		default:
			width++
		}
	}
	return width
}

// maxVisibleColumns 返回一帧可见行的最大显示列宽。
func maxVisibleColumns(frame string) int {
	maxWidth := 0
	for _, line := range visibleLines(frame) {
		if width := displayColumns(line); width > maxWidth {
			maxWidth = width
		}
	}
	return maxWidth
}

// maxVisibleRunes 返回一帧可见行的最大 rune 数（画布按 rune 列渲染，用于验证不横向增长；
// 东亚宽字符的显示列宽见 displayColumns 与 CJK 缺口测试）。
func maxVisibleRunes(frame string) int {
	maxRunes := 0
	for _, line := range visibleLines(frame) {
		if count := len([]rune(line)); count > maxRunes {
			maxRunes = count
		}
	}
	return maxRunes
}

// runReplayApp 在给定输入上运行 App；返回终端记录与 Run 的错误。
func runReplayApp(t *testing.T, terminal *replayTerminal, configPath string,
	detect DetectFunc, setup func(*App)) error {
	t.Helper()
	if detect == nil {
		detect = func(context.Context, DetectOptions) Detection {
			return Detection{Kind: StateNoConfig, Summary: "测试状态"}
		}
	}
	app := NewApp(terminal, configPath, detect)
	if setup != nil {
		setup(app)
	}
	return app.Run(context.Background())
}

// TestReplayArrowTabHelpAndExit 回放箭头/Tab 导航、帮助快捷键、Esc 返回与退出，核对终端恢复。
func TestReplayArrowTabHelpAndExit(t *testing.T) {
	// 只依赖按键行为，不依赖菜单项数量/顺序（277/279 等新菜单项不得让测试脆弱）。
	// 上、下、Tab、上 移动光标，h 打开帮助，Esc 返回主菜单，Ctrl-C 退出。
	terminal := newReplayTerminal("\x1b[A\x1b[B\t\x1b[A" + "h" + "\x1b" + "\x03")
	if err := runReplayApp(t, terminal, "test-login.yaml", nil, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if terminal.initCalls != 1 || terminal.closeCalls != 1 {
		t.Fatalf("Init/Close = %d/%d，期望 1/1（正常退出必须恢复终端）",
			terminal.initCalls, terminal.closeCalls)
	}
	if len(terminal.frames) < 3 {
		t.Fatalf("帧数 = %d，期望至少 3（主菜单/帮助/返回）", len(terminal.frames))
	}
	text := visibleText(terminal.frames)
	if !strings.Contains(text, "本控制台用于本地维护") {
		t.Fatalf("帮助画面未渲染：%s", text)
	}
	for index, frame := range terminal.frames {
		for _, line := range visibleLines(frame) {
			if strings.ContainsAny(line, "\x00\x07\x1b") {
				t.Fatalf("帧 %d 可见行含原始控制字符: %q", index, line)
			}
		}
	}
}

// TestReplayWideCharPathInputAndDetection 回放中文路径输入/退格/Enter，核对检测输入。
func TestReplayWideCharPathInputAndDetection(t *testing.T) {
	var detectedPath string
	detect := func(_ context.Context, options DetectOptions) Detection {
		detectedPath = options.ConfigPath
		return Detection{Kind: StateNoConfig, ConfigPath: options.ConfigPath,
			Summary: "配置不存在（回放测试）"}
	}
	// 直接进入内置路径画面（稳定画面状态，不依赖菜单项数量/顺序）；输入“配置.yaml”；
	// 退格删除最后一个字符；Enter 检测；Ctrl-C 从状态画面退出。
	raw := "配置.yaml" + "\x7f" + "\r" + "\x03"
	terminal := newReplayTerminal(raw)
	setup := func(app *App) {
		app.screen = ScreenPath
		app.editing = ""
	}
	if err := runReplayApp(t, terminal, "", detect, setup); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if detectedPath != "配置.yam" {
		t.Fatalf("检测路径 = %q，期望 %q（宽字符按 rune 退格一次）", detectedPath, "配置.yam")
	}
	text := visibleText(terminal.frames)
	if !strings.Contains(text, "配置.yam") {
		t.Fatalf("状态帧未显示输入的路径：%s", text)
	}
	if terminal.closeCalls != 1 {
		t.Fatalf("Close 调用 = %d，期望 1", terminal.closeCalls)
	}
}

// TestReplayNarrowTerminalMinimumSize 回放 20x6 窄屏：不 panic、显示宽度不越界、仍可退出。
func TestReplayNarrowTerminalMinimumSize(t *testing.T) {
	terminal := newReplayTerminal("\x03", [2]int{20, 6})
	setup := func(app *App) { app.screen = ScreenStatus }
	if err := runReplayApp(t, terminal, "narrow.yaml", nil, setup); err != nil {
		t.Fatalf("窄屏 Run: %v", err)
	}
	if len(terminal.frames) == 0 {
		t.Fatal("窄屏未写出任何帧")
	}
	for index, frame := range terminal.frames {
		if runes := maxVisibleRunes(frame); runes > 20 {
			t.Fatalf("帧 %d 可见 rune 数 %d 超过终端 20 列", index, runes)
		}
		if width := maxVisibleColumns(frame); width > 20 {
			t.Fatalf("帧 %d 显示宽度 %d 超过终端 20 列（CJK 宽度处理）", index, width)
		}
	}
}

// TestReplayResizeBetweenFrames 回放窗口缩放：画布按新尺寸重建且显示宽度不越界。
func TestReplayResizeBetweenFrames(t *testing.T) {
	terminal := newReplayTerminal("\r\x03", [2]int{100, 34}, [2]int{20, 6}, [2]int{40, 10})
	setup := func(app *App) { app.screen = ScreenStatus }
	if err := runReplayApp(t, terminal, "resize.yaml", nil, setup); err != nil {
		t.Fatalf("缩放 Run: %v", err)
	}
	if len(terminal.frames) < 2 {
		t.Fatalf("帧数 = %d，期望至少 2", len(terminal.frames))
	}
	if width := maxVisibleColumns(terminal.frames[0]); width > 100 {
		t.Fatalf("首帧显示宽度 %d 超过 100", width)
	}
	if width := maxVisibleColumns(terminal.frames[1]); width > 20 {
		t.Fatalf("缩放后第 2 帧显示宽度 %d 超过 20", width)
	}
}

// TestReplayExternalScreenLifecycle 回放扩展画面注册/进入/按键/Esc 返回主菜单。
// 用稳定 Order=-100 让扩展项排在首位（不依赖 277/279 等新增菜单项后的序号）。
func TestReplayExternalScreenLifecycle(t *testing.T) {
	var received []Key
	controller := &replayScreen{title: "测试维护画面", received: &received}
	terminal := newReplayTerminal("\rx\x1b")
	setup := func(app *App) {
		if err := app.RegisterMenu(MenuEntry{ID: "test.replay", Label: "回放测试画面", Order: -100,
			Enabled: func(Detection) bool { return true }}); err != nil {
			t.Fatalf("注册菜单: %v", err)
		}
		if err := app.RegisterScreen("test.replay", func() ScreenController { return controller }); err != nil {
			t.Fatalf("注册画面: %v", err)
		}
	}
	// Enter 打开首个菜单（扩展画面）；x 交给画面；Esc 返回主菜单；随后 EOF 退出（应恢复终端）。
	err := runReplayApp(t, terminal, "external.yaml", nil, setup)
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("扩展画面 Esc 返回后 EOF 应返回 io.EOF，得到 %v", err)
	}
	text := visibleText(terminal.frames)
	if !strings.Contains(text, controller.title) {
		t.Fatalf("扩展画面标题未渲染：%s", text)
	}
	if !strings.Contains(text, "请选择操作") {
		t.Fatalf("Esc 后未回到主菜单：%s", text)
	}
	foundRune := false
	for _, key := range received {
		if key.Kind == KeyRune && key.Rune == 'x' {
			foundRune = true
		}
	}
	if !foundRune {
		t.Fatalf("扩展画面未收到 'x' 按键：%+v", received)
	}
	if terminal.closeCalls != 1 {
		t.Fatalf("Close 调用 = %d，期望 1", terminal.closeCalls)
	}
}

// replayScreen 是扩展画面测试替身。
type replayScreen struct {
	title    string
	received *[]Key
}

func (s *replayScreen) Title() string { return s.title }

func (s *replayScreen) Render(_ context.Context, canvas *Canvas, _ SessionView) {
	canvas.Text(2, 5, "扩展画面内容")
}

func (s *replayScreen) HandleKey(_ context.Context, key Key, _ SessionView) (bool, error) {
	*s.received = append(*s.received, key)
	return false, nil
}

// TestReplayTerminalRestoresOnReadEOF 输入 EOF（例如终端关闭）也必须恢复终端。
func TestReplayTerminalRestoresOnReadEOF(t *testing.T) {
	terminal := newReplayTerminal("")
	err := runReplayApp(t, terminal, "eof.yaml", nil, nil)
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF 应返回 io.EOF，得到 %v", err)
	}
	if terminal.initCalls != 1 || terminal.closeCalls != 1 {
		t.Fatalf("Init/Close = %d/%d，期望 1/1（异常退出恢复终端）",
			terminal.initCalls, terminal.closeCalls)
	}
}

// TestReplayTerminalRestoresOnWriteError 写帧失败也恢复终端。
func TestReplayTerminalRestoresOnWriteError(t *testing.T) {
	terminal := newReplayTerminal("\x03")
	terminal.writeErr = errors.New("模拟写失败")
	err := runReplayApp(t, terminal, "write.yaml", nil, nil)
	if err == nil {
		t.Fatal("写失败应返回错误")
	}
	if terminal.closeCalls != 1 {
		t.Fatalf("Close 调用 = %d，期望 1", terminal.closeCalls)
	}
}

// TestReplayInitErrorSkipsLoop Init 失败时不进入交互循环、也不 Close（未进入全屏）。
func TestReplayInitErrorSkipsLoop(t *testing.T) {
	terminal := newReplayTerminal("\x03")
	terminal.initErr = errors.New("模拟 Init 失败")
	if err := runReplayApp(t, terminal, "init.yaml", nil, nil); err == nil {
		t.Fatal("Init 失败应返回错误")
	}
	if len(terminal.frames) != 0 {
		t.Fatalf("Init 失败仍写帧 %d", len(terminal.frames))
	}
	if terminal.closeCalls != 0 {
		t.Fatalf("Init 失败不应调用 Close（当前 %d）", terminal.closeCalls)
	}
}

// TestReplayEscFromMainQuits 主菜单 Esc 退出并恢复终端。
func TestReplayEscFromMainQuits(t *testing.T) {
	terminal := newReplayTerminal("\x1b")
	if err := runReplayApp(t, terminal, "esc.yaml", nil, nil); err != nil {
		t.Fatalf("Esc 退出 Run: %v", err)
	}
	if terminal.closeCalls != 1 {
		t.Fatalf("Close 调用 = %d，期望 1", terminal.closeCalls)
	}
}

// TestReplayNarrowCJKOverflow 20 列窄屏下中文菜单/状态必须按显示宽度截断，不越界。
func TestReplayNarrowCJKOverflow(t *testing.T) {
	terminal := newReplayTerminal("\x03", [2]int{20, 6})
	if err := runReplayApp(t, terminal, "narrow-cjk.yaml", nil, nil); err != nil {
		t.Fatalf("窄屏 Run: %v", err)
	}
	if len(terminal.frames) == 0 {
		t.Fatal("窄屏未写出帧")
	}
	if width := maxVisibleColumns(terminal.frames[0]); width > 20 {
		t.Fatalf("窄屏中文帧显示宽度 %d 超过 20 列", width)
	}
}
