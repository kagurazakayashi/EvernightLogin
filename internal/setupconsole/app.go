package setupconsole

// 全屏主框架（步骤277）与主菜单/画面调度。
//
// 界面结构：标题栏 / 主体 / 状态行 / 按键提示。启动不依赖生产 Runtime：
// 无配置、坏配置、无数据库、数据库不可达、结构待迁移、root 缺失均能显示并允许退出。
// 277 提供入口/路径选择/只读状态检测/帮助/退出；278 起在同一框架内增加配置修复/编辑
// 画面；WS2–WS4 通过 extension.go 的注册 API 挂接各自画面（见接口冻结文档）。

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Screen 是控制台当前画面。
type Screen int

const (
	ScreenMain Screen = iota
	ScreenPath
	ScreenStatus
	ScreenHelp
	ScreenConfig // 278：坏配置诊断与修复/编辑
	ScreenFields // 279：全配置字段分组编辑
	ScreenExternal
)

// 内置菜单项 ID（稳定契约，扩展项不得复用）。
const (
	MenuStatus = "status"
	MenuConfig = "config"
	MenuFields = "fields"
	MenuPath   = "path"
	MenuHelp   = "help"
	MenuExit   = "exit"
)

// DetectFunc 是状态检测注入点（测试可替换；生产使用 Detect）。
type DetectFunc func(ctx context.Context, options DetectOptions) Detection

// App 是全屏控制台状态机。
type App struct {
	term       Terminal
	detect     DetectFunc
	configPath string
	screen     Screen
	cursor     int
	editing    string
	detection  Detection
	quit       bool
	statusText string
	title      string
	// 扩展点（WS2–WS4）。
	menuEntries    map[string]MenuEntry
	screens        map[string]func() ScreenController
	menuOrderDirty bool
	activeScreen   ScreenController
	// 278 配置修复/编辑状态下文。
	configUI *configScreenState
	// 279 全配置字段编辑状态。
	fieldsUI *fieldsScreenState
	// 会话内“上次有效配置原文”缓存（278）。
	lastValid LastValidStore
}

// menuItem 是渲染/按键使用的菜单项视图。
type menuItem struct {
	ID      string
	Label   string
	Enabled bool
}

// NewApp 构造控制台；terminal 必需，detect 为空时使用生产 Detect。
func NewApp(terminal Terminal, configPath string, detect DetectFunc) *App {
	if detect == nil {
		detect = Detect
	}
	return &App{term: terminal, configPath: strings.TrimSpace(configPath), detect: detect,
		title:       "EvernightLogin 本地维护控制台",
		menuEntries: make(map[string]MenuEntry), screens: make(map[string]func() ScreenController)}
}

// Run 进入全屏交互循环；Init/Close 由本方法负责（异常返回也恢复终端）。
func (a *App) Run(ctx context.Context) (runErr error) {
	if a == nil || a.term == nil {
		return fmt.Errorf("控制台终端未装配")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := a.term.Init(); err != nil {
		return err
	}
	defer func() {
		if closeErr := a.term.Close(); closeErr != nil && runErr == nil {
			runErr = closeErr
		}
	}()
	for !a.quit {
		width, height := a.term.Size()
		canvas := NewCanvas(width, height)
		a.render(ctx, canvas)
		if err := a.term.Write(canvas.Render()); err != nil {
			return err
		}
		key, err := a.term.ReadKey()
		if err != nil {
			return err
		}
		if handleErr := a.handleKey(ctx, key); handleErr != nil {
			return handleErr
		}
	}
	return nil
}

// builtinMenuEntries 是内置菜单项（277–280）。
func builtinMenuEntries() []MenuEntry {
	return []MenuEntry{
		{ID: MenuStatus, Label: "检查实例状态", Order: 0},
		{ID: MenuConfig, Label: "修复/编辑配置", Order: 10},
		{ID: MenuFields, Label: "全配置字段编辑", Order: 11},
		{ID: MenuPath, Label: "选择实例配置路径", Order: 20},
		{ID: MenuHelp, Label: "帮助", Order: 900},
		{ID: MenuExit, Label: "退出", Order: 1000},
	}
}

// menuItems 合成内置 + 扩展菜单项（按 Order 稳定排序，禁用项保留）。
func (a *App) menuItems() []menuItem {
	entries := make([]MenuEntry, 0, len(builtinMenuEntries())+len(a.menuEntries))
	entries = append(entries, builtinMenuEntries()...)
	registered := make([]MenuEntry, 0, len(a.menuEntries))
	for _, entry := range a.menuEntries {
		registered = append(registered, entry)
	}
	sort.SliceStable(registered, func(left, right int) bool {
		if registered[left].Order != registered[right].Order {
			return registered[left].Order < registered[right].Order
		}
		return registered[left].ID < registered[right].ID
	})
	entries = append(entries, registered...)
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].Order != entries[right].Order {
			return entries[left].Order < entries[right].Order
		}
		return entries[left].ID < entries[right].ID
	})
	items := make([]menuItem, 0, len(entries))
	for _, entry := range entries {
		enabled := true
		if entry.Enabled != nil {
			enabled = entry.Enabled(a.detection)
		}
		items = append(items, menuItem{ID: entry.ID, Label: entry.Label, Enabled: enabled})
	}
	return items
}

// render 绘制当前画面。
func (a *App) render(ctx context.Context, canvas *Canvas) {
	width, height := canvas.Width(), canvas.Height()
	title := a.title
	if a.screen == ScreenExternal && a.activeScreen != nil {
		title = a.activeScreen.Title()
	}
	canvas.Box(0, 0, width, height, title)
	stateLine := "实例配置：" + displayOr(a.configPath, "（未选择）")
	canvas.Text(2, 1, stateLine)
	status := "最近状态：未检测"
	if a.detection.Kind != "" {
		status = "最近状态：" + a.detection.Kind.Label()
	}
	if a.statusText != "" {
		status = a.statusText
	}
	canvas.Text(2, 2, status)
	bodyTop := 3
	bodyHeight := height - bodyTop - 3
	if bodyHeight < 3 {
		bodyHeight = 3
	}
	switch a.screen {
	case ScreenMain:
		a.renderMain(canvas, bodyTop)
	case ScreenPath:
		a.renderPath(canvas, bodyTop)
	case ScreenStatus:
		a.renderStatus(canvas, bodyTop, bodyHeight)
	case ScreenHelp:
		a.renderHelp(canvas, bodyTop)
	case ScreenConfig:
		a.renderConfig(ctx, canvas, bodyTop, bodyHeight)
	case ScreenFields:
		a.renderFields(ctx, canvas, bodyTop, bodyHeight)
	case ScreenExternal:
		if a.activeScreen != nil {
			a.activeScreen.Render(ctx, canvas, a.Session())
		}
	}
	canvas.HLine(height-2, '├', '┤')
	canvas.Text(2, height-1, a.footerText())
}

// footerText 是底部按键提示。
func (a *App) footerText() string {
	if a.screen == ScreenExternal {
		return "Esc 返回主菜单 · ↑/↓ 移动 · Enter 确认"
	}
	return "↑/↓ 选择 · Enter 确认 · Esc 返回/退出 · F1 帮助"
}

func (a *App) renderMain(canvas *Canvas, top int) {
	canvas.Text(2, top, "请选择操作：")
	items := a.menuItems()
	if a.cursor >= len(items) {
		a.cursor = len(items) - 1
	}
	if a.cursor < 0 {
		a.cursor = 0
	}
	for index, item := range items {
		position := top + 2 + index
		if position >= canvas.Height()-3 {
			break
		}
		prefix := "  "
		if index == a.cursor {
			if item.Enabled {
				prefix = "▶ "
			} else {
				prefix = "▶ (不可用) "
			}
		}
		canvas.Text(2, position, prefix+item.Label)
	}
	if a.detection.Kind != "" && a.configPath != "" {
		position := top + 2 + len(items) + 1
		if position < canvas.Height()-3 {
			canvas.Text(2, position, "状态："+a.detection.Kind.Label()+" · "+a.detection.Summary)
		}
	}
}

func (a *App) renderPath(canvas *Canvas, top int) {
	canvas.Text(2, top, "输入 login.yaml 配置路径（绝对/相对均可）：")
	canvas.Text(2, top+2, "> "+displayOr(a.editing, "（输入路径后按 Enter 检测）"))
	canvas.Text(2, top+4, "Enter 检测 · Esc 返回 · Backspace 删除")
}

func (a *App) renderStatus(canvas *Canvas, top, bodyHeight int) {
	detection := a.detection
	canvas.Text(2, top, "状态："+detection.Kind.Label())
	canvas.Text(2, top+1, detection.Summary)
	line := top + 3
	for _, detail := range detection.Details {
		if line >= canvas.Height()-3 {
			break
		}
		canvas.Text(2, line, "· "+detail)
		line++
	}
	if len(detection.Issues) > 0 {
		line++
		canvas.Text(2, line, "配置问题（修复建议）：")
		line++
		for _, issue := range detection.Issues {
			if line >= canvas.Height()-3 {
				break
			}
			canvas.Text(2, line, "· "+issue.Kind+" "+issue.Detail)
			line++
			if issue.Suggestion != "" && line < canvas.Height()-3 {
				canvas.Text(4, line, "建议："+issue.Suggestion)
				line++
			}
		}
	}
	_ = bodyHeight
	canvas.Text(2, canvas.Height()-3, "R 重新检测 · Esc 返回 · E 进入配置修复")
}

func (a *App) renderHelp(canvas *Canvas, top int) {
	lines := []string{
		"本控制台用于本地维护：无需先启动主服务，也不需要已有可用数据库。",
		"",
		"· 检查实例状态：只读检测配置/数据库/结构/root，不修改任何数据。",
		"· 修复/编辑配置：查看坏配置行列/字段/原因/建议；坏文件不会被自动覆盖。",
		"· 选择实例配置路径：指定要维护的 login.yaml。",
		"· 帮助：显示本页。退出：恢复终端并返回命令行。",
		"",
		"后续步骤将提供：数据库初始化/root 创建、维护画面、备份恢复与一键启动。",
		"安全：本地维护操作仍不跳过数据库一致性、用户名唯一性、密码策略与关键审计。",
	}
	for index, line := range lines {
		if top+index >= canvas.Height()-3 {
			break
		}
		canvas.Text(2, top+index, line)
	}
	canvas.Text(2, canvas.Height()-3, "Esc/Enter 返回")
}

// handleKey 处理一次按键。
func (a *App) handleKey(ctx context.Context, key Key) error {
	if key.Kind == KeyCtrlC || key.Kind == KeyCtrlD {
		a.quit = true
		return nil
	}
	// G4：F1 在任意画面打开帮助（帮助画面 Esc/Enter 返回主菜单）。
	if key.Kind == KeyF1 {
		a.screen = ScreenHelp
		return nil
	}
	// G5：bracketed paste 内容按文本分发，不把控制序列当按键。
	if key.Kind == KeyPaste {
		a.insertPaste(key.Text)
		return nil
	}
	if a.screen == ScreenExternal {
		return a.handleExternalKey(ctx, key)
	}
	// 278 配置画面自行处理 Esc（编辑器 Esc 返回诊断而不是退出控制台）。
	if a.screen == ScreenConfig {
		return a.handleConfigKey(ctx, key)
	}
	// 279 字段编辑画面自行处理 Esc（返回配置诊断，不退出控制台）。
	if a.screen == ScreenFields {
		return a.handleFieldsKey(ctx, key)
	}
	if key.Kind == KeyEsc {
		switch a.screen {
		case ScreenMain:
			a.quit = true
		default:
			a.screen = ScreenMain
			a.cursor = 0
			a.configUI = nil
		}
		return nil
	}
	switch a.screen {
	case ScreenMain:
		return a.handleMainKey(ctx, key)
	case ScreenPath:
		return a.handlePathKey(ctx, key)
	case ScreenStatus:
		return a.handleStatusKey(ctx, key)
	case ScreenHelp:
		if key.Kind == KeyEnter {
			a.screen = ScreenMain
			a.cursor = 0
		}
		return nil
	}
	return nil
}

func (a *App) handleExternalKey(ctx context.Context, key Key) error {
	if a.activeScreen == nil {
		a.screen = ScreenMain
		return nil
	}
	if key.Kind == KeyEsc {
		a.activeScreen = nil
		a.screen = ScreenMain
		a.cursor = 0
		return nil
	}
	closeScreen, err := a.activeScreen.HandleKey(ctx, key, a.Session())
	if err != nil {
		return err
	}
	if closeScreen {
		a.activeScreen = nil
		a.screen = ScreenMain
		a.cursor = 0
	}
	return nil
}

func (a *App) handleMainKey(ctx context.Context, key Key) error {
	items := a.menuItems()
	switch key.Kind {
	case KeyUp:
		if a.cursor > 0 {
			a.cursor--
		}
	case KeyDown, KeyTab:
		if a.cursor < len(items)-1 {
			a.cursor++
		}
	case KeyEnter:
		if len(items) == 0 {
			return nil
		}
		item := items[a.cursor]
		if !item.Enabled {
			a.statusText = "该维护功能当前不可用（前置条件未满足）"
			return nil
		}
		return a.activateMenu(ctx, item.ID)
	case KeyRune:
		switch key.Rune {
		case 'q', 'Q':
			a.quit = true
		case 'h', 'H', '?':
			a.screen = ScreenHelp
		case 'e', 'E':
			return a.activateMenu(ctx, MenuConfig)
		}
	}
	return nil
}

// activateMenu 打开内置或扩展菜单项。
func (a *App) activateMenu(ctx context.Context, id string) error {
	switch id {
	case MenuStatus:
		a.RefreshDetection(ctx)
		a.screen = ScreenStatus
		return nil
	case MenuConfig:
		return a.openConfigScreen(ctx)
	case MenuFields:
		return a.openFieldsScreen(ctx)
	case MenuPath:
		a.editing = a.configPath
		a.screen = ScreenPath
		return nil
	case MenuHelp:
		a.screen = ScreenHelp
		return nil
	case MenuExit:
		a.quit = true
		return nil
	default:
		return a.OpenScreen(id)
	}
}

func (a *App) handleStatusKey(ctx context.Context, key Key) error {
	switch key.Kind {
	case KeyEnter:
		a.screen = ScreenMain
		a.cursor = 0
	case KeyRune:
		switch key.Rune {
		case 'r', 'R':
			a.RefreshDetection(ctx)
		case 'e', 'E':
			return a.openConfigScreen(ctx)
		}
	}
	return nil
}

func (a *App) handlePathKey(ctx context.Context, key Key) error {
	switch key.Kind {
	case KeyEnter:
		path := strings.TrimSpace(a.editing)
		if path == "" {
			a.statusText = "路径不能为空"
			return nil
		}
		a.configPath = path
		a.lastValid = LastValidStore{}
		a.RefreshDetection(ctx)
		a.configUI = nil
		a.screen = ScreenStatus
	case KeyBackspace:
		runes := []rune(a.editing)
		if len(runes) > 0 {
			a.editing = string(runes[:len(runes)-1])
		}
	case KeyRune:
		a.editing += string(key.Rune)
	}
	return nil
}

// displayOr 返回非空可显示值。
func displayOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return sanitizeDisplay(value)
}

// insertPaste 把粘贴文本分发给当前需要文本输入的控件；其它画面安全忽略（G5）。
func (a *App) insertPaste(text string) {
	clean := sanitizeDisplay(text)
	switch a.screen {
	case ScreenPath:
		a.editing += clean
	case ScreenConfig:
		if a.configUI == nil {
			return
		}
		switch a.configUI.mode {
		case configModeEditor:
			if a.configUI.editor != nil {
				a.configUI.editor.InsertText(clean)
			}
		case configModeSaveAs:
			a.configUI.savePath += clean
		}
	case ScreenFields:
		if a.fieldsUI == nil {
			return
		}
		switch {
		case a.fieldsUI.preview:
			return
		case a.fieldsUI.editInput:
			a.fieldsUI.editText += clean
		case a.fieldsUI.searchInput:
			a.fieldsUI.search += clean
			a.fieldsUI.clampCursor()
		}
	default:
		a.statusText = "已忽略粘贴内容（当前画面不支持文本输入）"
	}
}
