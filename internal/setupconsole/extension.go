package setupconsole

// WS1 扩展点（步骤277 + 冻结给 WS2–WS4 并行开发的注册 API，见
// .ai/lead/round12-ws1-interfaces.md）。
//
// 设计约束：
//   - 其他工作流只新增自己的文件并调用 RegisterMenu/RegisterScreen，不编辑 WS1 文件；
//   - 菜单项只是入口，业务逻辑/授权/领域调用在各自 ScreenController 实现；
//   - ID 稳定且全局唯一（重复注册返回错误，不静默覆盖）；
//   - 禁用项仍显示但不可进入，避免“菜单看得到但功能未实现”的假象。

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// SessionView 是控制台会话的只读快照 + 受限能力入口。
type SessionView struct {
	ConfigPath string
	Detection  Detection
	// App 指向控制台本体，供画面调用只读检测/状态栏/退出等公共能力；
	// 不向画面暴露终端读写或内部注册表。
	App *App
}

// MenuEntry 是注册到主菜单的一项。
type MenuEntry struct {
	// ID 是稳定唯一标识；同时用于 RegisterScreen。
	ID string
	// Label 是中文菜单文案（会做控制字符清洗）。
	Label string
	// Order 决定菜单顺序；内置项使用 0/10/20/900/1000，WS2–4 建议 100–899。
	Order int
	// Enabled 为 nil 表示总是可用；返回 false 时该菜单项显示但不可进入。
	Enabled func(Detection) bool
}

// ScreenController 是各工作流注册的维护画面。
type ScreenController interface {
	// Title 是画面标题（显示在窗口标题栏）。
	Title() string
	// Render 只写画布；不得直接写终端/读终端、不得启动无界后台任务。
	Render(ctx context.Context, canvas *Canvas, session SessionView)
	// HandleKey 返回 closeScreen=true 时回到主菜单；err 非 nil 退出控制台。
	HandleKey(ctx context.Context, key Key, session SessionView) (closeScreen bool, err error)
}

// 注册相关错误。
var (
	ErrScreenIDInvalid     = errors.New("画面/菜单 ID 无效")
	ErrScreenAlreadyInUse  = errors.New("画面/菜单 ID 已被注册")
	ErrScreenNotRegistered = errors.New("画面未注册")
)

// RegisterMenu 注册一个主菜单项；同一 ID 重复注册返回错误。
func (a *App) RegisterMenu(entry MenuEntry) error {
	if a == nil {
		return errors.New("控制台未初始化")
	}
	id := strings.TrimSpace(entry.ID)
	if id == "" || strings.ContainsAny(id, " \t\r\n") {
		return fmt.Errorf("%w: %q", ErrScreenIDInvalid, entry.ID)
	}
	if strings.TrimSpace(entry.Label) == "" {
		return fmt.Errorf("%w: %q 缺少菜单文案", ErrScreenIDInvalid, id)
	}
	entry.ID = id
	entry.Label = strings.TrimSpace(entry.Label)
	if a.menuEntries == nil {
		a.menuEntries = make(map[string]MenuEntry)
	}
	if _, exists := a.menuEntries[id]; exists {
		return fmt.Errorf("%w: %s", ErrScreenAlreadyInUse, id)
	}
	a.menuEntries[id] = entry
	a.menuOrderDirty = true
	return nil
}

// RegisterScreen 注册画面工厂；同一 ID 重复注册返回错误。
func (a *App) RegisterScreen(id string, factory func() ScreenController) error {
	if a == nil {
		return errors.New("控制台未初始化")
	}
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return fmt.Errorf("%w: %q", ErrScreenIDInvalid, id)
	}
	if factory == nil {
		return fmt.Errorf("%w: %q 缺少画面工厂", ErrScreenIDInvalid, cleanID)
	}
	if a.screens == nil {
		a.screens = make(map[string]func() ScreenController)
	}
	if _, exists := a.screens[cleanID]; exists {
		return fmt.Errorf("%w: %s", ErrScreenAlreadyInUse, cleanID)
	}
	a.screens[cleanID] = factory
	return nil
}

// OpenScreen 打开已注册画面；未注册/工厂失败返回错误。
func (a *App) OpenScreen(id string) error {
	if a == nil {
		return errors.New("控制台未初始化")
	}
	factory, exists := a.screens[strings.TrimSpace(id)]
	if !exists {
		return fmt.Errorf("%w: %s", ErrScreenNotRegistered, id)
	}
	controller := factory()
	if controller == nil {
		return fmt.Errorf("%w: %s 工厂返回空画面", ErrScreenNotRegistered, id)
	}
	a.activeScreen = controller
	a.screen = ScreenExternal
	a.statusText = ""
	return nil
}

// Session 返回当前会话快照。
func (a *App) Session() SessionView {
	if a == nil {
		return SessionView{}
	}
	return SessionView{ConfigPath: a.configPath, Detection: a.detection, App: a}
}

// Detection 返回最近一次检测结果。
func (a *App) Detection() Detection {
	if a == nil {
		return Detection{}
	}
	return a.detection
}

// ConfigPath 返回当前实例配置路径。
func (a *App) ConfigPath() string {
	if a == nil {
		return ""
	}
	return a.configPath
}

// Terminal 返回终端（仅 WS1 主框架/测试使用；画面应只写画布）。
func (a *App) Terminal() Terminal {
	if a == nil {
		return nil
	}
	return a.term
}

// SetStatus 写入底部状态行（文本会被清洗）。
func (a *App) SetStatus(text string) {
	if a == nil {
		return
	}
	a.statusText = sanitizeDisplay(text)
}

// RequestQuit 请求退出主循环。
func (a *App) RequestQuit() {
	if a == nil {
		return
	}
	a.quit = true
}

// RefreshDetection 重新执行只读状态检测并返回结果。
func (a *App) RefreshDetection(ctx context.Context) Detection {
	if a == nil {
		return Detection{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.detection = a.detect(ctx, DetectOptions{ConfigPath: a.configPath})
	a.statusText = "检测完成：" + a.detection.Kind.Label()
	return a.detection
}
