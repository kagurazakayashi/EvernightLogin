package setupconsole

// 坏配置诊断与可恢复修复画面（步骤278）。
//
// 流程：诊断（只读）→ 原文局部编辑（内存草稿，不写盘）→ 重新验证 → 另存为（显式动作，
// 原子写入）。坏文件永远不会被自动覆盖；未知字段/注释/顺序因按原文编辑而保留；
// 数据库不可达不影响配置修复（本画面不访问数据库）。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type configMode int

const (
	configModeIssues configMode = iota
	configModeEditor
	configModeSaveAs
)

type configScreenState struct {
	report   ConfigReport
	mode     configMode
	editor   *lineEditor
	savePath string
	message  string
}

// openConfigScreen 载入配置诊断并进入修复画面。
func (a *App) openConfigScreen(ctx context.Context) error {
	if strings.TrimSpace(a.configPath) == "" {
		a.statusText = "请先选择实例配置路径，再进行配置诊断/修复"
		a.screen = ScreenPath
		a.editing = ""
		return nil
	}
	report := LoadConfigReport(a.configPath)
	if report.Valid {
		a.lastValid.Remember(report)
	}
	a.configUI = &configScreenState{report: report}
	a.screen = ScreenConfig
	_ = ctx
	return nil
}

// renderConfig 绘制配置诊断/编辑画面。
func (a *App) renderConfig(ctx context.Context, canvas *Canvas, top, bodyHeight int) {
	state := a.configUI
	if state == nil {
		canvas.Text(2, top, "配置诊断状态丢失，按 Esc 返回重新进入。")
		return
	}
	_ = ctx
	switch state.mode {
	case configModeEditor:
		a.renderConfigEditor(canvas, top, bodyHeight, state)
	case configModeSaveAs:
		a.renderConfigSaveAs(canvas, top, state)
	default:
		a.renderConfigIssues(canvas, top, bodyHeight, state)
	}
	if state.message != "" && canvas.Height() > 4 {
		canvas.Text(2, canvas.Height()-3, sanitizeDisplay(state.message))
	}
}

func (a *App) renderConfigIssues(canvas *Canvas, top, bodyHeight int, state *configScreenState) {
	report := state.report
	canvas.Text(2, top, "配置文件："+displayOr(a.configPath, "（未选择）"))
	canvas.Text(2, top+1, "诊断："+displayOr(report.Summary, "未诊断"))
	line := top + 3
	if len(report.Issues) == 0 {
		canvas.Text(2, line, report.Summary)
		line++
	} else {
		for _, issue := range report.Issues {
			if line >= canvas.Height()-4 {
				canvas.Text(2, line, "…（还有更多诊断，缩小终端可滚动查看/编辑）")
				break
			}
			location := ""
			if issue.Line > 0 {
				location = fmt.Sprintf("第 %d 行 ", issue.Line)
			}
			field := ""
			if issue.Field != "" {
				field = "[" + issue.Field + "] "
			}
			canvas.Text(2, line, fmt.Sprintf("· %s%s%s%s", location, field, issue.Kind, issue.Detail))
			line++
			if issue.Suggestion != "" && line < canvas.Height()-4 {
				canvas.Text(4, line, "建议："+issue.Suggestion)
				line++
			}
		}
	}
	canvas.Text(2, canvas.Height()-3, "E 编辑原文 · V 重新加载 · L 读取上次有效 · S 另存为 · Esc 返回")
}

func (a *App) renderConfigEditor(canvas *Canvas, top, bodyHeight int, state *configScreenState) {
	editor := state.editor
	if editor == nil {
		canvas.Text(2, top, "编辑器未就绪；按 Esc 返回诊断。")
		return
	}
	lineNumberWidth := 4
	viewHeight := bodyHeight - 2
	if viewHeight < 3 {
		viewHeight = 3
	}
	start, end := editor.VisibleLines(viewHeight)
	cursorLine, cursorColumn := editor.Cursor()
	for index := start; index < end; index++ {
		y := top + 1 + (index - start)
		marker := "  "
		if index == cursorLine {
			marker = "→ "
		}
		canvas.Text(2, y, fmt.Sprintf("%s%*d │ %s", marker, lineNumberWidth, index+1,
			editor.Line(index)))
	}
	// 光标列位置提示放在状态行上方（全屏渲染不移动真实光标，避免中文宽度问题）。
	canvas.Text(2, top, fmt.Sprintf("编辑草稿 %s（未写盘）  行 %d 列 %d",
		dirtyText(editor.Dirty()), cursorLine+1, cursorColumn+1))
	canvas.Text(2, canvas.Height()-3,
		"↑↓←→ 移动 · Enter 换行 · Tab 缩进 · Ctrl+S 验证 · Ctrl+O 另存为 · Esc 返回诊断")
}

func (a *App) renderConfigSaveAs(canvas *Canvas, top int, state *configScreenState) {
	canvas.Text(2, top, "另存为（不会覆盖当前坏文件）：")
	placeholder := ""
	if strings.TrimSpace(state.savePath) == "" {
		placeholder = "（留空 = " + defaultSaveAsPath(a.configPath) + "）"
	}
	canvas.Text(2, top+2, "> "+displayOr(state.savePath, placeholder))
	canvas.Text(2, top+4, "Enter 另存为（原子写入）· Esc 取消")
}

// handleConfigKey 处理配置画面按键（Esc 由这里处理，不直接退出控制台）。
func (a *App) handleConfigKey(ctx context.Context, key Key) error {
	state := a.configUI
	if state == nil {
		a.screen = ScreenMain
		return nil
	}
	state.message = ""
	switch state.mode {
	case configModeSaveAs:
		return a.handleConfigSaveAsKey(ctx, key, state)
	case configModeEditor:
		return a.handleConfigEditorKey(ctx, key, state)
	default:
		return a.handleConfigIssuesKey(ctx, key, state)
	}
}

func (a *App) handleConfigIssuesKey(ctx context.Context, key Key, state *configScreenState) error {
	switch key.Kind {
	case KeyEsc, KeyEnter:
		a.screen = ScreenMain
		a.cursor = 0
		a.configUI = nil
	case KeyRune:
		switch key.Rune {
		case 'e', 'E':
			if !state.report.ReloadAllowed() {
				state.message = "当前文件超出控制台编辑边界（过大/过深/不可读），只提供只读诊断"
				return nil
			}
			state.editor = newLineEditor(state.report.Raw)
			state.mode = configModeEditor
		case 'v', 'V':
			state.report = LoadConfigReport(a.configPath)
			if state.report.Valid {
				a.lastValid.Remember(state.report)
			}
			state.message = "已重新加载：" + state.report.Summary
		case 'l', 'L':
			if raw, found := a.lastValid.Load(a.configPath); found {
				state.editor = newLineEditor(raw)
				state.mode = configModeEditor
				state.message = "已载入本次会话的上次有效配置副本（尚未写盘）"
			} else {
				state.message = "没有可用的上次有效副本；请手工修复或另存为"
			}
		case 's', 'S':
			if state.report.Readable {
				state.editor = newLineEditor(state.report.Raw)
				state.savePath = ""
				state.mode = configModeSaveAs
			} else {
				state.message = "文件不可读，无法另存为；先选择有效路径或手工创建"
			}
		}
	}
	_ = ctx
	return nil
}

func (a *App) handleConfigEditorKey(ctx context.Context, key Key, state *configScreenState) error {
	editor := state.editor
	if editor == nil {
		state.mode = configModeIssues
		return nil
	}
	switch key.Kind {
	case KeyEsc:
		state.mode = configModeIssues
		state.message = "已返回诊断；草稿仍在内存中未写盘"
		return nil
	case KeyUp:
		editor.MoveLine(-1)
	case KeyDown:
		editor.MoveLine(1)
	case KeyLeft:
		editor.MoveColumn(-1)
	case KeyRight:
		editor.MoveColumn(1)
	case KeyHome:
		line, _ := editor.Cursor()
		editor.SetCursor(line, 0)
	case KeyEnd:
		line, _ := editor.Cursor()
		editor.SetCursor(line, len([]rune(editor.Line(line))))
	case KeyPageUp:
		editor.MoveLine(-10)
	case KeyPageDown:
		editor.MoveLine(10)
	case KeyEnter:
		editor.SplitLine()
	case KeyBackspace:
		editor.Backspace()
	case KeyTab:
		editor.InsertText("  ")
	case KeyCtrlS:
		report := ValidateConfigText(editor.Bytes())
		state.report = report
		state.message = "验证完成：" + report.Summary
		if report.Valid {
			a.lastValid.Remember(report)
		}
		state.mode = configModeIssues
	case KeyCtrlO:
		state.savePath = ""
		state.mode = configModeSaveAs
	case KeyRune:
		editor.InsertRune(key.Rune)
	}
	_ = ctx
	return nil
}

func (a *App) handleConfigSaveAsKey(ctx context.Context, key Key, state *configScreenState) error {
	switch key.Kind {
	case KeyEsc:
		state.mode = configModeIssues
		state.message = "已取消另存为；原文件未被修改"
	case KeyEnter:
		target := strings.TrimSpace(state.savePath)
		if target == "" {
			target = defaultSaveAsPath(a.configPath)
		}
		raw := state.report.Raw
		if state.editor != nil {
			raw = state.editor.Bytes()
		}
		if err := SafeWriteFile(target, raw, 0o600); err != nil {
			state.message = "另存为失败：" + publicFileError(err)
			return nil
		}
		// 另存为不改变当前实例路径；展示新文件的诊断结果。
		saved := LoadConfigReport(target)
		state.report = saved
		state.editor = nil
		state.mode = configModeIssues
		state.message = "已另存为：" + target + "（" + saved.Summary + "）"
		_ = ctx
	case KeyBackspace:
		runes := []rune(state.savePath)
		if len(runes) > 0 {
			state.savePath = string(runes[:len(runes)-1])
		}
	case KeyRune:
		state.savePath += string(key.Rune)
	}
	return nil
}

// defaultSaveAsPath 生成默认另存路径（同目录带 .repaired 后缀），不覆盖原文件。
func defaultSaveAsPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "login.repaired.yaml"
	}
	directory := filepath.Dir(trimmed)
	base := filepath.Base(trimmed)
	extension := filepath.Ext(base)
	stem := strings.TrimSuffix(base, extension)
	if extension == "" {
		extension = ".yaml"
	}
	return filepath.Join(directory, stem+".repaired"+extension)
}

// dirtyText 返回草稿状态文案。
func dirtyText(dirty bool) string {
	if dirty {
		return "（已修改）"
	}
	return "（未修改）"
}

var _ = os.FileMode(0)
