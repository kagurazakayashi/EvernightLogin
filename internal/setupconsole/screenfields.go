package setupconsole

// 全配置字段编辑画面（步骤279）。
//
// 以 config.Fields() 注册表 + config.Load 校验器为唯一语义来源；本画面只改内存草稿，
// 不写盘（保存/差异确认在步骤280接入）。功能：分组展示、搜索、只看修改/错误、高级分组
// 折叠、默认值/文件值/有效值/覆盖来源、重载生效分类、秘密字段只显示状态、列表/映射/
// 嵌套字段编辑。所有行渲染经画布清洗，秘密字段不回显值。

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type fieldsScreenState struct {
	draft        *ConfigDraft
	views        []FieldView
	cursor       int
	search       string
	searchInput  bool
	onlyModified bool
	onlyErrors   bool
	showAdvanced bool
	editInput    bool
	editText     string
	message      string
	report       ConfigReport
	// 280：差异预览/保存状态。
	preview     bool
	saveMessage string
	lastSave    SaveResult
}

// advancedGroups 是“高级”分组（默认折叠以降低误改风险）。
var advancedGroups = map[string]bool{
	"secrets": true, "protocol": true, "app_qr_login": true,
	"passkey": true, "mail": true, "manual_recovery": true,
}

// openFieldsScreen 从当前配置文件构造草稿并进入字段编辑画面。
func (a *App) openFieldsScreen(ctx context.Context) error {
	path := strings.TrimSpace(a.configPath)
	if path == "" {
		a.statusText = "请先选择实例配置路径"
		a.screen = ScreenPath
		a.editing = ""
		return nil
	}
	raw, err := readConfigRaw(path)
	if err != nil {
		a.statusText = "无法读取配置：" + publicFileError(err)
		return a.openConfigScreen(ctx)
	}
	draft, draftErr := NewConfigDraft(path, raw)
	if draftErr != nil {
		a.statusText = "配置 YAML 无法解析：" + publicFileError(draftErr)
		return a.openConfigScreen(ctx)
	}
	report := draft.Validate()
	state := &fieldsScreenState{draft: draft, report: report}
	state.refreshViews()
	state.moveCursor(1)
	a.fieldsUI = state
	a.screen = ScreenFields
	return nil
}

// refreshViews 重建字段视图并裁剪光标。
func (s *fieldsScreenState) refreshViews() {
	s.views = BuildFieldViews(s.draft)
	s.report = s.draft.Validate()
	s.clampCursor()
}

// visibleViews 返回当前筛选/折叠条件下可见的字段视图（保持注册表顺序）。
func (s *fieldsScreenState) visibleViews() []FieldView {
	query := strings.ToLower(strings.TrimSpace(s.search))
	visible := make([]FieldView, 0, len(s.views))
	for _, view := range s.views {
		if s.onlyModified && !view.Modified {
			continue
		}
		if s.onlyErrors && view.Error == "" {
			continue
		}
		if !s.showAdvanced && advancedGroups[view.Group] {
			// 折叠高级分组：仅在“只看错误/只看修改或搜索命中”时临时显示，
			// 避免用户把被隐藏字段的变更误认为不存在。
			if !(s.onlyModified || s.onlyErrors) && query == "" {
				continue
			}
		}
		if query != "" {
			haystack := strings.ToLower(view.Path + " " + view.GroupLabel + " " +
				view.Effective + " " + view.Default)
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		visible = append(visible, view)
	}
	return visible
}

func (s *fieldsScreenState) clampCursor() {
	visible := s.visibleViews()
	if len(visible) == 0 {
		s.cursor = 0
		return
	}
	if s.cursor >= len(visible) {
		s.cursor = len(visible) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *fieldsScreenState) moveCursor(delta int) {
	visible := s.visibleViews()
	if len(visible) == 0 {
		return
	}
	s.cursor += delta
	if s.cursor < 0 {
		s.cursor = 0
	}
	if s.cursor >= len(visible) {
		s.cursor = len(visible) - 1
	}
}

func (s *fieldsScreenState) selected() (FieldView, bool) {
	visible := s.visibleViews()
	if len(visible) == 0 || s.cursor < 0 || s.cursor >= len(visible) {
		return FieldView{}, false
	}
	return visible[s.cursor], true
}

// renderFields 绘制字段编辑画面。
func (a *App) renderFields(ctx context.Context, canvas *Canvas, top, bodyHeight int) {
	state := a.fieldsUI
	if state == nil {
		canvas.Text(2, top, "字段编辑状态丢失，按 Esc 返回重新进入。")
		return
	}
	if state.preview {
		a.renderDraftPreview(canvas, top, bodyHeight, state)
		return
	}
	canvas.Text(2, top, "配置文件："+displayOr(a.configPath, "（未选择）"))
	filter := "筛选："
	if state.search != "" {
		filter += "搜索=" + state.search + " "
	}
	if state.onlyModified {
		filter += "只看修改 "
	}
	if state.onlyErrors {
		filter += "只看错误 "
	}
	if state.showAdvanced {
		filter += "高级分组=显示 "
	}
	filter += fmt.Sprintf("· 校验：%s", displayOr(state.report.Summary, "未校验"))
	canvas.Text(2, top+1, filter)
	visible := state.visibleViews()
	rowsTop := top + 3
	rowsHeight := bodyHeight - 2
	if rowsHeight < 3 {
		rowsHeight = 3
	}
	lastGroup := ""
	row := 0
	for index, view := range visible {
		if row >= rowsHeight {
			break
		}
		if view.Group != lastGroup {
			canvas.Text(2, rowsTop+row, "── "+view.GroupLabel+" "+view.Group+" ──")
			row++
			lastGroup = view.Group
			if row >= rowsHeight {
				break
			}
		}
		marker := "  "
		if index == state.cursor {
			marker = "▶ "
		}
		line := fmt.Sprintf("%s%s", marker, view.Path)
		canvas.Text(2, rowsTop+row, line)
		details := "文件=" + view.File + " · 有效=" + view.Effective
		if view.Override != "" {
			details += " · " + view.Override
		}
		state.styles(details, view)
		canvas.Text(4, rowsTop+row+0, "")
		canvas.Text(26, rowsTop+row, truncateFieldText(details, canvas.Width()-28))
		if view.Modified {
			canvas.Text(canvas.Width()-3, rowsTop+row, "M")
		}
		if view.Error != "" {
			canvas.Text(canvas.Width()-3, rowsTop+row, "!")
		}
		row++
	}
	if len(visible) == 0 {
		canvas.Text(2, rowsTop, "（没有符合当前筛选的字段）")
	}
	if state.editInput {
		selected, _ := state.selected()
		canvas.Text(2, canvas.Height()-5, "编辑 "+selected.Path+"（"+FieldTypeHint(selected.Path)+"）")
		canvas.Text(2, canvas.Height()-4, "> "+displayOr(state.editText, "输入值；<unset> 清除文件值"))
	}
	canvas.Text(2, canvas.Height()-3,
		"↑↓ 选择 · Enter 编辑 · / 搜索 · M 只看修改 · E 只看错误 · A 高级分组 · V 校验 · W 保存草稿 · Esc 返回")
	if state.message != "" && canvas.Height() > 6 {
		canvas.Text(2, canvas.Height()-2, sanitizeDisplay(state.message))
	}
}

// styles 预留给未来颜色支持；当前不改变内容。
func (s *fieldsScreenState) styles(_ string, _ FieldView) {}

func truncateFieldText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	return string(runes[:width])
}

// handleFieldsKey 处理字段编辑画面按键。
func (a *App) handleFieldsKey(ctx context.Context, key Key) error {
	state := a.fieldsUI
	if state == nil {
		a.screen = ScreenMain
		return nil
	}
	if state.preview {
		a.handleDraftPreviewKey(key, state)
		return nil
	}
	if state.editInput {
		a.handleFieldEditKey(key, state)
		return nil
	}
	if state.searchInput {
		a.handleFieldSearchKey(key, state)
		return nil
	}
	state.message = ""
	switch key.Kind {
	case KeyEsc:
		if state.draft != nil && state.draft.Digest() != digestOf(state.draft.BaseRaw()) {
			state.message = "草稿未保存（保存功能在步骤280接入）；已放弃本次编辑"
		}
		a.fieldsUI = nil
		a.screen = ScreenConfig
		a.openConfigScreen(ctx)
	case KeyUp:
		state.moveCursor(-1)
	case KeyDown, KeyTab:
		state.moveCursor(1)
	case KeyPageUp:
		state.moveCursor(-10)
	case KeyPageDown:
		state.moveCursor(10)
	case KeyEnter:
		selected, ok := state.selected()
		if !ok {
			return nil
		}
		if selected.Secret {
			state.message = "秘密字段不回显/不在此画面编辑；请使用受保护来源或导入导出流程"
			return nil
		}
		state.editInput = true
		state.editText = ""
		if selected.HasFile {
			state.editText = strings.Trim(selected.File, "\"")
		}
	case KeyRune:
		switch key.Rune {
		case '/':
			state.searchInput = true
			state.search = ""
		case 'm', 'M':
			state.onlyModified = !state.onlyModified
			state.clampCursor()
		case 'e', 'E':
			state.onlyErrors = !state.onlyErrors
			state.clampCursor()
		case 'a', 'A':
			state.showAdvanced = !state.showAdvanced
			state.clampCursor()
		case 'v', 'V':
			state.refreshViews()
			state.message = "校验完成：" + state.report.Summary
		case 'w', 'W':
			state.refreshViews()
			if !state.report.Valid {
				state.message = "草稿校验未通过，不能保存：" + state.report.Summary
				break
			}
			state.preview = true
			state.saveMessage = ""
		}
	}
	return nil
}

func (a *App) handleFieldSearchKey(key Key, state *fieldsScreenState) {
	switch key.Kind {
	case KeyEnter, KeyEsc:
		state.searchInput = false
		state.clampCursor()
	case KeyBackspace:
		runes := []rune(state.search)
		if len(runes) > 0 {
			state.search = string(runes[:len(runes)-1])
			state.clampCursor()
		}
	case KeyRune:
		state.search += string(key.Rune)
		state.clampCursor()
	}
}

func (a *App) handleFieldEditKey(key Key, state *fieldsScreenState) {
	switch key.Kind {
	case KeyEsc:
		state.editInput = false
		state.message = "已取消本次编辑"
	case KeyEnter:
		selected, ok := state.selected()
		if !ok {
			state.editInput = false
			return
		}
		input := strings.TrimSpace(state.editText)
		state.editInput = false
		switch input {
		case "<unset>":
			state.draft.Unset(selected.Path)
			state.refreshViews()
			state.message = "已把 " + selected.Path + " 的文件值清除（回退默认值）"
		case "<empty>":
			if err := state.draft.SetValue(selected.Path, ""); err != nil {
				state.message = "写入草稿失败：" + state.message
			} else {
				state.refreshViews()
				state.message = "已把 " + selected.Path + " 设为空字符串"
			}
		default:
			value, parseErr := ParseFieldInput(input)
			if parseErr != nil {
				state.message = parseErr.Error()
				return
			}
			if err := state.draft.SetValue(selected.Path, value); err != nil {
				state.message = "写入草稿失败：" + publicFileError(err)
				return
			}
			state.refreshViews()
			state.message = "已更新草稿：" + selected.Path + "（尚未写盘）"
		}
	case KeyBackspace:
		runes := []rune(state.editText)
		if len(runes) > 0 {
			state.editText = string(runes[:len(runes)-1])
		}
	case KeyRune:
		state.editText += string(key.Rune)
	}
}

// digestOf 计算原始文本摘要（用于未保存提示）。
func digestOf(raw []byte) string {
	draft, err := NewConfigDraft("", raw)
	if err != nil {
		return ""
	}
	return draft.Digest()
}

// readConfigRaw 读取配置文件原始文本（有界）。
func readConfigRaw(path string) ([]byte, error) {
	info, err := statFile(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("配置文件超过 %d 字节上限", MaxConfigBytes)
	}
	return readFileBytes(path)
}

// statFile/readFileBytes 是 os 调用的薄包装，便于测试替换（当前直接转发）。
var statFile = os.Stat
var readFileBytes = os.ReadFile

// fieldVisibleCount 返回可见字段数（供状态提示/测试）。
func (s *fieldsScreenState) fieldVisibleCount() int { return len(s.visibleViews()) }

var _ = context.Background

// renderDraftPreview 绘制 280 差异预览/保存确认画面。
func (a *App) renderDraftPreview(canvas *Canvas, top, bodyHeight int, state *fieldsScreenState) {
	canvas.Text(2, top, "草稿保存预览（文件保存与服务生效分别返回）")
	canvas.Text(2, top+1, "目标文件："+displayOr(a.configPath, "（未选择）"))
	canvas.Text(2, top+2, "校验："+displayOr(state.report.Summary, "未知"))
	line := top + 4
	if canvas.Height() <= 8 {
		return
	}
	modifiedCount := 0
	for _, view := range state.views {
		if !view.Modified {
			continue
		}
		modifiedCount++
		if line >= canvas.Height()-5 {
			break
		}
		canvas.Text(2, line, "· "+view.Path+"："+view.File+" → 草稿修改")
		line++
	}
	if modifiedCount == 0 {
		canvas.Text(2, line, "· 没有字段修改（显式保存仍会写文件/保留备份）")
	}
	overrides := overriddenFields()
	if len(overrides) > 0 {
		line++
		if line < canvas.Height()-5 {
			canvas.Text(2, line, "环境变量覆盖（文件保存后仍以环境变量为准）："+
				truncateFieldText(strings.Join(overrides, ", "), canvas.Width()-6))
		}
	}
	canvas.Text(2, canvas.Height()-3,
		"Enter 校验并原子保存 · Esc 取消；保存前保留最后有效备份，外部修改默认拒绝覆盖")
	if state.saveMessage != "" {
		canvas.Text(2, canvas.Height()-2, sanitizeDisplay(state.saveMessage))
	}
	_ = bodyHeight
}

// handleDraftPreviewKey 处理保存确认画面按键。
func (a *App) handleDraftPreviewKey(key Key, state *fieldsScreenState) {
	switch key.Kind {
	case KeyEsc:
		state.preview = false
		state.saveMessage = ""
	case KeyEnter:
		result, err := SaveConfigDraft(context.Background(), SaveRequest{
			Draft: state.draft, ConflictPolicy: ConflictFail, CreateBackup: true})
		if err != nil {
			state.saveMessage = "保存失败：" + publicFileError(err)
			return
		}
		state.lastSave = result
		state.preview = false
		if raw, readErr := readConfigRaw(state.draft.Path); readErr == nil {
			if reloaded, draftErr := NewConfigDraft(state.draft.Path, raw); draftErr == nil {
				state.draft = reloaded
			}
		}
		state.refreshViews()
		state.message = "已保存（摘要 " + shortDigest(result.FileDigest) + "）；生效：" +
			result.ReloadResult
		if result.BackupPath != "" {
			state.message += "；最后有效备份：" + result.BackupPath
		}
		if len(result.OverriddenFields) > 0 {
			state.message += "；环境变量覆盖：" + strings.Join(result.OverriddenFields, ",")
		}
	}
}
