package setupconsole

// 配置原文行编辑器（步骤278）。
//
// 目标：坏配置不能被自动覆盖，但必须能在控制台内做**局部文本修复**：
//   - 按原始行编辑（不解析后重写），因此未知字段/注释/顺序天然保留；
//   - 支持移动、插入字符、退格/删除、换行拆分/合并、插入/删除行；
//   - 只修改内存草稿，写盘由 278 的“另存为”/280 的正式保存动作显式调用；
//   - 所有行在渲染时清洗控制字符；编辑器不打印秘密值（文件本身只有来源引用）。

import "strings"

// lineEditor 是 UTF-8 行文本编辑器。
type lineEditor struct {
	lines  [][]rune
	cursor [2]int // [行, 列]
	scroll int
	dirty  bool
}

// newLineEditor 从原始文本构造编辑器。
func newLineEditor(raw []byte) *lineEditor {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	parts := strings.Split(text, "\n")
	// 末尾换行产生的空尾行保留（写回时恢复原始结构）。
	lines := make([][]rune, len(parts))
	for index, part := range parts {
		lines[index] = []rune(part)
	}
	return &lineEditor{lines: lines}
}

// Bytes 按行重新组装文本（保留行尾结构：内部行之间 \n）。
func (e *lineEditor) Bytes() []byte {
	if e == nil {
		return nil
	}
	parts := make([]string, len(e.lines))
	for index, line := range e.lines {
		parts[index] = string(line)
	}
	return []byte(strings.Join(parts, "\n"))
}

// Dirty 表示是否发生过修改。
func (e *lineEditor) Dirty() bool { return e != nil && e.dirty }

// LineCount 返回行数。
func (e *lineEditor) LineCount() int {
	if e == nil {
		return 0
	}
	return len(e.lines)
}

// Cursor 返回当前行列（0 基）。
func (e *lineEditor) Cursor() (line, column int) {
	if e == nil {
		return 0, 0
	}
	return e.cursor[0], e.cursor[1]
}

// SetCursor 设置光标（越界自动裁剪）；scroll 由界面读取以保持可见。
func (e *lineEditor) SetCursor(line, column int) {
	if e == nil {
		return
	}
	if line < 0 {
		line = 0
	}
	if line >= len(e.lines) {
		line = len(e.lines) - 1
	}
	if column < 0 {
		column = 0
	}
	if column > len(e.lines[line]) {
		column = len(e.lines[line])
	}
	e.cursor = [2]int{line, column}
}

// MoveLine 上下移动光标行（保持列尽量不变）。
func (e *lineEditor) MoveLine(delta int) {
	if e == nil {
		return
	}
	line := e.cursor[0] + delta
	e.SetCursor(line, e.cursor[1])
}

// MoveColumn 左右移动光标列；跨行按文档顺序（右移到行尾后进入下一行行首）。
func (e *lineEditor) MoveColumn(delta int) {
	if e == nil {
		return
	}
	line, column := e.cursor[0], e.cursor[1]
	if delta > 0 {
		if column < len(e.lines[line]) {
			column++
		} else if line < len(e.lines)-1 {
			line++
			column = 0
		}
	} else if delta < 0 {
		if column > 0 {
			column--
		} else if line > 0 {
			line--
			column = len(e.lines[line])
		}
	}
	e.cursor = [2]int{line, column}
}

// InsertRune 在光标处插入字符并右移光标。
func (e *lineEditor) InsertRune(value rune) {
	if e == nil {
		return
	}
	line, column := e.cursor[0], e.cursor[1]
	current := e.lines[line]
	updated := make([]rune, 0, len(current)+1)
	updated = append(updated, current[:column]...)
	updated = append(updated, value)
	updated = append(updated, current[column:]...)
	e.lines[line] = updated
	e.cursor[1] = column + 1
	e.dirty = true
}

// InsertText 插入一段文本（用于粘贴/制表符）；包含换行时拆分行。
func (e *lineEditor) InsertText(text string) {
	if e == nil {
		return
	}
	clean := strings.ReplaceAll(text, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	clean = sanitizeDisplay(clean)
	parts := strings.Split(clean, "\n")
	for index, part := range parts {
		if index > 0 {
			e.SplitLine()
		}
		for _, character := range part {
			e.InsertRune(character)
		}
	}
}

// Backspace 删除光标前一个字符；行首时与上一行合并。
func (e *lineEditor) Backspace() {
	if e == nil {
		return
	}
	line, column := e.cursor[0], e.cursor[1]
	if column > 0 {
		e.lines[line] = append(e.lines[line][:column-1], e.lines[line][column:]...)
		e.cursor[1] = column - 1
		e.dirty = true
		return
	}
	if line > 0 {
		previousLength := len(e.lines[line-1])
		merged := append(append([]rune{}, e.lines[line-1]...), e.lines[line]...)
		e.lines[line-1] = merged
		e.lines = append(e.lines[:line], e.lines[line+1:]...)
		e.cursor = [2]int{line - 1, previousLength}
		e.dirty = true
	}
}

// Delete 删除光标处字符；行尾时与下一行合并。
func (e *lineEditor) Delete() {
	if e == nil {
		return
	}
	line, column := e.cursor[0], e.cursor[1]
	if column < len(e.lines[line]) {
		e.lines[line] = append(e.lines[line][:column], e.lines[line][column+1:]...)
		e.dirty = true
		return
	}
	if line < len(e.lines)-1 {
		e.lines[line] = append(e.lines[line], e.lines[line+1]...)
		e.lines = append(e.lines[:line+1], e.lines[line+2:]...)
		e.dirty = true
	}
}

// SplitLine 在光标处把当前行拆成两行（Enter）。
func (e *lineEditor) SplitLine() {
	if e == nil {
		return
	}
	line, column := e.cursor[0], e.cursor[1]
	current := e.lines[line]
	head := append([]rune{}, current[:column]...)
	tail := append([]rune{}, current[column:]...)
	e.lines[line] = head
	updated := make([][]rune, 0, len(e.lines)+1)
	updated = append(updated, e.lines[:line+1]...)
	updated = append(updated, tail)
	updated = append(updated, e.lines[line+1:]...)
	e.lines = updated
	e.cursor = [2]int{line + 1, 0}
	e.dirty = true
}

// InsertLineAfter 在当前行后插入空行并把光标移到新行。
func (e *lineEditor) InsertLineAfter() {
	if e == nil {
		return
	}
	line := e.cursor[0]
	empty := make([]rune, 0, 1)
	updated := make([][]rune, 0, len(e.lines)+1)
	updated = append(updated, e.lines[:line+1]...)
	updated = append(updated, empty)
	updated = append(updated, e.lines[line+1:]...)
	e.lines = updated
	e.cursor = [2]int{line + 1, 0}
	e.dirty = true
}

// DeleteLine 删除当前行（至少保留一行）。
func (e *lineEditor) DeleteLine() {
	if e == nil || len(e.lines) <= 1 {
		return
	}
	line := e.cursor[0]
	e.lines = append(e.lines[:line], e.lines[line+1:]...)
	if line >= len(e.lines) {
		line = len(e.lines) - 1
	}
	e.cursor = [2]int{line, 0}
	e.dirty = true
}

// Line 返回指定行文本（清洗后用于显示）。
func (e *lineEditor) Line(line int) string {
	if e == nil || line < 0 || line >= len(e.lines) {
		return ""
	}
	return sanitizeDisplay(string(e.lines[line]))
}

// VisibleLines 返回 [start, end) 范围的可见行文本与光标所在可见行。
func (e *lineEditor) VisibleLines(height int) (start, end int) {
	if e == nil || height <= 0 {
		return 0, 0
	}
	line := e.cursor[0]
	if line < e.scroll {
		e.scroll = line
	}
	if line >= e.scroll+height {
		e.scroll = line - height + 1
	}
	if e.scroll < 0 {
		e.scroll = 0
	}
	start = e.scroll
	end = start + height
	if end > len(e.lines) {
		end = len(e.lines)
	}
	return start, end
}
