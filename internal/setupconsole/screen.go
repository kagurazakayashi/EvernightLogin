package setupconsole

// 全屏画布（步骤277 + WS5 G2/G3 修复）。
//
// 显示宽度按终端列计算（东亚宽字符/emoji 占 2 列，组合字符与既有字符合并占 0 列）：
//   - Text 以“显示列”定位，宽字符占两个单元格、组合字符附加到前一字符；
//   - 单行单元格内的 \n/\r/\t 一律转空格，避免破坏帧布局；
//   - Center/HLine/Box/截断均按显示宽度计算；
//   - Render 跳过宽字符的占位单元格，末尾按显示宽度裁剪空格。

import (
	"strings"
	"unicode"
)

// Canvas 是固定尺寸（显示列×行）的字符画布。
type Canvas struct {
	width  int
	height int
	// cells[row][column] 是单元格文本；宽字符占第 1 格，第 2 格为空串占位。
	cells [][]string
}

// NewCanvas 创建至少 20x6 的画布。
func NewCanvas(width, height int) *Canvas {
	if width < 20 {
		width = 20
	}
	if height < 6 {
		height = 6
	}
	cells := make([][]string, height)
	for row := range cells {
		cells[row] = make([]string, width)
	}
	return &Canvas{width: width, height: height, cells: cells}
}

// Width/Height 返回画布显示列/行。
func (c *Canvas) Width() int  { return c.width }
func (c *Canvas) Height() int { return c.height }

// Clear 用空格填充全部单元格。
func (c *Canvas) Clear() {
	for row := range c.cells {
		for column := range c.cells[row] {
			c.cells[row][column] = " "
		}
	}
}

// Text 在显示列 x、行 y 写单行文本；越界安全截断。
func (c *Canvas) Text(x, y int, text string) {
	if y < 0 || y >= c.height {
		return
	}
	clean := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(text)
	column := x
	runes := []rune(clean)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if character < 0x20 || character == 0x7f ||
			(character >= 0x80 && character <= 0x9f) { // C1 控制字符（SEC INFO-2）
			character = ' '
		}
		width := runeDisplayWidth(character)
		if width == 0 {
			// 组合字符附加到前一个单元格，不拆开。
			if column-1 >= 0 && column-1 < c.width {
				previous := c.cells[y][column-1]
				if previous == "" && column-2 >= 0 {
					previous = c.cells[y][column-2]
					c.cells[y][column-2] = previous + string(character)
				} else {
					c.cells[y][column-1] = previous + string(character)
				}
			}
			continue
		}
		if column < 0 {
			column += width
			continue
		}
		if column >= c.width {
			break
		}
		if width == 2 && column+1 >= c.width {
			break // 宽字符不能跨右边界拆开。
		}
		c.cells[y][column] = string(character)
		if width == 2 {
			c.cells[y][column+1] = ""
		}
		column += width
	}
}

// Center 在指定行按显示宽度居中写文本。
func (c *Canvas) Center(y int, text string) {
	width := displayWidth(text)
	start := (c.width - width) / 2
	if start < 0 {
		start = 0
	}
	c.Text(start, y, text)
}

// HLine 在 y 行画横线。
func (c *Canvas) HLine(y int, left, right rune) {
	if y < 0 || y >= c.height {
		return
	}
	for column := 0; column < c.width; column++ {
		c.cells[y][column] = "─"
	}
	if left != 0 {
		c.cells[y][0] = string(left)
	}
	if right != 0 {
		c.cells[y][c.width-1] = string(right)
	}
}

// Box 画矩形边框并在顶部写标题。
func (c *Canvas) Box(x, y, width, height int, title string) {
	if width < 4 || height < 3 {
		return
	}
	for row := 0; row < height; row++ {
		for column := 0; column < width; column++ {
			character := " "
			switch {
			case row == 0 && column == 0:
				character = "┌"
			case row == 0 && column == width-1:
				character = "┐"
			case row == height-1 && column == 0:
				character = "└"
			case row == height-1 && column == width-1:
				character = "┘"
			case row == 0 || row == height-1:
				character = "─"
			case column == 0 || column == width-1:
				character = "│"
			}
			drawY, drawX := y+row, x+column
			if drawY < 0 || drawY >= c.height || drawX < 0 || drawX >= c.width {
				continue
			}
			c.cells[drawY][drawX] = character
		}
	}
	if title != "" {
		c.Text(x+2, y, " "+title+" ")
	}
}

// Render 生成整帧字符串：光标归位、逐行清行输出。
func (c *Canvas) Render() string {
	var builder strings.Builder
	builder.Grow(c.width * c.height)
	builder.WriteString("\x1b[H")
	for row := 0; row < c.height; row++ {
		builder.WriteString("\x1b[2K")
		builder.WriteString(c.rowText(row))
		if row == c.height-1 {
			break
		}
		builder.WriteString("\r\n")
	}
	return builder.String()
}

// rowText 返回一行渲染文本（跳过宽字符占位，裁剪尾部空格）。
func (c *Canvas) rowText(row int) string {
	var builder strings.Builder
	for column := 0; column < c.width; column++ {
		cell := c.cells[row][column]
		if cell == "" {
			continue // 宽字符占位单元格，由前一个宽字符实际覆盖。
		}
		builder.WriteString(cell)
	}
	return strings.TrimRight(builder.String(), " ")
}

// runeDisplayWidth 返回字符的显示宽度（0/1/2）。
func runeDisplayWidth(character rune) int {
	if character == 0 {
		return 0
	}
	if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) ||
		unicode.Is(unicode.Cf, character) {
		return 0
	}
	if isWideRune(character) {
		return 2
	}
	return 1
}

// isWideRune 判断东亚宽字符/emoji 范围（保守覆盖常见范围）。
func isWideRune(character rune) bool {
	switch {
	case character >= 0x1100 && character <= 0x115f, // Hangul Jamo
		character >= 0x2e80 && character <= 0x303e, // CJK Radicals..Kangxi
		character >= 0x3041 && character <= 0x33ff, // Hiragana..CJK Compatibility
		character >= 0x3400 && character <= 0x4dbf, // CJK Ext A
		character >= 0x4e00 && character <= 0x9fff, // CJK Unified
		character >= 0xa000 && character <= 0xa4cf, // Yi
		character >= 0xac00 && character <= 0xd7a3, // Hangul Syllables
		character >= 0xf900 && character <= 0xfaff, // CJK Compatibility Ideographs
		character >= 0xfe30 && character <= 0xfe4f, // CJK Compatibility Forms
		character >= 0xff00 && character <= 0xff60, // Fullwidth Forms
		character >= 0xffe0 && character <= 0xffe6,
		character >= 0x1f300 && character <= 0x1f64f, // emoji
		character >= 0x1f900 && character <= 0x1f9ff,
		character >= 0x20000 && character <= 0x3fffd:
		return true
	}
	return false
}

// displayWidth 返回字符串显示宽度。
func displayWidth(text string) int {
	width := 0
	for _, character := range text {
		width += runeDisplayWidth(character)
	}
	return width
}
