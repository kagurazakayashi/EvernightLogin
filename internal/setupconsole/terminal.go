package setupconsole

// 终端抽象与真实 ANSI 终端实现（步骤277 + WS5 G4/G5/G6 修复）。
//
// 设计目标：
//   - App/界面逻辑只依赖 Terminal 接口，测试用脚本化内存终端覆盖按键/渲染/退出恢复；
//   - 真实实现使用 x/term 进入原始模式，切到备用屏幕并隐藏光标，退出时严格恢复终端
//     状态（异常退出路径也要恢复）；非 TTY 由 cmd 层走简化文本模式；
//   - 按键解析覆盖方向键/Enter/Esc/Tab/Backspace/Home/End/PageUp/PageDown/F1/Ctrl-C/
//     Ctrl-S/Ctrl-O，识别并消费 bracketed paste；
//   - ESC 序列严格解析：不吞下不属于序列的后续字节（ESC 后跟普通字符按 Esc 返回，
//     该字符由下一次 ReadKey 正常返回）；
//   - 非法 UTF-8 单字节返回 KeyUnknown 并被消费，不把 UI 误判为输入结束；
//   - 渲染成整帧重绘，ANSI 控制序列只由渲染器生成，数据文本先清洗。

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// KeyKind 是规范化的按键类别。
type KeyKind int

const (
	KeyRune KeyKind = iota
	KeyEnter
	KeyEsc
	KeyTab
	KeyBackspace
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPageUp
	KeyPageDown
	KeyF1
	KeyCtrlC
	KeyCtrlD
	KeyCtrlS
	KeyCtrlO
	KeyPaste
	KeyUnknown
)

// Key 是一次按键事件；KeyPaste 时 Text 是粘贴内容（调用方需清洗后按文本处理）。
type Key struct {
	Kind KeyKind
	Rune rune
	Text string
}

// Terminal 是控制台依赖的最小终端能力。
type Terminal interface {
	Init() error
	Close() error
	Size() (width, height int)
	Write(frame string) error
	ReadKey() (Key, error)
}

// ANSITerminal 是基于 stdin/stdout 的真实终端实现。
type ANSITerminal struct {
	rawOut   io.Writer
	inFd     uintptr
	hasFd    bool
	state    *term.State
	reader   *bufio.Reader
	restored bool
}

// NewANSITerminal 用输入/输出流构造终端；in 必须实现 Fd() 才能进入原始模式。
func NewANSITerminal(in io.Reader, out io.Writer) *ANSITerminal {
	terminal := &ANSITerminal{rawOut: out, reader: bufio.NewReader(in)}
	if fdSource, ok := in.(interface{ Fd() uintptr }); ok {
		terminal.inFd = fdSource.Fd()
		terminal.hasFd = true
	}
	return terminal
}

// Init 进入原始模式并切换到备用屏幕。
func (t *ANSITerminal) Init() error {
	if t == nil || t.rawOut == nil {
		return errors.New("终端输出不可用")
	}
	if t.hasFd {
		state, err := term.MakeRaw(int(t.inFd))
		if err != nil {
			return fmt.Errorf("进入终端原始模式失败: %w", err)
		}
		t.state = state
	}
	t.restored = false
	if _, err := io.WriteString(t.rawOut, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H"); err != nil {
		_ = t.Close()
		return err
	}
	return nil
}

// Close 恢复终端；幂等。
func (t *ANSITerminal) Close() error {
	if t == nil || t.restored {
		return nil
	}
	t.restored = true
	var errs []error
	if t.rawOut != nil {
		if _, err := io.WriteString(t.rawOut, "\x1b[?25h\x1b[?1049l"); err != nil {
			errs = append(errs, err)
		}
	}
	if t.state != nil && t.hasFd {
		if err := term.Restore(int(t.inFd), t.state); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Size 返回终端字符尺寸；非 TTY 或查询失败时使用 80x24 兜底。
func (t *ANSITerminal) Size() (width, height int) {
	if t != nil && t.hasFd {
		if w, h, err := term.GetSize(int(t.inFd)); err == nil && w >= 20 && h >= 6 {
			return w, h
		}
	}
	return 80, 24
}

// Write 输出一帧。
func (t *ANSITerminal) Write(frame string) error {
	if t == nil || t.rawOut == nil {
		return errors.New("终端输出不可用")
	}
	_, err := io.WriteString(t.rawOut, frame)
	return err
}

// ReadKey 解析一次按键。
func (t *ANSITerminal) ReadKey() (Key, error) {
	if t == nil || t.reader == nil {
		return Key{}, io.EOF
	}
	first, err := t.reader.ReadByte()
	if err != nil {
		return Key{}, err
	}
	switch first {
	case '\r', '\n':
		return Key{Kind: KeyEnter}, nil
	case '\t':
		return Key{Kind: KeyTab}, nil
	case 0x7f, 0x08:
		return Key{Kind: KeyBackspace}, nil
	case 0x03:
		return Key{Kind: KeyCtrlC}, nil
	case 0x04:
		return Key{Kind: KeyCtrlD}, nil
	case 0x13:
		return Key{Kind: KeyCtrlS}, nil
	case 0x0f:
		return Key{Kind: KeyCtrlO}, nil
	case 0x1b:
		return t.readEscapeKey()
	}
	if first >= 0x80 {
		// 非法/折叠 UTF-8：消费该起始字节并返回 KeyUnknown，不让 UI 误退出。
		if err := t.reader.UnreadByte(); err != nil {
			return Key{Kind: KeyUnknown}, nil
		}
		character, size, readErr := t.reader.ReadRune()
		if readErr != nil {
			return Key{Kind: KeyUnknown}, nil
		}
		if character == utf8.RuneError && size <= 1 {
			return Key{Kind: KeyUnknown}, nil
		}
		return Key{Kind: KeyRune, Rune: character}, nil
	}
	if first < 0x20 {
		return Key{Kind: KeyUnknown}, nil
	}
	return Key{Kind: KeyRune, Rune: rune(first)}, nil
}

// readEscapeKey 解析 ESC 开头的按键：只有确属 CSI/SS3 序列才消费后续字节。
func (t *ANSITerminal) readEscapeKey() (Key, error) {
	if t.reader.Buffered() == 0 {
		return Key{Kind: KeyEsc}, nil
	}
	next, err := t.reader.Peek(1)
	if err != nil || len(next) == 0 {
		return Key{Kind: KeyEsc}, nil
	}
	switch next[0] {
	case '[':
		_, _ = t.reader.ReadByte() // 消费 '['
		return t.readCSI()
	case 'O':
		_, _ = t.reader.ReadByte() // 消费 'O'
		return t.readSS3()
	default:
		// ESC 后跟普通字符：按 Esc 返回，字符留给下一次读取（G5）。
		return Key{Kind: KeyEsc}, nil
	}
}

// readCSI 读取并解析 CSI 序列（ESC [ ... final）。
func (t *ANSITerminal) readCSI() (Key, error) {
	var params strings.Builder
	var final byte
	for {
		value, err := t.reader.ReadByte()
		if err != nil {
			return Key{Kind: KeyUnknown}, nil
		}
		if value >= 0x40 && value <= 0x7e {
			final = value
			break
		}
		if params.Len() > 16 {
			// 参数过长视为未知序列（仍消费到 final，避免污染后续输入）。
			continue
		}
		params.WriteByte(value)
	}
	parameter := params.String()
	if parameter == "200" && final == '~' {
		return t.readBracketedPaste()
	}
	switch final {
	case 'A':
		return Key{Kind: KeyUp}, nil
	case 'B':
		return Key{Kind: KeyDown}, nil
	case 'C':
		return Key{Kind: KeyRight}, nil
	case 'D':
		return Key{Kind: KeyLeft}, nil
	case 'H':
		return Key{Kind: KeyHome}, nil
	case 'F':
		return Key{Kind: KeyEnd}, nil
	case '~':
		switch parameter {
		case "1", "7":
			return Key{Kind: KeyHome}, nil
		case "4", "8":
			return Key{Kind: KeyEnd}, nil
		case "5":
			return Key{Kind: KeyPageUp}, nil
		case "6":
			return Key{Kind: KeyPageDown}, nil
		case "11":
			return Key{Kind: KeyF1}, nil
		}
	}
	return Key{Kind: KeyUnknown}, nil
}

// readSS3 读取并解析 SS3 序列（ESC O final）。
func (t *ANSITerminal) readSS3() (Key, error) {
	final, err := t.reader.ReadByte()
	if err != nil {
		return Key{Kind: KeyUnknown}, nil
	}
	switch final {
	case 'A':
		return Key{Kind: KeyUp}, nil
	case 'B':
		return Key{Kind: KeyDown}, nil
	case 'C':
		return Key{Kind: KeyRight}, nil
	case 'D':
		return Key{Kind: KeyLeft}, nil
	case 'H':
		return Key{Kind: KeyHome}, nil
	case 'F':
		return Key{Kind: KeyEnd}, nil
	case 'P':
		return Key{Kind: KeyF1}, nil
	}
	return Key{Kind: KeyUnknown}, nil
}

// readBracketedPaste 读取 ESC[200~ ... ESC[201~ 的粘贴内容（有界），返回 KeyPaste。
func (t *ANSITerminal) readBracketedPaste() (Key, error) {
	const maxPasteBytes = 64 << 10
	endMarker := []byte("\x1b[201~")
	buffer := make([]byte, 0, 256)
	window := make([]byte, 0, len(endMarker))
	for len(buffer) < maxPasteBytes {
		value, err := t.reader.ReadByte()
		if err != nil {
			// 粘贴未正常结束：丢弃已读内容，避免把半个序列当成普通按键。
			return Key{Kind: KeyPaste, Text: string(buffer)}, nil
		}
		buffer = append(buffer, value)
		window = append(window, value)
		if len(window) > len(endMarker) {
			window = window[1:]
		}
		if len(window) == len(endMarker) && string(window) == string(endMarker) {
			payload := buffer[:len(buffer)-len(endMarker)]
			return Key{Kind: KeyPaste, Text: string(payload)}, nil
		}
	}
	return Key{Kind: KeyPaste, Text: string(buffer)}, nil
}

// sanitizeDisplay 移除控制字符（除换行/制表），避免用户数据/日志操纵终端。
func sanitizeDisplay(text string) string {
	var builder strings.Builder
	for _, character := range text {
		switch {
		case character == '\n' || character == '\t':
			builder.WriteRune(character)
		case character < 0x20, character == 0x7f:
			builder.WriteRune(' ')
		case character >= 0x80 && character < 0xa0:
			builder.WriteRune(' ')
		default:
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
