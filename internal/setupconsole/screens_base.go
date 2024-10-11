package setupconsole

// WS3 本地维护画面的公共基座（步骤 286–291）。
//
// 画面只使用 Canvas 渲染、Key 处理；打开/关闭本地维护会话由 ws3ScreenBase 统一
// 负责：进入画面时按需打开，Esc 退出/关闭会话或出错时关闭。任何领域错误都显示
// 稳定中文说明并 fail-closed，不把失败画成成功。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ws3MenuEnabled 是菜单可用条件：只在实例可打开本地维护会话时进入。
// root 缺失时仍允许用户/审计等救援画面（创建 root 归 WS2 初始化画面）。
func ws3MenuEnabled(detection Detection) bool {
	switch detection.Kind {
	case StateReady, StateRootMissing:
		return true
	default:
		return false
	}
}

// ws3ScreenBase 是 WS3 画面共享状态。
type ws3ScreenBase struct {
	open     WS3SessionOpener
	session  WS3Session
	services *WS3Services
	// statusText 是成功/提示信息；errText 是失败信息；两者不同时长期存在。
	statusText string
	errText    string
}

// ensureSession 按需打开本地维护会话；失败时保留错误供渲染，不继续操作。
func (b *ws3ScreenBase) ensureSession(ctx context.Context) error {
	if b.services != nil {
		return nil
	}
	if b.open == nil {
		b.errText = "本地维护入口未装配"
		return errors.New(b.errText)
	}
	session, err := b.open(ctx)
	if err != nil {
		b.errText = ws3ErrorText(err)
		return err
	}
	b.session = session
	b.services = session.Services()
	if b.services == nil {
		b.errText = "本地维护会话没有可用的领域适配器"
		_ = session.Close(context.Background())
		b.session = nil
		return errors.New(b.errText)
	}
	return nil
}

// closeSession 关闭本地维护会话（幂等）。
func (b *ws3ScreenBase) closeSession() {
	if b.session == nil {
		return
	}
	_ = b.session.Close(context.Background())
	b.session = nil
	b.services = nil
}

// setStatus/setError 清理另一侧信息，避免成功与失败同时展示造成误导。
func (b *ws3ScreenBase) setStatus(text string) {
	b.statusText = strings.TrimSpace(text)
	b.errText = ""
}

func (b *ws3ScreenBase) setError(err error) {
	b.errText = ws3ErrorText(err)
	b.statusText = ""
}

// ws3ErrorText 把错误转为可展示中文；保留领域错误语义，脱敏内部细节。
func ws3ErrorText(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrLocalUnsupported):
		return strings.TrimPrefix(err.Error(), ErrLocalUnsupported.Error()+": ")
	case errors.Is(err, ErrLocalRuntimeUnavailable):
		return strings.TrimPrefix(err.Error(), ErrLocalRuntimeUnavailable.Error()+": ")
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "操作失败"
	}
	// 控制字符统一清洗，避免终端转义注入；Canvas.Text 也会再次清洗。
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, message)
	return message
}

// ws3CanvasArea 返回外部画面可用的正文区域（App 已画标题/状态/底栏）。
func ws3CanvasArea(canvas *Canvas) (left, top, width, height int) {
	left = 2
	top = 3
	width = canvas.Width() - 4
	height = canvas.Height() - top - 3
	if width < 10 {
		width = 10
	}
	if height < 3 {
		height = 3
	}
	return left, top, width, height
}

// ws3Truncate 按显示宽度截断（中文宽字符占 2 格；这里保守按 rune 截断后由
// Canvas 保证不越界，避免复杂宽度计算引入错位）。
func ws3Truncate(text string, maxRunes int) string {
	text = strings.ReplaceAll(text, "\t", " ")
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	if maxRunes <= 1 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-1]) + "…"
}

// ws3DrawMessage 绘制多行消息（状态/错误/不可用说明），带自动换行。
func ws3DrawMessage(canvas *Canvas, top, width int, prefix, text string) int {
	text = strings.TrimSpace(text)
	if text == "" {
		return top
	}
	lineWidth := width - len([]rune(prefix))
	if lineWidth < 10 {
		lineWidth = 10
	}
	runes := []rune(strings.ReplaceAll(text, "\r", " "))
	line := ""
	first := true
	flush := func() {
		displayPrefix := ""
		if first {
			displayPrefix = prefix
			first = false
		}
		canvas.Text(2, top, displayPrefix+line)
		top++
		line = ""
	}
	for _, r := range runes {
		if r == '\n' {
			flush()
			continue
		}
		line += string(r)
		if len([]rune(line)) >= lineWidth {
			flush()
		}
	}
	if line != "" {
		flush()
	}
	return top
}

// ws3DrawStatus 在正文顶部绘制状态/错误行，返回正文内容起始行。
func ws3DrawStatus(b *ws3ScreenBase, canvas *Canvas, top, width int) int {
	if b.errText != "" {
		top = ws3DrawMessage(canvas, top, width, "错误：", b.errText)
	}
	if b.statusText != "" {
		top = ws3DrawMessage(canvas, top, width, "提示：", b.statusText)
	}
	if b.errText != "" || b.statusText != "" {
		top++
	}
	return top
}

// ws3FormState 是简单文本表单：label/value 列表、焦点与掩码输入。
type ws3FormState struct {
	title   string
	labels  []string
	values  []string
	secret  []bool
	focus   int
	help    string
	errText string
}

func newWS3Form(title string, labels []string, secret []bool, help string) *ws3FormState {
	return &ws3FormState{title: title, labels: append([]string(nil), labels...),
		values: make([]string, len(labels)), secret: append([]bool(nil), secret...),
		help: help}
}

func (f *ws3FormState) setValue(index int, value string) {
	if index >= 0 && index < len(f.values) {
		f.values[index] = value
	}
}

// handleKey 处理编辑按键；返回 submitted=true 表示 Enter 提交（调用方校验）。
func (f *ws3FormState) handleKey(key Key) (submitted, cancelled bool) {
	switch key.Kind {
	case KeyEsc:
		return false, true
	case KeyTab, KeyDown:
		if len(f.values) > 0 {
			f.focus = (f.focus + 1) % len(f.values)
		}
		return false, false
	case KeyUp:
		if len(f.values) > 0 {
			f.focus = (f.focus - 1 + len(f.values)) % len(f.values)
		}
		return false, false
	case KeyBackspace:
		if f.focus < len(f.values) && len(f.values[f.focus]) > 0 {
			runes := []rune(f.values[f.focus])
			f.values[f.focus] = string(runes[:len(runes)-1])
		}
		return false, false
	case KeyEnter:
		return true, false
	case KeyRune:
		if f.focus < len(f.values) && key.Rune != 0 {
			f.values[f.focus] += string(key.Rune)
		}
		return false, false
	default:
		return false, false
	}
}

// draw 渲染表单；values 在掩码字段只显示占位。
func (f *ws3FormState) draw(canvas *Canvas, top, width int) {
	canvas.Text(2, top, f.title)
	top += 2
	for index, label := range f.labels {
		marker := "  "
		if index == f.focus {
			marker = "> "
		}
		value := ""
		if index < len(f.values) {
			value = f.values[index]
			if index < len(f.secret) && f.secret[index] && value != "" {
				value = strings.Repeat("*", len([]rune(value)))
			}
		}
		canvas.Text(2, top, marker+label+"："+ws3Truncate(value, maxInt(width-20, 8)))
		top++
	}
	if f.errText != "" {
		top = ws3DrawMessage(canvas, top+1, width, "错误：", f.errText)
	}
	if f.help != "" {
		top++
		ws3DrawMessage(canvas, top, width, "", f.help)
	}
}

func (f *ws3FormState) value(index int) string {
	if index < 0 || index >= len(f.values) {
		return ""
	}
	return strings.TrimSpace(f.values[index])
}

// ws3ConfirmState 是危险操作确认（展示目标与影响，Enter=确认，Esc=取消）。
type ws3ConfirmState struct {
	title  string
	lines  []string
	danger bool
}

func (f *ws3FormState) reset(values ...string) {
	f.values = make([]string, len(f.labels))
	for index := range values {
		if index < len(f.values) {
			f.values[index] = values[index]
		}
	}
	f.focus = 0
	f.errText = ""
}

// ws3ConfirmAction 描述一次需确认的危险动作；confirmAction 显示并等待确认。
type ws3ConfirmAction struct {
	title   string
	details []string
	// execute 返回提示文本与错误；执行前已展示真实目标与影响。
	execute func(ctx context.Context) (string, error)
}

// ws3RenderConfirm 渲染确认画面。
func ws3RenderConfirm(canvas *Canvas, top, width int, title string, details []string) {
	canvas.Text(2, top, title)
	top += 2
	for _, line := range details {
		top = ws3DrawMessage(canvas, top, width, "  ", line)
	}
	top++
	canvas.Text(2, top, "Enter 确认执行 · Esc 取消")
}

// ws3ParseTime 解析日期/时间输入：
//   - 空字符串返回 nil（表示该端永久有效/清除）；
//   - "YYYY-MM-DD" 按 UTC 当日 00:00；
//   - RFC3339 原样解析；
//   - "now" 返回当前 UTC 时间。
func ws3ParseTime(value string, now time.Time) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.EqualFold(value, "now") {
		parsed := now.UTC().Truncate(time.Second)
		return &parsed, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		utc := parsed.UTC()
		return &utc, nil
	}
	if parsed, err := time.ParseInLocation("2006-01-02", value, time.UTC); err == nil {
		return &parsed, nil
	}
	return nil, fmt.Errorf("时间格式无效：%q（支持 YYYY-MM-DD、RFC3339 或 now）", value)
}

// ws3FormatTime 格式化时间；零值显示“—”。
func ws3FormatTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04:05Z")
}

// ws3BoolLabel 把状态布尔转为中文。
func ws3BoolLabel(enabled bool) string {
	if enabled {
		return "启用"
	}
	return "停用"
}

// minInt 返回较小值；WS3 screens 共用，避免各文件重复定义。
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
