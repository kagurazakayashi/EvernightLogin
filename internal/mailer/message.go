package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"strings"
	"time"
)

// Header 是一条附加邮件头部；值在写入前会被安全检查。
type Header struct {
	Name  string
	Value string
}

// Message 是一封待发送邮件。From/To 是校验后的地址；Subject 是被信任代码提供的
// 主题模板渲染结果；TextBody 是纯文本正文（渲染后的模板输出）。
//
// 注意：本类型只接受纯文本正文，不提供 HTML，避免引入未转义 HTML 注入面；
// 需要富文本的后续步骤必须单独设计严格的 HTML 转义与 Content-Type 策略。
type Message struct {
	// From 是发件地址（信封与头部一致，不支持 Sender/Reply-To 伪造）。
	From Address
	// To 是收件人列表；至少一个，最多 MaxRecipientsPerMessage 个。
	To []Address
	// Subject 是主题原文（可包含非 ASCII，写入时 RFC 2047 编码）。
	Subject string
	// TextBody 是纯文本正文。
	TextBody string
	// Headers 是可选附加头部（例如 X-Request-ID）；名称必须是合法 token。
	Headers []Header
}

// Validate 校验消息结构、地址、头部与大小。
func (m Message) Validate() error {
	if m.From.Spec == "" {
		return fmt.Errorf("%w: 缺少发件地址", ErrInvalidMessage)
	}
	if err := validateAddrSpec(m.From.Spec); err != nil {
		return fmt.Errorf("%w: 发件地址: %v", ErrInvalidMessage, err)
	}
	if len(m.To) == 0 {
		return fmt.Errorf("%w: 缺少收件人", ErrInvalidMessage)
	}
	if len(m.To) > MaxRecipientsPerMessage {
		return fmt.Errorf("%w: 收件人超过 %d 个", ErrInvalidMessage, MaxRecipientsPerMessage)
	}
	for _, to := range m.To {
		if err := validateAddrSpec(to.Spec); err != nil {
			return fmt.Errorf("%w: 收件地址: %v", ErrInvalidMessage, err)
		}
	}
	if len(m.Subject) > MaxSubjectRunes {
		return fmt.Errorf("%w: 主题超过 %d 个字符", ErrInvalidMessage, MaxSubjectRunes)
	}
	if _, err := SanitizeHeaderValue("Subject", m.Subject); err != nil {
		return err
	}
	if len(m.TextBody) > MaxBodyBytes {
		return fmt.Errorf("%w: 正文超过 %d 字节", ErrInvalidMessage, MaxBodyBytes)
	}
	for _, h := range m.Headers {
		if !validHeaderName(h.Name) {
			return fmt.Errorf("%w: 头部名称 %q 非法", ErrInvalidMessage, h.Name)
		}
		if _, err := SanitizeHeaderValue(h.Name, h.Value); err != nil {
			return err
		}
	}
	return nil
}

// validHeaderName 检查 RFC 5322 field-name：可见 ASCII 且不含冒号与空白。
func validHeaderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r > 0x7e || r == ':' {
			return false
		}
	}
	return true
}

// Bytes 构建可直接交给 SMTP DATA 的完整邮件字节（CRLF 行尾、头部已防注入）。
// 正文使用 base64 传输编码，避免行长度、非 ASCII 与引号转义问题。
func (m Message) Bytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	subject, err := SanitizeHeaderValue("Subject", m.Subject)
	if err != nil {
		return nil, err
	}
	messageID, err := newMessageID(m.From.Spec)
	if err != nil {
		return nil, err
	}

	var header bytes.Buffer
	writeHeader := func(name, value string) {
		header.WriteString(name)
		header.WriteString(": ")
		header.WriteString(value)
		header.WriteString("\r\n")
	}
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("From", "<"+m.From.Spec+">")

	recipients := make([]string, 0, len(m.To))
	for _, to := range m.To {
		recipients = append(recipients, "<"+to.Spec+">")
	}
	writeHeader("To", strings.Join(recipients, ", "))
	writeHeader("Subject", mime.QEncoding.Encode("UTF-8", subject))
	writeHeader("Message-ID", messageID)
	writeHeader("MIME-Version", "1.0")
	writeHeader("Content-Type", "text/plain; charset=UTF-8")
	writeHeader("Content-Transfer-Encoding", "base64")
	for _, h := range m.Headers {
		safe, err := SanitizeHeaderValue(h.Name, h.Value)
		if err != nil {
			return nil, err
		}
		writeHeader(h.Name, safe)
	}
	header.WriteString("\r\n")

	var body bytes.Buffer
	encoded := base64.StdEncoding.EncodeToString([]byte(normalizeCRLF(m.TextBody)))
	for len(encoded) > 76 {
		body.WriteString(encoded[:76])
		body.WriteString("\r\n")
		encoded = encoded[76:]
	}
	if encoded != "" {
		body.WriteString(encoded)
		body.WriteString("\r\n")
	}

	out := append(header.Bytes(), body.Bytes()...)
	if len(out) > MaxBodyBytes+8*1024 {
		return nil, fmt.Errorf("%w: 组装后的邮件超过大小上限", ErrInvalidMessage)
	}
	return out, nil
}

// normalizeCRLF 把任意换行统一为 CRLF（先统一为 LF，再转 CRLF），避免正文里的
// 裸 CR 被解释为头部结束或行结束。
func normalizeCRLF(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.ReplaceAll(text, "\n", "\r\n")
}

// newMessageID 生成 <随机@发件域> 形式的 Message-ID。
func newMessageID(fromSpec string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("mailer: 生成 Message-ID 失败: %w", err)
	}
	domain := "localhost"
	if at := strings.LastIndexByte(fromSpec, '@'); at >= 0 && at < len(fromSpec)-1 {
		domain = fromSpec[at+1:]
	}
	return "<" + hex.EncodeToString(buffer) + "@" + domain + ">", nil
}
