package testmail

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Header 是一个消息头部字段（已展开折行，保留原始名称大小写与值的原文）。
type Header struct {
	Name  string
	Value string
}

// Message 是一封被本地捕获的邮件。
//
// EnvelopeFrom/EnvelopeTo 是 SMTP 信封（MAIL FROM / RCPT TO）的地址，可能与
// 头部中的 From/To 不同；Data 是按 CRLF 行尾原样保存的完整消息字节（点填充已
// 还原），不包含 DATA 结束标记与邮件正文之后的任何内容。头部解析采用"尽力而为"
// 策略：格式异常的头部行被忽略，不因此丢弃整封邮件。
type Message struct {
	// ID 是服务内自增的消息编号，从 1 开始；仅用于诊断与日志。
	ID string
	// ReceivedAt 是服务端完成 DATA 接收的时间（UTC）。
	ReceivedAt time.Time
	// RemoteAddr 是客户端地址（host:port）。
	RemoteAddr string
	// EnvelopeFrom 是 MAIL FROM 地址；空字符串表示空发送者（退信语义）。
	EnvelopeFrom string
	// EnvelopeTo 是全部 RCPT TO 地址，按接收顺序。
	EnvelopeTo []string
	// Data 是完整原始消息字节（CRLF 行尾，点填充已还原）。
	Data []byte
	// Subject 是首个 Subject 头部的尽力解码结果（RFC 2047）；无法解码时为原文。
	Subject string
	// Date 是首个 Date 头部的解析结果；缺失或无法解析时为零值。
	Date time.Time
	// Headers 是全部头部字段，按出现顺序，折行已展开。
	Headers []Header
	// AuthUser 是会话认证用户名；未认证时为空字符串。
	AuthUser string
	// TLS 表示该消息是否经 STARTTLS 加密的连接接收。
	TLS bool

	// bodyOffset 是 Data 中正文起始位置，由解析器在接收时设置。
	bodyOffset int
}

// Body 返回消息正文（头部与正文之间空行之后的部分）。返回切片与 Data 共用底层
// 数组，调用方应视为只读。
func (m Message) Body() []byte {
	if m.bodyOffset <= 0 || m.bodyOffset > len(m.Data) {
		return nil
	}
	return m.Data[m.bodyOffset:]
}

// HeaderBlock 返回原始头部块，包含头部与正文之间的空行（行尾 CRLF）。返回切片与
// Data 共用底层数组，调用方应视为只读；IMAP 的 BODY[HEADER] 与 POP3 的 TOP 直接
// 使用该结果，保证与 SMTP 捕获的原始字节一致。
func (m Message) HeaderBlock() []byte {
	if m.bodyOffset <= 0 || m.bodyOffset > len(m.Data) {
		return nil
	}
	return m.Data[:m.bodyOffset]
}

// Header 返回首个名称不区分大小写匹配的头部值。
func (m Message) Header(name string) (string, bool) {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// HeaderValues 返回所有名称不区分大小写匹配的头部值（如 Received、To）。
func (m Message) HeaderValues(name string) []string {
	var values []string
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			values = append(values, h.Value)
		}
	}
	return values
}

// Query 是消息查询条件。零值字段表示不过滤；多个字段同时给出时按 AND 组合。
type Query struct {
	// To 按信封收件人精确匹配（不区分大小写）。消息有多个收件人时任一匹配即可。
	To string
	// From 按信封发送人精确匹配（不区分大小写）。
	From string
	// Subject 按解码后主题的子串匹配（不区分大小写）。
	Subject string
	// Since 是接收时间下界（含）。
	Since time.Time
	// Until 是接收时间上界（不含）。
	Until time.Time
	// Limit 限制返回条数（按接收顺序），0 表示不限制。
	Limit int
}

// matches 判断消息是否满足查询条件。
func (q Query) matches(m *Message) bool {
	if q.To != "" {
		found := false
		for _, to := range m.EnvelopeTo {
			if strings.EqualFold(to, q.To) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if q.From != "" && !strings.EqualFold(m.EnvelopeFrom, q.From) {
		return false
	}
	if q.Subject != "" && !strings.Contains(strings.ToLower(m.Subject), strings.ToLower(q.Subject)) {
		return false
	}
	if !q.Since.IsZero() && m.ReceivedAt.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !m.ReceivedAt.Before(q.Until) {
		return false
	}
	return true
}

// store 是并发安全、有容量上限的内存消息仓库。容量耗尽时新消息按 ErrStoreFull
// 拒绝而不是静默丢弃，测试能明确观察到限制是否生效。
type store struct {
	mu   sync.Mutex
	max  int
	seq  uint64
	msgs []Message
}

func newStore(max int) *store {
	return &store{max: max}
}

// add 保存消息并分配编号；容量已满时返回 ErrStoreFull。
func (st *store) add(m Message) (Message, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.msgs) >= st.max {
		return Message{}, ErrStoreFull
	}
	st.seq++
	m.ID = fmt.Sprintf("%d", st.seq)
	if m.ReceivedAt.IsZero() {
		m.ReceivedAt = time.Now().UTC()
	}
	st.msgs = append(st.msgs, m)
	return m, nil
}

// count 返回当前保留的消息数。
func (st *store) count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.msgs)
}

// nextSeq 返回下一个将被分配的消息编号；IMAP 的 UIDNEXT 使用该值。编号在同一
// 服务器实例内单调递增且不会复用（Clear/Take 也不会回退），因此 UID 空间稳定。
func (st *store) nextSeq() uint64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.seq + 1
}

// query 返回匹配消息的只读快照。返回的消息与仓库共用 Data 底层数组，调用方不应
// 修改其内容。
func (st *store) query(q Query) []Message {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Message
	for i := range st.msgs {
		if !q.matches(&st.msgs[i]) {
			continue
		}
		out = append(out, st.msgs[i])
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out
}

// take 取出（移除并返回）匹配消息，释放的容量可供后续消息使用。
func (st *store) take(q Query) []Message {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Message
	kept := st.msgs[:0]
	for i := range st.msgs {
		if q.matches(&st.msgs[i]) {
			out = append(out, st.msgs[i])
			if q.Limit > 0 && len(out) >= q.Limit {
				kept = append(kept, st.msgs[i+1:]...)
				break
			}
			continue
		}
		kept = append(kept, st.msgs[i])
	}
	st.msgs = kept
	return out
}

// clear 清空全部消息并返回清空数量。
func (st *store) clear() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := len(st.msgs)
	st.msgs = nil
	return n
}
