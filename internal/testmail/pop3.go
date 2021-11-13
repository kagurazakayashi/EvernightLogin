package testmail

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// pop3State 是 POP3 会话状态（RFC 1939 的 AUTHORIZATION 与 TRANSACTION）。
type pop3State int

const (
	// pop3StateAuthorization 表示等待 USER/PASS 认证。
	pop3StateAuthorization pop3State = iota
	// pop3StateTransaction 表示已认证，可以读取邮件列表。
	pop3StateTransaction
)

// pop3Session 是单个 POP3 连接的状态。它只在所属 goroutine 中被访问，不需要加锁。
type pop3Session struct {
	srv        *Server
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	remote     string
	sessionID  uint64
	sessionEnd time.Time

	state        pop3State
	user         string
	pendingUser  string
	authAttempts int

	// msgs 是认证成功时按账户过滤后的收件箱快照；deleted 是仅限本会话的删除
	// 标记。POP3 的 DELE 在本测试服务器中不会真正删除共享内存仓库中的消息。
	msgs    []Message
	deleted []bool
}

// servePOP3 处理单个 POP3 连接：可选隐式 TLS 握手、发送问候语并进入命令循环。
func (s *Server) servePOP3(conn net.Conn) {
	sessionID := s.sessionSeq.Add(1)
	if s.pop3TLSConf != nil {
		tlsConn, err := s.wrapTLS(conn, s.pop3TLSConf)
		if err != nil {
			return
		}
		conn = tlsConn
	}
	ss := &pop3Session{
		srv:        s,
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
		remote:     conn.RemoteAddr().String(),
		sessionID:  sessionID,
		sessionEnd: time.Now().Add(s.opts.SessionTimeout),
	}
	ss.greet()
	ss.loop()
}

// greet 发送 POP3 问候语。应答文本保持 ASCII，避免严格客户端解析失败。
func (ss *pop3Session) greet() {
	_ = ss.okLine(pop3ResponseText(ss.srv.opts.Hostname) + " POP3 test server ready")
}

// loop 读取并分发命令，直到客户端退出、连接出错或会话时长耗尽。
func (ss *pop3Session) loop() {
	for {
		line, err := ss.readLine()
		if err != nil {
			switch {
			case errors.Is(err, errLineTooLong):
				_ = ss.errLine("command line too long")
			case isTimeout(err):
				_ = ss.errLine("idle timeout, closing connection")
			}
			return
		}
		if !ss.handle(line) {
			return
		}
	}
}

// handle 处理一条 POP3 命令；返回 false 表示结束会话。
func (ss *pop3Session) handle(line string) bool {
	verb, arg := splitFirstWord(line)
	if verb == "" {
		return ss.errLine("empty command")
	}
	switch strings.ToUpper(verb) {
	case "CAPA":
		return ss.handleCapa()
	case "USER":
		return ss.handleUser(arg)
	case "PASS":
		return ss.handlePass(arg)
	case "QUIT":
		_ = ss.okLine("bye")
		return false
	case "NOOP":
		return ss.okLine("ok")
	case "STAT", "LIST", "RETR", "TOP", "DELE", "RSET":
		if ss.state != pop3StateTransaction {
			return ss.errLine("authorization required; send USER and PASS first")
		}
		switch strings.ToUpper(verb) {
		case "STAT":
			return ss.handleStat()
		case "LIST":
			return ss.handleList(arg)
		case "RETR":
			return ss.handleRetr(arg)
		case "TOP":
			return ss.handleTop(arg)
		case "DELE":
			return ss.handleDele(arg)
		default:
			return ss.handleRset()
		}
	default:
		return ss.errLine("unsupported command")
	}
}

// handleCapa 返回最小能力列表：支持 USER 与 TOP，不支持任何写操作。
func (ss *pop3Session) handleCapa() bool {
	if !ss.okLine("capability list follows") {
		return false
	}
	for _, capability := range []string{"USER", "TOP", "IMPLEMENTATION testmail-readonly"} {
		if !ss.writeLine(capability) {
			return false
		}
	}
	return ss.writeLine(".")
}

// handleUser 记录待认证用户名。认证结果只在 PASS 阶段判定，避免提前暴露
// 用户名是否存在。
func (ss *pop3Session) handleUser(arg string) bool {
	if ss.state != pop3StateAuthorization {
		return ss.errLine("already authenticated")
	}
	name := strings.TrimSpace(arg)
	if name == "" {
		return ss.errLine("USER requires a username")
	}
	ss.pendingUser = name
	return ss.okLine("user accepted, send PASS")
}

// handlePass 校验模拟账户凭据。失败次数达到上限后关闭连接，避免在线穷举。
func (ss *pop3Session) handlePass(arg string) bool {
	if ss.state != pop3StateAuthorization {
		return ss.errLine("already authenticated")
	}
	if ss.pendingUser == "" {
		return ss.errLine("send USER first")
	}
	if ss.srv.opts.Auth == nil {
		return ss.errLine("authentication is not configured")
	}
	pass := strings.TrimSpace(arg)
	if !credentialsMatch(ss.srv.opts.Auth.Users, ss.pendingUser, pass) {
		ss.authAttempts++
		if ss.authAttempts >= defaultMaxAuthAttempts {
			_ = ss.errLine("too many authentication failures")
			return false
		}
		return ss.errLine("authentication failed, invalid credentials")
	}
	ss.user = ss.pendingUser
	ss.msgs = ss.srv.accountInbox(ss.user)
	ss.deleted = make([]bool, len(ss.msgs))
	ss.state = pop3StateTransaction
	ss.authAttempts = 0
	count, size := ss.counts()
	return ss.okLine(fmt.Sprintf("maildrop has %d messages (%d octets)", count, size))
}

// handleStat 回复当前未被本会话删除的邮件数量与总字节数。
func (ss *pop3Session) handleStat() bool {
	count, size := ss.counts()
	return ss.okLine(fmt.Sprintf("%d %d", count, size))
}

// handleList 处理 LIST：无参数返回全部邮件的编号与字节数；带参数返回单封。
func (ss *pop3Session) handleList(arg string) bool {
	arg = strings.TrimSpace(arg)
	if arg != "" {
		index, ok := ss.messageIndex(arg)
		if !ok {
			return ss.errLine("no such message")
		}
		return ss.okLine(fmt.Sprintf("%d %d", index+1, len(ss.msgs[index].Data)))
	}
	count, size := ss.counts()
	if !ss.okLine(fmt.Sprintf("%d messages (%d octets)", count, size)) {
		return false
	}
	for i := range ss.msgs {
		if ss.deleted[i] {
			continue
		}
		if !ss.writeLine(fmt.Sprintf("%d %d", i+1, len(ss.msgs[i].Data))) {
			return false
		}
	}
	return ss.writeLine(".")
}

// handleRetr 返回完整消息（与 SMTP 捕获的原始字节一致）。
func (ss *pop3Session) handleRetr(arg string) bool {
	index, ok := ss.messageIndex(arg)
	if !ok {
		return ss.errLine("no such message")
	}
	message := ss.msgs[index]
	if !ss.okLine(fmt.Sprintf("%d octets", len(message.Data))) {
		return false
	}
	return ss.writeMultiline(message.Data)
}

// handleTop 返回消息头部与前 lines 行正文（RFC 1939 的 TOP 扩展）。
func (ss *pop3Session) handleTop(arg string) bool {
	fields := strings.Fields(arg)
	if len(fields) != 2 {
		return ss.errLine("TOP requires a message number and a line count")
	}
	index, ok := ss.messageIndex(fields[0])
	if !ok {
		return ss.errLine("no such message")
	}
	lines, err := strconv.Atoi(fields[1])
	if err != nil || lines < 0 {
		return ss.errLine("invalid line count")
	}
	if !ss.okLine(fmt.Sprintf("top of message %d, %d body lines", index+1, lines)) {
		return false
	}
	return ss.writeMultiline(topContent(ss.msgs[index], lines))
}

// handleDele 在本次会话内隐藏消息；QUIT 或断开后共享存储中的消息仍然存在，
// 其他会话与 IMAP 客户端仍能看到。测试服务器不真正删除任何邮件。
func (ss *pop3Session) handleDele(arg string) bool {
	index, ok := ss.messageIndex(arg)
	if !ok {
		return ss.errLine("no such message")
	}
	ss.deleted[index] = true
	return ss.okLine(fmt.Sprintf("message %d marked deleted (this session only)", index+1))
}

// handleRset 取消本会话内的全部删除标记。
func (ss *pop3Session) handleRset() bool {
	for i := range ss.deleted {
		ss.deleted[i] = false
	}
	count, size := ss.counts()
	return ss.okLine(fmt.Sprintf("maildrop has %d messages (%d octets)", count, size))
}

// counts 返回未被本会话删除的邮件数量与总字节数。
func (ss *pop3Session) counts() (count, size int) {
	for i := range ss.msgs {
		if ss.deleted[i] {
			continue
		}
		count++
		size += len(ss.msgs[i].Data)
	}
	return count, size
}

// messageIndex 解析邮件编号（从 1 开始）并确认它存在且未被本会话删除。
func (ss *pop3Session) messageIndex(arg string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || n < 1 || n > len(ss.msgs) {
		return 0, false
	}
	if ss.deleted[n-1] {
		return 0, false
	}
	return n - 1, true
}

// topContent 生成 TOP 响应内容：原始头部块 + 前 lines 行正文（CRLF 行尾）。
func topContent(message Message, lines int) []byte {
	var b bytes.Buffer
	header := message.HeaderBlock()
	if len(header) == 0 {
		b.WriteString("\r\n")
	} else {
		b.Write(header)
	}
	body := message.Body()
	for count := 0; count < lines && len(body) > 0; count++ {
		if i := bytes.Index(body, []byte("\r\n")); i >= 0 {
			b.Write(body[:i])
			b.WriteString("\r\n")
			body = body[i+2:]
			continue
		}
		b.Write(body)
		b.WriteString("\r\n")
		body = nil
	}
	return b.Bytes()
}

// pop3ResponseText 清洗问候语中的主机名，避免 CR/LF 破坏协议。
func pop3ResponseText(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

// readLine 读取一行（不含 CRLF）。单行超过 maxLineBytes 时返回 errLineTooLong。
func (ss *pop3Session) readLine() (string, error) {
	var line []byte
	for {
		deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
		if deadline.After(ss.sessionEnd) {
			deadline = ss.sessionEnd
		}
		if err := ss.conn.SetReadDeadline(deadline); err != nil {
			return "", err
		}
		frag, err := ss.reader.ReadSlice('\n')
		if len(line)+len(frag) > maxLineBytes {
			return "", errLineTooLong
		}
		line = append(line, frag...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return "", err
	}
	s := strings.TrimSuffix(string(line), "\n")
	s = strings.TrimSuffix(s, "\r")
	return s, nil
}

// writeDeadline 返回写入截止时间：单次读取超时与会话总时长取较早者。
func (ss *pop3Session) writeDeadline() time.Time {
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	return deadline
}

// writeLine 写入一行并追加 CRLF。
func (ss *pop3Session) writeLine(line string) bool {
	_ = ss.conn.SetWriteDeadline(ss.writeDeadline())
	if _, err := ss.writer.WriteString(line + "\r\n"); err != nil {
		return false
	}
	return ss.writer.Flush() == nil
}

// writeBytes 写入并刷新一段原始字节。
func (ss *pop3Session) writeBytes(data []byte) bool {
	_ = ss.conn.SetWriteDeadline(ss.writeDeadline())
	if _, err := ss.writer.Write(data); err != nil {
		return false
	}
	return ss.writer.Flush() == nil
}

// okLine 回复 +OK 响应。
func (ss *pop3Session) okLine(text string) bool {
	return ss.writeLine("+OK " + text)
}

// errLine 回复 -ERR 响应。
func (ss *pop3Session) errLine(text string) bool {
	return ss.writeLine("-ERR " + text)
}

// writeMultiline 以点填充规则写出一段多行数据，并以单独一行 "." 结束。
// data 的行尾必须是 CRLF（SMTP 捕获的消息本身如此）；最后一行缺少 CRLF 时会补上。
func (ss *pop3Session) writeMultiline(data []byte) bool {
	var b bytes.Buffer
	rest := data
	for len(rest) > 0 {
		var line []byte
		if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
			line, rest = rest[:i], rest[i+2:]
		} else {
			line, rest = rest, nil
		}
		if len(line) > 0 && line[0] == '.' {
			b.WriteByte('.')
		}
		b.Write(line)
		b.WriteString("\r\n")
	}
	b.WriteString(".\r\n")
	return ss.writeBytes(b.Bytes())
}
