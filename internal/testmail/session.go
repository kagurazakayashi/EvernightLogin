package testmail

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// 会话内部错误。协议层错误直接回复 SMTP 状态码；这两个错误用于中断连接。
var (
	// errLineTooLong 表示单个协议行超过 maxLineBytes。
	errLineTooLong = errors.New("testmail: 协议行过长")
	// errDataDrainLimit 表示 DATA 内容在超过上限后仍继续发送过多数据，服务端
	// 拒绝继续读取并断开连接，避免被超大消息占用会话。
	errDataDrainLimit = errors.New("testmail: DATA 内容过大已停止读取")
)

// session 是单个 SMTP 连接的状态。它只在所属 goroutine 中被访问，不需要加锁。
type session struct {
	srv        *Server
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	remote     string
	sessionID  uint64
	tls        bool
	sessionEnd time.Time

	helo     bool
	heloName string

	authUser     string
	authAttempts int

	mailFrom    string
	mailFromSet bool
	rcpts       []string
}

// greet 发送 220 问候语。
func (ss *session) greet() {
	ss.reply(220, ss.srv.opts.Hostname+" ESMTP testmail ready")
}

// emit 向可选的调试轨迹回调发送一次会话事件。回调为 nil 时直接返回。
func (ss *session) emit(kind SessionEventKind, command, parameter string) {
	cb := ss.srv.opts.OnSessionEvent
	if cb == nil {
		return
	}
	cb(SessionEvent{
		Kind:       kind,
		SessionID:  ss.sessionID,
		RemoteAddr: ss.remote,
		Command:    command,
		Parameter:  parameter,
	})
}

// loop 读取并分发命令，直到客户端退出、连接出错或会话时长耗尽。
func (ss *session) loop() {
	for {
		line, err := ss.readLine()
		if err != nil {
			switch {
			case errors.Is(err, errLineTooLong):
				ss.reply(500, "5.5.2 Line too long")
			case isTimeout(err):
				ss.reply(421, "4.4.2 Timeout, closing connection")
			}
			return
		}
		verb, arg := splitCommand(line)
		if ss.srv.opts.OnSessionEvent != nil {
			ss.emit(SessionEventCommand, strings.ToUpper(verb), redactCommandArg(verb, arg))
		}
		if !ss.handle(line) {
			return
		}
	}
}

// handle 处理一条命令；返回 false 表示结束会话。
func (ss *session) handle(line string) bool {
	if line == "" {
		return ss.reply(500, "5.5.2 Empty command")
	}
	verb, arg := splitCommand(line)
	switch strings.ToUpper(verb) {
	case "HELO":
		return ss.handleHelo(arg, false)
	case "EHLO":
		return ss.handleHelo(arg, true)
	case "MAIL":
		return ss.handleMail(arg)
	case "RCPT":
		return ss.handleRcpt(arg)
	case "DATA":
		return ss.handleData()
	case "RSET":
		ss.resetEnvelope()
		return ss.reply(250, "2.0.0 Ok")
	case "NOOP":
		return ss.reply(250, "2.0.0 Ok")
	case "QUIT":
		ss.reply(221, "2.0.0 Bye")
		return false
	case "STARTTLS":
		return ss.handleStartTLS()
	case "AUTH":
		return ss.handleAuth(arg)
	case "HELP", "VRFY", "EXPN":
		return ss.reply(502, "5.5.1 Command not implemented")
	default:
		return ss.reply(500, "5.5.2 Command unrecognized")
	}
}

// splitCommand 把一行拆成动词与参数（以第一段空白分隔）。
func splitCommand(line string) (verb, arg string) {
	trimmed := strings.TrimSpace(line)
	if i := strings.IndexAny(trimmed, " \t"); i >= 0 {
		return trimmed[:i], strings.TrimSpace(trimmed[i+1:])
	}
	return trimmed, ""
}

// handleHelo 处理 HELO/EHLO。EHLO 返回多行能力列表。
func (ss *session) handleHelo(arg string, extended bool) bool {
	if arg == "" {
		if extended {
			return ss.reply(501, "5.5.4 Syntax: EHLO hostname")
		}
		return ss.reply(501, "5.5.4 Syntax: HELO hostname")
	}
	ss.helo = true
	ss.heloName = arg
	ss.resetEnvelope()
	if !extended {
		return ss.reply(250, ss.srv.opts.Hostname)
	}
	return ss.replyLines(250, ss.ehloLines())
}

// ehloLines 构造 EHLO 能力列表，最后一行不带连字符。STARTTLS 只在已配置且尚未
// 启用 TLS 时公布，AUTH 只在配置了测试凭据时公布。
func (ss *session) ehloLines() []string {
	lines := []string{
		ss.srv.opts.Hostname,
		fmt.Sprintf("SIZE %d", ss.srv.opts.MaxMessageBytes),
		"8BITMIME",
		"ENHANCEDSTATUSCODES",
	}
	if ss.srv.opts.Auth != nil {
		lines = append(lines, "AUTH PLAIN LOGIN")
	}
	if ss.srv.tlsConf != nil && !ss.tls {
		lines = append(lines, "STARTTLS")
	}
	lines = append(lines, "HELP")
	return lines
}

// authRequired 报告当前配置是否要求先认证才能发信。
func (ss *session) authRequired() bool {
	return ss.srv.opts.Auth != nil && ss.srv.opts.Auth.RequireAuth
}

// handleMail 处理 MAIL FROM。
func (ss *session) handleMail(arg string) bool {
	if ss.authRequired() && ss.authUser == "" {
		return ss.reply(530, "5.7.0 Authentication required")
	}
	if !ss.helo {
		return ss.reply(503, "5.5.1 Send HELO/EHLO first")
	}
	addr, ok := parsePath(arg, "FROM:")
	if !ok {
		return ss.reply(501, "5.5.4 Syntax: MAIL FROM:<address>")
	}
	if !validAddress(addr, true) {
		return ss.reply(501, "5.1.7 Bad sender address syntax")
	}
	ss.resetEnvelope()
	ss.mailFrom = addr
	ss.mailFromSet = true
	return ss.reply(250, "2.1.0 Ok")
}

// handleRcpt 处理 RCPT TO，并在此处检查收件人数上限。
func (ss *session) handleRcpt(arg string) bool {
	if !ss.mailFromSet {
		return ss.reply(503, "5.5.1 Need MAIL command")
	}
	addr, ok := parsePath(arg, "TO:")
	if !ok || !validAddress(addr, false) {
		return ss.reply(501, "5.1.3 Bad recipient address syntax")
	}
	if len(ss.rcpts) >= ss.srv.opts.MaxRecipients {
		return ss.reply(452, "4.5.3 Too many recipients")
	}
	ss.rcpts = append(ss.rcpts, addr)
	return ss.reply(250, "2.1.5 Ok")
}

// handleData 处理 DATA：读取点填充正文、按上限判定、保存消息。
func (ss *session) handleData() bool {
	if !ss.mailFromSet {
		return ss.reply(503, "5.5.1 Need MAIL command")
	}
	if len(ss.rcpts) == 0 {
		return ss.reply(503, "5.5.1 Need RCPT command")
	}
	if !ss.reply(354, "End data with <CR><LF>.<CR><LF>") {
		return false
	}
	data, tooBig, err := ss.readData()
	if err != nil {
		switch {
		case errors.Is(err, errLineTooLong):
			// 单行过长无法可靠对齐协议边界，直接断开，避免把后续内容误当命令。
			ss.reply(500, "5.5.2 Line too long")
		case errors.Is(err, errDataDrainLimit):
			ss.reply(552, "5.3.4 Message size exceeds fixed maximum message size")
		case isTimeout(err):
			ss.reply(421, "4.4.2 Timeout, closing connection")
		}
		return false
	}
	if tooBig {
		ss.resetEnvelope()
		return ss.reply(552, "5.3.4 Message size exceeds fixed maximum message size")
	}
	msg := ss.buildMessage(data)
	stored, err := ss.srv.store.add(msg)
	if err != nil {
		ss.resetEnvelope()
		if errors.Is(err, ErrStoreFull) {
			return ss.reply(452, "4.3.1 Insufficient system storage, message not stored")
		}
		return ss.reply(451, "4.3.0 Requested action aborted: local error")
	}
	ss.resetEnvelope()
	if cb := ss.srv.opts.OnMessage; cb != nil {
		cb(stored)
	}
	return ss.replyf(250, "2.0.0 Ok: queued as %s", stored.ID)
}

// readData 读取 DATA 内容直到单独的 "." 行，还原点填充，并检查单消息大小上限。
// 超限后仍继续消费到结束标记（以便返回标准 552），但另有硬上限防止无限读取。
func (ss *session) readData() (data []byte, tooBig bool, err error) {
	var buf bytes.Buffer
	maxBytes := ss.srv.opts.MaxMessageBytes
	// 超限后继续读取的硬上限：超过后直接断开，避免超大消息长时间占用会话。
	drainLimit := maxBytes * 4
	total := 0
	for {
		line, err := ss.readLine()
		if err != nil {
			return nil, false, err
		}
		if line == "." {
			return buf.Bytes(), tooBig, nil
		}
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}
		total += len(line) + 2 // 还原后的行尾 CRLF
		if total > drainLimit {
			return nil, false, errDataDrainLimit
		}
		if tooBig {
			continue
		}
		if buf.Len()+len(line)+2 > maxBytes {
			tooBig = true
			buf.Reset()
			continue
		}
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
}

// buildMessage 由原始字节构造消息记录。
func (ss *session) buildMessage(data []byte) Message {
	headers, subject, date, bodyOffset := parseReceived(data)
	rcpts := make([]string, len(ss.rcpts))
	copy(rcpts, ss.rcpts)
	return Message{
		ReceivedAt:   time.Now().UTC(),
		RemoteAddr:   ss.remote,
		EnvelopeFrom: ss.mailFrom,
		EnvelopeTo:   rcpts,
		Data:         append([]byte(nil), data...),
		Subject:      subject,
		Date:         date,
		Headers:      headers,
		AuthUser:     ss.authUser,
		TLS:          ss.tls,
		bodyOffset:   bodyOffset,
	}
}

// resetEnvelope 清空当前邮件事务的信封状态（MAIL/RCPT/DATA）。
func (ss *session) resetEnvelope() {
	ss.mailFrom = ""
	ss.mailFromSet = false
	ss.rcpts = nil
}

// handleStartTLS 处理 STARTTLS：先回复 220，再完成 TLS 握手并重置会话状态。
// 握手失败直接结束连接；成功后必须重新 EHLO 才能继续发信。
func (ss *session) handleStartTLS() bool {
	if ss.srv.tlsConf == nil {
		return ss.reply(502, "5.5.1 Command not implemented")
	}
	if ss.tls {
		return ss.reply(503, "5.5.1 TLS already active")
	}
	if !ss.helo {
		return ss.reply(503, "5.5.1 Send EHLO first")
	}
	if !ss.reply(220, "2.0.0 Ready to start TLS") {
		return false
	}
	// 明文阶段的状态一律丢弃，TLS 之后必须重新 EHLO 并重新认证。
	ss.resetEnvelope()
	ss.authUser = ""
	ss.helo = false
	ss.heloName = ""

	tlsConn := tls.Server(ss.conn, ss.srv.tlsConf)
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	_ = tlsConn.SetDeadline(time.Time{})
	ss.conn = tlsConn
	ss.reader = bufio.NewReader(tlsConn)
	ss.writer = bufio.NewWriter(tlsConn)
	ss.tls = true
	ss.emit(SessionEventTLS, "STARTTLS", "握手完成，后续命令与正文均已加密")
	return true
}

// handleAuth 处理 AUTH PLAIN/LOGIN。只使用配置中的测试凭据，失败计数达到上限后
// 断开连接。
func (ss *session) handleAuth(arg string) bool {
	if ss.srv.opts.Auth == nil {
		return ss.reply(502, "5.5.1 Command not implemented")
	}
	if ss.authUser != "" {
		return ss.reply(503, "5.5.1 Already authenticated")
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return ss.reply(501, "5.5.4 Syntax: AUTH mechanism [initial-response]")
	}
	switch strings.ToUpper(fields[0]) {
	case "PLAIN":
		response := ""
		if len(fields) > 1 {
			response = fields[1]
		} else {
			if !ss.reply(334, "") {
				return false
			}
			line, err := ss.readLine()
			if err != nil {
				return false
			}
			response = strings.TrimSpace(line)
			if response == "*" {
				return ss.reply(501, "5.7.0 Authentication cancelled")
			}
		}
		decoded, ok := decodeBase64(response)
		if !ok {
			return ss.authFailure(501, "5.5.2 Cannot decode AUTH response")
		}
		parts := bytes.Split(decoded, []byte{0})
		if len(parts) != 3 {
			return ss.authFailure(501, "5.5.2 Invalid AUTH PLAIN response")
		}
		return ss.finishAuth(string(parts[1]), string(parts[2]))
	case "LOGIN":
		var user string
		if len(fields) > 1 {
			decoded, ok := decodeBase64(fields[1])
			if !ok {
				return ss.authFailure(501, "5.5.2 Cannot decode AUTH response")
			}
			user = string(decoded)
		} else {
			// "Username:" 的 base64 形式。
			if !ss.reply(334, base64.StdEncoding.EncodeToString([]byte("Username:"))) {
				return false
			}
			line, err := ss.readLine()
			if err != nil {
				return false
			}
			decoded, ok := decodeBase64(strings.TrimSpace(line))
			if !ok {
				return ss.authFailure(501, "5.5.2 Cannot decode AUTH response")
			}
			user = string(decoded)
		}
		if !ss.reply(334, base64.StdEncoding.EncodeToString([]byte("Password:"))) {
			return false
		}
		line, err := ss.readLine()
		if err != nil {
			return false
		}
		decoded, ok := decodeBase64(strings.TrimSpace(line))
		if !ok {
			return ss.authFailure(501, "5.5.2 Cannot decode AUTH response")
		}
		return ss.finishAuth(user, string(decoded))
	default:
		return ss.reply(504, "5.5.4 Unrecognized authentication type")
	}
}

// finishAuth 校验凭据并回复认证结果。
func (ss *session) finishAuth(user, pass string) bool {
	if ss.credentialsMatch(user, pass) {
		ss.authUser = user
		ss.authAttempts = 0
		ok := ss.reply(235, "2.7.0 Authentication successful")
		if ok {
			ss.emit(SessionEventAuth, "AUTH", user)
		}
		return ok
	}
	return ss.authFailure(535, "5.7.8 Authentication credentials invalid")
}

// authFailure 记录一次失败尝试；达到上限时以 421 关闭连接。
func (ss *session) authFailure(code int, text string) bool {
	ss.authAttempts++
	if ss.authAttempts >= defaultMaxAuthAttempts {
		ss.reply(421, "4.7.0 Too many authentication attempts, closing connection")
		return false
	}
	return ss.reply(code, text)
}

// credentialsMatch 以恒定时间比较检查凭据。实现见 auth.go 的包级函数，SMTP 与
// IMAP/POP3 共用同一份比较逻辑，避免不同协议出现认证行为差异。
func (ss *session) credentialsMatch(user, pass string) bool {
	return credentialsMatch(ss.srv.opts.Auth.Users, user, pass)
}

// decodeBase64 解码 AUTH 响应；容忍省略尾部填充的写法。
func decodeBase64(v string) ([]byte, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "=")); err == nil {
		return b, true
	}
	return nil, false
}

// readLine 读取一行（不含 CRLF）。单行超过 maxLineBytes 时返回 errLineTooLong。
func (ss *session) readLine() (string, error) {
	var line []byte
	for {
		if err := ss.bumpReadDeadline(); err != nil {
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

// bumpReadDeadline 设置下一次读取的截止时间：单次读取超时与会话总时长取较早者。
func (ss *session) bumpReadDeadline() error {
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	return ss.conn.SetReadDeadline(deadline)
}

// writeDeadline 返回写入截止时间，规则与读取相同。
func (ss *session) writeDeadline() time.Time {
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	return deadline
}

// writeString 写入并刷新一段响应；写失败表示连接已不可用。
func (ss *session) writeString(s string) bool {
	_ = ss.conn.SetWriteDeadline(ss.writeDeadline())
	if _, err := ss.writer.WriteString(s); err != nil {
		return false
	}
	return ss.writer.Flush() == nil
}

// reply 回复单行响应；text 为空时输出 "code" 单行（用于 334 空挑战）。
func (ss *session) reply(code int, text string) bool {
	var ok bool
	if text == "" {
		ok = ss.writeString(fmt.Sprintf("%d\r\n", code))
	} else {
		ok = ss.writeString(fmt.Sprintf("%d %s\r\n", code, text))
	}
	if ok {
		ss.emit(SessionEventReply, strconv.Itoa(code), text)
	}
	return ok
}

// replyf 是带格式化文本的 reply。
func (ss *session) replyf(code int, format string, args ...any) bool {
	return ss.reply(code, fmt.Sprintf(format, args...))
}

// replyLines 回复多行响应：除最后一行外使用 "code-text"，最后一行使用 "code text"。
func (ss *session) replyLines(code int, lines []string) bool {
	if len(lines) == 0 {
		return ss.reply(code, "")
	}
	var b strings.Builder
	for i, line := range lines {
		if i == len(lines)-1 {
			fmt.Fprintf(&b, "%d %s\r\n", code, line)
			continue
		}
		fmt.Fprintf(&b, "%d-%s\r\n", code, line)
	}
	if !ss.writeString(b.String()) {
		return false
	}
	ss.emit(SessionEventReply, strconv.Itoa(code), strings.Join(lines, " | "))
	return true
}

// isTimeout 判断错误是否为网络超时。
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
