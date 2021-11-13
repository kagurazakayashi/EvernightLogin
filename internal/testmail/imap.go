package testmail

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IMAP 只读收件箱的常量与限制。
const (
	// imapUIDValidity 是固定的 UIDVALIDITY。消息编号在同一服务器实例内单调
	// 递增且永不复用（Clear/Take 也不会回退编号），因此固定值长期有效。
	imapUIDValidity uint32 = 1
	// maxIMAPLiteralBytes 是单条 IMAP 字面量（{n}，用于 LOGIN 参数、APPEND
	// 内容等）的字节上限，防止客户端用超大 literal 占用内存。
	maxIMAPLiteralBytes = 1 << 20
	// maxIMAPCommandBytes 是单条 IMAP 命令（命令行 + 全部字面量内容）的累计
	// 字节上限。仅限制单行/单字面量不够：未认证客户端可以用大量小字面量把命令
	// 拼得很长，因此必须对整条命令的总字节数设上限，超限直接 BAD 并断开。
	maxIMAPCommandBytes = 1 << 20
	// maxIMAPLiteralsPerCommand 是单条命令允许的字面量个数上限（LOGIN 最多
	// 2 个；其余合法命令远小于该值），防止用大量 {1} 字面量累积内存。
	maxIMAPLiteralsPerCommand = 32
	// maxIMAPHeaderFields 是 BODY[HEADER.FIELDS (...)] 允许请求的字段数上限。
	maxIMAPHeaderFields = 100
	// maxIMAPSeqSetExpansion 是一次 FETCH/UID FETCH 消息集合最多展开的条数，
	// 与内存仓库消息上限一致；实际响应条数仍受邮箱消息数约束。
	maxIMAPSeqSetExpansion = MaxMaxMessages
)

// imapLiteralPattern 匹配命令行末尾的 IMAP 字面量标记（{n} 或 {n+}）。
var imapLiteralPattern = regexp.MustCompile(`\{([0-9]+)\+?\}$`)

// imapState 是 IMAP 会话状态（RFC 3501 的四种状态去掉已注销）。
type imapState int

const (
	// imapStateNotAuthenticated 表示尚未通过 LOGIN。
	imapStateNotAuthenticated imapState = iota
	// imapStateAuthenticated 表示已认证但未选择邮箱。
	imapStateAuthenticated
	// imapStateSelected 表示已 SELECT/EXAMINE INBOX。
	imapStateSelected
)

// imapSession 是单个 IMAP 连接的状态。它只在所属 goroutine 中被访问，不需要加锁。
type imapSession struct {
	srv        *Server
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	remote     string
	sessionID  uint64
	sessionEnd time.Time

	state        imapState
	user         string
	authAttempts int

	// inbox 是 SELECT/EXAMINE 时按账户过滤后的收件箱快照。会话期间新到达的
	// 邮件不会增加 EXISTS（不主动推送更新），重新 SELECT 后可见。
	inbox []Message
}

// serveIMAP 处理单个 IMAP 连接：可选隐式 TLS 握手、发送问候语并进入命令循环。
func (s *Server) serveIMAP(conn net.Conn) {
	sessionID := s.sessionSeq.Add(1)
	if s.imapTLSConf != nil {
		tlsConn, err := s.wrapTLS(conn, s.imapTLSConf)
		if err != nil {
			return
		}
		conn = tlsConn
	}
	ss := &imapSession{
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

// greet 发送 IMAP 问候语，并公布最小能力集合。
func (ss *imapSession) greet() {
	hostname := imapResponseText(ss.srv.opts.Hostname)
	_ = ss.writeLine("* OK [CAPABILITY IMAP4rev1] " + hostname + " IMAP4rev1 test server ready")
}

// loop 读取并分发命令，直到客户端退出、连接出错或会话时长耗尽。
func (ss *imapSession) loop() {
	for {
		line, err := ss.readCommand()
		if err != nil {
			switch {
			case errors.Is(err, errLineTooLong):
				_ = ss.writeLine("* BAD Command line too long")
			case errors.Is(err, errIMAPLiteralTooBig):
				_ = ss.writeLine("* BAD Literal too large")
			case errors.Is(err, errIMAPCommandTooBig):
				_ = ss.writeLine("* BAD Command too large")
			case isTimeout(err):
				_ = ss.writeLine("* BYE Idle timeout, closing connection")
			}
			return
		}
		if !ss.handle(line) {
			return
		}
	}
}

// errIMAPLiteralTooBig 表示客户端请求的字面量超过 maxIMAPLiteralBytes。
var errIMAPLiteralTooBig = errors.New("testmail: IMAP 字面量过大")

// errIMAPWriteFailed 表示向客户端写继续响应失败（连接已不可用）。
var errIMAPWriteFailed = errors.New("testmail: IMAP 写响应失败")

// errIMAPCommandTooBig 表示一条 IMAP 命令（含字面量累计）超过资源上限。
var errIMAPCommandTooBig = errors.New("testmail: IMAP 命令过大")

// readCommand 读取一条完整 IMAP 命令，并把字面量（{n}）解析值转成带引号的参数，
// 使后续分词只面对 quoted string 与 atom 两种形式。字面量之后同一命令行的剩余
// 内容会继续读取，直到该行结束。
func (ss *imapSession) readCommand() (string, error) {
	var full strings.Builder
	// total 与 literals 是整条命令的累计资源用量：单行长度由 readLine 限制，
	// 但一条命令可以跨多段（每次字面量后继续读下一段），因此必须在这里累计，
	// 否则未认证客户端可以用大量小字面量拼出超长命令（内存 DoS）。
	total := 0
	literals := 0
	for {
		line, err := ss.readLine()
		if err != nil {
			return "", err
		}
		total += len(line) + 2 // 行尾 CRLF 也计入命令累计大小
		if total > maxIMAPCommandBytes {
			return "", errIMAPCommandTooBig
		}
		loc := imapLiteralPattern.FindStringIndex(line)
		if loc == nil {
			full.WriteString(line)
			return full.String(), nil
		}
		n, err := strconv.Atoi(imapLiteralPattern.FindStringSubmatch(line)[1])
		if err != nil || n < 0 || n > maxIMAPLiteralBytes {
			return "", errIMAPLiteralTooBig
		}
		literals++
		if literals > maxIMAPLiteralsPerCommand {
			return "", errIMAPCommandTooBig
		}
		if total+n > maxIMAPCommandBytes {
			return "", errIMAPCommandTooBig
		}
		total += n
		// 去掉行尾的 {n} 标记，把字面量原文以 quoted string 形式接上。
		full.WriteString(line[:loc[0]])
		// 按 RFC 3501 先发送 "+" 继续响应，再读取恰好 n 字节的字面量内容。
		if !ss.writeLine("+ Ready for literal data") {
			return "", errIMAPWriteFailed
		}
		literal := make([]byte, n)
		if err := ss.readFull(literal); err != nil {
			return "", err
		}
		full.WriteString(`"`)
		full.WriteString(imapEscapeQuoted(string(literal)))
		full.WriteString(`"`)
	}
}

// handle 处理一条命令；返回 false 表示结束会话。
func (ss *imapSession) handle(line string) bool {
	tag, verb, rest := splitIMAPCommand(line)
	if !validIMAPTag(tag) {
		return ss.writeLine("* BAD Invalid command tag")
	}
	if verb == "" {
		return ss.taggedBad(tag, "Missing command")
	}
	switch strings.ToUpper(verb) {
	case "CAPABILITY":
		return ss.writeLine("* CAPABILITY IMAP4rev1") && ss.taggedOK(tag, "CAPABILITY completed")
	case "NOOP":
		return ss.taggedOK(tag, "NOOP completed")
	case "LOGOUT":
		_ = ss.writeLine("* BYE " + imapResponseText(ss.srv.opts.Hostname) + " IMAP4rev1 test server logging out")
		_ = ss.taggedOK(tag, "LOGOUT completed")
		return false
	case "LOGIN":
		return ss.handleLogin(tag, rest)
	case "LIST":
		return ss.handleList(tag, rest, false)
	case "LSUB":
		return ss.handleList(tag, rest, true)
	case "SELECT":
		return ss.handleSelect(tag, rest, false)
	case "EXAMINE":
		return ss.handleSelect(tag, rest, true)
	case "FETCH":
		return ss.handleFetch(tag, rest, false)
	case "UID":
		return ss.handleUID(tag, rest)
	case "CLOSE":
		return ss.handleClose(tag)
	case "STATUS":
		return ss.handleStatus(tag, rest)
	case "STORE", "EXPUNGE", "APPEND", "COPY", "MOVE",
		"CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE":
		// 只读卡死写操作：不解析参数、不做任何修改，明确返回 NO。
		return ss.taggedNo(tag, "[READ-ONLY] Test mail server is read-only; this operation is rejected")
	case "AUTHENTICATE":
		return ss.taggedBad(tag, "Only LOGIN authentication is supported")
	default:
		return ss.taggedBad(tag, "Unsupported command: "+imapResponseText(strings.ToUpper(verb)))
	}
}

// handleLogin 处理 LOGIN（模拟账户认证）。认证只接受配置中的测试凭据；失败次数
// 达到上限后主动断开连接，避免在线穷举。
func (ss *imapSession) handleLogin(tag, rest string) bool {
	if ss.state != imapStateNotAuthenticated {
		return ss.taggedBad(tag, "LOGIN is only allowed before authentication")
	}
	if ss.srv.opts.Auth == nil {
		return ss.taggedNo(tag, "Authentication is not configured")
	}
	args := imapTokens(rest)
	if len(args) != 2 {
		return ss.taggedBad(tag, "LOGIN requires username and password")
	}
	if credentialsMatch(ss.srv.opts.Auth.Users, args[0], args[1]) {
		ss.user = args[0]
		ss.authAttempts = 0
		ss.state = imapStateAuthenticated
		return ss.taggedOK(tag, "[CAPABILITY IMAP4rev1] LOGIN completed")
	}
	ss.authAttempts++
	if ss.authAttempts >= defaultMaxAuthAttempts {
		_ = ss.taggedNo(tag, "[AUTHENTICATIONFAILED] Authentication failed")
		_ = ss.writeLine("* BYE Too many authentication failures")
		return false
	}
	return ss.taggedNo(tag, "[AUTHENTICATIONFAILED] Authentication failed")
}

// handleList 处理 LIST/LSUB。测试服务器只有 INBOX 一个邮箱；请求其他模式时返回
// 空列表。LSUB 始终报告已订阅 INBOX（测试客户端无需显式 SUBSCRIBE）。
func (ss *imapSession) handleList(tag, rest string, lsub bool) bool {
	if ss.state == imapStateNotAuthenticated {
		return ss.taggedBad(tag, "Not authenticated")
	}
	keyword := "LIST"
	if lsub {
		keyword = "LSUB"
	}
	args := imapTokens(rest)
	if len(args) < 2 {
		return ss.taggedBad(tag, keyword+" requires reference and mailbox pattern")
	}
	pattern := args[1]
	if pattern == "" {
		return ss.writeLine(`* `+keyword+` (\Noselect) "/" ""`) && ss.taggedOK(tag, keyword+" completed")
	}
	if !imapPatternMatches(pattern, "INBOX") {
		return ss.taggedOK(tag, keyword+" completed")
	}
	flag := `\HasNoChildren`
	if lsub {
		flag = ""
	}
	if !ss.writeLine(`* ` + keyword + ` (` + flag + `) "/" "INBOX"`) {
		return false
	}
	return ss.taggedOK(tag, keyword+" completed")
}

// handleSelect 处理 SELECT/EXAMINE INBOX。测试服务器始终只读，两种情况都返回
// [READ-ONLY] 并且 PERMANENTFLAGS 为空。
func (ss *imapSession) handleSelect(tag, rest string, examine bool) bool {
	if ss.state == imapStateNotAuthenticated {
		return ss.taggedBad(tag, "Not authenticated")
	}
	keyword := "SELECT"
	if examine {
		keyword = "EXAMINE"
	}
	args := imapTokens(rest)
	if len(args) != 1 {
		return ss.taggedBad(tag, keyword+" requires exactly one mailbox name")
	}
	if !strings.EqualFold(args[0], "INBOX") {
		return ss.taggedNo(tag, "[NONEXISTENT] No such mailbox; only INBOX is available")
	}
	inbox := ss.srv.accountInbox(ss.user)
	ss.inbox = inbox
	ss.state = imapStateSelected

	lines := []string{
		`* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)`,
		fmt.Sprintf("* %d EXISTS", len(inbox)),
		"* 0 RECENT",
		fmt.Sprintf("* OK [UIDVALIDITY %d] UIDs valid", imapUIDValidity),
		fmt.Sprintf("* OK [UIDNEXT %d] Predicted next UID", ss.srv.store.nextSeq()),
		"* OK [PERMANENTFLAGS ()] Read-only mailbox; no permanent flags",
	}
	if len(inbox) > 0 {
		lines = append(lines, "* OK [UNSEEN 1] First unseen message")
	}
	for _, line := range lines {
		if !ss.writeLine(line) {
			return false
		}
	}
	return ss.taggedOK(tag, "[READ-ONLY] "+keyword+" completed")
}

// handleClose 处理 CLOSE：只读服务器不执行清除（EXPUNGE），直接回到已认证状态。
func (ss *imapSession) handleClose(tag string) bool {
	if ss.state != imapStateSelected {
		return ss.taggedBad(tag, "CLOSE is only allowed in selected state")
	}
	ss.state = imapStateAuthenticated
	ss.inbox = nil
	return ss.taggedOK(tag, "CLOSE completed")
}

// handleStatus 处理 STATUS INBOX (...)：返回实时计数，不改变会话状态。
// 只支持测试收件箱实际具备的项；不支持的项按协议返回 BAD，避免给出假数据。
func (ss *imapSession) handleStatus(tag, rest string) bool {
	if ss.state == imapStateNotAuthenticated {
		return ss.taggedBad(tag, "Not authenticated")
	}
	args := imapTokens(rest)
	if len(args) < 2 {
		return ss.taggedBad(tag, "STATUS requires a mailbox name and item list")
	}
	if !strings.EqualFold(args[0], "INBOX") {
		return ss.taggedNo(tag, "[NONEXISTENT] No such mailbox; only INBOX is available")
	}
	itemText := strings.Join(args[1:], " ")
	itemText = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(itemText, "("), ")"))
	wanted := strings.Fields(strings.ToUpper(itemText))
	if len(wanted) == 0 {
		return ss.taggedBad(tag, "STATUS requires at least one data item")
	}
	valid := map[string]bool{
		"MESSAGES": true, "UIDNEXT": true, "UIDVALIDITY": true, "UNSEEN": true, "RECENT": true,
	}
	for _, item := range wanted {
		if !valid[item] {
			return ss.taggedBad(tag, "Unsupported STATUS item: "+item)
		}
	}
	inbox := ss.srv.accountInbox(ss.user)
	values := map[string]int{
		"MESSAGES":    len(inbox),
		"UIDNEXT":     int(ss.srv.store.nextSeq()),
		"UIDVALIDITY": int(imapUIDValidity),
		"UNSEEN":      len(inbox),
		"RECENT":      0,
	}
	parts := make([]string, 0, len(wanted))
	for _, item := range wanted {
		parts = append(parts, fmt.Sprintf("%s %d", item, values[item]))
	}
	if !ss.writeLine("* STATUS INBOX (" + strings.Join(parts, " ") + ")") {
		return false
	}
	return ss.taggedOK(tag, "STATUS completed")
}

// handleUID 处理 UID 子命令：只实现 UID FETCH；UID 写操作明确拒绝。
func (ss *imapSession) handleUID(tag, rest string) bool {
	sub, subRest := splitFirstWord(rest)
	switch strings.ToUpper(sub) {
	case "FETCH":
		return ss.handleFetch(tag, subRest, true)
	case "STORE", "EXPUNGE", "COPY", "MOVE":
		return ss.taggedNo(tag, "[READ-ONLY] Test mail server is read-only; this operation is rejected")
	case "":
		return ss.taggedBad(tag, "UID requires a subcommand")
	default:
		return ss.taggedBad(tag, "Unsupported UID subcommand: "+imapResponseText(strings.ToUpper(sub)))
	}
}

// handleFetch 处理 FETCH / UID FETCH。支持的数据项见 parseFetchItem；不支持的数据
// 项在发送任何未标记数据之前返回 BAD，避免客户端收到半个结果。
func (ss *imapSession) handleFetch(tag, rest string, uidMode bool) bool {
	if ss.state != imapStateSelected {
		return ss.taggedBad(tag, "FETCH is only allowed in selected state; SELECT/EXAMINE INBOX first")
	}
	seqText, itemText := splitFirstWord(rest)
	if seqText == "" {
		return ss.taggedBad(tag, "FETCH requires a message set")
	}
	if itemText == "" {
		return ss.taggedBad(tag, "FETCH requires data items")
	}
	items, err := parseFetchItems(itemText)
	if err != nil {
		return ss.taggedBad(tag, err.Error())
	}

	var maxUID uint32
	for _, m := range ss.inbox {
		if uid := messageUID(m); uid > maxUID {
			maxUID = uid
		}
	}
	limit := len(ss.inbox)
	if uidMode {
		limit = int(maxUID)
	}
	numbers, err := parseIMAPSeqSet(seqText, limit)
	if err != nil {
		return ss.taggedBad(tag, err.Error())
	}

	if uidMode {
		wanted := make(map[uint32]bool, len(numbers))
		for _, n := range numbers {
			wanted[uint32(n)] = true
		}
		for idx, m := range ss.inbox {
			uid := messageUID(m)
			if uid == 0 || !wanted[uid] {
				continue
			}
			if !ss.writeFetch(uint32(idx+1), m, items, true) {
				return false
			}
		}
		return ss.taggedOK(tag, "UID FETCH completed")
	}

	wanted := make(map[int]bool, len(numbers))
	for _, n := range numbers {
		wanted[n] = true
	}
	for idx, m := range ss.inbox {
		if !wanted[idx+1] {
			continue
		}
		if !ss.writeFetch(uint32(idx+1), m, items, false) {
			return false
		}
	}
	return ss.taggedOK(tag, "FETCH completed")
}

// fetchKind 是支持的 FETCH 数据项类型。
type fetchKind int

const (
	fetchKindFlags fetchKind = iota
	fetchKindUID
	fetchKindInternalDate
	fetchKindSize
	fetchKindEnvelope
	fetchKindFull
	fetchKindHeader
	fetchKindText
	fetchKindHeaderFields
)

// fetchItem 是一条已解析的 FETCH 数据项。
type fetchItem struct {
	// name 是响应中使用的数据项名（BODY.PEEK 统一输出为 BODY）。
	name string
	// kind 指示数据项类型。
	kind fetchKind
	// headerFields 仅 fetchKindHeaderFields 使用，保持请求顺序。
	headerFields []string
}

// parseFetchItems 解析 FETCH 数据项列表（可有外层括号），展开 FAST/ALL 宏。
// 不支持的数据项（BODYSTRUCTURE、BODY[1]、FULL 宏中的 BODY 等）返回错误。
func parseFetchItems(text string) ([]fetchItem, error) {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "(") && strings.HasSuffix(trimmed, ")") {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	tokens := splitFetchTokens(trimmed)
	if len(tokens) == 0 {
		return nil, errors.New("FETCH requires data items")
	}
	var items []fetchItem
	for _, token := range tokens {
		switch strings.ToUpper(token) {
		case "FAST":
			items = append(items,
				fetchItem{name: "FLAGS", kind: fetchKindFlags},
				fetchItem{name: "INTERNALDATE", kind: fetchKindInternalDate},
				fetchItem{name: "RFC822.SIZE", kind: fetchKindSize},
			)
			continue
		case "ALL":
			items = append(items,
				fetchItem{name: "FLAGS", kind: fetchKindFlags},
				fetchItem{name: "INTERNALDATE", kind: fetchKindInternalDate},
				fetchItem{name: "RFC822.SIZE", kind: fetchKindSize},
				fetchItem{name: "ENVELOPE", kind: fetchKindEnvelope},
			)
			continue
		case "FULL":
			return nil, errors.New("FULL macro is not supported (it requires BODY, which is not implemented)")
		}
		item, err := parseFetchItem(token)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// parseFetchItem 解析单个 FETCH 数据项。partial 后缀（<start.count>）会被忽略并
// 返回完整内容（RFC 允许服务器不支持 partial 时返回完整项而不带 partial 标记）。
func parseFetchItem(token string) (fetchItem, error) {
	text := strings.TrimSpace(token)
	upper := strings.ToUpper(text)
	// 去掉 partial 后缀：形如 BODY[]<0.1024>。
	if i := strings.LastIndexByte(upper, '>'); i == len(upper)-1 {
		if j := strings.LastIndexByte(upper, '<'); j > 0 {
			text = text[:j]
			upper = upper[:j]
		}
	}
	switch upper {
	case "UID":
		return fetchItem{name: "UID", kind: fetchKindUID}, nil
	case "FLAGS":
		return fetchItem{name: "FLAGS", kind: fetchKindFlags}, nil
	case "INTERNALDATE":
		return fetchItem{name: "INTERNALDATE", kind: fetchKindInternalDate}, nil
	case "RFC822.SIZE":
		return fetchItem{name: "RFC822.SIZE", kind: fetchKindSize}, nil
	case "SIZE":
		return fetchItem{name: "SIZE", kind: fetchKindSize}, nil
	case "ENVELOPE":
		return fetchItem{name: "ENVELOPE", kind: fetchKindEnvelope}, nil
	case "RFC822":
		return fetchItem{name: "RFC822", kind: fetchKindFull}, nil
	case "RFC822.HEADER":
		return fetchItem{name: "RFC822.HEADER", kind: fetchKindHeader}, nil
	case "RFC822.TEXT":
		return fetchItem{name: "RFC822.TEXT", kind: fetchKindText}, nil
	}
	if !strings.HasPrefix(upper, "BODY[") && !strings.HasPrefix(upper, "BODY.PEEK[") {
		return fetchItem{}, fmt.Errorf("Unsupported FETCH data item: %s", imapResponseText(token))
	}
	open := strings.IndexByte(text, '[')
	if open < 0 {
		return fetchItem{}, fmt.Errorf("Unsupported FETCH data item: %s", imapResponseText(token))
	}
	closeOffset := strings.IndexByte(text[open:], ']')
	if closeOffset < 0 {
		return fetchItem{}, fmt.Errorf("Malformed FETCH data item: %s", imapResponseText(token))
	}
	closeIdx := open + closeOffset
	if strings.TrimSpace(text[closeIdx+1:]) != "" {
		return fetchItem{}, fmt.Errorf("Unsupported FETCH data item: %s", imapResponseText(token))
	}
	section := text[open+1 : closeIdx]
	switch {
	case section == "":
		return fetchItem{name: "BODY[]", kind: fetchKindFull}, nil
	case strings.EqualFold(section, "HEADER"):
		return fetchItem{name: "BODY[HEADER]", kind: fetchKindHeader}, nil
	case strings.EqualFold(section, "TEXT"):
		return fetchItem{name: "BODY[TEXT]", kind: fetchKindText}, nil
	}
	if strings.HasPrefix(strings.ToUpper(section), "HEADER.FIELDS") {
		fields, err := parseHeaderFieldList(section)
		if err != nil {
			return fetchItem{}, err
		}
		return fetchItem{
			name:         "BODY[HEADER.FIELDS (" + strings.Join(fields, " ") + ")]",
			kind:         fetchKindHeaderFields,
			headerFields: fields,
		}, nil
	}
	return fetchItem{}, fmt.Errorf("Unsupported BODY section: %s (only HEADER, TEXT and HEADER.FIELDS are supported)", imapResponseText(section))
}

// parseHeaderFieldList 解析 "HEADER.FIELDS (FROM TO SUBJECT)" 中的字段列表。
func parseHeaderFieldList(section string) ([]string, error) {
	open := strings.IndexByte(section, '(')
	closeOffset := strings.IndexByte(section, ')')
	if open < 0 || closeOffset < open {
		return nil, errors.New("Malformed BODY[HEADER.FIELDS (...)]: missing field list")
	}
	inner := strings.TrimSpace(section[open+1 : closeOffset])
	if inner == "" {
		return nil, errors.New("BODY[HEADER.FIELDS (...)] requires at least one header field")
	}
	fields := strings.Fields(inner)
	if len(fields) > maxIMAPHeaderFields {
		return nil, fmt.Errorf("BODY[HEADER.FIELDS (...)] accepts at most %d fields", maxIMAPHeaderFields)
	}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		valid := true
		for _, r := range field {
			if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				valid = false
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("Invalid header field name: %s", imapResponseText(field))
		}
		out = append(out, strings.ToUpper(field))
	}
	return out, nil
}

// splitFetchTokens 按空白切分 FETCH 数据项，但不会在方括号内切分
// （例如 BODY[HEADER.FIELDS (FROM TO)] 保持为一个 token），也尊重引号。
func splitFetchTokens(text string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0
	inQuote := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inQuote:
			current.WriteByte(c)
			if c == '\\' && i+1 < len(text) {
				i++
				current.WriteByte(text[i])
				continue
			}
			if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
			current.WriteByte(c)
		case c == '[':
			depth++
			current.WriteByte(c)
		case c == ']':
			if depth > 0 {
				depth--
			}
			current.WriteByte(c)
		case (c == ' ' || c == '\t') && depth == 0:
			flush()
		default:
			current.WriteByte(c)
		}
	}
	flush()
	return tokens
}

// writeFetch 写出一条 "* n FETCH (...)" 响应，包含所需的字面量数据。
func (ss *imapSession) writeFetch(seq uint32, m Message, items []fetchItem, uidMode bool) bool {
	hasUID := false
	for _, item := range items {
		if item.kind == fetchKindUID {
			hasUID = true
		}
	}
	var buf strings.Builder
	fmt.Fprintf(&buf, "* %d FETCH (", seq)
	written := 0
	appendText := func(text string) {
		if written > 0 {
			buf.WriteByte(' ')
		}
		written++
		buf.WriteString(text)
	}
	appendLiteral := func(name string, data []byte) bool {
		if written > 0 {
			buf.WriteByte(' ')
		}
		written++
		fmt.Fprintf(&buf, "%s {%d}\r\n", name, len(data))
		if !ss.writeRaw(buf.String()) {
			return false
		}
		buf.Reset()
		if len(data) == 0 {
			return true
		}
		return ss.writeBytes(data)
	}

	for _, item := range items {
		switch item.kind {
		case fetchKindFlags:
			appendText("FLAGS ()")
		case fetchKindUID:
			appendText(fmt.Sprintf("UID %d", messageUID(m)))
		case fetchKindInternalDate:
			appendText("INTERNALDATE " + imapQuote(imapInternalDate(m.ReceivedAt)))
		case fetchKindSize:
			appendText(item.name + " " + strconv.Itoa(len(m.Data)))
		case fetchKindEnvelope:
			appendText("ENVELOPE " + imapEnvelope(m))
		case fetchKindFull:
			if !appendLiteral(item.name, m.Data) {
				return false
			}
		case fetchKindHeader:
			if !appendLiteral(item.name, m.HeaderBlock()) {
				return false
			}
		case fetchKindText:
			if !appendLiteral(item.name, m.Body()) {
				return false
			}
		case fetchKindHeaderFields:
			if !appendLiteral(item.name, headerFieldsBlock(m, item.headerFields)) {
				return false
			}
		}
	}
	if uidMode && !hasUID {
		appendText(fmt.Sprintf("UID %d", messageUID(m)))
	}
	buf.WriteString(")\r\n")
	return ss.writeRaw(buf.String())
}

// headerFieldsBlock 按请求的字段生成头部块（每个字段一行，末尾空行 CRLF）。
// 数据来自 SMTP 捕获时解析出的头部（折行已展开），因此可能与原始折行字节不同；
// BODY[HEADER] 仍返回原始字节。
func headerFieldsBlock(m Message, fields []string) []byte {
	wanted := make(map[string]bool, len(fields))
	for _, field := range fields {
		wanted[strings.ToUpper(field)] = true
	}
	var b strings.Builder
	for _, header := range m.Headers {
		if !wanted[strings.ToUpper(header.Name)] {
			continue
		}
		b.WriteString(header.Name)
		b.WriteString(": ")
		b.WriteString(header.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// imapInternalDate 格式化 IMAP INTERNALDATE：固定英文月份与带符号时区。
func imapInternalDate(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.Format("02-Jan-2006 15:04:05 -0700")
}

// imapEnvelope 由消息头部生成 IMAP ENVELOPE。解析失败或缺失的字段用 NIL 表示，
// 不伪造数据；Subject/Date 使用原始头部值（未做 RFC 2047 解码）。
func imapEnvelope(m Message) string {
	date := "NIL"
	if value, ok := m.Header("Date"); ok && strings.TrimSpace(value) != "" {
		date = imapNString(value)
	}
	subject := "NIL"
	if value, ok := m.Header("Subject"); ok {
		subject = imapNString(value)
	}
	from := imapAddressList(m.HeaderValues("From"))
	sender := from
	if values := m.HeaderValues("Sender"); len(values) > 0 {
		sender = imapAddressList(values)
	}
	replyTo := from
	if values := m.HeaderValues("Reply-To"); len(values) > 0 {
		replyTo = imapAddressList(values)
	}
	to := imapAddressList(m.HeaderValues("To"))
	cc := imapAddressList(m.HeaderValues("Cc"))
	bcc := imapAddressList(m.HeaderValues("Bcc"))
	inReplyTo := "NIL"
	if value, ok := m.Header("In-Reply-To"); ok {
		inReplyTo = imapNString(value)
	}
	messageID := "NIL"
	if value, ok := m.Header("Message-ID"); ok {
		messageID = imapNString(value)
	}
	return "(" + strings.Join([]string{
		date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID,
	}, " ") + ")"
}

// imapAddressList 把一组头部值解析成 IMAP 地址列表；无法解析时返回 NIL。
func imapAddressList(values []string) string {
	var addrs []string
	for _, value := range values {
		addrs = append(addrs, parseAddressListLenient(value)...)
	}
	if len(addrs) == 0 {
		return "NIL"
	}
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, imapAddress(addr))
	}
	return "(" + strings.Join(parts, " ") + ")"
}

// imapAddress 把单个邮件地址转换成 IMAP 地址结构 (name adl mailbox host)。
func imapAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	name, mailbox, host := "NIL", addr, "NIL"
	if parsed, err := mail.ParseAddress(addr); err == nil {
		if parsed.Name != "" {
			name = imapNString(parsed.Name)
		}
		mailbox = parsed.Address
	}
	if i := strings.LastIndexByte(mailbox, '@'); i > 0 {
		host = imapNString(mailbox[i+1:])
		mailbox = mailbox[:i]
	}
	return "(" + name + " NIL " + imapNString(mailbox) + " " + host + ")"
}

// imapNString 返回 IMAP nstring：空值用 NIL，否则用带引号转义的字符串。
func imapNString(value string) string {
	if value == "" {
		return "NIL"
	}
	return imapQuote(value)
}

// imapQuote 把文本转成 IMAP 带引号字符串，转义反斜杠与双引号，并把 CR/LF 替换为
// 空格，避免头部中的控制字符破坏协议行结构。
func imapQuote(value string) string {
	return `"` + imapEscapeQuoted(value) + `"`
}

// imapEscapeQuoted 转义 quoted string 内容。
func imapEscapeQuoted(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 8)
	for _, r := range value {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\r', '\n':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// imapResponseText 清洗应答文本：去掉 CR/LF，防止把客户端输入原样回显时破坏协议。
func imapResponseText(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

// splitIMAPCommand 把一行拆成 tag、命令动词与剩余参数。
func splitIMAPCommand(line string) (tag, verb, rest string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", ""
	}
	tag, remainder := splitFirstWord(trimmed)
	verb, rest = splitFirstWord(remainder)
	return tag, verb, rest
}

// splitFirstWord 以第一段空白切开字符串并去掉两侧空白。
func splitFirstWord(s string) (first, rest string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// validIMAPTag 校验命令 tag 是合法 atom，防止回显非法/超长内容。
func validIMAPTag(tag string) bool {
	if tag == "" || len(tag) > 64 {
		return false
	}
	for _, r := range tag {
		if r <= 0x20 || r >= 0x7f {
			return false
		}
		if strings.ContainsRune(`(){%*"\]`, r) {
			return false
		}
	}
	return true
}

// imapTokens 把参数文本切分成 token：支持带转义的 quoted string 与普通 atom。
// 字面量已在 readCommand 中转换成 quoted string，因此这里不需要再处理 {n}。
func imapTokens(s string) []string {
	var tokens []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			i++
			var b strings.Builder
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '"' {
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			tokens = append(tokens, b.String())
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		tokens = append(tokens, s[start:i])
	}
	return tokens
}

// imapPatternMatches 判断 LIST/LSUB 的通配模式是否匹配邮箱名。'*' 匹配任意字符，
// '%' 匹配除层级分隔符 '/' 以外的任意字符；INBOX 按协议不区分大小写比较。
func imapPatternMatches(pattern, name string) bool {
	if strings.EqualFold(pattern, name) {
		return true
	}
	return imapGlob(pattern, name, 0, 0)
}

// imapGlob 是支持 '*' 与 '%' 的递归匹配实现（INBOX 名称很短，无需优化）。
func imapGlob(pattern, name string, pi, ni int) bool {
	for pi < len(pattern) {
		switch pattern[pi] {
		case '*':
			for k := ni; k <= len(name); k++ {
				if imapGlob(pattern, name, pi+1, k) {
					return true
				}
			}
			return false
		case '%':
			for k := ni; k <= len(name); k++ {
				if k > ni && name[k-1] == '/' {
					break
				}
				if imapGlob(pattern, name, pi+1, k) {
					return true
				}
			}
			return false
		default:
			if ni >= len(name) || !strings.EqualFold(string(pattern[pi]), string(name[ni])) {
				return false
			}
			pi++
			ni++
		}
	}
	return ni == len(name)
}

// parseIMAPSeqSet 解析消息集合（如 "1,3:5,7:*"），返回升序去重的编号。
// max 是 '*' 的含义：序列号模式为邮箱条数，UID 模式为最大 UID。
func parseIMAPSeqSet(spec string, max int) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty message set")
	}
	seen := make(map[int]bool)
	var out []int
	addRange := func(lo, hi int) error {
		if hi < lo {
			lo, hi = hi, lo
		}
		if lo < 1 {
			lo = 1
		}
		if hi < 1 {
			return nil
		}
		if hi-lo+1 > maxIMAPSeqSetExpansion {
			return errors.New("message set is too large")
		}
		for n := lo; n <= hi; n++ {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		return nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid message set: %s", imapResponseText(spec))
		}
		loText, hiText, isRange := strings.Cut(part, ":")
		lo, err := parseIMAPSeqNumber(loText, max)
		if err != nil {
			return nil, err
		}
		hi := lo
		if isRange {
			if hi, err = parseIMAPSeqNumber(hiText, max); err != nil {
				return nil, err
			}
		}
		if err := addRange(lo, hi); err != nil {
			return nil, err
		}
	}
	sort.Ints(out)
	return out, nil
}

// parseIMAPSeqNumber 解析单个消息编号；'*' 表示 max（无消息时为 0）。
func parseIMAPSeqNumber(text string, max int) (int, error) {
	text = strings.TrimSpace(text)
	if text == "*" {
		return max, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("invalid message number: %s", imapResponseText(text))
	}
	return n, nil
}

// readLine 读取一行（不含 CRLF）。单行超过 maxLineBytes 时返回 errLineTooLong。
func (ss *imapSession) readLine() (string, error) {
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

// readFull 读取恰好 len(buf) 字节的字面量内容。
func (ss *imapSession) readFull(buf []byte) error {
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	if err := ss.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	_, err := io.ReadFull(ss.reader, buf)
	return err
}

// writeDeadline 返回写入截止时间：单次读取超时与会话总时长取较早者。
func (ss *imapSession) writeDeadline() time.Time {
	deadline := time.Now().Add(ss.srv.opts.ReadTimeout)
	if deadline.After(ss.sessionEnd) {
		deadline = ss.sessionEnd
	}
	return deadline
}

// writeRaw 写入并刷新一段文本；写失败表示连接已不可用。
func (ss *imapSession) writeRaw(text string) bool {
	_ = ss.conn.SetWriteDeadline(ss.writeDeadline())
	if _, err := ss.writer.WriteString(text); err != nil {
		return false
	}
	return ss.writer.Flush() == nil
}

// writeBytes 写入并刷新一段原始字节（IMAP 字面量）。
func (ss *imapSession) writeBytes(data []byte) bool {
	_ = ss.conn.SetWriteDeadline(ss.writeDeadline())
	if _, err := ss.writer.Write(data); err != nil {
		return false
	}
	return ss.writer.Flush() == nil
}

// writeLine 写入一行并追加 CRLF。
func (ss *imapSession) writeLine(line string) bool {
	return ss.writeRaw(line + "\r\n")
}

// taggedOK 回复带 tag 的 OK 响应。
func (ss *imapSession) taggedOK(tag, text string) bool {
	return ss.writeLine(tag + " OK " + imapResponseText(text))
}

// taggedNo 回复带 tag 的 NO 响应。
func (ss *imapSession) taggedNo(tag, text string) bool {
	return ss.writeLine(tag + " NO " + imapResponseText(text))
}

// taggedBad 回复带 tag 的 BAD 响应。
func (ss *imapSession) taggedBad(tag, text string) bool {
	return ss.writeLine(tag + " BAD " + imapResponseText(text))
}
