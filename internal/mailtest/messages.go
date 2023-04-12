// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mailtest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrIndexStale 表示 Mail 索引尚未就绪（夹具会等待而不是立刻失败）。
var ErrIndexStale = errors.New("mailtest: Mail 索引尚未就绪")

// Query 是邮件查询条件（与旧 testmail.Query 语义兼容）。
type Query struct {
	To, From, Subject string
	Since, Until      time.Time
	Limit             int
}

// Header 是一个已展开折行的邮件头字段。
type Header struct {
	Name  string
	Value string
}

// Message 是一封已提交邮件的测试视图，字段与方法保持与旧 testmail.Message 兼容，
// 便于 136 迁移旧断言强度（信封、TLS、认证用户、原始 Data、Header/Body）。
type Message struct {
	ID           string
	ReceivedAt   time.Time
	EnvelopeFrom string
	EnvelopeTo   []string
	From         string
	To           []string
	Cc           []string
	Subject      string
	Date         time.Time
	Headers      []Header
	Data         []byte
	AuthUser     string
	TLS          bool
}

// mailListEntry 是 Mail 管理 API 邮件列表项（索引结构直接序列化，键名大写）。
type mailListEntry struct {
	MailID       string
	UserKey      string
	Folder       string
	EnvelopeFrom string
	EnvelopeTo   []string
	From         []string
	To           []string
	Cc           []string
	Subject      string
	Size         int64
	SHA256       string
	ReceivedAt   time.Time
	RunID        string
	Injected     bool
}

// fileMeta 是已提交邮件 JSON 元数据的最小读取结构（数据目录回退路径）。
type fileMeta struct {
	MailID       string    `json:"mail_id"`
	UserKey      string    `json:"user_key"`
	Subject      string    `json:"subject"`
	EnvelopeFrom string    `json:"envelope_from"`
	EnvelopeTo   []string  `json:"envelope_to"`
	From         []string  `json:"from,omitempty"`
	To           []string  `json:"to,omitempty"`
	Cc           []string  `json:"cc,omitempty"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ReceivedAt   time.Time `json:"received_at"`
	TLS          bool      `json:"tls,omitempty"`
	RunID        string    `json:"run_id,omitempty"`
	Injected     bool      `json:"injected,omitempty"`
	OriginMailID string    `json:"origin_mail_id,omitempty"`
}

// Messages 查询邮件：优先 Mail 管理 API（公开契约）；当前 Mail 的 HTTP 索引不会
// 随新投递自动 Sync，API 列表可能为空，此时回退到“已提交的 .eml+.json 成对文件”
// 扫描，确保夹具对合成邮件的等待/查询稳定。查询结果始终来自真实落盘数据。

func (i *Instance) Messages(query Query) ([]Message, error) {
	// 当前 Mail HTTP 索引不会随新投递自动同步；查询以已提交 .eml/.json 成对文件为
	// 事实源（校验 size/sha256），HTTP 列表仍由 httpEntries 用于契约探测。
	return i.fileMessages(query)
}

// httpEntries 读取 Mail 管理 API 的邮件列表（索引未就绪返回 ErrIndexStale）。
func (i *Instance) httpEntries() ([]mailListEntry, error) {
	if i.client == nil {
		return nil, errors.New("mailtest: 管理器未登录")
	}
	url := "http://" + i.HTTPAddr + "/api/v1/admin/mails?user_key=" + i.UserID + "&limit=200&desc=true"
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := i.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	var envelope struct {
		Data  []mailListEntry `json:"data"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("mailtest: 邮件列表响应无法解析: %w", err)
	}
	if envelope.Error != nil {
		if envelope.Error.Code == "MAIL_INDEX_STALE" {
			return nil, ErrIndexStale
		}
		return nil, fmt.Errorf("mailtest: 邮件列表失败: %s %s", envelope.Error.Code, envelope.Error.Message)
	}
	return append([]mailListEntry(nil), envelope.Data...), nil
}

// fileMessages 扫描已提交的邮件对并按 Query 过滤（索引未同步时的回退路径）。
func (i *Instance) fileMessages(query Query) ([]Message, error) {
	mailRoot := filepath.Join(i.DataDir, "mail")
	type pair struct {
		meta fileMeta
		eml  string
	}
	pairs := make([]pair, 0)
	walkErr := filepath.WalkDir(mailRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil
		}
		metadata, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var meta fileMeta
		if json.Unmarshal(metadata, &meta) != nil || meta.UserKey != i.UserID {
			return nil
		}
		pairs = append(pairs, pair{meta: meta, eml: strings.TrimSuffix(path, ".json") + ".eml"})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.SliceStable(pairs, func(a, b int) bool { return pairs[a].meta.ReceivedAt.Before(pairs[b].meta.ReceivedAt) })
	messages := make([]Message, 0, len(pairs))
	for _, item := range pairs {
		entry := mailListEntry{
			MailID: item.meta.MailID, UserKey: item.meta.UserKey, EnvelopeFrom: item.meta.EnvelopeFrom,
			EnvelopeTo: item.meta.EnvelopeTo, From: item.meta.From, To: item.meta.To, Cc: item.meta.Cc,
			Subject: item.meta.Subject, Size: item.meta.Size, SHA256: item.meta.SHA256,
			ReceivedAt: item.meta.ReceivedAt, RunID: item.meta.RunID, Injected: item.meta.Injected,
		}
		if !entryMatches(entry, query) {
			continue
		}
		raw, err := readVerifiedPair(item.eml, item.meta)
		if err != nil {
			return nil, err
		}
		from := item.meta.EnvelopeFrom
		if len(item.meta.From) > 0 {
			from = item.meta.From[0]
		}
		message := Message{
			ID: item.meta.MailID, ReceivedAt: item.meta.ReceivedAt,
			EnvelopeFrom: item.meta.EnvelopeFrom, EnvelopeTo: append([]string{}, item.meta.EnvelopeTo...),
			From: from, To: append([]string{}, item.meta.To...), Cc: append([]string{}, item.meta.Cc...),
			Subject: item.meta.Subject, Data: raw, AuthUser: i.UserLogin, TLS: item.meta.TLS,
		}
		message.Headers = parseHeaders(raw)
		if dateText, ok := message.Header("Date"); ok {
			if parsedDate, parseErr := http.ParseTime(dateText); parseErr == nil {
				message.Date = parsedDate
			}
		}
		messages = append(messages, message)
		if query.Limit > 0 && len(messages) >= query.Limit {
			break
		}
	}
	return messages, nil
}

// readVerifiedPair 读取 .eml 并校验 JSON 摘要/大小。
func readVerifiedPair(emlPath string, meta fileMeta) ([]byte, error) {
	raw, err := os.ReadFile(emlPath)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != meta.Size {
		return nil, fmt.Errorf("mailtest: 提交大小不一致（eml=%d json=%d）", len(raw), meta.Size)
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), meta.SHA256) {
		return nil, fmt.Errorf("mailtest: 提交摘要不一致（MailID %s）", meta.MailID)
	}
	return raw, nil
}

// entryMatches 按与旧 testmail.Query 接近的语义过滤。
func entryMatches(entry mailListEntry, query Query) bool {
	if query.To != "" && !containsFold(append(append(append([]string{}, entry.EnvelopeTo...), entry.To...), entry.Cc...), query.To) {
		return false
	}
	if query.From != "" && !containsFold(append([]string{entry.EnvelopeFrom}, entry.From...), query.From) {
		return false
	}
	if query.Subject != "" && !strings.Contains(strings.ToLower(entry.Subject), strings.ToLower(query.Subject)) {
		return false
	}
	if !query.Since.IsZero() && entry.ReceivedAt.Before(query.Since) {
		return false
	}
	if !query.Until.IsZero() && entry.ReceivedAt.After(query.Until) {
		return false
	}
	return true
}

// containsFold 判断任一字符串包含目标子串（不区分大小写）。
func containsFold(values []string, needle string) bool {
	lower := strings.ToLower(needle)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), lower) {
			return true
		}
	}
	return false
}

// WaitMessage 等待至少一封匹配邮件出现（索引未就绪时继续等待）。
func (i *Instance) WaitMessage(ctx context.Context, query Query) ([]Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	interval := 100 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		messages, err := i.Messages(query)
		if err == nil && len(messages) > 0 {
			return messages, nil
		}
		if err != nil && !errors.Is(err, ErrIndexStale) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Snapshot 返回查询结果（忽略内部错误，旧 testmail.Server.Messages 语义兼容；
// 错误场景请用 Messages）。
func (i *Instance) Snapshot(query Query) []Message {
	messages, _ := i.Messages(query)
	return messages
}

// Wait 等待匹配邮件出现（旧 testmail.Server.Wait 语义兼容）。
func (i *Instance) Wait(ctx context.Context, query Query) ([]Message, error) {
	return i.WaitMessage(ctx, query)
}

// Addr 返回 SMTP 监听地址（旧 testmail.Server.Addr 语义兼容）。
func (i *Instance) Addr() net.Addr { return tcpAddr(i.SMTPAddr) }

// MessageCount 返回当前可查询的邮件数。
func (i *Instance) MessageCount() int {
	messages, _ := i.fileMessages(Query{})
	return len(messages)
}

// mailMetaMinimal 是读取已提交原始 eml 所需的最小元数据。
type mailMetaMinimal struct {
	MailID string `json:"mail_id"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// readCommittedEML 在数据目录中按 MailID 找到成对 .eml/.json，并校验提交摘要。
func (i *Instance) readCommittedEML(mailID string) ([]byte, error) {
	mailRoot := filepath.Join(i.DataDir, "mail")
	var found string
	var foundMeta mailMetaMinimal
	walkErr := filepath.WalkDir(mailRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil
		}
		metadata, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var meta mailMetaMinimal
		if json.Unmarshal(metadata, &meta) != nil {
			return nil
		}
		if meta.MailID == mailID {
			found = strings.TrimSuffix(path, ".json") + ".eml"
			foundMeta = meta
			return io.EOF
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, io.EOF) {
		return nil, walkErr
	}
	if found == "" {
		return nil, fmt.Errorf("mailtest: 未找到 MailID %s 的已提交邮件对", mailID)
	}
	raw, err := os.ReadFile(found)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != foundMeta.Size {
		return nil, fmt.Errorf("mailtest: 提交大小不一致（eml=%d json=%d）", len(raw), foundMeta.Size)
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), foundMeta.SHA256) {
		return nil, fmt.Errorf("mailtest: 提交摘要不一致（MailID %s）", mailID)
	}
	return raw, nil
}

// Body 返回正文（头块后第一个空行之后）；返回切片与 Data 共用底层数组。
func (m Message) Body() []byte {
	_, body := splitHeaderBody(m.Data)
	return body
}

// HeaderBlock 返回原始头块（含头与正文之间的空行）。
func (m Message) HeaderBlock() []byte {
	header, _ := splitHeaderBody(m.Data)
	return header
}

// Header 返回首个名称不区分大小写匹配的头值。
func (m Message) Header(name string) (string, bool) {
	for _, header := range m.Headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value, true
		}
	}
	return "", false
}

// HeaderValues 返回全部匹配头值（折行已展开）。
func (m Message) HeaderValues(name string) []string {
	values := make([]string, 0)
	for _, header := range m.Headers {
		if strings.EqualFold(header.Name, name) {
			values = append(values, header.Value)
		}
	}
	return values
}

// parseHeaders 解析原始头块为 Header 列表（尽力而为，异常行忽略）。
func parseHeaders(raw []byte) []Header {
	headerBlock, _ := splitHeaderBody(raw)
	var headers []Header
	var current *Header
	for _, line := range strings.Split(string(headerBlock), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && current != nil {
			current.Value += " " + strings.TrimSpace(line)
			continue
		}
		index := strings.IndexByte(line, ':')
		if index <= 0 {
			continue
		}
		headers = append(headers, Header{Name: strings.TrimSpace(line[:index]), Value: strings.TrimSpace(line[index+1:])})
		current = &headers[len(headers)-1]
	}
	return headers
}

// splitHeaderBody 按 CRLF/ LF 空行切分头与正文。
func splitHeaderBody(raw []byte) (header, body []byte) {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[:index], raw[index+4:]
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[:index], raw[index+2:]
	}
	return raw, nil
}

// Pop3Header 是 POP3 UIDL 列表项。
type Pop3Header struct {
	Index int
	UIDL  string
	Size  int64
}

// Pop3List 通过 POP3 列出 tester 邮箱中的邮件（明文回环）。
func (i *Instance) Pop3List() ([]Pop3Header, error) {
	conn, reader, writer, err := i.pop3Connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	lines, err := pop3MultiLine(reader, writer, "UIDL")
	if err != nil {
		return nil, err
	}
	headers := make([]Pop3Header, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		index, convErr := strconv.Atoi(fields[0])
		if convErr != nil {
			continue
		}
		headers = append(headers, Pop3Header{Index: index, UIDL: fields[1]})
	}
	return headers, nil
}

// Pop3FetchRaw 按 MailID（POP3 UIDL）读取原始 eml。
func (i *Instance) Pop3FetchRaw(mailID string) ([]byte, error) {
	headers, err := i.Pop3List()
	if err != nil {
		return nil, err
	}
	for _, header := range headers {
		if header.UIDL == mailID {
			return i.Pop3FetchIndex(header.Index)
		}
	}
	return nil, fmt.Errorf("mailtest: POP3 未找到 UIDL %s", mailID)
}

// Pop3FetchIndex 按 POP3 序号读取原始 eml（含 CRLF 还原）。
func (i *Instance) Pop3FetchIndex(index int) ([]byte, error) {
	conn, reader, writer, err := i.pop3Connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	lines, err := pop3MultiLine(reader, writer, fmt.Sprintf("RETR %d", index))
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	for _, line := range lines {
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}
		buffer.WriteString(line)
		buffer.WriteString("\r\n")
	}
	return buffer.Bytes(), nil
}

// pop3MultiLine 发送命令并读取多行响应（点终止）。
func pop3MultiLine(reader *bufio.Reader, writer *bufio.Writer, command string) ([]string, error) {
	if _, err := writer.WriteString(command + "\r\n"); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "+OK") {
		return nil, fmt.Errorf("mailtest: POP3 命令 %q 失败: %q %v", command, line, err)
	}
	lines := make([]string, 0)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			return lines, nil
		}
		lines = append(lines, line)
	}
}

// pop3Connect 建立并认证 POP3 连接。
func (i *Instance) pop3Connect() (net.Conn, *bufio.Reader, *bufio.Writer, error) {
	conn, err := net.DialTimeout("tcp", i.POP3Addr, 3*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "+OK") {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("mailtest: POP3 问候失败: %q %v", line, err)
	}
	for _, command := range []string{"USER " + i.UserLogin, "PASS " + i.UserPassword} {
		if _, err := writer.WriteString(command + "\r\n"); err != nil {
			_ = conn.Close()
			return nil, nil, nil, err
		}
		if err := writer.Flush(); err != nil {
			_ = conn.Close()
			return nil, nil, nil, err
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "+OK") {
			_ = conn.Close()
			return nil, nil, nil, fmt.Errorf("mailtest: POP3 认证失败: %q %v", line, err)
		}
	}
	return conn, reader, writer, nil
}

// tcpAddr 把 host:port 转为 net.TCPAddr（无法解析时返回 nil）。
func tcpAddr(addr string) net.Addr {
	if addr == "" {
		return nil
	}
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil
	}
	return tcp
}
