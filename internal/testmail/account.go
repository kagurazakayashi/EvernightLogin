package testmail

import (
	"net/mail"
	"regexp"
	"strconv"
	"strings"
)

// 账户收件箱可见性规则。
//
// 测试邮件服务器没有真实投递系统：一封邮件是否属于某个模拟账户由收件人决定。
// 规则如下（任一命中的账户都能在 IMAP/POP3 中看到这封邮件）：
//   - SMTP 信封收件人（RCPT TO）的本地部分等于模拟账户用户名，例如账户
//     "tester" 能看到 RCPT TO:<tester@example.test> 与 <tester>；
//   - 头部 To / Cc / Bcc 中任一地址的本地部分等于模拟账户用户名（Bcc 通常不
//     写入邮件头部，但测试发送方可能显式写入）。
//
// 未命中的账户完全看不到该邮件（EXISTS 计数、STAT 数量与 FETCH/RETR 都不包含），
// 避免多账户测试时互相泄露内容。用户名本身含 "@" 时按完整地址比较。

// accountInbox 返回指定模拟账户的收件箱快照（按接收顺序，即消息编号升序）。
func (s *Server) accountInbox(user string) []Message {
	all := s.store.query(Query{})
	inbox := make([]Message, 0, len(all))
	for _, m := range all {
		if messageVisibleTo(m, user) {
			inbox = append(inbox, m)
		}
	}
	return inbox
}

// messageVisibleTo 判断一封邮件是否对指定模拟账户可见。
func messageVisibleTo(m Message, user string) bool {
	if user == "" {
		return false
	}
	for _, rcpt := range m.EnvelopeTo {
		if addressMatchesAccount(rcpt, user) {
			return true
		}
	}
	for _, field := range [...]string{"To", "Cc", "Bcc"} {
		for _, value := range m.HeaderValues(field) {
			for _, addr := range parseAddressListLenient(value) {
				if addressMatchesAccount(addr, user) {
					return true
				}
			}
		}
	}
	return false
}

// addressMatchesAccount 判断邮件地址是否属于账户。账户名不含 "@" 时比较地址的
// 本地部分（@ 之前），账户名本身是邮件地址时只做完整比较。
func addressMatchesAccount(addr, user string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || user == "" {
		return false
	}
	if strings.EqualFold(addr, user) {
		return true
	}
	if strings.Contains(user, "@") {
		return false
	}
	if i := strings.LastIndexByte(addr, '@'); i > 0 {
		return strings.EqualFold(addr[:i], user)
	}
	return false
}

// parseAddressListLenient 尽力解析头部地址列表。格式损坏时退化为按逗号切分并去掉
// 尖括号与显示名的简单解析，保证一封头部不规范的测试邮件不会导致整封邮件不可见。
func parseAddressListLenient(value string) []string {
	parsed, err := mail.ParseAddressList(value)
	if err == nil {
		addrs := make([]string, 0, len(parsed))
		for _, addr := range parsed {
			addrs = append(addrs, addr.Address)
		}
		return addrs
	}
	var addrs []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if start := strings.LastIndexByte(part, '<'); start >= 0 {
			if end := strings.IndexByte(part[start:], '>'); end > 0 {
				addrs = append(addrs, strings.TrimSpace(part[start+1:start+end]))
				continue
			}
		}
		if matched := simpleAddress.FindString(part); matched != "" {
			addrs = append(addrs, matched)
		}
	}
	return addrs
}

// simpleAddress 匹配一个不带尖括号与显示名的邮件地址，用于宽松解析退化路径。
var simpleAddress = regexp.MustCompile(`[^\s<>,"]+@[^\s<>,"]+`)

// messageUID 返回消息在 IMAP 中的 UID。消息编号由内存仓库单调递增分配且永不
// 复用，因此直接作为 UID 使用；解析失败（不应发生）时返回 0，调用方会跳过该消息，
// 避免返回非法 UID 0。
func messageUID(m Message) uint32 {
	n, err := strconv.ParseUint(m.ID, 10, 32)
	if err != nil || n == 0 {
		return 0
	}
	return uint32(n)
}
