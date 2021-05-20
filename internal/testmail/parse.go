package testmail

import (
	"bytes"
	"mime"
	"net/mail"
	"strings"
	"time"
)

// headerDecoder 用于 RFC 2047 编码字（=?UTF-8?B?...?= 等）的尽力解码。标准库
// 的默认解码器只处理 UTF-8 与可直接解释的字符集；遇到其他字符集或损坏的编码字
// 时保留原文，不因为一个头部无法解码就拒绝整封邮件。
var headerDecoder = mime.WordDecoder{}

// decodeHeader 尽力解码头部值；失败时返回原文。
func decodeHeader(v string) string {
	decoded, err := headerDecoder.DecodeHeader(v)
	if err != nil {
		return v
	}
	return decoded
}

// parseReceived 解析收到的原始消息字节，返回头部集合、主题、日期与正文偏移。
//
// 解析是宽松的：头部行缺少冒号、折行出现在第一个头部之前、缺少头部/正文分隔空行
// 等异常都不会返回错误，只会让对应字段缺失，从而保证"任何可接收的字节都能保存"。
func parseReceived(data []byte) (headers []Header, subject string, date time.Time, bodyOffset int) {
	sep := bytes.Index(data, []byte("\r\n\r\n"))
	var headerBlock []byte
	switch {
	case sep >= 0:
		headerBlock = data[:sep]
		bodyOffset = sep + 4
	case len(data) == 0:
		return nil, "", time.Time{}, 0
	default:
		// 没有头部/正文分隔空行时，把全部内容当作头部处理；正文为空。
		headerBlock = bytes.TrimSuffix(data, []byte("\r\n"))
		bodyOffset = len(data)
	}

	lines := bytes.Split(headerBlock, []byte("\r\n"))
	for _, raw := range lines {
		line := string(raw)
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// 折行：并入上一个头部值，用一个空格连接。
			if len(headers) == 0 {
				continue
			}
			headers[len(headers)-1].Value += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "" {
			continue
		}
		headers = append(headers, Header{Name: name, Value: strings.TrimSpace(line[idx+1:])})
	}

	for _, h := range headers {
		switch {
		case subject == "" && strings.EqualFold(h.Name, "Subject"):
			subject = decodeHeader(h.Value)
		case date.IsZero() && strings.EqualFold(h.Name, "Date"):
			if parsed, err := mail.ParseDate(h.Value); err == nil {
				date = parsed
			}
		}
	}
	return headers, subject, date, bodyOffset
}

// parsePath 从 MAIL FROM / RCPT TO 参数中提取地址。
//
// 同时容忍 "FROM:<a@b>"、"FROM: <a@b>"、"FROM: a@b" 三种写法，并忽略地址之后
// 的 ESMTP 参数（如 SIZE=123、BODY=8BITMIME）。prefix 是字母部分（"FROM:" 或
// "TO:"），比较不区分大小写。语法损坏时 ok 为 false。
func parsePath(arg, prefix string) (addr string, ok bool) {
	trimmed := strings.TrimSpace(arg)
	if len(trimmed) < len(prefix) || !strings.EqualFold(trimmed[:len(prefix)], prefix) {
		return "", false
	}
	rest := strings.TrimSpace(trimmed[len(prefix):])
	if rest == "" {
		return "", false
	}
	if rest[0] != '<' {
		// 无尖括号写法：地址到第一个空白为止。
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			rest = rest[:i]
		}
		return rest, true
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return "", false
	}
	return rest[1:end], true
}

// validAddress 校验信封地址。allowEmpty 为 true 时接受空地址（MAIL FROM:<> 的
// 空发送者，用于退信）。这里只做基本的语法与长度检查，不解析 DNS，也不要求域名
// 存在——测试邮件服务器必须能接收任意测试域名。
func validAddress(addr string, allowEmpty bool) bool {
	if addr == "" {
		return allowEmpty
	}
	if len(addr) > maxAddressBytes {
		return false
	}
	for _, r := range addr {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.ContainsAny(addr, "<>") {
		return false
	}
	if i := strings.IndexByte(addr, '@'); i >= 0 {
		if strings.Count(addr, "@") != 1 || i == 0 || i == len(addr)-1 {
			return false
		}
	}
	return true
}
