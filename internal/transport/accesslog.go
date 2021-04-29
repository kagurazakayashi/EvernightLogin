package transport

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// accessLogFields 是 W3C Extended 访问日志字段列表。刻意不包含
	// cs-uri-query：查询参数可能含令牌、验证码或其他敏感值，整体省略；认证头、
	// Cookie 与请求正文也从不记录。
	accessLogFields = "date time c-ip cs-method cs-uri-stem sc-status sc-bytes cs-bytes " +
		"time-taken cs-version cs(User-Agent) cs(Referer) x-request-id x-error-code"
	// accessLogHeaderVersion 是 W3C Extended 日志版本行。
	accessLogHeaderVersion = "#Version: 1.0"
	// maxAccessLogValueBytes 是单个日志字段转义后的长度上限。
	maxAccessLogValueBytes = 512
)

// accessEntry 是一次请求的访问日志记录；字段值由调用方提供原始值，写出前统一
// 做 W3C 转义与截断。
type accessEntry struct {
	started       time.Time
	finished      time.Time
	remoteAddr    string
	method        string
	path          string
	status        int
	responseBytes int64
	requestBytes  int64
	protocol      string
	userAgent     string
	referer       string
	requestID     string
	errorCode     string
}

// accessLog 串行写 W3C Extended 日志。写入失败只调用告警回调，不改变响应，也
// 不写入安全审计；访问日志与安全审计保持分离。
type accessLog struct {
	mu            sync.Mutex
	writer        io.Writer
	headerWritten bool
	alert         func(error)
}

// newAccessLog 构造访问日志写入器；writer 为 nil 时禁用（不生成任何输出）。
func newAccessLog(writer io.Writer, alert func(error)) *accessLog {
	return &accessLog{writer: writer, alert: alert}
}

// log 写入一条访问日志。header 在第一次写入时输出，便于按文件滚动后仍可解析。
func (l *accessLog) log(entry accessEntry) {
	if l == nil || l.writer == nil {
		return
	}
	line := formatAccessEntry(entry)
	l.mu.Lock()
	defer l.mu.Unlock()
	var buffer strings.Builder
	if !l.headerWritten {
		buffer.WriteString(accessLogHeaderVersion)
		buffer.WriteByte('\n')
		buffer.WriteString("#Fields: ")
		buffer.WriteString(accessLogFields)
		buffer.WriteByte('\n')
		l.headerWritten = true
	}
	buffer.WriteString(line)
	if _, err := io.WriteString(l.writer, buffer.String()); err != nil {
		if l.alert != nil {
			// 告警回调来自宿主，可能 panic；隔离它，避免访问日志故障破坏响应。
			func() {
				defer func() { _ = recover() }()
				l.alert(err)
			}()
		}
	}
}

// sanitizeReferer 只保留 Referer 的来源与路径，去掉查询串与片段：Referer 的
// 查询参数同样可能携带令牌或验证码，不能因为它是请求头就原样进日志。无法解析
// 的值输出 "-"。
func sanitizeReferer(referer string) string {
	if referer == "" {
		return ""
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "-"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
}

// formatAccessEntry 把一次请求格式化为单行 W3C Extended 记录。
func formatAccessEntry(entry accessEntry) string {
	finished := entry.finished.UTC()
	var builder strings.Builder
	builder.Grow(256)
	writeField := func(value string) {
		builder.WriteByte(' ')
		builder.WriteString(w3cToken(value, maxAccessLogValueBytes))
	}
	builder.WriteString(finished.Format("2006-01-02"))
	builder.WriteByte(' ')
	builder.WriteString(finished.Format("15:04:05"))
	writeField(remoteHost(entry.remoteAddr))
	writeField(entry.method)
	writeField(entry.path)
	writeField(strconv.Itoa(entry.status))
	writeField(strconv.FormatInt(entry.responseBytes, 10))
	if entry.requestBytes >= 0 {
		writeField(strconv.FormatInt(entry.requestBytes, 10))
	} else {
		writeField("-")
	}
	writeField(strconv.FormatInt(entry.finished.Sub(entry.started).Milliseconds(), 10))
	writeField(entry.protocol)
	builder.WriteByte(' ')
	builder.WriteString(w3cQuoted(entry.userAgent, maxAccessLogValueBytes))
	builder.WriteByte(' ')
	builder.WriteString(w3cQuoted(sanitizeReferer(entry.referer), maxAccessLogValueBytes))
	writeField(entry.requestID)
	writeField(entry.errorCode)
	builder.WriteByte('\n')
	return builder.String()
}

// remoteHost 只保留 RemoteAddr 的主机部分；端口不是访问日志字段。该地址未经
// 可信代理校验（可信代理与公开访问地址在后续步骤实现），不得用于授权判断。
func remoteHost(remoteAddr string) string {
	if remoteAddr == "" {
		return "-"
	}
	if host, _, err := splitHostPort(remoteAddr); err == nil && host != "" {
		return host
	}
	return remoteAddr
}

// w3cToken 把字段值转义为不含空白的 W3C 记号：空格、控制字符、非 ASCII 与
// 引号/反斜杠都按 %XX 编码，防止日志注入与字段错位。空值输出 "-"。
func w3cToken(value string, maxBytes int) string {
	if value == "" {
		return "-"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	encoded := 0
	for index := 0; index < len(value); index++ {
		if encoded >= maxBytes {
			builder.WriteString("...")
			break
		}
		character := value[index]
		if character >= 0x21 && character <= 0x7e && character != '"' && character != '\\' {
			builder.WriteByte(character)
			encoded++
			continue
		}
		builder.WriteByte('%')
		builder.WriteString(hexUpper(character))
		encoded += 3
	}
	if builder.Len() == 0 {
		return "-"
	}
	return builder.String()
}

// w3cQuoted 把 User-Agent/Referer 输出为带引号的 W3C 字符串；引号内部仍做
// %XX 转义，避免引号、换行或反斜杠破坏日志结构。空值输出 "-"（不带引号）。
func w3cQuoted(value string, maxBytes int) string {
	if value == "" {
		return "-"
	}
	escaped := w3cToken(value, maxBytes)
	if escaped == "-" {
		return "-"
	}
	var builder strings.Builder
	builder.Grow(len(escaped) + 2)
	builder.WriteByte('"')
	builder.WriteString(escaped)
	builder.WriteByte('"')
	return builder.String()
}

// hexUpper 返回字节的两位大写十六进制表示。
func hexUpper(value byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[value>>4], digits[value&0x0f]})
}

// splitHostPort 拆分 host:port，兼容 IPv6 方括号形式。
func splitHostPort(address string) (string, string, error) {
	if !strings.Contains(address, ":") {
		return address, "", nil
	}
	index := strings.LastIndexByte(address, ':')
	host := address[:index]
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return host, address[index+1:], nil
}
