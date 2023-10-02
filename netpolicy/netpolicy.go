// Package netpolicy 实现监听地址、允许主机名与 HTTP Host 的严格解析。
//
// 本包只做“字节到结构化值”的校验与规范化，不解析 DNS、不建立连接、不读取
// 环境变量。调用方（配置加载、传输层代理边界、监听组件）必须使用同一套规则，
// 避免配置校验与实际监听、Host 校验出现两套口径。
//
// 安全不变量：
//   - 监听主机只接受 IP 字面量、localhost 或空主机（所有接口），不接受任意
//     域名；监听地址不允许端口 0（测试用的临时端口必须显式允许）。
//   - HTTP Host 只接受 LDH 形式的 ASCII 主机名或 IP 字面量，拒绝 Unicode、
//     通配符、用户信息、路径、百分号编码与未加方括号的 IPv6，避免 Host 走私
//     与同形字混淆。
//   - 允许列表匹配比较规范化后的小写主机名与规范 IP；带端口的条目不接受
//     端口缺失的请求 Host，不带端口的条目接受任意端口。
package netpolicy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// maxHostBytes 是主机名/IP 文本的硬上限（DNS 主机名上限 253 字节，另留方括号
// 与端口余量）。
const maxHostBytes = 255

// ListenAddress 是已校验的监听地址。字段不导出，避免调用方绕过校验自行拼接。
type ListenAddress struct {
	raw      string
	host     string
	port     uint16
	ip       netip.Addr
	hostname string
	wildcard bool
}

// ParseListenAddress 解析 host:port 形式的监听地址。
//
// 允许的形式：
//   - "127.0.0.1:8080"、"0.0.0.0:8080"、"[::1]:8080"、"[::]:8080"
//   - "localhost:8080"（只监听这个名称解析出的地址，具体协议族由操作系统决定）
//   - ":8080" 表示所有接口（等价于监听通配地址，按非回环处理）
//
// allowEphemeralPort 为 true 时允许端口 0（由操作系统分配）；配置加载不允许，
// 只有明确的测试/嵌入预检场景才允许。其他域名一律拒绝，防止监听地址随 DNS
// 变化而改变实际暴露面。
func ParseListenAddress(raw string, allowEphemeralPort bool) (ListenAddress, error) {
	if raw == "" {
		return ListenAddress{}, fmt.Errorf("监听地址不能为空")
	}
	if strings.TrimSpace(raw) != raw {
		return ListenAddress{}, fmt.Errorf("监听地址不能包含首尾空白")
	}
	if len(raw) > maxHostBytes {
		return ListenAddress{}, fmt.Errorf("监听地址过长")
	}
	if strings.ContainsAny(raw, " \t\r\n/\\?#") {
		return ListenAddress{}, fmt.Errorf("监听地址不能包含空白、路径或查询字符")
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return ListenAddress{}, fmt.Errorf("监听地址必须为 host:port 形式")
	}
	portNumber, err := strconv.Atoi(portText)
	if err != nil {
		return ListenAddress{}, fmt.Errorf("监听端口必须是十进制整数")
	}
	if portNumber < 0 || portNumber > 65535 {
		return ListenAddress{}, fmt.Errorf("监听端口必须在 1～65535 之间")
	}
	if portNumber == 0 && !allowEphemeralPort {
		return ListenAddress{}, fmt.Errorf("监听端口必须在 1～65535 之间")
	}
	address := ListenAddress{raw: raw, host: host, port: uint16(portNumber)}
	switch {
	case host == "":
		address.wildcard = true
	case strings.EqualFold(host, "localhost"):
		address.hostname = "localhost"
	default:
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return ListenAddress{}, fmt.Errorf("监听主机必须是 IP 字面量、localhost 或空（所有接口）")
		}
		address.ip = ip.Unmap()
		if address.ip.IsUnspecified() {
			address.wildcard = true
		}
	}
	return address, nil
}

// Port 返回监听端口。
func (a ListenAddress) Port() uint16 {
	return a.port
}

// IsWildcard 报告监听地址是否绑定所有接口。
func (a ListenAddress) IsWildcard() bool {
	return a.wildcard
}

// IsLoopback 报告监听地址是否只绑定本机回环接口。通配地址（含 0.0.0.0 与 ::）
// 按非回环处理；未知情况一律按非回环处理，避免误判为安全。
func (a ListenAddress) IsLoopback() bool {
	switch {
	case a.wildcard:
		return false
	case a.hostname == "localhost":
		return true
	default:
		return a.ip.IsLoopback()
	}
}

// String 返回规范化的 host:port，可直接交给 net.Listen。通配地址统一写成
// ":port"，便于去重与日志输出。
func (a ListenAddress) String() string {
	switch {
	case a.wildcard:
		return ":" + strconv.Itoa(int(a.port))
	case a.hostname != "":
		return a.hostname + ":" + strconv.Itoa(int(a.port))
	default:
		return netip.AddrPortFrom(a.ip, a.port).String()
	}
}

// Key 返回用于判重的稳定键；与 String 相同。
func (a ListenAddress) Key() string {
	return a.String()
}

// RequestHost 是已校验的 HTTP Host 值。
type RequestHost struct {
	host string
	port uint16
	ip   netip.Addr
	isIP bool
}

// Host 返回规范化后的主机名或规范 IP 文本。
func (h RequestHost) Host() string {
	if h.isIP {
		return h.ip.String()
	}
	return h.host
}

// Port 返回 Host 中显式写的端口；没有端口时为 0。
func (h RequestHost) Port() uint16 {
	return h.port
}

// IsIP 报告 Host 是否为 IP 字面量。
func (h RequestHost) IsIP() bool {
	return h.isIP
}

// ParseRequestHost 解析并规范化 HTTP Host 头（也用于公开基础 URL 的主机部分）。
//
// 规则：
//   - 空值、控制字符、非 ASCII、空白、逗号、百分号、路径或查询字符一律拒绝；
//   - 只接受 ASCII LDH 主机名（可带一个结尾点，会被去掉）、IPv4 或方括号
//     IPv6（可带端口）；未加方括号的多冒号 IPv6 拒绝；
//   - 端口必须是 1～65535 的十进制整数；
//   - 通配符 "*" 拒绝。
func ParseRequestHost(raw string) (RequestHost, error) {
	if raw == "" {
		return RequestHost{}, fmt.Errorf("主机名不能为空")
	}
	if len(raw) > maxHostBytes {
		return RequestHost{}, fmt.Errorf("主机名过长")
	}
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if character <= 0x20 || character >= 0x7f {
			return RequestHost{}, fmt.Errorf("主机名只能包含可见 ASCII 字符")
		}
		switch character {
		case ' ', '\t', '\r', '\n', '/', '\\', '?', '#', '%', ',', '@', '*':
			return RequestHost{}, fmt.Errorf("主机名包含不安全字符")
		}
	}

	var (
		hostPart string
		port     uint16
	)
	if raw[0] == '[' {
		closing := strings.IndexByte(raw, ']')
		if closing < 0 {
			return RequestHost{}, fmt.Errorf("IPv6 主机名缺少右方括号")
		}
		hostPart = raw[1:closing]
		rest := raw[closing+1:]
		switch {
		case rest == "":
		case strings.HasPrefix(rest, ":"):
			number, err := parseHostPort(rest[1:])
			if err != nil {
				return RequestHost{}, err
			}
			port = number
		default:
			return RequestHost{}, fmt.Errorf("IPv6 主机名后的内容不合法")
		}
		ip, err := netip.ParseAddr(hostPart)
		if err != nil || ip.Zone() != "" {
			return RequestHost{}, fmt.Errorf("IPv6 主机名不合法")
		}
		return RequestHost{ip: ip.Unmap(), isIP: true, port: port}, nil
	}

	if strings.Count(raw, ":") > 1 {
		return RequestHost{}, fmt.Errorf("IPv6 主机名必须使用方括号")
	}
	if colon := strings.IndexByte(raw, ':'); colon >= 0 {
		hostPart = raw[:colon]
		number, err := parseHostPort(raw[colon+1:])
		if err != nil {
			return RequestHost{}, err
		}
		port = number
	} else {
		hostPart = raw
	}

	if ip, err := netip.ParseAddr(hostPart); err == nil {
		if ip.Zone() != "" {
			return RequestHost{}, fmt.Errorf("主机名不能包含 IPv6 区域标识")
		}
		return RequestHost{ip: ip.Unmap(), isIP: true, port: port}, nil
	}
	host, err := normalizeHostname(hostPart)
	if err != nil {
		return RequestHost{}, err
	}
	return RequestHost{host: host, port: port}, nil
}

// parseHostPort 解析 Host 中的端口部分。
func parseHostPort(raw string) (uint16, error) {
	number, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("主机端口必须是十进制整数")
	}
	if number < 1 || number > 65535 {
		return 0, fmt.Errorf("主机端口必须在 1～65535 之间")
	}
	return uint16(number), nil
}

// normalizeHostname 校验 LDH 主机名并转为小写；结尾的根域点会被去掉一次。
func normalizeHostname(raw string) (string, error) {
	host := raw
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("主机名长度不合法")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("主机名标签长度不合法")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("主机名标签不能以连字符开头或结尾")
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' {
				continue
			}
			return "", fmt.Errorf("主机名包含非法字符")
		}
	}
	return strings.ToLower(host), nil
}

// AllowedHost 是允许列表中的一个条目。Port 为 0 表示接受任意端口。
type AllowedHost struct {
	host string
	port uint16
	ip   netip.Addr
	isIP bool
}

// ParseAllowedHost 解析允许列表条目：主机名或 IP，可选端口。
func ParseAllowedHost(raw string) (AllowedHost, error) {
	if raw == "" {
		return AllowedHost{}, fmt.Errorf("允许的主机名不能为空")
	}
	if strings.ContainsAny(raw, "/\\?#@*%,") {
		return AllowedHost{}, fmt.Errorf("允许的主机名必须是 host 或 host:port")
	}
	parsed, err := ParseRequestHost(raw)
	if err != nil {
		return AllowedHost{}, err
	}
	return AllowedHost{host: parsed.host, port: parsed.port, ip: parsed.ip, isIP: parsed.isIP}, nil
}

// HostSet 是不可变的允许主机集合；构造后并发安全。
type HostSet struct {
	entries       []AllowedHost
	allowLoopback bool
}

// NewHostSet 解析允许主机列表。空列表返回空集合；是否回退到“仅回环”由调用方
// 决定（见 LoopbackHostSet）。
func NewHostSet(values []string) (HostSet, error) {
	var set HostSet
	for index, raw := range values {
		entry, err := ParseAllowedHost(strings.TrimSpace(raw))
		if err != nil {
			return HostSet{}, fmt.Errorf("允许的主机名第 %d 项无效: %w", index+1, err)
		}
		if set.contains(entry) {
			return HostSet{}, fmt.Errorf("允许的主机名第 %d 项重复", index+1)
		}
		set.entries = append(set.entries, entry)
	}
	return set, nil
}

// LoopbackHostSet 返回开发默认的允许集合：localhost、127.0.0.0/8 与 ::1 的任意
// 端口。它只在没有配置公开地址与允许主机时使用，确保本机开发监听不响应外部
// 域名；一旦配置了公开地址，该默认集合被显式列表替代。
func LoopbackHostSet() HostSet {
	return HostSet{allowLoopback: true}
}

// WithHost 返回加入一个 host 或 host:port 后的新集合（值语义，调用方原集合
// 不变）。用于把公开基础 URL 的主机加入允许列表。
func (s HostSet) WithHost(raw string) (HostSet, error) {
	entry, err := ParseAllowedHost(raw)
	if err != nil {
		return HostSet{}, err
	}
	cloned := HostSet{
		entries:       append([]AllowedHost(nil), s.entries...),
		allowLoopback: s.allowLoopback,
	}
	if !cloned.contains(entry) {
		cloned.entries = append(cloned.entries, entry)
	}
	return cloned, nil
}

// contains 报告集合中是否已有同一主机与端口的条目。
func (s HostSet) contains(entry AllowedHost) bool {
	for _, existing := range s.entries {
		if existing.isIP != entry.isIP || existing.port != entry.port {
			continue
		}
		if entry.isIP {
			if existing.ip == entry.ip {
				return true
			}
			continue
		}
		if existing.host == entry.host {
			return true
		}
	}
	return false
}

// Empty 报告集合是否没有任何条目。
func (s HostSet) Empty() bool {
	return len(s.entries) == 0 && !s.allowLoopback
}

// Len 返回条目数；回环默认集合按 0 计。
func (s HostSet) Len() int {
	return len(s.entries)
}

// Allows 报告请求 Host 是否被允许。返回的错误表示 Host 本身语法无效（调用方
// 应返回 400），返回 false 且无错误表示语法有效但不在允许列表（调用方应返回
// 421）。任何解析歧义都按不允许处理，绝不做前缀或后缀模糊匹配。
func (s HostSet) Allows(rawHost string) (bool, error) {
	request, err := ParseRequestHost(rawHost)
	if err != nil {
		return false, err
	}
	if s.allowLoopback {
		if request.isIP && request.ip.IsLoopback() {
			return true, nil
		}
		if !request.isIP && request.host == "localhost" {
			return true, nil
		}
	}
	for _, entry := range s.entries {
		if entry.isIP != request.isIP {
			continue
		}
		if entry.port != 0 && entry.port != request.port {
			continue
		}
		if entry.isIP {
			if entry.ip == request.ip {
				return true, nil
			}
			continue
		}
		if entry.host == request.host {
			return true, nil
		}
	}
	return false, nil
}

// Keys 返回规范化条目文本，用于诊断输出（不含请求数据）。
func (s HostSet) Keys() []string {
	keys := make([]string, 0, len(s.entries))
	for _, entry := range s.entries {
		var text string
		if entry.isIP {
			text = entry.ip.String()
		} else {
			text = entry.host
		}
		if entry.port != 0 {
			text += ":" + strconv.Itoa(int(entry.port))
		}
		keys = append(keys, text)
	}
	return keys
}
