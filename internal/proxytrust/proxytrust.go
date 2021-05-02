// Package proxytrust 实现反向代理信任边界：只有直连对端命中显式配置的可信
// 代理时，才解析 Forwarded（RFC 7239）或 X-Forwarded-* 转发头；否则完全忽略，
// 防止任意客户端伪造客户端地址、协议与域名。
//
// 本包不写响应、不决定 HTTP 状态，只返回结构化的解析结果与错误，由传输层代理
// 边界映射为 400。解析规则是确定的、文档化的，不依赖头部出现顺序的猜测：
//
//  1. 直连对端从 net.Conn 的 RemoteAddr 取得，优先于任何头部。
//  2. 对端不可信或未配置可信代理时，忽略一切转发头；畸形头也不影响结果。
//  3. 对端可信时，若存在 Forwarded 头，则 RFC 7239 头是唯一权威来源，
//     X-Forwarded-* 全部忽略；Forwarded 存在但语法非法时返回错误（fail-closed，
//     不回退到可能被混淆的 X-Forwarded-*）。
//  4. 没有 Forwarded 头时解析 X-Forwarded-For/Proto/Host：
//     - 地址链从右向左跳过可信代理，遇到第一个不可信地址即客户端地址；
//     - 协议取最右侧值（最近一跳可信代理的视图），只接受 http/https；
//     - 主机只接受单值，多值或逗号列表视为歧义并报错。
//  5. 长度、跳数与地址格式都设上限；任一已知字段语法非法时报错而不是猜测。
//  6. RFC 7239 的混淆节点标识（unknown/_hidden）无法用于限流，停止链解析并
//     使用当前最近的代理地址；这不是伪造凭证，但会失去更细的客户端粒度。
package proxytrust

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// MaxForwardedBytes 是单个转发头集合的长度上限，防止解析放大。
	MaxForwardedBytes = 2 << 10
	// MaxForwardedHops 是转发链最大跳数；超过视为异常并报错。
	MaxForwardedHops = 16
	// MaxTrustedProxies 是可信代理配置条目上限。
	MaxTrustedProxies = 32
)

// Trusted 是不可变的可信代理前缀集合；零值表示不信任任何代理。
type Trusted struct {
	prefixes []netip.Prefix
}

// Parse 解析可信代理 IP 或 CIDR 列表。只接受明确的地址或前缀；空条目、非法
// 地址与超过 MaxTrustedProxies 的配置都返回错误。IPv4-mapped IPv6 前缀会归一
// 化为 IPv4。
func Parse(values []string) (Trusted, error) {
	if len(values) > MaxTrustedProxies {
		return Trusted{}, fmt.Errorf("可信代理数量不能超过 %d", MaxTrustedProxies)
	}
	trusted := Trusted{prefixes: make([]netip.Prefix, 0, len(values))}
	for index, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return Trusted{}, fmt.Errorf("可信代理第 %d 项不能为空", index+1)
		}
		if strings.Contains(trimmed, "/") {
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return Trusted{}, fmt.Errorf("可信代理第 %d 项 CIDR 无效", index+1)
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return Trusted{}, fmt.Errorf("可信代理第 %d 项 CIDR 无效", index+1)
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			trusted.prefixes = append(trusted.prefixes, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(trimmed)
		if err != nil {
			return Trusted{}, fmt.Errorf("可信代理第 %d 项地址无效", index+1)
		}
		address = address.Unmap()
		trusted.prefixes = append(trusted.prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	return trusted, nil
}

// Empty 报告是否没有配置任何可信代理。
func (t Trusted) Empty() bool {
	return len(t.prefixes) == 0
}

// Len 返回可信代理条目数。
func (t Trusted) Len() int {
	return len(t.prefixes)
}

// Contains 报告地址是否命中可信代理集合。
func (t Trusted) Contains(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range t.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// Peer 返回直连对端地址；RemoteAddr 非法时返回 false。
func Peer(remoteAddr string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		host = trimmed
	}
	host = strings.Trim(host, "[]")
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// Info 是可信转发结果。HasProto/HasHost 表示可信代理确实提供了对应字段；未提供
// 的字段为空，调用方不得自行用请求头补全。
type Info struct {
	// ClientAddr 是经过可信链解析的客户端地址；对端无效时为无效地址。
	ClientAddr netip.Addr
	// Proto 是最近一跳可信代理看到的入站协议：http 或 https。
	Proto string
	// HasProto 表示可信代理提供了协议信息。
	HasProto bool
	// Host 是最近一跳可信代理看到的外部主机（可能带端口）。
	Host string
	// HasHost 表示可信代理提供了主机信息。
	HasHost bool
}

// Resolve 按包文档的确定规则解析转发信息。对端不可信时忽略所有转发头且不报错；
// 对端可信时，畸形转发头返回错误，由调用方 fail-closed。
func (t Trusted) Resolve(remoteAddr string, header http.Header) (Info, error) {
	peer, peerOK := Peer(remoteAddr)
	info := Info{ClientAddr: peer}
	if !peerOK || t.Empty() || !t.Contains(peer) {
		return info, nil
	}

	if values := header.Values("Forwarded"); len(values) > 0 {
		return t.resolveForwarded(peer, values)
	}
	return t.resolveXForwarded(peer, header)
}

// resolveForwarded 解析 RFC 7239 Forwarded 头。存在该头时它是唯一权威来源。
func (t Trusted) resolveForwarded(peer netip.Addr, values []string) (Info, error) {
	raw := strings.Join(values, ",")
	if len(raw) > MaxForwardedBytes {
		return Info{ClientAddr: peer}, fmt.Errorf("Forwarded 头过长")
	}
	elements, err := parseForwardedElements(raw)
	if err != nil {
		return Info{ClientAddr: peer}, err
	}
	if len(elements) == 0 {
		return Info{ClientAddr: peer}, fmt.Errorf("Forwarded 头为空")
	}
	if len(elements) > MaxForwardedHops {
		return Info{ClientAddr: peer}, fmt.Errorf("Forwarded 转发链过长")
	}
	return t.resolveForwardedElements(peer, elements)
}

// resolveForwardedElements 从最近的代理（最右元素）向客户端方向解析地址链。
func (t Trusted) resolveForwardedElements(peer netip.Addr, elements []forwardedElement) (Info, error) {
	info := Info{ClientAddr: peer}
	// 协议与主机取最右侧提供该字段的元素（最近一跳代理的视图）。
	for index := len(elements) - 1; index >= 0; index-- {
		element := elements[index]
		if !info.HasProto && element.proto != "" {
			proto, err := normalizeProto(element.proto)
			if err != nil {
				return Info{ClientAddr: peer}, err
			}
			info.Proto = proto
			info.HasProto = true
		}
		if !info.HasHost && element.host != "" {
			info.Host = element.host
			info.HasHost = true
		}
	}

	candidate := peer
	for index := len(elements) - 1; index >= 0; index-- {
		if !t.Contains(candidate) {
			break
		}
		element := elements[index]
		if element.forValue == "" {
			return Info{ClientAddr: peer}, fmt.Errorf("Forwarded 元素缺少 for 参数")
		}
		address, obfuscated, err := parseForwardedNode(element.forValue)
		if err != nil {
			return Info{ClientAddr: peer}, err
		}
		if obfuscated {
			// 混淆标识无法作为限流键；停止解析，使用当前最近代理地址。
			break
		}
		candidate = address
	}
	info.ClientAddr = candidate
	return info, nil
}

// resolveXForwarded 解析 X-Forwarded-For/Proto/Host。未出现的字段保持未设置。
func (t Trusted) resolveXForwarded(peer netip.Addr, header http.Header) (Info, error) {
	info := Info{ClientAddr: peer}

	if values := header.Values("X-Forwarded-For"); len(values) > 0 {
		raw := strings.Join(values, ",")
		if len(raw) > MaxForwardedBytes {
			return info, fmt.Errorf("X-Forwarded-For 头过长")
		}
		parts := strings.Split(raw, ",")
		if len(parts) > MaxForwardedHops {
			return info, fmt.Errorf("X-Forwarded-For 转发链过长")
		}
		candidate := peer
		for index := len(parts) - 1; index >= 0; index-- {
			if !t.Contains(candidate) {
				break
			}
			address, err := parseForwardedAddress(parts[index])
			if err != nil {
				return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-For 应包含 IP 地址")
			}
			candidate = address
		}
		info.ClientAddr = candidate
	}

	if values := header.Values("X-Forwarded-Proto"); len(values) > 0 {
		raw := strings.Join(values, ",")
		if len(raw) > MaxForwardedBytes {
			return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-Proto 头过长")
		}
		parts := strings.Split(raw, ",")
		if len(parts) > MaxForwardedHops {
			return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-Proto 转发链过长")
		}
		proto, err := normalizeProto(parts[len(parts)-1])
		if err != nil {
			return Info{ClientAddr: peer}, err
		}
		info.Proto = proto
		info.HasProto = true
	}

	if values := header.Values("X-Forwarded-Host"); len(values) > 0 {
		if len(values) != 1 {
			return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-Host 不能有多个值")
		}
		host := strings.TrimSpace(values[0])
		if host == "" || strings.Contains(host, ",") {
			return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-Host 只能包含一个主机")
		}
		if len(host) > maxHostValueBytes {
			return Info{ClientAddr: peer}, fmt.Errorf("X-Forwarded-Host 过长")
		}
		info.Host = host
		info.HasHost = true
	}
	return info, nil
}

// maxHostValueBytes 是转发主机值的长度上限（主机名 253 字节 + 端口 + 方括号）。
const maxHostValueBytes = 300

// forwardedElement 是 RFC 7239 的一个转发元素。
type forwardedElement struct {
	forValue string
	proto    string
	host     string
}

// parseForwardedElements 解析 Forwarded 头为元素列表。语法错误一律报错，不做
// 容错修复，避免歧义被不同中间件解释成不同地址。
func parseForwardedElements(raw string) ([]forwardedElement, error) {
	var elements []forwardedElement
	for _, elementText := range splitOutsideQuotes(raw, ',') {
		elementText = strings.TrimSpace(elementText)
		if elementText == "" {
			return nil, fmt.Errorf("Forwarded 元素为空")
		}
		element := forwardedElement{}
		seen := make(map[string]struct{}, 3)
		for _, pairText := range splitOutsideQuotes(elementText, ';') {
			pairText = strings.TrimSpace(pairText)
			if pairText == "" {
				return nil, fmt.Errorf("Forwarded 参数为空")
			}
			name, value, err := parseForwardedPair(pairText)
			if err != nil {
				return nil, err
			}
			if _, duplicated := seen[name]; duplicated {
				return nil, fmt.Errorf("Forwarded 参数重复")
			}
			seen[name] = struct{}{}
			switch name {
			case "for":
				element.forValue = value
			case "proto":
				element.proto = value
			case "host":
				element.host = value
			}
		}
		elements = append(elements, element)
	}
	return elements, nil
}

// splitOutsideQuotes 按分隔符切分，忽略双引号内的分隔符；引号不配对时报错
// （由调用方通过返回的 nil 与错误路径体现）。
func splitOutsideQuotes(raw string, separator byte) []string {
	parts := []string{}
	start := 0
	inQuotes := false
	escaped := false
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if escaped {
			escaped = false
			continue
		}
		switch character {
		case '\\':
			if inQuotes {
				escaped = true
			}
		case '"':
			inQuotes = !inQuotes
		case separator:
			if !inQuotes {
				parts = append(parts, raw[start:index])
				start = index + 1
			}
		}
	}
	parts = append(parts, raw[start:])
	return parts
}

// parseForwardedPair 解析 name=value；值可以是 token 或 quoted-string。
func parseForwardedPair(text string) (string, string, error) {
	equals := strings.IndexByte(text, '=')
	if equals <= 0 {
		return "", "", fmt.Errorf("Forwarded 参数必须是 name=value")
	}
	name := strings.ToLower(strings.TrimSpace(text[:equals]))
	if name == "" {
		return "", "", fmt.Errorf("Forwarded 参数名不能为空")
	}
	value := strings.TrimSpace(text[equals+1:])
	if value == "" {
		return "", "", fmt.Errorf("Forwarded 参数值不能为空")
	}
	if value[0] == '"' {
		unquoted, err := unquoteForwardedValue(value)
		if err != nil {
			return "", "", err
		}
		value = unquoted
	} else if strings.ContainsAny(value, "\"\\ \t") {
		return "", "", fmt.Errorf("Forwarded 参数值包含非法字符")
	}
	return name, value, nil
}

// unquoteForwardedValue 解析 RFC 7239 quoted-string。
func unquoteForwardedValue(value string) (string, error) {
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", fmt.Errorf("Forwarded 引号值未闭合")
	}
	var builder strings.Builder
	escaped := false
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if escaped {
			builder.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			return "", fmt.Errorf("Forwarded 引号值包含未转义引号")
		}
		builder.WriteByte(character)
	}
	if escaped {
		return "", fmt.Errorf("Forwarded 引号值以转义符结尾")
	}
	return builder.String(), nil
}

// parseForwardedNode 解析 RFC 7239 node 标识（for= 的值），返回地址或混淆标记。
func parseForwardedNode(value string) (netip.Addr, bool, error) {
	if value == "unknown" || strings.HasPrefix(value, "_") {
		return netip.Addr{}, true, nil
	}
	address, err := parseForwardedAddress(value)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("Forwarded for 参数不是合法地址")
	}
	return address, false, nil
}

// parseForwardedAddress 解析带可选端口与方括号的 IP 地址。
func parseForwardedAddress(raw string) (netip.Addr, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("地址为空")
	}
	if len(value) > maxHostValueBytes {
		return netip.Addr{}, fmt.Errorf("地址过长")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if _, parseErr := strconv.Atoi(port); parseErr != nil {
			return netip.Addr{}, fmt.Errorf("地址端口无效")
		}
		value = host
	}
	value = strings.Trim(value, "[]")
	if value == "" {
		return netip.Addr{}, fmt.Errorf("地址为空")
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("地址无效")
	}
	return address.Unmap(), nil
}

// normalizeProto 校验并规范化协议值。
func normalizeProto(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", fmt.Errorf("转发协议为空")
	}
	if strings.Contains(value, "://") {
		return "", fmt.Errorf("转发协议只能是 http 或 https")
	}
	switch value {
	case "http", "https":
		return value, nil
	default:
		return "", fmt.Errorf("转发协议只能是 http 或 https")
	}
}
