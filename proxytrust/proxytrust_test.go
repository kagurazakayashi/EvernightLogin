package proxytrust

import (
	"net/http"
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("解析地址 %q 失败：%v", raw, err)
	}
	return address.Unmap()
}

func header(pairs ...string) http.Header {
	values := http.Header{}
	for index := 0; index+1 < len(pairs); index += 2 {
		values.Add(pairs[index], pairs[index+1])
	}
	return values
}

func TestParseTrusted(t *testing.T) {
	trusted, err := Parse([]string{"10.0.0.1", "192.0.2.0/24", "2001:db8::/32", "::ffff:198.51.100.0/120"})
	if err != nil {
		t.Fatalf("解析可信代理失败：%v", err)
	}
	if trusted.Empty() || trusted.Len() != 4 {
		t.Fatalf("可信代理数量 = %d", trusted.Len())
	}
	for _, raw := range []string{"10.0.0.1", "192.0.2.55", "2001:db8::1", "198.51.100.9"} {
		if !trusted.Contains(mustAddr(t, raw)) {
			t.Errorf("应命中可信代理 %s", raw)
		}
	}
	for _, raw := range []string{"10.0.0.2", "192.0.3.1", "2001:db9::1", "203.0.113.1"} {
		if trusted.Contains(mustAddr(t, raw)) {
			t.Errorf("不应命中可信代理 %s", raw)
		}
	}
	for _, values := range [][]string{{""}, {"not-an-ip"}, {"192.0.2.0/33"}} {
		if _, err := Parse(values); err == nil {
			t.Errorf("应拒绝可信代理配置 %v", values)
		}
	}
	empty := Trusted{}
	if !empty.Empty() || empty.Contains(mustAddr(t, "10.0.0.1")) {
		t.Error("零值 Trusted 不应信任任何地址")
	}
}

func TestPeer(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:1234":   "127.0.0.1",
		"[::1]:10000":      "::1",
		"192.0.2.1":        "192.0.2.1",
		"[2001:db8::1]:80": "2001:db8::1",
	}
	for raw, want := range tests {
		address, ok := Peer(raw)
		if !ok || address.String() != want {
			t.Errorf("Peer(%q) = %v, %v；期望 %s", raw, address, ok, want)
		}
	}
	for _, raw := range []string{"", "not-an-address"} {
		if _, ok := Peer(raw); ok {
			t.Errorf("Peer(%q) 应返回 false", raw)
		}
	}
}

func TestUntrustedPeerIgnoresForwardingHeaders(t *testing.T) {
	trusted, err := Parse([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	headers := header(
		"Forwarded", `for=203.0.113.9;proto=https;host=evil.example.com`,
		"X-Forwarded-For", "203.0.113.9",
		"X-Forwarded-Proto", "https",
		"X-Forwarded-Host", "evil.example.com",
	)
	info, err := trusted.Resolve("192.0.2.7:5555", headers)
	if err != nil {
		t.Fatalf("不可信对端的转发头应被忽略而不是报错：%v", err)
	}
	if info.ClientAddr.String() != "192.0.2.7" {
		t.Errorf("客户端地址 = %s，期望直连地址", info.ClientAddr)
	}
	if info.HasProto || info.HasHost {
		t.Errorf("不可信对端不应产生协议/主机信息：%+v", info)
	}

	// 未配置可信代理时同样忽略一切头。
	info, err = Trusted{}.Resolve("192.0.2.7:5555", headers)
	if err != nil || info.ClientAddr.String() != "192.0.2.7" {
		t.Fatalf("未配置可信代理时结果 = %+v, %v", info, err)
	}
}

func TestXForwardedChain(t *testing.T) {
	trusted, err := Parse([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := trusted.Resolve("10.0.0.1:4000", header(
		"X-Forwarded-For", "198.51.100.7, 203.0.113.9",
		"X-Forwarded-Proto", "http, https",
		"X-Forwarded-Host", "login.example.com:8443",
	))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if info.ClientAddr.String() != "203.0.113.9" {
		t.Errorf("客户端地址 = %s，期望 203.0.113.9", info.ClientAddr)
	}
	if !info.HasProto || info.Proto != "https" {
		t.Errorf("协议 = %q（提供 %v），期望 https", info.Proto, info.HasProto)
	}
	if !info.HasHost || info.Host != "login.example.com:8443" {
		t.Errorf("主机 = %q（提供 %v）", info.Host, info.HasHost)
	}

	// 中间还有一层可信代理时继续向左解析。
	multi, err := Parse([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	info, err = multi.Resolve("10.0.0.1:4000", header("X-Forwarded-For", "10.0.0.9, 198.51.100.7"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if info.ClientAddr.String() != "198.51.100.7" {
		t.Errorf("客户端地址 = %s，期望 198.51.100.7", info.ClientAddr)
	}

	if _, err := trusted.Resolve("10.0.0.1:4000", header("X-Forwarded-For", "not-an-ip")); err == nil {
		t.Error("非法 X-Forwarded-For 应报错")
	}
	if _, err := trusted.Resolve("10.0.0.1:4000", header("X-Forwarded-Proto", "ftp")); err == nil {
		t.Error("非法协议应报错")
	}
	if _, err := trusted.Resolve("10.0.0.1:4000", header("X-Forwarded-Host", "a.example.com, b.example.com")); err == nil {
		t.Error("多值主机应报错")
	}
}

func TestForwardedHeader(t *testing.T) {
	trusted, err := Parse([]string{"10.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := trusted.Resolve("10.0.0.1:4000", header(
		"Forwarded", `for=192.0.2.60;proto=https;host="login.example.com", for="[2001:db8::1]:1234"`,
		"X-Forwarded-For", "203.0.113.99",
	))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	// RFC 7239 从右向左跳过可信代理：最右 for 是 2001:db8::1（不可信）即客户端；
	// 左元素的 192.0.2.60 不再参与。
	if info.ClientAddr.String() != "2001:db8::1" {
		t.Errorf("客户端地址 = %s，期望 2001:db8::1", info.ClientAddr)
	}
	// Forwarded 存在时 X-Forwarded-* 全部忽略。
	if info.Proto != "https" || info.Host != "login.example.com" {
		t.Errorf("协议/主机 = %q/%q", info.Proto, info.Host)
	}

	// 全部节点可信时取最左地址。
	info, err = trusted.Resolve("10.0.0.1:4000", header("Forwarded", "for=10.0.0.2, for=10.0.0.3"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if info.ClientAddr.String() != "10.0.0.2" {
		t.Errorf("客户端地址 = %s，期望 10.0.0.2", info.ClientAddr)
	}

	// 混淆节点标识停止链解析，使用最近的代理地址。
	info, err = trusted.Resolve("10.0.0.1:4000", header("Forwarded", "for=unknown, for=10.0.0.3"))
	if err != nil {
		t.Fatalf("混淆标识不应报错：%v", err)
	}
	if info.ClientAddr.String() != "10.0.0.3" {
		t.Errorf("客户端地址 = %s，期望最近的代理 10.0.0.3", info.ClientAddr)
	}

	invalid := []string{
		`for=192.0.2.1;for=192.0.2.2`,
		`for=`,
		`for=not-an-address`,
		`for=192.0.2.1;proto=ftp`,
		`for=192.0.2.1;host="unterminated`,
	}
	for _, value := range invalid {
		if _, err := trusted.Resolve("10.0.0.1:4000", header("Forwarded", value)); err == nil {
			t.Errorf("应拒绝畸形 Forwarded：%q", value)
		}
	}
}

func TestForwardedLimits(t *testing.T) {
	trusted, err := Parse([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	chain := ""
	for index := 0; index <= MaxForwardedHops; index++ {
		if index > 0 {
			chain += ","
		}
		chain += "for=198.51.100.1"
	}
	if _, err := trusted.Resolve("10.0.0.1:4000", header("Forwarded", chain)); err == nil {
		t.Error("超长 Forwarded 链应报错")
	}
	longValue := ""
	for index := 0; index < MaxForwardedBytes; index++ {
		longValue += "a"
	}
	if _, err := trusted.Resolve("10.0.0.1:4000", header("X-Forwarded-For", longValue)); err == nil {
		t.Error("超长 X-Forwarded-For 应报错")
	}
}
