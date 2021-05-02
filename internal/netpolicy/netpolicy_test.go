package netpolicy

import (
	"strings"
	"testing"
)

func TestParseListenAddressValid(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantKey   string
		loopback  bool
		wildcard  bool
		wantPort  uint16
		ephemeral bool
	}{
		{name: "IPv4 回环", raw: "127.0.0.1:8080", wantKey: "127.0.0.1:8080", loopback: true, wantPort: 8080},
		{name: "IPv6 回环", raw: "[::1]:8081", wantKey: "[::1]:8081", loopback: true, wantPort: 8081},
		{name: "IPv4 通配", raw: "0.0.0.0:8080", wantKey: ":8080", wildcard: true, wantPort: 8080},
		{name: "IPv6 通配", raw: "[::]:8080", wantKey: ":8080", wildcard: true, wantPort: 8080},
		{name: "空主机通配", raw: ":8080", wantKey: ":8080", wildcard: true, wantPort: 8080},
		{name: "localhost", raw: "LOCALHOST:8080", wantKey: "localhost:8080", loopback: true, wantPort: 8080},
		{name: "IPv4-mapped 归一", raw: "[::ffff:127.0.0.1]:8080", wantKey: "127.0.0.1:8080", loopback: true, wantPort: 8080},
		{name: "IPv6 区域标识", raw: "[fe80::1%eth0]:8080", wantKey: "[fe80::1%eth0]:8080", wantPort: 8080},
		{name: "允许临时端口", raw: "127.0.0.1:0", wantKey: "127.0.0.1:0", loopback: true, wantPort: 0, ephemeral: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, err := ParseListenAddress(test.raw, test.ephemeral)
			if err != nil {
				t.Fatalf("解析失败：%v", err)
			}
			if address.Key() != test.wantKey {
				t.Errorf("Key = %q，期望 %q", address.Key(), test.wantKey)
			}
			if address.IsLoopback() != test.loopback {
				t.Errorf("IsLoopback = %v，期望 %v", address.IsLoopback(), test.loopback)
			}
			if address.IsWildcard() != test.wildcard {
				t.Errorf("IsWildcard = %v，期望 %v", address.IsWildcard(), test.wildcard)
			}
			if address.Port() != test.wantPort {
				t.Errorf("Port = %d，期望 %d", address.Port(), test.wantPort)
			}
		})
	}
}

func TestParseListenAddressInvalid(t *testing.T) {
	invalid := []string{
		"",
		" 127.0.0.1:8080",
		"127.0.0.1:8080 ",
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:-1",
		"127.0.0.1:abc",
		"example.com:8080",
		"127.0.0.1:8080/path",
		"[::1]8080",
		"[::1",
		"http://127.0.0.1:8080",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseListenAddress(raw, false); err == nil {
				t.Fatalf("期望拒绝 %q", raw)
			}
		})
	}
}

func TestParseRequestHostValid(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantPort uint16
		isIP     bool
	}{
		{raw: "example.com", wantHost: "example.com"},
		{raw: "Example.COM.", wantHost: "example.com"},
		{raw: "login.example.com:8443", wantHost: "login.example.com", wantPort: 8443},
		{raw: "127.0.0.1", wantHost: "127.0.0.1", isIP: true},
		{raw: "127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: 8080, isIP: true},
		{raw: "[::1]:8443", wantHost: "::1", wantPort: 8443, isIP: true},
		{raw: "[::1]", wantHost: "::1", isIP: true},
		{raw: "localhost", wantHost: "localhost"},
		{raw: "[::ffff:127.0.0.1]:80", wantHost: "127.0.0.1", wantPort: 80, isIP: true},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			host, err := ParseRequestHost(test.raw)
			if err != nil {
				t.Fatalf("解析失败：%v", err)
			}
			if host.Host() != test.wantHost || host.Port() != test.wantPort || host.IsIP() != test.isIP {
				t.Errorf("解析结果 = host %q port %d isIP %v，期望 %q %d %v",
					host.Host(), host.Port(), host.IsIP(), test.wantHost, test.wantPort, test.isIP)
			}
		})
	}
}

func TestParseRequestHostInvalid(t *testing.T) {
	invalid := []string{
		"",
		" ",
		"exa mple.com",
		"*.example.com",
		"example.com/path",
		"example.com?a=1",
		"user@example.com",
		"[::1]:0",
		"example.com:65536",
		"example.com:abc",
		"2001:db8::1",
		"example_com",
		"-bad.example.com",
		"bad-.example.com",
		"example..com",
		"例子.example",
		strings.Repeat("a", 64) + ".com",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseRequestHost(raw); err == nil {
				t.Fatalf("期望拒绝 %q", raw)
			}
		})
	}
}

func TestHostSetMatching(t *testing.T) {
	set, err := NewHostSet([]string{"login.example.com", "api.example.com:8443", "192.0.2.10"})
	if err != nil {
		t.Fatalf("构造允许列表失败：%v", err)
	}
	allowed := []string{
		"login.example.com",
		"LOGIN.EXAMPLE.COM",
		"login.example.com:443",
		"login.example.com.",
		"api.example.com:8443",
		"192.0.2.10",
		"192.0.2.10:9000",
	}
	for _, raw := range allowed {
		t.Run("允许 "+raw, func(t *testing.T) {
			ok, err := set.Allows(raw)
			if err != nil || !ok {
				t.Fatalf("Allows(%q) = %v, %v", raw, ok, err)
			}
		})
	}
	denied := []string{
		"evil.example.com",
		"login.example.com.evil.com",
		"api.example.com",
		"api.example.com:9443",
		"192.0.2.11",
		"sub.login.example.com",
	}
	for _, raw := range denied {
		t.Run("拒绝 "+raw, func(t *testing.T) {
			ok, err := set.Allows(raw)
			if err != nil || ok {
				t.Fatalf("Allows(%q) = %v, %v", raw, ok, err)
			}
		})
	}
	if ok, err := set.Allows("bad host"); err == nil || ok {
		t.Fatalf("语法无效的主机名应返回错误：%v", err)
	}
}

func TestLoopbackHostSet(t *testing.T) {
	set := LoopbackHostSet()
	allowed := []string{"localhost", "localhost:8080", "127.0.0.1", "127.0.0.2:9000", "[::1]:8443"}
	for _, raw := range allowed {
		if ok, err := set.Allows(raw); err != nil || !ok {
			t.Errorf("回环 Host 应允许 %q：%v %v", raw, ok, err)
		}
	}
	for _, raw := range []string{"example.com", "192.0.2.1", "[2001:db8::1]"} {
		if ok, err := set.Allows(raw); err != nil || ok {
			t.Errorf("非回环 Host 应拒绝 %q：%v %v", raw, ok, err)
		}
	}
	if set.Empty() {
		t.Error("回环默认集合不应为空")
	}
}

func TestHostSetWithHostAndDuplicates(t *testing.T) {
	set, err := NewHostSet(nil)
	if err != nil || !set.Empty() {
		t.Fatalf("空列表应返回空集合：%v", err)
	}
	withHost, err := set.WithHost("[::1]:8080")
	if err != nil {
		t.Fatalf("WithHost 失败：%v", err)
	}
	if ok, err := withHost.Allows("[::1]:8080"); err != nil || !ok {
		t.Fatalf("加入的主机应允许：%v %v", ok, err)
	}
	if ok, err := withHost.Allows("[::1]:8081"); err != nil || ok {
		t.Fatalf("端口必须精确匹配：%v %v", ok, err)
	}
	if _, err := NewHostSet([]string{"login.example.com", "LOGIN.example.com"}); err == nil {
		t.Fatal("重复主机名应被拒绝")
	}
	if _, err := NewHostSet([]string{"*.example.com"}); err == nil {
		t.Fatal("通配符应被拒绝")
	}
}
