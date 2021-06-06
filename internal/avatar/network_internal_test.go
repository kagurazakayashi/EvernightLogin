package avatar

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeResolver 是可控 DNS 解析器，用于在不访问真实网络的情况下验证地址分类。
type fakeResolver struct {
	addresses []net.IPAddr
	err       error
}

// LookupIPAddr 实现 IPResolver。
func (f fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f.addresses, f.err
}

// TestIsPublicIP 覆盖环回、私有、链路本地、CGNAT、保留段与公网地址分类。
func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":          true,
		"1.1.1.1":          true,
		"93.184.216.34":    true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"169.254.1.1":      false,
		"100.64.0.1":       false,
		"192.0.0.8":        false,
		"192.0.2.5":        false,
		"198.18.0.1":       false,
		"198.51.100.7":     false,
		"203.0.113.9":      false,
		"240.0.0.1":        false,
		"0.0.0.0":          false,
		"224.0.0.1":        false,
		"255.255.255.255":  false,
		"::1":              false,
		"::":               false,
		"fc00::1":          false,
		"fe80::1":          false,
		"2001:db8::1":      false,
		"64:ff9b::1.2.3.4": false,
		"2002::1":          false,
		"2001::1":          false,
		"::1.2.3.4":        false,
		"64:ff9b:1::1":     false,
		"192.88.99.1":      false,
		// IPv4-mapped IPv6 必须按其 IPv4 语义判定，不能绕过私网/环回拒绝。
		"::ffff:127.0.0.1":       false,
		"::ffff:10.0.0.1":        false,
		"::ffff:192.168.1.1":     false,
		"::ffff:169.254.169.254": false,
		"::ffff:8.8.8.8":         true,
	}
	for raw, want := range cases {
		if got := isPublicIP(net.ParseIP(raw)); got != want {
			t.Errorf("isPublicIP(%q) = %v，期望 %v", raw, got, want)
		}
	}
	if isPublicIP(nil) {
		t.Error("isPublicIP(nil) 应为 false")
	}
}

// TestNetworkURLPolicy 覆盖 URL 协议/凭证/端口/主机白名单与公网地址判断。
func TestNetworkURLPolicy(t *testing.T) {
	production := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: DefaultMaxRedirects,
	}, net.DefaultResolver)
	allowlisted := newNetworkFetcher(resolvedNetwork{
		allowedHosts: []string{"cdn.example.com"},
		maxBytes:     MaxUploadBytes, timeout: time.Second, maxRedirects: DefaultMaxRedirects,
	}, net.DefaultResolver)
	testMode := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: DefaultMaxRedirects,
		testMode: true,
	}, net.DefaultResolver)

	accepted := []string{
		"https://example.com/avatar.png",
		"https://example.com:443/a/b.png?x=1",
		"HTTPS://EXAMPLE.COM/x.png",
	}
	for _, raw := range accepted {
		parsed, err := production.validateURL(raw)
		if err != nil {
			t.Errorf("validateURL(%q) = %v，期望通过", raw, err)
			continue
		}
		if parsed.Fragment != "" {
			t.Errorf("validateURL(%q) 未清除 fragment", raw)
		}
	}
	blocked := []struct {
		raw  string
		want error
	}{
		{raw: "http://example.com/x.png", want: ErrRemoteBlocked},
		{raw: "ftp://example.com/x.png", want: ErrRemoteBlocked},
		{raw: "file:///etc/passwd", want: ErrRemoteBlocked},
		{raw: "javascript:alert(1)", want: ErrRemoteBlocked},
		{raw: "https://example.com:8443/x.png", want: ErrRemoteBlocked},
		{raw: "https://user:pass@example.com/x.png", want: ErrRemoteBlocked},
		{raw: "https://127.0.0.1/x.png", want: ErrRemoteBlocked},
		{raw: "https://[::1]/x.png", want: ErrRemoteBlocked},
		{raw: "https://10.0.0.1/x.png", want: ErrRemoteBlocked},
		{raw: "https://169.254.169.254/latest/meta-data", want: ErrRemoteBlocked},
		{raw: "https://100.64.0.1/x.png", want: ErrRemoteBlocked},
		{raw: "https://[::ffff:127.0.0.1]/x.png", want: ErrRemoteBlocked},
		{raw: "https://[::ffff:10.0.0.1]/x.png", want: ErrRemoteBlocked},
		{raw: "https://example.com/" + strings.Repeat("a", MaxURLBytes), want: ErrInvalidRequest},
		{raw: "", want: ErrInvalidRequest},
	}
	for _, test := range blocked {
		if _, err := production.validateURL(test.raw); !errors.Is(err, test.want) {
			t.Errorf("validateURL(%q) = %v，期望 %v", test.raw, err, test.want)
		}
	}
	if _, err := allowlisted.validateURL("https://cdn.example.com/a.png"); err != nil {
		t.Errorf("白名单内主机被拒绝: %v", err)
	}
	if _, err := allowlisted.validateURL("https://evil.example.com/a.png"); !errors.Is(err, ErrRemoteBlocked) {
		t.Errorf("白名单外主机错误 = %v，期望 ErrRemoteBlocked", err)
	}
	if _, err := testMode.validateURL("http://127.0.0.1:8080/a.png"); err != nil {
		t.Errorf("测试模式本地地址被拒绝: %v", err)
	}
}

// TestDialRejectsNonPublicResolution 验证 DNS 解析到非公网/混合地址时拒绝连接，
// 且解析失败按远端不可用处理；不发起真实外网连接。
func TestDialRejectsNonPublicResolution(t *testing.T) {
	private := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: 1,
	}, fakeResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}})
	if _, err := private.dial(context.Background(), "tcp", "evil.example:443"); !errors.Is(err, ErrRemoteBlocked) {
		t.Errorf("私有地址解析错误 = %v，期望 ErrRemoteBlocked", err)
	}
	mixed := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: 1,
	}, fakeResolver{addresses: []net.IPAddr{
		{IP: net.ParseIP("93.184.216.34")},
		{IP: net.ParseIP("127.0.0.1")},
	}})
	if _, err := mixed.dial(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrRemoteBlocked) {
		t.Errorf("混合地址解析错误 = %v，期望整体拒绝 ErrRemoteBlocked", err)
	}
	failing := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: 1,
	}, fakeResolver{err: errors.New("dns boom")})
	if _, err := failing.dial(context.Background(), "tcp", "down.example:443"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Errorf("解析失败错误 = %v，期望 ErrRemoteUnavailable", err)
	}
	blockedPort := newNetworkFetcher(resolvedNetwork{
		maxBytes: MaxUploadBytes, timeout: time.Second, maxRedirects: 1,
	}, fakeResolver{})
	if _, err := blockedPort.dial(context.Background(), "tcp", "example.com:8443"); !errors.Is(err, ErrRemoteBlocked) {
		t.Errorf("非默认端口错误 = %v，期望 ErrRemoteBlocked", err)
	}
}

// TestStorageJoinRejectsEscape 验证受控存储键拼路径的逃逸防护。
func TestStorageJoinRejectsEscape(t *testing.T) {
	storage, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("构造存储: %v", err)
	}
	valid := "ab/" + strings.Repeat("0", 32) + ".png"
	path, err := storage.join(valid)
	if err != nil {
		t.Fatalf("合法键被拒绝: %v", err)
	}
	if !strings.HasPrefix(path, storage.root) {
		t.Errorf("合法键解析到受控目录之外: %q", path)
	}
	for _, key := range []string{
		"../evil.png", "ab/../../../evil.png", "/etc/passwd",
		"ab/" + strings.Repeat("0", 32) + ".svg",
		"ab/" + strings.Repeat("0", 33) + ".png",
	} {
		if _, err := storage.join(key); err == nil {
			t.Errorf("非法键 %q 未被拒绝", key)
		}
	}
}
