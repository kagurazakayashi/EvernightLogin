package netguard_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netguard"
)

type resolverStub struct{ ips []string }

func (r *resolverStub) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	addresses := make([]net.IPAddr, 0, len(r.ips))
	for _, value := range r.ips {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(value)})
	}
	return addresses, nil
}

// TestIPClassification 验证公网/私网/环回/链路本地/CGNAT/保留/映射地址分类。
func TestIPClassification(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"}
	for _, value := range public {
		if !netguard.IsPublicIP(net.ParseIP(value)) {
			t.Errorf("%s 应判定为公网地址", value)
		}
	}
	private := []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1",
		"::1", "fe80::1", "fc00::1", "2001:db8::1", "64:ff9b::1", "::ffff:127.0.0.1"}
	for _, value := range private {
		if netguard.IsPublicIP(net.ParseIP(value)) {
			t.Errorf("%s 应被拒绝", value)
		}
	}
}

// TestValidateURL 验证协议/凭证/端口/主机列表与测试开关。
func TestValidateURL(t *testing.T) {
	validator, err := netguard.NewValidator(netguard.Policy{
		Timeout: 5 * time.Second, AllowedHosts: []string{"hooks.example.test"},
	}, nil)
	if err != nil {
		t.Fatalf("构造校验器: %v", err)
	}
	if _, err := validator.ValidateURL("https://hooks.example.test/path"); err != nil {
		t.Fatalf("合法 https 地址被拒绝: %v", err)
	}
	cases := []struct {
		url     string
		blocked bool
	}{
		{"http://hooks.example.test/path", true},
		{"https://user:pass@hooks.example.test/path", true},
		{"https://hooks.example.test:8443/path", true},
		{"https://other.example.test/path", true},
		{"https://127.0.0.1/path", true},
		{"https://[::1]/path", true},
		{"https://hooks.example.test/path#fragment", false},
	}
	for _, test := range cases {
		_, err := validator.ValidateURL(test.url)
		if test.blocked && !errors.Is(err, netguard.ErrBlocked) &&
			!errors.Is(err, netguard.ErrInvalidURL) {
			t.Errorf("%s 应被拒绝，得到 %v", test.url, err)
		}
		if !test.blocked && err != nil {
			t.Errorf("%s 应允许，得到 %v", test.url, err)
		}
	}
}

// TestDialRejectsRepeatedResolution 验证连接前重新解析并拒绝敏感地址。
func TestDialRejectsRepeatedResolution(t *testing.T) {
	validator, err := netguard.NewValidator(netguard.Policy{Timeout: 2 * time.Second},
		&resolverStub{ips: []string{"10.0.0.1"}})
	if err != nil {
		t.Fatalf("构造校验器: %v", err)
	}
	client := validator.NewClient()
	if _, err := client.Get("https://hooks.example.test/path"); !errors.Is(err,
		netguard.ErrBlocked) {
		t.Fatalf("私网解析结果应被拒绝，得到 %v", err)
	}
}
