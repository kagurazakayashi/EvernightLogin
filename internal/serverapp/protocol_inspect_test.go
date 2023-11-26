package serverapp

// 步骤 227：令牌状态查询受控 Go 入口的边界单元测试。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

func TestResourceRegistryLookupByServiceID(t *testing.T) {
	registry := &resourceRegistry{byClient: map[string][]resourceServiceEntry{
		"client_a": {{ServiceID: "svc-a", ClientID: "client_a", Audience: "https://a.example/api"}},
		"client_b": {{ServiceID: "svc-b", ClientID: "client_b", Audience: "https://b.example/api"}},
	}}
	entry, err := registry.lookupByServiceID("svc-a")
	if err != nil || entry.ClientID != "client_a" ||
		entry.Audience != "https://a.example/api" {
		t.Fatalf("按 service_id 查询 = %+v err=%v", entry, err)
	}
	for _, serviceID := range []string{"", "unknown"} {
		if _, err := registry.lookupByServiceID(serviceID); err == nil {
			t.Fatalf("非法/未登记 service_id %q 应拒绝", serviceID)
		}
	}
	// 首尾空白按规范化后的值匹配（配置登记同样去除空白）。
	if entry, err := registry.lookupByServiceID(" svc-b "); err != nil ||
		entry.ClientID != "client_b" {
		t.Fatalf("带空白 service_id = %+v err=%v", entry, err)
	}
	if _, err := (*resourceRegistry)(nil).lookupByServiceID("svc-a"); err == nil {
		t.Fatal("nil 登记必须拒绝")
	}
}

func TestInspectTokenForResourceServiceFailClosed(t *testing.T) {
	ctx := context.Background()
	var nilDomains *ProtocolDomains
	if _, err := nilDomains.InspectTokenForResourceService(ctx, "svc", "token",
		"", "", "req_x"); !errors.Is(err, ErrProtocolInspectDisabled) {
		t.Fatalf("nil 协议域错误 = %v，期望 ErrProtocolInspectDisabled", err)
	}
	disabled := &ProtocolDomains{registry: &resourceRegistry{
		byClient: map[string][]resourceServiceEntry{
			"client_a": {{ServiceID: "svc", ClientID: "client_a",
				Audience: "https://a.example/api"}}}}}
	if _, err := disabled.InspectTokenForResourceService(ctx, "svc", "token",
		"", "", "req_x"); !errors.Is(err, ErrProtocolInspectDisabled) {
		t.Fatalf("未启用状态查询错误 = %v，期望 ErrProtocolInspectDisabled", err)
	}
	// 启用但 service_id/audience 不属于登记项：在调用令牌服务前拒绝。
	enabled := &ProtocolDomains{InspectEnabled: true, OAuthFlow: &oauthflow.Service{},
		registry: disabled.registry}
	if _, err := enabled.InspectTokenForResourceService(ctx, "unknown", "token",
		"", "", "req_x"); !errors.Is(err, ErrResourceServiceUnknown) {
		t.Fatalf("未登记 service_id 错误 = %v，期望 ErrResourceServiceUnknown", err)
	}
	if _, err := enabled.InspectTokenForResourceService(ctx, "svc", "token",
		"", "https://other.example/api", "req_x"); !errors.Is(err,
		ErrResourceServiceUnknown) {
		t.Fatalf("跨资源 audience 错误 = %v，期望 ErrResourceServiceUnknown", err)
	}
}
