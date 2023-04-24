package serverapp

import (
	"context"
	"testing"
)

func testResourceRegistry() *resourceRegistry {
	return &resourceRegistry{byClient: map[string][]resourceServiceEntry{
		"app_billing": {
			{ServiceID: "billing-api", ClientID: "app_billing", Audience: "https://billing.example.test/api"},
			{ServiceID: "billing-api", ClientID: "app_billing", Audience: "https://billing.example.test/api2"},
		},
		"app_other": {
			{ServiceID: "other-api", ClientID: "app_other", Audience: "https://other.example.test/api"},
		},
	}}
}

func TestResourceRegistryResolve(t *testing.T) {
	registry := testResourceRegistry()
	if _, err := registry.resolve("app_billing", "https://billing.example.test/api2"); err != nil {
		t.Fatalf("已登记 audience 解析失败: %v", err)
	}
	if _, err := registry.resolve("app_billing", "https://evil.example.test/api"); err == nil {
		t.Fatal("未登记 audience 必须拒绝")
	}
	if _, err := registry.resolve("unknown", "https://billing.example.test/api"); err == nil {
		t.Fatal("未登记客户端必须拒绝")
	}
	if _, err := registry.resolve("app_billing", ""); err == nil {
		t.Fatal("多 audience 客户端未指定 audience 时必须拒绝")
	}
}

func TestResourceInspectAuthorizer(t *testing.T) {
	registry := testResourceRegistry()
	authorizer := resourceInspectAuthorizer{registry: registry}
	permission, err := authorizer.AuthorizeInspection(context.Background(),
		"app_billing", "https://billing.example.test/api")
	if err != nil || !permission.Allowed {
		t.Fatalf("已登记资源应允许 introspection: %+v %v", permission, err)
	}
	if permission.ShowSubject {
		t.Fatal("跨资源 introspection 不应默认披露 sub")
	}
	permission, err = authorizer.AuthorizeInspection(context.Background(),
		"app_billing", "https://other.example.test/api")
	if err != nil || permission.Allowed {
		t.Fatalf("未登记 audience 必须拒绝: %+v %v", permission, err)
	}
}

func TestResourceInspectClientAuthorizerRejectsCrossClient(t *testing.T) {
	registry := testResourceRegistry()
	authorizer := resourceInspectClientAuthorizer{registry: registry}
	if err := authorizer.AuthorizeClientInspection(context.Background(),
		"app_billing", "app_billing", "https://billing.example.test/api"); err != nil {
		t.Fatalf("同客户端刷新令牌查询应允许: %v", err)
	}
	if err := authorizer.AuthorizeClientInspection(context.Background(),
		"app_billing", "app_other", "https://billing.example.test/api"); err == nil {
		t.Fatal("跨客户端刷新令牌查询必须拒绝")
	}
}
