package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeResourceServiceConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "login.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	return path
}

func TestLoadResourceServicesYAML(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  resource_services:
    - service_id: billing-api
      client_id: app_billing
      audience: https://billing.example.test/api
`)
	cfg, err := Load(LoadOptions{YAMLFile: path})
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(cfg.Protocol.ResourceServices) != 1 {
		t.Fatalf("资源服务数量错误: %+v", cfg.Protocol.ResourceServices)
	}
	entry := cfg.Protocol.ResourceServices[0]
	if entry.ServiceID != "billing-api" || entry.ClientID != "app_billing" ||
		entry.Audience != "https://billing.example.test/api" {
		t.Fatalf("资源服务字段错误: %+v", entry)
	}
}

func TestResourceServicesRequireProtocolEnabled(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  resource_services:
    - service_id: billing-api
      client_id: app_billing
      audience: https://billing.example.test/api
`)
	if _, err := Load(LoadOptions{YAMLFile: path}); err == nil {
		t.Fatal("未启用协议端点时应拒绝资源服务登记")
	}
}

func TestResourceServicesRejectInvalidAudience(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  resource_services:
    - service_id: billing-api
      client_id: app_billing
      audience: not-an-absolute-uri
`)
	if _, err := Load(LoadOptions{YAMLFile: path}); err == nil {
		t.Fatal("非法 audience 应被拒绝")
	}
}

func TestResourceServicesRejectDuplicateServiceID(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  resource_services:
    - service_id: billing-api
      client_id: app_billing
      audience: https://billing.example.test/api
    - service_id: billing-api
      client_id: app_billing
      audience: https://billing.example.test/api2
`)
	if _, err := Load(LoadOptions{YAMLFile: path}); err == nil {
		t.Fatal("重复 service_id 应被拒绝")
	}
}

func TestIntrospectionRequiresResourceService(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  enable_introspection: true
`)
	if _, err := Load(LoadOptions{YAMLFile: path}); err == nil {
		t.Fatal("状态查询缺少资源服务登记时应拒绝")
	}
}
