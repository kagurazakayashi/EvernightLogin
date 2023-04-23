package login

import "testing"

func TestDeviceCodeRequiresPublicBaseURL(t *testing.T) {
	path := writeResourceServiceConfig(t, `
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  device_code_enabled: true
`)
	if _, err := Load(LoadOptions{YAMLFile: path}); err == nil {
		t.Fatal("启用设备码缺少 server.public_base_url 应拒绝")
	}
}

func TestDeviceCodeWithPublicBaseURLLoads(t *testing.T) {
	path := writeResourceServiceConfig(t, `
server:
  public_base_url: http://127.0.0.1:8080
protocol:
  enabled: true
  issuer: http://127.0.0.1:8080
  device_code_enabled: true
`)
	cfg, err := Load(LoadOptions{YAMLFile: path})
	if err != nil {
		t.Fatalf("设备码配置应可加载: %v", err)
	}
	if !cfg.Protocol.DeviceCodeEnabled {
		t.Fatal("device_code_enabled 未生效")
	}
}
