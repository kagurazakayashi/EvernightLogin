package main

import (
	"strings"
	"testing"
)

// TestConfigAccountNameAmbiguity 验证工具层在配置解析/合并阶段就拒绝“大小写或
// Unicode 归一化后相同”的模拟账户用户名，给出中文错误而不是等到启动失败。
func TestConfigAccountNameAmbiguity(t *testing.T) {
	path := writeConfigFile(t, `
auth:
  accounts:
    - username: "tester"
      password: "pass-a"
    - username: "Tester"
      password: "pass-b"
`)
	if _, err := loadConfigFile(path); err == nil {
		t.Fatal("配置文件中归一化后重复的用户名应被拒绝")
	} else if !strings.Contains(err.Error(), "归一化") {
		t.Errorf("错误信息应说明归一化歧义: %v", err)
	}

	// 命令行 -auth 来源同样在合并阶段被拒绝。
	if _, err := resolveConfig(defaultFileConfig(), cliOverrides{
		set:  map[string]bool{"auth": true},
		auth: credentials{"tester": "pass-a", "Tester": "pass-b"},
	}); err == nil {
		t.Fatal("命令行 -auth 归一化后重复的用户名应被拒绝")
	} else if !strings.Contains(err.Error(), "归一化") {
		t.Errorf("错误信息应说明归一化歧义: %v", err)
	}
}
