package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// 最小外部 Module 测试：不依赖仓库 internal 包，仅验证自检结构化输出。
func TestSelfTestJSON(t *testing.T) {
	ctx := context.Background()
	result := runSelfTest(ctx)
	if result.Status != "PASS" {
		payload, _ := json.Marshal(result)
		t.Fatalf("自检失败: %s", payload)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("编码自检结果: %v", err)
	}
	if !strings.Contains(string(payload), selfTestSchema) {
		t.Fatalf("自检 schema 缺失: %s", payload)
	}
	if len(result.Checks) < 10 {
		t.Fatalf("自检检查项过少: %d", len(result.Checks))
	}
}
