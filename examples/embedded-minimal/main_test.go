package main

// main_test.go 让 `go test ./...` 也覆盖真实最小嵌入链路：自检本身就是有界、
// 自清理的，因此测试直接调用同一个 executeSelfTest，不复制第二套断言逻辑。
// 它使用真实临时 SQLite、动态回环端口与真实 HTTP 请求，不是内存假实现。

import (
	"context"
	"testing"
	"time"
)

// TestSelfCheck 断言有界自检全部检查项通过，且临时数据目录被删除。
func TestSelfCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report := executeSelfTest(ctx)
	if report.Status != "PASS" {
		t.Fatalf("自检状态 = %q，期望 PASS；错误: %s", report.Status, report.Error)
	}
	if len(report.Checks) == 0 {
		t.Fatal("自检未产生任何检查项")
	}
	if report.Port <= 0 || report.ListenAddr == "" {
		t.Fatalf("自检未报告有效动态回环端口: addr=%q port=%d",
			report.ListenAddr, report.Port)
	}
	if !report.DataDirRemoved || report.DataDir == "" {
		t.Fatalf("临时数据目录未被删除: dir=%q removed=%t",
			report.DataDir, report.DataDirRemoved)
	}
	for _, check := range report.Checks {
		if check.Status != "PASS" {
			t.Errorf("检查项 %s 状态 = %q，期望 PASS（%s）",
				check.ID, check.Status, check.Detail)
		}
	}
}
