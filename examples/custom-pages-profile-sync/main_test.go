package main

// main_test.go 让 `go test ./...` 覆盖真实宿主页面 + 资料同步链路：自检本身有界、
// 自清理，因此测试直接复用 executeSelfTest，不复制第二套断言逻辑。它使用真实临时
// SQLite、动态回环端口、进程内本地邮件捕获器与真实 HTTP 请求。

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSelfCheck 断言有界自检全部检查项通过，且临时数据目录被删除。
func TestSelfCheck(t *testing.T) {
	report := executeSelfTest(context.Background(), 150*time.Second)
	if report.Status != "PASS" {
		t.Fatalf("自检状态 = %q，期望 PASS；错误: %s", report.Status, report.Error)
	}
	if len(report.Checks) == 0 {
		t.Fatal("自检未产生任何检查项")
	}
	if report.Port <= 0 || report.ListenAddr == "" || report.MailSinkAddr == "" {
		t.Fatalf("自检未报告有效动态端口/邮件捕获器: listen=%q port=%d mail=%q",
			report.ListenAddr, report.Port, report.MailSinkAddr)
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
	// 结果 JSON 不应包含会话秘密/CSRF 令牌/一次性令牌（自检已断言，这里再粗查）。
	for _, marker := range []string{"host_session=", "csrf_token=", "token="} {
		if strings.Contains(report.Error, marker) {
			t.Errorf("自检错误信息包含敏感标记 %q", marker)
		}
	}
}
