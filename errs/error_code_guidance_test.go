package errs

// 步骤 74：错误码公开说明补充（可能原因/处理建议/重试条件）与手册逐项校验。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestErrorCodeGuidanceMatchesManual 逐项比较公开说明补充与错误码手册第 3 节，
// 防止页面展示的原因/建议与手册逐渐失配。手册不存在时跳过并记录限制。
func TestErrorCodeGuidanceMatchesManual(t *testing.T) {
	path := filepath.Join("..", "docs", "requirements", "login_错误码与排障手册.md")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 手册是错误码说明的同一事实源；缺失时说明覆盖无法验证，按失败处理，
			// 避免静默失去校验（产品文档属于可提交内容，构建环境应携带）。
			t.Fatalf("错误码手册不存在，无法校验公开说明：%v", err)
		}
		t.Fatalf("读取错误码手册失败：%v", err)
	}
	rows := parseManualGuidanceRows(t, string(data))
	if len(rows) != 48 {
		t.Fatalf("手册说明行数 = %d，期望 48", len(rows))
	}
	if len(errorCodeGuidance) != len(rows) {
		t.Fatalf("说明补充 %d 项，手册 %d 项", len(errorCodeGuidance), len(rows))
	}
	for _, row := range rows {
		guidance, ok := LookupErrorCodeGuidance(ErrorCode(row.code))
		if !ok {
			t.Errorf("错误码 %s 缺少公开说明补充", row.code)
			continue
		}
		if guidance.Cause != row.cause {
			t.Errorf("错误码 %s 可能原因：代码 %q，手册 %q", row.code, guidance.Cause, row.cause)
		}
		if guidance.Advice != row.advice {
			t.Errorf("错误码 %s 处理建议：代码 %q，手册 %q", row.code, guidance.Advice, row.advice)
		}
		if guidance.Retry != row.retry {
			t.Errorf("错误码 %s 重试规则：代码 %q，手册 %q", row.code, guidance.Retry, row.retry)
		}
	}
	if _, ok := LookupErrorCodeGuidance(ErrorCode("NOT_REGISTERED")); ok {
		t.Error("未登记错误码不应返回公开说明")
	}
}

// manualGuidanceRow 是手册表格中一行公开说明。
type manualGuidanceRow struct {
	code, cause, advice, retry string
}

// parseManualGuidanceRows 解析手册第 3 节表格的后三列；只接受全大写错误码。
func parseManualGuidanceRows(t *testing.T, markdown string) []manualGuidanceRow {
	t.Helper()
	var rows []manualGuidanceRow
	for _, line := range strings.Split(markdown, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for index := range cells {
			cells[index] = strings.TrimSpace(cells[index])
		}
		if len(cells) < 7 {
			continue
		}
		code := cells[0]
		if code == "" || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			continue
		}
		rows = append(rows, manualGuidanceRow{code: code, cause: cells[4],
			advice: cells[5], retry: cells[6]})
	}
	return rows
}
