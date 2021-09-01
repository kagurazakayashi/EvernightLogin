package login

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// TestStatsErrorClassifierCoversRegisteredCodes 核验统计错误分类与根包错误码
// 注册表同步：新增错误码若未同步统计字典会归入“未知”，本测试会失败提醒。
func TestStatsErrorClassifierCoversRegisteredCodes(t *testing.T) {
	for _, definition := range RegisteredErrorCodes() {
		code := string(definition.Code)
		if !stats.IsRegisteredErrorCode(code) {
			t.Errorf("统计字典缺少已登记错误码 %s（错误码与统计分类需同步）", code)
			continue
		}
		classification := stats.ClassifyEvent(audit.OutcomeFailure, code, "test.action")
		if classification.Category == stats.CategoryUnknown {
			t.Errorf("错误码 %s 的故障事件被归入未知类别", code)
		}
		if classification.Category == stats.CategoryFailure && classification.Severity == stats.SeverityUnknown {
			t.Errorf("错误码 %s 的故障事件严重度未知", code)
		}
		if !classification.Counted {
			t.Errorf("错误码 %s 的失败事件未计入错误统计", code)
		}
	}
	// 统计字典不能包含根包未登记的错误码，避免出现两套注册表。
	for _, code := range stats.RegisteredErrorCodes() {
		if _, ok := LookupErrorCode(ErrorCode(code)); !ok {
			t.Errorf("统计字典包含根包未登记错误码 %s", code)
		}
	}
}

// TestStatsClassifierSeparatesFlowStates 核验等待授权/正常拒绝/取消/警告/故障在
// 统计分类中分开，且普通成功动作不计入错误统计。
func TestStatsClassifierSeparatesFlowStates(t *testing.T) {
	cases := []struct {
		name     string
		outcome  audit.Outcome
		code     string
		action   string
		category stats.Category
		counted  bool
	}{
		{"等待授权", audit.OutcomeSuccess, "", "app_qr_login.request_created", stats.CategoryPending, true},
		{"正常拒绝", audit.OutcomeDenied, "ACCESS_DENIED", "role.assign", stats.CategoryDenied, true},
		{"主动取消", audit.OutcomeFailure, "TASK_CANCELLED", "mail.send", stats.CategoryCancelled, true},
		{"数据质量警告", audit.OutcomeFailure, "REPORT_DATA_INCOMPLETE", "report.generate", stats.CategoryWarning, true},
		{"系统故障", audit.OutcomeFailure, "INTERNAL_ERROR", "profile.update", stats.CategoryFailure, true},
		{"普通成功", audit.OutcomeSuccess, "", "session.issue", stats.CategoryUnknown, false},
		{"未登记错误码", audit.OutcomeFailure, "NOT_REGISTERED", "x", stats.CategoryUnknown, true},
		{"取消动作以关键故障结束", audit.OutcomeFailure, "DB_UNAVAILABLE", "email.change.cancel", stats.CategoryFailure, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			classification := stats.ClassifyEvent(testCase.outcome, testCase.code, testCase.action)
			if classification.Category != testCase.category || classification.Counted != testCase.counted {
				t.Errorf("分类 = %+v，期望 category=%s counted=%v",
					classification, testCase.category, testCase.counted)
			}
		})
	}
	// 取消类动作上的关键故障不得被归为 cancelled/info：严重度必须保留 critical。
	critical := stats.ClassifyEvent(audit.OutcomeFailure, "AUDIT_WRITE_FAILED", "audit.purge.cancel")
	if critical.Category != stats.CategoryFailure || critical.Severity != stats.SeverityCritical {
		t.Errorf("取消动作上的关键故障分类 = %+v，期望 failure/critical", critical)
	}
	// 正常成功结束的取消动作仍归 cancelled/info。
	cancelled := stats.ClassifyEvent(audit.OutcomeSuccess, "", "audit.export.cancel")
	if cancelled.Category != stats.CategoryCancelled || cancelled.Severity != stats.SeverityInfo {
		t.Errorf("成功取消动作分类 = %+v，期望 cancelled/info", cancelled)
	}
}
