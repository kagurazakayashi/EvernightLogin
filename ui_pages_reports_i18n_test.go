package login_test

// 步骤 79 报告页面 i18n 与模板键自检：报告管理模板中引用的每个静态 i18n 键都必须在
// 内置 zh-CN 目录登记；动态键（状态/周期/粒度/补跑/类别）必须覆盖全部稳定值。
// 该测试直接防止“模板使用 common.label.format 但目录缺键”导致整包测试失败。

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// reportTemplateFiles 是步骤 79 报告管理模板清单。
func reportTemplateFiles() []string {
	return []string{
		"web/templates/page/admin/report_history.html",
		"web/templates/page/admin/report_detail.html",
		"web/templates/page/admin/report_schedules.html",
		"web/templates/page/admin/report_schedule_detail.html",
		"web/templates/page/admin/report_schedule_form.html",
		"web/templates/page/admin/report_schedule_delete.html",
		"web/templates/page/admin/report_retention.html",
	}
}

// TestReportTemplateI18nKeysRegistered 校验模板引用的 i18n 键均已登记。
func TestReportTemplateI18nKeysRegistered(t *testing.T) {
	raw, err := os.ReadFile("web/i18n/zh-CN.json")
	if err != nil {
		t.Fatalf("读取内置 zh-CN 目录失败: %v", err)
	}
	catalog := map[string]string{}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("解析内置 zh-CN 目录失败: %v", err)
	}
	staticKeys := map[string]struct{}{}
	quotedKey := regexp.MustCompile(`\bt "[a-z0-9_.]+"`)
	for _, path := range reportTemplateFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取模板 %s 失败: %v", path, err)
		}
		for _, match := range quotedKey.FindAllString(string(data), -1) {
			key := strings.TrimSuffix(strings.TrimPrefix(match, `t "`), `"`)
			staticKeys[key] = struct{}{}
		}
	}
	missing := make([]string, 0, len(staticKeys))
	for key := range staticKeys {
		if _, ok := catalog[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("报告模板引用了未登记 i18n 键: %v", missing)
	}
	// 动态键：状态/周期/粒度/补跑策略/错误类别必须覆盖全部稳定值。
	dynamic := map[string][]string{
		"page.admin.reports.state":         {"queued", "running", "cancel_requested", "cancelled", "succeeded", "failed", "timed_out"},
		"page.admin.reports.schedule_type": {"daily", "weekly", "monthly", "custom"},
		"page.admin.reports.granularity":   {"day", "week", "month"},
		"page.admin.reports.missed_policy": {"skip", "latest", "all"},
		"page.admin.reports.category":      {"pending", "denied", "cancelled", "warning", "failure", "unknown"},
	}
	for prefix, values := range dynamic {
		for _, value := range values {
			key := prefix + "." + value
			if _, ok := catalog[key]; !ok {
				t.Fatalf("动态 i18n 键未登记: %s", key)
			}
		}
	}
	// 常见通用键（模板大量复用）必须存在，避免再次出现 common.label.format 缺键。
	for _, key := range []string{"common.label.format", "common.label.status",
		"common.label.scope", "common.label.actions", "common.state.all",
		"common.action.cancel", "common.action.apply_filter"} {
		if _, ok := catalog[key]; !ok {
			t.Fatalf("通用 i18n 键未登记: %s", key)
		}
	}
}
