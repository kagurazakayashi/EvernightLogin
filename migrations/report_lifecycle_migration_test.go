package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestReportLifecycleMigration 校验 0042 报告计划与报告历史表：计划/执行身份分开、
// 范围与周期受约束、状态使用真实任务状态（含取消请求与超时）、时间使用 UTC 毫秒
// 整数、JSON 列有效；不保存产物宿主路径、原始审计/凭证/秘密或本地时间文本。
func TestReportLifecycleMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0042_report_lifecycle.sql")
	if err != nil {
		t.Fatalf("读取 0042 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table report_plans",
		"id text primary key",
		"owner_type text not null check(owner_type in('user','system','local_admin'))",
		"execution_actor_type text not null check(execution_actor_type in('user','system','local_admin'))",
		"scope_kind text not null check(scope_kind in('system','app'))",
		"schedule_type text not null check(schedule_type in('daily','weekly','monthly','custom'))",
		"time_zone text not null check(length(time_zone) > 0 and time_zone <> 'local')",
		"granularity text not null check(granularity in('day','week','month'))",
		"window_days integer not null check(window_days between 1 and 90)",
		"missed_policy text not null check(missed_policy in('skip','latest','all'))",
		"enabled integer not null check(enabled in(0,1))",
		"version integer not null check(version >= 1)",
		"create index ix_report_plans_owner",
		"create index ix_report_plans_scope",
		"create table report_history",
		"state text not null check(state in(",
		"'queued','running','cancel_requested','cancelled','succeeded','failed','timed_out'",
		"data_scope_json text not null default '{}' check(json_valid(data_scope_json))",
		"snapshot_json text not null default '' check(snapshot_json = '' or json_valid(snapshot_json))",
		"artifacts_json text not null default '[]' check(json_valid(artifacts_json))",
		"cleanup_state text not null default 'none'",
		"create index ix_report_history_scope_time",
		"create index ix_report_history_plan_time",
		"create index ix_report_history_state_time",
		// 计划历史在计划删除后仍保留：plan_id 不能声明级联删除。
		"plan_id text not null default ''",
		"retry_of text not null default ''",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0042 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password", "token_plain", "secret", "mfa_seed", "recovery_code",
		"dsn", "connection_string", "host_path", "raw_log", "username",
		"on delete cascade", "on delete set null",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0042 不应保存敏感/原始内容或级联删除历史: %s", forbidden)
		}
	}
	// 报告生命周期元数据必须使用毫秒整数时间，不使用本地时间文本。
	for _, timeColumn := range []string{
		"created_at text", "started_at text", "finished_at text",
		"expires_at text", "retention_until text",
	} {
		if strings.Contains(sql, timeColumn) {
			t.Fatalf("0042 不应使用本地时间文本列: %s", timeColumn)
		}
	}
	// 取消请求与实际取消必须是不同状态，不能合并成一种。
	if !strings.Contains(sql, "'cancel_requested','cancelled'") {
		t.Fatal("0042 必须分开表示取消请求已接受与实际取消")
	}
}
