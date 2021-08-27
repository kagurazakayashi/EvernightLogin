package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestAuditReadLifecycleMigration 校验 0040 审计读取/导出/保留清理表：
// 单行保留策略、导出筛选与数据范围快照、清理运行计数、受保护追加日志与触发器、
// 以及查询索引。禁止保存文件绝对路径、审计正文或秘密列。
func TestAuditReadLifecycleMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0040_audit_read_lifecycle.sql")
	if err != nil {
		t.Fatalf("读取 0040 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table audit_retention_policy",
		"id integer primary key check(id=1)",
		"retention_days integer not null check(retention_days between 1 and 3650)",
		"create table audit_exports",
		"filter_json text not null check(json_valid(filter_json))",
		"data_scope_json text not null check(json_valid(data_scope_json))",
		"format text not null check(format in('csv','json'))",
		"state text not null check(state in('queued','running','succeeded','failed','cancelled'))",
		"file_sha256 blob check(file_sha256 is null or length(file_sha256)=32)",
		"create table audit_maintenance_runs",
		"scope_kind text not null check(scope_kind in('system','app'))",
		"cutoff_ms integer not null check(cutoff_ms>0)",
		"batch_size integer not null check(batch_size between 1 and 5000)",
		"max_records integer not null check(max_records between 1 and 1000000)",
		"create table audit_maintenance_log",
		"executor_id text",
		"create trigger trg_audit_maintenance_log_no_replace",
		"before insert on audit_maintenance_log",
		"create trigger trg_audit_maintenance_log_no_update",
		"create trigger trg_audit_maintenance_log_no_delete",
		"raise(abort, 'audit_maintenance_log is append-only')",
		"ix_audit_events_app_occurred_at_ms",
		"ix_audit_events_actor_occurred_at_ms",
		"ix_audit_events_outcome_occurred_at_ms",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0040 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password", "token_plain", "secret", "mfa_seed", "recovery_code",
		"absolute_path", "host_path", "file_content", "detail_body",
		"sql_stack", "raw_log",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0040 不应保存敏感/原始内容列: %s", forbidden)
		}
	}
}
