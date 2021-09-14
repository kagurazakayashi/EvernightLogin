package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestBackupLifecycleMigration 校验 0043 备份生命周期迁移：产物只保存受控元数据、
// 保留策略单行且必须有至少一项有限上限、计划附加配置与状态/通知分开、任务索引不
// 复制任务状态机；不含宿主路径、密钥材料、通知地址原文、级联删除或原始审计清理。
func TestBackupLifecycleMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0043_backup_lifecycle.sql")
	if err != nil {
		t.Fatalf("读取 0043 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table backup_artifacts",
		"backup_id text primary key",
		"origin text not null default 'manual' check(origin in('manual','schedule','catch_up','retry','system'))",
		"file_name text not null",
		"file_sha256 text not null check(length(file_sha256) = 64)",
		"manifest_sha256 text not null check(length(manifest_sha256) = 64)",
		"verification_state text not null check(verification_state in('verified','unverified','unknown','failed'))",
		"cleanup_state text not null default 'retained' check(cleanup_state in('retained','cleaned'))",
		"check(cleanup_state <> 'cleaned' or cleaned_at_ms > 0)",
		"check(verification_state <> 'verified' or verified_at_ms > 0)",
		"create index ix_backup_artifacts_published",
		"create table backup_retention_policy",
		"id integer primary key check(id = 1)",
		"max_count integer not null check(max_count >= 0)",
		"max_age_days integer not null check(max_age_days >= 0 and max_age_days <= 36500)",
		"max_total_bytes integer not null check(max_total_bytes >= 0)",
		"updated_by_type text not null check(updated_by_type in('user','system','local_admin'))",
		"check(max_count > 0 or max_age_days > 0 or max_total_bytes > 0)",
		"create table backup_schedules",
		"notify_failures integer not null default 0 check(notify_failures in(0,1))",
		"notify_success integer not null default 0 check(notify_success in(0,1))",
		"create table backup_jobs",
		"kind text not null check(kind in('backup.create','backup.cleanup'))",
		"create table backup_job_state",
		"stage_code text not null default ''",
		"progress_done integer",
		"progress_total integer",
		"notification_state text not null default 'not_configured'",
		"create table backup_notifications",
		"kind text not null check(kind in('backup_succeeded','backup_failed','backup_timeout','permission_denied','cleanup_failed'))",
		"state text not null check(state in('pending','accepted','failed','unknown'))",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0043 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password", "token_plain", "recovery_code", "mfa_seed", "key_material",
		"private_key", "host_path", "absolute_path", "on delete cascade",
		"on delete set null", "audit_purge", "delete from audit_events",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0043 不应保存秘密/宿主路径、级联删除或审计清理结构: %s", forbidden)
		}
	}
}
