package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestUserBatchMigration 校验 0039 用户批量导入导出表：幂等键唯一、调用者/摘要绑定、
// 逐行结果主键、导入文件大小上限、无密码/哈希/MFA/自由文本秘密列。
func TestUserBatchMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0039_user_batch.sql")
	if err != nil {
		t.Fatalf("读取 0039 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table user_batch_jobs",
		"kind text not null check(kind in('import','export'))",
		"idempotency_key text not null unique",
		"request_digest blob not null check(length(request_digest)=32)",
		"owner_type text not null",
		"owner_id text not null",
		"state text not null check(state in('queued','running','succeeded','partial','failed','cancelled'))",
		"input_csv blob check(input_csv is null or length(input_csv)<=5242880)",
		"export_sha256 blob check(export_sha256 is null or length(export_sha256)=32)",
		"ix_user_batch_jobs_owner",
		"create table user_batch_rows",
		"action text not null check(action in('created','skipped','conflict','failed','denied'))",
		"primary key(job_id, row_number)",
		"ix_user_batch_rows_action",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0039 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password text", "password_hash", "mfa_secret", "totp_secret",
		"recovery_code text", "raw_row text", "row_content", "secret text",
		"is_root integer", "verified_at_ms",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0039 不应保存秘密或原始行内容列: %s", forbidden)
		}
	}
}
