package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestManagedAPIPolicyMigration 校验 0038 托管管理 API 策略表：每应用一行、严格
// JSON 策略、行版本与更新时间约束、外键级联删除，不保存秘密。
func TestManagedAPIPolicyMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0038_managed_api_policies.sql")
	if err != nil {
		t.Fatalf("读取 0038 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table app_managed_api_policies",
		"application_id text primary key not null references applications(id) on delete cascade",
		"policy_json text not null check(json_valid(policy_json))",
		"row_version integer not null default 1 check(row_version>=1)",
		"updated_by text not null default ''",
		"check(updated_at_ms >= created_at_ms)",
		"ix_app_managed_api_policies_updated",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0038 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{"password", "token", "secret", "private_key"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0038 不应保存敏感字段: %s", forbidden)
		}
	}
}
