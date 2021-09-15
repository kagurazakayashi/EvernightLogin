package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestRestoreLifecycleMigration 校验 0044 恢复生命周期迁移：恢复代际单行且非负、
// 恢复运行记录区分 completed/failed/rolled_back、暂停清单只引用真实恢复运行且按
// restore_id+kind+target_id 唯一；不含备份正文、密钥材料、凭据明文、宿主绝对路径、
// 级联删除或原始审计清理结构。
func TestRestoreLifecycleMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0044_restore_lifecycle.sql")
	if err != nil {
		t.Fatalf("读取 0044 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table restore_generation",
		"id integer primary key check(id=1)",
		"generation integer not null check(generation >= 0)",
		"insert into restore_generation(id,generation,updated_at_ms) values(1,0,0)",
		"create table restore_runs",
		"restore_id text primary key",
		"operator_type text not null check(operator_type in('user','local_admin','system'))",
		"status text not null check(status='completed')",
		"rollback_backup_file text not null default ''",
		"result_json text not null default '{}' check(json_valid(result_json))",
		"create index ix_restore_runs_completed",
		"create table restore_paused_items",
		"kind text not null check(kind in('schedule','webhook','job','mail','notification'))",
		"references restore_runs(restore_id) on delete restrict",
		"unique(restore_id,kind,target_id)",
		"reviewed_at_ms",
		"reenabled_at_ms",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0044 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password", "token_plain", "recovery_code", "mfa_seed", "key_material",
		"private_key", "host_path", "absolute_path", "on delete cascade",
		"on delete set null", "delete from audit_events", "backup_content",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0044 不应保存秘密/宿主路径、级联删除或审计清理结构: %s", forbidden)
		}
	}
}
