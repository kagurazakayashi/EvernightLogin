package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestStatisticsMigration 校验 0041 统计采样与可信业务活动表：健康采样按
// (module, observed_at_ms) 幂等、业务活动 (app_id, dedupe_key) 幂等唯一且来源受约束、时间使用
// UTC 毫秒整数；不保存连接串、凭据、原始事件正文或自由文本。
func TestStatisticsMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0041_statistics.sql")
	if err != nil {
		t.Fatalf("读取 0041 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table stats_health_samples",
		"module text not null",
		"observed_at_ms integer not null check(observed_at_ms >= 0)",
		"state text not null",
		"enabled integer not null check(enabled in(0,1))",
		"detail_json text not null default '{}' check(json_valid(detail_json))",
		"primary key(module, observed_at_ms)",
		"create index ix_stats_health_samples_observed_at_ms",
		"create table stats_business_activity",
		"dedupe_key text not null",
		"source text not null check(source in('app_server'))",
		"create unique index ux_stats_business_activity_app_dedupe_key",
		"on stats_business_activity(app_id,dedupe_key)",
		"create index ix_stats_business_activity_occurred_at_ms",
		"create index ix_stats_business_activity_app_time",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0041 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"password", "token_plain", "secret", "mfa_seed", "recovery_code",
		"dsn", "connection_string", "host_path", "raw_log", "username",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0041 不应保存敏感/原始内容列: %s", forbidden)
		}
	}
	// 统计采样与业务活动都必须使用毫秒整数时间，不使用本地时间文本。
	if strings.Contains(sql, "occurred_at text") || strings.Contains(sql, "observed_at text") {
		t.Fatal("0041 不应使用本地时间文本列")
	}
}
