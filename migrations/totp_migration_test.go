package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestTOTPMigration 校验 0021：mfa_challenges 重建后允许 totp 因素且保留 0020 全部列；
// totp_bindings 区分 pending/active、同一用户最多一个 active、种子以密文列保存、
// 参数有 CHECK 界限并记录 last_accepted_step；不得出现明文种子列。
func TestTOTPMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0021_totp.sql")
	if err != nil {
		t.Fatalf("读取 TOTP 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0021 CREATE TABLE 数量 = %d，期望 2（重建挑战表 + 绑定表）", count)
	}
	for _, want := range []string{
		"CREATE TABLE mfa_challenges_v2 (",
		"factor_type TEXT NOT NULL CHECK(factor_type IN('email','totp'))",
		"app_id TEXT NOT NULL DEFAULT ''",
		"restricted_session_id TEXT NOT NULL DEFAULT ''",
		"attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)",
		"max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10)",
		"INSERT INTO mfa_challenges_v2(",
		"FROM mfa_challenges;",
		"ALTER TABLE mfa_challenges_v2 RENAME TO mfa_challenges;",
		"CREATE TABLE totp_bindings (",
		"status TEXT NOT NULL CHECK(status IN('pending','active','disabled'))",
		"sealed_secret BLOB NOT NULL CHECK(length(sealed_secret) > 0)",
		"algorithm TEXT NOT NULL DEFAULT 'SHA1' CHECK(algorithm IN('SHA1'))",
		"digits INTEGER NOT NULL DEFAULT 6 CHECK(digits BETWEEN 6 AND 8)",
		"period_seconds INTEGER NOT NULL DEFAULT 30 CHECK(period_seconds BETWEEN 15 AND 60)",
		"window_steps INTEGER NOT NULL DEFAULT 1 CHECK(window_steps BETWEEN 0 AND 3)",
		"last_accepted_step INTEGER NOT NULL DEFAULT -1",
		"expires_at_ms INTEGER NOT NULL",
		"activated_at_ms INTEGER",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0021 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_totp_bindings_user_status",
		"CREATE UNIQUE INDEX ux_totp_bindings_user_active",
		"CREATE INDEX ix_mfa_challenges_user_state",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0021 缺少索引 %q", index)
		}
	}
	// 不得保存明文种子/验证码/恢复码。
	for _, forbidden := range []string{
		" seed TEXT", " secret TEXT", " code TEXT", " plaintext", " recovery_codes",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0021 不应引入明文敏感列 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
