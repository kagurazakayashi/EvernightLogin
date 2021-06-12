package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestFIDO2SecondFactorMigration 校验 0023：凭证用途扩展 login/second_factor/both、
// ceremony 增加 purpose/context_id 与 second_factor 操作类型、mfa 挑战扩展 passkey
// 因素与 strong_setup 用途并新增 factor_ref；原有 email/totp 行保留。
func TestFIDO2SecondFactorMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0023_fido2_second_factor.sql")
	if err != nil {
		t.Fatalf("读取 0023 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0023 CREATE TABLE 数量 = %d，期望 3（重建三张表）", count)
	}
	for _, want := range []string{
		"CREATE TABLE mfa_challenges_v3 (",
		"factor_type TEXT NOT NULL CHECK(factor_type IN('email','totp','passkey'))",
		"purpose TEXT NOT NULL CHECK(purpose IN('login','factor_enroll','strong_setup'))",
		"factor_ref TEXT NOT NULL DEFAULT ''",
		"require_strong INTEGER NOT NULL DEFAULT 0 CHECK(require_strong IN(0,1))",
		"FROM mfa_challenges;",
		"ALTER TABLE mfa_challenges_v3 RENAME TO mfa_challenges;",
		"CREATE TABLE webauthn_credentials_v2 (",
		"usage TEXT NOT NULL DEFAULT 'login' CHECK(usage IN('login','second_factor','both'))",
		"FROM webauthn_credentials;",
		"ALTER TABLE webauthn_credentials_v2 RENAME TO webauthn_credentials;",
		"CREATE TABLE webauthn_ceremonies_v2 (",
		"operation TEXT NOT NULL CHECK(operation IN('registration','authentication','second_factor'))",
		"purpose TEXT NOT NULL DEFAULT 'login' CHECK(purpose IN('login','second_factor','both'))",
		"context_id TEXT NOT NULL DEFAULT ''",
		"FROM webauthn_ceremonies;",
		"ALTER TABLE webauthn_ceremonies_v2 RENAME TO webauthn_ceremonies;",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0023 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_mfa_challenges_user_state",
		"CREATE INDEX ix_webauthn_credentials_user_active",
		"CREATE INDEX ix_webauthn_ceremonies_user_operation",
		"CREATE INDEX ix_webauthn_ceremonies_expires",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0023 缺少索引 %q", index)
		}
	}
	// 使用 INSERT ... SELECT 保留既有行（升级兼容），不得 DROP 后不复制。
	for _, table := range []string{"mfa_challenges", "webauthn_credentials", "webauthn_ceremonies"} {
		if !strings.Contains(sqlText, "FROM "+table+";") {
			t.Errorf("0023 重建 %s 时未复制既有行", table)
		}
	}
	for _, forbidden := range []string{"private_key", "secret TEXT", "seed TEXT", "password TEXT"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0023 不应引入敏感列 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
