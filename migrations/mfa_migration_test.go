package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestMFAMigration 校验 0020 的 MFA 因素与挑战结构：每用户每类型唯一因素、挑战绑定
// 用户/尝试摘要/用途/因素/凭证/代数、状态机枚举与过期索引，且不保存明文验证码、
// 密码或会话秘密。
func TestMFAMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0020_mfa.sql")
	if err != nil {
		t.Fatalf("读取 MFA 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0020 CREATE TABLE 数量 = %d，期望 2", count)
	}
	for _, want := range []string{
		"CREATE TABLE mfa_factors (",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"factor_type TEXT NOT NULL CHECK(factor_type IN('email'))",
		"status TEXT NOT NULL CHECK(status IN('active','disabled'))",
		"UNIQUE(user_id, factor_type)",
		"CREATE TABLE mfa_challenges (",
		"purpose TEXT NOT NULL CHECK(purpose IN('login','factor_enroll'))",
		"attempt_sha256 BLOB NOT NULL CHECK(length(attempt_sha256) = 32)",
		"credential_id TEXT NOT NULL",
		"generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1)",
		"state TEXT NOT NULL CHECK(state IN('pending','verified','failed','expired','cancelled'))",
		"app_id TEXT NOT NULL DEFAULT ''",
		"remember_me INTEGER NOT NULL DEFAULT 0 CHECK(remember_me IN(0,1))",
		"client_user_agent TEXT NOT NULL DEFAULT ''",
		"client_address TEXT NOT NULL DEFAULT ''",
		"restricted_session_id TEXT NOT NULL DEFAULT ''",
		"attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)",
		"max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10)",
		"security_version INTEGER NOT NULL DEFAULT 0",
		"completed_at_ms INTEGER NOT NULL DEFAULT 0",
		"expires_at_ms INTEGER NOT NULL",
		"verified_at_ms INTEGER",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0020 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_mfa_factors_user",
		"CREATE INDEX ix_mfa_challenges_user_state",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0020 缺少索引 %q", index)
		}
	}
	for _, forbidden := range []string{
		" code TEXT", " secret TEXT", " password", " token TEXT", " session", " plaintext",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0020 不应引入敏感列 %q", forbidden)
		}
	}
	for _, future := range []string{
		"CREATE TABLE totp_credentials", "CREATE TABLE passkey_credentials",
		"CREATE TABLE webauthn_credentials", "CREATE TABLE recovery_codes",
	} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0020 提前创建了后续因素表 %q", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
