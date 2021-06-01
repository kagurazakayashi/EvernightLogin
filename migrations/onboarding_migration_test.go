package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const onboardingMigration = "0014_onboarding.sql"

// readOnboardingMigration 读取 0014 邀请与注册审核迁移。
func readOnboardingMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(onboardingMigration)
	if err != nil {
		t.Fatalf("读取入驻迁移失败: %v", err)
	}
	return string(data)
}

// TestOnboardingMigration 校验步骤 34 的邀请/接受/审核结构：状态枚举、二选一目标
// 约束、使用次数边界、到期单调、重复接受唯一键、审核决定互斥约束；不含令牌/邮件
// 正文等可重放秘密。
func TestOnboardingMigration(t *testing.T) {
	sqlText := readOnboardingMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 4 {
		t.Fatalf("0014 CREATE TABLE 数量 = %d，期望 4", count)
	}
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"inviter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"target_kind TEXT NOT NULL CHECK(target_kind IN('email','user'))",
		"status TEXT NOT NULL CHECK(status IN('pending','accepted','cancelled','expired'))",
		"max_uses INTEGER NOT NULL DEFAULT 1 CHECK(max_uses BETWEEN 1 AND 50)",
		"used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count>=0 AND used_count<=max_uses)",
		"notify_state TEXT NOT NULL DEFAULT 'pending' CHECK(notify_state IN('pending','sent','failed'))",
		"CHECK((target_kind='email' AND target_email IS NOT NULL AND target_user_id IS NULL)",
		"CHECK(expires_at_ms>created_at_ms)",
		"PRIMARY KEY(invitation_id,user_id)",
		"user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"status TEXT NOT NULL CHECK(status IN('pending','approved','rejected'))",
		"CHECK((status='pending' AND decided_at_ms IS NULL)",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0014 缺少定义 %q", want)
		}
	}
	for _, forbidden := range []string{" token ", " secret ", " body ", " plaintext ", " password "} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0014 不应引入明文敏感列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_invitations_inviter ON invitations(inviter_user_id,created_at_ms);",
		"CREATE INDEX ix_invitations_email ON invitations(target_email);",
		"CREATE INDEX ix_registration_reviews_status ON registration_reviews(status,created_at_ms);",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0014 缺少索引 %q", index)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
