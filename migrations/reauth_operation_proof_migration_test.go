package migrations_test

// 步骤 255：0054 目标绑定一次性两步验证操作证明迁移的结构断言。
//
// 校验：
//   - 只追加四列（reauth_challenges/reauth_approvals 各 session_id、intent_sealed）；
//   - 不建表、不回填、不更新数据、不改已发布迁移、不保存令牌/密码明文；
//   - 四列全部可空：0054 之前的旧行没有会话/意图绑定，服务层据此 fail-closed，
//     不在迁移里伪造或回填绑定。

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// migration0054SQLStatements 去掉行注释，只保留可执行 SQL 文本。
func migration0054SQLStatements(sqlText string) string {
	var builder strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

// TestReauthOperationProofMigration 校验 0054 迁移文件的结构与安全边界。
func TestReauthOperationProofMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0054_reauth_operation_proof.sql")
	if err != nil {
		t.Fatalf("读取 0054 迁移: %v", err)
	}
	sqlOnly := migration0054SQLStatements(string(data))
	if count := strings.Count(sqlOnly, "CREATE TABLE "); count != 0 {
		t.Fatalf("0054 不应创建表，CREATE TABLE 数量 = %d", count)
	}
	if count := strings.Count(sqlOnly, "INSERT INTO "); count != 0 {
		t.Fatalf("0054 不应复制/回填数据，INSERT INTO 数量 = %d", count)
	}
	if count := strings.Count(sqlOnly, "UPDATE "); count != 0 {
		t.Fatalf("0054 不应更新数据（旧行不回填），UPDATE 数量 = %d", count)
	}
	alters := 0
	for _, line := range strings.Split(sqlOnly, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ALTER TABLE ") {
			continue
		}
		alters++
		if strings.Contains(trimmed, "NOT NULL") {
			t.Errorf("0054 追加列必须可空以兼容迁移前旧行: %s", trimmed)
		}
	}
	if alters != 4 {
		t.Fatalf("0054 应有 4 条 ALTER TABLE ADD COLUMN 语句，实际 %d", alters)
	}
	for _, want := range []string{
		"ALTER TABLE reauth_challenges ADD COLUMN session_id TEXT;",
		"ALTER TABLE reauth_challenges ADD COLUMN intent_sealed BLOB;",
		"ALTER TABLE reauth_approvals ADD COLUMN session_id TEXT;",
		"ALTER TABLE reauth_approvals ADD COLUMN intent_sealed BLOB;",
	} {
		if !strings.Contains(sqlOnly, want) {
			t.Errorf("0054 缺少定义 %q", want)
		}
	}
	// 不保存秘密明文，也不改动其他对象。
	lowerSQL := strings.ToLower(sqlOnly)
	for _, forbidden := range []string{
		" token ", "token_sha256", "password_hash", " password text",
		"drop table", "drop column", "rename to", "create index",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Errorf("0054 不应包含 %q", forbidden)
		}
	}
}
