package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const coreMigration = "0001_identity_and_scope_core.sql"

func readCoreMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(coreMigration)
	if err != nil {
		t.Fatalf("读取核心迁移失败：%v", err)
	}
	return string(data)
}

// tableDefinition 返回指定表的 CREATE TABLE 片段，便于按结构断言。
func tableDefinition(t *testing.T, sqlText, table string) string {
	t.Helper()
	marker := "CREATE TABLE " + table + " ("
	start := strings.Index(sqlText, marker)
	if start < 0 {
		t.Fatalf("迁移缺少表 %s", table)
	}
	relativeEnd := strings.Index(sqlText[start:], "\n);")
	if relativeEnd < 0 {
		t.Fatalf("表 %s 定义未闭合", table)
	}
	return sqlText[start : start+relativeEnd+3]
}

func TestCoreMigrationCreatesOnlyIsolationCore(t *testing.T) {
	sqlText := readCoreMigration(t)
	expected := []string{
		"users", "applications", "scopes", "app_memberships",
		"roles", "permissions", "role_permissions",
		"user_groups", "group_members", "user_roles", "group_roles",
	}
	if count := strings.Count(sqlText, "CREATE TABLE "); count != len(expected) {
		t.Fatalf("CREATE TABLE 数量 = %d，期望 %d（只创建隔离核心表，未来表由后续迁移落地）",
			count, len(expected))
	}
	for _, table := range expected {
		tableDefinition(t, sqlText, table)
	}
	// 这些表属于后续步骤，当前迁移不应提前创建。
	for _, future := range []string{
		"password_credentials", "sessions", "audit_events", "jobs",
		"oauth_grants", "refresh_tokens", "report_runs", "notifications",
	} {
		if strings.Contains(sqlText, "CREATE TABLE "+future+" (") {
			t.Errorf("迁移提前创建了后续步骤的表 %s", future)
		}
	}
	if !strings.Contains(sqlText, "INSERT INTO scopes(id,kind,app_id) VALUES('system','system',NULL);") {
		t.Error("迁移缺少 system scope 种子记录")
	}
}

func TestUsersUseOpaqueIDAndNormalizedUsernameOnly(t *testing.T) {
	sqlText := readCoreMigration(t)
	users := tableDefinition(t, sqlText, "users")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"username TEXT NOT NULL",
		"username_normalized TEXT NOT NULL UNIQUE",
	} {
		if !strings.Contains(users, want) {
			t.Errorf("users 定义缺少 %q", want)
		}
	}
	// 用户名不是永久关联键：任何表都不得用 username 建外键或当作其它表关联键。
	if strings.Contains(sqlText, "FOREIGN KEY(username") ||
		strings.Contains(sqlText, "REFERENCES users(username") ||
		strings.Contains(sqlText, "REFERENCES users (username") {
		t.Error("迁移把 username 当作外键关联键")
	}
	if count := strings.Count(sqlText, "username"); count != 2 {
		t.Errorf("username 出现次数 = %d，期望仅 users 表中的原始值与规范值", count)
	}
	// 关联表应使用 user_id 指向 users(id)。
	if !strings.Contains(tableDefinition(t, sqlText, "applications"), "REFERENCES users(id)") {
		t.Error("applications.owner_user_id 应引用 users(id)")
	}
	if !strings.Contains(tableDefinition(t, sqlText, "app_memberships"), "REFERENCES users(id)") {
		t.Error("app_memberships.user_id 应引用 users(id)")
	}
}

func TestScopeIsolationConstraints(t *testing.T) {
	sqlText := readCoreMigration(t)

	scopes := tableDefinition(t, sqlText, "scopes")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"kind TEXT NOT NULL CHECK(kind IN('system','application'))",
		"app_id TEXT UNIQUE REFERENCES applications(id)",
		"kind='system' AND app_id IS NULL AND id='system'",
		"kind='application' AND app_id IS NOT NULL AND id<>'system'",
	} {
		if !strings.Contains(scopes, want) {
			t.Errorf("scopes 定义缺少 %q", want)
		}
	}

	// 角色/权限/组通过 (id, scope_id) 复合唯一键，供成员关系用复合外键限制同范围。
	for _, table := range []string{"roles", "permissions", "user_groups"} {
		definition := tableDefinition(t, sqlText, table)
		if !strings.Contains(definition, "UNIQUE(id,scope_id)") {
			t.Errorf("%s 缺少 (id, scope_id) 复合唯一键", table)
		}
	}
	rolePermissions := tableDefinition(t, sqlText, "role_permissions")
	if !strings.Contains(rolePermissions, "FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id)") {
		t.Error("role_permissions 未用复合外键限制 role 与 scope 组合")
	}
	if !strings.Contains(rolePermissions, "FOREIGN KEY(permission_id,scope_id) REFERENCES permissions(id,scope_id)") {
		t.Error("role_permissions 未用复合外键限制 permission 与 scope 组合")
	}
	userRoles := tableDefinition(t, sqlText, "user_roles")
	if !strings.Contains(userRoles, "FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id)") {
		t.Error("user_roles 未用复合外键限制 role 与 scope 组合")
	}
	groupRoles := tableDefinition(t, sqlText, "group_roles")
	if !strings.Contains(groupRoles, "FOREIGN KEY(group_id,scope_id) REFERENCES user_groups(id,scope_id)") {
		t.Error("group_roles 未用复合外键限制 group 与 scope 组合")
	}

	memberships := tableDefinition(t, sqlText, "app_memberships")
	for _, want := range []string{
		"PRIMARY KEY(app_id,user_id)",
		"app_id TEXT NOT NULL REFERENCES applications(id)",
		"user_id TEXT NOT NULL REFERENCES users(id)",
	} {
		if !strings.Contains(memberships, want) {
			t.Errorf("app_memberships 定义缺少 %q", want)
		}
	}
	if strings.Contains(sqlText, "PRIMARY KEY(user_id)") {
		t.Error("用户不应只有一个应用身份：成员关系主键必须包含 app_id")
	}
}

func TestCrossDatabaseRepresentationConventions(t *testing.T) {
	sqlText := readCoreMigration(t)
	// 时间统一 UTC 毫秒整数，列名以 _at_ms 结尾。
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "DATETIME") {
		t.Error("迁移不应使用 TIMESTAMP/DATETIME，时间统一 UTC 毫秒整数")
	}
	if !strings.Contains(sqlText, "created_at_ms INTEGER NOT NULL") ||
		!strings.Contains(sqlText, "updated_at_ms INTEGER NOT NULL") {
		t.Error("迁移缺少毫秒时间列")
	}
	// 布尔使用 0/1 整数加 CHECK，而不是 BOOLEAN。
	if strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 BOOLEAN 类型名")
	}
	if !strings.Contains(sqlText, "is_root INTEGER NOT NULL DEFAULT 0 CHECK(is_root IN (0,1))") {
		t.Error("布尔列应使用 0/1 整数加 CHECK")
	}
	// 二进制列使用 BLOB（当前核心表没有二进制列，规则写入设计文档）。
	// 行版本用于乐观并发。
	if !strings.Contains(sqlText, "row_version INTEGER NOT NULL DEFAULT 1") {
		t.Error("缺少 row_version 乐观并发列")
	}
}

// TestEmbeddedMigrationFilesExist 检查内嵌目录存在核心迁移，且后续迁移延续
// 同一命名与编码约定。
func TestEmbeddedMigrationFilesExist(t *testing.T) {
	entries, err := migrations.SQLite.ReadDir(".")
	if err != nil {
		t.Fatalf("读取迁移目录失败：%v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Name() == coreMigration {
			found = true
		}
	}
	if !found {
		t.Fatalf("内嵌迁移缺少 %s", coreMigration)
	}
	// 迁移文件必须是 UTF-8 文本且不以 BOM 开头，避免校验和与执行差异。
	for _, name := range []string{coreMigration, credentialMigration} {
		data, err := migrations.SQLite.ReadFile(name)
		if err != nil {
			t.Fatalf("读取迁移 %s 失败：%v", name, err)
		}
		if strings.HasPrefix(string(data), "\ufeff") {
			t.Errorf("迁移 %s 不应带 UTF-8 BOM", name)
		}
	}
}

const credentialMigration = "0002_one_time_credentials.sql"

// readCredentialMigration 读取 0002 一次性凭证迁移。
func readCredentialMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(credentialMigration)
	if err != nil {
		t.Fatalf("读取一次性凭证迁移失败：%v", err)
	}
	return string(data)
}

// TestOneTimeCredentialMigration 校验步骤 09 的一次性凭证表结构、约束与索引，
// 确保摘要使用 BLOB、时间使用毫秒整数、应用绑定有外键，且不提前创建其他表。
func TestOneTimeCredentialMigration(t *testing.T) {
	sqlText := readCredentialMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0002 CREATE TABLE 数量 = %d，期望只创建一次性凭证表", count)
	}
	definition := tableDefinition(t, sqlText, "one_time_credentials")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"purpose TEXT NOT NULL",
		"subject_id TEXT NOT NULL",
		"app_id TEXT REFERENCES applications(id) ON DELETE CASCADE",
		"verifier_hash BLOB NOT NULL UNIQUE",
		"key_id TEXT",
		"context_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(context_json))",
		"attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0)",
		"max_attempts INTEGER NOT NULL CHECK(max_attempts>0)",
		"created_at_ms INTEGER NOT NULL",
		"expires_at_ms INTEGER NOT NULL",
		"consumed_at_ms INTEGER",
		"revoked_at_ms INTEGER",
		"CHECK(expires_at_ms>created_at_ms)",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("one_time_credentials 定义缺少 %q", want)
		}
	}
	// 摘要必须是二进制列；保持与跨数据库表示约定一致，不用十六进制文本。
	if strings.Contains(definition, "verifier_hash TEXT") {
		t.Error("verifier_hash 应使用 BLOB 二进制列")
	}
	for _, want := range []string{
		"CREATE INDEX ix_one_time_credentials_expires_at_ms ON one_time_credentials(expires_at_ms);",
		"CREATE INDEX ix_one_time_credentials_scope ON one_time_credentials(purpose,subject_id,app_id,created_at_ms);",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0002 缺少索引 %q", want)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
