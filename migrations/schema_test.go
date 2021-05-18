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
	for _, name := range []string{coreMigration, credentialMigration, auditMigration, taskMigration, scheduleMigration, delegationMigration, presetMigration, rootInitializationMigration} {
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

const auditMigration = "0003_audit_events.sql"

// readAuditMigration 读取 0003 安全审计迁移。
func readAuditMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(auditMigration)
	if err != nil {
		t.Fatalf("读取安全审计迁移失败：%v", err)
	}
	return string(data)
}

// TestAuditEventsMigration 校验步骤 10 的安全审计表结构、身份/结果枚举约束、
// 应用快照无外键、脱敏差异 JSON、幂等键唯一索引与查询索引。
func TestAuditEventsMigration(t *testing.T) {
	sqlText := readAuditMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0003 CREATE TABLE 数量 = %d，期望只创建审计事件表", count)
	}
	definition := tableDefinition(t, sqlText, "audit_events")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"occurred_at_ms INTEGER NOT NULL",
		"actor_type TEXT NOT NULL CHECK(actor_type IN('user','system','local_admin','anonymous'))",
		"actor_id TEXT",
		"app_id_snapshot TEXT",
		"action TEXT NOT NULL",
		"target_type TEXT NOT NULL",
		"target_id TEXT",
		"outcome TEXT NOT NULL CHECK(outcome IN('success','failure','denied'))",
		"error_code TEXT",
		"reason_code TEXT",
		"request_id TEXT",
		"task_id TEXT",
		"detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json))",
		"dedupe_key TEXT",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("audit_events 定义缺少 %q", want)
		}
	}
	// 审计快照不能外键级联删除，避免应用删除后丢失安全事件。
	if strings.Contains(definition, "app_id_snapshot TEXT REFERENCES") {
		t.Error("app_id_snapshot 不应建立外键")
	}
	for _, want := range []string{
		"CREATE INDEX ix_audit_events_occurred_at_ms ON audit_events(occurred_at_ms);",
		"CREATE INDEX ix_audit_events_request_id ON audit_events(request_id);",
		"CREATE INDEX ix_audit_events_task_id ON audit_events(task_id);",
		"CREATE INDEX ix_audit_events_action_occurred_at_ms ON audit_events(action,occurred_at_ms);",
		"CREATE UNIQUE INDEX ux_audit_events_dedupe_key ON audit_events(dedupe_key) WHERE dedupe_key IS NOT NULL;",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0003 缺少索引 %q", want)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}

const taskMigration = "0004_jobs.sql"

// readTaskMigration 读取 0004 后台任务迁移。
func readTaskMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(taskMigration)
	if err != nil {
		t.Fatalf("读取后台任务迁移失败：%v", err)
	}
	return string(data)
}

// TestJobsMigration 校验步骤 11 的后台任务表：状态枚举、可信发起/执行/取消身份、
// 墙钟上限、互斥键、载荷 JSON 与索引；不提前创建后续重试/调度表。
func TestJobsMigration(t *testing.T) {
	sqlText := readTaskMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0004 CREATE TABLE 数量 = %d，期望只创建 jobs 表", count)
	}
	definition := tableDefinition(t, sqlText, "jobs")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"kind TEXT NOT NULL",
		"state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','failed','cancel_requested','cancelled','timed_out'))",
		"initiated_by_type TEXT NOT NULL CHECK(initiated_by_type IN('user','system','local_admin'))",
		"initiated_by_id TEXT NOT NULL",
		"executed_by TEXT",
		"cancelled_by_type TEXT CHECK(cancelled_by_type IS NULL OR cancelled_by_type IN('user','system','local_admin'))",
		"cancelled_by_id TEXT",
		"cancellation_reason TEXT",
		"cancel_requested_at_ms INTEGER",
		"started_at_ms INTEGER",
		"finished_at_ms INTEGER",
		"timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds>0)",
		"attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0)",
		"max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts>0)",
		"mutex_key TEXT",
		"payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json))",
		"request_id TEXT",
		"error_code TEXT",
		"failure_reason TEXT",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("jobs 定义缺少 %q", want)
		}
	}
	for _, want := range []string{
		"CREATE INDEX ix_jobs_state_created_at_ms ON jobs(state,created_at_ms);",
		"CREATE INDEX ix_jobs_mutex_active ON jobs(mutex_key,state) WHERE mutex_key IS NOT NULL AND state IN('running','cancel_requested');",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0004 缺少索引 %q", want)
		}
	}
	// 后续步骤的表不得提前创建。
	for _, future := range []string{"job_attempts", "schedules", "schedule_firings", "outbox_events"} {
		if strings.Contains(sqlText, "CREATE TABLE "+future+" (") {
			t.Errorf("0004 提前创建了后续步骤的表 %s", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}

const scheduleMigration = "0005_schedules_attempts.sql"

// readScheduleMigration 读取 0005 定时计划与尝试历史迁移。
func readScheduleMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(scheduleMigration)
	if err != nil {
		t.Fatalf("读取定时计划迁移失败：%v", err)
	}
	return string(data)
}

// TestScheduleMigration 校验步骤 12 的计划、触发去重与尝试历史结构：可信身份、
// 启用/权限/错过策略枚举、唯一触发键、作业重试列与索引，且只追加结构。
func TestScheduleMigration(t *testing.T) {
	sqlText := readScheduleMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0005 CREATE TABLE 数量 = %d，期望计划、触发与尝试历史三张表", count)
	}
	attemptDefinition := tableDefinition(t, sqlText, "job_attempts")
	for _, want := range []string{
		"job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE",
		"attempt INTEGER NOT NULL CHECK(attempt>=1)",
		"started_at_ms INTEGER NOT NULL",
		"finished_at_ms INTEGER",
		"outcome TEXT",
		"error_code TEXT",
		"executor_id TEXT",
		"PRIMARY KEY(job_id,attempt)",
	} {
		if !strings.Contains(attemptDefinition, want) {
			t.Errorf("job_attempts 定义缺少 %q", want)
		}
	}
	scheduleDefinition := tableDefinition(t, sqlText, "schedules")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"kind TEXT NOT NULL",
		"schedule_type TEXT NOT NULL CHECK(schedule_type IN('daily','weekly','monthly','custom'))",
		"expression TEXT NOT NULL",
		"timezone TEXT NOT NULL",
		"owner_type TEXT NOT NULL CHECK(owner_type IN('user','system','local_admin'))",
		"owner_id TEXT NOT NULL",
		"execution_type TEXT NOT NULL CHECK(execution_type IN('user','system','local_admin'))",
		"execution_id TEXT NOT NULL",
		"scope_id TEXT NOT NULL REFERENCES scopes(id)",
		"enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1))",
		"permission_required INTEGER NOT NULL DEFAULT 1 CHECK(permission_required IN(0,1))",
		"missed_policy TEXT NOT NULL DEFAULT 'skip' CHECK(missed_policy IN('skip','latest','all'))",
		"max_catch_up INTEGER NOT NULL DEFAULT 24 CHECK(max_catch_up>0 AND max_catch_up<=1000)",
		"config_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(config_json))",
		"last_scheduled_at_ms INTEGER",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(scheduleDefinition, want) {
			t.Errorf("schedules 定义缺少 %q", want)
		}
	}
	firingDefinition := tableDefinition(t, sqlText, "schedule_firings")
	for _, want := range []string{
		"schedule_id TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE",
		"scheduled_at_ms INTEGER NOT NULL",
		"job_id TEXT REFERENCES jobs(id)",
		"outcome TEXT NOT NULL CHECK(outcome IN('enqueued','skipped','denied'))",
		"error_code TEXT",
		"reason_code TEXT",
		"created_at_ms INTEGER NOT NULL",
		"PRIMARY KEY(schedule_id,scheduled_at_ms)",
	} {
		if !strings.Contains(firingDefinition, want) {
			t.Errorf("schedule_firings 定义缺少 %q", want)
		}
	}
	for _, want := range []string{
		"ALTER TABLE jobs ADD COLUMN next_attempt_at_ms INTEGER;",
		"ALTER TABLE jobs ADD COLUMN permission_required INTEGER NOT NULL DEFAULT 0 CHECK(permission_required IN(0,1));",
		"CREATE INDEX ix_jobs_retry_due ON jobs(next_attempt_at_ms) WHERE state='queued' AND next_attempt_at_ms IS NOT NULL;",
		"CREATE INDEX ix_job_attempts_open ON job_attempts(job_id) WHERE finished_at_ms IS NULL;",
		"CREATE INDEX ix_schedules_enabled ON schedules(enabled,created_at_ms);",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0005 缺少结构 %q", want)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}

const delegationMigration = "0006_permission_delegations.sql"

// readDelegationMigration 读取 0006 可转授权限委派迁移。
func readDelegationMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(delegationMigration)
	if err != nil {
		t.Fatalf("读取委派资格迁移失败: %v", err)
	}
	return string(data)
}

// TestDelegationMigration 校验步骤 26 的委派资格结构：同一委派者在同一范围对同一
// 权限只有一条资格，数据范围上限与目标白名单使用带版本 JSON 的默认值，自我/本组
// 转授默认禁止，资格可过期/可撤回，签发者必须记录可信身份，权限外键使用复合键
// 保证权限与范围一致；只追加本表与索引。
func TestDelegationMigration(t *testing.T) {
	sqlText := readDelegationMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0006 CREATE TABLE 数量 = %d，期望只创建权限委派资格表", count)
	}
	definition := tableDefinition(t, sqlText, "permission_delegations")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"delegator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE",
		"permission_id TEXT NOT NULL",
		`max_data_scope_json TEXT NOT NULL DEFAULT '{"v":1,"mode":"all"}'`,
		`allowed_targets_json TEXT NOT NULL DEFAULT '{"v":1}'`,
		"allow_self INTEGER NOT NULL DEFAULT 0 CHECK(allow_self IN(0,1))",
		"expires_at_ms INTEGER",
		"revoked_at_ms INTEGER",
		"created_by_type TEXT NOT NULL",
		"created_by_id TEXT NOT NULL",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
		"UNIQUE(delegator_user_id,scope_id,permission_id)",
		"FOREIGN KEY(permission_id,scope_id) REFERENCES permissions(id,scope_id) ON DELETE CASCADE",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("permission_delegations 定义缺少 %q", want)
		}
	}
	for _, want := range []string{
		"CREATE INDEX idx_permission_delegations_delegator ON permission_delegations(delegator_user_id,scope_id);",
		"CREATE INDEX idx_permission_delegations_permission ON permission_delegations(permission_id);",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0006 缺少结构 %q", want)
		}
	}
	// 委派资格只登记“可转授”，不得出现 enabled/granted 之类的默认放行标记，
	// 也不得把 allow_self 默认成 1（默认必须封堵自我提权）。
	if strings.Contains(definition, "enabled") || strings.Contains(definition, "allowed_default") {
		t.Error("委派资格表不应包含默认放行标记")
	}
	if strings.Contains(definition, "allow_self INTEGER NOT NULL DEFAULT 1") {
		t.Error("allow_self 默认必须为 0")
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}

const presetMigration = "0007_preset_installations.sql"

// readPresetMigration 读取 0007 预设目录初始化版本迁移。
func readPresetMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(presetMigration)
	if err != nil {
		t.Fatalf("读取预设初始化迁移失败: %v", err)
	}
	return string(data)
}

// TestPresetMigration 校验步骤 27 的初始化版本记录结构：同一作用范围只有一条记录、
// 作用范围外键级联、版本与时间字段必填；只追加本表与索引，不改变任何授权数据。
func TestPresetMigration(t *testing.T) {
	sqlText := readPresetMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0007 CREATE TABLE 数量 = %d，期望只创建初始化版本记录表", count)
	}
	definition := tableDefinition(t, sqlText, "preset_installations")
	for _, want := range []string{
		"scope_id TEXT PRIMARY KEY NOT NULL REFERENCES scopes(id) ON DELETE CASCADE",
		"catalog_version TEXT NOT NULL",
		"applied_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("preset_installations 定义缺少 %q", want)
		}
	}
	if !strings.Contains(sqlText, "CREATE INDEX idx_preset_installations_version ON preset_installations(catalog_version);") {
		t.Error("0007 缺少版本索引")
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}

const rootInitializationMigration = "0008_root_initialization.sql"

// readRootInitializationMigration 读取 0008 首次初始化与 root 受限状态迁移。
func readRootInitializationMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(rootInitializationMigration)
	if err != nil {
		t.Fatalf("读取首次初始化迁移失败: %v", err)
	}
	return string(data)
}

// TestRootInitializationMigration 校验步骤 28 的初始化记录结构：单例约束、
// root 外键禁止删除、受限状态机与验证/完成时间联动，且只追加本表与索引。
func TestRootInitializationMigration(t *testing.T) {
	sqlText := readRootInitializationMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0008 CREATE TABLE 数量 = %d，期望只创建初始化状态记录表", count)
	}
	definition := tableDefinition(t, sqlText, "root_initializations")
	for _, want := range []string{
		"singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1)",
		"root_user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT",
		"state TEXT NOT NULL CHECK(state IN('pending_setup','setup_verified','ready'))",
		"setup_credential_id TEXT REFERENCES one_time_credentials(id) ON DELETE SET NULL",
		"started_by TEXT NOT NULL",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
		"verified_at_ms INTEGER",
		"ready_at_ms INTEGER",
		"state='pending_setup' AND verified_at_ms IS NULL AND ready_at_ms IS NULL",
		"state='setup_verified' AND verified_at_ms IS NOT NULL AND ready_at_ms IS NULL",
		"state='ready' AND verified_at_ms IS NOT NULL AND ready_at_ms IS NOT NULL",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("root_initializations 定义缺少 %q", want)
		}
	}
	if !strings.Contains(sqlText, "CREATE INDEX idx_root_initializations_state ON root_initializations(state);") {
		t.Error("0008 缺少状态索引")
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
	// 0008 不得创建密码、会话或令牌表：本步没有默认密码，也不提前签发会话。
	for _, future := range []string{
		"CREATE TABLE password_credentials", "CREATE TABLE sessions", "CREATE TABLE tokens",
	} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0008 提前创建了后续步骤的表 %q", future)
		}
	}
}
