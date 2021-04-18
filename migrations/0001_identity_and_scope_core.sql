-- 0001 身份与权限隔离核心表。
--
-- 本迁移只建立当前基础模型必需的隔离核心：全局账户、应用、scope、应用成员关系、
-- 角色、权限、用户组及其关联。认证凭证、会话、审计、任务、报告、备份等表由
-- 对应步骤通过追加新迁移落地，见 docs/database/存储模型与迁移设计.md。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE users (
id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL, username_normalized TEXT NOT NULL UNIQUE,
nickname TEXT NOT NULL DEFAULT '', biography TEXT NOT NULL DEFAULT '', avatar_ref TEXT,
language TEXT NOT NULL DEFAULT 'zh-CN', timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled','pending_delete')),
is_root INTEGER NOT NULL DEFAULT 0 CHECK(is_root IN (0,1)), security_version INTEGER NOT NULL DEFAULT 1,
row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX ux_single_root ON users(is_root) WHERE is_root=1;

CREATE TABLE applications (
id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', icon_ref TEXT, homepage TEXT,
owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL, contact_info TEXT,
status TEXT NOT NULL DEFAULT 'disabled' CHECK(status IN('active','disabled')),
client_type TEXT NOT NULL CHECK(client_type IN('confidential','public')), row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE scopes (
id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL CHECK(kind IN('system','application')),
app_id TEXT UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
CHECK((kind='system' AND app_id IS NULL AND id='system') OR (kind='application' AND app_id IS NOT NULL AND id<>'system'))
);

CREATE TABLE app_memberships (
app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL CHECK(status IN('active','disabled')),
profile_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(profile_json)), row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(app_id,user_id)
);

CREATE TABLE roles (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
role_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, limits_text TEXT NOT NULL,
is_builtin INTEGER NOT NULL DEFAULT 0 CHECK(is_builtin IN(0,1)), enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),
created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,role_key), UNIQUE(id,scope_id)
);

CREATE TABLE permissions (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
permission_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, limits_text TEXT NOT NULL,
is_builtin INTEGER NOT NULL DEFAULT 0 CHECK(is_builtin IN(0,1)), root_only INTEGER NOT NULL DEFAULT 0 CHECK(root_only IN(0,1)),
enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,permission_key), UNIQUE(id,scope_id)
);

CREATE TABLE role_permissions (
role_id TEXT NOT NULL, permission_id TEXT NOT NULL, scope_id TEXT NOT NULL,
PRIMARY KEY(role_id,permission_id), FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE,
FOREIGN KEY(permission_id,scope_id) REFERENCES permissions(id,scope_id) ON DELETE CASCADE
);

CREATE TABLE user_groups (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
group_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,group_key), UNIQUE(id,scope_id)
);

CREATE TABLE group_members (
group_id TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at_ms INTEGER NOT NULL, PRIMARY KEY(group_id,user_id)
);

CREATE TABLE user_roles (
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id TEXT NOT NULL, scope_id TEXT NOT NULL,
data_scope_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(data_scope_json)), assigned_by TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
PRIMARY KEY(user_id,role_id), FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE
);

CREATE TABLE group_roles (
group_id TEXT NOT NULL, role_id TEXT NOT NULL, scope_id TEXT NOT NULL,
data_scope_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(data_scope_json)), created_at_ms INTEGER NOT NULL,
PRIMARY KEY(group_id,role_id), FOREIGN KEY(group_id,scope_id) REFERENCES user_groups(id,scope_id) ON DELETE CASCADE,
FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE
);

INSERT INTO scopes(id,kind,app_id) VALUES('system','system',NULL);
