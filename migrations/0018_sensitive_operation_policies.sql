-- 0018 敏感操作策略目录：作用域版本与策略覆盖/应用声明。
--
-- 对应步骤 38 的“可管理敏感操作目录、root 策略配置与恢复默认”：
--   - 系统内置敏感操作目录保留在代码（internal/policy）中，是稳定只读基线；
--     本表只保存“偏离默认值”的覆盖行与应用声明的操作，恢复默认即删除覆盖行，
--     因此默认值升级不需要重写每一行，也不会把用户配置误当成默认值。
--   - sensitive_policy_scopes 保存每个作用域（system 或应用 ID）的策略版本。
--     版本只在策略真实变更时递增，用于“读取-修改”乐观并发（过期版本返回
--     CONFLICT，不覆盖其他操作者的修改），并作为差异/恢复的防 TOCTOU 依据。
--   - sensitive_operation_policies 以 (scope_id, operation_id) 唯一定位：
--       source_kind='override'    对系统内置操作的覆盖；
--       source_kind='application' 由 root 审核并配置的应用自身敏感操作声明，
--                                 name/description 是该声明的直白说明。
--     是否敏感、认证新鲜度（秒）、所需认证强度、确认与告知要求可覆盖；
--     基础权限、root 专属限制与审计不可覆盖（由代码目录固定，不存本表）。
--   - 作用域通过 scopes(id) 外键限定为 system 或已登记应用，应用删除级联清理其
--     策略，不会遗留跨应用可见的策略行。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE sensitive_policy_scopes (
  scope_id TEXT PRIMARY KEY NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE sensitive_operation_policies (
  scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128),
  is_sensitive INTEGER NOT NULL CHECK(is_sensitive IN(0,1)),
  reauth_required INTEGER NOT NULL CHECK(reauth_required IN(0,1)),
  max_auth_age_seconds INTEGER NOT NULL CHECK(max_auth_age_seconds BETWEEN 0 AND 2592000),
  required_strength TEXT NOT NULL CHECK(required_strength IN('none','password','strong')),
  confirmation_required INTEGER NOT NULL CHECK(confirmation_required IN(0,1)),
  notification_required INTEGER NOT NULL CHECK(notification_required IN(0,1)),
  source_kind TEXT NOT NULL CHECK(source_kind IN('override','application')),
  name TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(scope_id, operation_id)
);

CREATE INDEX ix_sensitive_operation_policies_scope_source
  ON sensitive_operation_policies(scope_id, source_kind);
