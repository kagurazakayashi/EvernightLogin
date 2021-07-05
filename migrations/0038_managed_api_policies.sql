-- 0038 业务托管管理 API 的应用级委托策略（步骤 60）。
--
-- 设计边界：
--   - 每个应用最多一行策略；无策略行 = 该应用的托管管理 API 关闭（默认拒绝）。
--   - 策略由 root/受信本地管理员/系统组件通过受控 Go API 写入：要求敏感操作
--     managed_api.policy.manage（默认近期强认证）、行版本条件更新与同事务审计。
--   - policy_json 是版本化严格 JSON（v1）：允许操作、服务身份允许操作、对象范围
--     （仅应用作用域，不允许 system）、可读/可写字段白名单、分页/批量上限。未知
--     操作/字段/对象、硬禁敏感字段、非法上限一律在写入前拒绝，不落库。
--   - 本表不保存秘密；updated_by 是受信操作者稳定标识（脱敏），变更差异写审计。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE app_managed_api_policies (
  application_id TEXT PRIMARY KEY NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1),
  updated_by TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(updated_at_ms >= created_at_ms)
);

CREATE INDEX ix_app_managed_api_policies_updated
  ON app_managed_api_policies(updated_at_ms);
