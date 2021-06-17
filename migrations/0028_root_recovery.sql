-- 0028 root 本地应急恢复操作记录与通知 outbox（步骤 48）。
--
-- 语义：
--   - 一行代表一次**已成功提交**的本地 root 应急恢复操作；记录本地操作者
--     （OS 用户/机器名等稳定标识，不含秘密）、原因、操作范围、安全版本与
--     撤销/禁用数量，供审计与排障追踪。失败或被取消的操作不写本表。
--   - notification_state 是补发安全告知的持久化 outbox 状态：成功恢复时在同一
--     事务内插入 pending 行；宿主/下次启动读取 pending 并通过自己的通知渠道
--     补发（事件不含密码、哈希、种子、恢复代码或 Passkey 公钥等秘密材料）。
--   - 本表只记录 root 应急恢复，不替代 audit_events；审计事件与恢复事务一致提交。
--   - actions_json 是恢复范围布尔快照（password/mfa/passkeys），受 json_valid 约束；
--     恢复语义以本表与审计事件为准，不保存任何新密码或认证器材料。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE root_recovery_events (
  id TEXT PRIMARY KEY NOT NULL,
  root_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  operator_id TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 128),
  operator_machine TEXT NOT NULL CHECK(length(operator_machine) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  actions_json TEXT NOT NULL CHECK(json_valid(actions_json)),
  password_reset INTEGER NOT NULL CHECK(password_reset IN(0,1)),
  mfa_reset INTEGER NOT NULL CHECK(mfa_reset IN(0,1)),
  passkeys_revoked INTEGER NOT NULL CHECK(passkeys_revoked IN(0,1)),
  sessions_revoked INTEGER NOT NULL DEFAULT 0 CHECK(sessions_revoked >= 0),
  factors_disabled INTEGER NOT NULL DEFAULT 0 CHECK(factors_disabled >= 0),
  recovery_code_groups_revoked INTEGER NOT NULL DEFAULT 0
    CHECK(recovery_code_groups_revoked >= 0),
  security_version_after INTEGER NOT NULL CHECK(security_version_after > 0),
  request_id TEXT NOT NULL DEFAULT '',
  notification_state TEXT NOT NULL DEFAULT 'pending'
    CHECK(notification_state IN('pending','delivered','failed')),
  notification_attempts INTEGER NOT NULL DEFAULT 0 CHECK(notification_attempts >= 0),
  last_error_code TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  delivered_at_ms INTEGER,
  CHECK(notification_state <> 'delivered' OR delivered_at_ms IS NOT NULL)
);

CREATE INDEX ix_root_recovery_events_pending
  ON root_recovery_events(notification_state, created_at_ms);

CREATE INDEX ix_root_recovery_events_root
  ON root_recovery_events(root_user_id, created_at_ms);
