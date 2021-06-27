-- 0034 OAuth 授权撤回与令牌撤销（步骤 55）。
--
-- 设计边界：
--   - oauth_authorization_codes 增加 revoked_at_ms：用户撤回授权或退出应用时，未兑换的
--     授权码必须立即失效（已兑换码的状态由刷新令牌族/访问令牌撤销记录约束）。
--   - oauth_client_user_revocations：用户在某应用上的授权撤回/退出标记。在线校验的
--     访问令牌属于该（用户,客户端）且签发时间早于撤回时间时按无效处理；这是保守的
--     在线状态边界，不把无状态 JWT 的离线副本当成即时失效。
--   - oauth_user_revocations：用户级安全事件（改密、恢复完成等）触发的在线撤销标记；
--     与安全版本/令牌族撤销配合，不替代它们。
--   - oauth_access_token_revocations：标准撤销端点按 jti 撤销某一访问令牌，供在线
--     校验查询；撤销记录保留到令牌自然到期附近（写入 expires_at_ms 以便清理）。
--   - 不保存访问令牌/刷新令牌/授权码明文、客户端 secret 或会话秘密。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE oauth_authorization_codes ADD COLUMN revoked_at_ms INTEGER;

CREATE INDEX ix_oauth_authorization_codes_revocation
  ON oauth_authorization_codes(revoked_at_ms, expires_at_ms);

CREATE TABLE oauth_client_user_revocations (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  revoked_at_ms INTEGER NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
  request_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id, client_id)
);

CREATE INDEX ix_oauth_client_user_revocations_time
  ON oauth_client_user_revocations(revoked_at_ms);

CREATE TABLE oauth_user_revocations (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revoked_at_ms INTEGER NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
  request_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE oauth_access_token_revocations (
  jti TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT '',
  subject_type TEXT NOT NULL CHECK(subject_type IN('user','service')),
  revoked_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
  request_id TEXT NOT NULL DEFAULT '',
  CHECK(expires_at_ms > revoked_at_ms)
);

CREATE INDEX ix_oauth_access_token_revocations_expiry
  ON oauth_access_token_revocations(expires_at_ms);
