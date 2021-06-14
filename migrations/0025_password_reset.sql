-- 0025 密码找回请求与 OAuth 撤销可靠事件（outbox）。
--
-- 对应步骤 45 的邮件找回与关联凭证失效：
--   - password_reset_requests 记录一次性找回请求：绑定用户、受保护邮箱提示、
--     credential 服务的高熵凭证 ID、状态机与有效期。明文找回链接/凭证只在邮件
--     中出现，本表不保存 token 明文；凭证由 internal/credential 以摘要保存并原子
--     消费，并发两个重置只有一个成功。
--   - oauth_revocation_events 是密码变更/找回后为尚未完成的 OAuth Token 撤销预留
--     的可靠事件（outbox）：本步只写入事件，不宣称已撤销外部应用/Token；后续
--     OAuth 步骤接入消费者后按 processed_at_ms 标记处理。事件不含秘密。
--   - 不保存密码、密码哈希、会话秘密或 token 明文；密码变更/历史/安全版本由
--     internal/authn 在其事务内维护，本迁移只补找回请求与撤销事件。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE password_reset_requests (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  masked_email TEXT NOT NULL DEFAULT '',
  credential_id TEXT NOT NULL,
  token_sha256 BLOB NOT NULL CHECK(length(token_sha256) = 32),
  state TEXT NOT NULL CHECK(state IN('pending','consumed','expired','cancelled')),
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  CHECK(expires_at_ms > created_at_ms)
);

CREATE INDEX ix_password_reset_requests_user_state
  ON password_reset_requests(user_id, state, expires_at_ms);

CREATE INDEX ix_password_reset_requests_credential
  ON password_reset_requests(credential_id);

CREATE TABLE oauth_revocation_events (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  processed_at_ms INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0)
);

CREATE INDEX ix_oauth_revocation_events_pending
  ON oauth_revocation_events(processed_at_ms, created_at_ms);
