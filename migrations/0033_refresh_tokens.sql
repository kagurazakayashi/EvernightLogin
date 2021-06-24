-- +migrate whole-file
-- 0033 刷新令牌与令牌族（步骤 54）。
--
-- 设计边界：
--   - 刷新令牌是高熵不透明秘密（非 JWT），数据库只保存 SHA-256 验证摘要，
--     明文只在签发/轮换响应中返回一次，不进入日志、审计或普通列表。
--   - 每个刷新令牌属于一个令牌族（family）：族绑定客户端、用户主体、授权请求、
--     Scope、资源 audience 与用户安全版本快照。轮换时旧令牌条件消费为 used 并插入
--     新令牌；旧令牌再次使用视为重放，整族撤销（含全部后代令牌）。
--   - 绝对有效期固定在族上（family.absolute_expires_at_ms），新令牌的空闲有效期
--     不超过绝对到期；族/令牌撤销使用条件更新保证并发单赢家。
--   - 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。
CREATE TABLE refresh_token_families (
  id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  subject_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  authorization_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  audiences_json TEXT NOT NULL,
  security_version INTEGER NOT NULL CHECK(security_version>0),
  created_at_ms INTEGER NOT NULL,
  absolute_expires_at_ms INTEGER NOT NULL,
  idle_timeout_ms INTEGER NOT NULL CHECK(idle_timeout_ms>0),
  revoked_at_ms INTEGER,
  revoke_reason TEXT,
  CHECK(absolute_expires_at_ms>created_at_ms)
);

CREATE INDEX ix_refresh_token_families_subject
  ON refresh_token_families(subject_user_id, client_id);
CREATE INDEX ix_refresh_token_families_client
  ON refresh_token_families(client_id, created_at_ms);

CREATE TABLE refresh_tokens (
  id TEXT PRIMARY KEY NOT NULL,
  family_id TEXT NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
  token_sha256 BLOB NOT NULL UNIQUE CHECK(length(token_sha256)=32),
  status TEXT NOT NULL CHECK(status IN('active','used','revoked','expired')),
  issued_at_ms INTEGER NOT NULL,
  idle_expires_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  used_at_ms INTEGER,
  revoked_at_ms INTEGER,
  revoke_reason TEXT,
  replaced_by_id TEXT,
  request_id TEXT,
  CHECK(idle_expires_at_ms<=expires_at_ms),
  CHECK(status='active' OR status='used' OR status='revoked' OR status='expired')
);

CREATE INDEX ix_refresh_tokens_family
  ON refresh_tokens(family_id, status);
CREATE INDEX ix_refresh_tokens_status
  ON refresh_tokens(status, idle_expires_at_ms);
