-- 0020 两步验证（邮件第二步）因素与挑战。
--
-- 对应步骤 40 的“MFA 状态机与邮件第二步验证”：
--   - mfa_factors 保存已启用的因素（当前只有 email）。因素新增必须先证明渠道控制权
--     （向已验证邮箱发送验证码并成功验证），一个用户同一类型最多一个活动因素。
--   - mfa_challenges 保存统一挑战：绑定用户、当前登录尝试（attempt_sha256 是客户端
--     持有的一次性尝试令牌摘要，不存明文）、用途（login/factor_enroll）、所选因素、
--     验证码凭证 ID、重发代数 generation、状态机与有效期。状态 pending 只能条件迁移
--     为 verified/failed/expired/cancelled，并发消费只有一方成功。
--   - 验证码本身不存本表：复用 internal/credential 的受密钥保护低熵验证码（只存
--     HMAC 摘要、尝试上限、原子消费、重发替换），本表只保存凭证 ID。
--   - 用户名/安全版本/认证完成时间来自可信认证结果快照，用于在第二因素通过后构造
--     完整认证结果；不保存密码、会话语义或明文验证码。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE mfa_factors (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK(factor_type IN('email')),
  status TEXT NOT NULL CHECK(status IN('active','disabled')),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  UNIQUE(user_id, factor_type)
);

CREATE INDEX ix_mfa_factors_user ON mfa_factors(user_id);

CREATE TABLE mfa_challenges (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK(factor_type IN('email')),
  purpose TEXT NOT NULL CHECK(purpose IN('login','factor_enroll')),
  attempt_sha256 BLOB NOT NULL CHECK(length(attempt_sha256) = 32),
  credential_id TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
  state TEXT NOT NULL CHECK(state IN('pending','verified','failed','expired','cancelled')),
  username TEXT NOT NULL DEFAULT '',
  app_id TEXT NOT NULL DEFAULT '',
  remember_me INTEGER NOT NULL DEFAULT 0 CHECK(remember_me IN(0,1)),
  client_user_agent TEXT NOT NULL DEFAULT '',
  client_address TEXT NOT NULL DEFAULT '',
  restricted_session_id TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10),
  security_version INTEGER NOT NULL DEFAULT 0,
  completed_at_ms INTEGER NOT NULL DEFAULT 0,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  verified_at_ms INTEGER
);

CREATE INDEX ix_mfa_challenges_user_state ON mfa_challenges(user_id, state, expires_at_ms);
