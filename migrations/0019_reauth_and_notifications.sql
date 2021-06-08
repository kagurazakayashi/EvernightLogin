-- 0019 敏感操作再次认证挑战、一次性批准与安全告知记录。
--
-- 对应步骤 39 的“再次认证、认证强度判断与敏感操作邮件告知”：
--   - reauth_challenges 保存操作绑定挑战：用户、作用域、稳定操作 ID、目标、
--     服务端计算的操作参数摘要、要求强度、尝试次数上限与有效期。挑战本身不是
--     批准；只有通过真实的近期密码验证后才产生一次性批准。
--   - reauth_approvals 保存短时、一次性的操作批准：令牌只存 SHA-256 摘要（明文
--     令牌只返回一次），并绑定挑战、用户、作用域、操作、目标与参数摘要。
--     consumed_at_ms 非空表示已使用；消费是条件更新，重放/换对象/换参数均失败。
--     批准不保存密码、密码哈希或任何认证秘密。
--   - security_notifications 记录敏感操作后的安全告知结果：成功/失败、收件地址
--     是否可用（地址只存脱敏值）、通知状态与稳定原因码；通知失败不回滚已完成的
--     安全操作，也不把“已通知”当作认证或批准。
--   - 所有时间使用 UTC 毫秒整数；不存明文令牌、密码、验证码或邮件正文。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE reauth_challenges (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128),
  target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
  target_id TEXT NOT NULL DEFAULT '' CHECK(length(target_id) <= 128),
  params_sha256 BLOB NOT NULL CHECK(length(params_sha256) = 32),
  required_strength TEXT NOT NULL CHECK(required_strength IN('none','password','strong')),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN('pending','verified','cancelled','expired')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10),
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  verified_at_ms INTEGER
);

CREATE INDEX ix_reauth_challenges_user_status ON reauth_challenges(user_id, status, expires_at_ms);

CREATE TABLE reauth_approvals (
  id TEXT PRIMARY KEY NOT NULL,
  challenge_id TEXT NOT NULL REFERENCES reauth_challenges(id) ON DELETE CASCADE,
  token_sha256 BLOB NOT NULL UNIQUE CHECK(length(token_sha256) = 32),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128),
  target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
  target_id TEXT NOT NULL DEFAULT '' CHECK(length(target_id) <= 128),
  params_sha256 BLOB NOT NULL CHECK(length(params_sha256) = 32),
  granted_strength TEXT NOT NULL CHECK(granted_strength IN('none','password','strong')),
  authentication_complete INTEGER NOT NULL DEFAULT 0 CHECK(authentication_complete IN(0,1)),
  granted_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_reauth_approvals_user_operation ON reauth_approvals(user_id, operation_id);

CREATE TABLE security_notifications (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128),
  target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
  target_id TEXT NOT NULL DEFAULT '' CHECK(length(target_id) <= 128),
  outcome TEXT NOT NULL CHECK(outcome IN('success','failure')),
  state TEXT NOT NULL CHECK(state IN('sent','failed','no_verified_email','rate_limited','not_configured','suppressed')),
  error_code TEXT,
  reason_code TEXT,
  recipient_masked TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_security_notifications_user_created ON security_notifications(user_id, created_at_ms);
