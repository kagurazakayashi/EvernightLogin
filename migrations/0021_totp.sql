-- 0021 TOTP 绑定（种子加密）与登录第二步时间步防重放。
--
-- 对应步骤 41 的“TOTP 绑定、首次确认、登录验证与安全解除”：
--   - 重建 mfa_challenges 的 factor_type CHECK，允许 'totp' 作为第二步因素；列集合
--     与 0020 完全一致（SQLite 无法直接修改 CHECK，只能重建表并复制数据）。
--   - totp_bindings 保存 TOTP 绑定：pending（绑定中，等待验证码确认）与 active
--     （已激活）明确分开。同一用户允许多个 pending（重绑时先验证新因素），但同一
--     用户最多一个 active（部分唯一索引），保证重绑是“先验证新、再替换旧”。
--   - sealed_secret 是 internal/secrets.Sealer 的认证加密信封（绑定用途 mfa.totp /
--     对象为绑定 ID / 范围 system），数据库不保存明文种子；普通查询与导出不得返回
--     或解密该列，明文种子只出现在绑定开始响应的 otpauth URI/种子中。
--   - algorithm/digits/period_seconds/window_steps 记录生成与校验参数并受 CHECK
--     界限约束；last_accepted_step 记录已接受时间步，登录验证通过条件更新原子推进
--     （只接受严格更大的时间步），防止同一步并发/重放。
--   - 解除绑定同样在本表内条件迁移为 disabled，并配合宿主 Policy/其他因素检查。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE mfa_challenges_v2 (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK(factor_type IN('email','totp')),
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

INSERT INTO mfa_challenges_v2(
  id,user_id,factor_type,purpose,attempt_sha256,credential_id,generation,state,username,
  app_id,remember_me,client_user_agent,client_address,restricted_session_id,attempts,
  max_attempts,security_version,completed_at_ms,expires_at_ms,created_at_ms,updated_at_ms,
  verified_at_ms)
SELECT id,user_id,factor_type,purpose,attempt_sha256,credential_id,generation,state,username,
  app_id,remember_me,client_user_agent,client_address,restricted_session_id,attempts,
  max_attempts,security_version,completed_at_ms,expires_at_ms,created_at_ms,updated_at_ms,
  verified_at_ms
FROM mfa_challenges;

DROP TABLE mfa_challenges;

ALTER TABLE mfa_challenges_v2 RENAME TO mfa_challenges;

CREATE INDEX ix_mfa_challenges_user_state ON mfa_challenges(user_id, state, expires_at_ms);

CREATE TABLE totp_bindings (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN('pending','active','disabled')),
  sealed_secret BLOB NOT NULL CHECK(length(sealed_secret) > 0),
  algorithm TEXT NOT NULL DEFAULT 'SHA1' CHECK(algorithm IN('SHA1')),
  digits INTEGER NOT NULL DEFAULT 6 CHECK(digits BETWEEN 6 AND 8),
  period_seconds INTEGER NOT NULL DEFAULT 30 CHECK(period_seconds BETWEEN 15 AND 60),
  window_steps INTEGER NOT NULL DEFAULT 1 CHECK(window_steps BETWEEN 0 AND 3),
  last_accepted_step INTEGER NOT NULL DEFAULT -1,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10),
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  activated_at_ms INTEGER
);

CREATE INDEX ix_totp_bindings_user_status ON totp_bindings(user_id, status);

CREATE UNIQUE INDEX ux_totp_bindings_user_active
  ON totp_bindings(user_id) WHERE status='active';
