-- 0023_fido2_second_factor.sql：FIDO2 第二步验证与认证方式选择策略（步骤 43）。
--
-- 三处结构变化（SQLite 无法直接修改 CHECK，需重建表并复制数据；0001～0022 不改）：
--   - webauthn_credentials.usage 扩展为 'login' / 'second_factor' / 'both'：凭证用
--     途由服务端注册 ceremony（webauthn_ceremonies.purpose）决定并强校验，客户端不能
--     在完成注册时改写；已有凭证默认保持 'login'（升级兼容：升级前的凭证都是主登录
--     用途，不会被自动当作第二因素）。
--   - webauthn_ceremonies 增加 purpose（注册时的目标用途）与 context_id（第二步认证
--     绑定的 MFA 挑战 ID，防止把其他登录尝试的挑战挪用到本挑战）；operation 扩展为
--     'registration' / 'authentication' / 'second_factor'，第二步认证与主登录认证
--     使用不同操作类型，不能互相替代。
--   - mfa_challenges.factor_type 扩展 'passkey'（WebAuthn/FIDO2 安全密钥第二步）与
--     purpose 扩展 'strong_setup'（高权限账户强认证未就绪时的受限初始化）；新增
--     factor_ref 保存第二步 WebAuthn ceremony ID（不使用 credential_id 承担两种
--     语义）。原有 email/totp 行全部保留。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE mfa_challenges_v3 (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK(factor_type IN('email','totp','passkey')),
  purpose TEXT NOT NULL CHECK(purpose IN('login','factor_enroll','strong_setup')),
  attempt_sha256 BLOB NOT NULL CHECK(length(attempt_sha256) = 32),
  credential_id TEXT NOT NULL,
  factor_ref TEXT NOT NULL DEFAULT '',
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
  require_strong INTEGER NOT NULL DEFAULT 0 CHECK(require_strong IN(0,1)),
  security_version INTEGER NOT NULL DEFAULT 0,
  completed_at_ms INTEGER NOT NULL DEFAULT 0,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  verified_at_ms INTEGER
);

INSERT INTO mfa_challenges_v3(
  id,user_id,factor_type,purpose,attempt_sha256,credential_id,factor_ref,generation,state,
  username,app_id,remember_me,client_user_agent,client_address,restricted_session_id,
  attempts,max_attempts,require_strong,security_version,completed_at_ms,expires_at_ms,
  created_at_ms,updated_at_ms,verified_at_ms)
SELECT id,user_id,factor_type,purpose,attempt_sha256,credential_id,'',generation,state,
  username,app_id,remember_me,client_user_agent,client_address,restricted_session_id,
  attempts,max_attempts,0,security_version,completed_at_ms,expires_at_ms,created_at_ms,
  updated_at_ms,verified_at_ms
FROM mfa_challenges;

DROP TABLE mfa_challenges;

ALTER TABLE mfa_challenges_v3 RENAME TO mfa_challenges;

CREATE INDEX ix_mfa_challenges_user_state ON mfa_challenges(user_id, state, expires_at_ms);

CREATE TABLE webauthn_credentials_v2 (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE CHECK(length(credential_id) BETWEEN 16 AND 1023),
    public_key BLOB NOT NULL CHECK(length(public_key) > 0),
    aaguid BLOB NOT NULL,
    rp_id TEXT NOT NULL CHECK(length(rp_id) > 0),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK(sign_count >= 0),
    transports TEXT NOT NULL DEFAULT '[]',
    backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN(0,1)),
    backed_up INTEGER NOT NULL DEFAULT 0 CHECK(backed_up IN(0,1)),
    user_present INTEGER NOT NULL DEFAULT 1 CHECK(user_present IN(0,1)),
    user_verified INTEGER NOT NULL DEFAULT 0 CHECK(user_verified IN(0,1)),
    attachment TEXT NOT NULL DEFAULT '',
    usage TEXT NOT NULL DEFAULT 'login' CHECK(usage IN('login','second_factor','both')),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    last_used_at_ms INTEGER,
    revoked_at_ms INTEGER,
    revoked_reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK(backup_eligible = 1 OR backed_up = 0)
);

INSERT INTO webauthn_credentials_v2(
  id,user_id,credential_id,public_key,aaguid,rp_id,name,sign_count,transports,
  backup_eligible,backed_up,user_present,user_verified,attachment,usage,version,
  last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,updated_at_ms)
SELECT id,user_id,credential_id,public_key,aaguid,rp_id,name,sign_count,transports,
  backup_eligible,backed_up,user_present,user_verified,attachment,usage,version,
  last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,updated_at_ms
FROM webauthn_credentials;

DROP TABLE webauthn_credentials;

ALTER TABLE webauthn_credentials_v2 RENAME TO webauthn_credentials;

CREATE INDEX ix_webauthn_credentials_user_active
    ON webauthn_credentials(user_id, revoked_at_ms);

CREATE TABLE webauthn_ceremonies_v2 (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN('registration','authentication','second_factor')),
    purpose TEXT NOT NULL DEFAULT 'login' CHECK(purpose IN('login','second_factor','both')),
    context_id TEXT NOT NULL DEFAULT '',
    challenge TEXT NOT NULL CHECK(length(challenge) BETWEEN 16 AND 128),
    rp_id TEXT NOT NULL CHECK(length(rp_id) > 0),
    session_data BLOB NOT NULL CHECK(length(session_data) > 0),
    app_id TEXT NOT NULL DEFAULT '',
    remember_me INTEGER NOT NULL DEFAULT 0 CHECK(remember_me IN(0,1)),
    client_user_agent TEXT NOT NULL DEFAULT '',
    client_address TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    consumed_at_ms INTEGER,
    CHECK(expires_at_ms > created_at_ms)
);

INSERT INTO webauthn_ceremonies_v2(
  id,user_id,operation,purpose,context_id,challenge,rp_id,session_data,app_id,remember_me,
  client_user_agent,client_address,request_id,created_at_ms,expires_at_ms,consumed_at_ms)
SELECT id,user_id,operation,'login','',challenge,rp_id,session_data,app_id,remember_me,
  client_user_agent,client_address,
  request_id,created_at_ms,expires_at_ms,consumed_at_ms
FROM webauthn_ceremonies;

DROP TABLE webauthn_ceremonies;

ALTER TABLE webauthn_ceremonies_v2 RENAME TO webauthn_ceremonies;

CREATE INDEX ix_webauthn_ceremonies_user_operation
    ON webauthn_ceremonies(user_id, operation, consumed_at_ms);

CREATE INDEX ix_webauthn_ceremonies_expires
    ON webauthn_ceremonies(expires_at_ms);
