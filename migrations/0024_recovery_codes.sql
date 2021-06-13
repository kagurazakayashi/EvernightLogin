-- 步骤 44：恢复代码（按组管理）与受限恢复尝试。
--
-- 安全模型：
--   * 恢复代码是高熵一次性代码；数据库只保存 internal/secrets.Keyring 派生的
--     HMAC-SHA256 验证摘要，不保存明文或可逆加密值，因此无法从数据库、日志或审计
--     恢复出代码本身。明文只在生成/重新生成时返回一次。
--   * 代码按组管理：同一用户最多一个 active 组（部分唯一索引）；重新生成会在同一
--     审计事务内把旧组置为 superseded 并插入新组，旧组代码立即失效。
--   * 每行 recovery_codes 的 used_at_ms 只能由条件更新从 NULL 置为非空，保证并发
--     重复使用同一代码时只有一个赢家；代码使用后即作废，不会重新可用。
--   * recovery_attempts 记录一次“已消费代码 → 受限恢复会话 → 新因素绑定”的短时
--     尝试；同一用户同时最多一个 pending_binding 尝试，绑定完成前旧因素与会话保持
--     不动；完成后旧组作废并生成新组，且必须以新的正常登录重新获得完整会话。
CREATE TABLE recovery_code_groups (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation>=1),
    status TEXT NOT NULL CHECK(status IN('active','superseded','exhausted','revoked')),
    code_count INTEGER NOT NULL CHECK(code_count>0 AND code_count<=64),
    created_at_ms INTEGER NOT NULL,
    invalidated_at_ms INTEGER,
    UNIQUE(user_id,generation)
);

CREATE UNIQUE INDEX ux_recovery_code_groups_active
    ON recovery_code_groups(user_id) WHERE status='active';
CREATE INDEX ix_recovery_code_groups_user
    ON recovery_code_groups(user_id,created_at_ms);

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,
    group_id TEXT NOT NULL REFERENCES recovery_code_groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    digest BLOB NOT NULL CHECK(length(digest)=32),
    key_id TEXT NOT NULL,
    used_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_recovery_codes_group
    ON recovery_codes(group_id,used_at_ms);
CREATE INDEX ix_recovery_codes_user
    ON recovery_codes(user_id,used_at_ms);

CREATE TABLE recovery_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES recovery_code_groups(id) ON DELETE RESTRICT,
    code_id TEXT NOT NULL REFERENCES recovery_codes(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN('pending_binding','completed','cancelled','expired','failed')),
    session_id TEXT,
    planned_method TEXT,
    planned_binding_id TEXT,
    factor_method TEXT,
    factor_ref TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    max_attempts INTEGER NOT NULL CHECK(max_attempts>=1 AND max_attempts<=10),
    expires_at_ms INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER,
    CHECK(status<>'pending_binding' OR planned_method IS NULL
        OR planned_method IN('passkey','totp'))
);

CREATE UNIQUE INDEX ux_recovery_attempts_pending
    ON recovery_attempts(user_id) WHERE status='pending_binding';
CREATE INDEX ix_recovery_attempts_user
    ON recovery_attempts(user_id,created_at_ms);
CREATE INDEX ix_recovery_attempts_session
    ON recovery_attempts(session_id);
