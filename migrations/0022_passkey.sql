-- 0022_passkey.sql：WebAuthn/Passkey 注册、登录与凭证管理（步骤 42）。
--
-- 三张表：
--   webauthn_user_handles：稳定的 WebAuthn 用户句柄（user handle）。句柄是
--     crypto/rand 生成的 32 字节随机值，与 users.id 无关，不可枚举、不写入
--     认证器可读以外的响应字段；每个用户至多一个，创建后不变。
--   webauthn_credentials：public-key 凭证记录。credential_id 是认证器返回的
--     原始 ID，全表唯一（同一凭证不能被登记到第二个账户，也不能重复注册）；
--     撤销使用 revoked_at_ms 软删除，保留审计关联。public_key 是 COSE 公钥
--     原始字节，不是私钥；不保存任何可还原秘密。sign_count 是已接受的签名
--     计数器，同步凭证（backup_eligible=1）不要求每次递增。
--   webauthn_ceremonies：注册/认证挑战的服务器端状态。挑战与 go-webauthn 的
--     SessionData 只保存在服务端（session_data 为库的 msgp 编码），一次性消费
--     由 consumed_at_ms 条件更新保证；user_id 为 NULL 表示可发现凭证登录
--     （usernameless）尚未确定用户。app_id/remember_me/客户端描述在开始认证
--     时绑定，完成认证时只能使用这里保存的值，不能由客户端替换。

CREATE TABLE webauthn_user_handles (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    handle BLOB NOT NULL UNIQUE CHECK(length(handle) BETWEEN 16 AND 64),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials (
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
    usage TEXT NOT NULL DEFAULT 'login' CHECK(usage IN('login','second_factor')),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    last_used_at_ms INTEGER,
    revoked_at_ms INTEGER,
    revoked_reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK(backup_eligible = 1 OR backed_up = 0)
);

CREATE INDEX ix_webauthn_credentials_user_active
    ON webauthn_credentials(user_id, revoked_at_ms);

CREATE TABLE webauthn_ceremonies (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN('registration','authentication')),
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

CREATE INDEX ix_webauthn_ceremonies_user_operation
    ON webauthn_ceremonies(user_id, operation, consumed_at_ms);

CREATE INDEX ix_webauthn_ceremonies_expires
    ON webauthn_ceremonies(expires_at_ms);
