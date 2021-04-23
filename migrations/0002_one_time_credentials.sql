-- 0002 一次性凭证（验证码与短期令牌）。
--
-- 对应步骤 09 与设计基线 one_time_credentials 表。正式迁移按
-- docs/database/存储模型与迁移设计.md 的跨数据库表示约定落地：验证摘要使用
-- BLOB 二进制列而不是十六进制文本；时间使用 UTC 毫秒整数；JSON 使用 json_valid。
--
-- 语义：
--   - key_id 为 NULL 表示高熵令牌，verifier_hash 是 SHA-256 摘要；
--   - key_id 非空表示低熵验证码，verifier_hash 是用该密钥材料派生的
--     HMAC-SHA256 受密钥保护摘要，防止数据库泄露后被离线穷举；
--   - key_id 引用主密钥环中的密钥编号（不是数据库外键），轮换后旧密钥必须
--     保留到相关凭证过期或被清理，否则未使用的历史凭证将无法验证；
--   - consumed_at_ms / revoked_at_ms 为空表示仍可能被消费；实际有效性还要
--     结合 expires_at_ms 与 attempts < max_attempts 判断；
--   - subject_id 是一次性凭证的接收方/目标对象（不可为空），app_id 为空表示
--     系统范围，非空时绑定到 applications(id)。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE one_time_credentials (
id TEXT PRIMARY KEY NOT NULL,
purpose TEXT NOT NULL,
subject_id TEXT NOT NULL,
app_id TEXT REFERENCES applications(id) ON DELETE CASCADE,
verifier_hash BLOB NOT NULL UNIQUE,
key_id TEXT,
context_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(context_json)),
attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
max_attempts INTEGER NOT NULL CHECK(max_attempts>0),
created_at_ms INTEGER NOT NULL,
expires_at_ms INTEGER NOT NULL,
consumed_at_ms INTEGER,
revoked_at_ms INTEGER,
CHECK(expires_at_ms>created_at_ms)
);

CREATE INDEX ix_one_time_credentials_expires_at_ms ON one_time_credentials(expires_at_ms);

CREATE INDEX ix_one_time_credentials_scope ON one_time_credentials(purpose,subject_id,app_id,created_at_ms);
