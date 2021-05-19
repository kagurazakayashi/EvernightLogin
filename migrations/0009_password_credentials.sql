-- 0009 正式密码凭证、可选密码历史与已验证邮箱登录标识。
--
-- 对应步骤 29 的“正式密码哈希、密码验证与认证结果”。本迁移只登记数据，
-- 不创建会话、令牌或任何可远程使用的登录凭证：
--   - password_credentials 每个用户至多一条正式密码记录。password_hash 保存
--     成熟库生成的 Argon2id PHC 编码字符串（含算法版本、参数、盐与摘要），
--     不保存明文密码、可逆密文或单独的摘要列；hash_scheme/hash_version 是
--     便于查询与升级判断的冗余版本标记，必须与 PHC 内容一致。
--   - password_history 保存被替换的旧密码哈希用于“可选历史限制”，只保存与
--     password_credentials 相同的 PHC 值，保存条数由服务层按策略裁剪，不在
--     数据库层保存任何明文。历史记录不参与登录验证，只阻止重复使用旧密码。
--   - user_emails 保存用户已验证邮箱登录标识；email_normalized 是唯一键，
--     由服务层统一做 NFKC + Unicode 大小写折叠 + NFC 后写入，登录查询必须使用
--     同一口径。该规范化包含非 ASCII 大小写折叠，不能在 SQLite 中用 lower()
--     近似（SQLite lower() 只处理 ASCII）；因此数据库只保证长度与唯一性，规范
--     口径由服务层的 NormalizeEmail 单一实现负责。verified_at_ms 为 NULL 表示
--     尚未验证，绝不能用于登录。邮箱注册与验证流程在后续步骤实现，本步只提供
--     登录查询所需的稳定结构。
--   - 不记录失败次数：登录失败限制由服务层的有界状态实现，重启即恢复（不永久
--     锁号）；数据库只保存长期成立的凭证与验证事实。
--   - 密码变更会同时递增 users.security_version，供后续会话/令牌模块拒绝旧会话；
--     本迁移不创建会话表。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE password_credentials (
user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
hash_scheme TEXT NOT NULL CHECK(hash_scheme='argon2id'),
hash_version INTEGER NOT NULL CHECK(hash_version=19),
password_hash TEXT NOT NULL CHECK(length(password_hash) BETWEEN 32 AND 512),
must_change INTEGER NOT NULL DEFAULT 0 CHECK(must_change IN(0,1)),
row_version INTEGER NOT NULL DEFAULT 1,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL,
changed_at_ms INTEGER NOT NULL
);

CREATE INDEX idx_password_credentials_changed ON password_credentials(changed_at_ms);

CREATE TABLE password_history (
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
password_hash TEXT NOT NULL CHECK(length(password_hash) BETWEEN 32 AND 512),
created_at_ms INTEGER NOT NULL,
PRIMARY KEY(user_id,password_hash)
);

CREATE INDEX idx_password_history_user_time ON password_history(user_id,created_at_ms DESC);

CREATE TABLE user_emails (
email_normalized TEXT PRIMARY KEY NOT NULL CHECK(length(email_normalized) BETWEEN 3 AND 254),
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
verified_at_ms INTEGER,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL
);

CREATE INDEX idx_user_emails_user ON user_emails(user_id);
CREATE INDEX idx_user_emails_verified ON user_emails(email_normalized) WHERE verified_at_ms IS NOT NULL;
