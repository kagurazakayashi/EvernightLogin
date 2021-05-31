-- 0013 自主注册的邮箱验证状态：每个用户至多一个待验证入口。
--
-- 对应步骤 33 的“按配置开放的自主注册 + 邮箱验证”。本迁移只登记状态，不保存
-- 任何可直接使用的验证秘密：
--   - 一次性验证凭证（高熵令牌）由 0002 的 one_time_credentials 保存摘要，
--     明文只在签发时返回一次并只出现在发给用户的邮件链接中。
--   - 本表把“用户 + 待验证地址 + 凭证 ID + 有效期”绑定在一起。credential_id
--     只用于与凭证记录交叉校验，不是可单独使用的入口；同时重新发送会覆盖本行，
--     旧链接因 credential_id 不再匹配而失效（凭证同时被 ReplaceActive 撤销）。
--   - email_normalized 使用服务层 authn.NormalizeEmail 的统一规范化口径；本表
--     只保证长度，唯一性最终由 user_emails.email_normalized 主键保证。
--   - 完成验证时服务层在审计事务内条件更新 user_emails.verified_at_ms 并删除本
--     行；任一条件不满足（地址已替换、已删除或已由其他入口验证）整体回滚。
--   - 不保存令牌明文、验证码、邮件正文或任何可重放秘密。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE email_verification_tickets (
user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
credential_id TEXT NOT NULL,
email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
email_normalized TEXT NOT NULL CHECK(length(email_normalized) BETWEEN 3 AND 254),
created_at_ms INTEGER NOT NULL,
expires_at_ms INTEGER NOT NULL,
CHECK(expires_at_ms>created_at_ms)
);

CREATE INDEX ix_email_verification_tickets_credential ON email_verification_tickets(credential_id);
CREATE INDEX ix_email_verification_tickets_email ON email_verification_tickets(email_normalized);
