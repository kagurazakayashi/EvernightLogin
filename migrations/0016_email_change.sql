-- 0016 邮箱变更申请、验证与切换。
--
-- 对应步骤 36 的“邮箱变更申请、验证新地址、切换生效”：
--   - 每个用户同一时间至多一条 pending 申请（部分唯一索引），新申请会取消旧申请；
--   - 申请绑定 user_id、旧已验证邮箱（首次添加时为空）与规范化新邮箱；旧邮箱在
--     新地址验证成功前仍保留原 user_emails 行与验证状态；
--   - 一次性高熵凭证只保存于 0002 one_time_credentials（摘要），本表只保存凭证 ID
--     用于与请求交叉校验，不保存令牌明文；
--   - 切换完成在服务层审计事务内校验唯一性、旧地址版本、消费凭证后删除旧已验证行、
--     写入新已验证行并标记 completed；本表不保存邮件正文或校验链接；
--   - 告知旧邮箱的状态只记录结果类别与稳定错误码，不含敏感凭证。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE email_change_requests (
id TEXT PRIMARY KEY NOT NULL,
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
old_email TEXT,
old_email_normalized TEXT,
new_email TEXT NOT NULL CHECK(length(new_email) BETWEEN 3 AND 254),
new_email_normalized TEXT NOT NULL CHECK(length(new_email_normalized) BETWEEN 3 AND 254),
status TEXT NOT NULL CHECK(status IN('pending','completed','cancelled','expired')),
credential_id TEXT NOT NULL,
created_at_ms INTEGER NOT NULL,
expires_at_ms INTEGER NOT NULL,
completed_at_ms INTEGER,
cancelled_at_ms INTEGER,
request_id TEXT,
verify_state TEXT NOT NULL DEFAULT 'pending' CHECK(verify_state IN('pending','sent','failed')),
verify_error_code TEXT,
verify_notified_at_ms INTEGER,
notify_state TEXT NOT NULL DEFAULT 'pending' CHECK(notify_state IN('pending','sent','failed','skipped')),
notify_error_code TEXT,
notified_at_ms INTEGER,
CHECK(expires_at_ms>created_at_ms),
CHECK((old_email IS NULL AND old_email_normalized IS NULL)
   OR (old_email IS NOT NULL AND old_email_normalized IS NOT NULL))
);

CREATE UNIQUE INDEX ux_email_change_pending ON email_change_requests(user_id) WHERE status='pending';
CREATE INDEX ix_email_change_credential ON email_change_requests(credential_id);
CREATE INDEX ix_email_change_user_created ON email_change_requests(user_id,created_at_ms);
