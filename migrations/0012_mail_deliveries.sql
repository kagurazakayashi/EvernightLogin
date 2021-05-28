-- 邮件投递记录：幂等键、状态、重试上限、任务关联与加密载荷。
-- 敏感模板数据（验证码、找回链接）只以 secrets.Sealer 加密后的 BLOB 保存，
-- 本表不存明文；邮件正文不落库。
CREATE TABLE mail_deliveries (
id TEXT PRIMARY KEY NOT NULL,
idempotency_key TEXT NOT NULL UNIQUE,
template_kind TEXT NOT NULL CHECK(template_kind IN('verification','password_reset','security_notice')),
recipient TEXT NOT NULL,
owner_type TEXT NOT NULL CHECK(owner_type IN('user','system','local_admin')),
owner_id TEXT NOT NULL,
state TEXT NOT NULL CHECK(state IN('queued','sending','succeeded','failed','cancelled')),
attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts>0),
task_id TEXT,
last_error_code TEXT,
last_error_kind TEXT,
sealed_payload BLOB NOT NULL,
request_id TEXT,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_mail_deliveries_state_created_at_ms ON mail_deliveries(state,created_at_ms);
CREATE INDEX ix_mail_deliveries_recipient ON mail_deliveries(recipient);
