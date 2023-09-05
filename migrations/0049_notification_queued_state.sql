-- 步骤 197：为安全告知/人工恢复通知增加 queued 状态（入可靠投递队列，不等于已送达）。
--
-- SQLite 无法修改既有 CHECK 约束，按项目既有做法重建表并复制数据；迁移一旦执行
-- 不得修改，后续结构变化只能追加新版本迁移文件。
--
-- 语义：
--   - security_notifications.state 新增 'queued'：已交给可靠投递队列，真实送达/失败
--     由 mailer 投递记录与 mail_delivery 任务终态体现（不是 sent）。
--   - manual_recovery_executions.notification_state 新增 'queued'：同上；sent 仅表示
--     直接发送器已接受（回退路径）。

CREATE TABLE security_notifications_v2 (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128),
  target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
  target_id TEXT NOT NULL DEFAULT '' CHECK(length(target_id) <= 128),
  outcome TEXT NOT NULL CHECK(outcome IN('success','failure')),
  state TEXT NOT NULL CHECK(state IN('sent','queued','failed','no_verified_email','rate_limited','not_configured','suppressed')),
  error_code TEXT,
  reason_code TEXT,
  recipient_masked TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL
);

INSERT INTO security_notifications_v2(
  id,user_id,operation_id,target_type,target_id,outcome,state,error_code,reason_code,
  recipient_masked,created_at_ms)
SELECT id,user_id,operation_id,target_type,target_id,outcome,state,error_code,reason_code,
  recipient_masked,created_at_ms
FROM security_notifications;

DROP TABLE security_notifications;

ALTER TABLE security_notifications_v2 RENAME TO security_notifications;

CREATE INDEX ix_security_notifications_user_created ON security_notifications(user_id, created_at_ms);

CREATE TABLE manual_recovery_executions_v2 (
  id TEXT PRIMARY KEY NOT NULL,
  request_id TEXT NOT NULL REFERENCES manual_recovery_requests(id) ON DELETE CASCADE,
  approval_id TEXT NOT NULL UNIQUE REFERENCES manual_recovery_approvals(id) ON DELETE RESTRICT,
  executor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_type TEXT NOT NULL CHECK(operation_type IN('password_reset','mfa_reset')),
  status TEXT NOT NULL CHECK(status IN('running','succeeded','failed')),
  sessions_revoked INTEGER NOT NULL DEFAULT 0 CHECK(sessions_revoked>=0),
  factors_reset INTEGER NOT NULL DEFAULT 0 CHECK(factors_reset IN(0,1)),
  reset_credential_issued INTEGER NOT NULL DEFAULT 0 CHECK(reset_credential_issued IN(0,1)),
  notification_state TEXT NOT NULL DEFAULT 'pending'
    CHECK(notification_state IN('pending','sent','queued','failed','not_configured')),
  error_code TEXT,
  started_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER
);

INSERT INTO manual_recovery_executions_v2(
  id,request_id,approval_id,executor_user_id,operation_type,status,sessions_revoked,
  factors_reset,reset_credential_issued,notification_state,error_code,started_at_ms,finished_at_ms)
SELECT id,request_id,approval_id,executor_user_id,operation_type,status,sessions_revoked,
  factors_reset,reset_credential_issued,notification_state,error_code,started_at_ms,finished_at_ms
FROM manual_recovery_executions;

DROP TABLE manual_recovery_executions;

ALTER TABLE manual_recovery_executions_v2 RENAME TO manual_recovery_executions;

CREATE INDEX ix_manual_recovery_executions_request
  ON manual_recovery_executions(request_id, status);
