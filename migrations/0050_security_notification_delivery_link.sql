-- 0050 安全告知主记录与可靠邮件投递记录的关联（步骤 210）。
--
-- 背景：步骤 197 起敏感操作安全告知改走可靠投递队列（mailer.Enqueue 成功只代表
-- “已受理”，真实结果由 mail_deliveries 与 mail_delivery 任务终态体现）。但
-- internal/reauth 的告知记录此前丢弃了 Enqueue 返回的投递标识，页面也无法区分
-- 排队/投递中/发送后端已接受/失败/取消。
--
-- 本迁移只做**增量可空列 + 索引**，不重建表、不修改已发布迁移、不清库：
--   - delivery_id：关联 mail_deliveries.id（可靠投递记录）。可为空：历史记录、
--     直接发送回退路径、入队前失败或关联回写尚未完成的记录没有投递标识。
--   - dedup_key：稳定业务去重键（同一业务事件同一结果的重试/重启复用同一键）。
--     作为邮件入队的幂等键，并让告知主记录在同一业务事件上幂等更新而不是重复插入。
--     历史记录与直接发送回退路径为空。
--   - 部分唯一索引只约束非空去重键；SQLite/PostgreSQL 唯一索引本可含多个 NULL，
--     但 SQL Server 的普通唯一索引只允许一个 NULL，故用 partial/filtered 语义
--     显式排除 NULL，保持跨方言一致。
--
-- 语义边界：
--   - delivery_id 只表示“关联到哪次可靠投递”，不表示送达；delivery 状态以
--     mail_deliveries.state 为准（succeeded 仅表示发送后端已接受，不代表已读或
--     最终送达）。
--   - 通知失败不回滚已成功业务；本表只记录告知结果与关联，不承载业务状态。
--   - 不存明文收件地址（recipient_masked 仍为脱敏值）、不存令牌/验证码/正文。

ALTER TABLE security_notifications ADD COLUMN delivery_id TEXT;
ALTER TABLE security_notifications ADD COLUMN dedup_key TEXT;

CREATE UNIQUE INDEX ux_security_notifications_dedup_key
  ON security_notifications(dedup_key) WHERE dedup_key IS NOT NULL;

CREATE INDEX ix_security_notifications_delivery
  ON security_notifications(delivery_id);
