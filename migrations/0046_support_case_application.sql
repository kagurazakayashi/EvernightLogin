-- 0046 客服求助单增加应用归属（步骤 154）。
--
-- 应用受限客服 API 只能创建/读取本应用工单；空 application_id 保持既有系统/全局
-- 客服工单语义。列可为空以兼容旧数据，不重写历史工单；索引用于按应用过滤，
-- 与既有 assignee/target 索引共存。本迁移不保存密码、MFA、恢复代码或找回 token。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE support_cases ADD COLUMN application_id TEXT;

CREATE INDEX ix_support_cases_application
  ON support_cases(application_id, updated_at_ms);
