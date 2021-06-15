-- +migrate whole-file
-- 0026 客服求助单与处理历史。
--
-- 对应步骤 46 的客服求助单与向原验证邮箱发起找回：
--   - support_cases 记录求助单：目标用户、真实操作者（创建人/当前指派客服）、
--     处理原因、状态机、辅助核验信息（只保存脱敏邮箱快照）与行版本。求助单不保存
--     密码、密码哈希、MFA 秘密、恢复代码、凭证或找回 token；客服能看到的信息由
--     internal/support 服务在返回前脱敏。
--   - support_case_events 是求助单处理历史（追加式）：记录动作、真实操作者与时间、
--     状态迁移与脱敏说明。服务不提供修改/删除历史的方法，并由触发器禁止 UPDATE
--     （历史不可覆盖）；用户账户被彻底删除时随外键级联清理整条求助单的既有语义，
--     这不是普通业务可调用的删除路径。
--   - 状态机：pending_verification（已登记待核验/待发送）→ sent（已向原已验证邮箱
--     发起找回）或 manual_review（未具备验证渠道，转步骤 47 人工核验待处理）；
--     closed/cancelled 为终态。本迁移不实现人工核验审批与执行。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE support_cases (
  id TEXT PRIMARY KEY NOT NULL,
  target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assignee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 2000),
  status TEXT NOT NULL CHECK(status IN(
    'pending_verification','sent','manual_review','closed','cancelled')),
  target_masked_email TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version >= 1),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(updated_at_ms >= created_at_ms)
);

CREATE INDEX ix_support_cases_assignee
  ON support_cases(assignee_user_id, status, updated_at_ms);

CREATE INDEX ix_support_cases_target
  ON support_cases(target_user_id, updated_at_ms);

CREATE TABLE support_case_events (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT NOT NULL REFERENCES support_cases(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL CHECK(seq >= 1),
  action TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK(actor_type IN('user','system','local_admin')),
  actor_id TEXT NOT NULL,
  from_status TEXT NOT NULL DEFAULT '',
  to_status TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  UNIQUE(case_id, seq)
);

CREATE INDEX ix_support_case_events_case
  ON support_case_events(case_id, seq);

-- 处理历史是追加式安全记录：禁止原地改写（UPDATE）。删除仅随求助单/用户账户的
-- 外键级联发生，业务 API 没有单独删除历史的方法。
CREATE TRIGGER trg_support_case_events_no_update
BEFORE UPDATE ON support_case_events
BEGIN
  SELECT RAISE(ABORT, 'support_case_events is append-only');
END;
