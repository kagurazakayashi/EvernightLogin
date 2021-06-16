-- +migrate whole-file
-- 0027 人工核验恢复申请、独立审批与受控执行。
--
-- 对应步骤 47：默认关闭、由 root/宿主显式配置的人工账户恢复（只处理既有验证渠道
-- 不可用的普通账户）。密码恢复与 MFA 恢复是**分别申请、分别授权**的操作类型，
-- 一次批准只对一条请求的固定内容、固定操作类型有效。
--
-- 安全约束：
--   - manual_recovery_requests 只保存目标稳定 ID、发起人、操作类型、核验依据/外部
--     核验记录编号、证据摘要（SHA-256，不保存证据明文）、原因、交付渠道、目标安全
--     版本/高权限快照、交付地址指纹（只保存不可逆指纹，不保存邮箱明文）以及服务端
--     计算的内容摘要 content_digest；不保存密码、MFA
--     秘密、恢复代码、凭证/token 或证件材料。
--   - manual_recovery_approvals 绑定请求内容摘要与操作类型，记录独立审批人、批准
--     等待期起点/执行有效期；同一请求最多一个 active 批准（部分唯一索引）。
--   - manual_recovery_executions 记录一次性执行（同一批准最多一次）；执行状态迁移
--     使用条件更新，双执行竞争只有一个成功。
--   - 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE manual_recovery_requests (
  id TEXT PRIMARY KEY NOT NULL,
  target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  initiator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_type TEXT NOT NULL CHECK(operation_type IN('password_reset','mfa_reset')),
  status TEXT NOT NULL CHECK(status IN(
    'pending_approval','approved','executing','completed','rejected','cancelled','failed','expired')),
  verification_basis TEXT NOT NULL CHECK(verification_basis IN(
    'in_person_identity_document','notarized_declaration')),
  verification_reference TEXT NOT NULL CHECK(length(verification_reference) BETWEEN 1 AND 128),
  evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  delivery_channel TEXT NOT NULL CHECK(delivery_channel IN('verified_email')),
  delivery_fingerprint TEXT NOT NULL CHECK(length(delivery_fingerprint) BETWEEN 1 AND 128),
  target_security_version INTEGER NOT NULL CHECK(target_security_version>0),
  target_high_privilege INTEGER NOT NULL DEFAULT 0 CHECK(target_high_privilege IN(0,1)),
  content_digest BLOB NOT NULL CHECK(length(content_digest)=32),
  support_case_id TEXT,
  expires_at_ms INTEGER NOT NULL,
  closed_reason TEXT,
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(updated_at_ms>=created_at_ms),
  CHECK(expires_at_ms>created_at_ms)
);

CREATE INDEX ix_manual_recovery_requests_target
  ON manual_recovery_requests(target_user_id, status);
CREATE INDEX ix_manual_recovery_requests_status
  ON manual_recovery_requests(status, created_at_ms);
CREATE INDEX ix_manual_recovery_requests_initiator
  ON manual_recovery_requests(initiator_user_id, created_at_ms);

CREATE TABLE manual_recovery_approvals (
  id TEXT PRIMARY KEY NOT NULL,
  request_id TEXT NOT NULL REFERENCES manual_recovery_requests(id) ON DELETE CASCADE,
  approver_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_type TEXT NOT NULL CHECK(operation_type IN('password_reset','mfa_reset')),
  content_digest BLOB NOT NULL CHECK(length(content_digest)=32),
  status TEXT NOT NULL CHECK(status IN('active','consumed','invalidated','expired')),
  approved_at_ms INTEGER NOT NULL,
  not_before_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER,
  invalidated_reason TEXT,
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1),
  CHECK(not_before_ms>=approved_at_ms),
  CHECK(expires_at_ms>not_before_ms)
);

CREATE UNIQUE INDEX ux_manual_recovery_approvals_active
  ON manual_recovery_approvals(request_id) WHERE status='active';
CREATE INDEX ix_manual_recovery_approvals_approver
  ON manual_recovery_approvals(approver_user_id, status);

CREATE TABLE manual_recovery_executions (
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
    CHECK(notification_state IN('pending','sent','failed','not_configured')),
  error_code TEXT,
  started_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER
);

CREATE INDEX ix_manual_recovery_executions_request
  ON manual_recovery_executions(request_id, status);
