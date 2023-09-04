-- 0048 人工核验 MFA 恢复后的强制重绑状态（步骤 188）。
--
-- 语义：
--   - MFA 恢复执行器成功重置因素后写入一行未清除记录：目标在重新完成强认证初始化
--     （Passkey，Passkey-only 先行）之前只能得到受限会话，不能访问普通业务。
--   - cleared_at_ms 非空表示已由真实强认证初始化完成并清除；不清除则登录持续受限。
--   - 只保存“需要重绑”的事实（时间、原因、来源申请编号），不含任何秘密/凭证/令牌。
--   - root/高权限目标由人工恢复目标保护拒绝，不会进入本表；本表不改变该保护。
CREATE TABLE mfa_rebind_requirements (
  user_id           TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  required_at_ms    INTEGER NOT NULL,
  reason_code       TEXT NOT NULL,
  source_request_id TEXT NOT NULL,
  cleared_at_ms     INTEGER
);

CREATE INDEX ix_mfa_rebind_requirements_pending
  ON mfa_rebind_requirements(cleared_at_ms) WHERE cleared_at_ms IS NULL;
