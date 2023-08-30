-- 0047 应用逻辑删除与生命周期（步骤 190）。
--
-- 语义：
--   - deleted_at_ms 非空表示应用已“逻辑删除”：所有令牌/会话/客户端/权限判定按应用
--     不可用拒绝，应用数据（成员/角色/权限/客户端凭证/授权记录）保留供审计与追溯。
--   - 停用（status='disabled' 且 deleted_at_ms 为空）不等于删除；启用/停用/改资料
--     在逻辑删除后一律拒绝（服务层按防回退状态机判定）。
--   - 物理清理不是本迁移的默认动作：只允许受控本地/系统通道在保留期后执行，
--     审计事件（audit_events.app_id_snapshot 无外键）与应用历史快照不受影响。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE applications ADD COLUMN deleted_at_ms INTEGER;

CREATE INDEX ix_applications_deleted_at
  ON applications(deleted_at_ms) WHERE deleted_at_ms IS NOT NULL;
