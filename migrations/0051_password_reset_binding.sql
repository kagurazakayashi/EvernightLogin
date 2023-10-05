-- 0051 找回入口的安全代际与已验证邮箱身份绑定（步骤 206）。
--
-- 对应步骤 206 的“旧找回链接随密码和邮箱安全变更失效”：
--   - security_version 记录签发时 users.security_version（统一安全代际）；密码修改、
--     管理员强制改密、管理员/人工恢复、MFA 因素变更、账户禁用等安全变更都在各自事务内
--     原子递增该版本，因此旧链接在完成/预检查时因版本不符而失效（禁用后再启用不会递减）。
--   - bound_email_normalized 记录签发时账户的最近已验证邮箱（规范化）；验证邮箱切换在
--     email_change 事务内原子删除旧验证行并插入新行，旧链接因邮箱身份不再匹配而失效。
--   - 两列可空仅为兼容迁移前已存在的行：未绑定行（任一列为 NULL）由服务层按失效处理
--     （保守拒绝，不回填、不留不安全兼容）；迁移后新写入的请求总是同时写入两列绑定。
--   - 本表不保存 token 明文、密码或密码哈希；普通审计仍只记录脱敏邮箱，不写原始邮箱
--     或绑定值。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE password_reset_requests ADD COLUMN security_version INTEGER;
ALTER TABLE password_reset_requests ADD COLUMN bound_email_normalized TEXT;
