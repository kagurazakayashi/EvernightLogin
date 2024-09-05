-- 0054 目标绑定的一次性两步验证操作证明（步骤 255）。
--
-- 背景：0019 的再次认证批准只绑定“操作者 + 作用域 + 操作 + 目标 + 参数摘要”，
-- 用于操作者与目标相同的敏感操作；且批准消费发生在独立审计事务中，业务提交失败
-- 会烧掉批准。直接修改他人用户名/直接重置他人密码需要：
--   - 操作者与目标不是同一人；
--   - 操作者本次完成两步验证（不是目标用户的验证）；
--   - 会话、范围与“本次新值意图”（新用户名/新口令）分别绑定；
--   - 同一证明可在提交失败后重试，成功后单次消费、重放不二次执行；
--   - 新口令等秘密不得以明文或无密钥摘要落库。
--
-- 本迁移只追加可空列（不改已发布迁移、不建表、不回填）：
--   - reauth_challenges.session_id：创建挑战时绑定的操作者会话 ID；为空表示
--     0019 兼容的“操作者即目标”旧挑战（不能用于直接管理操作）。
--   - reauth_challenges.intent_sealed：用既有 internal/secrets AES-256-GCM 密封的
--     本次新值意图（JSON：kind + value；绑定用途/对象/范围，密文无法跨记录复用）。
--     为空表示没有意图绑定（旧挑战/非直接管理操作）。
--   - reauth_approvals.session_id：从挑战复制的一次性证明会话绑定。
--   - reauth_approvals.intent_sealed：从挑战复制的密封意图；消费时同一事务把该列
--     清空（`intent_sealed=NULL`），过期未消费的密文由有界清理语句擦除。批准表仍
--     不保存令牌明文、密码、密码哈希或任何可解密的新值以外的秘密。
--   - 旧行（0054 之前）四列为 NULL：直接管理证明要求会话与意图同时存在，因此旧行
--     fail-closed（保守拒绝，不回填、不猜测）。
--
-- 本文件不包含 Go 常量或迁移计数；迁移版本由文件名与 migrate 加载器决定，不要在
-- 这里硬编码版本号。MySQL/PostgreSQL/SQL Server 结构由 migrations/{mysql,postgres,
-- sqlserver} 从本 SQLite 迁移确定性翻译（只有标准 ALTER TABLE ADD COLUMN）。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE reauth_challenges ADD COLUMN session_id TEXT;
ALTER TABLE reauth_challenges ADD COLUMN intent_sealed BLOB;
ALTER TABLE reauth_approvals ADD COLUMN session_id TEXT;
ALTER TABLE reauth_approvals ADD COLUMN intent_sealed BLOB;
