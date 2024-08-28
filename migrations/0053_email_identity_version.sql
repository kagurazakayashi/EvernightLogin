-- 0053 已验证邮箱身份代际（步骤 250）。
--
-- 背景：找回入口在 0051 绑定 security_version（统一安全代际）与
-- bound_email_normalized（最近已验证邮箱文本）。当账户在入口有效期内发生
-- A→B→A 往返换绑时，当前邮箱文本重新等于签发值、安全版本也可能未变，
-- 于是旧链接会重新匹配并恢复可用。仅靠邮箱文本无法区分“同一地址的新身份”
-- 与“签发时的旧身份”。
--
-- 本迁移引入单调、不可回退的已验证邮箱身份代际：
--   - users.email_identity_version：账户当前“已验证邮箱身份”的代际，初始 0。
--     每次真实改变该用户已验证邮箱身份（本人换绑、首次添加/首次验证、邀请新
--     用户预验证邮箱等写入点）都在各自审计事务内原子 +1；代际只增不减，邮箱
--     文本往返复原时也会得到新代际，旧授权不会因文本相同而复活。
--   - password_reset_requests.bound_email_identity_version：找回入口签发时绑定
--     的邮箱身份代际。签发与完成/预检查都在提交边界核对“安全版本 + 邮箱身份
--     代际 + 规范化邮箱”三者；任一不符即确定性失效。
--   - 该列可空仅为兼容 0053 之前已存在的行（0051 已绑定行没有代际）：未绑定行
--     （该列为 NULL）由服务层按失效处理（保守拒绝、不回填、不留不安全兼容）；
--     迁移后新写入的请求总是写入绑定列。
--   - 本文件不建表、不回填、不更新数据、不修改已发布迁移，也不保存 token
--     明文、密码或密码哈希。MySQL/PostgreSQL/SQL Server 迁移由
--     migrations/{mysql,postgres,sqlserver} 从本 SQLite 迁移确定性翻译得到，
--     因此这里只使用标准的 ALTER TABLE ADD COLUMN 语法。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE users ADD COLUMN email_identity_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE password_reset_requests ADD COLUMN bound_email_identity_version INTEGER;
