-- 0015 用户资料扩展：可选电话与更名时间。
--
-- 对应步骤 35 的“用户自助资料修改与获授权管理员修改”：
--   - phone 保存 E.164 规范化后的可选电话；phone_verified_at_ms 由本步永远不会
--     写入，电话不参与登录、找回或任何身份验证；读取方必须把 NULL 解释为未验证。
--   - username_changed_at_ms 保存最近一次受控更名时间，供更名冷却策略判断；
--     0 表示从未更名。稳定用户 ID 不因更名改变。
--   - 昵称/简介/语言/时区复用 0001 的列，不在此重复定义；应用专属资料仍在
--     app_memberships.profile_json，本迁移不改动应用隔离边界。
--   - 本迁移不新增邮箱验证、密码、MFA、角色或 root 字段。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE users ADD COLUMN phone TEXT
  CHECK(phone IS NULL OR (length(phone) BETWEEN 8 AND 32));

ALTER TABLE users ADD COLUMN phone_verified_at_ms INTEGER;

ALTER TABLE users ADD COLUMN username_changed_at_ms INTEGER NOT NULL DEFAULT 0;
