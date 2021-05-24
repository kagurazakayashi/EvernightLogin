-- 0010 会话：普通/受限会话的验证摘要、到期与撤销状态。
--
-- 对应步骤 30 的“把密码认证结果接入会话服务”。本迁移只登记会话事实：
--   - 数据库绝不保存会话秘密、Cookie 原文、CSRF 令牌原文或任何可还原的
--     凭证明文；secret_digest/csrf_digest 是 internal/secrets.Keyring 以当前写
--     密钥派生的 HMAC-SHA256 验证摘要（32 字节），会话秘密本身由 crypto/rand
--     生成 256 位随机值，只返回给客户端一次。
--   - kind 只有 normal（完整认证会话）与 restricted（受限会话）两种；受限会话
--     用 restricted_reason 细分待补充认证（pending_second_factor /
--     pending_password_change）、受限恢复（recovery）与受限初始化
--     （initialization），它们都不得访问普通业务或管理接口。
--   - security_version 是签发时账户安全版本的快照；每次校验都会重读
--     users.status 与 users.security_version，不一致即视为失效，因此账户禁用、
--     删除请求、密码变更等递增安全版本的操作会立即使既有会话不可用。
--   - app_id 非空表示会话绑定在某个应用上下文中；每次校验都会重读应用状态与
--     应用成员状态，应用停用或成员被移除/停用后该会话失效。
--   - strong_auth_verified_at_ms 为 NULL 表示强认证（MFA）尚未完成；管理接口
--     必须要求该时间非空。MFA 未实现前会话签发不会写入它，管理访问保持拒绝。
--   - 到期有两道独立约束：idle_expires_at_ms（最后活动 + 空闲期限）与
--     absolute_expires_at_ms（签发 + 绝对期限）；续期只能延长空闲到期，绝不
--     越过绝对到期。
--   - 撤销是服务端状态：revoked_at_ms 非空后任何校验/续期都必须失败；退出与
--     管理撤销都写这里，不依赖客户端删除 Cookie。
--   - 该表不替代 OAuth Access Token（后续步骤另行实现），也不承载权限判定。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE sessions (
id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
app_id TEXT REFERENCES applications(id) ON DELETE CASCADE,
kind TEXT NOT NULL CHECK(kind IN('normal','restricted')),
restricted_reason TEXT NOT NULL DEFAULT '' CHECK(restricted_reason IN(
'','pending_second_factor','pending_password_change','recovery','initialization')),
required_steps_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(required_steps_json)),
security_version INTEGER NOT NULL CHECK(security_version>0),
secret_digest BLOB NOT NULL CHECK(length(secret_digest)=32),
csrf_digest BLOB NOT NULL CHECK(length(csrf_digest)=32),
key_id TEXT NOT NULL,
strong_auth_verified_at_ms INTEGER,
row_version INTEGER NOT NULL DEFAULT 1,
created_at_ms INTEGER NOT NULL,
last_seen_at_ms INTEGER NOT NULL,
idle_expires_at_ms INTEGER NOT NULL,
absolute_expires_at_ms INTEGER NOT NULL,
revoked_at_ms INTEGER,
revoked_reason TEXT NOT NULL DEFAULT '',
request_id TEXT NOT NULL DEFAULT '',
CHECK((kind='normal' AND restricted_reason='') OR (kind='restricted' AND restricted_reason<>'')),
CHECK(idle_expires_at_ms<=absolute_expires_at_ms),
CHECK(revoked_at_ms IS NULL OR revoked_at_ms>=created_at_ms)
);

CREATE INDEX idx_sessions_user ON sessions(user_id,revoked_at_ms);
CREATE INDEX idx_sessions_app ON sessions(app_id,revoked_at_ms);
CREATE INDEX idx_sessions_absolute_expiry ON sessions(absolute_expires_at_ms);
