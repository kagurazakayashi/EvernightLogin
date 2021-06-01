-- 0014 受控邀请、邀请接受与注册审核状态。
--
-- 对应步骤 34 的“受控邀请、接受邀请和注册审核”：
--   - invitations 记录明确发起者、目标邮箱或目标用户、适用应用、到期与使用次数；
--     目标邮箱只保存规范化值（authn.NormalizeEmail 口径），不保存原始输入。
--   - invitation_roles 记录邀请允许分配的默认角色；接受时仍须按邀请者“当前”权限
--     经 internal/delegation.Guard 重新校验，不能借邀请绕过转授权限制。
--   - invitation_acceptances 以 (invitation_id,user_id) 主键防止同一用户重复接受，
--     使用次数由服务层在审计事务内条件扣减（used_count<max_uses）。
--   - registration_reviews 记录注册审核状态与决定者；批准/拒绝的账户状态变更与
--     可选的成员/角色变更必须与审计同事务。
--   - 通知状态只记录投递结果类别与稳定错误码，不保存邀请令牌、邮件正文或链接。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE invitations (
id TEXT PRIMARY KEY NOT NULL,
inviter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
target_kind TEXT NOT NULL CHECK(target_kind IN('email','user')),
target_email TEXT,
target_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
app_id TEXT REFERENCES applications(id) ON DELETE CASCADE,
status TEXT NOT NULL CHECK(status IN('pending','accepted','cancelled','expired')),
max_uses INTEGER NOT NULL DEFAULT 1 CHECK(max_uses BETWEEN 1 AND 50),
used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count>=0 AND used_count<=max_uses),
expires_at_ms INTEGER NOT NULL,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL,
cancelled_at_ms INTEGER,
cancel_reason TEXT,
request_id TEXT,
notify_state TEXT NOT NULL DEFAULT 'pending' CHECK(notify_state IN('pending','sent','failed')),
notify_error_code TEXT,
notified_at_ms INTEGER,
CHECK((target_kind='email' AND target_email IS NOT NULL AND target_user_id IS NULL)
   OR (target_kind='user' AND target_email IS NULL AND target_user_id IS NOT NULL)),
CHECK(expires_at_ms>created_at_ms)
);

CREATE INDEX ix_invitations_inviter ON invitations(inviter_user_id,created_at_ms);
CREATE INDEX ix_invitations_email ON invitations(target_email);
CREATE INDEX ix_invitations_app ON invitations(app_id);

CREATE TABLE invitation_roles (
invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
role_id TEXT NOT NULL,
scope_id TEXT NOT NULL,
PRIMARY KEY(invitation_id,role_id)
);

CREATE TABLE invitation_acceptances (
invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
accepted_at_ms INTEGER NOT NULL,
request_id TEXT,
PRIMARY KEY(invitation_id,user_id)
);

CREATE TABLE registration_reviews (
user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
status TEXT NOT NULL CHECK(status IN('pending','approved','rejected')),
reason TEXT,
decided_by_type TEXT CHECK(decided_by_type IN('user','system','local_admin')),
decided_by_id TEXT,
decided_at_ms INTEGER,
created_at_ms INTEGER NOT NULL,
updated_at_ms INTEGER NOT NULL,
request_id TEXT,
notify_state TEXT NOT NULL DEFAULT 'pending' CHECK(notify_state IN('pending','sent','failed')),
notify_error_code TEXT,
notified_at_ms INTEGER,
CHECK((status='pending' AND decided_at_ms IS NULL)
   OR (status IN('approved','rejected') AND decided_at_ms IS NOT NULL))
);

CREATE INDEX ix_registration_reviews_status ON registration_reviews(status,created_at_ms);
