-- 0036 已登录 APP 扫码确认网页登录（自定义登录流程，步骤 58）。
--
-- 设计边界（与 0035 标准设备码授权**分别命名、分别存储**，不共享表/接口）：
--   - 网页发起端创建一次短时登录请求；二维码只承载一次性请求标识 id（qrl_ + 128bit），
--     不承载任何长期 Token/密码/会话秘密。领取绑定是独立高熵 secret，库中只保存
--     keyring HMAC-SHA256 摘要 + key_id（支持密钥轮换），明文只在创建响应出现一次。
--   - 状态机 pending/approved/denied/cancelled/claimed；过期由服务层按 expires_at_ms
--     惰性判断（不写 expired 状态，与既有流程一致）。条件更新保证批准/取消/领取
--     并发单赢家；claimed 只允许从 approved 迁移一次。
--   - 批准绑定真实用户、确认端会话 ID、账户安全版本与认证方法快照；领取前服务层
--     重新核对用户/应用/成员/客户端/确认端会话与请求状态，任一变化都拒绝签发会话。
--   - 不保存二维码内容、领取秘密明文、会话秘密、Token 或客户端密钥。
--   - last_polled_at_ms/interval_seconds 由服务端强制最小查询间隔，防止刷库与猜测。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE app_qr_login_requests (
  id TEXT PRIMARY KEY NOT NULL,
  claim_digest BLOB NOT NULL UNIQUE CHECK(length(claim_digest)=32),
  claim_key_id TEXT NOT NULL CHECK(length(claim_key_id) BETWEEN 1 AND 64),
  client_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json)),
  request_version INTEGER NOT NULL DEFAULT 1 CHECK(request_version>=1),
  status TEXT NOT NULL CHECK(status IN('pending','approved','denied','cancelled','claimed')),
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT,
  security_version INTEGER CHECK(security_version IS NULL OR security_version>0),
  auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json)),
  requester_user_agent TEXT NOT NULL DEFAULT '',
  requester_address TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 1 AND 60),
  last_polled_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
  decided_at_ms INTEGER,
  cancelled_at_ms INTEGER,
  claimed_at_ms INTEGER,
  claimed_session_id TEXT,
  CHECK(
    (status='pending' AND user_id IS NULL AND session_id IS NULL
       AND security_version IS NULL AND decided_at_ms IS NULL
       AND cancelled_at_ms IS NULL AND claimed_at_ms IS NULL)
    OR (status='approved' AND user_id IS NOT NULL AND session_id IS NOT NULL
       AND security_version IS NOT NULL AND decided_at_ms IS NOT NULL
       AND cancelled_at_ms IS NULL AND claimed_at_ms IS NULL)
    OR (status='denied' AND user_id IS NOT NULL AND decided_at_ms IS NOT NULL
       AND session_id IS NULL AND security_version IS NULL
       AND cancelled_at_ms IS NULL AND claimed_at_ms IS NULL)
    OR (status='cancelled' AND user_id IS NULL AND session_id IS NULL
       AND security_version IS NULL AND decided_at_ms IS NULL
       AND cancelled_at_ms IS NOT NULL AND claimed_at_ms IS NULL)
    OR (status='claimed' AND user_id IS NOT NULL AND session_id IS NOT NULL
       AND security_version IS NOT NULL AND decided_at_ms IS NOT NULL
       AND cancelled_at_ms IS NULL AND claimed_at_ms IS NOT NULL)
  ),
  CHECK(last_polled_at_ms IS NULL OR last_polled_at_ms>=created_at_ms)
);

CREATE INDEX ix_app_qr_login_requests_client
  ON app_qr_login_requests(client_id, status, expires_at_ms);

CREATE INDEX ix_app_qr_login_requests_expiry
  ON app_qr_login_requests(expires_at_ms, status);
