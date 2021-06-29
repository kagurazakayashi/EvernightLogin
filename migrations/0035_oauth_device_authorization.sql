-- 0035 OAuth 设备授权（Device Authorization Grant，步骤 57）。
--
-- 设计边界：
--   - 一次设备授权申请（电视/无浏览器 CLI 发起）对应一行记录，绑定登记客户端、
--     规范化 scope、目标 audience、短时有效期与轮询间隔。
--   - 高熵 device_code 只保存无密钥 SHA-256 摘要（256 bit 高熵，字典/离线枚举不可行）；
--     可人工输入的 user_code 是 8 字符 base20（20^8 ≈ 34.6 bit）低熵短码，按 AGENTS §10
--     「低熵验证码不可仅用无密钥摘要存库」保存为**带密钥 HMAC-SHA256 摘要**
--     （user_code_digest + user_code_key_id，key_id 支持密钥环轮换后的历史查找）。
--     两类明文都只在申请响应出现一次，不进入数据库、日志、审计或错误信息。
--   - 状态机 pending/approved/denied/cancelled/consumed：用户批准绑定
--     user_id+session_id+security_version 快照；设备取消不需要用户；过期由服务层
--     按 expires_at_ms 惰性判断（不存"expired"状态）。条件更新保证批准/取消/领取
--     的并发单赢家，approved→consumed 只能成功一次。
--   - interval_seconds/last_polled_at_ms 服务端强制轮询间隔；过快的轮询返回标准
--     slow_down 并按上限增大间隔（写入本表，不依赖客户端自述）。
--   - 不保存设备码/短码明文、会话秘密、令牌明文或客户端 secret。
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE oauth_device_authorizations (
  id TEXT PRIMARY KEY NOT NULL,
  device_code_sha256 BLOB NOT NULL UNIQUE CHECK(length(device_code_sha256)=32),
  user_code_digest BLOB NOT NULL UNIQUE CHECK(length(user_code_digest)=32),
  user_code_key_id TEXT NOT NULL CHECK(length(user_code_key_id) BETWEEN 1 AND 64),
  client_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scope TEXT NOT NULL DEFAULT '',
  audience_json TEXT NOT NULL CHECK(json_valid(audience_json)),
  status TEXT NOT NULL CHECK(status IN('pending','approved','denied','cancelled','consumed')),
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT,
  security_version INTEGER CHECK(security_version IS NULL OR security_version>0),
  interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 1 AND 300),
  last_polled_at_ms INTEGER,
  request_id TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  decided_at_ms INTEGER,
  cancelled_at_ms INTEGER,
  consumed_at_ms INTEGER,
  CHECK(expires_at_ms>created_at_ms),
  CHECK(last_polled_at_ms IS NULL OR last_polled_at_ms>=created_at_ms),
  CHECK(
    (status='pending' AND user_id IS NULL AND session_id IS NULL
       AND security_version IS NULL AND decided_at_ms IS NULL
       AND cancelled_at_ms IS NULL AND consumed_at_ms IS NULL)
    OR (status='approved' AND user_id IS NOT NULL AND session_id IS NOT NULL
       AND security_version IS NOT NULL AND decided_at_ms IS NOT NULL
       AND cancelled_at_ms IS NULL AND consumed_at_ms IS NULL)
    OR (status='denied' AND user_id IS NOT NULL AND decided_at_ms IS NOT NULL
       AND cancelled_at_ms IS NULL AND consumed_at_ms IS NULL)
    OR (status='cancelled' AND user_id IS NULL AND session_id IS NULL
       AND security_version IS NULL AND decided_at_ms IS NULL
       AND cancelled_at_ms IS NOT NULL AND consumed_at_ms IS NULL)
    OR (status='consumed' AND user_id IS NOT NULL AND session_id IS NOT NULL
       AND security_version IS NOT NULL AND decided_at_ms IS NOT NULL
       AND consumed_at_ms IS NOT NULL)
  )
);

CREATE INDEX ix_oauth_device_authorizations_client
  ON oauth_device_authorizations(client_id, status, expires_at_ms);

CREATE INDEX ix_oauth_device_authorizations_expiry
  ON oauth_device_authorizations(expires_at_ms, status);
