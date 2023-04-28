-- 0045 业务托管管理 API 幂等记录（步骤 147）。
--
-- 设计边界：
--   - 幂等键作用域固定为 (application_id, principal_kind, principal_id, key)，不能
--     跨应用/跨主体复用；principal_id 是已认证用户/应用稳定 ID，不存会话秘密。
--   - 只保存方法+路径+严格 JSON 请求的 SHA-256 与已完成响应状态/正文；不保存认证头、
--     Cookie、证书、请求明文或任何秘密。
--   - 完成的响应可供同 key/同请求摘要重放；请求摘要不同返回冲突，不覆盖旧记录。
--   - 记录有过期时间，由请求路径与维护任务有界清理；进程崩溃可能留下 in_progress，
--     调用方按冲突处理，不能把“未完成”当成成功。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE managed_api_idempotency (
  application_id TEXT NOT NULL CHECK(length(application_id) BETWEEN 4 AND 128),
  principal_kind TEXT NOT NULL CHECK(principal_kind IN('user','service')),
  principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
  operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 64),
  status TEXT NOT NULL CHECK(status IN('in_progress','completed')),
  response_status INTEGER NOT NULL DEFAULT 0
    CHECK(response_status = 0 OR response_status BETWEEN 100 AND 599),
  response_body TEXT NOT NULL DEFAULT '' CHECK(length(response_body) <= 1048576),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= created_at_ms),
  PRIMARY KEY(application_id, principal_kind, principal_id, idempotency_key)
);

CREATE INDEX ix_managed_api_idempotency_expiry
  ON managed_api_idempotency(expires_at_ms);
