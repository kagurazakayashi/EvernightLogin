-- 0037 应用安全事件 Webhook 与投递（步骤 59）。
--
-- 设计边界：
--   - webhook_endpoints：应用级签名 Webhook 登记。URL 只保存受控校验过的地址文本；
--     每次投递前都会重新做 DNS/地址分类/重定向策略校验（SSRF 防护），不信任登记
--     时的解析结果。每个应用同一 URL 只能登记一次；停用代替删除以保留投递历史。
--   - webhook_endpoint_secrets：签名密钥只保存 Sealer 认证加密密文（purpose
--     webhook.signing，object=密钥 ID，scope system）与前缀；明文只在创建/轮换响应
--     出现一次。支持 active + retiring 两个可用密钥（轮换过渡期），retire/revoked
--     之后不再参与签名。
--   - webhook_events：事件以幂等键去重（同一逻辑事件重复 Emit 返回既有记录）；
--     payload 是严格白名单的最小 JSON（不含令牌/密码/会话秘密/自由文本），application_id
--     为空表示用户级事件，按“用户仍为 active 成员的应用”扇出。
--   - webhook_deliveries：每个 (事件, endpoint) 唯一一条投递记录，状态
--     queued/sending/succeeded/failed/cancelled；重试由 internal/task 承载（有界退避与
--     尝试上限），失败终态与失败原因可查询。至少一次送达，不承诺网络恰好一次。
--   - 不保存签名密钥明文、令牌、密码或会话秘密。迁移一旦执行不得修改；新增结构只能
--     追加新版本迁移文件。

CREATE TABLE webhook_endpoints (
  id TEXT PRIMARY KEY NOT NULL,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  url TEXT NOT NULL CHECK(length(url) BETWEEN 8 AND 2048),
  description TEXT NOT NULL DEFAULT '' CHECK(length(description)<=256),
  status TEXT NOT NULL CHECK(status IN('active','disabled')),
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(updated_at_ms>=created_at_ms),
  UNIQUE(application_id, url)
);

CREATE INDEX ix_webhook_endpoints_app ON webhook_endpoints(application_id, status);

CREATE TABLE webhook_endpoint_secrets (
  id TEXT PRIMARY KEY NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  secret_prefix TEXT NOT NULL CHECK(length(secret_prefix) BETWEEN 4 AND 16),
  sealed_secret BLOB NOT NULL CHECK(length(sealed_secret) BETWEEN 40 AND 4096),
  sealer_key_id TEXT NOT NULL CHECK(length(sealer_key_id) BETWEEN 1 AND 64),
  created_at_ms INTEGER NOT NULL,
  retire_at_ms INTEGER,
  revoked_at_ms INTEGER,
  CHECK(retire_at_ms IS NULL OR retire_at_ms>=created_at_ms),
  CHECK(revoked_at_ms IS NULL OR revoked_at_ms>=created_at_ms)
);

CREATE INDEX ix_webhook_endpoint_secrets_endpoint
  ON webhook_endpoint_secrets(endpoint_id, revoked_at_ms, retire_at_ms);

CREATE TABLE webhook_events (
  id TEXT PRIMARY KEY NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  type TEXT NOT NULL CHECK(length(type) BETWEEN 3 AND 64),
  application_id TEXT NOT NULL DEFAULT '',
  subject_user_id TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND length(payload_json)<=16384),
  truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN(0,1)),
  request_id TEXT NOT NULL DEFAULT '',
  occurred_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX ix_webhook_events_created ON webhook_events(created_at_ms);

CREATE TABLE webhook_deliveries (
  id TEXT PRIMARY KEY NOT NULL,
  event_id TEXT NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  application_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN('queued','sending','succeeded','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
  max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 10),
  task_id TEXT NOT NULL DEFAULT '',
  last_error_code TEXT NOT NULL DEFAULT '',
  last_error_kind TEXT NOT NULL DEFAULT '',
  last_response_status INTEGER NOT NULL DEFAULT 0,
  request_id TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER,
  UNIQUE(event_id, endpoint_id),
  CHECK(updated_at_ms>=created_at_ms)
);

CREATE INDEX ix_webhook_deliveries_endpoint
  ON webhook_deliveries(endpoint_id, state, created_at_ms);

CREATE INDEX ix_webhook_deliveries_state
  ON webhook_deliveries(state, updated_at_ms);
