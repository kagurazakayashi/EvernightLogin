-- 0029 OAuth 客户端安全设置与凭证。
--
-- 对应步骤 49 的应用作为 OAuth 客户端所需登记契约与身份验证：
--   - oauth_clients 保存与 applications 一对一的安全设置（client_id = 应用 ID）：
--     客户端类型、授权类型、精确回调/退出回调、scope、允许的目标资源（audience）、
--     令牌端点客户端身份验证方式与是否强制 PKCE。应用显示资料仍在 applications，
--     本表不复制名称/描述等展示字段。
--   - oauth_client_secrets 保存客户端密钥的**验证值**：明文只在登记/轮换时返回一次，
--     库中只保存前缀（用于列表展示/识别）与 32 字节摘要；支持到期、撤销与轮换过渡
--     （retire_at_ms 之后旧密钥不再可用）。
--   - oauth_client_certificates 保存保密客户端 TLS 客户端证书身份的公钥证书与
--     SHA-256 指纹；支持到期与撤销，不保存任何私钥。
--   - 两张凭证表都不保存明文秘密、私钥或可反推密钥的材料。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  client_type TEXT NOT NULL CHECK(client_type IN('public','confidential')),
  grant_types_json TEXT NOT NULL CHECK(json_valid(grant_types_json)),
  redirect_uris_json TEXT NOT NULL CHECK(json_valid(redirect_uris_json)),
  post_logout_redirect_uris_json TEXT NOT NULL CHECK(json_valid(post_logout_redirect_uris_json)),
  scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json)),
  audiences_json TEXT NOT NULL CHECK(json_valid(audiences_json)),
  auth_methods_json TEXT NOT NULL CHECK(json_valid(auth_methods_json)),
  require_pkce INTEGER NOT NULL CHECK(require_pkce IN(0,1)),
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version >= 1),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(updated_at_ms >= created_at_ms)
);

CREATE TABLE oauth_client_secrets (
  id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  secret_prefix TEXT NOT NULL CHECK(length(secret_prefix) BETWEEN 4 AND 16),
  secret_digest BLOB NOT NULL CHECK(length(secret_digest) = 32),
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  retire_at_ms INTEGER,
  revoked_at_ms INTEGER,
  CHECK(expires_at_ms > created_at_ms),
  CHECK(retire_at_ms IS NULL OR retire_at_ms >= created_at_ms),
  CHECK(revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms)
);

CREATE INDEX ix_oauth_client_secrets_client
  ON oauth_client_secrets(client_id, revoked_at_ms, retire_at_ms);

CREATE TABLE oauth_client_certificates (
  id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  fingerprint_sha256 BLOB NOT NULL CHECK(length(fingerprint_sha256) = 32),
  subject TEXT NOT NULL DEFAULT '',
  not_before_ms INTEGER NOT NULL,
  not_after_ms INTEGER NOT NULL,
  certificate_pem TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  revoked_at_ms INTEGER,
  CHECK(not_after_ms > not_before_ms),
  CHECK(revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms),
  UNIQUE(client_id, fingerprint_sha256)
);

CREATE INDEX ix_oauth_client_certificates_client
  ON oauth_client_certificates(client_id, revoked_at_ms);
