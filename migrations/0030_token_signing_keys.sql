-- +migrate whole-file
-- 0030 OAuth/OIDC 令牌签名密钥。
--
-- 对应步骤 50 的令牌签发/验证、签名密钥轮换与 JWKS 公钥发布：
--   - 私钥以 PKCS#8 编码后经 internal/secrets.Sealer 认证加密保存（sealed_private
--     BLOB），本表不保存任何私钥明文；public_jwk 是可公开的 JWK JSON（不含私有
--     字段），供 JWKS 发布与令牌验证使用。
--   - 状态：next（已生成、公钥可预发布、未用于签名）→ active（当前唯一签名密钥）
--     → retired（已退役，保留期内旧令牌仍可验证并继续发布公钥）→；revoked 为紧急
--     撤销，撤销后该密钥签发的令牌立即验证失败且公钥不再发布。
--   - 部分唯一索引保证同一时刻最多一个 active、一个 next；退役保留期 retire_after_ms
--     必须覆盖已签令牌最长有效期（服务层校验）。迁移一旦执行不得修改；新增结构
--     只能追加新版本迁移文件。
CREATE TABLE token_signing_keys (
  kid TEXT PRIMARY KEY NOT NULL,
  algorithm TEXT NOT NULL CHECK(algorithm='ES256'),
  status TEXT NOT NULL CHECK(status IN('next','active','retired','revoked')),
  public_jwk BLOB NOT NULL CHECK(length(public_jwk) BETWEEN 1 AND 8192),
  sealed_private BLOB NOT NULL CHECK(length(sealed_private) BETWEEN 1 AND 8192),
  created_at_ms INTEGER NOT NULL,
  activated_at_ms INTEGER,
  retired_at_ms INTEGER,
  retire_after_ms INTEGER,
  revoked_at_ms INTEGER,
  revoked_reason TEXT,
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1),
  CHECK(status='next' OR activated_at_ms IS NOT NULL),
  CHECK(status<>'retired' OR (retired_at_ms IS NOT NULL AND retire_after_ms IS NOT NULL)),
  CHECK(status<>'revoked' OR revoked_at_ms IS NOT NULL)
);

CREATE UNIQUE INDEX ux_token_signing_keys_active
  ON token_signing_keys(status) WHERE status='active';
CREATE UNIQUE INDEX ux_token_signing_keys_next
  ON token_signing_keys(status) WHERE status='next';
CREATE INDEX ix_token_signing_keys_status
  ON token_signing_keys(status, retire_after_ms);
