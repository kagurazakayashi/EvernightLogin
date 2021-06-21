-- 0031 OAuth 授权码、PKCE 与授权确认（步骤 51）。
--
-- 两张表：
--   oauth_authorization_requests：一次授权请求与用户确认状态。绑定真实用户会话
--     （session_id + security_version 快照）、客户端、精确回调、response_type=code、
--     规范化 scope、目标 audience、state、OIDC nonce（供步骤 52 使用）、PKCE
--     challenge（只允许 S256）与客户端请求编号。pending 只能条件迁移一次为
--     approved/denied；过期由服务层按 expires_at_ms 惰性判断，不落库未消费明文。
--   oauth_authorization_codes：授权码只保存 SHA-256 摘要（code_sha256），不保存
--     可兑换的明文；绑定用户、客户端、回调、scope/audience、PKCE challenge、会话
--     快照与签发请求；consumed_at_ms 条件更新保证一次性兑换与并发单赢家，
--     replayed_at_ms 记录重复兑换探测（供后续令牌撤销/刷新家族步骤使用）。
--
-- 安全边界：
--   - 不保存授权码/令牌明文、PKCE verifier、会话秘密或客户端 secret；state 是
--     不透明回传值，不用于授权判断。
--   - client_id 与应用一对一（oauth_clients.client_id 已引用 applications.id），
--     这里直接外键 applications(id) 保证授权绑定真实应用身份。
--   - audience_json 使用 json_valid；scope 为规范排序后空格连接的字符串。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

CREATE TABLE oauth_authorization_requests (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 8 AND 2048),
  response_type TEXT NOT NULL CHECK(response_type='code'),
  scope TEXT NOT NULL DEFAULT '',
  audience_json TEXT NOT NULL CHECK(json_valid(audience_json)),
  state TEXT NOT NULL DEFAULT '' CHECK(length(state)<=1024),
  nonce TEXT NOT NULL DEFAULT '' CHECK(length(nonce)<=512),
  code_challenge TEXT NOT NULL DEFAULT '' CHECK(length(code_challenge)<=128),
  code_challenge_method TEXT NOT NULL DEFAULT ''
    CHECK(code_challenge_method IN('','S256')),
  session_id TEXT NOT NULL CHECK(length(session_id)=36),
  security_version INTEGER NOT NULL CHECK(security_version>0),
  status TEXT NOT NULL CHECK(status IN('pending','approved','denied')),
  request_id TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  decided_at_ms INTEGER,
  CHECK(expires_at_ms>created_at_ms),
  CHECK((status='pending' AND decided_at_ms IS NULL)
     OR (status<>'pending' AND decided_at_ms IS NOT NULL)),
  CHECK((code_challenge='' AND code_challenge_method='')
     OR (code_challenge<>'' AND code_challenge_method='S256'))
);

CREATE INDEX ix_oauth_authorization_requests_user_status
  ON oauth_authorization_requests(user_id, status, expires_at_ms);

CREATE INDEX ix_oauth_authorization_requests_client
  ON oauth_authorization_requests(client_id, created_at_ms);

CREATE TABLE oauth_authorization_codes (
  id TEXT PRIMARY KEY NOT NULL,
  code_sha256 BLOB NOT NULL UNIQUE CHECK(length(code_sha256)=32),
  authorization_request_id TEXT NOT NULL
    REFERENCES oauth_authorization_requests(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 8 AND 2048),
  scope TEXT NOT NULL DEFAULT '',
  audience_json TEXT NOT NULL CHECK(json_valid(audience_json)),
  nonce TEXT NOT NULL DEFAULT '' CHECK(length(nonce)<=512),
  code_challenge TEXT NOT NULL CHECK(length(code_challenge) BETWEEN 43 AND 128),
  code_challenge_method TEXT NOT NULL CHECK(code_challenge_method='S256'),
  session_id TEXT NOT NULL CHECK(length(session_id)=36),
  security_version INTEGER NOT NULL CHECK(security_version>0),
  request_id TEXT NOT NULL DEFAULT '',
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  replayed_at_ms INTEGER,
  CHECK(expires_at_ms>issued_at_ms),
  CHECK(expires_at_ms-issued_at_ms<=600000),
  CHECK(consumed_at_ms IS NULL OR consumed_at_ms>=issued_at_ms),
  CHECK(replayed_at_ms IS NULL OR replayed_at_ms>=issued_at_ms)
);

CREATE INDEX ix_oauth_authorization_codes_client
  ON oauth_authorization_codes(client_id, expires_at_ms);

CREATE INDEX ix_oauth_authorization_codes_expiry
  ON oauth_authorization_codes(expires_at_ms, consumed_at_ms);
