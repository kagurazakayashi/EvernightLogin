-- 0032 OIDC 认证事实与授权快照扩展。
--
-- 对应步骤 52 的 OIDC ID Token/UserInfo/Discovery：
--   - sessions.auth_methods_json 记录登录时真实完成的认证方法（来自 authn 认证
--     结果，只存稳定方法标识，不含秘密/凭证）。ID Token 的 amr/acr 与 auth_time
--     必须来自这些真实事实，不能由客户端或调用方自述。
--   - oauth_authorization_requests / oauth_authorization_codes 增加 auth_time_ms 与
--     auth_methods_json：授权确认时把当时会话的真实认证时间与方法快照写入授权码，
--     兑换时用于签发 ID Token，避免用兑换时的新会话冒充原认证强度。
--   - 默认值保证升级兼容：既有行 auth_methods_json='[]'、auth_time_ms=0，表示
--     “无可用认证事实”，OIDC 签发按 fail-closed 处理（不得伪造 amr/acr）。
--
-- 迁移一旦执行不得修改；新增结构只能追加新版本迁移文件。

ALTER TABLE sessions
  ADD COLUMN auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json));

ALTER TABLE oauth_authorization_requests
  ADD COLUMN auth_time_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_authorization_requests
  ADD COLUMN auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json));

ALTER TABLE oauth_authorization_codes
  ADD COLUMN auth_time_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_authorization_codes
  ADD COLUMN auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json));
