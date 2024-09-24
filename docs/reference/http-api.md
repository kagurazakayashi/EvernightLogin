# HTTP 契约参考（管理 API / 协议路径 / 页面命名路由 / 页面表单 OpenAPI）

> 路由清单由 AST 扫描实际注册生成（`handler.go` 的 `add(...)`、领域 `DomainRoute{Method, Pattern}`、协议路径常量与 `UIRoute` 页面命名路由），不是手写端点表。鉴权/CSRF/开关与托管边界见 [../deployment/managed-api.md](../deployment/managed-api.md)、[../deployment/app-support-api.md](../deployment/app-support-api.md) 与 [../deployment/standalone-service.md](../deployment/standalone-service.md)。

## 1. 基础约定

- 所有路径带 `server.path_prefix`（默认空）；管理 API 默认前缀 `/admin/v1`，托管 API `/api/managed/v1`，应用客服 API `/api/app/v1/support`。
- **默认关闭**：OAuth/OIDC 协议端点、管理 JSON API、托管 API、应用客服 API 都需显式启用；未启用时对应路径 404，维护模式一律 503。
- 错误响应使用与 Go 门面一致的错误码 + `request_id`；**错误信封与重试语义见 [errors.md](errors.md)**，排障流程见 [../guide/troubleshooting.md](../guide/troubleshooting.md)。
- 管理 API 复用真实管理会话并校验 CSRF（Cookie 会话写请求要求 CSRF 令牌）；页面路由与 API 路由不共享鉴权旁路。
- 请求身份必须来自可信边界（Cookie/Authorization/宿主服务端存储）；请求参数不能自称管理员、root、应用或用户。
- `Host`、可信代理、TLS/mTLS 与公开基址使用同一套配置规则（`server.public_base_url`、`server.trusted_proxies`、`server.tls_terminating_proxy`）。

## 2. 管理 JSON API 路由（137 条，相对管理前缀）

| 方法 | 路径模式 | 关联能力 | 定义位置 |
|---|---|---|---|
| DELETE | `backups/schedules/{schedule_id}` | backup.restore | `internal/adminapi/handler.go` |
| DELETE | `groups/{group_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| DELETE | `report-plans/{plan_id}` | reports.generate | `internal/adminapi/handler.go` |
| DELETE | `roles/{role_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| GET | `applications` | applications.manage | `internal/serverapp/admin_domain_routes.go` |
| GET | `applications/{application_id}` | applications.manage | `internal/serverapp/admin_domain_routes.go` |
| GET | `applications/{application_id}/groups` | applications.manage | `internal/serverapp/admin_domain_routes.go` |
| GET | `applications/{application_id}/managed-policy` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| GET | `applications/{application_id}/members` | applications.manage | `internal/serverapp/admin_domain_routes.go` |
| GET | `applications/{application_id}/roles` | applications.manage | `internal/serverapp/admin_domain_routes.go` |
| GET | `audit/events` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/events/{event_id}` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/exports` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/exports/{export_id}` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/exports/{export_id}/download` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/purge-runs` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/purge-runs/{run_id}` | audit.events | `internal/adminapi/handler.go` |
| GET | `audit/retention` | audit.events | `internal/adminapi/handler.go` |
| GET | `backups` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/capabilities` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/cleanup-preview` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/jobs` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/jobs/{job_id}` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/retention` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/schedules` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/schedules/{schedule_id}` | backup.restore | `internal/adminapi/handler.go` |
| GET | `backups/{backup_id}` | backup.restore | `internal/adminapi/handler.go` |
| GET | `deliveries` | mail.delivery_console | `internal/adminapi/handler.go` |
| GET | `diagnostics` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `diagnostics/errors` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `diagnostics/export` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `error-codes` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `groups` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `groups/{group_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `groups/{group_id}/members` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `meta` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `notifications` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `notifications/history` | notifications.security_history | `internal/adminapi/handler.go` |
| GET | `permissions` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `report-plans` | reports.generate | `internal/adminapi/handler.go` |
| GET | `report-plans/{plan_id}` | reports.generate | `internal/adminapi/handler.go` |
| GET | `report-plans/{plan_id}/delete-preview` | reports.generate | `internal/adminapi/handler.go` |
| GET | `reports` | reports.generate | `internal/adminapi/handler.go` |
| GET | `reports/cleanup-preview` | reports.generate | `internal/adminapi/handler.go` |
| GET | `reports/{report_id}` | reports.generate | `internal/adminapi/handler.go` |
| GET | `reports/{report_id}/snapshot` | reports.generate | `internal/adminapi/handler.go` |
| GET | `roles` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `roles/{role_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `roles/{role_id}/assignments` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `sessions` | session.admin | `internal/adminapi/handler.go` |
| GET | `settings` | settings.managed | `internal/serverapp/settings.go` |
| GET | `settings/status` | settings.managed | `internal/serverapp/settings.go` |
| GET | `support/cases` | support.recovery | `internal/serverapp/admin_domain_routes.go` |
| GET | `support/cases/{case_id}` | support.recovery | `internal/serverapp/admin_domain_routes.go` |
| GET | `support/recovery/requests` | support.recovery | `internal/serverapp/admin_domain_routes.go` |
| GET | `support/recovery/requests/{request_id}` | support.recovery | `internal/serverapp/admin_domain_routes.go` |
| GET | `tasks` | admin.observability_lists | `internal/adminapi/handler.go` |
| GET | `tasks/{task_id}` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `users` | account.users | `internal/serverapp/admin_domain_routes.go` |
| GET | `users/{user_id}` | account.users | `internal/serverapp/admin_domain_routes.go` |
| GET | `users/{user_id}/validity` | account.users | `internal/serverapp/admin_validity_routes.go` |
| POST | `applications` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/certificates` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/certificates/{certificate_id}/revoke` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/delete` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/members` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/members/state` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/oauth-settings` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/secrets/rotate` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/secrets/{secret_id}/revoke` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| POST | `applications/{application_id}/state` | applications.manage | `internal/serverapp/admin_domain_writes.go` |
| POST | `audit/exports` | audit.events | `internal/adminapi/handler.go` |
| POST | `audit/exports/{export_id}/cancel` | audit.events | `internal/adminapi/handler.go` |
| POST | `audit/purge` | audit.events | `internal/adminapi/handler.go` |
| POST | `audit/purge/preview` | audit.events | `internal/adminapi/handler.go` |
| POST | `audit/purge/{run_id}/cancel` | audit.events | `internal/adminapi/handler.go` |
| POST | `backups` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/cleanup` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/download-tickets/redeem` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/jobs/{job_id}/cancel` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/schedules` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/schedules/{schedule_id}/enabled` | backup.restore | `internal/adminapi/handler.go` |
| POST | `backups/{backup_id}/download-tickets` | backup.restore | `internal/adminapi/handler.go` |
| POST | `groups` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes.go` |
| POST | `groups/{group_id}/members` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| POST | `notifications/test` | adminapi.core | `internal/adminapi/handler.go` |
| POST | `permissions/{permission_id}/state` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| POST | `report-plans` | reports.generate | `internal/adminapi/handler.go` |
| POST | `report-plans/{plan_id}/enabled` | reports.generate | `internal/adminapi/handler.go` |
| POST | `reports/cleanup` | reports.generate | `internal/adminapi/handler.go` |
| POST | `reports/download-tickets/redeem` | reports.generate | `internal/adminapi/handler.go` |
| POST | `reports/{report_id}/cancel` | reports.generate | `internal/adminapi/handler.go` |
| POST | `reports/{report_id}/download-tickets` | reports.generate | `internal/adminapi/handler.go` |
| POST | `reports/{report_id}/retry` | reports.generate | `internal/adminapi/handler.go` |
| POST | `roles` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes.go` |
| POST | `roles/{role_id}/assignments` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes.go` |
| POST | `roles/{role_id}/state` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| POST | `sessions/revoke` | session.admin | `internal/adminapi/handler.go` |
| POST | `settings/sensitive-policy/restore` | settings.managed | `internal/serverapp/settings.go` |
| POST | `settings/validate` | settings.managed | `internal/serverapp/settings.go` |
| POST | `support/cases` | support.recovery | `internal/serverapp/admin_domain_writes.go` |
| POST | `support/cases/{case_id}/reassign` | support.recovery | `internal/serverapp/admin_domain_writes2.go` |
| POST | `support/cases/{case_id}/send-reset` | support.recovery | `internal/serverapp/admin_domain_writes.go` |
| POST | `support/cases/{case_id}/transition` | support.recovery | `internal/serverapp/admin_domain_writes2.go` |
| POST | `support/recovery/requests` | support.recovery | `internal/serverapp/admin_domain_writes.go` |
| POST | `support/recovery/{request_id}/approve` | support.recovery | `internal/serverapp/admin_domain_writes.go` |
| POST | `support/recovery/{request_id}/cancel` | support.recovery | `internal/serverapp/admin_domain_writes2.go` |
| POST | `support/recovery/{request_id}/execute` | support.recovery | `internal/serverapp/admin_domain_writes.go` |
| POST | `support/recovery/{request_id}/reject` | support.recovery | `internal/serverapp/admin_domain_writes2.go` |
| POST | `users` | account.users | `internal/serverapp/admin_domain_writes.go` |
| POST | `users/{user_id}/delete` | account.users | `internal/serverapp/admin_domain_writes2.go` |
| POST | `users/{user_id}/delete-preview` | account.users | `internal/serverapp/admin_domain_writes2.go` |
| POST | `users/{user_id}/password` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/password-verification` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/password-verification/cancel` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/password-verification/confirm` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/password-verification/webauthn/begin` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/password-verification/webauthn/confirm` | account.users | `internal/serverapp/admin_direct_password_routes.go` |
| POST | `users/{user_id}/state` | account.users | `internal/serverapp/admin_domain_writes.go` |
| POST | `users/{user_id}/username` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/username-verification` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/username-verification/cancel` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/username-verification/confirm` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/username-verification/webauthn/begin` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/username-verification/webauthn/confirm` | account.users | `internal/serverapp/admin_direct_username_routes.go` |
| POST | `users/{user_id}/validity` | account.users | `internal/serverapp/admin_validity_routes.go` |
| PUT | `applications/{application_id}` | applications.manage | `internal/serverapp/admin_domain_writes.go` |
| PUT | `applications/{application_id}/managed-policy` | applications.manage | `internal/serverapp/admin_domain_writes2.go` |
| PUT | `audit/retention` | audit.events | `internal/adminapi/handler.go` |
| PUT | `backups/retention` | backup.restore | `internal/adminapi/handler.go` |
| PUT | `backups/schedules/{schedule_id}` | backup.restore | `internal/adminapi/handler.go` |
| PUT | `groups/{group_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| PUT | `permissions/{permission_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| PUT | `report-plans/{plan_id}` | reports.generate | `internal/adminapi/handler.go` |
| PUT | `roles/{role_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| PUT | `roles/{role_id}/permissions` | rbac.roles_permissions | `internal/serverapp/admin_domain_writes2.go` |
| PUT | `settings` | settings.managed | `internal/serverapp/settings.go` |

## 3. OAuth 2.0 / OIDC 协议端点契约（默认关闭；关闭时命名空间 404）

协议端点使用标准协议响应（RFC 6749/6750/7009/7662/8628），**不是**统一业务错误信封；自定义扫码端点例外使用项目信封。授权端点属浏览器重定向流程，其余端点返回 JSON。

### 3.1 协议路径常量（17 个）

| 常量名 | 路径 |
|---|---|
| PathAuthorize | `/oauth/authorize` |
| PathDeviceAuthorization | `/oauth/device_authorization` |
| PathDeviceCancel | `/oauth/device/cancel` |
| PathDiscovery | `/.well-known/openid-configuration` |
| PathIntrospect | `/oauth/introspect` |
| PathJWKS | `/jwks` |
| PathQRCancel | `/oauth/qr/cancel` |
| PathQRClaim | `/oauth/qr/claim` |
| PathQRDecision | `/oauth/qr/decision` |
| PathQRPrompt | `/oauth/qr/prompt` |
| PathQRRegenerate | `/oauth/qr/regenerate` |
| PathQRRequest | `/oauth/qr/request` |
| PathQRStatus | `/oauth/qr/status` |
| PathRevoke | `/oauth/revoke` |
| PathToken | `/oauth/token` |
| PathTokenAuthorize | `/oauth/token/authorize` |
| PathUserInfo | `/oauth/userinfo` |

### 3.2 端点 HTTP 契约（19 个；与 doc.go 端点表双向一致）

| 方法 | 路径 | 注册条件 | 传输 / 成功状态 | 客户端认证 | 会话/浏览器 | 协议错误 | Discovery 声明 |
|---|---|---|---|---|---|---|---|
| GET | `/.well-known/openid-configuration` | protocol.enabled=true（默认 false，关闭时协议命名空间 404） | json-standard / 200 | 无（公开只读） | 无 | 404（协议未启用）、405（非 GET） | 是（文档自身） |
| GET | `/jwks` | protocol.enabled=true | json-standard / 200 | 无（公开只读） | 无 | 404（协议未启用）、405（非 GET） | 是（jwks_uri） |
| GET | `/oauth/authorize` | protocol.enabled=true | browser-redirect / 200/303 | 公开/保密客户端均可（PKCE 必填；不支持 implicit/password） | 真实浏览器会话 Cookie（或 Bearer 会话）；未登录 303 到宿主登录页/受控错误 | invalid_request、unauthorized_client、unsupported_response_type、invalid_scope、server_error、temporarily_unavailable、access_denied | 是（authorization_endpoint） |
| POST | `/oauth/authorize` | protocol.enabled=true | browser-redirect / 303 | 沿用授权请求的客户端登记 | 同一浏览器会话 + 会话绑定 CSRF 令牌 +（携带时）同源 Origin | invalid_request、access_denied、server_error | - |
| POST | `/oauth/device/cancel` | protocol.enabled=true 且 EnableDeviceFlow=true | json-standard / 204 | 必须绑定申请时的同一 client_id；保密客户端还需客户端认证 | 无 | invalid_request、invalid_client、access_denied | 否（本包扩展，不在 OIDC 标准 Discovery 字段中） |
| POST | `/oauth/device_authorization` | protocol.enabled=true 且 EnableDeviceFlow=true（需 DeviceVerificationURI） | json-standard / 200 | 客户端认证（设备为公开客户端时可仅 client_id） | 无 | invalid_request、invalid_client、unsupported_grant_type、temporarily_unavailable | 是（device_authorization_endpoint，仅启用时） |
| POST | `/oauth/introspect` | protocol.enabled=true 且 EnableIntrospection=true（依赖 InspectAuthorizer/InspectClientAuthorizer） | json-standard / 200 | 资源服务器客户端认证（client_secret_basic/post 或已验证 TLS 证书） | 无 | invalid_request、invalid_client、invalid_token、temporarily_unavailable | 是（introspection_endpoint，仅启用时） |
| POST | `/oauth/qr/cancel` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 持有一次性领取绑定的原发起端 | 无 | 项目信封：REQ_INVALID、ACCESS_DENIED、CONFLICT、INTERNAL_ERROR | 否 |
| POST | `/oauth/qr/claim` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 持有正确领取绑定且请求已批准/未过期的原发起端 | 无（领取后写入目标应用会话 Cookie） | 项目信封：REQ_INVALID、ACCESS_DENIED、RESOURCE_FORBIDDEN、CONFLICT、GONE、INTERNAL_ERROR | 否 |
| POST | `/oauth/qr/decision` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 无 | 真实完整会话 + 会话绑定 CSRF（Cookie 会话）；Origin/Referer 至少一个存在并与 issuer 同源 | 项目信封：AUTH_FAILED、REQ_INVALID、ACCESS_DENIED、RESOURCE_FORBIDDEN、REAUTH_REQUIRED、INTERNAL_ERROR | 否 |
| GET | `/oauth/qr/prompt` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 无 | 真实完整会话（Cookie/Bearer） | 项目信封：AUTH_FAILED、REQ_INVALID、ACCESS_DENIED、RESOURCE_FORBIDDEN、INTERNAL_ERROR | 否 |
| POST | `/oauth/qr/regenerate` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 持有一次性领取绑定的原发起端 | 无 | 项目信封：REQ_INVALID、ACCESS_DENIED、RESOURCE_FORBIDDEN、CONFLICT、INTERNAL_ERROR | 否 |
| POST | `/oauth/qr/request` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 仅允许登记/允许的 QRClientID（可请求体声明，服务端复核） | 无（匿名） | 项目信封：REQ_INVALID、ACCESS_DENIED、RATE_LIMITED、INTERNAL_ERROR | 否（项目扩展；Discovery 不声明扫码端点） |
| POST | `/oauth/qr/status` | protocol.enabled=true 且注入 QRLogin 服务 | json-project-envelope / 200 | 持有一次性领取绑定的原发起端（无客户端密钥） | 无 | 项目信封：REQ_INVALID、ACCESS_DENIED、RESOURCE_FORBIDDEN、CONFLICT、INTERNAL_ERROR | 否 |
| POST | `/oauth/revoke` | protocol.enabled=true | json-standard / 200 | 与令牌端点相同的客户端认证 | 无 | invalid_request、invalid_client、unsupported_token_type | 是（revocation_endpoint） |
| POST | `/oauth/token` | protocol.enabled=true | json-standard / 200 | 保密客户端：client_secret_basic / client_secret_post / 已验证 TLS 客户端证书（三选一）；公开客户端 PKCE | 无 | invalid_request、invalid_client、invalid_grant、unauthorized_client、unsupported_grant_type、invalid_scope、authorization_pending、slow_down、access_denied、expired_token、temporarily_unavailable | 是（token_endpoint；grant_types_supported 只列真实支持项） |
| POST | `/oauth/token/authorize` | protocol.enabled=true 且宿主注入 TokenAuthorize 处理器（本包不内置实现） | json-standard / 200 | 由注入处理器与真实服务判定（不得自行信任请求参数） | 由注入处理器判定 | - | 否（宿主扩展，不写入 Discovery） |
| GET | `/oauth/userinfo` | protocol.enabled=true | json-standard / 200 | Access Token 的客户端/audience 校验由令牌与授权服务判定 | 无；只接受 Authorization: Bearer | invalid_request、invalid_token、insufficient_scope | 是（userinfo_endpoint） |
| POST | `/oauth/userinfo` | protocol.enabled=true | json-standard / 200 | 同 GET /oauth/userinfo | 无；只接受 Authorization: Bearer | invalid_request、invalid_token、insufficient_scope | 是（userinfo_endpoint；GET/POST 均支持） |

### 3.3 请求/响应字段与安全说明

| 端点 | 请求字段 | 响应字段（秘密字段标注） | 说明 |
|---|---|---|---|
| GET `/.well-known/openid-configuration` | - | - | 只声明已启用端点与能力；不声明 end_session/PAR/动态注册/CIBA/token exchange 等未实现项。；缓存由宿主中间件决定；本包不设置 CORS。 |
| GET `/jwks` | - | - | 只含公钥与 kid/alg（ES256）；不含私钥材料。 |
| GET `/oauth/authorize` | `response_type`（query，必填）、`client_id`（query，必填）、`redirect_uri`（query，必填）、`scope`（query）、`state`（query）、`code_challenge`（query，必填）、`code_challenge_method`（query，必填）、`login_path`（query） | `state`（body）、`code`（body，秘密）、`error`（body）、`error_description`（body） | 无效 client_id/redirect_uri 不重定向，返回 JSON 错误（不得开放重定向）；其余错误只在已登记回调上用 error 参数 303 重定向。；同意页是内置窄 HTML；GET 只创建待确认请求，绝不自动批准。 |
| POST `/oauth/authorize` | `request_id`（form，必填）、`decision`（form，必填）、`csrf_token`（form，必填，秘密） | - | 批准/拒绝是显式决定；CSRF 与 Origin 两类校验不可互相替代。 |
| POST `/oauth/device/cancel` | `device_code`（form，必填，秘密） | - | 扩展端点只在 Discovery 说明或部署文档中出现，不伪造标准字段。 |
| POST `/oauth/device_authorization` | `client_id`（form）、`scope`（form） | `device_code`（body，秘密）、`user_code`（body，秘密）、`verification_uri`（body）、`expires_in`（body）、`interval`（body） | device_code/短码只在申请响应出现一次；短码只存 keyed HMAC 摘要。；轮询由 /oauth/token 的 device_code grant 完成，服务端强制 interval/slow_down。 |
| POST `/oauth/introspect` | `token`（form，必填，秘密）、`token_type_hint`（form）、`audience`（form）、`resource`（form） | `active`（body）、`scope`（body）、`client_id`（body）、`sub`（body）、`aud`（body）、`exp`（body） | ResourceServerClientID 只来自真实客户端认证结果，不来自请求自报。；未启用时端点不注册（404），Discovery 不声明。 |
| POST `/oauth/qr/cancel` | `request_id`（json，必填）、`claim_secret`（json，必填，秘密） | `status`（body）、`expires_at`（body） |  |
| POST `/oauth/qr/claim` | `request_id`（json，必填）、`claim_secret`（json，必填，秘密） | `status`（body）、`user_id`（body）、`session_id`（body，秘密）、`app_id`（body）、`expires_at`（body） | 领取只能成功一次；跨用户/无绑定 410；正文绝不返回会话秘密或 Token。 |
| POST `/oauth/qr/decision` | `request_id`（json，必填）、`decision`（json，必填）、`csrf_token`（json，必填，秘密） | `status`（body）、`request_id`（body） | 缺少 Origin/Referer 直接 403（纵深防御）；批准页由宿主页面层实现，本端点不提供页面。 |
| GET `/oauth/qr/prompt` | `request_id`（query，必填） | `request_id`（body）、`client_id`（body）、`application_name`（body）、`scopes`（body）、`status`（body）、`warning`（body） | 不存在/无权限统一错误，避免探测他人请求；不返回 claim_secret。 |
| POST `/oauth/qr/regenerate` | `request_id`（json，必填）、`claim_secret`（json，必填，秘密） | `request_id`（body）、`qr_payload`（body）、`claim_secret`（body，秘密）、`expires_at`（body） |  |
| POST `/oauth/qr/request` | `client_id`（json）、`scopes`（json） | `request_id`（body）、`qr_payload`（body）、`claim_secret`（body，秘密）、`expires_at`（body）、`poll_interval_seconds`（body） | 二维码载荷只含 request_id，不含令牌/会话秘密/领取绑定。；claim_secret 只出现一次；共享缓存/日志不得记录响应正文。 |
| POST `/oauth/qr/status` | `request_id`（json，必填）、`claim_secret`（json，必填，秘密） | `request_id`（body）、`status`（body）、`retry_after_seconds`（body）、`expires_at`（body） | 不存在的请求与无绑定请求使用同一受控错误，避免探测他人请求。 |
| POST `/oauth/revoke` | `token`（form，必填，秘密）、`token_type_hint`（form） | - | 撤销是幂等语义；未知 token 不披露存在性（200）。 |
| POST `/oauth/token` | `grant_type`（form，必填）、`code`（form，秘密）、`redirect_uri`（form）、`code_verifier`（form，秘密）、`refresh_token`（form，秘密）、`device_code`（form，秘密）、`scope`（form） | `access_token`（body，秘密）、`token_type`（body）、`expires_in`（body）、`refresh_token`（body，秘密）、`id_token`（body，秘密）、`scope`（body） | 一次请求只能使用一种客户端认证方式；重复参数/未知参数按 invalid_request 拒绝。；响应 no-store；成功=签发事实，审计不可用时返回 temporarily_unavailable。 |
| POST `/oauth/token/authorize` | - | - | 该端点只登记路径常量与条件注册：没有注入处理器时不会挂载（404），不能按“存在路径常量”认为可用。；处理器由宿主装配，契约字段/响应以宿主实现为准；本包不伪造成功。 |
| GET `/oauth/userinfo` | `Authorization`（header，必填，秘密） | `sub`（body）、`name`（body）、`preferred_username`（body）、`email`（body，秘密）、`email_verified`（body） | 查询串/请求体里的令牌被拒绝（避免进 URL/日志）；ID Token 不能冒充 Access Token。；错误响应带 RFC 6750 WWW-Authenticate 挑战。 |
| POST `/oauth/userinfo` | `Authorization`（header，必填，秘密） | `sub`（body） | POST 不把令牌放进请求体；请求体参数被忽略/拒绝。 |

### 3.4 协议例外登记（显式登记，不能整体豁免）

| 例外 | 类别 | 涉及端点 | 理由 |
|---|---|---|---|
| `STD-OAUTH-ERROR` | standard-error-envelope | POST /oauth/token、GET /oauth/userinfo、POST /oauth/userinfo、POST /oauth/revoke、POST /oauth/introspect、POST /oauth/device_authorization、POST /oauth/device/cancel、GET /oauth/authorize | 标准协议端点错误使用 RFC 6749/6750/7009/7662/8628 的 error/error_description（UserInfo 带 WWW-Authenticate），不得改写为项目 {code,message,request_id} 信封 |
| `QR-PROJECT-ENVELOPE` | project-envelope | POST /oauth/qr/request、POST /oauth/qr/status、POST /oauth/qr/claim、POST /oauth/qr/cancel、POST /oauth/qr/regenerate、GET /oauth/qr/prompt、POST /oauth/qr/decision | 自定义扫码端点使用项目统一错误信封 {code,message,request_id}（与业务 API 一致），成功响应为 data |
| `CONDITIONAL-INTROSPECTION` | conditional-registration | POST /oauth/introspect | 只有宿主显式 EnableIntrospection 且注入真实 Authorizer 才注册；未启用时 404，Discovery 不声明 |
| `CONDITIONAL-DEVICE` | conditional-registration | POST /oauth/device_authorization、POST /oauth/device/cancel | 只有 EnableDeviceFlow=true（且配置设备确认页）才注册；未启用时 404，Discovery 不声明 |
| `CONDITIONAL-QR` | conditional-registration | POST /oauth/qr/request、POST /oauth/qr/status、POST /oauth/qr/claim、POST /oauth/qr/cancel、POST /oauth/qr/regenerate、GET /oauth/qr/prompt、POST /oauth/qr/decision | 只有注入 QRLogin 服务才注册；未注入时 404。Discovery 不声明扫码扩展端点 |
| `CONDITIONAL-TOKEN-AUTHORIZE` | conditional-registration | POST /oauth/token/authorize | POST /oauth/token/authorize 只有在宿主注入 TokenAuthorize 处理器时才存在；本包不内置该端点实现，契约索引只登记路径常量 |
| `BROWSER-REDIRECT` | browser-redirect | GET /oauth/authorize、POST /oauth/authorize | 授权端点是浏览器流程：成功/协议错误可能是 303 重定向到已登记回调，而不是 JSON 响应；无效 client_id/redirect_uri 仍是 JSON 错误（防开放重定向） |
| `DISABLED-404` | disabled-404 | - | protocol.enabled=false（默认）时整个协议命名空间不挂载，所有协议路径 404；不要把它当作“端点存在但未授权” |
| `DISCOVERY-LIMIT` | discovery-limit | GET /.well-known/openid-configuration | Discovery 只声明真实启用的能力；end_session/PAR/动态注册/request_uri/CIBA/token exchange 未实现且不声明 |
| `HOST-MIDDLEWARE` | host-middleware | - | TLS/HSTS、请求体总量、限流、访问日志、可信客户端地址与反向代理前缀由宿主负责；协议包只做单请求上限与协议语义 |
| `ROOT-ROUTER-ENVELOPE` | root-router | - | 协议命名空间未匹配路径/panic 恢复返回项目统一 404/500 信封（不是 OAuth 标准错误）；这是路由边界而不是协议端点契约 |
| `HOST-CONFIRM-PAGES` | host-middleware | - | 设备码/扫码“用户确认页”由宿主页面层实现，本包只提供协议端点；确认页接线未验收，不得宣传为已交付 |

## 4. 内置页面命名路由（250 个冻结命名路由）

页面路由是 `ui.v1` 命名契约：名字/路径/访问级别稳定，DOM 与模板不承诺稳定；宿主可用 `PageOverrides` 替换展示，但不改变服务端认证/授权/CSRF。214 起页面实现位于公开包 `ui/`，根包保留 `UIRoute`/`BuiltinUIRoutes` 等兼容别名；下表“定义位置”即实际定义文件。表中包含仅在 `EnableComponentPreview` 时注册的组件预览路由（默认不注册），不要把它们当作默认页面。

| 命名路由 | 方法 | 路径 | 访问级别 | 关联能力 | 定义位置 |
|---|---|---|---|---|---|
| `account.activity` | GET | `/account/activity` | UIAccessUser | ui.public_pages | `ui/pages_audit.go` |
| `account.activity_detail` | GET | `/account/activity/detail` | UIAccessUser | ui.public_pages | `ui/pages_audit.go` |
| `account.app_profile` | GET | `/account/app-profile` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.app_profile.submit` | POST | `/account/app-profile` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.email_change_verify` | GET | `/email/change/verify` | UIAccessPublic | ui.public_pages | `ui/pages_account.go` |
| `account.email_change_verify.submit` | POST | `/email/change/verify` | UIAccessPublic | ui.public_pages | `ui/pages_account.go` |
| `account.grants` | GET | `/account/grants` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.grants.revoke` | POST | `/account/grants/revoke` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.password` | GET | `/account/password` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.password.submit` | POST | `/account/password` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile` | GET | `/account/profile` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile.update` | POST | `/account/profile` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_avatar` | GET | `/account/profile/avatar` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_avatar.remove` | POST | `/account/profile/avatar/remove` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_avatar.submit` | POST | `/account/profile/avatar` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_avatar_image` | GET | `/account/profile/avatar/image` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_email` | GET | `/account/profile/email` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_email.cancel` | POST | `/account/profile/email/cancel` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_email.submit` | POST | `/account/profile/email` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_username` | GET | `/account/profile/username` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.profile_username.submit` | POST | `/account/profile/username` | UIAccessUser | ui.public_pages | `ui/pages_account.go` |
| `account.security` | GET | `/account/security` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_mfa` | GET | `/account/security/mfa` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_mfa.add_confirm` | POST | `/account/security/mfa/confirm` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_mfa.add_start` | POST | `/account/security/mfa` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_mfa.remove` | POST | `/account/security/mfa/remove` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_passkeys` | GET | `/account/security/passkeys` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_passkeys.register_finish` | POST | `/account/security/passkeys/register/finish` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_passkeys.register_start` | POST | `/account/security/passkeys/register` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_passkeys.rename` | POST | `/account/security/passkeys/rename` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_passkeys.revoke` | POST | `/account/security/passkeys/revoke` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_recovery_codes` | GET | `/account/security/recovery-codes` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_recovery_codes.generate` | POST | `/account/security/recovery-codes` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_totp` | GET | `/account/security/totp` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_totp.bind_confirm` | POST | `/account/security/totp/confirm` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_totp.bind_start` | POST | `/account/security/totp/bind` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.security_totp.remove` | POST | `/account/security/totp/remove` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.sessions` | GET | `/account/sessions` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.sessions.revoke` | POST | `/account/sessions/revoke` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.sessions.revoke_all` | POST | `/account/sessions/revoke-all` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `account.sessions.revoke_others` | POST | `/account/sessions/revoke-others` | UIAccessUser | ui.public_pages | `ui/pages_security.go` |
| `admin.access_effective` | GET | `/admin/access/effective` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.application_create` | GET | `/admin/applications/create` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_create.submit` | POST | `/admin/applications/create` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_credentials` | GET | `/admin/applications/credentials` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_credentials.submit` | POST | `/admin/applications/credentials` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_delete` | POST | `/admin/applications/status/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_grants` | GET | `/admin/applications/grants` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_grants.submit` | POST | `/admin/applications/grants` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_members` | GET | `/admin/applications/members` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_members.submit` | POST | `/admin/applications/members` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_profile` | GET | `/admin/applications/profile` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_profile.submit` | POST | `/admin/applications/profile` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_security` | GET | `/admin/applications/security` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_security.submit` | POST | `/admin/applications/security` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_status` | GET | `/admin/applications/status` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.application_status.submit` | POST | `/admin/applications/status` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.applications` | GET | `/admin/applications` | UIAccessManagement | ui.admin_pages | `ui/pages_apps.go` |
| `admin.audit` | GET | `/admin/audit` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_detail` | GET | `/admin/audit/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_export_cancel` | POST | `/admin/audit/exports/cancel` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_export_create` | POST | `/admin/audit/exports/create` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_export_download` | GET | `/admin/audit/exports/download` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_exports` | GET | `/admin/audit/exports` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_maintenance` | GET | `/admin/audit/maintenance` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_maintenance_cancel` | POST | `/admin/audit/maintenance/cancel` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_maintenance_preview` | POST | `/admin/audit/maintenance/preview` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.audit_maintenance_start` | POST | `/admin/audit/maintenance/start` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.backup_cancel` | POST | `/admin/backups/jobs/cancel` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_cleanup` | POST | `/admin/backups/cleanup` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_cleanup_preview` | GET | `/admin/backups/cleanup/preview` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_detail` | GET | `/admin/backups/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_download` | POST | `/admin/backups/download` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_job_detail` | GET | `/admin/backups/jobs/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_jobs` | GET | `/admin/backups/jobs` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_reconcile` | POST | `/admin/backups/reconcile` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_retention` | GET | `/admin/backups/retention` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_retention_save` | POST | `/admin/backups/retention` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_run` | POST | `/admin/backups/run` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedule_delete` | POST | `/admin/backups/schedules/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedule_edit` | GET | `/admin/backups/schedules/edit` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedule_new` | GET | `/admin/backups/schedules/new` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedule_save` | POST | `/admin/backups/schedules/save` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedule_state` | POST | `/admin/backups/schedules/state` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backup_schedules` | GET | `/admin/backups/schedules` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.backups` | GET | `/admin/backups` | UIAccessManagement | ui.admin_pages | `ui/pages_backup.go` |
| `admin.dashboard` | GET | `/admin/dashboard` | UIAccessManagement | ui.admin_pages | `ui/pages_stats.go` |
| `admin.delegations` | GET | `/admin/delegations` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.diagnostics` | GET | `/admin/diagnostics` | UIAccessManagement | diagnostics.operations、ui.admin_pages | `ui/pages_admin.go` |
| `admin.error_codes` | GET | `/admin/errors` | UIAccessManagement | ui.admin_pages | `ui/pages_audit.go` |
| `admin.group_create` | POST | `/admin/groups/create` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.group_delete` | POST | `/admin/groups/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.group_detail` | GET | `/admin/groups/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.group_members` | POST | `/admin/groups/members` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.group_update` | POST | `/admin/groups/update` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.groups` | GET | `/admin/groups` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.notification_mail` | GET | `/admin/notifications/mail` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.notification_mail_secret` | POST | `/admin/notifications/mail/secret` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.notification_mail_template_preview` | POST | `/admin/notifications/mail/template/preview` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.notification_mail_test` | POST | `/admin/notifications/mail/test` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.permission_create` | GET | `/admin/permissions/create` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permission_create.submit` | POST | `/admin/permissions/create` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permission_delete` | POST | `/admin/permissions/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permission_detail` | GET | `/admin/permissions/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permission_state` | POST | `/admin/permissions/state` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permission_update` | POST | `/admin/permissions/update` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.permissions` | GET | `/admin/permissions` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.preset_diff` | GET | `/admin/presets/diff` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.report_cancel` | POST | `/admin/reports/cancel` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_cleanup` | POST | `/admin/reports/cleanup` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_detail` | GET | `/admin/reports/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_download` | POST | `/admin/reports/download` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_retention` | GET | `/admin/reports/retention` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_retry` | POST | `/admin/reports/retry` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_create` | POST | `/admin/reports/schedules/create` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_delete` | POST | `/admin/reports/schedules/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_delete_preview` | GET | `/admin/reports/schedules/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_detail` | GET | `/admin/reports/schedules/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_edit` | GET | `/admin/reports/schedules/edit` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_new` | GET | `/admin/reports/schedules/new` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_state` | POST | `/admin/reports/schedules/state` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedule_update` | POST | `/admin/reports/schedules/update` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.report_schedules` | GET | `/admin/reports/schedules` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.reports` | GET | `/admin/reports` | UIAccessManagement | ui.admin_pages | `ui/pages_reports.go` |
| `admin.review_decide` | POST | `/admin/reviews/decide` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.review_detail` | GET | `/admin/reviews/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.reviews` | GET | `/admin/reviews` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.role_assign` | POST | `/admin/roles/assignments` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_assignments` | GET | `/admin/roles/assignments` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_create` | GET | `/admin/roles/create` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_create.submit` | POST | `/admin/roles/create` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_detail` | GET | `/admin/roles/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_permissions` | POST | `/admin/roles/permissions` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_state` | POST | `/admin/roles/state` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.role_update` | POST | `/admin/roles/update` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.roles` | GET | `/admin/roles` | UIAccessManagement | ui.admin_pages | `ui/pages_rbac.go` |
| `admin.security_policies` | GET | `/admin/security/policies` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_detail` | GET | `/admin/security/policies/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_diff` | GET | `/admin/security/policies/diff` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_preview` | POST | `/admin/security/policies/preview` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_restore` | POST | `/admin/security/policies/restore` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_restore_preview` | POST | `/admin/security/policies/restore/preview` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.security_policy_save` | POST | `/admin/security/policies/save` | UIAccessManagement | ui.admin_pages | `ui/pages_security_policy.go` |
| `admin.sessions` | GET | `/admin/sessions` | UIAccessManagement | ui.admin_pages | `ui/pages_admin_sessions.go` |
| `admin.sessions.revoke` | POST | `/admin/sessions/revoke` | UIAccessManagement | ui.admin_pages | `ui/pages_admin_sessions.go` |
| `admin.settings` | GET | `/admin/settings` | UIAccessManagement | settings.managed、ui.admin_pages | `ui/pages_admin.go` |
| `admin.settings_update` | POST | `/admin/settings` | UIAccessManagement | settings.managed、ui.admin_pages | `ui/pages_admin.go` |
| `admin.statistics` | GET | `/admin/statistics` | UIAccessManagement | ui.admin_pages | `ui/pages_stats.go` |
| `admin.statistics_errors` | GET | `/admin/statistics/errors` | UIAccessManagement | ui.admin_pages | `ui/pages_stats.go` |
| `admin.tasks` | GET | `/admin/tasks` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_batch` | GET | `/admin/users/batch` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_batch_action` | POST | `/admin/users/batch/action` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_batch_detail` | GET | `/admin/users/batch/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_batch_report` | GET | `/admin/users/batch/report` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_create` | GET | `/admin/users/create` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_create.submit` | POST | `/admin/users/create` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_delete` | POST | `/admin/users/delete` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_delete_preview` | GET | `/admin/users/delete-preview` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_detail` | GET | `/admin/users/detail` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_export` | GET | `/admin/users/export` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_export.submit` | POST | `/admin/users/export` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_import` | GET | `/admin/users/import` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_import.submit` | POST | `/admin/users/import` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_password_reset` | GET | `/admin/users/password-reset` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_password_reset.submit` | POST | `/admin/users/password-reset` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_rename` | GET | `/admin/users/rename` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_rename.submit` | POST | `/admin/users/rename` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_state` | POST | `/admin/users/state` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_update` | POST | `/admin/users/update` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.user_validity` | POST | `/admin/users/validity` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `admin.users` | GET | `/admin/users` | UIAccessManagement | ui.admin_pages | `ui/pages_admin.go` |
| `app.scan_confirm` | GET | `/app/scan` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `app.scan_confirm.decide` | POST | `/app/scan` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.email_verify` | GET | `/email/verify` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.email_verify.submit` | POST | `/email/verify` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.email_verify_resend` | POST | `/email/verify/resend` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.invitation_accept` | GET | `/invitation/accept` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.invitation_accept.submit` | POST | `/invitation/accept` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.landing` | GET | `/home` | UIAccessUser | ui.public_pages | `ui/pages_auth.go` |
| `auth.login` | GET | `/login` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.login.submit` | POST | `/login` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.logout` | POST | `/logout` | UIAccessUser | ui.public_pages | `ui/pages_auth.go` |
| `auth.passkey_login` | GET | `/login/passkey` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.passkey_login.finish` | POST | `/login/passkey/finish` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.password_forgot` | GET | `/login/forgot-password` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.password_forgot.submit` | POST | `/login/forgot-password` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.password_reset` | GET | `/login/reset-password` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.password_reset.submit` | POST | `/login/reset-password` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.qr_login` | GET | `/login/qr` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.qr_login.cancel` | POST | `/login/qr/cancel` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.qr_login.claim` | POST | `/login/qr/claim` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.qr_login.poll` | POST | `/login/qr/poll` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.qr_login.regenerate` | POST | `/login/qr/regenerate` | UIAccessPublic | ui.public_pages | `ui/pages_oauth.go` |
| `auth.recovery_cancel` | POST | `/login/recovery/cancel` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.recovery_code` | GET | `/login/recovery-code` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.recovery_code.submit` | POST | `/login/recovery-code` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.recovery_rebind` | GET | `/login/recovery/rebind` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.recovery_rebind.complete` | POST | `/login/recovery/rebind/complete` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.recovery_rebind.start` | POST | `/login/recovery/rebind/start` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.register` | GET | `/register` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.register.submit` | POST | `/register` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.registration_status` | GET | `/register/status` | UIAccessPublic | ui.public_pages | `ui/pages_auth.go` |
| `auth.second_factor` | GET | `/login/second-factor` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.second_factor.cancel` | POST | `/login/second-factor/cancel` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.second_factor.resend` | POST | `/login/second-factor/resend` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.second_factor.verify` | POST | `/login/second-factor` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.strong_setup` | GET | `/login/strong-setup` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.strong_setup.passkey_finish` | POST | `/login/strong-setup/passkey/finish` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.strong_setup.passkey_start` | POST | `/login/strong-setup/passkey/start` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.strong_setup.totp_finish` | POST | `/login/strong-setup/totp/finish` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `auth.strong_setup.totp_start` | POST | `/login/strong-setup/totp/start` | UIAccessPublic | ui.public_pages | `ui/pages_mfa.go` |
| `manage.apps` | GET | `/manage/applications` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.members` | GET | `/manage/applications/members` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.members_submit` | POST | `/manage/applications/members` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.permission_state` | POST | `/manage/applications/permissions/state` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.permissions` | GET | `/manage/applications/permissions` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.role_assign` | POST | `/manage/applications/roles/assignments` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.role_assignments` | GET | `/manage/applications/roles/assignments` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.role_detail` | GET | `/manage/applications/roles/detail` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.role_permissions` | POST | `/manage/applications/roles/permissions` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.role_state` | POST | `/manage/applications/roles/state` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `manage.roles` | GET | `/manage/applications/roles` | UIAccessUser | ui.admin_pages | `ui/pages_manage.go` |
| `oauth.consent` | GET | `/oauth/authorize` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `oauth.consent.decide` | POST | `/oauth/authorize` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `oauth.device_confirm` | GET | `/oauth/device/confirm` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `oauth.device_confirm.decide` | POST | `/oauth/device/confirm` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `oauth.device_verify` | GET | `/oauth/device` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `oauth.device_verify.describe` | POST | `/oauth/device` | UIAccessPublic | oauth_oidc.protocol | `ui/pages_oauth.go` |
| `support.case_create` | GET | `/support/cases/create` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.case_create.submit` | POST | `/support/cases/create` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.case_detail` | GET | `/support/cases/detail` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.case_reassign.submit` | POST | `/support/cases/reassign` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.case_send.submit` | POST | `/support/cases/send` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.case_transition.submit` | POST | `/support/cases/transition` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.cases` | GET | `/support/cases` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_approval` | GET | `/support/recovery/approval` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_approve.submit` | POST | `/support/recovery/approval` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_cancel.submit` | POST | `/support/recovery/cancel` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_create.submit` | POST | `/support/recovery/request` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_execute` | GET | `/support/recovery/execute` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_execute.submit` | POST | `/support/recovery/execute` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_inbox` | GET | `/support/recovery` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_reject.submit` | POST | `/support/recovery/reject` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `support.recovery_request` | GET | `/support/recovery/request` | UIAccessManagement | support.recovery | `ui/pages_support.go` |
| `system.error` | GET | `/500` | UIAccessPublic | ui.public_pages | `ui/contracts.go` |
| `system.forbidden` | GET | `/403` | UIAccessPublic | ui.public_pages | `ui/contracts.go` |
| `system.not_found` | GET | `/404` | UIAccessPublic | ui.public_pages | `ui/contracts.go` |
| `system.session_expired` | GET | `/401` | UIAccessPublic | ui.public_pages | `ui/contracts.go` |
| `ui.component_preview` | GET | `/_ui/preview` | UIAccessUser | ui.public_pages | `ui/contracts.go` |
| `ui.component_preview.submit` | POST | `/_ui/preview` | UIAccessUser | ui.public_pages | `ui/contracts.go` |

## 5. 页面/表单操作契约（OpenAPI 页面段，95 条）

账户/资料/会话/注册登录/MFA/三种恢复流程（邮件找回、恢复代码重绑、客服人工恢复）的页面路由已在机器可读 OpenAPI 中定义请求字段、响应、状态转移与限流说明；页面与 JSON API 用 `x-login-route-kind` 分开标识；页面处理器产生的错误以 HTML 错误页呈现，但传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/内部 panic）在进入页面处理器之前返回 application/json 统一错误信封。

- **同源生成**：方法与路径来自 `ui/` 中 `UIRoute` 字面量的 AST 扫描；字段/响应/状态转移契约在 `internal/transport/pagecontracts_*.go`；二者不一致时 `scripts/reference -check` 直接失败。
- **运行期文档**：`{prefix}/openapi.json` 由实际注册的页面路由生成（宿主未挂载的模块不会出现），`docs/reference/http-openapi.json` 是全部模块的离线投影。
- **传输语义**：写操作为 `application/x-www-form-urlencoded`（头像上传为 `multipart/form-data`），要求 CSRF 隐藏令牌与精确同源；成功通常 303 跳转流程下一步。页面处理器产生的错误以 HTML 错误页返回（HTTP 状态码 + 页面错误摘要）；传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/内部 panic）返回 `application/json` 统一业务错误信封（Error schema），不声明未实现的额外错误码头。
- **秘密与示例**：密码/令牌/恢复码/WebAuthn 断言等字段标记 `writeOnly`，示例全部是明确合成值，不包含可用凭据。
- **范围**：管理/审计/报告/备份/OAuth 等页面路由尚未登记本步契约，完整路由清单见 §4 与 [http-routes.json](http-routes.json)。
- **启用条件**：对应 `ui.Page*` 模块由宿主装配；OAuth 2.0 / OIDC 协议端点由 `protocol.enabled`（默认 false）显式启用，关闭时保留前缀直接 404，不属于本表。

| 命名路由 | 方法 | 路径 | 访问级别 | 页面模块 | 请求字段 | 响应状态 | 状态转移（摘要） |
|---|---|---|---|---|---|---|---|
| `account.activity` | GET | `/account/activity` | user | security | query:action、query:cursor、query:error_code、query:from、query:limit、query:offset、query:order、query:request_id、query:system_only、query:target_id、query:target_type、query:to | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 分页渲染本人安全活动；非法时间/分页/游标 → 400 并提示字段错误 等 |
| `account.activity_detail` | GET | `/account/activity/detail` | user | security | query:event_id（必填）、query:occurred_at | 200, 401, 404, 405, 429, 500, 503 | 事件属于本人 → 200 渲染详情；事件不属于本人/不存在 → 404 或按不存在处理 等 |
| `account.app_profile` | GET | `/account/app-profile` | user | account | query:status | 200, 401, 404, 405, 429, 500, 503 | 完整会话 + 已选择应用 → 200 渲染应用内资料；完整会话 + 未选择应用 → 200 提示未选择应用，不伪造资料 |
| `account.app_profile.submit` | POST | `/account/app-profile` | user | account | csrf_token（必填）[只写]、display_name、note、row_version（必填）、title | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 应用成员关系有效 → 更新成功：303 /account/app-profile?status=updated；未选择应用 → 200 提示，不写数据 等 |
| `account.email_change_verify` | GET | `/email/change/verify` | public | account | query:cid（必填）、query:rid（必填）、query:token（必填）[只写] | 200, 404, 405, 429, 500, 503 | 参数完整 → 渲染确认页（不消费令牌）；参数缺失/形状非法 → 400 |
| `account.email_change_verify.submit` | POST | `/email/change/verify` | public | account | cid（必填）、csrf_token（必填）[只写]、rid（必填）、token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 有效令牌 → 邮箱变更完成：200，旧邮箱不再作为身份邮箱；令牌无效/过期/已用 → 400 统一文案 |
| `account.grants` | GET | `/account/grants` | user | security | query:page、query:page_size | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 分页渲染授权摘要；非法分页参数 → 400 |
| `account.grants.revoke` | POST | `/account/grants/revoke` | user | security | authorization_id（必填）、csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 授权属于本人 + 复核通过 → 撤销成功：200，相关令牌失效；授权不存在/不属于本人 → 403 |
| `account.password` | GET | `/account/password` | user | account | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 渲染改密表单；无会话 → 401 |
| `account.password.submit` | POST | `/account/password` | user | account | csrf_token（必填）[只写]、current_password（必填）[只写]、new_password（必填）[只写]、password_confirm（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 原密码正确 + 新密码合规 → 改密成功：303 跳转登录页并撤销旧会话；原密码错误/新密码不合规/历史复用 → 400，不半改密 等 |
| `account.profile` | GET | `/account/profile` | user | account | query:status | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染当前用户资料；无会话/会话过期 → 401 受限提示页 |
| `account.profile.update` | POST | `/account/profile` | user | account | biography、csrf_token（必填）[只写]、language、nickname、phone、row_version（必填）、timezone | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 版本匹配 → 更新成功：303 /account/profile?status=updated；行版本缺失/过期 → 409 冲突页，要求重新读取 等 |
| `account.profile_avatar` | GET | `/account/profile/avatar` | user | account | query:status | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染头像管理页 |
| `account.profile_avatar.remove` | POST | `/account/profile/avatar/remove` | user | account | csrf_token（必填）[只写]、row_version（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 版本匹配 → 移除成功：303 /account/profile/avatar?status=removed；行版本过期 → 409 |
| `account.profile_avatar.submit` | POST | `/account/profile/avatar` | user | account | avatar（必填）、csrf_token（必填）[只写]、row_version（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 文件/版本有效 → 上传成功：303 /account/profile/avatar?status=uploaded；文件过大/类型不支持 → 400/413/415 等 |
| `account.profile_avatar_image` | GET | `/account/profile/avatar/image` | user | account | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 + 已设置头像 → 200 图片字节；未设置头像 → 404 等 |
| `account.profile_email` | GET | `/account/profile/email` | user | account | query:status | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染邮箱变更状态页 |
| `account.profile_email.cancel` | POST | `/account/profile/email/cancel` | user | account | csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 存在进行中申请 → 取消成功：303 /account/profile/email?status=cancelled；无进行中申请 → 200 提示，不伪造取消成功 |
| `account.profile_email.submit` | POST | `/account/profile/email` | user | account | csrf_token（必填）[只写]、current_password（必填）[只写]、new_email（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 密码正确 → 申请受理：200 展示待验证状态；密码错误/邮箱格式不合法 → 400 等 |
| `account.profile_username` | GET | `/account/profile/username` | user | account | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 渲染更名表单；无会话 → 401 |
| `account.profile_username.submit` | POST | `/account/profile/username` | user | account | csrf_token（必填）[只写]、current_password（必填）[只写]、new_username（必填）、row_version（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 校验通过 → 改名成功：200 展示结果；唯一性冲突/保留名/冷却中 → 400 或 409，明确原因 等 |
| `account.security` | GET | `/account/security` | user | security | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染安全概览；无会话/会话过期 → 401 |
| `account.security_mfa` | GET | `/account/security/mfa` | user | security | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染因素状态 |
| `account.security_mfa.add_confirm` | POST | `/account/security/mfa/confirm` | user | security | attempt_token（必填）[只写]、challenge_id（必填）、code（必填）[只写]、csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 挑战有效 + 验证码正确 → 绑定成功：200；验证码错误/过期 → 400，不绑定 |
| `account.security_mfa.add_start` | POST | `/account/security/mfa` | user | security | csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 → 生成挑战：200（发送失败如实提示，不伪造已绑定） |
| `account.security_mfa.remove` | POST | `/account/security/mfa/remove` | user | security | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 密码正确且策略允许 → 解除成功：200；密码错误 → 400/403；策略禁止删除最后因素 → 403 |
| `account.security_passkeys` | GET | `/account/security/passkeys` | user | security | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染凭据列表；passkey.enabled=false → 页面说明不可用 |
| `account.security_passkeys.register_finish` | POST | `/account/security/passkeys/register/finish` | user | security | ceremony_id（必填）、csrf_token（必填）[只写]、current_password[只写]、name、passkey_response（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 注册校验通过 → 凭据创建：200；校验失败/挑战过期 → 400/403，不创建凭据 |
| `account.security_passkeys.register_start` | POST | `/account/security/passkeys/register` | user | security | csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 → 生成注册挑战：200 |
| `account.security_passkeys.rename` | POST | `/account/security/passkeys/rename` | user | security | credential_id（必填）、csrf_token（必填）[只写]、name | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 凭据属于本人 → 重命名成功：200；凭据不存在/不属于本人 → 403 |
| `account.security_passkeys.revoke` | POST | `/account/security/passkeys/revoke` | user | security | credential_id（必填）、csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 复核通过且策略允许 → 撤销成功：200；凭据不属于本人/策略禁止 → 403 |
| `account.security_recovery_codes` | GET | `/account/security/recovery-codes` | user | security | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染库存摘要（不含明文代码） |
| `account.security_recovery_codes.generate` | POST | `/account/security/recovery-codes` | user | security | confirm（必填）、csrf_token（必填）[只写]、current_password（必填）[只写]、totp_code（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 双因素复核 + 确认 → 生成新代码：200（仅本次显示）；复核失败/未确认 → 400/403，旧代码不变 |
| `account.security_totp` | GET | `/account/security/totp` | user | security | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染 TOTP 状态 |
| `account.security_totp.bind_confirm` | POST | `/account/security/totp/confirm` | user | security | binding_id（必填）、code（必填）[只写]、csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 验证码正确 → 绑定成功：200；验证码错误/过期 → 400，不绑定 |
| `account.security_totp.bind_start` | POST | `/account/security/totp/bind` | user | security | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 密码正确 → 生成绑定材料：200 |
| `account.security_totp.remove` | POST | `/account/security/totp/remove` | user | security | code（必填）[只写]、csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 复核通过且策略允许 → 解除成功：200；验证码/密码错误 → 400/403；策略禁止 → 403 |
| `account.sessions` | GET | `/account/sessions` | user | security | query:page、query:page_size | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 分页渲染会话摘要；非法分页参数 → 400 |
| `account.sessions.revoke` | POST | `/account/sessions/revoke` | user | security | csrf_token（必填）[只写]、current_password（必填）[只写]、target_session_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 目标会话属于本人 → 撤销成功：200；目标不存在/不属于本人 → 403 |
| `account.sessions.revoke_all` | POST | `/account/sessions/revoke-all` | user | security | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 复核通过 → 全部会话撤销：303 跳转登录页；密码错误 → 400/403，会话不变 |
| `account.sessions.revoke_others` | POST | `/account/sessions/revoke-others` | user | security | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 完整会话 + 复核通过 → 其他会话撤销：200，当前会话保留；密码错误 → 400/403 |
| `auth.email_verify` | GET | `/email/verify` | public | auth | query:cid（必填）、query:token（必填）[只写]、query:uid（必填） | 200, 404, 405, 429, 500, 503 | 验证链接参数完整 → 渲染确认页（不消费令牌）；参数缺失/形状非法 → 400，不区分“不存在/已用” |
| `auth.email_verify.submit` | POST | `/email/verify` | public | auth | cid（必填）、csrf_token（必填）[只写]、token（必填）[只写]、uid（必填） | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 有效令牌 → 邮箱标记为已验证：200，不签发会话；令牌无效/过期/已用 → 400 统一文案 |
| `auth.email_verify_resend` | POST | `/email/verify/resend` | public | auth | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 → 统一受理：200 页面提示已受理，不透露账户是否存在；冷却期内重复请求 → 同样统一受理（服务端按冷却策略处理） 等 |
| `auth.invitation_accept` | GET | `/invitation/accept` | public | auth | query:cid（必填）、query:iid（必填）、query:token（必填）[只写] | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染接受邀请表单（不消费票据）；票据无效/过期/不匹配 → 400 统一文案 |
| `auth.invitation_accept.submit` | POST | `/invitation/accept` | public | auth | cid（必填）、csrf_token（必填）[只写]、iid（必填）、language、nickname、password[只写]、password_confirm[只写]、timezone、token（必填）[只写]、username | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 + 有效票据 → 创建普通用户并接受邀请：200 展示应用/角色结果，不自动授予系统资格；已登录 + 有效票据 → 接受邀请：200，不切换身份 等 |
| `auth.landing` | GET | `/home` | user | auth | - | 200, 401, 404, 405, 429, 500, 503 | 完整会话 → 200 渲染落地页；无会话/会话过期 → 401 受限提示页 等 |
| `auth.login` | GET | `/login` | public | auth | query:return | 200, 404, 405, 429, 500, 503 | 匿名或未完整认证 → 渲染登录表单；已登录普通完整会话 → 303 跳转默认落地页或安全 return 路径 等 |
| `auth.login.submit` | POST | `/login` | public | auth | csrf_token（必填）[只写]、identifier（必填）、password（必填）[只写]、remember_me、return | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 → 完整会话：303 跳转 return/默认落地页并下发会话 Cookie；匿名 → 需要第二因素：303 跳转 /login/second-factor 并下发受限会话与签名状态 Cookie 等 |
| `auth.logout` | POST | `/logout` | user | auth | csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 已登录 → 服务端撤销当前会话：303 跳转登录页并清除 Cookie；无有效会话 → 清理 Cookie 后同样跳转登录页 |
| `auth.passkey_login` | GET | `/login/passkey` | public | auth | - | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染 Passkey 登录页并开始断言挑战；passkey.enabled=false → 403 或页面明示不可用，不伪造可登录状态 |
| `auth.passkey_login.finish` | POST | `/login/passkey/finish` | public | auth | csrf_token（必填）[只写]、passkey_ceremony_id（必填）、passkey_response（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 → 断言通过且已绑定用户：303 跳转落地页并下发完整会话；匿名 → 断言失败/挑战过期：400，不签发会话 |
| `auth.password_forgot` | GET | `/login/forgot-password` | public | mfa | - | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染找回密码表单 |
| `auth.password_forgot.submit` | POST | `/login/forgot-password` | public | mfa | csrf_token（必填）[只写]、identifier（必填） | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 → 统一受理：200 页面提示已受理；限流/失败预算：429 |
| `auth.password_reset` | GET | `/login/reset-password` | public | mfa | query:token（必填）[只写] | 200, 404, 405, 429, 500, 503 | 令牌有效 → 渲染新密码表单（不消费）；令牌缺失/过期/已用 → 400 CHALLENGE_INVALID |
| `auth.password_reset.submit` | POST | `/login/reset-password` | public | mfa | confirm_password（必填）[只写]、csrf_token（必填）[只写]、new_password（必填）[只写]、token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 令牌有效 + 新密码合规 → 密码变更：200，旧凭证失效；弱密码/历史复用 → 400 且不消费令牌（可重试），不造成半改密 等 |
| `auth.qr_login` | GET | `/login/qr` | public | auth | - | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染二维码页并下发签名状态 Cookie；扫码登录未启用 → 页面说明不可用，不生成可用二维码 |
| `auth.qr_login.cancel` | POST | `/login/qr/cancel` | public | auth | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 发起请求有效 → 取消：200 状态提示，旧二维码失效 |
| `auth.qr_login.claim` | POST | `/login/qr/claim` | public | auth | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 已确认 + 原发起端 + 未领取 → 303 跳转落地页并下发会话 Cookie；未确认/已领取/非原发起端 → 400/403，不签发会话 |
| `auth.qr_login.poll` | POST | `/login/qr/poll` | public | auth | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 发起请求有效 → 200 返回当前状态并刷新状态 Cookie；二维码过期/已取消 → 200 状态提示（不签发会话） 等 |
| `auth.qr_login.regenerate` | POST | `/login/qr/regenerate` | public | auth | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 发起请求过期/用户刷新 → 新二维码生效，旧二维码失效 |
| `auth.recovery_cancel` | POST | `/login/recovery/cancel` | public | mfa | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 受限恢复会话 → 取消：303 跳转登录页并清除受限 Cookie |
| `auth.recovery_code` | GET | `/login/recovery-code` | public | mfa | - | 200, 404, 405, 429, 500, 503 | 待第二因素 → 渲染恢复代码输入页 |
| `auth.recovery_code.submit` | POST | `/login/recovery-code` | public | mfa | attempt_token[只写]、challenge_id、code（必填）[只写]、csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待第二因素 + 有效代码 → 303 进入受限恢复（/login/recovery/rebind）；代码无效/已消费/过期 → 400 统一文案 等 |
| `auth.recovery_rebind` | GET | `/login/recovery/rebind` | public | mfa | - | 200, 404, 405, 429, 500, 503 | 受限恢复会话 → 渲染重绑页；无受限恢复会话 → 重定向登录页 |
| `auth.recovery_rebind.complete` | POST | `/login/recovery/rebind/complete` | public | mfa | binding_id（必填）、csrf_token（必填）[只写]、method、response（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 受限恢复 + 绑定校验通过：200，因素绑定完成；校验失败/过期：400，保持受限状态 |
| `auth.recovery_rebind.start` | POST | `/login/recovery/rebind/start` | public | mfa | csrf_token（必填）[只写]、method | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 受限恢复会话 → 生成绑定挑战：200 |
| `auth.register` | GET | `/register` | public | auth | - | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染注册表单（字段按注册策略显示必填项）；registration.enabled=false → 403，注册不可用 |
| `auth.register.submit` | POST | `/register` | public | auth | csrf_token（必填）[只写]、email、language、nickname、password（必填）[只写]、password_confirm（必填）[只写]、timezone、username（必填） | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 匿名 → 注册成功：200 页面展示状态（待邮箱验证/待审核/已可用）；不自动签发会话；匿名 → 字段不合法/密码不一致：400 等 |
| `auth.registration_status` | GET | `/register/status` | public | auth | - | 200, 404, 405, 429, 500, 503 | 匿名 → 渲染状态说明页（无敏感账户枚举） |
| `auth.second_factor` | GET | `/login/second-factor` | public | mfa | - | 200, 404, 405, 429, 500, 503 | 登录后待第二因素 → 渲染确认页（受限会话）；挑战过期/状态 Cookie 无效 → 重定向登录页重新发起 等 |
| `auth.second_factor.cancel` | POST | `/login/second-factor/cancel` | public | mfa | csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待第二因素 → 取消：303 跳转登录页并清除受限会话/状态 Cookie |
| `auth.second_factor.resend` | POST | `/login/second-factor/resend` | public | mfa | attempt_token（必填）[只写]、challenge_id（必填）、csrf_token（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待第二因素 → 重发受理：200 并刷新状态 Cookie；冷却/限流 → 429 等 |
| `auth.second_factor.verify` | POST | `/login/second-factor` | public | mfa | attempt_token（必填）[只写]、challenge_id（必填）、code[只写]、csrf_token（必填）[只写]、passkey_ceremony_id、passkey_response[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待第二因素 → 验证通过：303 跳转落地页并签发完整会话；待第二因素 → 验证失败：400/403，保持受限状态可重试 等 |
| `auth.strong_setup` | GET | `/login/strong-setup` | public | mfa | - | 200, 404, 405, 429, 500, 503 | 待绑定强因素 → 渲染初始化页；无需绑定（已满足策略）→ 重定向第二因素确认页 等 |
| `auth.strong_setup.passkey_finish` | POST | `/login/strong-setup/passkey/finish` | public | mfa | csrf_token（必填）[只写]、current_password[只写]、passkey_ceremony_id、passkey_response（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待绑定 → 注册校验通过：200，因素绑定成功；校验失败/挑战过期 → 400/403，不绑定，不放宽策略 |
| `auth.strong_setup.passkey_start` | POST | `/login/strong-setup/passkey/start` | public | mfa | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待绑定 → 生成注册挑战：200，不改动已有安全状态 |
| `auth.strong_setup.totp_finish` | POST | `/login/strong-setup/totp/finish` | public | mfa | binding_id（必填）、code（必填）[只写]、csrf_token（必填）[只写]、current_password[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待绑定 → 验证通过：200，TOTP 绑定成功；验证码错误/过期：400，不绑定 |
| `auth.strong_setup.totp_start` | POST | `/login/strong-setup/totp/start` | public | mfa | csrf_token（必填）[只写]、current_password（必填）[只写] | 200, 303, 400, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 待绑定 → 生成 TOTP 绑定材料：200，不改动已生效因素 |
| `support.case_create` | GET | `/support/cases/create` | management | support | query:reason、query:target_user_id | 200, 401, 404, 405, 429, 500, 503 | 管理会话 → 200 渲染新建表单；目标越权/不存在 → 403 或页面错误摘要 |
| `support.case_create.submit` | POST | `/support/cases/create` | management | support | action（必填）、confirm（必填）、csrf_token（必填）[只写]、reason（必填）、target_user_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 管理会话 + 有创建权限 + 目标在范围 → 创建成功：200 跳转详情；目标越权/不存在 → 403；字段不合法 → 400；再次认证不满足 → 403 |
| `support.case_detail` | GET | `/support/cases/detail` | management | support | query:case_id（必填） | 200, 401, 404, 405, 429, 500, 503 | 范围内求助单 → 200 渲染详情；不存在/超出范围 → 403 或 404，不泄露他人数据 |
| `support.case_reassign.submit` | POST | `/support/cases/reassign` | management | support | case_id（必填）、confirm（必填）、csrf_token（必填）[只写]、new_assignee_user_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 范围 + 接单资格通过 → 转派成功：200；目标无资格/越权 → 403 |
| `support.case_send.submit` | POST | `/support/cases/send` | management | support | case_id（必填）、confirm（必填）、csrf_token（必填）[只写] | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 范围内求助单 → 发送受理：200（入队不等于送达，失败如实提示）；越权/状态不允许 → 403/409 |
| `support.case_transition.submit` | POST | `/support/cases/transition` | management | support | case_id（必填）、confirm（必填）、csrf_token（必填）[只写]、note、to_status（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 合法状态转移 → 成功：200；非法转移/并发冲突 → 409；越权 → 403 |
| `support.cases` | GET | `/support/cases` | management | support | query:offset、query:status | 200, 401, 404, 405, 429, 500, 503 | 管理会话 + 有查询权限 → 200 分页渲染范围内求助单；无权限/范围外 → 403 或 200 空列表（不越权），不返回他人范围数据 |
| `support.recovery_approval` | GET | `/support/recovery/approval` | management | support | query:request_id（必填） | 200, 401, 404, 405, 429, 500, 503 | 有审批资格且非自我批准 → 200 渲染审批页；无资格/自我批准 → 403 |
| `support.recovery_approve.submit` | POST | `/support/recovery/approval` | management | support | confirm（必填）、csrf_token（必填）[只写]、note、request_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 独立审批通过 → 批准成功：200（仍待执行）；自我批准/无资格 → 403；状态不允许 → 409 |
| `support.recovery_cancel.submit` | POST | `/support/recovery/cancel` | management | support | confirm（必填）、csrf_token（必填）[只写]、reason（必填）、request_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 可取消状态 + 权限通过 → 取消成功：200；已执行/状态不允许 → 409；越权 → 403 |
| `support.recovery_create.submit` | POST | `/support/recovery/request` | management | support | confirm（必填）、csrf_token（必填）[只写]、delivery、evidence_summary（必填）、operation（必填）、reason（必填）、support_case_id、target_user_id（必填）、verification_basis（必填）、verification_reference（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 有登记权限 + 目标在范围 + 核验依据合规 → 申请登记成功：200 跳转详情（待独立审批）；目标越权/root → 403；字段不合法 → 400；重复申请 → 409 |
| `support.recovery_execute` | GET | `/support/recovery/execute` | management | support | query:request_id（必填） | 200, 401, 404, 405, 429, 500, 503 | 已批准 + 有执行权限 → 200 渲染执行确认；未批准/无权限/策略关闭 → 200 展示阻塞原因，不提供可用执行 |
| `support.recovery_execute.submit` | POST | `/support/recovery/execute` | management | support | confirm（必填）、csrf_token（必填）[只写]、request_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 已批准 + 执行权限 + 再次认证通过 → 执行成功：200 展示脱敏结果；未批准/权限不足/再次认证失败 → 403；状态冲突 → 409 |
| `support.recovery_inbox` | GET | `/support/recovery` | management | support | query:mode、query:offset、query:operation | 200, 401, 404, 405, 429, 500, 503 | 管理会话 → 200 渲染范围内工作台；无权限 → 403 |
| `support.recovery_reject.submit` | POST | `/support/recovery/reject` | management | support | confirm（必填）、csrf_token（必填）[只写]、reason（必填）、request_id（必填） | 200, 303, 400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503 | 有审批资格 → 驳回成功：200；无资格 → 403；状态不允许 → 409 |
| `support.recovery_request` | GET | `/support/recovery/request` | management | support | query:request_id（必填） | 200, 401, 404, 405, 429, 500, 503 | 参与者且有读取权限 → 200 渲染详情；不存在/超出范围 → 403/404 |

## 6. OpenAPI 与 Discovery 边界（不造假完整契约）

- OpenAPI 由三部分组成：运行期最小 JSON API（`/healthz`、`/openapi.json`，错误用统一信封）；页面/表单操作（本页 §5）；**协议端点离线 OpenAPI**（[protocol-openapi.json](protocol-openapi.json)，本页 §3 的同源生成物，不影响运行期 `/openapi.json`）。管理 JSON API 的请求/响应模式由管理组契约（[http-openapi-admin.json](http-openapi-admin.json)）定义，§2 路由清单用于交叉核对。
- OAuth 2.0 / OIDC 协议端点默认关闭（`protocol.enabled=false`），关闭时协议命名空间返回普通 404；启用后使用标准协议响应（RFC 6749/6750/7009/7662/8628），**不被统一业务错误信封包装**；自定义扫码端点按 §3.4 例外使用项目信封。
- 协议契约与 OpenAPI 段由 `scripts/internal/apidoc/protocol_contract.go` 的同一份表生成：端点/方法/字段/错误/开关与 `internal/protocolapi/doc.go` 端点表及 `routes.go` 条件注册双向核对，不一致或例外未登记时 `scripts/reference -check` 直接失败。
- OIDC Discovery 只声明真实启用的能力（含 `EnableIntrospection`/`EnableDeviceFlow` 条件端点）；扫码扩展与本包设备取消扩展不伪装成标准 Discovery 字段。真实第三方 OIDC 客户端、设备码/扫码真机互操作等未完成验收的边界见 [../guide/login-and-oauth.md](../guide/login-and-oauth.md)。
- 管理/托管/客服 API 的授权、对象/字段白名单与审计约束见对应部署文档；不要把管理 API 暴露给业务应用。
- 新增/删除路由必须同步更新能力声明（catalog.json）、页面契约与协议契约；未映射的公开符号、能力声明或契约/路由不一致会让 `scripts/reference -check` 失败。

## 7. 机器可读

- [http-routes.json](http-routes.json)：方法/路径/来源/能力关联的完整机器表（含协议端点 HTTP 契约与例外登记）。
- [http-openapi.json](http-openapi.json)：页面/表单 OpenAPI 3 文档（秘密字段 writeOnly、示例为合成值）。
- [protocol-openapi.json](protocol-openapi.json)：协议端点 OpenAPI 3 文档（OAuth/OIDC/设备码/扫码；标准错误与项目信封分别建模）。
- 页面 `Access` 列来自 `UIRoute` 字面量；执行时仍由服务端重新判定，台账仅用于契约对照。
