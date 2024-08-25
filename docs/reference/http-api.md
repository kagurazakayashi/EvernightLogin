# HTTP 契约参考（管理 API / 协议路径 / 页面命名路由）

> 路由清单由 AST 扫描实际注册生成（`handler.go` 的 `add(...)`、领域 `DomainRoute{Method, Pattern}`、协议路径常量与 `UIRoute` 页面命名路由），不是手写端点表。鉴权/CSRF/开关与托管边界见 [../deployment/managed-api.md](../deployment/managed-api.md)、[../deployment/app-support-api.md](../deployment/app-support-api.md) 与 [../deployment/standalone-service.md](../deployment/standalone-service.md)。

## 1. 基础约定

- 所有路径带 `server.path_prefix`（默认空）；管理 API 默认前缀 `/admin/v1`，托管 API `/api/managed/v1`，应用客服 API `/api/app/v1/support`。
- **默认关闭**：OAuth/OIDC 协议端点、管理 JSON API、托管 API、应用客服 API 都需显式启用；未启用时对应路径 404，维护模式一律 503。
- 错误响应使用与 Go 门面一致的错误码 + `request_id`；**错误信封与重试语义见 [errors.md](errors.md)**，排障流程见 [../guide/troubleshooting.md](../guide/troubleshooting.md)。
- 管理 API 复用真实管理会话并校验 CSRF（Cookie 会话写请求要求 CSRF 令牌）；页面路由与 API 路由不共享鉴权旁路。
- 请求身份必须来自可信边界（Cookie/Authorization/宿主服务端存储）；请求参数不能自称管理员、root、应用或用户。
- `Host`、可信代理、TLS/mTLS 与公开基址使用同一套配置规则（`server.public_base_url`、`server.trusted_proxies`、`server.tls_terminating_proxy`）。

## 2. 管理 JSON API 路由（123 条，相对管理前缀）

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
| GET | `diagnostics` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `diagnostics/errors` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `diagnostics/export` | diagnostics.operations | `internal/serverapp/diagnostics.go` |
| GET | `error-codes` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `groups` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `groups/{group_id}` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `groups/{group_id}/members` | rbac.roles_permissions | `internal/serverapp/admin_domain_routes.go` |
| GET | `meta` | adminapi.core | `internal/adminapi/handler.go` |
| GET | `notifications` | adminapi.core | `internal/adminapi/handler.go` |
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
| POST | `users/{user_id}/state` | account.users | `internal/serverapp/admin_domain_writes.go` |
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

## 3. OAuth 2.0 / OIDC 协议路径常量（17 个）

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

### 3.1 协议包文档声明的端点（18 个）

| 方法 | 路径 |
|---|---|
| GET | `/.well-known/openid-configuration` |
| GET | `/jwks` |
| GET | `/oauth/authorize` |
| POST | `/oauth/authorize` |
| POST | `/oauth/device/cancel` |
| POST | `/oauth/device_authorization` |
| POST | `/oauth/introspect` |
| POST | `/oauth/qr/cancel` |
| POST | `/oauth/qr/claim` |
| POST | `/oauth/qr/decision` |
| GET | `/oauth/qr/prompt` |
| POST | `/oauth/qr/regenerate` |
| POST | `/oauth/qr/request` |
| POST | `/oauth/qr/status` |
| POST | `/oauth/revoke` |
| POST | `/oauth/token` |
| POST | `/oauth/token/authorize` |
| GET | `/oauth/userinfo` |

## 4. 内置页面命名路由（245 个冻结命名路由）

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

## 5. OpenAPI 与 Discovery 边界（不造假完整契约）

- OpenAPI 当前只包含最小健康检查/错误契约（`/healthz`、`/openapi.json`），**不是**完整业务 API 文档；业务接口以本页路由清单、机器 JSON 与源码公开契约为准。
- OIDC Discovery 只声明真实启用的能力；默认关闭时相关路径 404。真实第三方 OIDC 客户端、设备码/扫码真机互操作等未完成验收的边界见 [../guide/login-and-oauth.md](../guide/login-and-oauth.md)。
- 管理/托管/客服 API 的授权、对象/字段白名单与审计约束见对应部署文档；不要把管理 API 暴露给业务应用。
- 新增/删除路由必须同步更新能力声明（catalog.json）；未映射的公开符号或能力声明会让 `scripts/reference -check` 失败。

## 6. 机器可读

- [http-routes.json](http-routes.json)：方法/路径/来源/能力关联的完整机器表。
- 页面 `Access` 列来自 `UIRoute` 字面量；执行时仍由服务端重新判定，台账仅用于契约对照。
