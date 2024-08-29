# 能力映射（catalog.json → 参考文档/机器 JSON）

> 能力声明来自 `scripts/capabilities/catalog.json`（机器可读能力映射的唯一来源），**实现状态不在这里重复**：请以 [能力矩阵](../acceptance/capability-matrix.md) 为准。本页提供“能力 → 公开面（Go/HTTP/页面/CLI/权限）→ 参考位置”的导航索引。

## 1. 能力参考索引（43 项）

| 能力 id | 领域 | 标题 | 分页 | 权限数 | 管理路由声明 | 页面声明 | CLI 声明 | 主要公开 Go API |
|---|---|---|---|---|---|---|---|---|
| `access.joint_check` | 授权 | 令牌与当前权限联合校验 | none | 1 | 0 | 0 | 0 | `AccessService`、`AccessRequest`、`AccessDecision`、`SessionAccessRequest`、`SessionAccessDecision`、`SessionService` |
| `account.lifecycle_public` | 账户 | 注册、资料与邮箱生命周期公开 Go 门面（步骤 221） | none | 0 | 0 | 0 | 0 | `CancelEmailChangeRequest`、`ChangeOwnUsernameRequest`、`EmailChangeService`、`EmailChangeState`、`EmailChangeStateRequest`、`EmailChangeVerified` |
| `account.user_lifecycle_public` | 账户 | 用户生命周期、自有密码、邀请审批与批量导入公开门面（步骤 223） | offset | 0 | 0 | 0 | 0 | `AdminCancelInvitationRequest`、`AdminCreateInvitationRequest`、`AdminDeletionPreview`、`AdminDeletionResult`、`AdminInvitation`、`AdminInvitationCancelResult` |
| `account.users` | 账户 | 用户查询、生命周期与批量导出 | offset | 8 | 2 | 0 | 0 | `UserService`、`CreateUserRequest`、`User` |
| `admin.facade_api` | 管理 | 受信管理 Go 门面（用户/资料/应用/角色/权限） | offset | 1 | 0 | 0 | 0 | `AdminService`、`AdminCaller`、`AdminUser`、`AdminUserProfile`、`AdminUserList`、`AdminListUsersRequest` |
| `admin.observability_lists` | 管理 | 审计/报告/任务/备份管理列表分页闭环（步骤 218） | cursor | 0 | 1 | 0 | 0 | `AdminAuditChange`、`AdminAuditEvent`、`AdminAuditEventList`、`AdminAuditFilter`、`AdminBackupArtifact`、`AdminBackupArtifactList` |
| `adminapi.core` | 管理 | 管理 JSON API 基础端点、错误码与任务详情 | fixed | 0 | 5 | 0 | 0 | - |
| `applications.manage` | 授权 | 应用、成员与应用凭证管理 | offset | 5 | 3 | 0 | 0 | `AdminApplication`、`AdminCreateApplicationRequest`、`AdminApplicationRequest`、`AdminSetApplicationEnabledRequest`、`AdminAddMemberRequest` |
| `applications.oauth_delegation_public` | 应用 | 应用生命周期、OAuth 客户端与应用成员委派公开门面（步骤 225） | offset | 0 | 0 | 0 | 0 | `AdminApplicationDeleteRequest`、`AdminApplicationDeletionPreview`、`AdminApplicationDeletionResult`、`AdminApplicationDetail`、`AdminApplicationMemberChange`、`AdminApplicationMemberChangeRequest` |
| `audit.events` | 审计与报告 | 安全审计查询、导出与保留清理 | offset | 3 | 3 | 0 | 0 | - |
| `audit.reports_public` | 审计与报告 | 审计查询、导出/清理与统计报告公开 Go 门面（步骤 230） | offset | 0 | 0 | 0 | 0 | `AdminAuditEventDetail`、`AdminAuditEventRequest`、`AdminAuditExport`、`AdminAuditExportCancelRequest`、`AdminAuditExportList`、`AdminAuditExportListRequest` |
| `auth.password_session` | 认证与会话 | 密码登录、会话校验与 CSRF | none | 1 | 0 | 0 | 0 | `AuthService`、`LoginRequest`、`LoginResult`、`SecondFactorChallenge`、`VerifiedSession`、`VerifySecondFactorRequest` |
| `backup.restore` | 备份与恢复 | 备份创建、校验、离线查看与恢复 | offset | 7 | 4 | 0 | 15 | `BackupArtifact`、`BackupArtifactRequest`、`BackupArtifactService`、`BackupCheck`、`BackupCheckReport`、`BackupExport` |
| `bootstrap.root` | 身份基础 | 受控首次初始化与 root 自举 | none | 0 | 0 | 0 | 1 | `BootstrapService`、`RootRequest`、`RootResult` |
| `cli.loginctl` | CLI | 本地/在线管理 CLI（loginctl 命令组） | none | 0 | 0 | 0 | 23 | - |
| `config.load` | 配置 | YAML 配置加载、默认值、覆盖与校验 | none | 0 | 0 | 0 | 1 | - |
| `device_code.login` | 协议 | 设备码登录（RFC 8628） | none | 0 | 0 | 0 | 0 | - |
| `diagnostics.operations` | 管理 | 运行诊断与关联错误查询 | fixed | 1 | 3 | 1 | 0 | `DiagnosticsConfigSummary`、`DiagnosticsErrorEntry`、`DiagnosticsErrorList`、`DiagnosticsErrorsRequest`、`DiagnosticsExport`、`DiagnosticsQueueCount` |
| `mail.delivery` | 通知 | 站内邮件投递队列与本地测试邮件服务 | offset | 0 | 0 | 0 | 0 | - |
| `mfa.public_facade` | 认证与会话 | 认证因素与安全中心公开 Go 门面（步骤 222） | fixed | 1 | 0 | 0 | 0 | `MFAService`、`Runtime.MFA`、`MFAFactorListRequest`、`MFATOTPFactor`、`MFAEmailFactor`、`MFAPasskeyCredential` |
| `mfa.totp_recovery` | 认证与会话 | 两步验证（TOTP/恢复代码）与受限恢复 | none | 1 | 0 | 0 | 0 | `SecurityService`、`SecurityStatus`、`SecurityStatusRequest`、`BeginRecoveryRequest`、`RecoverySession`、`RecoveryStatus` |
| `oauth_oidc.protocol` | 协议 | OAuth2/OIDC 协议端点（授权码/刷新/撤销/内省/UserInfo） | none | 1 | 0 | 1 | 0 | `ProtocolService`、`ProtocolIntrospectRequest`、`ProtocolTokenInspection`、`ProtocolRevocationService`、`ProtocolRevokeTokenRequest`、`ProtocolRevokeResult` |
| `onboarding.invitations` | 账户 | 邀请与审核注册 | offset | 0 | 0 | 0 | 0 | - |
| `pagination.iteration` | 分页与列表 | 有界分页遍历辅助（宿主/CLI 可选） | none | 0 | 0 | 0 | 0 | `IterationOptions`、`IterationResult`、`IterateAdminPages`、`ErrPageNotAdvancing` |
| `passkey.webauthn` | 认证与会话 | Passkey/WebAuthn 登录与凭证管理 | none | 0 | 0 | 0 | 0 | `VerifySecondFactorRequest`、`SecondFactorChallenge` |
| `passwordreset.self_service` | 恢复 | 自助密码找回 | none | 1 | 0 | 0 | 0 | `PasswordResetService`、`RequestPasswordResetRequest`、`CompletePasswordResetRequest`、`PasswordResetResult`、`ValidatePasswordResetTokenRequest` |
| `qr_login.confirm` | 协议 | 已登录 APP 扫码登录与网页领取 | none | 0 | 0 | 0 | 0 | - |
| `rbac.public_facade` | 授权 | 角色/用户组/权限/预设/委派/授权查询公开门面（步骤 224） | offset | 0 | 0 | 0 | 0 | `RBACAuthorizationService`、`RBACCatalogRequest`、`RBACCheckRequest`、`RBACCheckResult`、`RBACCreateGroupRequest`、`RBACDelegatablePermission` |
| `rbac.roles_permissions` | 授权 | 用户组、角色、权限目录与委派 | offset | 8 | 11 | 0 | 0 | `AdminRole`、`AdminCreateRoleRequest`、`AdminRoleRequest`、`AdminRolePermissionRequest`、`AdminPermission`、`AdminCreatePermissionRequest` |
| `reports.generate` | 审计与报告 | 统计报告生成、导出、计划与清理 | offset | 5 | 6 | 0 | 0 | - |
| `runtime.embedded` | 嵌入式与运行时 | 嵌入式运行时装配（Open/Handler/Mount/生命周期） | none | 0 | 0 | 0 | 1 | `Runtime`、`Options`、`Open`、`Runtime.Handler`、`Runtime.Mount`、`Runtime.Start` |
| `security.policy_reauth` | 认证与会话 | 敏感操作安全策略与再次认证 | none | 1 | 0 | 0 | 0 | - |
| `session.admin` | 认证与会话 | 管理员会话查询与强制下线 | offset | 1 | 2 | 0 | 0 | `SessionService`、`SessionService.ListDevices`、`SessionDeviceRequest`、`SessionDevice`、`SessionDeviceList`、`AdminListUserSessionsRequest` |
| `settings.managed` | 配置 | 常规设置读取、校验、更新与敏感默认恢复 | none | 1 | 5 | 1 | 0 | `SettingField`、`SettingValidationError`、`SettingsFieldsRequest`、`SettingsRestoreSensitiveRequest`、`SettingsRestoreSensitiveResult`、`SettingsService` |
| `stats.overview` | 审计与报告 | 统计概览与健康状态 | fixed | 0 | 0 | 0 | 0 | - |
| `storage.sqlite_migrations` | 存储 | SQLite 存储、增量迁移与其他数据库方言适配 | none | 0 | 0 | 0 | 0 | - |
| `support.recovery` | 恢复 | 客服求助单、人工核验恢复与 root 本地应急 | offset | 7 | 2 | 1 | 1 | `SupportAdminService`、`SupportCase`、`SupportCaseEvent`、`SupportCasePage`、`SupportCaseRequest`、`SupportCreateCaseRequest` |
| `tasks.scheduler` | 任务 | 后台任务执行器与计划调度 | none | 0 | 0 | 0 | 0 | - |
| `token.jwt_keys` | 协议 | JWT 签发/验签、JWKS 与签名密钥轮换 | none | 0 | 0 | 0 | 0 | - |
| `transport.http_security` | 传输 | HTTP 传输安全链（限流/CSRF/CORS/边界/错误信封/OpenAPI） | none | 0 | 0 | 0 | 0 | - |
| `ui.admin_pages` | 页面 | 管理与客服页面框架（固定命名路由） | fixed | 0 | 0 | 2 | 0 | - |
| `ui.public_pages` | 页面 | 公开与自助页面（登录/注册/找回/账户/错误页） | fixed | 0 | 0 | 5 | 0 | - |
| `webhook.delivery` | 通知 | Webhook 端点、签名与投递重试 | none | 0 | 0 | 0 | 0 | - |

## 2. 与能力矩阵只读交叉核对

| 对象 | 能力矩阵盘点 | reference 扫描 |
|---|---|---|
| 能力总数 | 43 | 43 |
| 管理路由 | 123 | 123 |
| 页面路由 | 245 | 245 |
| 协议路径 | 17 | 17 |
| CLI 子命令 | 40 | 40 |
| 权限键 | 51 | 53 |

- app 函数（含导出方法）：能力矩阵盘点=266，reference 扫描=315（矩阵可能过期或扫描口径不同，需人工核对；不自动改写矩阵）
- 协议端点表：能力矩阵盘点=20，reference 扫描=18（矩阵可能过期或扫描口径不同，需人工核对；不自动改写矩阵）
- 权限键：能力矩阵盘点=51，reference 扫描=53（矩阵可能过期或扫描口径不同，需人工核对；不自动改写矩阵）

## 3. 使用方式

- 已知能力 id：在上表定位领域与公开面，再到 [go-api.md](go-api.md)、[http-api.md](http-api.md)、[permissions.md](permissions.md)、[cli.md](cli.md) 对应条目。
- 判断是否已实现/已测试：读 [能力矩阵](../acceptance/capability-matrix.md) 与 [需求矩阵](../acceptance/requirements-matrix-login.md)；README/本页不承诺状态。
- 机器消费：catalog.json 是声明源，本目录 4 个 JSON 是公开面清单；两者不一致时 `scripts/reference -check` 会报“能力声明无法解析”。
- 新增能力：先在 catalog.json 登记交叉层公开面，再实现代码并运行 `-write`；不允许只改文档宣称支持。

## 4. 相关机器文件

- 声明源：[scripts/capabilities/catalog.json](../../scripts/capabilities/catalog.json)
- 状态矩阵：[docs/acceptance/capability-matrix.json](../acceptance/capability-matrix.json)
- [http-routes.json](http-routes.json) / [cli-commands.json](cli-commands.json) / [permission-keys.json](permission-keys.json)
