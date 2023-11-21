# EvernightLogin 机器可读能力清单

> 本文件由 `go run ./scripts/capabilities` 从源码与能力声明自动生成，**不要手工编辑**。状态由「声明面是否在源码中真实解析到」决定，不是文档声称。

## 生成基线

| 项 | 值 |
|---|---|
| 生成时间（UTC） | 2026-11-24T20:55:41Z |
| 仓库 | . |
| Git HEAD / 分支 | `` / ``（工作树干净） |
| 工具链 / 平台 | go1.27.4 / windows/amd64 |
| 逻辑处理器 / 并发预算 | 4 / 2 |
| 能力声明 | `scripts/capabilities/catalog.json` |
| 扫描文件数 | 658 |

复跑命令（根目录，Windows PowerShell 示例）：

```powershell
$env:GOTOOLCHAIN='local'
$env:GOMAXPROCS='2'
go run ./scripts/capabilities -strict
```

## 状态汇总

| 状态 | 数量 | 含义 |
|---|---|---|
| `implemented` | 41 | 声明面全部在源码中解析到，且有定向测试证据 |
| `implemented_untested` | 0 | 声明面全部解析到，但缺少可核验的定向测试证据（未测，不是已完成） |
| `missing` | 0 | 至少一个声明面/测试/缺口证据未解析到（未实现或文档超前） |
| `unimplemented` | 1 | 已知未实现能力，缺口证据已核验（不得当作可用能力） |
| 合计 | 42 | 定向测试证据 154 条 |

## 能力矩阵

列值为「已解析/声明总数」；`-` 表示该层未声明。

| 能力 | 领域 | 状态 | 内部服务 | 公开 Go | 根包 | 管理 API | 协议 | CLI | 页面 | 权限 | 分页 | 定向测试 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `gap.unimplemented_permissions` 已知未实现权限键（settings.manage / diagnostics.read） | 已知缺口 | `unimplemented` | - | - | - | - | - | - | - | - | - | 无 |
| `access.joint_check` 令牌与当前权限联合校验 | 授权 | `implemented` | 2 | 7 | - | - | 1 | - | - | 1 | none | 2 |
| `account.lifecycle_public` 注册、资料与邮箱生命周期公开 Go 门面（步骤 221） | 账户 | `implemented` | 4 | 25 | - | - | - | - | - | - | none | 3 |
| `account.user_lifecycle_public` 用户生命周期、自有密码、邀请审批与批量导入公开门面（步骤 223） | 账户 | `implemented` | 5 | 44 | - | - | - | - | - | - | offset | 5 |
| `account.users` 用户查询、生命周期与批量导出 | 账户 | `implemented` | 4 | 3 | - | 2 | - | - | - | 8 | offset | 6 |
| `admin.facade_api` 受信管理 Go 门面（用户/资料/应用/角色/权限） | 管理 | `implemented` | - | 47 | - | - | - | - | - | 1 | offset | 4 |
| `admin.observability_lists` 审计/报告/任务/备份管理列表分页闭环（步骤 218） | 管理 | `implemented` | 5 | 27 | - | 1 | - | - | - | - | cursor | 4 |
| `adminapi.core` 管理 JSON API 基础端点、错误码与任务详情 | 管理 | `implemented` | 2 | - | 3 | 5 | - | - | - | - | fixed | 4 |
| `applications.manage` 应用、成员与应用凭证管理 | 授权 | `implemented` | 5 | 5 | - | 3 | - | - | - | 5 | offset | 5 |
| `applications.oauth_delegation_public` 应用生命周期、OAuth 客户端与应用成员委派公开门面（步骤 225） | 应用 | `implemented` | 5 | 36 | - | - | - | - | - | - | offset | 3 |
| `audit.events` 安全审计查询、导出与保留清理 | 审计与报告 | `implemented` | 2 | - | - | 3 | - | - | - | 3 | offset | 5 |
| `audit.reports_public` 审计查询、导出/清理与统计报告公开 Go 门面（步骤 230） | 审计与报告 | `implemented` | 4 | 52 | - | - | - | - | - | - | offset | 6 |
| `auth.password_session` 密码登录、会话校验与 CSRF | 认证与会话 | `implemented` | 3 | 8 | - | - | - | - | - | 1 | none | 4 |
| `backup.restore` 备份创建、校验、离线查看与恢复 | 备份与恢复 | `implemented` | 4 | - | - | 4 | - | 15 | - | 7 | offset | 4 |
| `bootstrap.root` 受控首次初始化与 root 自举 | 身份基础 | `implemented` | 2 | 3 | 1 | - | - | 1 | - | - | none | 4 |
| `cli.loginctl` 本地/在线管理 CLI（loginctl 命令组） | CLI | `implemented` | 1 | - | - | - | - | 23 | - | - | none | 4 |
| `config.load` YAML 配置加载、默认值、覆盖与校验 | 配置 | `implemented` | - | - | 5 | - | - | 1 | - | - | none | 3 |
| `device_code.login` 设备码登录（RFC 8628） | 协议 | `implemented` | 1 | - | - | - | 2 | - | - | - | none | 2 |
| `mail.delivery` 站内邮件投递队列与本地测试邮件服务 | 通知 | `implemented` | 3 | - | - | - | - | - | - | - | offset | 3 |
| `mfa.public_facade` 认证因素与安全中心公开 Go 门面（步骤 222） | 认证与会话 | `implemented` | 5 | 24 | - | - | - | - | - | 1 | fixed | 4 |
| `mfa.totp_recovery` 两步验证（TOTP/恢复代码）与受限恢复 | 认证与会话 | `implemented` | 3 | 13 | - | - | - | - | - | 1 | none | 5 |
| `oauth_oidc.protocol` OAuth2/OIDC 协议端点（授权码/刷新/撤销/内省/UserInfo） | 协议 | `implemented` | 5 | - | - | - | 7 | - | 1 | 1 | none | 4 |
| `onboarding.invitations` 邀请与审核注册 | 账户 | `implemented` | 1 | - | - | - | - | - | - | - | offset | 2 |
| `pagination.iteration` 有界分页遍历辅助（宿主/CLI 可选） | 分页与列表 | `implemented` | - | 4 | - | - | - | - | - | - | none | 13 |
| `passkey.webauthn` Passkey/WebAuthn 登录与凭证管理 | 认证与会话 | `implemented` | 1 | 2 | - | - | - | - | - | - | none | 2 |
| `passwordreset.self_service` 自助密码找回 | 恢复 | `implemented` | 1 | 5 | - | - | - | - | - | 1 | none | 3 |
| `qr_login.confirm` 已登录 APP 扫码登录与网页领取 | 协议 | `implemented` | 1 | - | - | - | 7 | - | - | - | none | 2 |
| `rbac.public_facade` 角色/用户组/权限/预设/委派/授权查询公开门面（步骤 224） | 授权 | `implemented` | 6 | 52 | - | - | - | - | - | - | offset | 5 |
| `rbac.roles_permissions` 用户组、角色、权限目录与委派 | 授权 | `implemented` | 4 | 14 | - | 11 | - | - | - | 8 | offset | 4 |
| `reports.generate` 统计报告生成、导出、计划与清理 | 审计与报告 | `implemented` | 1 | - | - | 6 | - | - | - | 5 | offset | 3 |
| `runtime.embedded` 嵌入式运行时装配（Open/Handler/Mount/生命周期） | 嵌入式与运行时 | `implemented` | 2 | 18 | 5 | - | - | 1 | - | - | none | 3 |
| `security.policy_reauth` 敏感操作安全策略与再次认证 | 认证与会话 | `implemented` | 4 | - | - | - | - | - | - | 1 | none | 3 |
| `session.admin` 管理员会话查询与强制下线 | 认证与会话 | `implemented` | 1 | 9 | - | 2 | - | - | - | 1 | offset | 3 |
| `stats.overview` 统计概览与健康状态 | 审计与报告 | `implemented` | 1 | - | - | - | - | - | - | - | fixed | 2 |
| `storage.sqlite_migrations` SQLite 存储、增量迁移与其他数据库方言适配 | 存储 | `implemented` | 6 | - | - | - | - | - | - | - | none | 3 |
| `support.recovery` 客服求助单、人工核验恢复与 root 本地应急 | 恢复 | `implemented` | 3 | - | - | 2 | - | 1 | 1 | 7 | offset | 4 |
| `tasks.scheduler` 后台任务执行器与计划调度 | 任务 | `implemented` | 2 | - | - | - | - | - | - | - | none | 2 |
| `token.jwt_keys` JWT 签发/验签、JWKS 与签名密钥轮换 | 协议 | `implemented` | 2 | - | - | - | 1 | - | - | - | none | 3 |
| `transport.http_security` HTTP 传输安全链（限流/CSRF/CORS/边界/错误信封/OpenAPI） | 传输 | `implemented` | 5 | - | 7 | - | - | - | - | - | none | 4 |
| `ui.admin_pages` 管理与客服页面框架（固定命名路由） | 页面 | `implemented` | 2 | - | - | - | - | - | 2 | - | fixed | 4 |
| `ui.public_pages` 公开与自助页面（登录/注册/找回/账户/错误页） | 页面 | `implemented` | 4 | - | 11 | - | - | - | 5 | - | fixed | 3 |
| `webhook.delivery` Webhook 端点、签名与投递重试 | 通知 | `implemented` | 1 | - | - | - | - | - | - | - | none | 2 |

### 声明面明细（逐项 found/total）

- `gap.unimplemented_permissions`: unimplemented_permission 2/2, matched_tests 无
- `access.joint_check`: internal_service 2/2, app_api 7/7, protocol_path 1/1, permission 1/1, test 2/2, matched_tests 2
- `account.lifecycle_public`: internal_service 4/4, app_api 25/25, test 3/3, matched_tests 3
- `account.user_lifecycle_public`: internal_service 5/5, app_api 44/44, test 4/4, matched_tests 5
- `account.users`: internal_service 4/4, app_api 3/3, admin_route 2/2, permission 8/8, test 6/6, matched_tests 6
- `admin.facade_api`: app_api 47/47, permission 1/1, test 4/4, matched_tests 4
- `admin.observability_lists`: internal_service 5/5, app_api 27/27, admin_route 1/1, test 4/4, matched_tests 4
- `adminapi.core`: internal_service 2/2, root_api 3/3, admin_route 5/5, test 4/4, matched_tests 4
- `applications.manage`: internal_service 5/5, app_api 5/5, admin_route 3/3, permission 5/5, test 5/5, matched_tests 5
- `applications.oauth_delegation_public`: internal_service 5/5, app_api 36/36, test 3/3, matched_tests 3
- `audit.events`: internal_service 2/2, admin_route 3/3, permission 3/3, test 4/4, matched_tests 5
- `audit.reports_public`: internal_service 4/4, app_api 52/52, test 6/6, matched_tests 6
- `auth.password_session`: internal_service 3/3, app_api 8/8, permission 1/1, test 4/4, matched_tests 4
- `backup.restore`: internal_service 4/4, admin_route 4/4, cli 15/15, permission 7/7, test 4/4, matched_tests 4
- `bootstrap.root`: internal_service 2/2, app_api 3/3, root_api 1/1, cli 1/1, test 4/4, matched_tests 4
- `cli.loginctl`: internal_service 1/1, cli 23/23, test 4/4, matched_tests 4
- `config.load`: root_api 5/5, cli 1/1, test 3/3, matched_tests 3
- `device_code.login`: internal_service 1/1, protocol_path 2/2, test 2/2, matched_tests 2
- `mail.delivery`: internal_service 3/3, test 3/3, matched_tests 3
- `mfa.public_facade`: internal_service 5/5, app_api 24/24, permission 1/1, test 4/4, matched_tests 4
- `mfa.totp_recovery`: internal_service 3/3, app_api 13/13, permission 1/1, test 5/5, matched_tests 5
- `oauth_oidc.protocol`: internal_service 5/5, protocol_path 7/7, page 1/1, permission 1/1, test 4/4, matched_tests 4
- `onboarding.invitations`: internal_service 1/1, test 2/2, matched_tests 2
- `pagination.iteration`: app_api 4/4, test 2/2, matched_tests 13
- `passkey.webauthn`: internal_service 1/1, app_api 2/2, test 2/2, matched_tests 2
- `passwordreset.self_service`: internal_service 1/1, app_api 5/5, permission 1/1, test 3/3, matched_tests 3
- `qr_login.confirm`: internal_service 1/1, protocol_path 7/7, test 2/2, matched_tests 2
- `rbac.public_facade`: internal_service 6/6, app_api 52/52, test 5/5, matched_tests 5
- `rbac.roles_permissions`: internal_service 4/4, app_api 14/14, admin_route 11/11, permission 8/8, test 4/4, matched_tests 4
- `reports.generate`: internal_service 1/1, admin_route 6/6, permission 5/5, test 3/3, matched_tests 3
- `runtime.embedded`: internal_service 2/2, app_api 18/18, root_api 5/5, cli 1/1, test 3/3, matched_tests 3
- `security.policy_reauth`: internal_service 4/4, permission 1/1, test 3/3, matched_tests 3
- `session.admin`: internal_service 1/1, app_api 9/9, admin_route 2/2, permission 1/1, test 3/3, matched_tests 3
- `stats.overview`: internal_service 1/1, test 2/2, matched_tests 2
- `storage.sqlite_migrations`: internal_service 6/6, test 3/3, matched_tests 3
- `support.recovery`: internal_service 3/3, admin_route 2/2, cli 1/1, page 1/1, permission 7/7, test 4/4, matched_tests 4
- `tasks.scheduler`: internal_service 2/2, test 2/2, matched_tests 2
- `token.jwt_keys`: internal_service 2/2, protocol_path 1/1, test 3/3, matched_tests 3
- `transport.http_security`: internal_service 5/5, root_api 7/7, test 4/4, matched_tests 4
- `ui.admin_pages`: internal_service 2/2, page 2/2, test 4/4, matched_tests 4
- `ui.public_pages`: internal_service 4/4, root_api 11/11, page 5/5, test 3/3, matched_tests 3
- `webhook.delivery`: internal_service 1/1, test 2/2, matched_tests 2


### 未关闭项（missing / unimplemented）

- **gap.unimplemented_permissions**（unimplemented）：已知未实现权限键（settings.manage / diagnostics.read）
  - 已知限制: settings.manage 与 diagnostics.read 只在权限目录登记，没有常规设置写入/运行诊断读取的服务端执行路径；不授予任何预设角色，也不能把页面/CLI 的本地受控操作当作该权限已接通。

## 反向覆盖（盘点到的生产面是否被能力声明覆盖）

| 生产面 | 盘点总数 | 未被声明覆盖 |
|---|---|---|
| app 公开类型 | 348 | 0 |
| 管理 API 路由 | 113 | 0 |
| 协议端点点位 | 17 | 0 |
| 页面命名路由 | 241 | 0 |
| CLI 子命令 | 40 | 0 |
| 内置权限键 | 51 | 0 |

## 分页审计

自动盘点 app 公开可增长列表的请求/结果边界，并核对各入口分页参数。`offset`/`cursor` 能力必须有“请求边界 + 结果继续”成对证据；`fixed`/`none` 与 `continuation=gap` 例外必须写明理由。

### 跨入口分页参数

| 入口 | 默认页大小 | 最大页大小 | offset 上限 | 备注 |
|---|---|---|---|---|
| app 公开契约 | 20 | 100 | 1000000 | 权威值 |
| internal/session | 20 | 100 | - | 领域列表 |
| internal/authz | 20 | 100 | - | 授权列表 |
| loginctl 列表 | 20 | 100 | 1000000 | CLI 帮助/参数 |
| 管理页面列表 | 20（固定） | - | 1000000 | 页面固定每页，无 limit 参数 |

### 可增长列表盘点

| 类型 | 类别 | 有界 | 能力 | 声明模式 | 继续字段 |
|---|---|---|---|---|---|
| `AdminApplicationList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminApplicationMemberList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminAuditEventList` | result | 是 | admin.observability_lists | cursor | HasMore,NextCursor |
| `AdminAuditExportList` | result | 是 | audit.reports_public | offset | HasMore,Page |
| `AdminAuditExportListRequest` | request | 是 | audit.reports_public | offset | - |
| `AdminAuditPurgeRunList` | result | 是 | audit.reports_public | offset | HasMore,Page |
| `AdminAuditPurgeRunListRequest` | request | 是 | audit.reports_public | offset | - |
| `AdminBackupArtifactList` | result | 是 | admin.observability_lists | cursor | HasMore,Page |
| `AdminBackupJobList` | result | 是 | admin.observability_lists | cursor | HasMore,Page |
| `AdminBackupNotificationList` | result | 是 | admin.observability_lists | cursor | HasMore,Page |
| `AdminBackupScheduleList` | result | 是 | admin.observability_lists | cursor | HasMore,Page |
| `AdminDelegationList` | result | 是 | applications.oauth_delegation_public | offset | HasMore,Page |
| `AdminErrorStatsRequest` | request | 是 | audit.reports_public | offset | - |
| `AdminErrorStatsResult` | result | 是 | audit.reports_public | offset | HasMore |
| `AdminGroupList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminGroupMemberList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminInvitationList` | result | 是 | account.user_lifecycle_public | offset | HasMore,Page |
| `AdminListApplicationGroupsRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListApplicationMembersRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListApplicationRolesRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListApplicationsRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListBackupArtifactsRequest` | request | 是 | admin.observability_lists | cursor | - |
| `AdminListBackupJobsRequest` | request | 是 | admin.observability_lists | cursor | - |
| `AdminListBackupNotificationsRequest` | request | 是 | admin.observability_lists | cursor | - |
| `AdminListBackupSchedulesRequest` | request | 是 | admin.observability_lists | cursor | - |
| `AdminListDelegationsRequest` | request | 是 | applications.oauth_delegation_public | offset | - |
| `AdminListGroupMembersRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListGroupsRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListInvitationsRequest` | request | 是 | account.user_lifecycle_public | offset | - |
| `AdminListPermissionsRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListRegistrationsRequest` | request | 是 | account.user_lifecycle_public | offset | - |
| `AdminListReportPlansRequest` | request | 是 | admin.observability_lists | cursor | - |
| `AdminListRolesRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListUserSessionsRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminListUsersRequest` | request | 是 | admin.facade_api | offset | - |
| `AdminPermissionList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminPermissionQuery` | request | 是 | rbac.roles_permissions | offset | - |
| `AdminRegistrationList` | result | 是 | account.user_lifecycle_public | offset | HasMore,Page |
| `AdminReportList` | result | 是 | admin.observability_lists | cursor | HasMore,NextCursor |
| `AdminReportPlanList` | result | 是 | admin.observability_lists | cursor | HasMore,Page |
| `AdminRoleAssignmentList` | result | 是 | admin.facade_api | offset | GroupPage,GroupsHasMore,UserPage,UsersHasMore |
| `AdminRoleList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminTaskList` | result | 是 | admin.observability_lists | cursor | HasMore,NextCursor |
| `AdminUserBatchJobList` | result | 是 | account.user_lifecycle_public | offset | HasMore,Page |
| `AdminUserBatchListJobsRequest` | request | 是 | account.user_lifecycle_public | offset | - |
| `AdminUserBatchPrecheckResult` | result | 是 | account.user_lifecycle_public | offset | Truncated |
| `AdminUserBatchRowList` | result | 是 | account.user_lifecycle_public | offset | Truncated |
| `AdminUserList` | result | 是 | admin.facade_api | offset | HasMore,Page |
| `AdminUserSessionList` | result | 是 | admin.facade_api | offset | HasMore,Page,Total |
| `IterationOptions` | request | 是 | pagination.iteration | none | - |
| `MFAFactorList` | result | 否 | mfa.public_facade | fixed | - |
| `MFAFactorListRequest` | request | 否 | mfa.public_facade | fixed | - |
| `MFAPasskeyListRequest` | request | 否 | mfa.public_facade | fixed | - |
| `RBACDelegationList` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `RBACDelegationListRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACEffectiveRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACEffectiveResult` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `RBACPermissionSourcesRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACPermissionSourcesResult` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `SessionDeviceList` | result | 是 | session.admin | offset | HasMore,Page,Total |
| `SessionDeviceRequest` | request | 是 | session.admin | offset | - |

### 分页例外（fixed/none 或 continuation=gap，需理由）

- IterationOptions -> pagination.iteration（none：由能力声明理由承担）
- MFAFactorList -> mfa.public_facade（fixed：由能力声明理由承担）
- MFAFactorListRequest -> mfa.public_facade（fixed：由能力声明理由承担）
- MFAPasskeyListRequest -> mfa.public_facade（fixed：由能力声明理由承担）

## 扫描口径与限制

- 扫描范围见 JSON `metadata.scan_scope`；跳过 `.ai/`、`docs/`、`scripts/`、`web/`、`migrations/`、`dist/`、`data/`，以及 `EvernightMail/`、`go-build-all/`、`examples/` 等嵌套 Module。
- 页面路由从 `UIRoute` 复合字面量盘点；动态生成或宿主替换的路由不在静态清单内。
- 协议端点表来自 `internal/protocolapi/doc.go` 的端点文档表；点位常量来自 `protocolapi.go`。文档表与代码漂移会体现为声明无法解析。
- 测试证据按「包路径 + 测试函数名前缀」解析，仅证明存在定向测试函数，不证明该测试当前通过；通过性需另行执行 `go test`（领域短测试可登记到统一入口 `scripts/shorttest.ps1`，见 `docs/acceptance/shorttest.md`）。

## 原始清单

机器可读原始盘点（app 公开面、管理路由、协议点位、页面路由、CLI、权限、测试）见同目录 `capability-matrix.json` 的 `inventories` 字段。
