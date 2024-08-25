# 公开 Go API 参考（Phase A：框架 + 稳定领域）

> 由 AST 扫描 `app/` 与根包公开符号生成。**Phase A 只交付框架与稳定领域**：每个服务接口的方法级参考（调用身份/应用范围/分页/取消/幂等/任务终态/错误/最小例）待 214/215（页面与 app 类型重组）及 226–235 公开门面稳定后由 Phase B 补齐。当前精确签名以 GoDoc 与源码为准。

## 1. 公开范围与生命周期契约

- **可导入包**：宿主只能导入模块根包（包名 `login`）与 `app` 包，以及 `access`、`extension`、`lifecycle`、`version`、`httpapi`、`httppolicy`、`netpolicy`、`proxytrust`、`passkeypolicy`、`ui`、`config`、`errs` 等公开叶子包；根包通过 `alias_*.go` 保留兼容别名（如 `UIRoute = ui.UIRoute`）。Go internal 规则禁止模块外导入 `internal/`。
- **页面契约**：214 起内置页面实现位于公开包 `ui/`，根包保留 `UIRoute`/`BuiltinUIRoutes` 等兼容别名；页面命名路由与来源见 [http-api.md](http-api.md) 第 4 节。
- **构造不启动**：`app.Open` 只构造运行时，不监听端口、不启动后台任务；后台任务必须由宿主显式 `Start`；`Close` 幂等，只关闭运行时自建资源，不关闭宿主注入的数据库/日志/通知器。
- **监听器归宿主**：运行时通过 `Handler`/`Mount`/`HTTPMounts` 暴露 HTTP；宿主自己的 `http.Server` 生命周期与优雅关闭由宿主负责。
- **调用身份**：`LocalAdmin` 仅代表持有宿主进程控制权的可信本地代码（不能由 HTTP 参数获得）；管理门面需要真实管理会话/CSRF；普通业务使用完整会话或受限会话，受限会话不得当登录成功。
- **错误与请求编号**：公开门面返回稳定错误码与 `request_id`；错误表见 [errors.md](errors.md)，HTTP 信封见 [http-api.md](http-api.md)。
- **分页/取消/幂等**：可增长列表在数据源处分页（默认/最大/排序白名单/稳定次序/HasMore 或游标）；长任务返回受理与任务 ID，受理不等于完成；敏感写操作需再次认证，重试不得绕过。
- **安全默认**：认证/授权/审计依赖失败时 fail-closed；来源地址必须来自可信边界；邮件测试只连本地捕获器；真实平台/客户端未实测的边界不写成已支持。

## 2. Runtime 公开方法（41 个）

| 方法 | 签名（不含接收者） | 说明 | 源码 |
|---|---|---|---|
| `Access` | `() AccessService` | Access 返回权限检查门面 | `app/runtime.go` |
| `Admin` | `() AdminService` | Admin 返回受信管理门面 | `app/runtime.go` |
| `AdminSession` | `(sessionSecret []byte) AdminCaller` | AdminSession 返回基于真实用户会话的管理调用者 | `app/admin_common.go` |
| `Applications` | `() ApplicationLifecycleService` | Applications 返回应用与成员管理公开门面 | `app/applications_public.go` |
| `Audit` | `() AuditService` | Audit 返回审计/运行诊断公开门面 | `app/audit_public.go` |
| `Auth` | `() AuthService` | Auth 返回登录门面 | `app/runtime.go` |
| `Backup` | `() BackupService` | Backup 返回备份公开服务（每个 Runtime 缓存同一门面，使恢复源加载在 Close 前后可用） | `app/backup_public.go` |
| `Bootstrap` | `() BootstrapService` | Bootstrap 返回首次初始化门面 | `app/runtime.go` |
| `Close` | `(ctx context.Context) error` | Close 幂等关闭本 Runtime 打开的资源（实例后台任务、任务运行时、数据库） | `app/runtime.go` |
| `Config` | `() login.Config` | Config 返回运行配置快照 | `app/runtime.go` |
| `Delegations` | `() DelegationAdminService` | Delegations 返回委派资格公开门面 | `app/delegations_public.go` |
| `Diagnostics` | `() DiagnosticsService` | Diagnostics 返回脱敏运行诊断门面（只读 | `app/diagnostics_public.go` |
| `EmailChange` | `() EmailChangeService` | EmailChange 返回邮箱变更公开门面 | `app/emailchange_public.go` |
| `HTTPMounts` | `() []string` | HTTPMounts 返回已挂载的协议/管理 API 站内路径（含前缀，供诊断/测试） | `app/runtime.go` |
| `HTTPPrefix` | `() string` | HTTPPrefix 返回 HTTP 处理器的规范化站内前缀（根路径为空字符串） | `app/runtime.go` |
| `Handler` | `() http.Handler` | Handler 返回与独立服务共用安全链的 HTTP 处理器 | `app/runtime.go` |
| `Instance` | `() *login.Instance` | Instance 返回构造完成但未启动的实例（Open 后 State=StateNew） | `app/runtime.go` |
| `Invitations` | `() InvitationAdminService` | Invitations 返回邀请与注册审核管理门面 | `app/invitations_public.go` |
| `LocalAdmin` | `() AdminCaller` | LocalAdmin 返回本机受信管理调用者：代表宿主进程（部署管理员，Options.OperatorID） | `app/admin_common.go` |
| `MFA` | `() MFAService` | MFA 返回认证因素管理门面（步骤 222）：脱敏因素清单、邮件因素启用/移除、Passkey | `app/runtime.go` |
| `ManualRecovery` | `() ManualRecoveryAdminService` | ManualRecovery 返回人工核验恢复公开门面 | `app/manualrecovery_public.go` |
| `Mount` | `(mux *http.ServeMux) (error)` | Mount 把已装配的 HTTP 处理器挂到宿主 *http.ServeMux 上：按固定前缀注册子树 | `app/runtime.go` |
| `OAuthClients` | `() OAuthClientAdminService` | OAuthClients 返回 OAuth 客户端公开门面 | `app/oauthclients_public.go` |
| `PasswordReset` | `() PasswordResetService` | PasswordReset 返回找回密码门面（邮件 token 发起/校验/完成） | `app/runtime.go` |
| `Passwords` | `() PasswordChangeService` | Passwords 返回本人受控改密门面 | `app/passwords_public.go` |
| `Profile` | `() ProfileService` | Profile 返回个人资料公开门面 | `app/profile_public.go` |
| `Protocol` | `() ProtocolService` | Protocol 返回 OAuth 协议受控查询门面 | `app/protocol_public.go` |
| `ProtocolRevocation` | `() ProtocolRevocationService` | ProtocolRevocation 返回 OAuth 撤销门面 | `app/protocol_revoke_public.go` |
| `RBAC` | `() RBACService` | RBAC 返回分组 RBAC 公开服务 | `app/rbac_public.go` |
| `Ready` | `(ctx context.Context) error` | Ready 检查运行时是否可以对外服务：必须已成功 Start | `app/runtime.go` |
| `Registration` | `() RegistrationService` | Registration 返回注册与邮箱验证公开门面 | `app/registration_public.go` |
| `Reports` | `() ReportsService` | Reports 返回报告公开门面 | `app/reports_public.go` |
| `Security` | `() SecurityService` | Security 返回认证/安全设置门面（TOTP 绑定、恢复代码、能力状态） | `app/runtime.go` |
| `Sessions` | `() SessionService` | Sessions 返回会话撤销门面 | `app/runtime.go` |
| `Settings` | `() SettingsService` | Settings 返回受控配置管理服务 | `app/settings_public.go` |
| `Start` | `(ctx context.Context) error` | Start 显式启动允许的后台任务（任务执行器与定时计划调度器） | `app/runtime.go` |
| `State` | `() login.State` | State 返回显式生命周期状态：new（已构造未启动）/running（任务已启动）/closed | `app/runtime.go` |
| `Support` | `() SupportAdminService` | Support 返回客服求助单公开门面 | `app/support_public.go` |
| `UserBatch` | `() UserBatchService` | UserBatch 返回用户批量管理门面 | `app/userbatch_public.go` |
| `UserLifecycle` | `() UserLifecycleService` | UserLifecycle 返回用户生命周期管理门面 | `app/users_public.go` |
| `Users` | `() UserService` | Users 返回用户门面 | `app/runtime.go` |

## 3. 公开服务接口总览（39 个接口 / 262 个方法）

| 接口 | 方法数 | 方法名 | 说明 | 源码 |
|---|---|---|---|---|
| `AccessService` | 1 | `Check` | AccessService 是联合权限检查门面 | `app/public_access.go` |
| `AdminService` | 36 | `AddApplicationMember`、`AddRolePermission`、`CheckPermission`、`CreateApplication`、`CreatePermission`、`CreateRole`、`CreateUser`、`EffectivePermissions`、`GetUserByUsername`、`GetUserProfile`、`GrantApplicationRole`、`GrantDelegation`、`ListApplicationGroups`、`ListApplicationMembers`、`ListApplicationRoles`、`ListApplications`、`ListAuditEvents`、`ListBackupArtifacts`、`ListBackupJobs`、`ListBackupNotifications`、`ListBackupSchedules`、`ListGroupMembers`、`ListGroups`、`ListPermissions`、`ListReportPlans`、`ListReports`、`ListRoleAssignments`、`ListRolePermissions`、`ListRoles`、`ListTasks`、`ListUserSessions`、`ListUsers`、`RevokeApplicationRole`、`RevokeUserSessions`、`SetApplicationEnabled`、`UpdateUserProfile` | AdminService 是受信管理门面：用户/资料/应用/角色/权限的受控管理操作 | `app/public_admin_users.go` |
| `ApplicationLifecycleService` | 10 | `DeleteApplication`、`DisableApplicationMember`、`EnableApplicationMember`、`GetApplication`、`GetApplicationMember`、`PreviewApplicationDeletion`、`PurgeApplication`、`RemoveApplicationMember`、`UpdateApplication`、`UpdateApplicationMemberProfile` | ApplicationLifecycleService 是应用与成员管理公开门面 | `app/applications_public.go` |
| `AuditService` | 18 | `CancelExport`、`CancelPurge`、`CancelTask`、`ErrorStats`、`GetEvent`、`GetExport`、`GetPurgeRun`、`GetTask`、`ListExports`、`ListPurgeRuns`、`ListTaskAttempts`、`OpenExport`、`PreviewPurge`、`Query`、`Retention`、`SetRetention`、`StartExport`、`StartPurge` | AuditService 是审计查询、错误分类统计、导出、清理/保留策略与后台任务运行诊断 | `app/audit_public.go` |
| `AuthService` | 4 | `BeginRecovery`、`Login`、`RecoveryStatus`、`VerifySecondFactor` | AuthService 是认证门面：密码第一步 + 第二因素/受限恢复验证 | `app/public_auth.go` |
| `BackupArtifactService` | 4 | `Check`、`Export`、`Get`、`List` | BackupArtifactService 是备份产物查看/认证检查/受控导出服务 | `app/backup_public.go` |
| `BackupJobService` | 4 | `Cancel`、`Get`、`List`、`Trigger` | BackupJobService 是备份任务触发/查询/取消服务 | `app/backup_public.go` |
| `BackupPlanService` | 6 | `Create`、`Delete`、`Get`、`List`、`SetEnabled`、`Update` | BackupPlanService 是备份计划管理服务（计划由真实任务调度器触发，本层不执行业务） | `app/backup_public.go` |
| `BackupRecoveryService` | 8 | `Configure`、`EnterMaintenance`、`Execute`、`ExitMaintenance`、`Initialize`、`LoadBackup`、`Rehearse`、`Status` | BackupRecoveryService 是仅受控本地可执行的备份检查/恢复/维护服务 | `app/backup_recovery.go` |
| `BackupService` | 4 | `Artifacts`、`Jobs`、`Plans`、`Recovery` | BackupService 是备份公开服务入口 | `app/backup_public.go` |
| `BootstrapService` | 1 | `EnsureRoot` | BootstrapService 是首次初始化门面 | `app/public_auth.go` |
| `DelegationAdminService` | 4 | `DelegatablePermissions`、`GetDelegation`、`ListDelegations`、`RevokeDelegation` | DelegationAdminService 是委派资格读取/撤回/可转授权限查询门面 | `app/delegations_public.go` |
| `DiagnosticsService` | 3 | `Export`、`Read`、`RelatedErrors` | DiagnosticsService 是脱敏运行诊断公开门面 | `app/diagnostics_public.go` |
| `EmailChangeService` | 4 | `Cancel`、`Request`、`State`、`Verify` | EmailChangeService 是邮箱变更公开门面 | `app/emailchange_public.go` |
| `InvitationAdminService` | 8 | `ApproveRegistration`、`CancelInvitation`、`CreateInvitation`、`GetInvitation`、`GetRegistration`、`ListInvitations`、`ListPendingRegistrations`、`RejectRegistration` | InvitationAdminService 是邀请与注册审核管理门面 | `app/invitations_public.go` |
| `MFAService` | 13 | `BeginEmailEnrollment`、`BeginPasskeyLogin`、`BeginPasskeyRegistration`、`ConfirmEmailEnrollment`、`FinishPasskeyLogin`、`FinishPasskeyRegistration`、`List`、`ListPasskeys`、`RecoveryCodes`、`RemoveEmail`、`RemovePasskey`、`RemoveTOTP`、`RenamePasskey` | MFAService 是认证因素管理门面（步骤 222） | `app/mfa_public.go` |
| `ManualRecoveryAdminService` | 10 | `Approve`、`Cancel`、`Create`、`Execute`、`GetApproval`、`GetExecution`、`GetRequest`、`List`、`Policy`、`Reject` | ManualRecoveryAdminService 是人工核验恢复公开门面 | `app/manualrecovery_public.go` |
| `OAuthClientAdminService` | 9 | `GetClient`、`ListClientCertificates`、`ListClientSecrets`、`RegisterClient`、`RegisterClientCertificate`、`RevokeClientCertificate`、`RevokeClientSecret`、`RotateClientSecret`、`UpdateClientSettings` | OAuthClientAdminService 是 OAuth 客户端凭证/安全设置公开门面 | `app/oauthclients_public.go` |
| `PasswordChangeService` | 1 | `ChangeOwnPassword` | PasswordChangeService 是本人受控改密门面 | `app/passwords_public.go` |
| `PasswordResetService` | 4 | `Complete`、`Request`、`ValidateToken`、`ValidateTokenWithSource` | PasswordResetService 是找回密码公开门面 | `app/passwordreset.go` |
| `ProfileService` | 3 | `ChangeUsername`、`GetProfile`、`UpdateProfile` | ProfileService 是个人资料公开门面 | `app/profile_public.go` |
| `ProtocolRevocationService` | 3 | `Logout`、`RevokeAuthorization`、`RevokeToken` | ProtocolRevocationService 是 OAuth 令牌/授权撤销的受控 Go 门面 | `app/protocol_revoke_public.go` |
| `ProtocolService` | 1 | `IntrospectToken` | ProtocolService 是 OAuth 协议受控 Go 状态查询门面 | `app/protocol_public.go` |
| `RBACAuthorizationService` | 4 | `Check`、`CheckResourceAccess`、`EffectivePermissions`、`PermissionSources` | RBACAuthorizationService 是有效权限/来源/资源级授权查询服务 | `app/rbac_authorization.go` |
| `RBACDelegationService` | 5 | `DelegatablePermissions`、`Get`、`Grant`、`List`、`Revoke` | RBACDelegationService 是可转授资格管理服务 | `app/rbac_delegations.go` |
| `RBACGroupService` | 8 | `AddMembers`、`Create`、`Delete`、`Get`、`List`、`ListMembers`、`RemoveMembers`、`Update` | RBACGroupService 是用户组与组成员批量变更服务 | `app/rbac_groups.go` |
| `RBACPermissionService` | 8 | `Catalog`、`Create`、`Delete`、`Disable`、`Enable`、`Get`、`List`、`Update` | RBACPermissionService 是权限目录生命周期与中文说明服务 | `app/rbac_permissions.go` |
| `RBACPresetService` | 3 | `Catalog`、`Preview`、`Restore` | RBACPresetService 是预设目录与恢复服务 | `app/rbac_presets.go` |
| `RBACRoleService` | 15 | `AddPermission`、`AssignGroup`、`AssignUser`、`Create`、`Delete`、`Disable`、`Enable`、`Get`、`List`、`ListAssignments`、`ListPermissions`、`RemovePermission`、`RevokeGroup`、`RevokeUser`、`Update` | RBACRoleService 是角色生命周期、权限组合与分配服务 | `app/rbac_roles.go` |
| `RBACService` | 6 | `Authorization`、`Delegations`、`Groups`、`Permissions`、`Presets`、`Roles` | RBACService 是分组清楚的 RBAC 公开服务入口 | `app/rbac_public.go` |
| `RegistrationService` | 5 | `Availability`、`RegisterAccount`、`ResendEmailVerification`、`SendEmailVerification`、`VerifyEmail` | RegistrationService 是注册与邮箱验证公开门面 | `app/registration_public.go` |
| `ReportsService` | 8 | `Cancel`、`Capabilities`、`CleanupExecute`、`CleanupPreview`、`Get`、`OpenArtifact`、`Retry`、`Start` | ReportsService 是统计报告生成与受控产物的公开门面 | `app/reports_public.go` |
| `SecurityService` | 4 | `BeginTOTPBinding`、`ConfirmTOTPBinding`、`GenerateRecoveryCodes`、`Status` | SecurityService 是认证/安全设置门面：敏感操作经真实再次认证后执行 | `app/public_security.go` |
| `SessionService` | 7 | `Authorize`、`ListDevices`、`Revoke`、`RevokeDevice`、`RevokeOtherDevices`、`Validate`、`ValidateCSRF` | SessionService 会话语义：校验当前会话、应用+权限联合检查、撤销当前会话 | `app/public_session.go` |
| `SettingsService` | 5 | `Fields`、`RestoreSensitiveDefaults`、`Status`、`Update`、`Validate` | SettingsService 是受认证、按字段白名单的配置查询/校验/变更/状态服务 | `app/settings_public.go` |
| `SupportAdminService` | 8 | `CreateCase`、`GetCase`、`ListCases`、`ListEvents`、`LookupTarget`、`ReassignCase`、`SendReset`、`TransitionCase` | SupportAdminService 是客服求助单公开门面 | `app/support_public.go` |
| `UserBatchService` | 8 | `CancelJob`、`GetJob`、`ListJobs`、`ListRows`、`PrecheckImport`、`RetryJob`、`StartExport`、`StartImport` | UserBatchService 是用户批量管理门面（最小闭环） | `app/userbatch_public.go` |
| `UserLifecycleService` | 8 | `CompleteUserDeletion`、`DisableUser`、`EnableUser`、`GetUser`、`GetUserValidity`、`PreviewUserDeletion`、`RequestUserDeletion`、`SetUserValidity` | UserLifecycleService 是用户生命周期管理门面（按稳定 ID 读取、禁用/启用、 | `app/users_public.go` |
| `UserService` | 1 | `Create` | UserService 是宿主受信用户门面 | `app/public_users.go` |

## 4. app 包公开函数（6 个）

| 函数 | 签名 | 说明 | 源码 |
|---|---|---|---|
| `AsNotFound` | `(err error) (*NotFoundError, bool)` | AsNotFound 在错误链中查找 NotFoundError | `app/errors.go` |
| `IsNotFound` | `(err error) bool` | IsNotFound 判断错误链是否表示“已授权但目标不存在” | `app/errors.go` |
| `IterateAdminPages` | `(ctx context.Context, options IterationOptions, fetch func(ctx context.Context, page AdminPage) (items []T, info AdminPageInfo, err error), visit func(ctx context.Context, info AdminPageInfo, items []T) error) (IterationResult, error)` | IterateAdminPages 按 AdminPage 契约有界遍历列表 | `app/iterate.go` |
| `NewAdminPageInfo` | `(page AdminPage, returned int, hasMore bool) AdminPageInfo` | NewAdminPageInfo 构造分页结果元数据 | `app/pagination.go` |
| `NormalizeAdminPage` | `(page AdminPage) (AdminPage, error)` | NormalizeAdminPage 规范化公开分页输入：零值使用默认每页条数 | `app/pagination.go` |
| `Open` | `(ctx context.Context, opts Options) (*Runtime, error)` | Open 构造真实服务运行时：配置/主密钥环/SQLite/迁移策略/审计/领域服务/敏感闸门/ | `app/runtime.go` |

### 4.1 app 包公开变量/常量（17 个）

| 名称 | 类别 | 说明 | 源码 |
|---|---|---|---|
| `AdminDefaultPageLimit` | const | AdminDefaultPageLimit 是公开管理列表默认每页条数 | `app/pagination.go` |
| `AdminMaxCursorBytes` | const | AdminMaxCursorBytes 是调用方可回传游标的最大长度（防御性上限） | `app/pagination_cursor.go` |
| `AdminMaxPageLimit` | const | AdminMaxPageLimit 是公开管理列表允许的最大每页条数 | `app/pagination.go` |
| `AdminMaxPageOffset` | const | AdminMaxPageOffset 是 offset 分页允许的最大偏移（深分页上限） | `app/pagination.go` |
| `DefaultIterationMaxItems` | const | DefaultIterationMaxItems 是未显式设置 MaxItems 时的默认最大处理条目数 | `app/iterate.go` |
| `DefaultIterationMaxPages` | const | DefaultIterationMaxPages 是未显式设置 MaxPages 时的默认最大页数 | `app/iterate.go` |
| `ErrNotFound` | var | ErrNotFound 是公开门面未找到语义的稳定哨兵 | `app/errors.go` |
| `ErrPageNotAdvancing` | var | ErrPageNotAdvancing 表示分页没有可靠前进：重复/回退 offset、空页却声明有更多、 | `app/iterate.go` |
| `IterationStopComplete` | const | IterationStopComplete 表示已到达列表末尾（HasMore=false） | `app/iterate.go` |
| `IterationStopContextCanceled` | const | IterationStopContextCanceled 表示 context 被取消/超时后停止 | `app/iterate.go` |
| `IterationStopFetchError` | const | IterationStopFetchError 表示某页读取失败后停止 | `app/iterate.go` |
| `IterationStopMaxItems` | const | IterationStopMaxItems 表示达到调用方/默认最大条目数而提前停止（可能截断 | `app/iterate.go` |
| `IterationStopMaxPages` | const | IterationStopMaxPages 表示达到调用方/默认最大页数而提前停止 | `app/iterate.go` |
| `IterationStopVisitError` | const | IterationStopVisitError 表示访问回调返回错误后停止 | `app/iterate.go` |
| `MaxIterationMaxItems` | const | MaxIterationMaxItems 是调用方允许设置的最大条目数上限 | `app/iterate.go` |
| `MaxIterationMaxPages` | const | MaxIterationMaxPages 是调用方允许设置的最大页数上限 | `app/iterate.go` |
| `NotFoundCode` | const | NotFoundCode 是公开门面“已通过调用身份与权限检查、但目标记录不存在”的稳定 | `app/errors.go` |

## 5. app 包公开类型（451 个）

| 类别 | 数量 |
|---|---|
| interface | 39 |
| struct | 412 |

按源码文件分布（完整类型名与字段请用 `go doc ./app` 或 GoDoc 查询；Phase B 将按领域展开关键类型字段与边界）：

| 源码文件 | 导出类型数 |
|---|---|
| `app/applications_public.go` | 13 |
| `app/audit_public.go` | 31 |
| `app/backup_public.go` | 17 |
| `app/backup_recovery.go` | 15 |
| `app/delegations_public.go` | 8 |
| `app/diagnostics_public.go` | 13 |
| `app/emailchange_public.go` | 7 |
| `app/errors.go` | 1 |
| `app/invitations_public.go` | 16 |
| `app/iterate.go` | 2 |
| `app/manualrecovery_public.go` | 14 |
| `app/mfa_public.go` | 23 |
| `app/oauthclients_public.go` | 12 |
| `app/options.go` | 1 |
| `app/pagination.go` | 2 |
| `app/passwordreset.go` | 5 |
| `app/passwords_public.go` | 3 |
| `app/profile_public.go` | 5 |
| `app/protocol_public.go` | 3 |
| `app/protocol_revoke_public.go` | 5 |
| `app/public_access.go` | 3 |
| `app/public_admin_apps.go` | 12 |
| `app/public_admin_observability.go` | 25 |
| `app/public_admin_rbac.go` | 25 |
| `app/public_admin_users.go` | 20 |
| `app/public_auth.go` | 14 |
| `app/public_http.go` | 2 |
| `app/public_security.go` | 7 |
| `app/public_session.go` | 12 |
| `app/public_users.go` | 3 |
| `app/rbac_authorization.go` | 12 |
| `app/rbac_delegations.go` | 7 |
| `app/rbac_groups.go` | 6 |
| `app/rbac_permissions.go` | 6 |
| `app/rbac_presets.go` | 10 |
| `app/rbac_public.go` | 4 |
| `app/rbac_roles.go` | 6 |
| `app/registration_public.go` | 10 |
| `app/reports_public.go` | 19 |
| `app/runtime.go` | 1 |
| `app/settings_public.go` | 13 |
| `app/support_public.go` | 14 |
| `app/userbatch_public.go` | 15 |
| `app/users_public.go` | 6 |
| `app/validity_public.go` | 3 |

## 6. 根包公开函数（38 个；另含公开类型 441 个）

| 函数 | 签名 | 说明 | 源码 |
|---|---|---|---|
| `AsAppError` | `(err error) (*AppError, bool)` | AsAppError 在原因链中查找 *AppError | `alias_errs.go` |
| `BuiltinUIRoutes` | `() []ui.UIRoute` | BuiltinUIRoutes 转发到 ui.BuiltinUIRoutes | `alias_ui.go` |
| `ClientServiceIdentityFromContext` | `(ctx context.Context) (string, bool)` | ClientServiceIdentityFromContext 返回独立监听的 mTLS 边界验证并显式映射后的 | `http.go` |
| `CurrentBuildInfo` | `() buildversion.BuildInfo` | CurrentBuildInfo 返回当前运行二进制的版本信息 | `version.go` |
| `Default` | `() Config` | Default 返回安全默认配置 | `alias_config.go` |
| `DefaultCookiePolicy` | `() CookiePolicy` | DefaultCookiePolicy 返回会话 Cookie 的安全默认值（唯一实现见 httpapi） | `alias_http.go` |
| `DefaultRateLimitOptions` | `() RateLimitOptions` | DefaultRateLimitOptions 返回安全默认多维限流配置（唯一实现见 httpapi） | `alias_http.go` |
| `DiffReload` | `(previous, next Config) ReloadDiff` | DiffReload 计算两次有效配置之间按热重载分类的差异 | `alias_config.go` |
| `ErrorCodeOf` | `(err error) (ErrorCode, bool)` | ErrorCodeOf 返回原因链中第一个 AppError 的错误码 | `alias_errs.go` |
| `Fields` | `() []FieldInfo` | Fields 返回按手册顺序排列的全部配置字段元数据副本 | `alias_config.go` |
| `FromError` | `(err error) *AppError` | FromError 把任意错误转为 *AppError | `alias_errs.go` |
| `IdentityFromContext` | `(ctx context.Context) (Identity, bool)` | IdentityFromContext 返回 HTTP Handler 或宿主中间件放入请求上下文的可信身份 | `http.go` |
| `IsErrorCode` | `(err error, code ErrorCode) bool` | IsErrorCode 报告原因链中是否存在指定错误码 | `alias_errs.go` |
| `Load` | `(options LoadOptions) (Config, error)` | Load 按默认值→YAML→环境变量→显式覆盖的顺序加载并严格校验配置 | `alias_config.go` |
| `LookupErrorCode` | `(code ErrorCode) (ErrorCodeDefinition, bool)` | LookupErrorCode 查询错误码定义 | `alias_errs.go` |
| `LookupErrorCodeGuidance` | `(code ErrorCode) (ErrorCodeGuidance, bool)` | LookupErrorCodeGuidance 查询错误码排障指引 | `alias_errs.go` |
| `LookupField` | `(path string) (FieldInfo, bool)` | LookupField 按点分字段路径查找字段元数据 | `alias_config.go` |
| `New` | `(opts Options) (*Instance, error)` | New 构造一个 Instance，但不启动任何组件、不监听端口、不打开数据库、不创建 | `instance.go` |
| `NewAppError` | `(code ErrorCode, message string, options ...ErrorOption) *AppError` | NewAppError 构造统一错误（未注册码回退 INTERNAL_ERROR） | `alias_errs.go` |
| `NewHTTPHandler` | `(options HTTPOptions) (http.Handler, error)` | NewHTTPHandler 构造标准 net/http Handler | `http.go` |
| `NewRequestID` | `() string` | NewRequestID 生成可对外返回的请求编号 | `alias_errs.go` |
| `NewSecret` | `(value []byte) Secret` | NewSecret 用字节构造可遮盖的秘密值 | `alias_config.go` |
| `NewSecretString` | `(value string) Secret` | NewSecretString 用字符串构造可遮盖的秘密值 | `alias_config.go` |
| `NewServer` | `(options ServerOptions) (*Server, error)` | NewServer 校验选项并构造监听服务，但不绑定任何端口、不创建协程 | `server.go` |
| `NormalizeTLSClientAuthMode` | `(mode TLSClientAuthMode) TLSClientAuthMode` | NormalizeTLSClientAuthMode 把空字符串归一为 disabled | `alias_config.go` |
| `OpenAPIDocument` | `(prefix string) ([]byte, error)` | OpenAPIDocument 生成指定路径前缀的机器可读 OpenAPI 文档 | `http.go` |
| `ParseSecretSource` | `(spec string) (SecretSource, error)` | ParseSecretSource 解析秘密来源描述（env:VAR 或 file:PATH） | `alias_config.go` |
| `Ptr` | `(v T) *T` | Ptr 返回值的指针，便于表达显式覆盖 | `alias_config.go` |
| `RegisteredErrorCodes` | `() []ErrorCodeDefinition` | RegisteredErrorCodes 返回按手册顺序排列的全部错误码定义副本 | `alias_errs.go` |
| `RequestIDFromContext` | `(ctx context.Context) string` | RequestIDFromContext 返回当前请求的查询编号 | `http.go` |
| `ValidateCorrelationID` | `(label, id string) error` | ValidateCorrelationID 校验通用关联标识（扩展名等） | `alias_errs.go` |
| `ValidateRequestID` | `(id string) error` | ValidateRequestID 校验请求编号格式 | `alias_errs.go` |
| `ValidateTaskID` | `(id string) error` | ValidateTaskID 校验任务编号格式（规则与请求编号相同） | `alias_errs.go` |
| `WithCause` | `(err error) ErrorOption` | WithCause 设置内部原因（不进入公开输出） | `alias_errs.go` |
| `WithIdentity` | `(ctx context.Context, identity Identity) (context.Context, error)` | WithIdentity 把已由可信边界建立的身份放入上下文，供宿主或测试中间件使用 | `http.go` |
| `WithInternalReasonCode` | `(code string) ErrorOption` | WithInternalReasonCode 设置受限内部原因码 | `alias_errs.go` |
| `WithRequestID` | `(id string) ErrorOption` | WithRequestID 设置请求编号（非法编号被忽略） | `alias_errs.go` |
| `WithTaskID` | `(id string) ErrorOption` | WithTaskID 设置任务编号（非法编号被忽略） | `alias_errs.go` |

### 6.1 根包公开符号按源文件分布（10 个文件）

| 源文件 | 类型 | 函数 | 常量/变量 |
|---|---|---|---|
| `alias_config.go` | 40 | 10 | 36 |
| `alias_contracts.go` | 22 | 0 | 24 |
| `alias_errs.go` | 6 | 16 | 77 |
| `alias_http.go` | 21 | 2 | 20 |
| `alias_ui.go` | 350 | 1 | 50 |
| `embed.go` | 0 | 0 | 2 |
| `http.go` | 0 | 6 | 0 |
| `instance.go` | 1 | 1 | 2 |
| `server.go` | 1 | 1 | 0 |
| `version.go` | 0 | 1 | 1 |

## 7. Phase B 待补领域

| 领域 | 待补内容 | 涉及接口数 |
|---|---|---|
| auth-session-mfa | 认证、会话、安全与 MFA 领域的方法级参考待 Phase B | 8 |
| users-account | 账户、资料、密码、注册、邀请、批量与有效期领域的方法级参考待 Phase B | 8 |
| rbac-applications | RBAC、应用、OAuth 客户端与委派领域的方法级参考待 Phase B | 8 |
| audit-reports | 审计与报告领域的方法级参考待 Phase B | 2 |
| backup-restore | 备份、恢复与任务领域的方法级参考待 Phase B | 6 |
| ops-diagnostics | 运维、诊断、设置、客服与协议管理领域的方法级参考待 Phase B | 6 |
| misc-interfaces | 未归类接口（Phase B 复核领域映射）：AdminService | 1 |

## 8. 最小可编译示例

Phase A 的最小可编译示例只依赖公开叶子包（避免随根包/UI 重构反复失配）：错误码用法见 [errors.md](errors.md) 第 3 节，配置字段用法见 [configuration.md](configuration.md) 第 3 节。运行时门面（`app.Open` → `Start` → `Mount` → `Close`）的完整可运行示例见 [examples/embedded-minimal](../../examples/embedded-minimal/)；Phase B 会把方法级调用例内嵌到本页。

## 9. 相关文档

- 公开 API 稳定范围、破坏性变更策略与生命周期细节：[../embedding/host_integration.md](../embedding/host_integration.md)
- 嵌入模式入口与示例：[../embedding/README.md](../embedding/README.md)
- GoDoc/OpenAPI 现状与错误约定：[../guide/api-status.md](../guide/api-status.md)
- 公开错误码：[errors.md](errors.md)；权限目录：[permissions.md](permissions.md)；配置：[configuration.md](configuration.md)。
