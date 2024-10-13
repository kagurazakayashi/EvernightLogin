# EvernightLogin 机器可读能力清单

> 本文件由 `go run ./scripts/capabilities` 从源码与能力声明自动生成，**不要手工编辑**。状态由「声明面是否在源码中真实解析到」决定，不是文档声称。

## 生成基线

| 项 | 值 |
|---|---|
| 生成时间（UTC） | 2026-11-27T03:01:40Z |
| 仓库 | . |
| Git HEAD / 分支 | `faa011a4cd9fe0d8b25ed60cd9231cffcd0c2f70` / `main`（工作树含未提交修改） |
| 工具链 / 平台 | go1.27.4 / windows/amd64 |
| 逻辑处理器 / 并发预算 | 16 / 8 |
| 能力声明 | `scripts/capabilities/catalog.json` |
| 扫描文件数 | 843 |

复跑命令（根目录，Windows PowerShell 示例）：

```powershell
$env:GOTOOLCHAIN='local'
$env:GOMAXPROCS='2'
go run ./scripts/capabilities -strict
go run ./scripts/capabilities -check   # 只读校验（不写 tracked 文件，EXIT 4=不一致）
```

## 状态汇总

| 状态 | 数量 | 含义 |
|---|---|---|
| `implemented` | 49 | 声明面全部在源码中解析到，且有定向测试证据 |
| `implemented_untested` | 0 | 声明面全部解析到，但缺少可核验的定向测试证据（未测，不是已完成） |
| `partial` | 3 | 声明面与测试解析到，但有已登记的产品缺口/环境未测/子模块阻塞（不能当作全部完成） |
| `missing` | 0 | 至少一个声明面/测试/缺口证据未解析到（未实现或文档超前） |
| `unimplemented` | 1 | 已知未实现能力，缺口证据已核验（不得当作可用能力） |
| 合计 | 53 | 定向测试证据 241 条 |

证据分级（步骤 267，防止“符号存在=完成”）：

| 分类 | 数量 |
|---|---|
| 正向证据（真实成功链证据文件标记） | 8 |
| 拒绝证据（真实越权/失败链证据文件标记） | 8 |
| 环境未测能力（真实硬件/非 SQLite/外部服务等） | 2 |
| 子模块/远端不可获取能力 | 1 |

## 能力矩阵

列值为「已解析/声明总数」；`-` 表示该层未声明。

| 能力 | 领域 | 状态 | 内部服务 | 公开 Go | 根包 | 管理 API | 协议 | CLI | 页面 | 权限 | 分页 | 定向测试 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `preset.install_gap` 预设安装生产入口缺口（D-252-1） | 授权 | `unimplemented` | - | - | - | - | - | - | - | - | - | 无 |
| `access.joint_check` 令牌与当前权限联合校验 | 授权 | `implemented` | 2 | 7 | - | - | 1 | - | - | 1 | none | 2 |
| `account.lifecycle_221_remaining` 221 范围的剩余入口（R10-22，部分完成） | 账户 | `partial` | - | - | - | - | - | - | - | - | - | 无 |
| `account.lifecycle_public` 注册、资料与邮箱生命周期公开 Go 门面（步骤 221） | 账户 | `implemented` | 4 | 25 | - | - | - | - | - | - | none | 3 |
| `account.user_lifecycle_public` 用户生命周期、自有密码、邀请审批与批量导入公开门面（步骤 223） | 账户 | `implemented` | 5 | 49 | - | - | - | - | - | - | offset | 7 |
| `account.users` 用户查询、生命周期与批量导出 | 账户 | `implemented` | 4 | 3 | - | 2 | - | - | - | 8 | offset | 6 |
| `admin.facade_api` 受信管理 Go 门面（用户/资料/应用/角色/权限） | 管理 | `implemented` | - | 47 | - | - | - | - | - | 1 | offset | 4 |
| `admin.observability_lists` 审计/报告/任务/备份管理列表分页闭环（步骤 218） | 管理 | `implemented` | 5 | 27 | - | 1 | - | - | - | - | cursor | 4 |
| `adminapi.core` 管理 JSON API 基础端点、错误码与任务详情 | 管理 | `implemented` | 2 | - | 3 | 5 | - | - | - | - | fixed | 4 |
| `applications.manage` 应用、成员与应用凭证管理 | 授权 | `implemented` | 5 | 5 | - | 3 | - | - | - | 5 | offset | 5 |
| `applications.oauth_delegation_public` 应用生命周期、OAuth 客户端与应用成员委派公开门面（步骤 225） | 应用 | `implemented` | 5 | 36 | - | - | - | - | - | - | offset | 3 |
| `audit.events` 安全审计查询、导出与保留清理 | 审计与报告 | `implemented` | 2 | - | - | 3 | - | - | - | 3 | offset | 5 |
| `audit.reports_public` 审计查询、导出/清理与统计报告公开 Go 门面（步骤 230） | 审计与报告 | `implemented` | 4 | 52 | - | - | - | - | - | - | offset | 6 |
| `auth.password_session` 密码登录、会话校验与 CSRF | 认证与会话 | `implemented` | 3 | 8 | - | - | - | - | - | 1 | none | 4 |
| `backup.restore` 备份创建、校验、离线查看与恢复 | 备份与恢复 | `implemented` | 4 | 59 | - | 4 | - | 15 | - | 7 | offset | 14 |
| `bootstrap.root` 受控首次初始化与 root 自举 | 身份基础 | `implemented` | 2 | 3 | 1 | - | - | 1 | - | - | none | 4 |
| `cli.loginctl` 本地/在线管理 CLI（loginctl 命令组） | CLI | `implemented` | 1 | - | - | - | - | 23 | - | - | none | 4 |
| `config.load` YAML 配置加载、默认值、覆盖与校验 | 配置 | `implemented` | - | - | 5 | - | - | 1 | - | - | none | 3 |
| `device_code.login` 设备码登录（RFC 8628） | 协议 | `implemented` | 1 | - | - | - | 2 | - | - | - | none | 2 |
| `diagnostics.operations` 运行诊断与关联错误查询 | 管理 | `implemented` | 3 | 17 | - | 3 | - | - | 1 | 1 | fixed | 4 |
| `docs.openapi_page_contract` OpenAPI 页面操作契约（步骤 268） | 文档与契约 | `implemented` | 1 | - | - | - | - | - | - | - | - | 2 |
| `mail.delivery` 站内邮件投递队列与本地测试邮件服务 | 通知 | `implemented` | 3 | - | - | - | - | - | - | - | offset | 3 |
| `mail.delivery_console` 邮件投递记录分页与取消语义（步骤 266） | 通知 | `implemented` | 1 | - | - | 1 | - | 1 | - | - | - | 3 |
| `mfa.public_facade` 认证因素与安全中心公开 Go 门面（步骤 222） | 认证与会话 | `implemented` | 5 | 24 | - | - | - | - | - | 1 | fixed | 4 |
| `mfa.totp_recovery` 两步验证（TOTP/恢复代码）与受限恢复 | 认证与会话 | `implemented` | 3 | 13 | - | - | - | - | - | 1 | none | 5 |
| `notifications.security_history` 安全告知投递关联与分页历史（步骤 265/266） | 通知 | `implemented` | 3 | - | - | 1 | - | 1 | - | - | - | 3 |
| `oauth_oidc.protocol` OAuth2/OIDC 协议端点（授权码/刷新/撤销/内省/UserInfo） | 协议 | `implemented` | 5 | 14 | - | - | 7 | - | 1 | 1 | none | 6 |
| `onboarding.invitations` 邀请与审核注册 | 账户 | `implemented` | 1 | - | - | - | - | - | - | - | offset | 2 |
| `operation.proof` 操作绑定的一次两步验证证明（步骤 255） | 认证与会话 | `implemented` | 1 | 9 | - | - | - | 1 | - | - | - | 25 |
| `pagination.iteration` 有界分页遍历辅助（宿主/CLI 可选） | 分页与列表 | `implemented` | - | 4 | - | - | - | - | - | - | none | 13 |
| `passkey.webauthn` Passkey/WebAuthn 登录与凭证管理 | 认证与会话 | `implemented` | 1 | 2 | - | - | - | - | - | - | none | 2 |
| `passwordreset.self_service` 自助密码找回 | 恢复 | `implemented` | 1 | 5 | - | - | - | - | - | 1 | none | 3 |
| `qr_login.confirm` 已登录 APP 扫码登录与网页领取 | 协议 | `implemented` | 1 | - | - | - | 7 | - | - | - | none | 2 |
| `rbac.public_facade` 角色/用户组/权限/预设/委派/授权查询公开门面（步骤 224） | 授权 | `implemented` | 6 | 52 | - | - | - | - | - | - | offset | 5 |
| `rbac.roles_permissions` 用户组、角色、权限目录与委派 | 授权 | `implemented` | 4 | 14 | - | 11 | - | - | - | 8 | offset | 4 |
| `reports.generate` 统计报告生成、导出、计划与清理 | 审计与报告 | `implemented` | 1 | - | - | 6 | - | - | - | 5 | offset | 3 |
| `runtime.embedded` 嵌入式运行时装配（Open/Handler/Mount/生命周期） | 嵌入式与运行时 | `implemented` | 2 | 18 | 5 | - | - | 1 | - | - | none | 3 |
| `search.domain_lists` 有界模糊搜索（步骤 261/262/263） | 分页与列表 | `partial` | - | - | - | - | - | - | - | - | - | 3 |
| `security.policy_reauth` 敏感操作安全策略与再次认证 | 认证与会话 | `implemented` | 4 | - | - | - | - | - | - | 1 | none | 3 |
| `session.admin` 管理员会话查询与强制下线 | 认证与会话 | `implemented` | 1 | 18 | - | 2 | - | - | - | 1 | offset | 6 |
| `settings.managed` 常规设置读取、校验、更新与敏感默认恢复 | 配置 | `implemented` | 3 | 19 | - | 5 | - | - | 1 | 1 | none | 6 |
| `setup.console_cli` login-setup 本地维护非交互命令（297） | 本地维护控制台 | `implemented` | 3 | - | - | - | - | 17 | - | - | none | 5 |
| `stats.overview` 统计概览与健康状态 | 审计与报告 | `implemented` | 1 | - | - | - | - | - | - | - | fixed | 2 |
| `storage.sqlite_migrations` SQLite 存储、增量迁移与其他数据库方言适配 | 存储 | `implemented` | 6 | - | - | - | - | - | - | - | none | 3 |
| `support.recovery` 客服求助单、人工核验恢复与 root 本地应急 | 恢复 | `implemented` | 3 | 48 | - | 2 | - | 1 | 1 | 7 | offset | 9 |
| `tasks.scheduler` 后台任务执行器与计划调度 | 任务 | `implemented` | 2 | - | - | - | - | - | - | - | none | 2 |
| `token.jwt_keys` JWT 签发/验签、JWKS 与签名密钥轮换 | 协议 | `implemented` | 2 | - | - | - | 1 | - | - | - | none | 3 |
| `transport.http_security` HTTP 传输安全链（限流/CSRF/CORS/边界/错误信封/OpenAPI） | 传输 | `implemented` | 5 | - | 7 | - | - | - | - | - | none | 4 |
| `ui.admin_pages` 管理与客服页面框架（固定命名路由） | 页面 | `implemented` | 2 | - | - | - | - | - | 2 | - | fixed | 4 |
| `ui.public_pages` 公开与自助页面（登录/注册/找回/账户/错误页） | 页面 | `implemented` | 4 | - | 11 | - | - | - | 5 | - | fixed | 3 |
| `users.direct_management` 直接改用户名/直接重置密码（步骤 256/257） | 账户 | `implemented` | 1 | 7 | - | - | - | 1 | - | 2 | - | 14 |
| `verification.environment_limits` 环境未测与子模块不可获取（分类登记） | 验证边界 | `partial` | - | - | - | - | - | - | - | - | - | 无 |
| `webhook.delivery` Webhook 端点、签名与投递重试 | 通知 | `implemented` | 1 | - | - | - | - | - | - | - | none | 2 |

### 声明面明细（逐项 found/total）

- `preset.install_gap`: matched_tests 无
- `access.joint_check`: internal_service 2/2, app_api 7/7, protocol_path 1/1, permission 1/1, test 2/2, matched_tests 2
- `account.lifecycle_221_remaining`: matched_tests 无
- `account.lifecycle_public`: internal_service 4/4, app_api 25/25, test 3/3, matched_tests 3
- `account.user_lifecycle_public`: internal_service 5/5, app_api 49/49, test 6/6, matched_tests 7
- `account.users`: internal_service 4/4, app_api 3/3, admin_route 2/2, permission 8/8, test 6/6, matched_tests 6
- `admin.facade_api`: app_api 47/47, permission 1/1, test 4/4, matched_tests 4
- `admin.observability_lists`: internal_service 5/5, app_api 27/27, admin_route 1/1, test 4/4, matched_tests 4
- `adminapi.core`: internal_service 2/2, root_api 3/3, admin_route 5/5, test 4/4, matched_tests 4
- `applications.manage`: internal_service 5/5, app_api 5/5, admin_route 3/3, permission 5/5, test 5/5, matched_tests 5
- `applications.oauth_delegation_public`: internal_service 5/5, app_api 36/36, test 3/3, matched_tests 3
- `audit.events`: internal_service 2/2, admin_route 3/3, permission 3/3, test 4/4, matched_tests 5
- `audit.reports_public`: internal_service 4/4, app_api 52/52, test 6/6, matched_tests 6
- `auth.password_session`: internal_service 3/3, app_api 8/8, permission 1/1, test 4/4, matched_tests 4
- `backup.restore`: internal_service 4/4, app_api 59/59, admin_route 4/4, cli 15/15, permission 7/7, test 14/14, matched_tests 14
- `bootstrap.root`: internal_service 2/2, app_api 3/3, root_api 1/1, cli 1/1, test 4/4, matched_tests 4
- `cli.loginctl`: internal_service 1/1, cli 23/23, test 4/4, matched_tests 4
- `config.load`: root_api 5/5, cli 1/1, test 3/3, matched_tests 3
- `device_code.login`: internal_service 1/1, protocol_path 2/2, test 2/2, matched_tests 2
- `diagnostics.operations`: internal_service 3/3, app_api 17/17, admin_route 3/3, page 1/1, permission 1/1, test 4/4, matched_tests 4
- `docs.openapi_page_contract`: internal_service 1/1, test 2/2, matched_tests 2
- `mail.delivery`: internal_service 3/3, test 3/3, matched_tests 3
- `mail.delivery_console`: internal_service 1/1, admin_route 1/1, cli 1/1, test 2/2, matched_tests 3
- `mfa.public_facade`: internal_service 5/5, app_api 24/24, permission 1/1, test 4/4, matched_tests 4
- `mfa.totp_recovery`: internal_service 3/3, app_api 13/13, permission 1/1, test 5/5, matched_tests 5
- `notifications.security_history`: internal_service 3/3, admin_route 1/1, cli 1/1, test 2/2, matched_tests 3
- `oauth_oidc.protocol`: internal_service 5/5, app_api 14/14, protocol_path 7/7, page 1/1, permission 1/1, test 6/6, matched_tests 6
- `onboarding.invitations`: internal_service 1/1, test 2/2, matched_tests 2
- `operation.proof`: internal_service 1/1, app_api 9/9, cli 1/1, test 2/2, matched_tests 25
- `pagination.iteration`: app_api 4/4, test 2/2, matched_tests 13
- `passkey.webauthn`: internal_service 1/1, app_api 2/2, test 2/2, matched_tests 2
- `passwordreset.self_service`: internal_service 1/1, app_api 5/5, permission 1/1, test 3/3, matched_tests 3
- `qr_login.confirm`: internal_service 1/1, protocol_path 7/7, test 2/2, matched_tests 2
- `rbac.public_facade`: internal_service 6/6, app_api 52/52, test 5/5, matched_tests 5
- `rbac.roles_permissions`: internal_service 4/4, app_api 14/14, admin_route 11/11, permission 8/8, test 4/4, matched_tests 4
- `reports.generate`: internal_service 1/1, admin_route 6/6, permission 5/5, test 3/3, matched_tests 3
- `runtime.embedded`: internal_service 2/2, app_api 18/18, root_api 5/5, cli 1/1, test 3/3, matched_tests 3
- `search.domain_lists`: test 3/3, matched_tests 3
- `security.policy_reauth`: internal_service 4/4, permission 1/1, test 3/3, matched_tests 3
- `session.admin`: internal_service 1/1, app_api 18/18, admin_route 2/2, permission 1/1, test 6/6, matched_tests 6
- `settings.managed`: internal_service 3/3, app_api 19/19, admin_route 5/5, page 1/1, permission 1/1, test 6/6, matched_tests 6
- `setup.console_cli`: internal_service 3/3, cli 17/17, test 5/5, matched_tests 5
- `stats.overview`: internal_service 1/1, test 2/2, matched_tests 2
- `storage.sqlite_migrations`: internal_service 6/6, test 3/3, matched_tests 3
- `support.recovery`: internal_service 3/3, app_api 48/48, admin_route 2/2, cli 1/1, page 1/1, permission 7/7, test 9/9, matched_tests 9
- `tasks.scheduler`: internal_service 2/2, test 2/2, matched_tests 2
- `token.jwt_keys`: internal_service 2/2, protocol_path 1/1, test 3/3, matched_tests 3
- `transport.http_security`: internal_service 5/5, root_api 7/7, test 4/4, matched_tests 4
- `ui.admin_pages`: internal_service 2/2, page 2/2, test 4/4, matched_tests 4
- `ui.public_pages`: internal_service 4/4, root_api 11/11, page 5/5, test 3/3, matched_tests 3
- `users.direct_management`: internal_service 1/1, app_api 7/7, cli 1/1, permission 2/2, test 2/2, matched_tests 14
- `verification.environment_limits`: matched_tests 无
- `webhook.delivery`: internal_service 1/1, test 2/2, matched_tests 2


### 未关闭项（missing / unimplemented）

- **preset.install_gap**（unimplemented）：预设安装生产入口缺口（D-252-1）
  - 已知限制: preset.Install 能力存在实现但生产装配无调用点（HIGH 产品缺口，不得当已完成，转 273/后续）

## 部分完成与已知缺口（不得当作全部完成）

- **preset.install_gap**（`unimplemented`）：预设安装生产入口缺口（D-252-1）
  - 已登记缺口: preset.Install 能力存在实现但生产装配无调用点（HIGH 产品缺口，不得当已完成，转 273/后续）
- **account.lifecycle_221_remaining**（`partial`）：221 范围的剩余入口（R10-22，部分完成）
  - 已登记缺口: 221 独立 example/HTTP/CLI/页面入口未闭环；已交付 app 公开 Go 门面不等同完整范围
- **search.domain_lists**（`partial`）：有界模糊搜索（步骤 261/262/263）
  - 已登记缺口: D-261-5 浏览器前进/后退可能显示旧条件结果（服务端仍重新授权，无越权）
  - 已登记缺口: D-263-1 客服/报告列表空搜索+非法字段的静默忽略口径未统一
- **verification.environment_limits**（`partial`）：环境未测与子模块不可获取（分类登记）

## 环境未测（不是通过，也不是缺陷）

- **mail.delivery_console**：邮件投递记录分页与取消语义（步骤 266）
  - 环境未测（docs/acceptance/capability-truth-matrix.md:真实外部 SMTP/Webhook 外发未测，已核实）
- **verification.environment_limits**：环境未测与子模块不可获取（分类登记）
  - 环境未测（docs/acceptance/capability-truth-matrix.md:非 SQLite 运行未测，已核实）
  - 环境未测（docs/acceptance/capability-truth-matrix.md:真实硬件 Passkey/Windows Hello/YubiKey 未测，已核实）
  - 环境未测（docs/acceptance/capability-truth-matrix.md:真实外部 SMTP/Webhook 外发未测，已核实）
  - 环境未测（docs/acceptance/capability-truth-matrix.md:-race/govulncheck/gosec 未跑，已核实）

## 子模块/远端不可获取

- **verification.environment_limits**：环境未测与子模块不可获取（分类登记）
  - 子模块不可获取（docs/acceptance/capability-truth-matrix.md:远端不可获取，已核实）
  - 子模块不可获取（docs/acceptance/capability-truth-matrix.md:子模块未纳入源码扫描，已核实）

## 证据分级明细（正向/拒绝证据）

| 能力 | 正向证据 | 拒绝证据 | 成熟度 |
|---|---|---|---|
| `docs.openapi_page_contract` | 1 | 1 | implemented |
| `mail.delivery_console` | 1 | 1 | implemented |
| `notifications.security_history` | 1 | 2 | implemented |
| `operation.proof` | 1 | 2 | implemented |
| `search.domain_lists` | 2 | 0 | partial |
| `users.direct_management` | 2 | 2 | implemented |

## 反向覆盖（盘点到的生产面是否被能力声明覆盖）

| 生产面 | 盘点总数 | 未被声明覆盖 |
|---|---|---|
| app 公开类型 | 468 | 0 |
| 管理 API 路由 | 137 | 0 |
| 协议端点点位 | 17 | 0 |
| 页面命名路由 | 250 | 0 |
| CLI 子命令 | 58 | 0 |
| 内置权限键 | 53 | 0 |

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
| `DiagnosticsErrorList` | result | 是 | diagnostics.operations | fixed | Truncated |
| `IterationOptions` | request | 是 | pagination.iteration | none | - |
| `MFAFactorList` | result | 否 | mfa.public_facade | fixed | - |
| `MFAFactorListRequest` | request | 否 | mfa.public_facade | fixed | - |
| `MFAPasskeyListRequest` | request | 否 | mfa.public_facade | fixed | - |
| `ManualRecoveryListPage` | result | 是 | support.recovery | offset | Page |
| `ManualRecoveryListRequest` | request | 是 | support.recovery | offset | - |
| `RBACDelegationList` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `RBACDelegationListRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACEffectiveRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACEffectiveResult` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `RBACPermissionSourcesRequest` | request | 是 | rbac.public_facade | offset | - |
| `RBACPermissionSourcesResult` | result | 是 | rbac.public_facade | offset | HasMore,Page |
| `SessionDeviceList` | result | 是 | session.admin | offset | HasMore,Page,Total |
| `SessionDeviceRequest` | request | 是 | session.admin | offset | - |
| `SupportCasePage` | result | 是 | support.recovery | offset | Page |
| `SupportEventPage` | result | 是 | support.recovery | offset | Page |
| `SupportListCasesRequest` | request | 是 | support.recovery | offset | - |

### 分页例外（fixed/none 或 continuation=gap，需理由）

- DiagnosticsErrorList -> diagnostics.operations（fixed：由能力声明理由承担）
- IterationOptions -> pagination.iteration（none：由能力声明理由承担）
- MFAFactorList -> mfa.public_facade（fixed：由能力声明理由承担）
- MFAFactorListRequest -> mfa.public_facade（fixed：由能力声明理由承担）
- MFAPasskeyListRequest -> mfa.public_facade（fixed：由能力声明理由承担）

## 扫描口径与限制

- 扫描范围见 JSON `metadata.scan_scope`；跳过 `.ai/`、`docs/`、`scripts/`、`ui/web/`、`migrations/`、`dist/`、`data/`，以及 `EvernightMail/`、`go-build-all/`、`examples/` 等嵌套 Module。
- 页面路由从 `UIRoute` 复合字面量盘点；动态生成或宿主替换的路由不在静态清单内。
- 协议端点表来自 `internal/protocolapi/doc.go` 的端点文档表；点位常量来自 `protocolapi.go`。文档表与代码漂移会体现为声明无法解析。
- 测试证据按「包路径 + 测试函数名前缀」解析，仅证明存在定向测试函数，不证明该测试当前通过；通过性需另行执行 `go test`（领域短测试可登记到统一入口 `scripts/shorttest.ps1`，见 `docs/acceptance/shorttest.md`）。

## 原始清单

机器可读原始盘点（app 公开面、管理路由、协议点位、页面路由、CLI、权限、测试）见同目录 `capability-matrix.json` 的 `inventories` 字段。
