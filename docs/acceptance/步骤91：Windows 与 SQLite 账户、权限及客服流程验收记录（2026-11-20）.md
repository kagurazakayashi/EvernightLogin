> 历史注记（步骤 136）：本文所引 `internal/testmail` / `tools/testmaild` 已在步骤 136 删除并迁移为父项目 `internal/mailtest`（外部 EvernightMail 进程夹具）。本文作为当时验收证据保留原文，不改写。

# 步骤91：Windows 与 SQLite 账户、权限及客服流程验收记录（2026-11-20）

本记录只覆盖步骤 91 约定的验收范围：账户生命周期、应用隔离、权限委派与客服人工恢复；
不泛化为全项目验收，也不代替步骤 92～96 的登录/MFA、安全审查与最终交付验收。

- 记录日期：2026-11-20（Asia/Shanghai）
- 验收环境：Windows 11 amd64，Go 1.27.4 windows/amd64，`CGO_ENABLED=0`，`GOMAXPROCS=2`，`go test -p 1`
- 数据库：每个用例独立 `t.TempDir()` 临时 SQLite 文件，执行仓库全部 44 个迁移；不读取、不修改 `database/login.db`
- 验收方式：测试进程内以真实领域服务 + 真实 SQLite 迁移构造隔离实例；**非部署后独立服务实测**
  （`cmd/login-server` 当前仅 CLI 装配，无 HTTP 管理路由），下面"未覆盖项"如实列出该边界
- 证据代码：根包 `step91_acceptance_env_test.go`（隔离环境与合成数据）、`step91_acceptance_test.go`（6 组验收用例）

## 1. 结论

- 步骤 91 约定范围内的账户、权限与客服流程在 Windows + SQLite 隔离环境通过验收：
  **6 个验收用例全部通过；验收矩阵 42 行场景/断言全部 PASS，PARTIAL 0，FAIL 0**（见第 4 节）。
- 未发现需要在步骤 91 内做"必要小修"的缺陷；本步没有改动任何既有业务代码、迁移、错误码或依赖，
  只新增验收测试与验收记录。大缺口见第 6 节的"未覆盖项"，均不属于本步验收范围或受项目规则限制。
- 该结论不代表整个系统可生产使用：独立服务 HTTP 装配、真实浏览器/页面、真实邮件外发、
  真实硬件 MFA、非 Windows 平台运行、`-race` 并发检测均未在本步实测。

## 2. 环境与资源边界

- 操作系统：Windows 11，amd64；Go 1.27.4 windows/amd64。
- 构建/测试：`CGO_ENABLED=0`、`GOMAXPROCS=2`、`-p 1`、`-timeout 600s`；串行执行，不并发重活。
- 数据隔离：每个用例 `t.TempDir()` 临时目录 + 独立 SQLite 文件；用例结束由测试框架回收；
  未使用固定端口（本批用例不监听端口）、未访问网络、未写仓库内文件。
- 邮件：仓库规则禁止真实外发，本步使用测试内本地捕获适配器保存邀请/审核/邮箱验证/安全告知内容；
  不使用 `internal/testmail` 的 SMTP 监听，因此"SMTP 协议层投递"不在本步证据内（该链路由步骤 32 的测试覆盖）。
- **敏感策略闸门披露（影响范围见下）**：验收环境的真实服务实例显式设置了生产过渡选项
  `AllowLegacyWithoutSensitive: true`，涉及 `profile`（第 188 行）、`role`（第 231 行）、`group`（第 250 行）、
  `session`（第 279 行 `session.Options.AllowLegacyWithoutSensitive: true`）、`emailchange`（第 334 行），
  位置见 `step91_acceptance_env_test.go`。含义：在宿主尚未接线步骤 39 敏感操作收敛执行器时，
  回退到既有的再次验证/管理强认证/委派转授检查闸门，而不是按默认 fail-closed 直接拒绝。
  - 该选项**放宽的只是敏感操作收敛入口**，不涉及本步实际断言的检查：账户状态/安全版本、成员状态、
    角色与权限启停、数据范围、委派转授（`role`/`group` 仍使用真实 `delegation.Service` 做转授检查）、
    root 保护、人工恢复的工作职员授权与目标保护等仍为真实 fail-closed 判定，未被绕过。
  - 会话部分只用真实 `session` 服务的 `Login`/`Validate`，未使用管理访问路径；profile/emailchange 的
    近期身份验证由测试按宿主契约注入的验证器实现（返回通过），属"宿主扩展点"测试实现，不是生产鉴权替身。
  - **对结论的影响**：本步结论证明的是"账户、权限与客服流程在 Windows/SQLite 隔离环境通过验收"，
    **不能**据此声称"接线步骤 39 敏感策略执行器后的敏感操作行为已验证"；该部分留待步骤 92/95 与宿主装配实测。
- 合成数据不含真实姓名、真实邮箱、密码明文或任何真实用户资料；所有账号、邮箱、主机名均为 `example.test` 合成值。

## 3. 合成数据说明

| 类别 | 合成内容 |
|---|---|
| 应用 | 验收应用A（`app_…01`）、验收应用B（`app_…02`），均为 SQLite 临时库内的 `active` 应用 |
| 作用范围 | `system` + 两个应用作用范围（迁移 0001 建立 system，测试补充应用作用范围） |
| 权限 | 应用A `app.read`/`app.write`；应用B 同名 `app.read`；系统 `users.read`（高权限判定用） |
| 角色 | 应用A 只读角色/可写角色、应用B 只读角色、系统只读角色 |
| 用户组 | 应用A 运维组（成员：普通用户1；组角色：应用A 只读角色，作为间接授权来源） |
| 普通用户 | 普通用户1（组成员）、普通用户2（直接角色 + 受限数据范围）、停用成员用户、无成员用户 |
| 管理身份 | 应用A管理员、应用B管理员（授权器只放行各自应用） |
| 客服流程 | 客服发起人、独立审批人、受控执行人、恢复目标、高权限目标、停用目标、唯一 root |
| 审计/会话 | 真实 `audit_events` 表、真实 `sessions` 表；会话秘密只在内存中传递，不落日志/文件 |

## 4. 验收矩阵

说明：需求ID引用 `docs/requirements/login_功能列表_v1.1.md`（正文版本 1.2）的章节与条目；
"前置"为空表示用例内自行初始化；证据列给出用例名（均为 `go test -run` 可直接复跑）。

| 需求ID | 场景 | 前置 | 步骤 | 预期 | 实际 | 证据（测试名） | 结果 | 问题 |
|---|---|---|---|---|---|---|---|---|
| §4.2 账户管理 | 管理员创建用户 | 本地受信管理员授权器 | 调用账户服务创建账户 | 状态 active、security_version=1、写成功审计 | 与预期一致 | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.2 账户管理 | 禁用/启用状态机与安全版本 | 已创建账户 | 禁用→校验会话→启用→重新登录 | 禁用递增 security_version；启用不降版本；旧会话不复活；新会话有效 | 与预期一致（版本 1→2，旧会话返回会话无效） | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.2 账户管理 | 删除预览与完成删除 | 已创建账户 | 预览→请求删除→完成删除 | 预览安全版本正确；状态 pending_delete、版本递增；删除后用户行消失 | 与预期一致（版本 2→3） | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.1 身份模型 | root 受保护 | 合成唯一 root | 本地管理员禁用 root | 拒绝（受保护账户），并写失败审计 | 与预期一致（失败审计 error_code=ACCESS_DENIED） | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §11.1 通用权限模型 | 普通用户不能禁用他人 | 普通用户身份 | 普通用户调用禁用他人账户 | 拒绝（未获准执行） | 与预期一致 | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.1 身份模型 | 受控更名不改变用户 ID | 本人资料会话 | 本人更名 | 用户名规范化生效、用户 ID 不变、写更名审计 | 与预期一致 | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.3 用户资料 | 资料字段白名单更新 | 本人资料会话 | 更新昵称/简介 | 仅白名单字段变化、行版本递增 | 与预期一致 | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.3 用户资料 | 跨用户更名拒绝 | 普通用户身份 | 他人账户更名 | 拒绝（未获准） | 与预期一致 | `TestStep91AccountLifecycleAndSessionInvalidation` | PASS | 无 |
| §4.2 账户管理 | 自主注册待审核 | 注册服务开启且要求审核 | 提交注册 | 状态 pending、不直接可用 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.2 账户管理 | 审核授予跨应用角色拒绝 | 待审核账户 | 以应用B角色批准应用A注册 | 拒绝且账户保持 pending | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.2 账户管理 | 审核批准应用A角色 | 待审核账户 + 应用A管理员 | 批准并分配应用A角色 | 账户 active、应用成员关系与角色生效、审核通知已发送 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.1 身份模型 | 非法管理身份不能审核 | 待审核账户 | 匿名调用审核批准 | 拒绝 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.2 账户管理 | 邀请注册→新用户接受 | 应用A管理员（委派资格已签发） | 创建邀请→本地捕获链接→新用户接受 | 邀请邮件已发送；接受后新用户 active、成员关系与角色生效 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.2 账户管理 | 邀请一次性凭证 | 已接受的邀请 | 重复使用同一邀请令牌 | 拒绝 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §11.1 通用权限模型 | 非授权发起者不能发邀请 | 应用B管理员 | 创建应用A邀请 | 拒绝 | 与预期一致 | `TestStep91RegistrationInviteAndReview` | PASS | 无 |
| §4.3 用户资料 | 邮箱变更申请→验证→切换 | 用户本人 | 申请新邮箱→错误令牌→正确令牌验证 | 错误令牌拒绝；正确令牌切换成功；申请/验证写审计 | 与预期一致 | `TestStep91ProfileAndEmailChange` | PASS | 无 |
| §4.3 用户资料 | 未验证邮箱不入库、旧邮箱告知 | 已验证旧邮箱 | 二次申请变更 | 新邮箱验证前不入库；切换后旧地址收到安全告知 | 与预期一致 | `TestStep91ProfileAndEmailChange` | PASS | 无 |
| §11.1 通用权限模型 | 间接授权（组→角色→权限） | 用户1为组成员 | 检查应用A `app.read` | 允许，且来源可追踪 | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 未授权权限拒绝码 | 用户1无 `app.write` | 检查应用A `app.write` | 拒绝，稳定码 PERMISSION_REQUIRED | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.2 应用独有权限 | 跨应用同名权限不关联 | 用户1非应用B成员；用户2为应用B成员但无角色 | 分别检查应用B `app.read` | 用户1 拒绝 APP_MEMBERSHIP_REQUIRED；用户2 拒绝 PERMISSION_REQUIRED | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 直接授权（用户→角色→权限） | 用户2直接角色 | 检查应用A `app.read`/`app.write` | 允许 | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §4.1 身份模型 | 成员状态 disabled / 无成员关系 | 停用成员、无成员用户 | 检查应用A `app.read` | 拒绝 APP_MEMBERSHIP_REQUIRED | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 角色停用/权限停用即时失效 | 已授权角色/权限 | 停用后检查 | 拒绝，来源标记 role_disabled / 稳定码 PERMISSION_DISABLED | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 数据范围资源边界 | 直接角色数据范围为 `resources` | 资源级检查范围内/外资源 | 范围内允许；范围外拒绝 RESOURCE_FORBIDDEN | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 有效权限查询的数据范围 | 普通用户身份 | 查询他人有效权限 | 拒绝（未获准查询） | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | root 不通过普通权限引擎 | 唯一 root | 系统身份检查 root 权限 | 拒绝（ACCESS_DENIED，root_protected） | 与预期一致 | `TestStep91PermissionMatrixAcrossApps` | PASS | 无 |
| §11.1 通用权限模型 | 防止自我提权 | 应用A管理员（仅获 app.read 转授资格） | 给自己分配含 app.write 的角色 | 拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.1 通用权限模型 | 合法直接授权（正路径对照） | 应用A管理员 + 委派资格 | 给应用A成员分配只读角色 | 成功并写成功审计 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.1 通用权限模型 | 跨应用越权委派 | 应用A管理员 | 分配应用B角色 | 拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.1 通用权限模型 | 应用管理员不能建系统角色/他应用组 | 应用A管理员 | 创建系统角色、创建应用B用户组 | 均拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.1 通用权限模型 | 普通用户不能分配角色 | 普通用户身份 | 给自己分配角色 | 拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.2 应用独有权限 | 跨应用角色塞入邀请 | 应用A管理员 | 邀请时带应用B角色 | 拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §4.2 账户管理 | 非授权管理员不能批准注册 | 应用B管理员 | 批准注册 | 拒绝 | 与预期一致 | `TestStep91SelfEscalationAndCrossAppDenied` | PASS | 无 |
| §11.4 客服协助重置 | 客服恢复正路径 | 人工恢复策略已启用、工作人员授权已接线 | 求助→发起人自批→独立审批→提前执行→等待期满执行 | 自批拒绝；等待期未满拒绝；执行完成、执行器调用 1 次、通知已发、写审计 | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 审批人越界执行 | 已批准申请、等待期满 | 审批人执行 | 拒绝（无执行权限） | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 重复执行 | 已完成申请 | 再次执行 | 拒绝（申请已结束） | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 拒绝路径 | 客服求助、独立审批人 | 拒绝后尝试执行 | 拒绝成功写审计；终态不能执行 | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 取消路径 | 客服求助 | 发起人取消后尝试审批 | 取消成功写审计；终态不能审批 | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | root/高权限目标保护 | 唯一 root、实际高权限账户 | 发起普通人工恢复 | 拒绝 SUPPORT_TARGET_PROTECTED | 与预期一致（错误码映射核对通过） | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 停用目标拒绝 | 已停用账户 | 发起人工恢复 | 拒绝（目标不可用） | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §11.4 客服协助重置 | 非工作人员发起求助 | 普通用户身份 | 发起人工恢复 | 拒绝（未获准） | 与预期一致 | `TestStep91SupportRecoveryFlow` | PASS | 无 |
| §14 安全审计 | 关键流程成功/拒绝留痕 | 各用例 | 查询 `audit_events` | 账户/更名/角色分配/用户组/邮箱变更/人工恢复均有对应成功或拒绝记录；人工恢复审计无口令/令牌字段 | 与预期一致 | 上述 6 个用例的审计断言 | PASS | 无 |

统计：验收矩阵共 **42 行**，结果全部为 **PASS**；对应 **6 个验收用例**（一个用例覆盖多个需求条目）。
**PARTIAL 0、FAIL 0、未通过行 0**。

## 5. 缺陷与必要小修

- 本步验收过程中**未发现**账户、权限、客服流程范围内需要在步骤 91 内修复的缺陷，因此没有代码小修，
  也没有因修复而复测的用例。
- 说明：验收测试本身的首轮失败均来自测试环境搭建错误（合成 ID 格式不符合 `usr_`/`app_`/`perm_`/`role_`/`grp_`
  生产格式、账户状态命令缺少必填行版本、断言口径与真实错误码不匹配），已修正测试；**不是产品缺陷**。
  首轮失败原因与最终通过结果均已保留在 `.ai/lead/reports/step91-dev.md`。

## 6. 未覆盖项与阻塞清单

| 项 | 状态 | 说明与后续 |
|---|---|---|
| 部署后独立服务实测 | 未覆盖（不阻塞本步结论） | `cmd/login-server` 仍只装配 CLI，无 HTTP 管理路由；本步在测试进程内用真实服务构造隔离实例，不能声称"部署后服务实测"。步骤 89/96 的装配状态见 MEMORY 与 README 边界说明 |
| 真实浏览器/页面交互 | 未覆盖 | 页面与无障碍验收属步骤 93；本步只验证服务层与领域流程 |
| 真实邮件外发 / SMTP 投递 | 按规则禁止 | 使用测试内本地捕获；SMTP 协议与重试链路由步骤 32 测试覆盖，本步不外发 |
| 登录/MFA 全链路 | 不在本步范围 | 密码/Passkey/MFA 属步骤 92；本步会话签发入参为真实结构体的测试构造，会话服务本身为真实实现 |
| 非 Windows 平台运行 | 未实测 | 项目规则只要求 Windows + SQLite 运行验证；其他平台编译状态见步骤 89 记录 |
| `-race` 并发检测 | 未实测 | `CGO_ENABLED=0` 环境下未启用；本批用例串行、无并发压力 |
| 真实强认证（客服/审批人强认证执行器） | 契约已接线，真实实现未在本步接入 | 人工恢复的敏感策略执行器与宿主执行器按生产契约注入；真实密码重置执行器未装配到独立服务 |
| 高并发/多实例下的权限与会话一致性 | 未覆盖 | 属步骤 95 安全审查与后续维护范围 |
| 应用停用后的权限整体拒绝 | 未在本步用例中单列 | 权限引擎已有该语义与既有测试；本步覆盖成员状态与角色/权限停启 |

阻塞清单：**无**。上述各项均不影响"步骤 91 账户、权限与客服流程在 Windows/SQLite 隔离环境通过验收"这一结论，
但必须在最终交付说明中如实保留。

## 7. 复现命令与证据

在项目根目录（Windows 11、Go 1.27.4）执行：

```bat
set CGO_ENABLED=0
set GOMAXPROCS=2
set GOFLAGS=-mod=readonly
go test -count=1 -p 1 -timeout 600s -run TestStep91 -v .
```

实际结果（2026-11-20 本机）：6 个用例全部 PASS，`ok ... 2.326s`，退出码 0。
用 `-count=3` 连跑同一批用例同样全部通过（无 flaky）。

补充回归（相关既有包，串行 `-p 1`）：`go test -count=1 -p 1 ./internal/account ./internal/profile
./internal/authz ./internal/role ./internal/group ./internal/session ./internal/manualrecovery
./internal/onboarding ./internal/registration ./internal/emailchange`，EXIT=0，10 包全部 ok
（account 9.126s、profile 7.181s、authz 5.413s、role 5.679s、group 5.539s、session 16.341s、
manualrecovery 8.574s、onboarding 4.419s、registration 7.342s、emailchange 4.755s）。

静态检查：`gofmt -l step91_acceptance_test.go step91_acceptance_env_test.go` 无输出；
`GOMAXPROCS=2 CGO_ENABLED=0 GOFLAGS=-mod=readonly go vet .` EXIT=0。

## 8. 结论与建议

- 建议按"步骤 91 已完成"处理并勾选滴答清单；前提是接受第 6 节的未覆盖边界（尤其是"非部署后服务实测"）。
- 本步没有改动产品代码，因此不需要为验收单独增加回归风险；新增测试随步骤 91 提交。
- 若后续要求"部署后独立服务实测"，需先在步骤 89/96 范围内完成 `cmd/login-server` 的 HTTP 装配，
  再按第 7 节同一批场景在真实启动的服务上复跑；当前不得以本记录替代该实测。
