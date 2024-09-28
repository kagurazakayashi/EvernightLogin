# 内置 Web 管理台操作指南

本文是内置页面（`login-server serve` 提供的 Web 管理台）的**操作入口**：按“普通用户”
与“root/授权管理员”两条路径，说明页面地址与常用操作。

> 本文内容迁移自根 `README.md` §4「内置 Web 管理台操作指南」（步骤 244 阶段 A），
> 保证信息不丢失；根 README 已收敛为入口页。页面路由以实际注册为
> 准，依赖不满足的页面可能返回 404。

服务启动后，页面按配置和权限显示。管理页要求已完成强认证的管理会话；普通用户只能访问
自己的页面。

## 1. 账户与个人中心（普通用户）

| 页面 | 地址 | 常用操作 |
|---|---|---|
| 登录/注册 | `/login`、`/register` | 登录、退出；开放注册时创建账户并完成邮箱验证/审核 |
| 邮箱验证/邀请 | `/email/verify`、`/invitation/accept` | 验证邮箱、接受邀请 |
| 个人资料 | `/account/profile` | 修改昵称、简介、语言、时区、电话；上传头像 |
| 用户名/邮箱 | `/account/profile/username`、`/account/profile/email` | 受控更名；变更邮箱（需当前密码，新邮箱验证后生效） |
| 密码 | `/account/password` | 修改密码（本人）；忘记密码从登录页进入 `/login/forgot-password`（仅当部署启用邮件找回；未启用时找回页明确提示并给出恢复代码/客服等下一路径） |
| 安全中心 | `/account/security` | 查看/管理 MFA、TOTP、Passkey、恢复代码、会话与已授权应用 |
| 两步验证 | `/account/security/mfa` | 添加邮件验证码因素；管理已启用因素 |
| TOTP | `/account/security/totp` | 绑定/解除 TOTP，查看恢复代码 |
| Passkey | `/account/security/passkeys` | 注册、重命名、撤销 Passkey |
| 恢复代码 | `/account/security/recovery-codes` | 生成/更新恢复代码（只展示一次） |
| 会话/授权 | `/account/sessions`、`/account/grants` | 退出设备、撤回应用授权、查看活动 |
| 安全活动 | `/account/activity` | 查看本人安全事件 |

操作提示：敏感操作（改密码、邮箱变更、MFA/Passkey 变更、恢复代码）通常要求再次输入
当前密码或完成强认证；确认页展示目标/范围/后果，服务端仍会重新鉴权，确认框本身不是授权。

## 2. 管理后台（root / 授权管理员）

| 页面组 | 地址 | 操作 |
|---|---|---|
| 仪表盘 | `/admin` | 查看系统状态、关键统计和待办 |
| 用户 | `/admin/users` | 列表/创建/详情/启停/删除预览/禁停；批量导入导出；审核注册；详情内**直接修改用户名**（`/admin/users/rename`）与**直接重置密码**（`/admin/users/password-reset`，需独立权限 + 操作者本次两步验证） |
| 用户组 | `/admin/groups` | 建组、改资料、增删成员、删除 |
| 角色/权限 | `/admin/roles`、`/admin/permissions` | 创建角色、组合权限、分配/撤销、启停；查看预设差异 |
| 委派/有效权限 | `/admin/delegations`、`/admin/access/effective` | 查看委派范围与实际有效权限（委派写操作按设计受限） |
| 应用 | `/admin/applications` | 新建应用（默认停用）、资料、成员、OAuth 安全接入、客户端凭证、授权、启停 |
| 应用托管策略 | 应用详情中的“托管策略”页 | 配置该应用可调用的管理 API 操作/对象/字段；只有 root/受信管理员可写 |
| 客服/恢复 | `/support/cases`、`/support/recovery` | 创建/处理工单、发起/审批人工恢复（人工恢复制度默认关闭，需配置文件与独立审批） |
| 安全策略 | `/admin/security/policies` | 查看/修改敏感操作策略、再次认证新鲜度、通知要求、恢复默认 |
| 审计 | `/admin/audit` | 查询/详情/导出、错误诊断、root 清理与保留策略 |
| 统计/报告 | `/admin/dashboard`、`/admin/reports` | 统计看板；报告五格式（HTML/PDF/Markdown/CSV/JSON）生成、计划、下载、清理 |
| 备份 | `/admin/backups` | 热备份任务、计划、详情、下载、清理、恢复状态 |
| 通知 | `/admin/notifications/mail` | 查看/测试邮件通知配置（测试只应指向本地捕获器） |

## 3. 注意

- **应用新建**后默认停用，需要先启用并登记客户端凭证；本版本不提供应用硬删除，停用不等于删除。
- **用户/角色/应用管理**都受真实授权与数据范围约束；页面按钮隐藏不代表授权，服务端每次请求都会重新判定。
- **root 是特殊账户**，不能作为普通角色分配；root 的敏感策略、备份恢复和审计清理需强认证。
- **人工恢复**默认关闭，必须由 root 配置可执行依据/独立审批人/等待期后才能使用；客服不能读取密码、恢复码或重置链接。
- **直接改名/直接重置密码是独立管理操作**（不是匿名找回）：需要对应权限键与操作者本人
  一次真实两步验证，不需要目标确认或另一管理员审批；直接重置后旧会话/旧找回链接失效、
  MFA/Passkey 保留、目标下次登录强制改密（must_change）。改名权与重置权互相独立。
- 未配置邮件（`mail.enabled=false`）时登录页不显示“忘记密码”入口，找回页返回稳定不可用
  提示与恢复代码/客服/管理员下一路径；管理员直接重置仍可用（不依赖邮件）。
- 直接管理的另一种入口是 CLI/管理 API（与页面共用同一门面与证明消费）：`loginctl admin
  rename-user <user_id> --new-username <新用户名> --reason <原因> --confirm RENAME-USER`、
  `loginctl admin reset-password <user_id> --reason <原因> --confirm RESET-PASSWORD
  [--new-password-file <受保护文件>]`；管理 API 路径见 [README §7](../README.md#7-管理员直接管理与列表模糊搜索本轮新增)。

## 4. 相关文档

- 登录、MFA/Passkey、OAuth/OIDC：[login-and-oauth.md](login-and-oauth.md)
- 应用、成员与权限键：[applications-and-permissions.md](applications-and-permissions.md)
- 角色、用户组、委派：[roles-and-scopes.md](roles-and-scopes.md)
- 审计、统计与报告：[audit-and-reports.md](audit-and-reports.md)
- 备份与恢复：[backup-and-restore.md](backup-and-restore.md)
- 客服与人工恢复：[support-and-recovery.md](support-and-recovery.md)
- 本地管理 CLI：[root-cli.md](root-cli.md)
- 页面替换与嵌入契约：[../embedding/host_integration.md](../embedding/host_integration.md)
