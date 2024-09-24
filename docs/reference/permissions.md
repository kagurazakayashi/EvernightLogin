# 内置权限、角色与用户组参考

> 由 `internal/preset.DefaultCatalog()` 生成（目录版本 `1.1.0`）；授权/委派规则与页面操作见 [../guide/applications-and-permissions.md](../guide/applications-and-permissions.md) 与 [../guide/roles-and-scopes.md](../guide/roles-and-scopes.md)。

这份参考回答“**谁能对哪些数据做什么**”：系统权限面向整个身份服务，应用权限默认只在该应用范围内生效；权限键创建后不可修改，内置权限不可删除、只能按规则停用。

## 1. 使用规则

- **系统 vs 应用**：系统权限（如 `users.*`、`audit.*`）作用于整个身份服务；应用独有权限只在该应用范围内判定，同名不等于同权限。
- **root 特殊**：`root_only` 权限只允许 root 特殊通道使用，普通角色不能组合；root 不能作为普通角色分配产生。
- **默认拒绝**：没有显式授予即拒绝；功能权限本身不替代业务资源归属检查（`RESOURCE_FORBIDDEN` 表示范围不足，而非缺少功能权限）。
- **再次认证**：标记“需要再次认证”的操作要求近期强认证或一次性批准，未满足时 fail-closed（`REAUTH_REQUIRED`/`MFA_REQUIRED`）。
- **实现标记**：`Implemented=false` 表示该权限仅登记目录说明、对应操作尚无可执行路径，不能当作开关或已实现能力使用。
- **委派**：应用委派不能获得系统资格或控制 root；委派范围只减不增。

## 2. 权限键表（53 个）

| 权限键 | 名称 | 能做什么 | 影响范围 | 不能做什么 | 再认证 | root only | 默认角色 | 已实现 | 关联能力 |
|---|---|---|---|---|---|---|---|---|---|
| `self.profile.read` | 查看自己的资料 | 查看自己的显示名称、联系资料与账户状态。 | 仅本人；不包含其他人的资料。 | 不能查看他人的资料、管理资格或安全设置。 | 否 | 否 | `system_admin`、`user_admin`、`support`、`auditor`、`normal_user` | 是 | account.users |
| `self.profile.update` | 修改自己的资料 | 修改自己的显示资料。 | 仅本人；用户名与邮箱修改遵守单独验证流程。 | 不能修改管理资格、安全版本、已验证状态或他人资料。 | 否 | 否 | `system_admin`、`user_admin`、`support`、`auditor`、`normal_user` | 是 | account.users |
| `self.credentials.manage` | 管理自己的登录凭证 | 管理自己的密码、Passkey 与两步验证。 | 仅本人；敏感修改仍需再次确认身份。 | 不能免除再次验证要求，不能为他人重置凭证或解除两步验证。 | 是 | 否 | `system_admin`、`user_admin`、`support`、`auditor`、`normal_user` | 是 | mfa.public_facade、mfa.totp_recovery |
| `self.sessions.manage` | 退出自己的设备 | 查看并退出自己的登录会话与设备。 | 仅本人。 | 不能退出或查看其他人的设备与会话。 | 否 | 否 | `system_admin`、`user_admin`、`support`、`auditor`、`normal_user` | 是 | auth.password_session |
| `self.grants.manage` | 撤回自己给应用的授权 | 查看并撤回自己授权给应用的访问。 | 仅本人。 | 不能撤回其他人的授权或应用自身的凭证。 | 否 | 否 | `system_admin`、`user_admin`、`support`、`auditor`、`normal_user` | 是 | oauth_oidc.protocol |
| `users.read` | 查看普通用户 | 按获准范围查看普通用户的必要资料。 | 仅获准管理的普通用户范围。 | 不能查看 root 或超出管理范围的高权限管理账户资料。 | 否 | 否 | `system_admin`、`user_admin` | 是 | account.users、admin.facade_api |
| `users.create` | 创建普通用户 | 创建普通用户并登记基本资料。 | 仅获准管理的普通用户范围。 | 不能创建 root 或带管理资格的账户，不能设置固定密码。 | 否 | 否 | `system_admin`、`user_admin` | 是 | account.users |
| `users.update` | 修改普通用户 | 修改普通用户的显示资料；用户名与密码各有独立权限和专门操作，不能随资料更新一起提交。 | 仅获准管理的普通用户范围。 | 不能修改用户名或密码、邮箱验证状态、安全版本或管理资格。 | 否 | 否 | `system_admin`、`user_admin` | 是 | account.users |
| `users.disable` | 禁用普通用户 | 禁用获准范围内的普通用户。 | 仅获准管理的普通用户范围。 | 不能禁用 root 或其他高权限管理账户。 | 否 | 否 | `system_admin`、`user_admin` | 是 | account.users |
| `users.delete` | 删除普通用户 | 删除获准范围内的普通用户。 | 仅获准普通用户，需确认；删除不清除审计。 | 默认不授予，需另行分配；不能删除 root 或高权限账户。 | 是 | 否 | - | 是 | account.users |
| `users.export` | 导出用户资料 | 按字段许可批量导出普通用户资料。 | 仅获准普通用户范围，导出仍按字段许可。 | 默认不授予；不能导出密码、MFA 秘密、恢复码或私钥。 | 是 | 否 | - | 是 | account.users |
| `users.username.change.other` | 直接修改他人用户名 | 对获准管理的其他用户直接修改全局用户名；需操作者本次完成两步验证，不需要目标当前密码、目标确认或另一管理员审批。 | 仅获准管理的普通用户范围；本人改名仍走本人受控流程。 | 不能修改 root 或超出管理范围的账户；不能修改密码、邮箱、MFA 秘密或管理资格，不能绕过用户名的唯一性、保留名与 Unicode 规则。 | 是 | 否 | `system_admin` | 是 | users.direct_management |
| `users.password.reset.other` | 直接重置他人密码 | 为获准管理的其他用户直接设置新密码；需操作者本次完成两步验证，不需要目标旧密码、目标确认或独立审批。 | 仅获准管理的普通用户范围；成功后使目标旧会话与找回入口失效，并要求目标下次登录改密。 | 不能读取或回显旧密码、不能重置 root 或高权限管理账户、不能移除或重置 MFA、不能为无密码账户添加密码；不能替代人工恢复审批流程。 | 是 | 否 | `system_admin` | 是 | users.direct_management |
| `recovery.request` | 发起密码找回 | 向用户此前已验证的渠道发送一次性密码找回入口。 | 仅获准的普通用户范围；不能选择新地址。 | 不能查看找回入口或验证码，不能解除两步验证，不能为 root 或高权限账户发起。 | 否 | 否 | `system_admin`、`user_admin`、`support` | 是 | passwordreset.self_service、support.recovery |
| `support.cases.read` | 查看求助单 | 查看分配给自己的求助单与必要脱敏信息。 | 仅分配给自己的求助单。 | 不能查看未分配求助单或未脱敏的敏感资料。 | 否 | 否 | `support` | 是 | support.recovery |
| `support.cases.create` | 登记求助单 | 登记用户求助事项与必要核验结果。 | 仅自己经手且获准的普通用户。 | 不能伪造核验结果，不能记录无关证件材料。 | 否 | 否 | `support` | 是 | support.recovery |
| `support.cases.update` | 更新求助单 | 更新分配给自己且未结束的求助单状态。 | 仅分配给自己的求助单。 | 不能改写历史处理记录，不能替用户设置新密码。 | 否 | 否 | `support` | 是 | support.recovery |
| `recovery.approve` | 审批人工核验恢复 | 审批通过人工核验的普通账户恢复申请。 | 仅获准的普通账户恢复申请；需独立审批。 | 默认不授予；不能审批本人发起的申请，不能审批 root 或高权限账户。 | 是 | 否 | - | 是 | support.recovery |
| `recovery.mfa.approve` | 审批两步验证恢复 | 审批普通用户的两步验证恢复申请。 | 仅获准的普通账户，独立核验与审批。 | 默认不授予；不能与密码恢复合并，完成后必须强制重新绑定。 | 是 | 否 | - | 是 | support.recovery |
| `recovery.execute` | 执行人工核验恢复 | 执行已独立批准且等待期结束的人工核验恢复申请。 | 仅获准的普通账户恢复；执行人不得是发起者或审批人。 | 默认不授予；不能跳过审批/等待期，root 与高权限账户拒绝，执行后旧会话/旧凭证失效。 | 是 | 否 | - | 是 | support.recovery |
| `groups.read` | 查看用户组 | 查看获准范围内的用户组与成员。 | 仅获准系统或应用范围。 | 不能查看范围外用户组，查看不代表可修改成员。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `groups.manage` | 管理用户组 | 创建、修改用户组并管理组成员。 | 仅获准系统或应用范围。 | 涉及赋权仍需角色分配权限；不能借组管理改变全局账户状态。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `roles.read` | 查看角色 | 查看获准范围内的普通角色及其权限组合。 | 仅获准系统或应用范围。 | 不能查看 root 能力，查看不代表可修改。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `roles.manage` | 管理普通角色 | 创建、修改普通角色及其权限组合。 | 仅获准范围且只能组合可委派权限。 | 不能制造 root 角色，不能组合超出自己委派范围的权限。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `roles.assign` | 分配角色 | 把允许转授的角色交给指定用户或用户组。 | 仅获准范围；不能授予超出自己委派范围的权限。 | 不能自行提权，不能把角色分配给 root 或范围外主体。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `permissions.read` | 查看权限目录 | 查看系统与获准应用范围的权限定义与说明。 | 仅获准系统或应用范围。 | 不能查看范围外应用权限，不能修改内置权限含义。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `permissions.manage` | 管理自定义权限 | 登记、修改与删除自定义权限。 | 仅获准系统或应用范围。 | 不能修改或删除内置系统权限，不能跨应用修改权限。 | 否 | 否 | `system_admin` | 是 | rbac.roles_permissions |
| `permissions.state.update` | 启停权限 | 启用或停用获准范围内的权限。 | 仅获准权限，停用即拒绝对应操作。 | 默认仅 root，可明确委派非核心范围；不能取消安全底线。 | 是 | 否 | - | 是 | rbac.roles_permissions |
| `applications.read` | 查看应用 | 查看获准范围内应用的资料与状态。 | 系统管理员限管理范围；应用管理员仅已分配应用。 | 不能查看未分配应用的资料或凭证。 | 否 | 否 | `system_admin` | 是 | applications.manage |
| `applications.create` | 创建应用 | 创建新的应用登记。 | 仅系统管理员的管理范围。 | 应用管理员不默认拥有；不能创建后自动获得系统管理资格。 | 否 | 否 | `system_admin` | 是 | applications.manage |
| `applications.update` | 修改应用资料 | 修改获准应用的显示资料。 | 系统管理员限管理范围；应用管理员仅已分配应用。 | 不能修改应用 ID、client_type 或作用范围，不能借此扩大权限。 | 否 | 否 | `system_admin` | 是 | applications.manage |
| `applications.credentials.manage` | 管理应用凭证 | 轮换应用密钥或公钥凭证。 | 仅指定应用；需再次确认身份。 | 不包含服务器 HTTPS 私钥；默认不授予应用管理员，需明确授予。 | 是 | 否 | `system_admin` | 是 | applications.manage |
| `applications.members.manage` | 管理应用成员 | 管理应用成员及应用内状态。 | 仅指定应用。 | 不能因此禁用或删除全局账户，不能修改全局管理资格。 | 否 | 否 | `system_admin` | 是 | applications.manage |
| `authorization.check` | 联合校验授权 | 校验访问令牌与所需应用权限。 | 仅获准调用的应用与目标资源。 | 不能查询其他应用的身份详情，不能改变权限或签发令牌。 | 否 | 否 | - | 是 | access.joint_check |
| `sessions.revoke` | 强制会话退出 | 强制获准范围内的普通用户退出相关会话。 | 仅获准用户或应用会话。 | 不包含 root；不能用于绕过登录验证或冒充用户。 | 否 | 否 | `system_admin`、`user_admin` | 是 | session.admin |
| `audit.read` | 查看安全记录 | 查看获准范围内的安全审计记录。 | 仅获准范围，内容按权限脱敏。 | 不能修改或删除原始记录，不能查看范围外记录。 | 否 | 否 | `system_admin`、`auditor` | 是 | audit.events |
| `audit.export` | 导出安全记录 | 按许可导出获准范围内的安全记录。 | 仅获准范围，导出仍脱敏。 | 不能删除记录，不能导出未脱敏的秘密或范围外数据。 | 否 | 否 | `system_admin`、`auditor` | 是 | audit.events |
| `reports.read` | 查看统计报告 | 查看获准数据范围内的统计报告。 | 仅获准数据范围。 | 不能查看范围外数据，缺失数据必须标记而不是记为零。 | 否 | 否 | `system_admin`、`auditor` | 是 | reports.generate |
| `reports.generate` | 生成统计报告 | 生成获准数据范围的统计报告。 | 仅获准数据范围。 | 不能生成超出权限范围的报告，不能伪造数据来源。 | 否 | 否 | `system_admin`、`auditor` | 是 | reports.generate |
| `reports.export` | 导出统计报告 | 导出获准范围的报告文件。 | 仅获准数据范围，按格式安全转义。 | 不能导出未获准的数据，不能绕过脱敏与注入防护。 | 否 | 否 | `system_admin`、`auditor` | 是 | reports.generate |
| `reports.schedule.manage` | 管理定期报告 | 安排与暂停定期报告任务。 | 仅获准数据范围；任务不能超出所有者当前权限。 | 不能创建超出权限范围的任务，不能修改他人报告。 | 否 | 否 | `system_admin`、`auditor` | 是 | reports.generate |
| `reports.cleanup` | 清理过期报告文件 | 按保留策略清理已到期的报告产物文件。 | 仅获准数据范围；必须强认证并记录实际目标与结果。 | 不能删除原始审计记录，不能清理未到期或范围外文件。 | 否 | 否 | `system_admin` | 是 | reports.generate |
| `backups.create` | 创建备份 | 创建备份任务；需要再次认证。 | 系统范围；同一时刻只运行一个备份。 | 不能下载数据库文件，不能覆盖既有备份。 | 是 | 否 | `system_admin` | 是 | backup.restore |
| `backups.read` | 查看备份任务 | 查看备份任务、计划与受控清单摘要。 | 获准系统范围。 | 查看清单不代表可下载数据库文件，也不代表可取消或清理。 | 否 | 否 | `system_admin` | 是 | backup.restore |
| `backups.cancel` | 取消备份任务 | 请求取消获准范围内的备份/清理任务。 | 获准系统范围；取消请求不等于实际取消。 | 不能删除既有备份，不能取消范围外任务。 | 否 | 否 | `system_admin` | 是 | backup.restore |
| `backups.export` | 下载备份 | 下载备份成品；需要独立权限与再次认证。 | 可能覆盖全系统数据，需明确授予。 | 默认仅 root，可审慎委派；查看列表不代表可下载。 | 是 | 否 | - | 是 | backup.restore |
| `backups.retention` | 管理备份保留策略 | 查看与修改数量/天数/容量保留上限。 | 系统范围。 | 修改需再次认证并记录责任身份；不能删除原始审计。 | 是 | 否 | `system_admin` | 是 | backup.restore |
| `backups.cleanup` | 清理备份产物 | 按保留策略清理备份成品文件。 | 系统范围；保护规则优先。 | 不能删除原始审计；最后可用备份与未知状态产物受保护。 | 是 | 否 | `system_admin` | 是 | backup.restore |
| `backups.restore` | 恢复备份 | 用备份恢复系统数据（维护模式 + 预演 + 凭证失效）。 | 全系统高风险操作。 | 仅 root 或受控本地应急管理员；不能通过普通角色分配下放。 | 是 | 是 | - | 是 | backup.restore |
| `audit.purge` | 清理安全记录 | 按保留策略清理安全审计记录。 | 全系统高风险操作。 | 仅 root；不能通过普通角色分配下放。 | 是 | 是 | - | 是 | audit.events |
| `security.policy.manage` | 修改敏感操作规则 | 查看、修改与恢复敏感操作安全策略。 | 全系统高风险操作。 | 仅 root；不能通过普通角色分配下放，不能取消安全底线。 | 是 | 是 | - | 是 | security.policy_reauth |
| `settings.manage` | 修改常规设置 | 修改常规运行设置。 | 仅常规设置，不包含敏感策略。 | 不能修改敏感操作规则、主密钥或未脱敏秘密。 | 否 | 否 | `system_admin` | 是 | settings.managed |
| `diagnostics.read` | 查看运行诊断 | 查看脱敏的运行诊断信息。 | 系统或明确的应用范围；仅返回脱敏运行状态、队列计数、配置生效/待重启字段与关联错误白名单。 | 不能查看未脱敏秘密、主密钥、完整配置、个人资料或审计原文；不能修改任何状态。 | 否 | 否 | `system_admin` | 是 | diagnostics.operations |

## 3. 系统预设角色（5 个）

| 角色键 | 名称 | 说明 | 限制 | 内置 | 默认权限 | 默认用户组 | 关联能力 |
|---|---|---|---|---|---|---|---|
| `system_admin` | 系统管理员 | 管理普通用户、应用、用户组和普通角色，维护备份与报告；新建预设按专门权限包含直接修改普通用户用户名与直接重置普通用户密码。 | 仅限 root 已交给他的管理范围；默认不能修改敏感操作规则、恢复备份、清理审计、操作 root 或自行扩大授权范围；两项直接管理操作仍要求操作者本次完成两步验证，不需要目标确认或独立审批。 | 是 | `self.profile.read`、`self.profile.update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage`、`users.read`、`users.create`、`users.update`、`users.disable`、`users.username.change.other`、`users.password.reset.other`、`recovery.request`、`groups.read`、`groups.manage`、`roles.read`、`roles.manage`、`roles.assign`、`permissions.read`、`permissions.manage`、`applications.read`、`applications.create`、`applications.update`、`applications.credentials.manage`、`applications.members.manage`、`sessions.revoke`、`audit.read`、`audit.export`、`reports.read`、`reports.generate`、`reports.export`、`reports.schedule.manage`、`reports.cleanup`、`diagnostics.read`、`settings.manage`、`backups.create`、`backups.read`、`backups.cancel`、`backups.retention`、`backups.cleanup` | `system-administrators` | account.users、admin.facade_api、applications.manage、audit.events、auth.password_session、backup.restore、diagnostics.operations、mfa.public_facade、mfa.totp_recovery、oauth_oidc.protocol、passwordreset.self_service、rbac.roles_permissions、reports.generate、session.admin、settings.managed、support.recovery、users.direct_management |
| `user_admin` | 用户管理员 | 创建、查询、修改和禁用普通用户，发起密码找回。 | 仅限获准管理的用户；默认不能操作 root、其他高权限管理账户或修改权限分配；直接修改他人用户名与直接重置他人密码是两项独立高风险权限，默认不授予，需由 root 逐项分配。 | 是 | `self.profile.read`、`self.profile.update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage`、`users.read`、`users.create`、`users.update`、`users.disable`、`recovery.request`、`sessions.revoke` | `user-administrators` | account.users、admin.facade_api、auth.password_session、mfa.public_facade、mfa.totp_recovery、oauth_oidc.protocol、passwordreset.self_service、session.admin、support.recovery |
| `support` | 客服 | 查询必要的脱敏资料，登记求助事项，向用户原已验证邮箱发送密码重置入口，查询本人负责的处理进度。 | 仅限分配给客服的普通用户；不能查看或指定密码、修改邮箱后再重置、清除两步验证、冒充用户登录或操作高权限账户。 | 是 | `self.profile.read`、`self.profile.update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage`、`recovery.request`、`support.cases.read`、`support.cases.create`、`support.cases.update` | `support-team` | account.users、auth.password_session、mfa.public_facade、mfa.totp_recovery、oauth_oidc.protocol、passwordreset.self_service、support.recovery |
| `auditor` | 审计员 | 查看安全记录，查看和生成统计报告，按许可导出记录。 | 仅限获准查看的应用和用户；不能修改用户、改变权限或删除原始记录。 | 是 | `self.profile.read`、`self.profile.update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage`、`audit.read`、`audit.export`、`reports.read`、`reports.generate`、`reports.export`、`reports.schedule.manage` | `auditors` | account.users、audit.events、auth.password_session、mfa.public_facade、mfa.totp_recovery、oauth_oidc.protocol、reports.generate |
| `normal_user` | 普通用户 | 修改自己的资料，管理自己的密码、登录方式、会话和应用授权。 | 仅限自己；敏感修改仍需再次确认身份，不能查看或改变他人资料。 | 是 | `self.profile.read`、`self.profile.update`、`self.credentials.manage`、`self.sessions.manage`、`self.grants.manage` | `normal-users` | account.users、auth.password_session、mfa.public_facade、mfa.totp_recovery、oauth_oidc.protocol |

## 4. 应用创建时的角色模板（2 个）

| 角色键 | 名称 | 说明 | 限制 | 内置 | 默认权限 | 默认用户组 | 关联能力 |
|---|---|---|---|---|---|---|---|
| `app_admin` | 应用管理员 | 管理指定应用资料、成员、应用内角色和应用独有权限。 | 仅限指定应用；不能修改共享密码、其他应用权限或系统管理资格；转授权限需另有许可。 | 否 | - | `app-administrators` | - |
| `app_user` | 应用普通用户 | 登录已加入的应用，使用明确分配的业务功能。 | 仅限自己已加入的应用和已获准功能；加入应用不代表自动拥有全部功能。 | 否 | - | `app-users` | - |

## 5. 系统默认用户组（5 个）

| 用户组键 | 名称 | 说明 |
|---|---|---|
| `system-administrators` | 系统管理员组 | 系统管理员角色的默认成员组，初始化不自动加入成员。 |
| `user-administrators` | 用户管理员组 | 用户管理员角色的默认成员组，初始化不自动加入成员。 |
| `support-team` | 客服组 | 客服角色的默认成员组，初始化不自动加入成员。 |
| `auditors` | 审计员组 | 审计员角色的默认成员组，初始化不自动加入成员。 |
| `normal-users` | 普通用户组 | 普通用户角色的默认成员组，初始化不自动加入成员。 |

## 6. 应用创建时的用户组模板（2 个）

| 用户组键 | 名称 | 说明 |
|---|---|---|
| `app-administrators` | 应用管理员组 | 应用管理员角色的默认成员组，初始化不自动加入成员。 |
| `app-users` | 应用用户组 | 应用普通用户角色的默认成员组，初始化不自动加入成员。 |

## 7. 机器可读

- [permission-keys.json](permission-keys.json)：权限/角色/用户组完整机器表（含默认权限与能力关联）。
- 生成源：`internal/preset.DefaultCatalog()`（版本化只读目录；不创建账户、不自动赋权）。
