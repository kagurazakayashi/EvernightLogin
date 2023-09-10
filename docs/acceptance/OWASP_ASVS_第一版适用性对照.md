# OWASP ASVS 4.0.3 第一版适用性对照（内部自评）

> **性质声明：本文件不是 OWASP ASVS 认证，也不构成任何合规声明。** ASVS 是应用安全验证
> 标准，不是认证证书；本文件只做“第一版功能范围内条款是否适用、当前实现到哪一步”的
> 内部自评，供发布说明、后续验证计划与差距跟踪使用。文中“已实现”仅表示仓库内存在代码
> 且本机有测试或验收证据，“部分实现/未验证/不适用”均为真实边界，不代表已满足条款本身。
> 本文件不宣称通过 ASVS L1/L2/L3 任何级别，也不宣称满足 PCI DSS、GDPR、等保或任何
> 外部标准。对外表述只能是“本项目按 ASVS 4.0.3 做了适用性自查，未做认证”。

## 0. 基线与口径

- 对照标准：OWASP Application Security Verification Standard（ASVS）4.0.3，按 V1～V14
  章节结构组织；条款编号以官方 4.0.3 文档为准，本文件不复述原文条款内容。
- 评估基线：`P:\go\src\github.com\kagurazakayashi\EvernightLogin`，当前干净基线（源码树 `b9c668f`，最终 HEAD 由 Lead 回填）；验收状态以 `requirements-matrix-login.md` 与当前有效验收记录为准。
- 运行与验证环境：Windows 11 amd64、Go 1.27.1、`CGO_ENABLED=0`、SQLite（modernc 纯 Go
  驱动）。其他平台与数据库只做编译/静态检查，**不算运行验证**。
- 状态图例：

| 状态 | 含义 |
|---|---|
| 已实现 | 有真实实现，且在本机 Windows/SQLite 范围内有测试或验收记录 |
| 部分实现 | 核心能力存在，但存在明确缺口（入口未装配、细粒度策略未接线、边界未验证） |
| 不适用 | 第一版产品范围明确不包含，或条款对象不存在（须写明理由） |
| 未验证 | 代码可能存在，但本机缺少真实环境证据（真实浏览器/硬件/外部服务/非 Windows 等） |

- 证据形式：`docs/guide/` 产品文档、`docs/acceptance/requirements-matrix-login.md` 与当前有效验收记录（`step156`、`步骤158`、`步骤159`、`step160`、`step161`、`step162`、`step163`、`step164`、`step165`、`step166`）。本文件只引用可在仓库内复核的结论，不把草稿或过程记录当作认证证据。

## 1. 逐章适用性对照

### V1 架构、设计与威胁建模

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 单一 Go Module；嵌入模式与独立服务共用领域逻辑，不复制两套业务逻辑；账户、认证、权限、审计、敏感操作策略、任务与存储分层；`internal/*` 领域服务不可由外部导入，公开扩展点显式声明。威胁建模以项目安全不变量、`step164` 安全审查与各验收记录的边界表形式存在。 |
| 缺口/未覆盖 | 没有正式的 STRIDE/数据流图威胁模型文档；没有历史的 ASVS 逐条映射（本文件是首个适用性对照）；多实例/多租户架构第一版不包含。 |
| 证据 | [docs/guide/README.md](../guide/README.md) 第 2 节、[docs/embedding/host_integration.md](../embedding/host_integration.md)、`docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`、`docs/acceptance/requirements-matrix-login.md`。 |

### V2 认证

| 项 | 内容 |
|---|---|
| 状态 | 部分实现（领域服务已实现；真实硬件/浏览器/外发渠道未验证） |
| 本项目情况 | 密码使用 Argon2id + 密码策略；登录失败限流；MFA 完整状态机（第一步、等待第二因素、受限恢复、完整认证分开）；TOTP 与 WebAuthn/Passkey 服务端校验（挑战、RP ID、来源、签名、UV）；恢复代码一次性消费后进入受限恢复并强制重新绑定；root 仅能由本地受控一次性初始化创建，不设默认密码。 |
| 缺口/未覆盖 | 真实浏览器 WebAuthn、Windows Hello/YubiKey 等真实硬件认证器未做互操作实测；真实邮件验证/找回外发被禁用（只用本地捕获或显式“未配置发送器”失败）；短信与第三方登录供应商第一版不实现；高权限账户强认证策略的完整运行验证不足。 |
| 证据 | [docs/guide/login-and-oauth.md](../guide/login-and-oauth.md)、[docs/guide/support-and-recovery.md](../guide/support-and-recovery.md)、`docs/acceptance/步骤158：Windows 与 SQLite 初始化、账户与权限端到端验收记录.md`、`docs/acceptance/step160-oauth-external.md`、`docs/acceptance/步骤159：真实浏览器Passkey两步验证与账户恢复验收记录.md`。 |

### V3 会话管理

| 项 | 内容 |
|---|---|
| 状态 | 已实现（运行实测范围）；部分边界未验证 |
| 本项目情况 | 服务端会话与设备管理；空闲/绝对过期；安全版本与账户状态失效；会话秘密只从受保护文件读取；管理会话强认证门禁；OAuth 刷新令牌轮换与重放处理；CSRF 令牌与会话绑定；退出/撤销分开记录。 |
| 缺口/未覆盖 | 多实例/负载均衡下的共享会话与撤销广播第一版不包含；管理强制下线（`sessions.revoke`）未在独立服务注入范围授权器，当前只有本人会话撤销可用（权限目录中该键仍标记未实现）；真实浏览器 Cookie 行为仅以测试客户端验证。 |
| 证据 | [docs/guide/login-and-oauth.md](../guide/login-and-oauth.md) 第 6 节、[docs/guide/root-cli.md](../guide/root-cli.md) 第 6 节、`docs/acceptance/requirements-matrix-login.md`。 |

### V4 访问控制

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | `internal/authz` 服务端判定“令牌范围 ∩ 当前有效权限 ∩ 应用成员/状态 ∩ 数据范围”；内置页面、管理 JSON API、OAuth 客户端动作与 CLI 在线命令都经服务端重新判定，前端隐藏按钮不作为授权；系统权限与应用独有权限分离；root 唯一且不可通过普通角色分配；委派 Guard 在关键写路径同事务检查；跨应用访问返回 `APP_SCOPE_MISMATCH`/`PERMISSION_REQUIRED`。 |
| 缺口/未覆盖 | 按部门/应用的细粒度数据范围映射尚未装配（当前授权器多按“系统范围全覆盖”处理，无权限即拒绝）；管理员强制下线未接线；权限目录中 5 个键（`recovery.approve`、`recovery.mfa.approve`、`sessions.revoke`、`settings.manage`、`diagnostics.read`）仍标记未实现；`authorization.check` 已按扩展端点 `/oauth/token/authorize` 标记实现且不授予预设，`settings.manage`/`diagnostics.read` 不授予预设并登记 203。 |
| 证据 | [docs/guide/applications-and-permissions.md](../guide/applications-and-permissions.md)、[docs/guide/roles-and-scopes.md](../guide/roles-and-scopes.md)、`docs/acceptance/requirements-matrix-login.md` 权限矩阵；`internal/preset/catalog.go` 逐键审计注释。 |

### V5 输入验证与编码

| 项 | 内容 |
|---|---|
| 状态 | 部分实现（实现存在；浏览器侧未做 E2E） |
| 本项目情况 | 请求体大小上限、字段白名单、显式类型/长度/格式校验；用户名规范化（NFKC + Unicode 大小写折叠 + NFC）；SQL 全部参数化；CSV 导出防公式注入；HTML/PDF/Markdown 模板转义或受限渲染；路径/备份条目防穿越；URL/重定向与 SSRF 检查。 |
| 缺口/未覆盖 | 真实浏览器 XSS/点击劫持、读屏与 200% 文本缩放未做 E2E；文件上传仅头像等受限场景；富文本/HTML 报告的外部资源限制靠自包含模板，未做模糊测试。 |
| 证据 | [docs/guide/api-status.md](../guide/api-status.md)、[docs/guide/audit-and-reports.md](../guide/audit-and-reports.md)、`docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`、`docs/acceptance/requirements-matrix-login.md`。 |

### V6 密码学

| 项 | 内容 |
|---|---|
| 状态 | 已实现（使用成熟库）；外部密码学合规未验证 |
| 本项目情况 | 使用 `golang.org/x/crypto`、`crypto/*` 与成熟第三方库，不自研密码协议；密码 Argon2id（参数版本化、随机盐、可升级）；敏感可恢复秘密认证加密；备份 AES-256-GCM；HMAC 摘要（含低熵验证码的密钥化摘要）；主密钥环与数据库/备份分离、受保护文件权限；TLS 1.2+ 与固定算法/允许清单。 |
| 缺口/未覆盖 | 未做 FIPS/HSM/密钥托管合规验证；主密钥轮换与多密钥历史的全链路外部演练未做；`govulncheck` 仅证明当前已知漏洞命中为 0（`step164` 依赖检查），不构成密码学证明。 |
| 证据 | [docs/guide/configuration.md](../guide/configuration.md) 第 3/4 节、[docs/guide/backup-and-restore.md](../guide/backup-and-restore.md)、`docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`、`docs/licenses/THIRD_PARTY_NOTICES.md`。 |

### V7 错误处理与日志

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 稳定公开错误码（48 个）与机器可读注册表；公开错误不泄露账户存在性；内部原因码只进受限审计；审计写入失败时关键操作 fail-closed；日志与报告脱敏、不记录 Token/密码/MFA 秘密；W3C 扩展访问日志含请求编号与安全响应头；文件访问日志默认按单文件上限 + 历史数量上限轮转（`--access-log-max-bytes`/`--access-log-max-files`）。 |
| 缺口/未覆盖 | 审计的自动定时清理与导出产物自动过期清理未实现（第一版靠 root 手动清理，已文档标注）；日志集中采集、外部只追加存储与防篡改未提供；访问日志轮转由单进程控制，多实例/外部轮转未覆盖。 |
| 证据 | [docs/guide/audit-and-reports.md](../guide/audit-and-reports.md) 第 1/2/4 节、[docs/deployment/standalone-service.md](../deployment/standalone-service.md) 第 3.5 节、`docs/requirements/login_错误码与排障手册.md`、`docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`。 |

### V8 数据保护

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 敏感字段加密存储（可恢复秘密、MFA/Passkey 关联材料等）；秘密只来自受保护来源，配置/日志/报告不落明文秘密；备份认证加密、清单含大小/SHA-256/数据库版本；导出按字段许可并脱敏；传输层由 TLS/mTLS 保护；页面不把秘密放 URL/localStorage。 |
| 缺口/未覆盖 | 没有正式的数据分类分级清单与全库静态加密（SQLite 依赖 OS 文件权限）；PII 保留期限与数据主体删除（导出/擦除）未形成自动流程；非 SQLite 数据库未运行实测；真实多用户 Windows DACL 对抗未测。 |
| 证据 | [docs/guide/configuration.md](../guide/configuration.md)、[docs/guide/backup-and-restore.md](../guide/backup-and-restore.md) 第 2/5 节、`docs/acceptance/step163-audit-report-backup.md`。 |

### V9 通信安全

| 项 | 内容 |
|---|---|
| 状态 | 部分实现（实现存在；真实部署未验证） |
| 本项目情况 | TLS/mTLS 监听；证书重载；可信代理与来源校验；Host 校验；安全响应头（CSP、`X-Content-Type-Options`、`Cache-Control: no-store`、`X-Request-ID`）；CORS 精确来源匹配（默认禁用）；SSRF 防护（Webhook/重定向/外部地址）；限流；优雅关闭。 |
| 缺口/未覆盖 | 真实反向代理/容器/公网 HTTPS 部署未实测；真实 mTLS 客户端链路未测；OCSP/CRL、证书自动续期第一版不包含；HSTS 由部署侧（反向代理样例）启用，应用层不设置；只做 Windows 本机回环 TLS 实测。 |
| 证据 | [docs/deployment/standalone-service.md](../deployment/standalone-service.md)、[docs/deployment/reverse-proxy.md](../deployment/reverse-proxy.md)、`docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`。 |

### V10 恶意代码防护

| 项 | 内容 |
|---|---|
| 状态 | 不适用（终端代码条款）+ 部分实现（供应链） |
| 本项目情况 | 本产品不分发移动/桌面终端程序，不加载用户上传的可执行内容、不执行备份内脚本（`login-backup` 只读解析）；备份查看器不自动连接生产库。供应链方面：`go.mod` 精确版本、无 `replace`/`exclude`、许可证清单、`step164` 的 `govulncheck` 当前无 symbol/package 命中。 |
| 缺口/未覆盖 | 无 SBOM、无产物签名/来源证明；依赖升级只做人工审查与 `govulncheck`，未做持续 SCA；第三方在线脚本默认不加载（页面自包含），但未做供应链攻击演练。 |
| 证据 | `docs/acceptance/step164-安全审查、依赖检查与有界并发回归记录.md`、`docs/licenses/THIRD_PARTY_NOTICES.md`、[docs/guide/backup-and-restore.md](../guide/backup-and-restore.md) 第 3 节。 |

### V11 业务逻辑

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 一次性凭证/授权码/恢复代码单次消费；刷新令牌轮换与重放处理；并发唯一性（root 单例、备份单实例、审批/执行单赢家）；取消请求与实际取消分开；幂等键；限流（登录/找回/客服发送）；敏感操作策略 + 再次认证 + 确认 + 安全告知；恢复制度要求独立审批与等待期，root/高权限目标拒绝；备份/恢复/导出记录真实操作者。 |
| 缺口/未覆盖 | 人工核验恢复在独立服务中默认关闭且执行器是 fail-closed 实现，审批/执行链路无法真实完成（`recovery.approve`/`recovery.mfa.approve` 保持未实现）；数据范围细粒度化未完成；真实业务并发压力与故障注入只做到 `step163` 的受控演练范围；自动定时审计清理未实现。 |
| 证据 | [docs/guide/support-and-recovery.md](../guide/support-and-recovery.md)、[docs/guide/backup-and-restore.md](../guide/backup-and-restore.md) 第 4 节、`docs/acceptance/步骤158：Windows 与 SQLite 初始化、账户与权限端到端验收记录.md`、`docs/acceptance/step163-audit-report-backup.md`。 |

### V12 文件与资源

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 受控输出目录（0700）；备份文件名随机 + `O_EXCL`；解压防路径穿越/符号链接/硬链接/膨胀与条目数上限；`login-backup` 只读、受限表白名单与操作符、行数/字节上限；报告渲染限制网络/文件/时间/内存；临时文件与不完整输出在失败时清理；开放文件描述符与连接有界。 |
| 缺口/未覆盖 | GB 级数据库、真实 ENOSPC、SIGKILL/断电恢复、Windows 硬链接/junction 逃逸未实测；非 SQLite 备份内部数据解析未实现（明确报错）；明文快照的安全擦除未提供。 |
| 证据 | [docs/guide/backup-and-restore.md](../guide/backup-and-restore.md) 第 2/3/5 节、步骤 83/94 记录。 |

### V13 API 与 Web 服务

| 项 | 内容 |
|---|---|
| 状态 | 部分实现 |
| 本项目情况 | 统一错误 envelope（稳定错误码 + `request_id`）；每个管理请求重新经会话/权限判定；管理 JSON API 默认关闭、写操作需强认证与 CSRF；OAuth 2.0/OIDC 采用正式库，授权码 + PKCE、设备码、客户端凭证、Refresh 轮换；Discovery 只声明真实实现的端点；内置页面与 API 共用服务端安全判定；OpenAPI 提供最小文档。 |
| 缺口/未覆盖 | OpenAPI 只是最小文档，不是完整契约；标准 Introspection/Revocation HTTP 端点未实现且未声明；没有 OIDC Conformance 测试，真实标准客户端互操作未测；设备码/扫码在部署后的 HTTP 闭环未验证；浏览器页面 E2E 未做。 |
| 证据 | [docs/guide/api-status.md](../guide/api-status.md)、[docs/guide/login-and-oauth.md](../guide/login-and-oauth.md)、[docs/deployment/integration.md](../deployment/integration.md)、`docs/acceptance/step160-oauth-external.md`、`docs/acceptance/step161-business-ui-support-isolation.md`。 |

### V14 配置

| 项 | 内容 |
|---|---|
| 状态 | 已实现（静态与测试核对）；部分边界未验证 |
| 本项目情况 | YAML 配置 37 个字段、严格校验、未知字段拒绝；默认值/环境变量/覆盖优先级明确；秘密字段只接受 `env:`/`file:` 受保护来源；热更新/重启分类；`verify-docs` 静态核对配置字段、错误码、权限键与文档链接；危险默认值默认拒绝（如未迁移数据库拒绝启动、默认库访问需显式开关）。 |
| 缺口/未覆盖 | 配置热重载需宿主自行触发，CLI 不会自动重建；没有配置完整性基线/签名或远程配置源；配置漂移监测未实现；安全默认值依赖部署者正确配置 TLS/反向代理。 |
| 证据 | [docs/guide/configuration.md](../guide/configuration.md)、[docs/deployment/first-run.md](../deployment/first-run.md)、`docs/acceptance/step165-文档最终核对记录.md` 的 `verify-docs` 结果。 |

## 2. 未覆盖与未验证清单（发布说明必须同步保留）

以下项目不是“已满足”，而是本机缺少证据或第一版明确不做。发布或对外说明时必须保留这些边界：

| 类别 | 未覆盖/未验证内容 | 关联章节 |
|---|---|---|
| 真实客户端 | 真实浏览器（含读屏、键盘、200% 文本、窄屏/平板视口）、真实手机 APP 扫码闭环 | V5、V11、V13 |
| 真实硬件 | Windows Hello/YubiKey 等真实认证器；真实 mTLS 客户端证书链路 | V2、V3、V9 |
| 外部服务 | 真实邮件外发、真实 Webhook 外发（按规则禁止真实外发，只用本地捕获/显式失败）；真实第三方 OAuth/OIDC 客户端互操作 | V2、V7、V13 |
| 部署形态 | 真实反向代理/容器/公网 HTTPS 部署、跨机器恢复、部署后独立服务全链路、多实例/负载均衡 | V1、V3、V9、V13 |
| 平台/数据库 | Windows arm64、Linux、macOS 运行；MySQL/PostgreSQL/SQL Server 真实连接 | 全章节（按项目约定只做编译/静态） |
| 并发与规模 | `-race`（无 cgo/gcc 未跑）、GB 级数据库、真实 ENOSPC/SIGKILL/断电、大规模压测 | V11、V12 |
| 标准与合规 | OWASP ASVS 认证、OIDC Conformance、FIDO/W3C WebAuthn 认证、PCI DSS/GDPR/等保等合规 | 全文 |
| 供应链 | SBOM、产物签名/来源证明、持续 SCA | V10 |

## 3. 级别结论与后续计划

- **级别声明：未声明通过 ASVS L1、L2 或 L3。** 本文件只给出第一版范围内的适用性判断：
  多数 L1 相关主题有代码与测试证据，但“部署后独立服务 + 真实浏览器/硬件/外部服务”证据
  缺失，因此不能给出级别通过结论。
- 若后续需要做 L1 自评，最低前置条件是：部署后独立服务端到端验收（真实 HTTP + 浏览器）、
  真实硬件认证器与真实客户端互操作、目标部署形态（反向代理/TLS）实测、以及逐条 ASVS
  条目的证据索引；这些均超出本轮收敛范围。
- 维护方式：新增或变更安全相关能力、依赖升级、发布前，应更新本文件的状态与证据；本文件
  不重复各步验收记录的内容，只维护“条款 → 状态 → 证据 → 缺口”的映射。

## 4. 索引与相关文档

- 新手总入口与能力状态：[docs/guide/README.md](../guide/README.md)
- 认证与协议：[login-and-oauth.md](../guide/login-and-oauth.md)
- 权限与角色：[applications-and-permissions.md](../guide/applications-and-permissions.md)、
  [roles-and-scopes.md](../guide/roles-and-scopes.md)
- 审计、报告与访问日志：[audit-and-reports.md](../guide/audit-and-reports.md)
- 备份、恢复与密钥分离：[backup-and-restore.md](../guide/backup-and-restore.md)
- 部署与运维：[docs/deployment/standalone-service.md](../deployment/standalone-service.md)、
  [docs/deployment/first-run.md](../deployment/first-run.md)
- 验收记录：`requirements-matrix-login.md` 与当前有效验收记录（`step156`、`步骤158`、`步骤159`、`step160`、`step161`、`step162`、`step163`、`step164`、`step165`、`step166`）；本文件与这些记录冲突时，以代码与验收记录为准并修正本文件。
