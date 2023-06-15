# Login 第一版需求矩阵（步骤 157 最终版 v1.0）

- 版本：**最终版 v1.0（2026-11-22 00:2x，Asia/Shanghai）**；执行者：小肥鱼（task-102）；按 `step157-audit.md` NOTES 收口。
- 依据：`docs/requirements/login_功能列表_v1.1.md`（正文 1.2，24 章）、`docs/requirements/login_错误码与排障手册.md`、根 `AGENTS.md` §6/§10/§11/§12/§13/§14、`plan-step157-166.md`、`.ai/lead/reports/step91～96*.md`、当前工作树只读实测与 `steps91-96` 历史矩阵。
- 基线：父仓库 HEAD `200bfac`，最终版时工作树 dirty **346 项**（Lead 将冻结/提交）；这是冻结前最终矩阵，**不是发布通过结论**。历史步骤 96 的 PASS 只作历史基线，不能替代当前树证据。
- 当前阶段（冻结前）：143 dev+审计 PASS_WITH_NOTES；144/145 复验 PASS_WITH_NOTES；152/154 审计 PASS_WITH_NOTES；156 审计 PARTIAL；159 PARTIAL（恢复代码/Passkey 登录 DEFERRED）；160 FAIL（设备页 404/reauth 阻塞）；162 PASS_WITH_NOTES；164 PASS_WITH_NOTES；166 候选 6/6+verify 183/0 完整（skip 171/0）、BLOCKED_FINAL（dirty/Mail pin）。

## 0. 状态图例

| 状态 | 含义 |
|---|---|
| **PASS-A** | 当前树存在真实生产装配（页面/CLI/API）且有当前树可复跑证据；本起草快照中尚无行达到该标准，待 158–163 验收后填写 |
| **PASS-H** | 有历史 Windows/SQLite 真实实现与步骤 91–96 验收证据；不等于当前生产入口已验收 |
| **PARTIAL** | 代码/历史证据存在，但当前生产装配、HTTP/页面/CLI 入口或当前轮证据缺失 |
| **BLOCKED** | 相关能力未交付或依赖步骤未完成，当前不可验收（注明归口步骤） |
| **N/A** | 需求明确第一版不包含（约定不做），不是缺口 |
| **DOC** | 非功能/文档项，已核对落点或待文档最终更新 |

## 1. 24 个需求章节矩阵

| 章 | 需求要点（摘要） | 代码落点 | 生产装配入口（页面/CLI/API） | 证据（当前可核对项） | 状态 | 缺口/归属 |
|---|---|---|---|---|---|---|
| 1 范围与原则 | Go Module、嵌入/独立共用、共享账户/应用隔离、单实例、SQLite/Windows 优先、默认拒绝、中文文档 | 根包 `login`/`Instance`、`internal/*`、`config`、`authz` | `login.New`/`Instance`；`login-server serve`；`examples/external-consumer` | 步骤 88/91/95 历史；138 A01 外部 module/API 表面 PASS | PASS-H | 138 Phase B（appcore 抽取）PARTIAL；独立服务当前树最终证据待 158 |
| 2 运行形态/集成 | net/http Handler、宿主注入、资源所有权、独立服务、CLI 与页面共用逻辑 | `internal/serverapp`、`cmd/*`、`app`/`appcore` | `serve`/`init`、`loginctl`、`login-backup`；14 个页面选项 | 138 A01 PASS、138 6/6 回归（21:45）；`login-server --help` 可运行 | PARTIAL | 138 Phase B；页面/HTTP 全量证据待 158/161 |
| 3 页面与替换 | 全功能内置页面、可替换、响应式/i18n、键盘/无障碍、管理后台 | `web/**`（104 模板）、`ui.go` 页面框架、`ui_pages_*` | 14 个页面选项；`/login\|register\|account\|security\|admin\|support` 等 | 步骤 93 38 行（34 PASS/2 PARTIAL/2 NOT_TESTED）；当前页面测试 PASS | PARTIAL | 真实浏览器/读屏/真机 NOT_TESTED（159/161）；可替换契约当前树证据待补 |
| 4 用户/资料/生命周期 | CRUD/禁停/导入导出、注册/邀请/审核、稳定 ID、资料/邮箱/电话/头像 | `internal/account\|profile\|emailchange\|avatar\|onboarding` | `/admin/users`、`/account/profile`；`loginctl user` | 步骤 91 42/42 PASS；147 页面后端 PASS_WITH_NOTES；155 应用侧页面测试 | PASS-H | 当前 HTTP 用户管理端到端待 158；邮箱验证/变更待 140（已出 dev） |
| 5 登录与认证 | 密码/邮箱登录、策略/限流/防枚举、Passkey、认证强度/近期认证 | `authn\|passkey\|ratelimit\|session` | `/login`、`/mfa`、`/security` | 步骤 91/92；95 审查；**159 真实 Chrome/CDP 虚拟认证器**：Passkey 注册、TOTP 绑定/二次登录 PASS；恢复代码/Passkey 登录页 DEFERRED | PARTIAL | 159 PARTIAL：恢复代码生成 400 MFA_REQUIRED、Passkey 登录页未接线；真实硬件/Windows Hello/读屏 NOT_TESTED |
| 6 设备码与扫码 | Device Grant、轮询/取消、扫码绑定/一次性/防重放/跨应用 | `oauthflow`、`qrlogin`、`protocolapi` | 协议端点默认关闭；设备确认/扫码页面 | 143 dev+审计 PASS_WITH_NOTES（真实 HTTP 设备码流程）；142 PARTIAL；160 设备确认页真实 serve 404、授权码/QR 批准被 reauth 阻塞 | PARTIAL | 142 完整 QR 批准/领取闭环未完成；160 B1 reauth/B2 设备页 404；完整设备/扫码验收待后续 |
| 7 两步验证与恢复 | 邮件码/TOTP/FIDO2/恢复码、找回、受限恢复、重绑、旧凭证失效 | `mfa\|recovery\|passwordreset\|credential` | `/mfa`、`/security`、找回页面 | 步骤 91/92；159 TOTP 绑定/二次登录 PASS、恢复代码生成 DEFERRED；162 邮件验证/找回/告知故障 PASS_WITH_NOTES（duplicate 等 PARTIAL） | PARTIAL | 159 恢复代码消费/受限重绑未完成；真实硬件 NOT_TESTED；162 Mail duplicate Copier/队列证据 PARTIAL |
| 8 敏感策略与告知 | 敏感操作目录/默认值、reauth、邮件告知队列/失败/频率 | `policy\|reauth\|notify\|mailer` | `/admin` 策略/通知页；`loginctl notify`；mail 配置 | 步骤 72/91；139 recheck PASS；140/141；**162 PASS_WITH_NOTES**：邮箱变更/旧邮箱告知失败路径通过，认证/TLS/拒收/断连/延迟/重试均实测 | PARTIAL | 162 duplicate Copier、找回/MFA 队列证据 PARTIAL；客服恢复/外部环境 NOT_TESTED |
| 9 会话/设备/令牌 | 会话/设备/退出、强制下线、令牌分离、权限变化即时、离线边界 | `session\|token\|tokenrevoke` | `/security` 本人会话；`loginctl session`；管理 API `/sessions/revoke` | 步骤 91/92/94；151 后端/API/CLI 完成，**管理强制下线 Web 页可选未做** | PASS-H | 151 可选页面缺口；跨应用 HTTP E2E 未做（151 自述） |
| 10 应用登记与 OAuth/OIDC | 应用登记/凭证/回调、Auth Code+PKCE、Device、Client Credentials、Refresh、Discovery/JWKS、撤销/状态查询 | `app\|oauthclient\|oauthflow\|protocolapi\|oidc\|token` | `/oauth/*`、`/admin/applications`；loginte2e | 步骤 92；144/145 复验 PASS_WITH_NOTES；142 PARTIAL；**160 FAIL**：Discovery/JWKS/PKCE/CC 通过，设备确认页 404、授权码/QR 批准被 reauth 阻塞 | PARTIAL | 160 设备页 404/外部 reauth；142 QR 闭环；真实第三方客户端/手机 NOT_TESTED；CLI help 仍过时（G157-11） |
| 11 组/角色/权限 | 组/角色/系统+应用权限、50 权限键、预设角色、委派/防自提权、客服限制 | `group\|role\|authz\|preset\|delegation` | `/admin/groups\|roles\|permissions\|applications`；`loginctl group/role/app/permission` | 步骤 91 权限矩阵 PASS；verify-docs 50 键 PASS；149 完成；146–148 notes；155 应用页 PARTIAL | PARTIAL | 权限目录 `Implemented` 44 true/6 false 需逐键核验；146–148/155 当前 HTTP 证据待收口 |
| 12 Token 联合校验 | 可信资源服务、all/any、令牌+当前权限交集、稳定错误码/request_id | `tokenauthz\|protocolapi\|authz` | 管理/业务 HTTP；Go API | 步骤 92；144/145 复验 PASS_WITH_NOTES（B1 CLOSED，真实 HTTP E2E 复跑） | PASS-H | 真实第三方资源服务/外部部署未测；160 外部客户端/reauth 仍未通 |
| 13 应用托管管理 API | 操作/对象/字段白名单、成员/角色/权限、幂等/分页/版本、Webhook | `managedapi\|app\|adminapi\|webhook` | `/admin/v1` 默认关闭；应用页 | 146/147/148 均有 PASS_WITH_NOTES；真实 SQLite + HTTP 集成用例 | PARTIAL | 146 缺“页面→适配器→managedapi→SQLite”单条 E2E；147 YAML 配置未落地；Webhook 真实外发 NOT_TESTED |
| 14 安全审计与日志 | 审计/访问/运行日志分离、W3C、脱敏、轮转/保留、查询/导出/root 清理 | `audit\|auditops\|logging\|transport/accesslog` | `loginctl audit`；`/admin/audit`；访问日志 | 步骤 73/74/93/94；当前 `verify-docs` PASS；审计页测试 | PASS-H | 当前生产审计清理/报告在线入口需 158–163 复跑；真实部署日志轮转 NOT_TESTED |
| 15 审计报告与统计 | 事件/错误/去重口径、趋势/分类、五格式、计划/下载/权限、完整性 | `reports\|stats\|task` | `/admin/reports\|statistics`；`loginctl reports`；管理 API | 步骤 93 五格式/口径/撤权 PASS | PASS-H | 163 在线报告/计划/下载/GB 级未验收；当前生产入口待补 |
| 16 网络/TLS/安全 | 多地址/SNI/证书/mTLS/代理/限流/CSRF/XSS/SSRF/路径/响应头、ASVS 对照 | `listener\|tlscert\|netguard\|ratelimit\|transport\|authz\|secret` | `login-server serve` TLS/mTLS/代理；管理入口 | 步骤 95 安全审查；`OWASP_ASVS_第一版适用性对照.md`（内部自评非认证） | PARTIAL | 真实反代/HTTPS/mTLS/浏览器 Cookie 联调 NOT_TESTED；ASVS 非认证 |
| 17 数据库与模型 | SQLite + 其他方言、ID/时间/唯一性/事务、46 条迁移 | `database\|internal/*/sqlite`、`migrations` | `serve/init --migrate`；`loginctl migrate` | SQLite 步骤 7/80–82/91/94；46 条迁移；其他 DB 编译/静态 | PASS-H | 非 SQLite 运行 NOT_TESTED（约定）；非 SQLite 备份未测 |
| 18 备份与恢复 | 热备份/调度/保留/取消/审计/加密、恢复预演/维护/回退/旧凭证失效/库外代际 | `backup\|restore\|maintenance\|task`、`login-backup`、`loginctl restore-*` | `login-backup`；`loginctl maintenance/restore` | 步骤 80–82/94；`login-backup --help` 全子命令；94 矩阵 PASS | PASS-H | 152 人工恢复制度/真实执行器未交付；163 在线恢复/失败回退未验收 |
| 19 离线备份查看/导出 | 版本/来源/清单/校验/加密、只读预览、CSV/JSON/提取、路径/解压/公式防护、操作记录 | `cmd/login-backup`、备份查看库 | `login-backup info/verify/list/tables/preview/export/extract` | 步骤 83/94；CLI help 完整；工具测试 | PASS-H | GB 级/真实 DACL/硬链接逃逸 NOT_TESTED（低风险残余） |
| 20 CLI 与 root 应急 | 初始化/诊断/迁移/管理/会话/审计/报告/备份、root 密码+MFA 重置、本地边界 | `cmd/loginctl`、`cmd/login-server init`、`login-backup`、`rootrecovery` | `loginctl help` 已列 root-recover/config/diag/migrate/task/session/user/group/...；在线域需 session-file | 步骤 48/84/93；CLI help 实测；151 session admin-revoke | PASS-H | 在线管理需管理会话/强认证；部分写动作 `MANAGEMENT_WRITE_NOT_EXPOSED` 为设计边界；root 真机强因素 NOT_TESTED |
| 21 配置/扩展/运维 | YAML/环境/代码优先级、51 字段、严格校验、热更新、防锁死、扩展、诊断 | `config`、`serverapp`、扩展接口 | `serve/init`；`loginctl config/diag` | `verify-docs` PASS checks=12（错误码 48/配置 51/权限 50/链接）；139 env 14 项复验 | PASS-H | 首次初始化 CLI 已具备；生产热更新/故障场景待 158–163 |
| 22 平台/文档/验证 | 六目标编译、Windows/SQLite 实测、其他仅编译、错误码/OpenAPI/文档一致 | `scripts/build-release\|verify-release\|verify-docs`、`docs/**` | 发布脚本；`verify-docs` | 当前 `go build`/`verify-docs` PASS；**166 候选（冻结前 00:17）：6/6 built、verify 183/0 完整（skip 171/0；含 LICENSE/署名与 Windows 冒烟）；产物 release-166-freeze-candidate**；165 文档 DRAFT_FINAL | PARTIAL | 仅 Windows amd64 运行；其他 NOT_TESTED；dirty 346 无干净基线；Mail 零提交/无 pin；166 仍 CANDIDATE/BLOCKED_FINAL |
| 23 第一版不包含 | 多租户/多实例、动态插件、第三方社交登录、短信、通用 APP、完整跨库迁移 | 无对应入口，未虚假声明 | — | 需求 §23/设计基线；未发现伪造入口 | N/A | 约定不做，不作为缺口 |
| 24 修订摘要 | 稳定 ID/资料可变性、客服流程、权限目录/中文说明、错误码/请求编号、报告/Markdown、安全边界、备份生命周期 | 分散：account/profile/support/preset/reports/backup | 对应页面/CLI/API | 步骤 91/93/95/96 对照 | DOC | 权限目录 `Implemented` 元数据 44/6、CLI/文档一致性需继续核对（165/157 收口） |


## 2. AGENTS 关键不变量表

| AGENTS 节 | 不变量 | 代码/入口 | 证据 | 状态 | 缺口 |
|---|---|---|---|---|---|
| §6 固定边界 | Go Module、嵌入/独立共用、共享账户/应用隔离、单实例、SQLite 优先、默认拒绝、中文文档 | 根包、internal、config/authz | 88/91/92/95 历史；138 A01 | PASS-H | 138 Phase B PARTIAL；独立服务 158 未验收 |
| §10 账户/权限 | 稳定 ID、用户名唯一可更名、状态机、资料白名单、邮箱验证、组/角色/权限、root 保护、防自提权、客服流程 | account/profile/group/role/authz/preset/support | 91 42/42；149/146–148/155 | PASS-H/PARTIAL | 155 硬删除/151 页/应用管理员列表；156 三端一致性 |
| §11 认证/MFA/OAuth | Argon2id、Passkey、TOTP/邮件/恢复码、找回/受限恢复、会话/令牌、OAuth/OIDC、Token 联合校验 | authn/passkey/mfa/recovery/session/token/oauthflow/tokenauthz | 91/92/94；143 dev+审计；144/145 复验 PWN；159 真实浏览器 PARTIAL | PARTIAL | 159 恢复代码/Passkey 登录 DEFERRED；142/160 设备页/QR/外部 reauth；真实硬件 NOT_TESTED |
| §12 页面/审计/报告 | 全功能页面/可替换/响应式、审计/访问日志、报告五格式/权限/计划/去重 | web/ui/audit/auditops/reports | 93 38 行；153/155 页面；verify-docs | PARTIAL | 真实浏览器（159/161）；在线报告/备份（163）；156 一致性 |
| §13 备份/部署/验收 | 热备份/取消/审计/恢复/旧凭证失效、离线查看、CLI/root、配置/平台/文档 | backup/restore/maintenance、CLI、发布脚本 | 80–83/94；152 dev+审计 PWN；166 候选 6/6+verify 171/0 | PASS-H/PARTIAL | 163 未验收；166 dirty/Mail pin；非 Windows/非 SQLite NOT_TESTED |
| §14 Mail/Login 区分 | Login 保留生产 SMTP/OAuth/SQLite；邮件验证只连 Mail；不移植 Mail 免认证/明文/无数据库 | mailer、mail 配置、mail 相关业务 | 139 recheck；140/141；**162 PASS_WITH_NOTES**；Mail 133/134 解锁 | PARTIAL | 162 Mail duplicate Copier/队列证据/客服外部 NOT_TESTED；真实外发未验收 |

## 3. 未登记/未收口缺口登记（归属与关闭条件）

| ID | 缺口/风险 | 影响章节 | 归口 | 关闭条件 |
|---|---|---|---|---|
| G157-01 | 143 已 dev+审计 PWN；仍未完成：142 完整 QR 批准/领取、160 设备确认页 404/reauth 阻塞 | 6 | 142/160 | 修复 160 设备页与外部 reauth；补 142 QR 完整闭环 |
| G157-02 | **CLOSED（复验 PWN）**：144 B1 夹具已修复，真实 HTTP E2E 复跑通过 | 12 | 144 | 已关闭；外部部署/第三方资源服务未测 |
| G157-03 | **CLOSED（复验 PWN）**：145 B1 已修复，introspection/撤销真实 HTTP E2E 复跑通过 | 10/12 | 145 | 已关闭；真实外部客户端未测 |
| G157-04 | 152 dev+审计 PASS_WITH_NOTES（密码恢复+Mail 实测；MFA 真实双操作员未测） | 8/18/153 | 152 | 最终 Windows 验收；MFA 真实双操作员 |
| G157-05 | 154 dev+审计 PASS_WITH_NOTES（真实 SQLite/HTTP/A-B 隔离；OAuth Token E2E 未做） | 8/11 | 154 | 最终 Windows 验收；真实 OAuth Token E2E |
| G157-06 | 156 dev+审计 PARTIAL（域路由/在线只读/未认证拒绝 PASS；强认证写 E2E/写面未完成） | 11/20/22 | 156 | 补强认证写 E2E/写面；三端同语义 |
| G157-07 | 138 Phase B appcore 构建层抽取 PARTIAL | 1/2 | 138 | 完成抽取并复跑 6 回归点；当前 6/6 PASS 但 Phase B 未闭环 |
| G157-08 | 应用硬删除无领域能力；只有停用，页面不伪造删除 | 10/11/155 | 155/Lead 决策 | 决定是否另立 app 领域删除任务；否则维持“停用不等于删除”并记录 |
| G157-09 | 151 可选强制下线 Web 页未做（无 `UIPageSessions` 公共契约） | 9 | 151/156 | 新增页面契约与后端或明确不做；当前仅 API/CLI |
| G157-10 | 应用管理员 `/admin/applications` 列表受 system-scope 限制 403 | 11/155 | 156/147 | 应用范围列表路由/授权语义收口 |
| G157-11 | `login-server --help` 仍称设备码/扫码/introspection 未启用，与 142/144/145 实现状态不一致 | 10/22 | 165 | 按最终实现更新 CLI 帮助/guide/README；不得提前宣称已启用 |
| G157-12 | 146 缺“页面→适配器→managedapi→SQLite”单条 E2E；147 YAML 配置因 139 写域未落地 | 13 | 146/147 | 补端到端用例；YAML 配置化完成 |
| G157-13 | 权限目录 50 键中 44 `Implemented=true`/6 false，需逐键代码核验 | 11 | 157/147/148/155 | 每键对应真实执行路径/拒绝路径；更新元数据与文档 |
| G157-14 | 真实浏览器/硬件认证器/第三方 OAuth 客户端/手机扫码 NOT_TESTED | 3/5/6/10/16 | 159/160/161 | 对应真实环境验收；无硬件明确标 NOT_TESTED |
| G157-15 | 非 Windows/非 SQLite 运行未实测；GB 级/ENOSPC/跨机恢复未测 | 16/17/18/22 | 约定/后续验收 | 项目约定只标 NOT_TESTED；不冒充支持 |
| G157-16 | 当前树 dirty **339 项**、无干净可复现基线 | 全部 | 用户提交/158+ | 用户提交后冻结基线，按干净树重建/重跑证据 |
| G157-17 | 158–163 端到端验收未全部执行（矩阵只有代码/历史/分段证据）；166 仅候选 | 全部 | 158–163/166 | 158–163 记录与干净基线重建后重评 PASS-A |
| G157-18 | 159 DEFERRED：恢复代码生成 400 `MFA_REQUIRED`、Passkey passwordless 登录页未接线；真实硬件/读屏未测 | 5/7 | 159 | 扩展 reauth 挑战/恢复装配、Passkey 登录页；重跑 159 |
| G157-19 | 160 真实阻塞：设备确认页 `/oauth/device` 404、授权码/QR 批准缺少受控外部 reauth；第三方客户端/手机 NOT_TESTED | 6/10 | 160 | 修设备页路由与外部 reauth 流程；重跑 160 |
| G157-20 | 166 候选：项目 LICENSE 已补；仍 dirty 346、Mail 零提交/无 gitlink、无干净发布基线 | 22/全部 | 用户/Lead/166 | 用户提交干净基线+Mail pin；重建/verify/冒烟后最终判 |

## 4. 证据来源与核实命令（当前实测）

| 检查 | 结果/输出 |
|---|---|
| `go run ./scripts/verify-docs` | **DOCS VERIFY: PASS checks=12 failures=0**（错误码 48、配置字段 51、权限键 50、链接/必备文档） |
| `go build ./...` | **PASS**（当前树；GOMAXPROCS=4，验证后并行改动仍可能变化） |
| `go run ./cmd/login-server --help` | 显示 serve/init；明确“未启用：设备码、扫码登录、令牌状态查询（introspection）”（需 165 按最终实现更新） |
| `go run ./cmd/loginctl help` | root-recover、restore-*、maintenance-*、config/diag/migrate/task/session/user/group/role/app/permission/notify/audit/reports/backups 等命令组 |
| `go run ./cmd/login-backup --help` | create/verify/info/list/tables/preview/export/extract/help/version |
| 页面清单 | `ui.go` **14 个页面选项**；`web/templates/page` **104 个模板**；路由名 grep 218 条（含少量非页面匹配，正式以 WebUI.Routes 为准） |
| 权限/迁移 | `internal/preset/catalog.go` 50 键，`Implemented` 44 true/6 false；`migrations/*.sql` 46 条 |
| loginte2e | 套件：`discovery jwks authcode token device qr tokenauthz introspect adminapi all`；秘密从受保护文件读取 |
| 历史证据 | `docs/acceptance/步骤91～96*.md`（42/77/38/60 行矩阵、NOT_TESTED 口径）、`OWASP_ASVS_第一版适用性对照.md` |
| 当前 dev/审计 | 138 Phase A/PARTIAL；139 recheck PASS；140/141 dev；**143 dev+审计 PASS_WITH_NOTES**；**144/145 复验 PASS_WITH_NOTES**；146–148 notes；149–151 done；152/154 审计 PASS_WITH_NOTES；**156 审计 PARTIAL**；153 dev；155 PARTIAL；**159 PARTIAL（DEFERRED 恢复代码/Passkey 登录）**；**160 FAIL（设备页 404/reauth）**；162/164 PASS_WITH_NOTES；**166 候选 6/6、verify 171/0、BLOCKED_FINAL** |

## 5. 142–166 收口表（矩阵更新入口）

| 步骤 | 当前证据/状态 | 对本矩阵的影响 | 收口后要补的证据列 |
|---|---|---|---|
| 138 | Phase A PASS / Phase B PARTIAL；6/6 回归 21:45 | 章 1/2 维持 PARTIAL | appcore 抽取完成 + 最终回归；独立服务/页面入口 |
| 139 | 安全复验 PASS_WITH_NOTES（14 env 修复） | 章 8/14 可升证据 | 邮件 env/真实 Mail E2E 当前树 |
| 140/141 | dev+审计已出（邮件验证/找回告知） | 章 4/7/8 | 真实 HTTP/邮件投递证据；未验证邮箱状态 |
| 142 | PARTIAL（QR 匿名/拒绝 HTTP；登录闭环 NOT_TESTED） | 章 6/10 | 完整 QR 批准→领取闭环、跨应用/重放 |
| 143 | dev+审计 PASS_WITH_NOTES（真实 HTTP 设备码流程；页面确认 UI/expired 等 NOT_TESTED） | 章 6 PARTIAL | 完整确认页/扫码页面/外部设备；160 设备页 404 修复 |
| 144/145 | **复验 PASS_WITH_NOTES（B1 CLOSED，真实 HTTP E2E 复跑）** | 章 12 PASS-H；章 10 仍受 160 外部 reauth 影响 | 真实第三方资源服务/外部部署；160 客户端闭环 |
| 146/147/148 | PASS_WITH_NOTES | 章 11/13 | 页面→managedapi SQLite 单条 E2E；YAML 配置 |
| 149/150/151 | done | 章 9/11 | 151 可选 Web 页/跨应用 HTTP；150 浏览器视觉 |
| 152 | dev + 审计 PASS_WITH_NOTES（密码恢复+Mail 实测；MFA 真实双操作员未测） | 章 8/18 可升 PARTIAL | 最终 Windows 验收；MFA 真实链路 |
| 153 | dev（客服前端执行 gating） | 章 8/11 | 152 执行器真实服务 + 浏览器 |
| 154 | dev + 审计 PASS_WITH_NOTES（真实 SQLite/HTTP、A/B 隔离、自批拒绝；OAuth Token E2E 未做） | 章 8/11 可升 PARTIAL | 最终 Windows 验收；真实 OAuth Token E2E |
| 155 | PARTIAL（应用新建完成；硬删除/151 页缺口） | 章 10/11 | 硬删除决策；应用管理员列表 403；浏览器 |
| 156 | dev + 审计 PARTIAL（domain routes/在线只读/未认证拒绝通过；强认证写 E2E 未完成） | 章 11/20/22 可升 PARTIAL | 补强认证写 E2E 与写面；三端一致 |

| 159 | PARTIAL（真实 Chrome+CDP 虚拟认证器：Passkey 注册、TOTP 绑定/二次登录 PASS；恢复代码生成 400 MFA_REQUIRED、Passkey 登录页未接线 DEFERRED） | 章 5/7 PARTIAL | reauth 挑战扩展、Passkey 登录页接线；硬件/读屏 NOT_TESTED |
| 160 | **FAIL（真实阻塞）**：Discovery/JWKS/PKCE/CC/introspection/设备申请/QR 创建部分通过；设备确认页 404、授权码/OIDC/refresh/QR 批准被 reauth 阻塞 | 章 6/10 PARTIAL | 修复设备页路由与受控外部 reauth；真实第三方客户端仍 NOT_TESTED |
| 162 | **PASS_WITH_NOTES**（CSRF 修复后邮箱变更/旧邮箱告知失败通过；认证/TLS/拒收/断连/延迟/重试实测） | 章 8 PARTIAL；162 记录 | Mail duplicate Copier、找回/MFA 队列证据 PARTIAL；客服恢复/外部 NOT_TESTED |
| 164 | **PASS_WITH_NOTES**（gofmt/vet/build/mod verify、Step94、session/token/reports 定向、CSRF 回归 PASS） | 章 16 证据 | govulncheck/gosec/race NOT_TESTED；真实部署/浏览器未测 |
| 166 | **CANDIDATE / BLOCKED_FINAL**（6/6 built、verify 183/0 完整含 LICENSE/冒烟；dirty/Mail pin） | 章 22 PARTIAL | 用户提交干净基线 + Mail pin 后重建/verify 最终判 |

## 6. 结论

- **最终统计（冻结前 v1.0）**：24 章中 **11 行 PASS-H、11 行 PARTIAL、0 行 BLOCKED、1 行 N/A、1 行 DOC**；自检 24=11+11+0+1+1。**PASS-A 仍为 0**（158–163 最终生产入口验收未全部完成）。
- **VERDICT：PASS_WITH_NOTES（157 矩阵最终版；不是发布通过）**：24 章/AGENTS 不变量/20 项缺口均有归口；159/160/162/164/166 状态已按最新报告更新；159 DEFERRED、160 FAIL、166 候选阻塞均已登记，未把历史 PASS 或分段测试冒充当前生产验收。
- 剩余硬阻塞：160 设备页 404/外部 reauth、159 恢复代码/Passkey 登录 DEFERRED、166 dirty/Mail pin/最终矩阵与 158–163 未收口；144/145/152/154 复验/审计已关闭（PWN），156 仍 PARTIAL。
- 下一步：Lead 提交干净基线后 166 重建复核；补 159/160 缺口并重跑；158–163 验收后把对应行升 PASS-A，再更新本矩阵统计，不得用历史 96 步 PASS 或测试数量替代真实生产入口/Windows SQLite 验收。
