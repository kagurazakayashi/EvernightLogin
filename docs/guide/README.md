# login 新手文档（产品使用指南）

本目录是 login（EvernightLogin）面向新用户、运维与接入开发者的**集中入口文档**。它按
“先能判断能不能用、再按场景操作”的顺序组织，并与详细的部署、嵌入、需求与数据库文档
互相链接，避免同一内容在多处重复。

> 本文档只描述**当前代码真实具备**的能力。所有“实现了但还不能通过独立服务 HTTP 使用”
> 的部分都会明确标注状态；请不要按功能清单（`docs/requirements/`）里的设计目标直接当
> 成已上线能力。

## 1. 文档地图

| 文档 | 读它做什么 |
|---|---|
| [quickstart.md](quickstart.md) | 在 Windows 上从空配置开始，跑通配置校验、迁移、诊断等当前真实可执行的步骤 |
| [deployment-modes.md](deployment-modes.md) | 选择嵌入模式（宿主 Go 进程）还是独立服务，并看清独立服务的当前缺口 |
| [api-status.md](api-status.md) | 公开 Go API 的稳定范围、GoDoc/OpenAPI 现状、错误响应与 request_id 约定 |
| [login-and-oauth.md](login-and-oauth.md) | 登录、扫码、OAuth 2.0 / OIDC（OpenID Connect，基于 OAuth 2.0 的身份层）接入契约与当前状态 |
| [applications-and-permissions.md](applications-and-permissions.md) | 应用、应用成员、系统权限与应用独有权限、权限键清单 |
| [roles-and-scopes.md](roles-and-scopes.md) | 预设角色、应用内角色、用户组、作用范围（scope）与数据范围、委派与有效权限 |
| [configuration.md](configuration.md) | 全部 37 个配置字段、默认值、覆盖优先级、秘密来源、热更新与重启分类 |
| [support-and-recovery.md](support-and-recovery.md) | 客服求助、人工核验恢复、恢复代码与受限恢复会话 |
| [root-cli.md](root-cli.md) | `loginctl` 本地应急命令（root 恢复、维护模式、恢复流程、诊断）与退出码 |
| [audit-and-reports.md](audit-and-reports.md) | 安全审计、统计看板与统计报告（HTML/PDF/CSV/JSON/Markdown）能力与边界 |
| [backup-and-restore.md](backup-and-restore.md) | 加密热备份、离线校验与只读查看/导出、维护模式恢复流程 |
| [troubleshooting.md](troubleshooting.md) | 48 个稳定错误码、按类别的排障顺序、CLI 退出码与常见“看起来坏了”的问题 |

已有的详细文档（本指南会引用，不重复内容）：

| 位置 | 内容 |
|---|---|
| [../deployment/README.md](../deployment/README.md) | 部署总览、当前交付状态、平台口径、样例文件 |
| [../deployment/first-run.md](../deployment/first-run.md) | 首次配置（root 受限初始化）的安全模型与防锁死清单 |
| [../deployment/standalone-service.md](../deployment/standalone-service.md) | 独立服务启动前置条件与嵌入模式启动骨架 |
| [../deployment/integration.md](../deployment/integration.md) | 业务接入的完整协议契约（OIDC、服务身份、设备码、扫码、Token 边界） |
| [../embedding/host_integration.md](../embedding/host_integration.md) | 把 login 嵌入 Go 程序的公开 API 稳定范围与生命周期约束 |
| [../requirements/login_功能列表_v1.1.md](../requirements/login_功能列表_v1.1.md) | 产品功能范围（设计目标，不等于全部已实现） |
| [../requirements/login_错误码与排障手册.md](../requirements/login_错误码与排障手册.md) | 错误码权威手册（与 `error_codes.go` 自动比对） |
| [../database/存储模型与迁移设计.md](../database/存储模型与迁移设计.md) | 数据库表、迁移与版本口径 |
| [../../README.md](../../README.md) | 按开发阶段记录的功能与技术细节（偏开发日志） |

## 2. 当前能力总览（先读这一节）

状态图例：**已实现**＝有代码且在本仓库测试；**部分实现**＝核心在、入口或装配缺失；
**未实现**＝没有对应代码或入口；**未实测**＝代码存在但没有真实运行验证。

| 能力 | 状态 | 说明 |
|---|---|---|
| 配置加载与校验（YAML < 环境变量 < 代码覆盖） | 已实现 | `login.Load`、`login.Default`、`login.Fields`；`loginctl config` 可查/校验/改（非秘密字段） |
| Go 嵌入：实例生命周期、扩展注册、页面与 HTTP 挂载 | 已实现（Go API） | `login.New` + `Instance.Start/Ready/Close`；示例 `examples/external-consumer` |
| 内置页面（登录、资料、安全、管理、审计、报告、备份等） | 已实现（内嵌 `embed.FS`） | 需要宿主注入真实后端（会话、权限、数据服务）；完整装配目前只在模块内可行 |
| 最小 HTTP 契约：`/healthz`、`/openapi.json` | 已实现 | 前缀 + 固定后缀；OpenAPI 只是最小文档（见 [api-status.md](api-status.md)） |
| 监听、TLS/mTLS、可信代理、多地址 | 已实现（Go API） | `login.NewServer`；默认只监听回环地址 |
| 账户、应用、角色权限、会话、MFA/Passkey、OAuth/OIDC、设备码、扫码、客服恢复等**领域服务** | 已实现（`internal/`，受信 Go API） | 有真实测试；**HTTP 路由尚未装配** |
| 独立服务进程 `cmd/login-server` | MVP 可用 | `serve` 真实启动 HTTP 服务（健康检查/OpenAPI/内置账户入口页、配置与迁移门禁、维护门禁、TLS、优雅关闭）；`init` 本地受控首次初始化；OAuth/OIDC/管理 API 仍未实现 |
| 首次配置（创建唯一 root） | 已实现（CLI） | `login-server init` 本地受控完成 root 创建、一次性凭证兑换与正式密码设置；不提供匿名 HTTP 入口；root 强认证绑定仍待后续步骤 |
| 本地应急命令 `cmd/loginctl` | 部分实现 | `root-recover`、恢复/维护命令、`config`/`diag`/`migrate`/`task`/`session`/`user` 可用；组/角色/应用/权限/通知在线管理命令当前入口未接通 |
| 备份工具 `cmd/login-backup` | 已实现 | `create`/`verify`/`info`/`list`/`tables`/`preview`/`export`/`extract` |
| SQLite 数据库与迁移 | 已实现 | 44 个内嵌迁移；SQLite 为唯一运行实测目标 |
| MySQL / PostgreSQL / SQL Server 适配 | 部分实现 | 有方言与迁移代码，**未运行实测** |
| 多实例/集群、TCP 代理协议、OCSP/CRL、证书自动续期 | 未实现 | 第一版不含 |

一句话结论：**当前版本可以作为 Go 库嵌入使用，内置页面与本地工具可用；`login-server`
也能真实启动独立 HTTP 服务并完成本地首次初始化，但仅覆盖健康检查与账户入口页，
OAuth/OIDC/设备码/扫码/管理 JSON API 与 root 强认证绑定仍未实现**，尚不能作为完整的
对外 OAuth2/OIDC 身份服务。部署前请读 [deployment-modes.md](deployment-modes.md) 与
`docs/deployment/standalone-service.md`。

## 3. 术语表（首次出现时也逐篇解释）

| 术语 | 直白解释 |
|---|---|
| Go Module（Go 模块） | Go 的依赖与版本单位；本项目本身是一个可被其他 Go 程序导入的模块 |
| 嵌入模式 | 把本项目的 Go 包编进你自己的程序，由你的程序打开数据库、监听端口、调用 API |
| 独立服务 | 单独运行的 login 进程（`login-server serve`），对外提供 HTTP 接口；当前为宿主装配 MVP（健康检查/OpenAPI/账户入口页），完整协议端点待后续步骤 |
| OAuth 2.0 | 一种“应用向用户申请有限访问权”的授权协议；本项目实现授权码、刷新令牌、设备码等流程 |
| OIDC（OpenID Connect） | 在 OAuth 2.0 上增加“登录并确认你是谁”的身份层；提供 ID Token 与 Discovery 文档 |
| PKCE | OAuth 的防授权码拦截机制；公开客户端必须使用，本项目强制 `S256` |
| Token（令牌） | 表示访问权限的凭证；Access Token 访问资源，Refresh Token 换新令牌，ID Token 表示身份 |
| JWT / JWKS | JWT 是带签名的令牌格式；JWKS 是公开发布验签公钥的地址 |
| MFA（两步验证） | 除密码外再要求一个因素（TOTP 动态码、邮件码、安全密钥等） |
| Passkey / WebAuthn | 用设备上的生物识别或安全密钥登录，不发送密码；依赖方（RP ID）是信任根 |
| TOTP | 基于时间的一次性动态码（常见 6 位数字） |
| CSRF / CSP | 跨站请求伪造防护 / 内容安全策略（限制页面能加载哪些资源） |
| mTLS | 双向 TLS：客户端也要出示证书并通过校验 |
| SQLite / WAL | 单文件嵌入式数据库 / 它的预写日志模式（提高并发读写能力） |
| 迁移（migration） | 按版本号顺序升级数据库结构的脚本，已应用的版本不可改写 |
| 热备份 | 服务运行中通过数据库在线备份接口生成一致快照，不能直接复制正在写的库文件 |
| 主密钥 / 密钥环 | 用于加密敏感数据与备份的密钥材料；必须与数据库、备份文件分开保存 |
| root | 唯一且受保护的系统最高管理员；只能由本地受控、一次性初始化流程创建 |
| 作用范围（scope） | 权限或数据“在哪个范围内有效”，分系统级与应用级 |
| 数据范围 | 同一权限能操作哪些数据（如仅本人、指定应用或系统） |
| 委派 | 把自己拥有的权限有条件地转授他人；系统区分“可使用”和“可转授” |
| 审计 | 记录“谁在何时对什么做了什么、结果如何”的安全日志 |
| request_id / task_id | 一次请求的查询编号 / 一个后台任务的编号，用于在受限日志中定位问题 |
| 敏感操作策略 | 对删除、恢复、备份等高风险操作规定再次验证、确认、通知要求的目录 |

## 4. 建议阅读路径

1. **只想确认能不能用**：第 2 节 + [deployment-modes.md](deployment-modes.md) 第 1 节。
2. **准备在自己的 Go 程序里嵌入**：[api-status.md](api-status.md) →
   [configuration.md](configuration.md) → `docs/embedding/host_integration.md`。
3. **想接入登录/OIDC/扫码**：[login-and-oauth.md](login-and-oauth.md) →
   `docs/deployment/integration.md`；先确认 HTTP 路由现状，不要按已上线接口对接。
4. **运维已装配好的实例**：[configuration.md](configuration.md)、[root-cli.md](root-cli.md)、
   [backup-and-restore.md](backup-and-restore.md)、[troubleshooting.md](troubleshooting.md)。
5. **出问题**：[troubleshooting.md](troubleshooting.md) 的错误码表 + 对应章节。

## 5. 本文档的约定

- 命令示例默认**在仓库根目录**执行（除非该命令注明其他目录），并优先给出 Windows 写法；
  非 Windows 平台按已有说明替换路径分隔符与执行位。
- 命令示例标注**前提**与**预期结果**；预期结果不是“绝对成功”，而是本版本的真实行为。
- 命令行、文件名、字段名使用 `代码格式`；配置字段一律用 YAML 点分路径（如
  `database.path`）。
- 不提供“一键关掉安全检查”“跳过权限”“默认密码”之类的捷径；这类做法会破坏本项目的
  安全不变量，相关章节会明确说明正确替代方案。
- 文档中的错误码与 `error_codes.go`（代码注册表）和
  `docs/requirements/login_错误码与排障手册.md`（权威手册）保持一致；配置默认值与
  `login.Default()` 保持一致；CLI 参数与 `--help` 输出保持一致。仓库提供
  `scripts/verify-docs` 静态核对工具，用于在 CI 或发布前复查（见该目录说明）。

## 6. 平台与实测口径

| 平台/架构 | 编译 | 运行实测 |
|---|---|---|
| Windows amd64 | 已实测 | 唯一运行实测平台（本版本） |
| Windows arm64 / Linux amd64、arm64 / macOS amd64、arm64 | 已编译 | 未运行实测 |
| SQLite | 已实测 | 唯一运行实测数据库 |
| MySQL / PostgreSQL / SQL Server | 已编译（方言代码） | 未运行实测 |

未实测不代表不可用，也不代表已通过；正式上线前请在自己的目标平台按
`docs/deployment/packaging.md` 的清单复验。
