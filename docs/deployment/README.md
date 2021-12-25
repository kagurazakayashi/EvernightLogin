# 部署与交付文档（步骤 89）

本目录是 login（EvernightLogin）第一版的**部署、首次配置、反向代理、容器、服务托管、
业务接入与发布包**说明。文档只描述**当前真实实现**；尚未实现的能力在每篇文档的
「当前状态」一节明确列出，不会用示例配置或截图冒充可用。

## 1. 文档索引

| 文档 | 内容 |
|---|---|
| [../guide/README.md](../guide/README.md) | 面向新手的产品使用指南（快速开始、配置参考、错误码与排障等集中入口） |
| [standalone-service.md](standalone-service.md) | 独立服务安全启动前置条件、配置加载顺序、监听/TLS/代理边界、停机与托管 |
| [first-run.md](first-run.md) | 首次配置（root 受限初始化）的真实流程、状态与防锁死要求 |
| [reverse-proxy.md](reverse-proxy.md) | 反向代理、可信转发头、路径前缀/子路径、公开地址的配置与样例 |
| [container.md](container.md) | 容器镜像、卷、只读根文件系统、非 root 运行与限制 |
| [service-hosting.md](service-hosting.md) | Windows 服务、systemd、launchd 托管样例与操作步骤 |
| [integration.md](integration.md) | 业务接入契约：OIDC 登录、服务身份、权限联合校验、设备码、扫码登录、Token 保存边界 |
| [packaging.md](packaging.md) | 发布包内容、跨平台构建矩阵、版本/依赖/许可证/校验清单、排除项 |
| [e2e-smoke.md](e2e-smoke.md) | 发布前端到端冒烟测试器说明（真实进程 + 真实 SQLite；依赖源码树脚本与 `tools/`） |
| [samples/](samples/) | 可直接对照修改的样例（YAML、Nginx、Caddy、Dockerfile、systemd、WinSW、launchd） |

样例配置**不含真实秘密**：密钥只能来自受保护的环境变量或受限权限文件，证书路径、
域名、应用 ID 都是占位符，使用时必须替换。

发布包内的对应关系：`samples/` 同时以 `docs/deployment/samples/` 保留（文档内链接在
包内可用），运维可直接使用的副本位于 `config/`（YAML、代理）与 `deploy/`（容器、
服务托管）。Linux/macOS 解压 ZIP 后 **没有 Unix 执行位**，先执行
`chmod +x bin/*` 再运行，详见 `packaging.md` §2.1。

`e2e-smoke.md` 描述的是源码树内的发布前冒烟门禁：它依赖 `scripts/e2e-login-server.ps1`
与 `tools/loginte2e`，这两个组件**不随发布包分发**，发布包内只有该说明文档；需要执行
冒烟测试时请在源码树中按该文档操作。

## 2. 当前交付状态（先读这一节）

| 能力 | 状态 | 证据 / 说明 |
|---|---|---|
| 配置加载与校验（YAML < 环境变量 < 代码覆盖） | 已实现 | `login.Load`/`login.Default`/`login.Fields`；示例 `examples/config-load` |
| 监听组件（多地址、Host、可信代理、TLS/mTLS、安全重载） | 已实现（Go API） | `login.NewServer` + `login.ServerOptions`；HTTP 处理与页面可通过 `login.NewHTTPHandler`、`login.NewWebUI`、`login.Instance` 装配 |
| 嵌入模式启动/关闭/就绪（宿主 `net/http`） | 已实现（Go API） | `login.New` + `Instance.Start/Ready/Close`，见 `docs/embedding/host_integration.md` |
| 内置 Web 页面、模板、静态资源、中文文案 | 已实现（内嵌 `embed.FS`） | `web/` + `ui_embed.go`；无 Node/npm 构建链 |
| 独立服务进程 `cmd/login-server` | 已实现（MVP） | `serve` 真实启动 HTTP 服务（配置/数据库/迁移门禁/密钥/审计/维护门禁/单实例锁/内置账户入口页/健康检查/TLS/访问日志轮转/后台任务运行时/协议与管理 API 挂载点/有界优雅关闭）；`init` 本地受控首次初始化 |
| 首次配置入口 | 已实现（CLI） | `login-server init`：本地一次性凭证 + 交互式/受保护 stdin 密码；不提供 HTTP 初始化入口，不接受命令行明文密码 |
| 内置页面装配范围 | 已装配 | `ui.go` 共 **14 个页面选项**：默认注册 **12 个**（账户入口/资料/两步验证/用户管理/RBAC/应用/客服/敏感策略/审计/统计/报告/备份）；**2 个条件注册**：安全中心需 `passkey.enabled` 且 `protocol.enabled`、OAuth 页面需 `protocol.enabled`，未满足时不注册（404），全部满足时 14 个。安全中心页另含 TOTP/Passkey/恢复代码/会话/已授权应用；真实服务与生产授权见 `standalone-service.md` 第 3.8 节 |
| OAuth/OIDC 协议与管理 API 的 HTTP 路由 | 已实现但默认关闭 | `protocol.enabled`/`--enable-protocol` 开启 OAuth/OIDC（Discovery/JWKS/授权/令牌/UserInfo/撤销）；`--enable-admin-api` 开启管理 JSON API（审计/报告/计划/备份/任务/错误码）。设备码、令牌状态查询、扫码登录未启用；关闭时 404、维护模式 503 |
| 备份创建与离线查看工具 `cmd/login-backup` | 已实现 | `create`/`verify`/`info`/`list`/`tables`/`preview`/`export`/`extract` |
| 本地管理/应急命令 `cmd/loginctl` | 已实现（部分写动作受限） | root 应急恢复、恢复/维护、`config`/`diag`/`migrate`/`task`/`session`/`user` 本地命令；`group`/`role`/`app`/`permission`/`notify` 本地管理（读取与受控建组；需要委派/敏感策略的写动作返回 `MANAGEMENT_WRITE_NOT_EXPOSED`）；`audit`/`reports`/`backups`/`notifications`/`tasks` 在线管理需 `--session-file` 并连接已启用管理 JSON API 的服务；逐条用法以 `loginctl help` 为准（详见 `../guide/root-cli.md` 第 8 节） |
| 数据库迁移 | 已实现（SQLite 为主） | `migrations/` 内嵌，按版本追加；MySQL/PostgreSQL/SQL Server 适配**未运行实测** |

> 结论：本版本可以**在受限范围内**作为独立 HTTP 服务启动（健康检查 + 14 个页面选项：
> 默认注册 12、条件 2 + 本地初始化），并可按开关提供 OAuth/OIDC 协议端点与管理 JSON API
> （默认关闭）；设备码/扫码/令牌状态查询未启用，root Passkey 绑定未做真机互操作，邮件
> 外发仍本地禁用。不要把「能启动」等同于「所有客户端互操作已验证」；可交付边界见
> `standalone-service.md` 第 6 节。

## 3. 平台与验证口径

| 平台/架构 | 代码 | 编译 | 运行实测 |
|---|---|---|---|
| Windows amd64 | 有 | 有（`CGO_ENABLED=0`） | 只允许在 Windows amd64 实测；本版本实测范围见 `packaging.md` |
| Windows arm64 | 有 | 有 | 未实测 |
| Linux amd64 / arm64 | 有 | 有 | 未实测（按项目约束不做运行实测） |
| macOS amd64 / arm64 | 有 | 有 | 未实测（按项目约束不做运行实测） |

本轮发布包干净重建（HEAD `597b503`）已实测六个目标全部编译成功，Windows amd64 二进制
冒烟通过；产物、构建信息与校验结果见 `packaging.md` 第 4、6 节。

数据库以 SQLite 为唯一运行实测目标；MySQL、PostgreSQL、SQL Server 只提供适配代码与
编译/静态检查结果，不声称已可用。

## 4. 阅读顺序建议

1. 先读 `standalone-service.md` 第 1 节，确认你要的部署形态当前是否可用；
2. 再读 `first-run.md` 与 `reverse-proxy.md`，准备配置与网络边界；
3. 上线前对照 `packaging.md` 核对产物与校验清单；
4. 业务接入按 `integration.md` 的契约与安全边界实现，不要把示例里的演示适配器当生产实现。
