# 部署与交付文档（步骤 89）

本目录是 login（EvernightLogin）第一版的**部署、首次配置、反向代理、容器、服务托管、
业务接入与发布包**说明。文档只描述**当前真实实现**；尚未实现的能力在每篇文档的
「当前状态」一节明确列出，不会用示例配置或截图冒充可用。

## 1. 文档索引

| 文档 | 内容 |
|---|---|
| [standalone-service.md](standalone-service.md) | 独立服务安全启动前置条件、配置加载顺序、监听/TLS/代理边界、停机与托管 |
| [first-run.md](first-run.md) | 首次配置（root 受限初始化）的真实流程、状态与防锁死要求 |
| [reverse-proxy.md](reverse-proxy.md) | 反向代理、可信转发头、路径前缀/子路径、公开地址的配置与样例 |
| [container.md](container.md) | 容器镜像、卷、只读根文件系统、非 root 运行与限制 |
| [service-hosting.md](service-hosting.md) | Windows 服务、systemd、launchd 托管样例与操作步骤 |
| [integration.md](integration.md) | 业务接入契约：OIDC 登录、服务身份、权限联合校验、设备码、扫码登录、Token 保存边界 |
| [packaging.md](packaging.md) | 发布包内容、跨平台构建矩阵、版本/依赖/许可证/校验清单、排除项 |
| [samples/](samples/) | 可直接对照修改的样例（YAML、Nginx、Caddy、Dockerfile、systemd、WinSW、launchd） |

样例配置**不含真实秘密**：密钥只能来自受保护的环境变量或受限权限文件，证书路径、
域名、应用 ID 都是占位符，使用时必须替换。

发布包内的对应关系：`samples/` 同时以 `docs/deployment/samples/` 保留（文档内链接在
包内可用），运维可直接使用的副本位于 `config/`（YAML、代理）与 `deploy/`（容器、
服务托管）。Linux/macOS 解压 ZIP 后 **没有 Unix 执行位**，先执行
`chmod +x bin/*` 再运行，详见 `packaging.md` §2.1。

## 2. 当前交付状态（先读这一节）

| 能力 | 状态 | 证据 / 说明 |
|---|---|---|
| 配置加载与校验（YAML < 环境变量 < 代码覆盖） | 已实现 | `login.Load`/`login.Default`/`login.Fields`；示例 `examples/config-load` |
| 监听组件（多地址、Host、可信代理、TLS/mTLS、安全重载） | 已实现（Go API） | `login.NewServer` + `login.ServerOptions`；HTTP 处理与页面可通过 `login.NewHTTPHandler`、`login.NewWebUI`、`login.Instance` 装配 |
| 嵌入模式启动/关闭/就绪（宿主 `net/http`） | 已实现（Go API） | `login.New` + `Instance.Start/Ready/Close`，见 `docs/embedding/host_integration.md` |
| 内置 Web 页面、模板、静态资源、中文文案 | 已实现（内嵌 `embed.FS`） | `web/` + `ui_embed.go`；无 Node/npm 构建链 |
| 独立服务进程 `cmd/login-server` | **仅命令行入口** | 只提供 `--version`/`--help`；不带参数以非零退出并明确报错，**不会假装服务已启动** |
| 独立服务 HTTP 启动装配（读取配置后监听） | **未实现** | 尚无 CLI/装配代码；部署时必须使用嵌入模式或等待后续装配步骤 |
| 首次配置的 CLI/HTTP 入口 | **未实现** | 领域能力在 `internal/bootstrap`（仅本模块可导入），未暴露给独立部署 |
| OAuth/OIDC、设备码、扫码、管理接口的 HTTP 路由 | **未实现** | 只有内嵌页面路由与受信 Go API；业务接入约定见 `integration.md` |
| 备份创建与离线查看工具 `cmd/login-backup` | 已实现 | `create`/`verify`/`info`/`list`/`tables`/`preview`/`export`/`extract` |
| 本地管理/应急命令 `cmd/loginctl` | 部分实现 | root 应急恢复、恢复/维护命令；常规管理命令依赖宿主装配，当前为工作树内未提交改动 |
| 数据库迁移 | 已实现（SQLite 为主） | `migrations/` 内嵌，按版本追加；MySQL/PostgreSQL/SQL Server 适配**未运行实测** |

> 结论：本版本**还不能作为独立 HTTP 身份服务直接对外部署**。发布包里的二进制可用于
> 版本查询、备份与本地管理；需要真实 HTTP 身份服务的部署必须基于 Go API（嵌入模式）
> 完成装配，相关前置在 `standalone-service.md` 第 1 节列出。

## 3. 平台与验证口径

| 平台/架构 | 代码 | 编译 | 运行实测 |
|---|---|---|---|
| Windows amd64 | 有 | 有（`CGO_ENABLED=0`） | 只允许在 Windows amd64 实测；本版本实测范围见 `packaging.md` |
| Windows arm64 | 有 | 有 | 未实测 |
| Linux amd64 / arm64 | 有 | 有 | 未实测（按项目约束不做运行实测） |
| macOS amd64 / arm64 | 有 | 有 | 未实测（按项目约束不做运行实测） |

数据库以 SQLite 为唯一运行实测目标；MySQL、PostgreSQL、SQL Server 只提供适配代码与
编译/静态检查结果，不声称已可用。

## 4. 阅读顺序建议

1. 先读 `standalone-service.md` 第 1 节，确认你要的部署形态当前是否可用；
2. 再读 `first-run.md` 与 `reverse-proxy.md`，准备配置与网络边界；
3. 上线前对照 `packaging.md` 核对产物与校验清单；
4. 业务接入按 `integration.md` 的契约与安全边界实现，不要把示例里的演示适配器当生产实现。
