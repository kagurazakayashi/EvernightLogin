# 嵌入模式与独立部署

login 有两种使用形态。**当前版本只有嵌入模式能真正启动 HTTP 服务**；独立服务进程
`cmd/login-server` 还只是命令行入口。本文说明如何选择、各自边界，以及独立部署前必须
补齐的前置条件。

## 1. 两种形态对照

| 维度 | 嵌入模式（Embedding） | 独立服务（Standalone） |
|---|---|---|
| 运行方式 | 你的 Go 程序导入 `github.com/kagurazakayashi/EvernightLogin`，在进程内装配 | 单独运行 `login-server` 进程，对外提供 HTTP |
| 当前状态 | **可用（Go API）** | **仅命令行入口**，HTTP 启动装配未实现 |
| 数据库/日志/监听 | 由你的程序打开、配置与关闭 | 计划由 login 自己管理 |
| 页面与路由 | 挂到你的 `http.ServeMux`（`Instance.Mount`）或使用 `Instance.Handler` | 计划内置全部页面与协议路由 |
| 适合场景 | 已有 Go 后端，希望“登录/权限”作为库使用 | 希望独立部署一个统一登录中心 |
| 当前可以直接上线 | 可以装配你需要的部分（配置、页面、健康检查、扩展），完整身份服务仍需模块内装配 | **不可以**（见第 3 节） |

## 2. 嵌入模式：能做什么、不能做什么

### 2.1 已实现的公开能力

- 配置：`login.Load`/`login.Default`/`login.Validate`/`Fields`/`Diagnostic`。
- 实例生命周期：`login.New` → `Start` → `Ready` → `Close`，失败可回滚，宿主资源不会被
  擅自关闭。
- 扩展注册：`Options.Extensions`，分类为组件/存储/通知/认证/MFA/页面；认证与 MFA
  分类的失败按 fail-closed 处理（不会降级为“跳过认证”）。
- HTTP 装配：`login.NewHTTPHandler`、`Options.HTTP`、`Options.Pages`、
  `Instance.Mount`、`Instance.Handler`、`Instance.HandlerPrefix`。
- 内置页面：`login.NewWebUI`（登录、注册、资料、安全中心、管理、审计、报告、备份等），
  可整体替换或按页覆盖；页面替换**不会**放宽服务端认证/授权/CSRF。
- 监听组件：`login.NewServer`（多地址、Host 校验、可信代理、TLS/mTLS、安全重载）。
- 授权判定契约：`AccessController`/`AccessRequest`/`AccessDecision` 与
  `Instance.CheckAccess`（未注入即拒绝的 fail-closed 语义）。

完整符号列表、兼容与破坏性变更策略见
[../embedding/host_integration.md](../embedding/host_integration.md)。

### 2.2 当前不承诺、或外部宿主做不到的部分

- **完整业务服务装配**：账户、认证、会话、授权、审计、报告、备份等真实服务目前在
  `internal/`（Go 的 `internal` 规则禁止模块外导入），外部宿主不能只靠公开包装配出
  完整身份服务。
- **认证/MFA 扩展只有契约**：可注册、可管理生命周期，但没有生产认证适配器；不装配时
  受限/拒绝是预期行为。
- **多实例/集群共享状态**：未实现；同一进程多实例隔离已测，跨进程协调没有。
- **第三方 HTTP 框架**：只承诺标准 `net/http`；gin/echo/chi 等需宿主自行适配。

### 2.3 最小装配顺序

```text
1) login.Load(...)                 // 配置校验；失败必须在任何副作用之前返回
2) login.NewWebUI(...)             // 可选：内置页面（注入页面后端）
3) login.NewHTTPHandler(...)       // 最小 HTTP 契约 + 页面挂载
4) login.NewServer(...)            // 可选：监听组件；本身不开始监听直到 Start
5) login.New(...) → Start → Ready  // 生命周期；宿主仍负责 Database/日志/监听
6) 宿主自行 http.ListenAndServe 或使用 Server.Start
7) 关闭：Instance.Close → Server.Close（顺序与启动相反）
```

完整代码与逐字段可编译检查见
`docs/deployment/standalone-service.md` 第 3 节和 `examples/deployment-minimal`。

**资源所有权**：数据库连接、HTTP 服务器与监听、日志器、Notifier、AccessController、
宿主 mux 都归宿主所有；实例只管理自己启动的扩展/组件。导入本包不会启动协程、打开
数据库或监听端口。

## 3. 独立部署：当前状态与上线前置

### 3.1 当前真实状态

| 项目 | 状态 |
|---|---|
| `login-server serve --config <path>` | **已实现**：读取并校验 YAML、打开/校验 SQLite 迁移、装配真实服务与账户入口页、监听 HTTP、有界优雅关闭 |
| `login-server init --config <path>` | **已实现**：本地受控首次初始化（唯一 root、一次性凭证兑换、root 正式密码） |
| `login-server --version` / `--help` | 可用（退出码 0） |
| `login-server`（无参数） | 退出码 1，stderr 明确提示使用 `serve`/`init` |
| 首次配置 HTTP 入口 | **不提供**（安全设计：root 只能本地受控创建） |
| OAuth/OIDC/设备码/扫码/管理 HTTP 路由 | **未实现**（协议实现仍是受信 Go API） |
| 发布包（`login-server.exe` 等二进制） | 可用于本地初始化与启动内置账户入口页；**不等同于完整 OAuth2/OIDC 服务** |

```bat
:: 实测（Windows amd64）
login-server.exe --version
:: 输出：login-server devel (commit unknown, built unknown, go1.27.4)，退出码 0

login-server.exe
:: 退出码 1；stderr 提示使用 serve 或 init 子命令，不会假装启动
```

完整命令、参数与限制见 [../deployment/standalone-service.md](../deployment/standalone-service.md)
与 [../deployment/first-run.md](../deployment/first-run.md)。

### 3.2 已补前置与仍缺前置

已补齐（本轮宿主装配 MVP）：

1. 服务启动装配：读取配置 → 校验 → 打开/迁移 SQLite → 装配真实服务与账户入口页 →
   监听 → 有界优雅关闭。
2. 首次配置 CLI：本机受限、一次性、限时的 root 初始化；不开放匿名远程初始化。

仍缺（不得当作已完成）：

3. 协议 HTTP 路由：OAuth/OIDC、设备码、扫码、管理 JSON API（按安全边界逐项接线）。
4. root 强认证（MFA/Passkey）绑定流程与在线管理授权（不能拿示例替身当生产鉴权）。
5. 其余管理页面后端、邮件/Webhook 投递、后台任务调度、备份/恢复端到端演练。

因此当前版本适合：本机/内网受限范围内的账户入口页与健康检查，以及嵌入式 Go 集成；
不适合：直接作为完整对外 OAuth2/OIDC 身份服务。安全模型与防锁死清单见
[../deployment/first-run.md](../deployment/first-run.md)。

## 4. 网络与 TLS 边界（两种形态共用）

- 默认只监听 `127.0.0.1:8080`；非回环明文监听必须同时满足：
  `server.tls_terminating_proxy=true`、非空 `server.trusted_proxies`、https 的
  `server.public_base_url`。
- 只有 `trusted_proxies` 里的直连来源提供的 `Forwarded`/`X-Forwarded-*` 才被采信；
  未配置时完全忽略转发头，客户端无法伪造地址、协议或域名。
- Host 必须显式允许：配置了 `public_base_url` 时只接受其主机与 `allowed_hosts`；否则
  只接受本机回环主机名。禁止从请求 Host 动态推导身份相关地址。
- 本地 TLS 用 `server.tls_cert_files`/`server.tls_key_files`（或 PFX）；与
  `tls_terminating_proxy` 互斥。私钥文件必须是受保护普通文件。
- mTLS 三件套：`tls_client_auth` + `tls_client_ca_files` + `tls_client_identities`；
  有可信 CA 签发的证书不等于获准接入，还必须命中显式身份映射。
- 部署在子路径时，`path_prefix`、`public_base_url` 的路径部分、反向代理转发路径三者
  必须一致；不一致时启动校验或请求校验会失败。
- 反代、容器、服务托管样例见 `docs/deployment/samples/`；这些样例**未做真实联调**，
  上线前按 `docs/deployment/reverse-proxy.md` 与 `service-hosting.md` 校验。

## 5. 平台与实测口径

| 平台/架构 | 编译 | 运行实测 |
|---|---|---|
| Windows amd64 | 已实测 | 唯一实测平台 |
| Windows arm64、Linux amd64/arm64、macOS amd64/arm64 | 已编译 | 未运行实测 |
| SQLite | 已实测 | 唯一实测数据库 |
| MySQL / PostgreSQL / SQL Server | 已编译（方言与适配代码） | 未运行实测 |

Linux/macOS 解压 ZIP 后没有 Unix 执行位，需要 `chmod +x bin/*`；详见
`docs/deployment/packaging.md`。

## 6. 选择建议

- 你的业务已经是 Go 服务，且只需要配置、页面框架、健康检查、扩展与生命周期：
  **用嵌入模式**，按第 2.3 节装配。
- 你需要一个独立的统一登录中心：**当前版本还不能满足**；请等待独立服务装配与首次
  配置入口实现，或由有能力的团队在模块内（`cmd/login-server` 所在模块）完成装配。
- 无论哪种形态，都不要把本地工具（`loginctl`、`login-backup`）暴露成网络接口；它们是
  本地运维/应急通道。
