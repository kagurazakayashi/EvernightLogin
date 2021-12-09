# GoDoc 与 OpenAPI 现状

本文说明 login 公开 Go API 的稳定范围、当前 GoDoc 与机器可读接口文档（OpenAPI）的
真实状态，以及调用方应如何理解错误响应。**不要**把这里的最小 OpenAPI 文档当作完整
业务 API 契约。

## 1. GoDoc：已提供，且是权威接口说明

- 根包名 `login`，导入路径 `github.com/kagurazakayashi/EvernightLogin`。
- 包级文档在仓库根 `doc.go`；公开类型与函数带 GoDoc 注释，关键安全不变量写明中文约束。
- 本地查看（任意目录，需在模块内）：

```bat
:: 运行目录：仓库根；平台：任意安装 Go 1.27.x 的环境
go doc .
go doc login.Instance
go doc login.WebUIOptions
go doc -all . | more
```

- 权威的“哪些公开符号稳定、哪些不承诺”见
  [../embedding/host_integration.md](../embedding/host_integration.md) 第 1 节。要点：

| 分类 | 宿主可以依赖 | 说明 |
|---|---|---|
| 稳定契约 | `New`/`Options`/`Instance`/`Start`/`Close`/`Ready`、`Load`/`Default`/`Fields`、`AppError`/`ErrorCode`/`Code*`、`NewHTTPHandler`/`HTTPOptions`、`NewWebUI`/`WebUIOptions`、`NewServer`/`ServerOptions`、身份与上下文函数 | 删除或改变语义属于破坏性变更 |
| 兼容扩展 | `Options`/`WebUIOptions` 新增可选字段、新增错误码、新增扩展分类、新增命名路由 | 零值等价“未启用”，旧代码行为不变 |
| 不承诺稳定 | 内置页面 HTML 结构、日志文本、诊断输出文本、`internal/`、`cmd/*` 命令行参数、未公开的仓储/服务装配 | 不要解析 DOM 或依赖输出格式 |

- 导入本包**不会**启动后台协程、打开数据库或监听端口（没有 `init()` 副作用）；同一进程
  可以安全创建多个实例，互不共享状态。
- 构建信息：`login.CurrentBuildInfo()` 返回版本/提交/构建时间等只读信息；
  `--version` 与文档中的版本示例以此为准。

## 2. OpenAPI：真实存在，但只是“最小 HTTP 契约”

实现位置：`login.OpenAPIDocument(prefix)`（根包导出）与内部传输层同名构造；HTTP
Handler 会在 `<prefix>/openapi.json` 提供该文档。

当前文档的真实内容（OpenAPI **3.0.3**）：

| 项 | 内容 |
|---|---|
| 路径 | 只有两条：`<prefix>/healthz`（GET，返回固定 `{"status":"ok"}`）与 `<prefix>/openapi.json`（GET，返回本文档） |
| 错误信封 | `Error` schema：`code`、`message`、`request_id` 必填，可选 `task_id`、`retry_after_seconds` |
| 错误码枚举 | `code.enum` 与 `x-login-error-registry` 由错误码注册表**同源生成**，新增错误码无需手工维护第二份清单 |
| 保留前缀 | `x-login-oauth-reserved-prefix: /oauth2/`：未来 OAuth/OIDC 标准协议响应空间，不使用统一错误信封 |
| 通用响应 | `x-login-common-error-responses`：400/401/403/404/405/413/414/415/429/500/504 的说明 |

**它不包含**业务接口（账户、权限、OAuth/OIDC、设备码、扫码、管理、报告、备份等）的
路径定义。真实状态：**OAuth/OIDC 协议端点与管理 JSON API 已装配**（可配置开关，
默认关闭：`protocol.enabled`/`--enable-protocol`、`--enable-admin-api`）；**设备码、
扫码登录、令牌状态查询（introspection）未启用**；维护模式一律 503（见
[deployment-modes.md](deployment-modes.md) 第 3.1 节与 `standalone-service.md` 第
3.8 节）。不要按“OpenAPI 里有”去对接，
也不要为了对接去改本文件；协议契约目前以受信 Go API 与
`docs/deployment/integration.md` 为准。

独立服务 `login-server serve` 现已真实启动，并向 `<prefix>/healthz`、`<prefix>/openapi.json`
与内置账户入口页（`<prefix>/login` 等）提供服务；但它同样**不提供业务 JSON API**，
OpenAPI 仍只有上述两条路径。`login-server init` 是本地受控首次初始化入口，
不是 HTTP 接口。

预览文档（不监听端口，直接生成）：

```go
document, err := login.OpenAPIDocument("/login") // /login 是路径前缀，可为空字符串
// document 是 JSON 字节串，可保存或交给测试断言
```

## 3. 错误响应与 request_id

统一业务错误响应（**只用于 login 自己的 API**，OAuth/OIDC 标准协议响应除外）：

```json
{
  "code": "PERMISSION_REQUIRED",
  "message": "缺少当前操作所需权限",
  "request_id": "用于受限排障的编号",
  "task_id": "可选：后台任务编号",
  "retry_after_seconds": 1
}
```

- `code` 是稳定错误码字符串，取值见 [troubleshooting.md](troubleshooting.md)；未登记的
  码不应对外返回。
- `message` 是可公开的直白说明，不包含内部原因码、秘密或堆栈。
- `request_id` 用于在受限审计/日志中定位一次请求。凭据：`login.NewRequestID()` 生成、
  `login.ValidateRequestID()` 校验格式；`login.RequestIDFromContext(ctx)` 读取当前请求
  编号。不要把 request_id 当作身份或授权凭证。
- `retry_after_seconds` 只在限流（`RATE_LIMITED`）等场景出现，表示建议等待秒数。
- 联合校验类接口可能在 **HTTP 200** 里返回 `allow=false` + 错误码表达业务拒绝；这不是
  故障，也不代表请求格式错误。分层约定见错误码手册第 2 节。

## 4. 身份与上下文

- 可信身份只能由可信边界建立：`login.WithIdentity(ctx, identity)` 由宿主在验证会话/
  令牌/证书之后调用；普通请求参数不能自称用户、应用或 root。
- 读取：`login.IdentityFromContext(ctx)`、`login.RequestIDFromContext(ctx)`；
  服务身份场景另见 `login.ClientServiceIdentityFromContext(ctx)`。
- `Identity.Kind = system` 只是主体类型，**不会自动获权**；授权必须经
  `AccessController`/`CheckAccess` 判定，未注入即拒绝（fail-closed）。
- 依赖失败（权限服务不可用等）默认拒绝并返回 `AUTHZ_UNAVAILABLE` 类错误，不降级放行。

## 5. 页面契约（`ui.v1`）

- `login.NewWebUI(login.WebUIOptions{...})` 构造页面处理器；契约版本常量
  `login.UIContractVersion` 当前为 `ui.v1`。
- 页面通过命名路由（`UIRoute`）与视图模型（`UIPageContext`）使用，不解析具体 DOM。
- 页面可整体替换（`DisableBuiltinPages` + `HostRenderer`）或按模板覆盖
  （`HostTemplates`）；也可按命名路由注册处理器（`Handlers`）。
- 页面替换只影响展示，不改变服务端认证/授权/CSRF；删除字段、改变路由含义或放宽安全
  要求必须升级契约版本。
- 内置页面需要宿主注入真实后端（会话、权限、各管理服务）；完整后端适配器在本模块
  `internal/` 内，外部宿主需要自行实现公开契约或等待公开装配入口。

## 6. 当前缺口（与文档相关）

| 缺口 | 影响 |
|---|---|
| 业务 HTTP API 与 OpenAPI 业务路径未提供 | 不能用标准 HTTP 客户端对接账户/OAuth/OIDC/管理能力 |
| 独立服务可启动，页面/协议按开关提供 | `login-server serve` 可启动并服务健康检查与 14 个页面选项（默认注册 12、条件注册 2），具备单实例数据库锁、访问日志轮转、后台任务执行器/调度器（邮件投递本地禁用、Webhook 投递）、管理会话强认证门禁、真实敏感操作 policy+reauth 链；OAuth/OIDC 协议端点（Discovery/JWKS/授权/令牌/UserInfo/撤销）与管理 JSON API 已实现但默认关闭；设备码/令牌状态查询/扫码登录未启用 |
| 完整服务装配入口未公开 | 外部宿主无法只靠公开 API 装配完整身份服务；独立进程请用 `login-server` |
| `cmd/*` 参数与输出不承诺稳定 | 发布包脚本应以本文与 `--help` 为准，不要长期依赖输出文本 |
| 未发布 `v1.0.0` | 破坏性变更策略按 `host_integration.md` 第 2 节执行，但仍应做适配测试 |

新增公开 API、错误码或权限键时，必须同步更新 GoDoc、本文相关段落与错误码手册；不允许
只在代码里加而不写文档。
