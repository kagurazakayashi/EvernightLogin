# AI 入口（机器可读优先）

> 面向 AI 与自动化调用者：先读本页，再按任务直接读对应机器 JSON 或稳定 Markdown。本目录全部由 `scripts/reference` 从代码生成，**不要手工编辑**；引用接口时以 JSON/源码为准，不要把本文当“功能已实现”的证明（状态见能力矩阵）。

## 1. 使用约定

- 机器优先：需要枚举/匹配/生成调用时读机器 JSON（当前输出见 §2）；需要解释/边界/示例时读 Markdown。
- 引用事实时带上错误码/权限键/路由/命令的稳定标识，不要引用会随重构变化的文件路径作为契约。
- 未知符号先运行 `go run ./scripts/reference -check` 与 `go doc ./app`；`-check` 失败表示文档与代码漂移，先修生成物。
- 不要把本目录之外的开发协作材料（`.ai/`、`AGENTS.md`、`MEMORY.md`）当作产品契约；产品交付文档只在 `docs/`。
- 涉及秘密/令牌/恢复码时只引用字段名与错误码，不生成或回显真实值。
- 能力是否已实现/已验收：读 [能力矩阵](../acceptance/capability-matrix.md)；本页不重复状态。

## 2. 机器 JSON（程序/AI 直接消费）

| 文件 | schema 后缀 | 内容 |
|---|---|---|
| error-codes.json | error-codes | 48 个错误码 |
| permission-keys.json | permission-keys | 53 权限 / 5 系统角色 / 5 用户组 |
| http-routes.json | http-routes | 137 管理路由 / 17 协议路径 / 250 页面 |
| http-openapi.json | http-openapi | 95 页面/表单操作 |
| protocol-openapi.json | protocol-openapi | 19 协议端点（标准错误/项目信封/浏览器重定向） |
| cli-commands.json | cli-commands | 4 程序 / 58 子命令 |

## 3. 任务 → 入口

| 任务 | 入口 | 说明 |
|---|---|---|
| 找某个错误码含义/处理 | [errors.md](errors.md) 或 [error-codes.json](error-codes.json) | 错误码表 + 排障指南 |
| 查权限键/谁能做什么 | [permissions.md](permissions.md) 或 [permission-keys.json](permission-keys.json) | 权限目录生成 |
| 查配置字段/环境变量/是否秘密 | [configuration.md](configuration.md) | 语义以 guide 为准 |
| 找 HTTP 管理路由/协议路径/页面路由 | [http-api.md](http-api.md) 或 [http-routes.json](http-routes.json) | AST 扫描注册 |
| 查页面/表单的字段/响应/状态转移 | [http-api.md](http-api.md) §5 或 [http-openapi.json](http-openapi.json) | OpenAPI 页面段 + 契约/路由一致性校验 |
| 查 OAuth/OIDC/设备码/扫码的 HTTP 契约 | [http-api.md](http-api.md) §3 或 [protocol-openapi.json](protocol-openapi.json) | 协议端点契约/例外 + 标准错误与项目信封区分 |
| 查 CLI 命令/flag/退出码 | [cli.md](cli.md) 或 [cli-commands.json](cli-commands.json) | 双风格 CLI 扫描 |
| 查公开 Go 接口/方法是否存在 | [go-api.md](go-api.md) + `go doc ./app` / GoDoc | Phase A 框架，Phase B 方法级 |
| 找最小可编译示例 | 本页第 4 节 + 对应文档示例块 | 源码 examples/reference-snippets |
| 能力 id → 领域/公开面 | [capability-map.md](capability-map.md) | catalog.json 映射 |
| 判断是否已实现/已测试 | [../acceptance/capability-matrix.md](../acceptance/capability-matrix.md) | 状态看矩阵，不看本页 |
| 部署/运维操作 | [../deployment/README.md](../deployment/README.md) 与 [../guide/README.md](../guide/README.md) | 任务导向文档 |

## 4. 最小可编译示例（源码内嵌，逐字一致）

| 示例函数 | 源码 |
|---|---|
| `ExampleConfigLookup` | `examples/reference-snippets/snippets.go` |
| `ExampleLookupError` | `examples/reference-snippets/snippets.go` |

示例分别内嵌于 [errors.md](errors.md)、[configuration.md](configuration.md)、[go-api.md](go-api.md)；`go build ./examples/reference-snippets` 做真实编译校验。

## 5. 覆盖范围与阶段

- 错误码 48、权限键 53、配置字段 58、管理路由 137、协议路径 17、页面命名路由 250、CLI 子命令 58、能力 53。
- Go API：Phase A 提供 Runtime 生命周期/访问器与接口总览；方法级参考（身份/范围/分页/幂等/错误/示例）Phase B 补齐。
- OpenAPI 含运行期最小 JSON API（健康/文档端点）、页面/表单操作（账户/资料/会话/注册登录/MFA/三种恢复流程）与协议端点离线段（OAuth/OIDC/设备码/扫码；protocol-openapi.json）；管理 JSON API 契约见 http-openapi-admin.json。

## 6. 生成与校验命令

```powershell
go run ./scripts/reference -write
go run ./scripts/reference -check
go run ./scripts/verify-docs
go build ./examples/reference-snippets
```
