# 嵌入模式（Go Module）文档入口

本目录面向把 EvernightLogin 作为 Go 模块嵌入自有业务的宿主开发者。宿主只能导入公开包
`github.com/kagurazakayashi/EvernightLogin`（包名 `login`）与
`github.com/kagurazakayashi/EvernightLogin/app`；Go 的 internal 规则禁止模块外导入
`internal/` 下的包。

## 1. 文档索引

| 文档 | 内容 |
|---|---|
| [host_integration.md](host_integration.md) | **完整嵌入指南**：公开 API 稳定范围、破坏性变更策略、最小装配、运行时装/认证流程/受信管理门面/HTTP 与页面挂载、生命周期与资源所有权、扩展注册、外部消费验证、已知限制、变更记录 |
| [../guide/api-status.md](../guide/api-status.md) | GoDoc/OpenAPI 现状、统一错误响应与 `request_id`、身份与上下文、页面契约、当前缺口 |
| [../guide/configuration.md](../guide/configuration.md) | 完整配置字段、默认值、秘密来源与生效/重启分类（嵌入与独立服务共用） |
| [../guide/deployment-modes.md](../guide/deployment-modes.md) | 嵌入 vs 独立服务的选择建议与当前边界 |
| [../README.md](../README.md) | 文档中心（guide/deployment/embedding/acceptance/database 等索引） |

可运行示例（真实外部 Go Module，只导入公开包；均使用临时 SQLite/密钥，退出即清理）：

| 示例 | 演示重点 |
|---|---|
| [../../examples/embedded-minimal/](../../examples/embedded-minimal/README.md) | 最小嵌入：`app.Open` → 受控初始化 → 注册/登录 → 会话校验 → HTTP/UI 挂载 → 关闭清理；`-self-test` 15 项检查 |
| [../../examples/custom-pages-profile-sync/](../../examples/custom-pages-profile-sync/README.md) | 宿主自定义页面与 Evernight 内置页面并存；`Profile()` 资料读写/受控改名；业务资料投影按稳定 UserID 同步；本地邮件验证/找回；`-self-test` 23 项检查 |
| [../../examples/app-delegation-support/](../../examples/app-delegation-support/README.md) | 两个应用共享账户但成员/权限隔离；应用范围权限/角色/委派资格（跨 scope 拒绝）；OAuth 客户端一次性秘密；业务投影稳定 UserID；客服/人工恢复边界（LocalAdmin 不能替代客服会话）；`-self-test` 11 项检查；见 [app-delegation-support.md](app-delegation-support.md) |
| [../../examples/external-consumer/](../../examples/external-consumer/) | 外部 module 仅用公开 API 完成配置校验、扩展注册、页面替换、HTTP 挂载、生命周期与 fail-closed 判定 |
| [../../examples/embedded-runtime/](../../examples/embedded-runtime/) | 完整嵌入验收骨架（运行时/页面/HTTP/管理/安全流程） |
| [../../examples/rbac-consumer/](../../examples/rbac-consumer/) | 公开 RBAC Go 接口（角色/组/权限/授权查询/预设拒绝）外部消费 |
| [../../examples/managed-api-client/](../../examples/managed-api-client/) | 业务托管管理 API 客户端（默认关闭的托管 API） |
| [../../examples/password-reset-consumer/](../../examples/password-reset-consumer/) | 外部消费者走找回密码/邮箱验证链路（配合本地 EvernightMail） |

一键自检（统一短测试入口，临时目录/动态端口/超时/清理与结构化 JSON 由入口负责，
在仓库根执行）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario embedded-minimal-selftest -TimeoutSeconds 180
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario custom-pages-profile-sync-selftest -TimeoutSeconds 240
```

## 2. 宿主调用安全边界补充（步骤 244 阶段 A 登记）

以下条目是对 [host_integration.md](host_integration.md) 的**契约补充说明**（该文件在
步骤 240/241 刚更新，本阶段不改写；后续文档步骤会把这些条目并入正式章节并互相链接）。
完整的调用身份、资源所有权与错误映射以完整指南与 [../guide/api-status.md](../guide/api-status.md)
为准。

### 2.1 找回密码入口的可信来源（R10-13，步骤 208）

`Runtime.PasswordReset()` 的 `Request`、`ValidateTokenWithSource`、`Complete` 都带有
`ClientIP` 字段，宿主**必须**传入从可信边界（连接地址或已配置可信代理链）解析出的
**单一 IP 字面量**：

- 空字符串表示没有可信来源，使用共享的“无来源”限流桶（仍是有界桶，不按客户端可控字符串
  无限分桶）；
- 原始 `X-Forwarded-For` 链、`unknown`、任意伪造字符串等非 IP 值会被拒绝并返回
  `REQ_INVALID`；宿主不能把未经校验的转发头直接当作来源；
- 来源只用于**有界限流**，不是身份或授权依据；令牌本身仍是高熵一次性凭证；
- 日志/审计不得写入完整 token、密码或找回链接；排障使用 `request_id` 关联。

### 2.2 找回令牌预检查的统一失败语义（R10-02，步骤 204）

`PasswordReset().ValidateToken` / `ValidateTokenWithSource` 是**非消费**预检查：它们不消费
令牌、不改请求状态。领域判断的**所有失败统一返回 `CHALLENGE_INVALID`**——包括令牌不存在、
过期、已消费/撤销、用途/目标不匹配、所在账户当前不可恢复等，避免公开入口泄露账户状态；
调用前校验保持各自稳定码（非法请求编号/非法来源 → `REQ_INVALID`，来源限流 →
`RATE_LIMITED`，服务未装配 → `CONFIG_INVALID`）。宿主不能依据返回错误码区分领域失败的
具体原因；内部诊断请用返回错误的 `request_id` 关联服务端日志与审计。最终提交（`Complete`）
会重新验证完整状态，不存在“预检查通过就必然完成”的捷径。

### 2.3 已授权查询的“未找到”公开契约（步骤 207）

公开 app 包对“**已通过调用身份与权限检查、但目标记录不存在**”提供独立于参数错误/权限拒绝
的稳定语义：

- `app.NotFoundCode`（字符串 `"NOT_FOUND"`）、`app.ErrNotFound`、`app.NotFoundError`、
  `app.IsNotFound(err)`；
- 权限/范围检查严格先于查询：未授权调用者无论目标是否存在都得到 `ACCESS_DENIED` 等拒绝码，
  不会因为 `NOT_FOUND` 探测目标是否存在；
- `NOT_FOUND` **不加入**根包 48 个错误码注册表（注册表描述协议/业务拒绝，合法未找到是授权
  查询的正常结果）；HTTP 层建议映射 404；
- 参数非法继续返回 `REQ_INVALID`；`NotFoundError` 公开字段只含固定资源类别与 `request_id`，
  不回显用户名/邮箱等查询值，避免存在性泄露与日志注入。

## 3. 相关边界（完整内容见指南）

- 生命周期：`Open` 只构造运行时（`State=StateNew`），不监听端口、不启动后台任务；后台任务
  只能由宿主显式 `Start` 启动；`Close` 幂等且不关闭宿主注入的 Logger/Database/Notifier。
- 资源所有权：宿主注入的数据库/通知器/日志器归宿主所有；主机自己的 `http.Server` 生命周期
  归宿主，运行时只提供 `Handler()`/`Mount()`。
- 可信身份：会话秘密必须来自可信边界（Cookie/Authorization 或宿主服务端存储），请求参数不能
  自称用户/root/应用；`LocalAdmin` 只表达持有宿主进程控制权的可信本地代码，不能由 HTTP 参数
  取得。
- 失败默认拒绝：认证/授权/审计依赖失败时 fail-closed；未配置的协议/管理/托管能力默认关闭。
- 邮件：示例与测试使用本地捕获器/EvernightMail；生产 SMTP 需宿主显式配置，测试邮件不得发往
  真实第三方地址。
