# 应用受限客服 API（步骤 154，接入契约草稿）

> **状态（2026-11-21 更新）**：步骤 154 dev + 审计 PASS_WITH_NOTES（真实 SQLite/HTTP 工单、
> A/B 应用隔离、自批拒绝、字段白名单/审计落库等通过）；`--enable-app-support` 默认关闭。
> 真实 OAuth 委托 Token E2E 与最终 Windows 生产验收仍未完成；本文只描述接入契约，**不表示
> 已生产验收或已默认启用**。启用前仍需完成 154 最终验收与 152/153 真实恢复执行链路。

`/api/app/v1/support` 供已登记业务应用的人工客服前端使用，只允许**应用客服人员**通过
OAuth 用户委托 Access Token 创建本应用的人工升级申请。它不是全局客服/人工恢复入口，
不能审批或执行恢复，不能修改密码、MFA、恢复代码或读取恢复链接。

## 1. 启用

需要同时启用 OAuth 协议端点（Access Token 由授权码 + PKCE 签发），然后：

```powershell
login-server serve --config <config.yaml> --master-key-file <key> `
  --enable-protocol --enable-app-support `
  --app-support-prefix /api/app/v1/support `
  --app-support-audience urn:evernight:app-support
```

默认关闭；`--app-support-audience` 省略时使用 `urn:evernight:app-support`。应用 OAuth
客户端必须登记该 audience 才能获得可用于本 API 的委托 Token。

## 2. 认证与授权

请求只能使用：

```http
Authorization: Bearer <用户委托 Access Token>
X-Evernight-API-Version: v1
X-Request-Id: req_...   # 可选
```

Token 必须满足：
- 类型为 Access Token、由本实例签发、未过期、audience = 配置的客服资源；
- `client_id` = 应用 ID（服务端据此确定应用，**不接受**路径/query/header 的 app_id）；
- `sub` = 客服用户稳定 ID，且该用户为该应用的有效成员；
- 当前应用作用域拥有 `support.cases.read` / `support.cases.create` 权限；
- 在线撤销检查与客户端/应用 active 状态通过；Token 的 `client_credentials` 服务身份
  不能代表客服用户。

任一条件不满足按 401/403 失败关闭；不把“知道 app_id/用户 ID”当作身份。

## 3. 路由与字段

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/cases?offset=&limit=` | 只列本应用工单，按应用归属过滤 |
| POST | `/cases` | 创建本应用人工升级申请（`target_user_id`、`reason`） |
| GET | `/cases/{case_id}` | 只读本应用工单；跨应用统一 403 |
| POST | `/cases/{case_id}/approve` | **始终拒绝**：全局恢复审批/执行必须由系统 `recovery.approve` 完成 |

创建请求严格 JSON 白名单，只接受 `target_user_id` 和 `reason`；未知字段（包括
`password`、`new_password`、`mfa`、`totp`、`recovery_code`、`token`、`reset_link`、
`email` 等）一律 400。响应工单只返回脱敏用户名/邮箱、状态、原因、指派和行版本，
不返回密码/MFA/恢复链接/验证码。创建工单初始状态为 `manual_review`（人工升级申请），
应用不能自行改为 `closed`/审批通过，也不能触发全局恢复执行。

## 4. 响应与错误

成功：

```json
{"request_id":"req_...","api_version":"v1","data":{...}}
```

失败：

```json
{"request_id":"req_...","api_version":"v1",
 "error":{"code":"ACCESS_DENIED","message":"...","retryable":false}}
```

400 `REQ_INVALID`；401 缺失/无效令牌；403 身份/成员/权限不足或应用自批；503 依赖/存储
不可用。审计记录真实客服用户、应用、目标、request_id 与动作；审计失败的创建路径不返回
成功。

## 5. 安全边界

- 应用 A 的客服令牌不能读取/创建/审批应用 B 工单；系统工单（application_id 为空）
  不能通过本 API 访问。
- 应用管理员可以拥有本应用 `support.cases.*` 权限，但不能因此获得全局
  `recovery.approve`，也不能自批恢复。
- 目标必须为应用有效成员且不是 root/受保护高权限账户；应用客服不能处理系统工单。
- 本 API 不提供改密、MFA 重置、恢复代码、找回链接或直接执行恢复的字段/路由。
- 旧系统客服工单保留 `application_id` 为空，兼容迁移；新应用工单必须带应用归属。
