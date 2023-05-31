# 业务应用托管管理 API（步骤 147–148，默认关闭）

> **状态（2026-11-21）**：147/148 已出开发报告（PASS_WITH_NOTES），真实 SQLite + HTTP
> 集成用例通过；默认关闭，YAML 配置化尚未落地（以命令行/宿主显式选项为准），页面→
> managedapi→SQLite 的完整单条 E2E 仍待补。详见 `docs/acceptance/requirements-matrix-login.md`。

`/api/managed/v1` 是给已登记业务应用使用的受限管理 API，与内置管理 JSON API
（`/admin/v1`，管理强会话）以及网页管理页面严格分离。默认关闭；只有显式启用后才挂载，
未启用时请求返回 404，维护模式下不挂载。

## 1. 启用

独立服务命令行：

```powershell
login-server serve --config <config.yaml> --master-key-file <key> `
  --enable-managed-api --managed-api-prefix /api/managed/v1
```

对应嵌入/测试入口是 `serverapp.ServeOptions.EnableManagedAPI` 与
`ManagedAPIPrefix`。启用前必须已应用数据库迁移（包含 `0045_managed_api_idempotency.sql`）。
当前版本没有把该开关加入根 YAML `Config`（为避免与并行中的邮件配置写域冲突）；命令行/
宿主显式选项是唯一启用入口，YAML 配置化将在配置写域稳定后集中补齐。

## 2. 认证

每个请求必须带 `Authorization` 与 `X-Evernight-API-Version: v1`；应用 ID 只来自 URL
路径（`/applications/{app_id}`）且必须与认证主体一致，**不接受** `app_id`/`application_id`
查询参数或请求体自报。

- **用户会话 Bearer**：`Authorization: Bearer <会话 secret>`。使用既有会话服务校验
  完整认证会话；若会话带应用作用域，必须等于路径应用，否则 `APP_SCOPE_MISMATCH`。
  API 不接受浏览器 Cookie 作为认证。
- **应用服务身份 secret**：HTTP Basic，用户名与密码分别是应用 ID 与客户端 secret
  （`Authorization: Basic base64(app_id:secret)`）。secret 由真实 oauthclient 服务校验。
- **应用服务身份证书**：TLS 层验证客户端叶子证书后，以路径应用 ID 作为客户端身份，
  managedapi 校验证书是否为该应用登记的未撤销证书。证书只取 TLS 已认证对端证书，
  不接受请求头自报证书。

每次请求还要求：
- `X-Evernight-API-Version: v1`（与路径版本一致，缺失/未知 400）；
- `X-Request-Id` 可选；缺失时服务端生成，非法时 400；成功/失败 envelope 都回显；
- 写请求（POST/PATCH）必须 `Content-Type: application/json` 且带 `Idempotency-Key`
  （1–200 个可打印 ASCII 字符）。

## 3. 路由（步骤 147 范围）

| 方法 | 路径 | 对应操作 |
|---|---|---|
| GET | `/applications/{app_id}` | 读取本应用资料（按策略字段投影） |
| GET | `/applications/{app_id}/members?limit=&offset=&status=&sort=&desc=` | 查询本应用授权成员 |
| GET | `/applications/{app_id}/members/{user_id}` | 读取单个成员 |
| PATCH | `/applications/{app_id}/members/{user_id}` | 更新应用内资料（`expected_row_version` + `display_name`/`title`/`note`） |
| POST | `/applications/{app_id}/members/{user_id}/enable` | 启用应用成员 |
| POST | `/applications/{app_id}/members/{user_id}/disable` | 禁用应用成员 |
| POST | `/applications/{app_id}/members/{user_id}/remove` | 移除应用成员 |
| POST | `/applications/{app_id}/users` | 创建全新账户并建立本应用成员关系（`username`/`nickname`/`biography`） |
| GET/POST | `/applications/{app_id}/groups` | 查询/创建本应用用户组 |
| GET/PATCH/DELETE | `/applications/{app_id}/groups/{group_id}` | 读取/更新/删除本应用用户组 |
| GET/POST/DELETE | `/applications/{app_id}/groups/{group_id}/members` | 查询/批量加入/批量移除组成员（`user_ids`） |
| GET/POST | `/applications/{app_id}/roles` | 查询/创建本应用角色 |
| GET/PATCH/DELETE | `/applications/{app_id}/roles/{role_id}` | 读取/更新/删除本应用角色（内置不可删除） |
| GET | `/applications/{app_id}/roles/{role_id}/permissions` | 角色权限组合 |
| GET | `/applications/{app_id}/roles/{role_id}/assignments` | 角色分配 |
| POST | `/applications/{app_id}/roles/{role_id}/assign\|revoke` | 分配/撤销用户或组角色（`user_id` 或 `group_id` 二选一） |
| GET/POST | `/applications/{app_id}/permissions` | 查询/创建本应用自定义权限 |
| GET/PATCH/DELETE | `/applications/{app_id}/permissions/{permission_id}` | 读取/更新/删除权限（内置不可删除） |
| POST | `/applications/{app_id}/permissions/{permission_id}/enable\|disable` | 启用/停用权限 |

角色/权限创建由服务端固定 scope=当前应用、`is_builtin=false`/`root_only=false`；系统内置对象不能通过策略或 API 下放/删除；角色分配仍由服务端真实委派 Guard 复核自我/目标/权限范围。

字段、对象范围、操作是否允许、分页/批量上限与当前主体权限由应用委托策略与
`internal/managedapi` 每次请求重新判定。响应只包含策略允许的字段；`is_root`、
密码哈希、MFA/恢复秘密、Token/私钥、邮箱/电话等敏感字段永不可读写。创建账户不认领
已有用户名；移除成员不删除全局账户；本 API 不提供重置密码、解除 MFA、禁用/删除全局
账户或修改系统资格的路由。

## 4. 响应 envelope 与错误

成功：

```json
{"request_id":"req_...","api_version":"v1","data":{...}}
```

失败：

```json
{"request_id":"req_...","api_version":"v1",
 "error":{"code":"PERMISSION_REQUIRED","message":"...","retryable":false}}
```

HTTP 状态：400 `REQ_INVALID`/版本/幂等键/JSON 错误；401 认证缺失/会话无效；403
`ACCESS_DENIED`/`PERMISSION_REQUIRED`/`APP_MEMBERSHIP_REQUIRED`/`APP_SCOPE_MISMATCH`/
`RESOURCE_FORBIDDEN`；409 `CONFLICT`（行版本或幂等冲突）；423 `USER_DISABLED`/
`CLIENT_DISABLED`；429 `RATE_LIMITED`；503 `DB_UNAVAILABLE`/`AUDIT_WRITE_FAILED`。
错误消息不包含内部细节、策略秘密或目标账户存在性；审计失败时写操作 fail-closed。

## 5. 幂等

写请求使用 `Idempotency-Key`：
- 同 key + 同方法/路径/严格 JSON 请求体：已完成响应重放，带 `Idempotent-Replayed: true`；
- 同 key 但请求体不同：409 `CONFLICT`；
- 同 key 仍有请求进行中：409 `CONFLICT`；
- 失败的请求不缓存成功响应，允许修正后重试；记录有界过期时间，按请求与维护路径清理。

幂等记录在 SQLite `managed_api_idempotency`（迁移 0045），作用域绑定应用、主体类型/ID
与 key，不保存认证头、Cookie、证书、请求明文或秘密。与领域写入**不是同一事务**；进程
在“领域写入成功、幂等记录完成”之间崩溃时，调用方应按未确认处理，不能用同一 key 宣称
重复安全。生产环境应优先使用业务唯一键并配合幂等键。

## 6. 外部客户端示例

`examples/managed-api-client/` 是独立 Go module，只用标准库 HTTP，不导入
`internal/`。示例支持用户 session 或应用 client secret，读取应用/成员与创建用户/更新
成员；写请求生成幂等键。示例不打印秘密，也不读取私钥。

## 7. 安全边界

- 应用 ID 只来自认证上下文/路径；跨应用对象 ID 由 managedapi 范围与领域归属二次拒绝。
- 应用管理员只能管理本应用成员/资料；修改全局账户、密码/MFA、系统角色/权限不在目录。
- 撤权/停用应用/删除策略后，下一次请求立即按当前状态拒绝，不缓存“已验证”结论。
- 审计记录真实操作者/应用/对象/request_id；审计不可用时写操作拒绝。
- 不得把本 API 部署到未启用维护/迁移门禁的实例；默认关闭可避免误暴露。
