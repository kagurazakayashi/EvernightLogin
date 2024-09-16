# 管理 JSON API 参考（运维 / 报告 / 客服域）

> 本文件由 `go run ./scripts/adminapi-doc -write` 从**AST 扫描的真实注册路由**（与 `docs/reference/http-routes.json` 同一扫描器）与 `internal/transport/admincontracts_*.go` 契约生成，**不要手工编辑**；`-check` 逐字节校验且失败非零退出。管理组（用户/角色/应用/会话）OpenAPI 属步骤 269、直接改名/改密属 258/259，本文件不包含其占位 schema。

## 1. 基础约定

- **挂载路径**：默认 `/admin/v1`；实际完整路径 = `server.path_prefix` + 该前缀（可配置）。路由按装配条件注册，未装配领域返回 404。
- **统一信封**：管理 API 统一 JSON 信封：成功 {"ok":true,"request_id":"…","data":…}；失败 {"ok":false,"code":"…","message":"…","request_id":"…"}；错误码来自根包 errs 注册表（HTTP 状态与默认消息同源）；请求编号优先复用上游 X-Request-ID，否则内部生成。
- **认证**：文档级 security 声明 `managementSessionCookie`（会话 Cookie）与 `managementSessionBearer`（Authorization: Bearer 会话秘密）二选一；每个操作都继承该要求，没有任何操作可关闭认证（含下载票据兑换）。每次请求重新校验会话状态、账户状态、安全版本与强认证新鲜度；受限会话与强认证过期一开始就 403 REAUTH_REQUIRED，不做只读降级。
- **CSRF**：Cookie 会话的非安全方法必须携带与会话绑定的 `X-CSRF-Token`；Bearer 会话秘密不随浏览器自动发送，不要求 CSRF 头。
- **权限**：端点声明所需权限键（任一满足）；root 按内核语义拥有全部已实现权限，但仍校验认证、两步验证、目标/输入、业务一致性与审计。表内 `root-only` 表示仅真实 root/受信本地主体可调用。
- **敏感操作**：`敏感=是` 表示领域服务会按 `internal/policy` 复核再次认证/强认证新鲜度与策略下限；前端确认不能替代。
- **确认与原因**：所有写操作必须 `confirm=true`（确认不是授权）；取消/清理/保留策略/启停等还要求非空 `reason`，原因进入真实审计。
- **分页与筛选**：列表 `limit` 默认 20、最大 100；`offset` 最大 1000000；部分列表提供稳定 `cursor`（与 offset 互斥，条件变化后旧游标失效）。时间参数使用 RFC3339；有界搜索最多 64 字符，通配符按字面。
- **异步语义**：提交/受理 ≠ 完成/取消。异步操作返回真实任务/状态，必须按任务编号查询终态；取消只表示“已受理取消”，终态以任务/状态为准。
- **下载与票据**：响应不暴露宿主路径，也不把服务器路径当下载地址。报告/备份使用**一次性短期下载票据**（签发只返回一次 token → 兑换时再次授权并重查产物状态 → 流式返回受控字节，重复兑换/撤权后拒绝）；审计导出每次下载重新授权。
- **错误码**：来自根包 `errs` 注册表（HTTP 状态与默认消息同源）；排障见 [errors.md](errors.md)。
- **范围**：本文件覆盖 core/audit/reports/plans/backups/tasks/diagnostics/settings/notifications/deliveries/support；用户/角色/应用/会话属 269，直接改名/改密属 258/259（不写占位）。

## 2. 操作总览

| 域 | 操作数 |
|---|---|
| 基础（元信息/错误码） | 2 |
| 审计（事件/保留策略/导出/清理） | 14 |
| 报告（历史/快照/下载票据/清理） | 9 |
| 报告计划与备份计划 | 13 |
| 备份（产物/任务/下载票据/保留/清理） | 13 |
| 任务（详情/尝试历史） | 2 |
| 配置诊断（脱敏运行诊断） | 3 |
| 配置管理（脱敏字段/校验/更新/恢复） | 5 |
| 安全通知与本地捕获测试 | 3 |
| 邮件投递记录（脱敏只读） | 1 |
| 客服工单与人工恢复 | 13 |

## 3. 基础（元信息/错误码）（2 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/error-codes` | 错误码注册表查询 | 管理会话基线 | 否 | - | - | `对象（见字段/说明）` |
| GET | `/meta` | 管理 API 元信息 | 管理会话基线 | 否 | - | - | `AdminMeta` |

### `GET /error-codes`

返回根包错误码注册表条目（code/message/http_status），供客户端映射稳定错误；可按 code 精确筛选。

查询参数：

- `code`（string，可选）：按稳定错误码精确筛选；空返回全部（只读目录，数量有界）。

边界与语义：

- 错误码与 HTTP 状态同源生成，不手写第二份清单；响应不含内部原因。

### `GET /meta`

返回管理 API 版本、直连路径、认证要求、已装配服务与限制快照。只要求管理会话基线，不需要额外权限键。

边界与语义：

- 响应不含任何凭据、数据库连接、配置秘密或宿主路径。
- services 反映当前部署实际装配的领域；未装配领域对应路由返回 404。

## 4. 审计（事件/保留策略/导出/清理）（14 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/audit/events` | 查询审计事件 | `audit.read` | 否 | - | - | `分页列表 events` |
| GET | `/audit/events/{event_id}` | 读取单条审计事件 | `audit.read` | 否 | - | - | `对象（见字段/说明）` |
| GET | `/audit/exports` | 分页查询审计导出任务 | `audit.export` | 否 | - | - | `分页列表 exports` |
| POST | `/audit/exports` | 提交审计导出任务 | `audit.export` | 是 | 确认 | 异步任务 | `对象（见字段/说明）` |
| GET | `/audit/exports/{export_id}` | 读取审计导出任务 | `audit.export` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/audit/exports/{export_id}/cancel` | 取消审计导出 | `audit.export` | 否 | 确认+原因 | 异步任务/可取消 | `AdminCancelResult` |
| GET | `/audit/exports/{export_id}/download` | 下载审计导出产物（流式） | `audit.export` | 否 | - | 下载:stream | `文件流` |
| POST | `/audit/purge` | 提交审计清理（root） | root-only | 是 | 确认+原因 | 异步任务 | `对象（见字段/说明）` |
| GET | `/audit/purge-runs` | 分页查询审计清理运行 | root-only | 否 | - | - | `分页列表 purge_runs` |
| GET | `/audit/purge-runs/{run_id}` | 读取审计清理运行 | root-only | 否 | - | - | `对象（见字段/说明）` |
| POST | `/audit/purge/preview` | 审计清理预演（只读） | root-only | 否 | - | - | `对象（见字段/说明）` |
| POST | `/audit/purge/{run_id}/cancel` | 取消审计清理运行（root） | root-only | 否 | 确认+原因 | 异步任务/可取消 | `AdminCancelResult` |
| GET | `/audit/retention` | 读取审计保留策略 | 管理会话基线 | 否 | - | - | `对象（见字段/说明）` |
| PUT | `/audit/retention` | 更新审计保留策略（root） | root-only | 是 | 确认+原因 | - | `对象（见字段/说明）` |

### `GET /audit/events`

按调用者数据范围与 audit.read 权限分页查询脱敏审计事件；筛选在授权范围之后应用，跨范围筛选被拒绝。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `order`（string，可选）：稳定排序：occurred_desc（默认，新→旧）或 occurred_asc（旧→新）；并列时按事件 ID 决胜。
- `scope_id`（string，可选）：数据范围：默认 system；应用范围传应用编号，必须落在调用者可管理范围内。
- `cursor`（string，可选）：稳定游标：下一页请求带 cursor；与 offset 互斥（两者同时出现返回 400）。
- `from`（string，可选）：起始时间（含），RFC3339，例如 2026-11-01T00:00:00Z。
- `to`（string，可选）：结束时间（不含），RFC3339。
- `outcome`（string，可选）：结果筛选；未知值由领域服务拒绝（400）。
- `app_id`（string，可选）：应用筛选。
- `actor_type`（string，可选）：操作者类型筛选（user/application/system/local_admin 等，服务层校验）。
- `actor_id`（string，可选）：操作者编号筛选。
- `action`（string，可选）：动作筛选（稳定动作名）。
- `error_code`（string，可选）：错误码筛选。
- `request_id`（string，可选）：请求编号筛选（关联排障）。
- `task_id`（string，可选）：任务编号筛选。
- `target_type`（string，可选）：目标类型筛选。
- `target_id`（string，可选）：目标编号筛选。
- `system_only`（boolean，可选）：只看系统范围事件（true/false/1/0）。

边界与语义：

- 只返回脱敏公开字段；不返回原始日志、SQL 或秘密。

### `GET /audit/events/{event_id}`

按事件编号读取详情（含脱敏字段变更）；必须落在调用者可读范围内，越权按不存在处理。

路径参数：`event_id`（string）：审计事件编号。

查询参数：

- `scope_id`（string，可选）：数据范围：默认 system；必须在调用者可管理范围内。
- `occurred_at_hint`（string，可选）：事件发生时间提示（RFC3339），用于稳定检索同编号事件。

边界与语义：

- stale=true 表示读取期间保留策略已变化，事件可能即将被清理。

### `GET /audit/exports`

按调用者数据范围分页查询审计导出任务与真实状态；审核/导出权限 audit.export。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `scope_id`（string，可选）：数据范围：默认 system。
- `state`（string，可选）：按任务状态筛选（状态由领域任务状态机校验）。

### `POST /audit/exports`

受理审计导出（CSV/JSON）；敏感操作由领域服务复核再次认证与 audit.export 敏感策略。响应返回真实任务与状态，受理≠完成。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `scope_id` | string | 否 | 数据范围：默认 system；必须在调用者可管理范围内。 |
| `format` | string | 是 | 导出格式：csv（UTF-8、防公式注入）或 json（UTF-8 数组）。 |
| `max_rows` | integer | 否 | 最大导出行数（服务端有硬上限，超出拒绝而非静默截断）。 |
| `order` | string | 否 | 导出排序；默认 occurred_desc。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |
| `filter` | object | 否 | 可选筛选对象：from/to（RFC3339）、app_id、system_only、actor_type、actor_id、action、outcome、error_code、request_id、task_id、target_type、target_id；未知字段拒绝。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "filter": {
        "example_field": "example-value"
    },
    "format": "csv",
    "max_rows": 1,
    "order": "occurred_desc",
    "request_id": "example-request_id",
    "scope_id": "example-scope_id"
}
```

边界与语义：

- 导出产物有保留期限；下载需在期限内按导出编号重新授权下载（见 GET .../download）。

### `GET /audit/exports/{export_id}`

读取单个导出任务详情（含产物可用性与过期时间）；异步任务状态以真实任务为准。

路径参数：`export_id`（string）：审计导出任务编号。

### `POST /audit/exports/{export_id}/cancel`

请求取消导出任务：root 或记录授权者可取消并写真实审计；accepted 只表示“已受理取消”，终态以任务状态为准。

路径参数：`export_id`（string）：审计导出任务编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

### `GET /audit/exports/{export_id}/download`

每次请求重新授权并复核产物可下载状态，随后流式输出受控文件字节；响应不含宿主路径。

路径参数：`export_id`（string）：审计导出任务编号。

边界与语义：

- 下载不是“票据”语义：每次下载都重新授权与重查产物状态；产物过期/不可用时返回 404/409，不返回空文件假成功。
- Content-Disposition 使用本包生成的稳定文件名，不使用宿主路径；Cache-Control: no-store。

### `POST /audit/purge`

root 专属 + audit.purge 敏感策略 + 确认 + 原因；按预演 digest 绑定的参数提交清理任务。受理≠完成，状态以清理运行/任务为准。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `scope_id` | string | 否 | 数据范围：默认 system。 |
| `cutoff` | string | 是 | 清理截止时间（RFC3339）。 |
| `batch_size` | integer | 否 | 批大小（服务端硬上限）。 |
| `max_records` | integer | 否 | 最大处理记录数（服务端硬上限）。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |
| `digest` | string | 是 | 预演返回的参数摘要，必须原样带回；摘要不匹配拒绝执行（409/400）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "batch_size": 1,
    "confirm": true,
    "cutoff": "example-cutoff",
    "digest": "example-digest",
    "max_records": 1,
    "reason": "example-reason",
    "scope_id": "example-scope_id"
}
```

### `GET /audit/purge-runs`

root 专属读取：分页查询审计清理运行记录（真实扫描/清理计数），按 kind/state 筛选。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `kind`（string，可选）：清理类型筛选（服务端枚举）。
- `state`（string，可选）：运行状态筛选（服务端状态机）。

### `GET /audit/purge-runs/{run_id}`

root 专属读取单次审计清理运行的状态与真实计数。

路径参数：`run_id`（string）：清理运行编号。

### `POST /audit/purge/preview`

root 专属只读预演：估算将被清理的记录数并返回 digest；执行时必须原样带回 digest，防止预览与执行不一致。不删除任何数据。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `scope_id` | string | 否 | 数据范围：默认 system。 |
| `cutoff` | string | 是 | 清理截止时间（RFC3339，必须提供）：只清理该时间之前、且超出保留策略的记录。 |
| `batch_size` | integer | 否 | 批大小（服务端有硬上限）。 |
| `max_records` | integer | 否 | 最大处理记录数（服务端有硬上限）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "batch_size": 1,
    "cutoff": "example-cutoff",
    "max_records": 1,
    "scope_id": "example-scope_id"
}
```

边界与语义：

- within_retention / maintenance_protected / artifacts_included 反映真实保护条件；digest 供执行阶段绑定。

### `POST /audit/purge/{run_id}/cancel`

root 专属取消清理运行并记录原因；accepted 只表示受理取消，终态以运行状态为准。

路径参数：`run_id`（string）：清理运行编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

### `PUT /audit/retention`

root 专属 + audit.retention.update 敏感策略 + 确认 + 原因 + 版本乐观并发；只允许 root 调整审计保留策略，写关键审计。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `retention_days` | integer | 是 | 保留天数；必须在服务端允许范围内（既有策略下限/上限）。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |
| `expected_version` | integer | 是 | 期望的当前策略版本；版本不一致返回 409，需重新读取后再提交。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "expected_version": 1,
    "reason": "example-reason",
    "retention_days": 1
}
```

边界与语义：

- root-only 属于身份能力，不能由普通权限获得；策略变更进入真实审计。

## 5. 报告（历史/快照/下载票据/清理）（9 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/reports` | 查询报告历史（创建时间+编号游标） | `reports.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/reports/cleanup` | 执行报告清理 | `reports.cleanup` | 是 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/reports/cleanup-preview` | 报告清理预演（只读） | `reports.cleanup` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/reports/download-tickets/redeem` | 兑换报告下载票据（流式下载） | `reports.export` | 否 | - | 下载:ticket-redeem | `文件流` |
| GET | `/reports/{report_id}` | 读取报告详情 | `reports.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/reports/{report_id}/cancel` | 取消报告生成任务 | `reports.read` | 否 | 确认+原因 | 异步任务/可取消 | `AdminCancelResult` |
| POST | `/reports/{report_id}/download-tickets` | 签发一次性报告下载票据 | `reports.export` | 是 | 确认 | 下载:ticket-issue | `对象（见字段/说明）` |
| POST | `/reports/{report_id}/retry` | 重试报告生成 | `reports.generate` | 是 | 确认+原因 | 异步任务 | `对象（见字段/说明）` |
| GET | `/reports/{report_id}/snapshot` | 读取报告快照 | `reports.read` | 否 | - | - | `对象（见字段/说明）` |

### `GET /reports`

按调用者数据范围查询报告历史；分页使用创建时间+编号游标（limit + before_created_at/before_id 或 cursor），筛选与有界字面搜索先于分页且不越权。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400。
- `cursor`（string，可选）：稳定游标：下一页请求带 cursor；与 before_created_at/before_id 游标二选一。
- `plan_id`（string，可选）：按报告计划编号筛选。
- `state`（string，可选）：按报告状态筛选（服务端状态机）。
- `before_created_at`（string，可选）：游标分页：上一页最后一条的创建时间（RFC3339）。
- `before_id`（string，可选）：游标分页：上一页最后一条的报告编号（与 before_created_at 配合）。
- `search`（string，可选）：有界字面搜索（NFKC + 大小写折叠，最多 64 字符）；空表示不过滤。
- `search_fields`（string，可选）：逗号分隔的搜索字段白名单：name/title 等许可字段（服务端白名单）；未知字段返回 400。

边界与语义：

- 该列表不使用 offset 分页（响应不返回 limit/offset）；结果与计数不越权。
- scope_trimmed 表示按调用者范围裁剪。

### `POST /reports/cleanup`

清理过期报告产物（reports.cleanup 敏感策略 + 确认 + 原因 + 有界目标数）；返回真实清理计数与失败明细。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |
| `max_targets` | integer | 否 | 本次最多清理目标数（服务端有硬上限，超出拒绝）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "max_targets": 1,
    "reason": "example-reason"
}
```

边界与语义：

- 清理结果区分 cleaned/failed/skipped；失败不伪装成功，原始审计保留。

### `POST /reports/download-tickets/redeem`

消费一次性票据并流式返回受控产物字节；兑换时再次授权并重新检查产物状态，重复兑换/撤权后兑换被拒绝。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `token` | string | 是 | 一次性下载票据（只写；示例为合成值，不可用于真实下载）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "token": "example-download-token-synthetic-not-real"
}
```

边界与语义：

- 成功响应不是 JSON 信封：返回 200 + 受控文件字节（Content-Disposition 使用稳定文件名，不含宿主路径）。
- 票据过期/已用/授权撤销返回 400/403/409，不返回空文件假成功。

### `GET /reports/{report_id}`

读取单个报告详情（含产物摘要与任务/执行者信息）；资源归属由领域服务判定，越权按不存在处理。

路径参数：`report_id`（string）：报告编号。

### `POST /reports/{report_id}/cancel`

取消进行中的报告生成（确认 + 原因）；accepted 只表示受理取消，终态以报告/任务状态为准。

路径参数：`report_id`（string）：报告编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

边界与语义：

- 取消不删除既有产物；已完成的报告不可被“取消”改写为失败。

### `POST /reports/{report_id}/download-tickets`

为指定报告的指定格式签发一次性短期下载票据（reports.export 敏感策略 + 确认）。token 只在本次响应返回一次，不在日志/审计出现。

路径参数：`report_id`（string）：报告编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `format` | string | 是 | 下载格式；必须是该报告实际生成的格式，否则返回 400/409。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "format": "html"
}
```

边界与语义：

- 票据 token 一次性：兑换成功即失效；过期、已兑换或授权被撤销后兑换被拒绝。
- 票据绑定报告/格式/调用者与签发时刻的授权结论；兑换时再次授权并重新检查产物状态。
- 响应不包含服务器路径；下载通过 POST /reports/download-tickets/redeem 流式返回。

### `POST /reports/{report_id}/retry`

对失败的报告按原计划/参数重新提交生成（reports.generate 敏感策略 + 确认 + 原因）；返回新的报告视图，受理≠完成。

路径参数：`report_id`（string）：待重试的报告编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

边界与语义：

- 重试生成新任务；旧报告的终态与审计保持可追溯。

### `GET /reports/{report_id}/snapshot`

读取报告的结构化只读快照（按报告模板生成）；快照字段以领域快照定义为准确来源。

路径参数：`report_id`（string）：报告编号。

## 6. 报告计划与备份计划（13 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/backups/schedules` | 分页查询备份计划 | `backups.read` | 否 | - | - | `分页列表 schedules` |
| POST | `/backups/schedules` | 创建备份计划 | `backups.create` | 是 | 确认 | - | `对象（见字段/说明）` |
| DELETE | `/backups/schedules/{schedule_id}` | 删除备份计划 | `backups.create` | 是 | 确认+原因 | - | `AdminDeletedArtifact` |
| GET | `/backups/schedules/{schedule_id}` | 读取备份计划 | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| PUT | `/backups/schedules/{schedule_id}` | 更新备份计划 | `backups.create` | 是 | 确认 | - | `对象（见字段/说明）` |
| POST | `/backups/schedules/{schedule_id}/enabled` | 启停备份计划 | `backups.create` | 是 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/report-plans` | 分页查询报告计划 | `reports.schedule.manage` | 否 | - | - | `分页列表 plans` |
| POST | `/report-plans` | 创建报告计划 | `reports.schedule.manage` | 是 | 确认 | - | `对象（见字段/说明）` |
| DELETE | `/report-plans/{plan_id}` | 删除报告计划 | `reports.schedule.manage` | 是 | 确认+原因 | - | `AdminDeletedArtifact` |
| GET | `/report-plans/{plan_id}` | 读取报告计划 | `reports.schedule.manage` | 否 | - | - | `对象（见字段/说明）` |
| PUT | `/report-plans/{plan_id}` | 更新报告计划 | `reports.schedule.manage` | 是 | 确认 | - | `对象（见字段/说明）` |
| GET | `/report-plans/{plan_id}/delete-preview` | 报告计划删除预演（只读） | `reports.schedule.manage` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/report-plans/{plan_id}/enabled` | 启停报告计划 | `reports.schedule.manage` | 是 | 确认+原因 | - | `对象（见字段/说明）` |

### `GET /backups/schedules`

按 backups.read 分页查询备份计划（含下次运行/权限状态）。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。

### `POST /backups/schedules`

创建备份计划（backups.create 敏感策略 + 确认 + 审计）；返回创建后的计划视图。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `name` | string | 是 | 备份计划名称。 |
| `schedule_type` | string | 是 | 调度类型（服务端白名单）。 |
| `expression` | string | 是 | 调度表达式（非法返回 400）。 |
| `time_zone` | string | 否 | IANA 时区；空使用服务端默认。 |
| `missed_policy` | string | 否 | 错过调度策略（skip/catch_up 等）。 |
| `max_catch_up` | integer | 否 | 最大补跑次数。 |
| `timeout_seconds` | integer | 否 | 单次备份超时秒数。 |
| `max_attempts` | integer | 否 | 最大尝试次数。 |
| `retention_version` | integer | 是 | 读取到的备份保留策略版本；用于绑定保留语义。 |
| `notify_failures` | boolean | 否 | 失败时是否发送安全告知。 |
| `notify_success` | boolean | 否 | 成功时是否发送安全告知。 |
| `notify_target` | string | 否 | 告知目标（服务端白名单渠道；不包含凭据）。 |
| `enabled` | boolean | 否 | 创建后是否立即启用。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |
| `reason` | string | 否 | 审计说明（可选）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "enabled": true,
    "expression": "example-expression",
    "max_attempts": 1,
    "max_catch_up": 1,
    "missed_policy": "example-missed_policy",
    "name": "example-name",
    "notify_failures": true,
    "notify_success": true,
    "notify_target": "example-notify_target",
    "reason": "example-reason",
    "request_id": "example-request_id",
    "retention_version": 1,
    "schedule_type": "example-schedule_type",
    "time_zone": "example-time_zone",
    "timeout_seconds": 1
}
```

### `DELETE /backups/schedules/{schedule_id}`

删除备份计划（敏感策略 + 确认 + 原因）；已生成的备份产物不随计划删除而删除。

路径参数：`schedule_id`（string）：备份计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

### `GET /backups/schedules/{schedule_id}`

读取单个备份计划详情。

路径参数：`schedule_id`（string）：备份计划编号。

### `PUT /backups/schedules/{schedule_id}`

按行版本/保留版本更新备份计划（敏感策略 + 确认）；版本冲突返回 409。

路径参数：`schedule_id`（string）：备份计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `name` | string | 是 | 备份计划名称。 |
| `schedule_type` | string | 是 | 调度类型（服务端白名单）。 |
| `expression` | string | 是 | 调度表达式（非法返回 400）。 |
| `time_zone` | string | 否 | IANA 时区；空使用服务端默认。 |
| `missed_policy` | string | 否 | 错过调度策略（skip/catch_up 等）。 |
| `max_catch_up` | integer | 否 | 最大补跑次数。 |
| `timeout_seconds` | integer | 否 | 单次备份超时秒数。 |
| `max_attempts` | integer | 否 | 最大尝试次数。 |
| `retention_version` | integer | 是 | 读取到的备份保留策略版本；用于绑定保留语义。 |
| `notify_failures` | boolean | 否 | 失败时是否发送安全告知。 |
| `notify_success` | boolean | 否 | 成功时是否发送安全告知。 |
| `notify_target` | string | 否 | 告知目标（服务端白名单渠道；不包含凭据）。 |
| `enabled` | boolean | 否 | 创建后是否立即启用。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |
| `reason` | string | 否 | 审计说明（可选）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "enabled": true,
    "expression": "example-expression",
    "max_attempts": 1,
    "max_catch_up": 1,
    "missed_policy": "example-missed_policy",
    "name": "example-name",
    "notify_failures": true,
    "notify_success": true,
    "notify_target": "example-notify_target",
    "reason": "example-reason",
    "request_id": "example-request_id",
    "retention_version": 1,
    "schedule_type": "example-schedule_type",
    "time_zone": "example-time_zone",
    "timeout_seconds": 1
}
```

### `POST /backups/schedules/{schedule_id}/enabled`

启用/停用备份计划（敏感策略 + 确认 + 原因）；原因进入真实审计。

路径参数：`schedule_id`（string）：备份计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `enabled` | boolean | 是 | true 启用 / false 停用。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "enabled": true,
    "reason": "example-reason"
}
```

### `GET /report-plans`

按 reports.schedule.manage 分页查询报告生成计划；支持有界字面搜索（计划名称/编号）。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `search`（string，可选）：有界字面搜索（NFKC + 大小写折叠，最多 64 字符）；空表示不过滤。
- `search_fields`（string，可选）：逗号分隔的搜索字段白名单：name 等许可字段（服务端白名单）；未知字段返回 400。

### `POST /report-plans`

创建报告生成计划（reports.schedule.manage 敏感策略 + 确认 + 作用范围校验 + 审计）；返回创建后的计划视图。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `name` | string | 是 | 计划名称（用户文本，不拼接 HTML）。 |
| `scope_id` | string | 是 | 作用范围：system 或应用编号；必须在调用者可管理范围内。 |
| `schedule_type` | string | 是 | 调度类型（服务端白名单：cron/固定周期等）。 |
| `expression` | string | 是 | 调度表达式（按 schedule_type 解析，非法返回 400）。 |
| `time_zone` | string | 否 | IANA 时区，例如 Asia/Shanghai；空使用服务端默认。 |
| `app_id` | string | 否 | 应用范围时的目标应用编号（与 scope_id 一致校验）。 |
| `granularity` | string | 否 | 统计粒度（服务端枚举）。 |
| `window_days` | integer | 否 | 统计窗口天数（服务端范围校验）。 |
| `categories` | array | 否 | 报告分类（服务端白名单）。 |
| `trend_metric` | string | 否 | 趋势指标（服务端枚举）。 |
| `formats` | array | 否 | 输出格式列表（html/csv/json/pdf/markdown，至少一种）。 |
| `detail_rows` | integer | 否 | 明细行数上限（服务端硬上限）。 |
| `missed_policy` | string | 否 | 错过调度策略（skip/catch_up 等，服务端枚举）。 |
| `max_catch_up` | integer | 否 | 最大补跑次数。 |
| `timeout_seconds` | integer | 否 | 单次生成超时秒数（服务端范围）。 |
| `max_attempts` | integer | 否 | 最大尝试次数。 |
| `enabled` | boolean | 否 | 创建后是否立即启用；默认按服务端策略。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |
| `reason` | string | 否 | 更新/审计说明（可选；创建不需要）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "app_id": "example-app_id",
    "categories": [
        "example-value"
    ],
    "confirm": true,
    "detail_rows": 1,
    "enabled": true,
    "expression": "example-expression",
    "formats": [
        "example-value"
    ],
    "granularity": "example-granularity",
    "max_attempts": 1,
    "max_catch_up": 1,
    "missed_policy": "example-missed_policy",
    "name": "example-name",
    "reason": "example-reason",
    "request_id": "example-request_id",
    "schedule_type": "example-schedule_type",
    "scope_id": "example-scope_id",
    "time_zone": "example-time_zone",
    "timeout_seconds": 1,
    "trend_metric": "example-trend_metric",
    "window_days": 1
}
```

### `DELETE /report-plans/{plan_id}`

删除报告计划（敏感策略 + 确认 + 原因）；历史报告与原始审计不随计划删除而消失。

路径参数：`plan_id`（string）：报告计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

### `GET /report-plans/{plan_id}`

读取单个报告计划详情（含下次运行/权限状态）；越权按不存在处理。

路径参数：`plan_id`（string）：报告计划编号。

### `PUT /report-plans/{plan_id}`

按行版本乐观并发更新报告计划（敏感策略 + 确认 + 原因）；version 不一致返回 409，需重新读取。

路径参数：`plan_id`（string）：报告计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `name` | string | 是 | 计划名称（用户文本，不拼接 HTML）。 |
| `scope_id` | string | 是 | 作用范围：system 或应用编号；必须在调用者可管理范围内。 |
| `schedule_type` | string | 是 | 调度类型（服务端白名单：cron/固定周期等）。 |
| `expression` | string | 是 | 调度表达式（按 schedule_type 解析，非法返回 400）。 |
| `time_zone` | string | 否 | IANA 时区，例如 Asia/Shanghai；空使用服务端默认。 |
| `app_id` | string | 否 | 应用范围时的目标应用编号（与 scope_id 一致校验）。 |
| `granularity` | string | 否 | 统计粒度（服务端枚举）。 |
| `window_days` | integer | 否 | 统计窗口天数（服务端范围校验）。 |
| `categories` | array | 否 | 报告分类（服务端白名单）。 |
| `trend_metric` | string | 否 | 趋势指标（服务端枚举）。 |
| `formats` | array | 否 | 输出格式列表（html/csv/json/pdf/markdown，至少一种）。 |
| `detail_rows` | integer | 否 | 明细行数上限（服务端硬上限）。 |
| `missed_policy` | string | 否 | 错过调度策略（skip/catch_up 等，服务端枚举）。 |
| `max_catch_up` | integer | 否 | 最大补跑次数。 |
| `timeout_seconds` | integer | 否 | 单次生成超时秒数（服务端范围）。 |
| `max_attempts` | integer | 否 | 最大尝试次数。 |
| `enabled` | boolean | 否 | 创建后是否立即启用；默认按服务端策略。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |
| `reason` | string | 否 | 更新/审计说明（可选；创建不需要）。 |
| `version` | integer | 是 | 读取时的行版本；必须 >0，版本不一致返回 409（乐观并发）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "app_id": "example-app_id",
    "categories": [
        "example-value"
    ],
    "confirm": true,
    "detail_rows": 1,
    "enabled": true,
    "expression": "example-expression",
    "formats": [
        "example-value"
    ],
    "granularity": "example-granularity",
    "max_attempts": 1,
    "max_catch_up": 1,
    "missed_policy": "example-missed_policy",
    "name": "example-name",
    "reason": "example-reason",
    "request_id": "example-request_id",
    "schedule_type": "example-schedule_type",
    "scope_id": "example-scope_id",
    "time_zone": "example-time_zone",
    "timeout_seconds": 1,
    "trend_metric": "example-trend_metric",
    "version": 1,
    "window_days": 1
}
```

### `GET /report-plans/{plan_id}/delete-preview`

只读预演删除计划的影响（活动任务/历史/不可逆说明）；预览不是删除授权。

路径参数：`plan_id`（string）：报告计划编号。

### `POST /report-plans/{plan_id}/enabled`

启用/停用报告计划（敏感策略 + 确认 + 原因）；启停改变实际执行范围，原因进入真实审计。

路径参数：`plan_id`（string）：报告计划编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `enabled` | boolean | 是 | true 启用 / false 停用。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "enabled": true,
    "reason": "example-reason"
}
```

## 7. 备份（产物/任务/下载票据/保留/清理）（13 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/backups` | 分页查询备份产物 | `backups.read` | 否 | - | - | `分页列表 backups` |
| POST | `/backups` | 提交备份任务 | `backups.create` | 是 | 确认 | 异步任务 | `对象（见字段/说明）` |
| GET | `/backups/capabilities` | 读取备份能力 | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/backups/cleanup` | 提交备份清理任务 | `backups.create` | 是 | 确认 | 异步任务 | `对象（见字段/说明）` |
| GET | `/backups/cleanup-preview` | 备份清理预演（只读） | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/backups/download-tickets/redeem` | 兑换备份下载票据（流式下载） | `backups.export` | 否 | - | 下载:ticket-redeem | `文件流` |
| GET | `/backups/jobs` | 分页查询备份任务 | `backups.read` | 否 | - | - | `分页列表 jobs` |
| GET | `/backups/jobs/{job_id}` | 读取备份任务 | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/backups/jobs/{job_id}/cancel` | 取消备份任务 | `backups.cancel` | 否 | 确认+原因 | 异步任务/可取消 | `对象（见字段/说明）` |
| GET | `/backups/retention` | 读取备份保留策略 | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| PUT | `/backups/retention` | 更新备份保留策略 | `backups.retention` | 是 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/backups/{backup_id}` | 读取备份产物 | `backups.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/backups/{backup_id}/download-tickets` | 签发一次性备份下载票据 | `backups.export` | 是 | 确认 | 下载:ticket-issue | `对象（见字段/说明）` |

### `GET /backups`

按 backups.read 分页查询备份产物元数据（大小/摘要/内容范围/校验状态/保留与可下载状态）；不返回宿主路径。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `schedule_id`（string，可选）：按备份计划编号筛选。
- `job_id`（string，可选）：按备份任务编号筛选。
- `origin`（string，可选）：按来源筛选（manual/schedule 等，服务端枚举）。
- `verification`（string，可选）：按校验状态筛选（服务端枚举）。
- `cleanup`（string，可选）：按清理状态筛选（服务端枚举）。

### `POST /backups`

提交一次备份（backups.create 敏感策略 + 确认）；受理/去重成功不等于备份完成，需按 job_id 查询真实终态。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "request_id": "example-request_id"
}
```

边界与语义：

- existing=true 表示命中活动任务去重，未重复创建；状态以任务真实状态为准。

### `POST /backups/cleanup`

提交清理任务（backups.create 敏感策略 + 确认）；执行时重新计算候选与保护状态，受理≠完成。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "request_id": "example-request_id"
}
```

边界与语义：

- 原始安全审计不受清理影响；受保护/最后可用备份不会被清理。

### `POST /backups/download-tickets/redeem`

消费一次性备份下载票据并流式返回受控备份字节；兑换时再次授权并重新检查产物状态，重复兑换/撤权后兑换被拒绝。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `token` | string | 是 | 一次性下载票据（只写；示例为合成值，不可用于真实下载）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "token": "example-download-token-synthetic-not-real"
}
```

边界与语义：

- 成功响应不是 JSON 信封：200 + 受控文件字节（Content-Disposition 使用稳定文件名，不含宿主路径）。
- 票据过期/已用/授权撤销返回 400/403/409，不返回空文件假成功。

### `GET /backups/jobs`

分页查询备份/清理任务（真实状态、阶段、进度与通知状态）；进度不表示成功。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `kind`（string，可选）：任务类型筛选（备份/清理等，服务端枚举）。
- `schedule_id`（string，可选）：按计划编号筛选。

### `GET /backups/jobs/{job_id}`

读取单个备份/清理任务详情（阶段、进度、尝试、通知状态、错误码）。

路径参数：`job_id`（string）：备份/清理任务编号。

### `POST /backups/jobs/{job_id}/cancel`

请求取消备份/清理任务（backups.cancel + 确认 + 原因）；accepted 只表示受理取消，终态以任务状态为准。

路径参数：`job_id`（string）：备份/清理任务编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason"
}
```

### `PUT /backups/retention`

更新备份保留策略（敏感策略 + 确认 + 原因 + 版本乐观并发）；不按旧预览强删，清理在执行时重新计算候选与保护状态。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `max_count` | integer | 是 | 最多保留备份数量；0 表示不设该维度上限（受服务端策略约束）。 |
| `max_age_days` | integer | 是 | 最长保留天数；0 表示不设该维度上限（受服务端策略约束）。 |
| `max_total_bytes` | integer | 是 | 保留总字节上限；0 表示不设该维度上限（受服务端策略约束）。 |
| `expected_version` | integer | 是 | 期望的当前策略版本；版本不一致返回 409。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "expected_version": 1,
    "max_age_days": 1,
    "max_count": 1,
    "max_total_bytes": 1,
    "reason": "example-reason"
}
```

### `GET /backups/{backup_id}`

读取单个备份产物元数据（含校验状态、保留保护与可下载性）。

路径参数：`backup_id`（string）：备份产物编号。

### `POST /backups/{backup_id}/download-tickets`

为指定备份签发一次性短期下载票据（backups.export 敏感策略 + 确认）；token 只在本次响应返回一次，不写入日志/审计。

路径参数：`backup_id`（string）：备份产物编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "request_id": "example-request_id"
}
```

边界与语义：

- 票据短期有效（有效期见 GET /backups/capabilities 的 download_ttl_seconds），一次性消费。
- 兑换路径：POST /backups/download-tickets/redeem；兑换时再次授权并重新检查产物状态与保留保护。
- 响应不含服务器路径；不要把它当可分享的下载地址。

## 8. 任务（详情/尝试历史）（2 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/tasks` | 查询任务（稳定游标） | `diagnostics.read` | 否 | - | - | `对象（见字段/说明）` |
| GET | `/tasks/{task_id}` | 读取任务详情 | `diagnostics.read` | 否 | - | - | `对象（见字段/说明）` |

### `GET /tasks`

按 diagnostics.read 与数据范围/属主查询任务摘要（显式剔除任务载荷）；使用稳定 cursor 分页（offset 必须为 0，非零被拒绝），支持 kind/state/request_id/时间筛选。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100。
- `cursor`（string，可选）：稳定游标：下一页请求带 cursor。
- `kind`（string，可选）：任务类型筛选。
- `state`（string，可选）：任务状态筛选（服务端任务状态机）。
- `request_id`（string，可选）：请求编号筛选。
- `from`（string，可选）：创建时间起始（含，RFC3339）。
- `to`（string，可选）：创建时间结束（不含，RFC3339）。

边界与语义：

- 列表级授权先于查询：普通用户只看到本人发起的任务；不返回任务载荷与秘密。

### `GET /tasks/{task_id}`

按 diagnostics.read + 数据范围/属主读取任务详情与尝试历史（显式剔除任务载荷）；越权 403、不存在 404。

路径参数：`task_id`（string）：任务编号。

## 9. 配置诊断（脱敏运行诊断）（3 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/diagnostics` | 读取脱敏运行诊断 | `diagnostics.read` | 否 | - | - | `AdminDiagnosticsReport` |
| GET | `/diagnostics/errors` | 读取关联错误 | `diagnostics.read` | 否 | - | - | `AdminDiagnosticsErrors` |
| GET | `/diagnostics/export` | 脱敏诊断导出 | `diagnostics.read` | 否 | - | - | `AdminDiagnosticsExport` |

### `GET /diagnostics`

按 diagnostics.read 与明确 system/应用范围读取只读脱敏运行状态、队列、配置待重启与关联错误白名单；不含秘密。

查询参数：

- `scope`（string，可选）：数据范围：空或 system 表示系统范围；应用范围传应用编号。

### `GET /diagnostics/errors`

按 request_id 读取有界关联错误（只读脱敏，不返回审计 detail）；limit 超硬上限返回 400。

查询参数：

- `scope`（string，可选）：数据范围：空或 system 表示系统范围；应用范围传应用编号。
- `request_id`（string，可选）：按请求编号关联错误（可选）。
- `limit`（integer，可选）：错误条数上限（1～50）；空使用诊断服务默认，超限返回 400。

### `GET /diagnostics/export`

按 diagnostics.read 生成有界脱敏诊断导出（JSON 快照，可带关联错误）；不执行脚本、不返回秘密或内部连接细节。

查询参数：

- `scope`（string，可选）：数据范围：空或 system 表示系统范围；应用范围传应用编号。
- `request_id`（string，可选）：可选：附带该请求编号的关联错误。
- `limit`（integer，可选）：关联错误条数上限（1～50）。

## 10. 配置管理（脱敏字段/校验/更新/恢复）（5 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/settings` | 读取脱敏配置字段 | `settings.manage` | 否 | - | - | `AdminSettingsFields` |
| PUT | `/settings` | 更新配置 | `settings.manage` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/settings/sensitive-policy/restore` | 恢复敏感操作策略（仅 root） | root-only | 是 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/settings/status` | 读取配置状态 | `settings.manage` | 否 | - | - | `AdminSettingsStatus` |
| POST | `/settings/validate` | 校验配置变更（不落盘） | `settings.manage` | 否 | - | - | `对象（见字段/说明）` |

### `PUT /settings`

按版本乐观并发原子写入配置（settings.manage + 审计；root-only 字段按真实 root 判定）；失败保留最后有效值。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `expected_version` | string | 是 | 期望的当前配置版本；不一致返回 409，需重新读取。 |
| `changes` | object | 是 | 字段名→新值的映射（秘密字段仅接受受控占位语义；不接受明文回写掩盖真实秘密）。 |
| `reason` | string | 否 | 操作原因（可选，进入审计）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "changes": {
        "example_field": "example-value"
    },
    "expected_version": "example-expected_version",
    "reason": "example-reason"
}
```

边界与语义：

- 区分磁盘值/当前有效值/待重启；失败不覆盖真实秘密。

### `POST /settings/sensitive-policy/restore`

仅真实 root 用户 + 再次认证（强认证因素）+ 版本冲突检查 + 关键审计；恢复后策略下限不可被普通 settings.manage 放宽。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `scope_id` | string | 是 | 作用范围：system 或应用编号。 |
| `operation_id` | string | 是 | 敏感操作 ID（服务端目录白名单）。 |
| `all` | boolean | 否 | true 表示恢复该范围全部操作（与 operation_id 二选一，由服务端校验）。 |
| `expected_version` | integer | 是 | 期望的策略版本；不一致返回 409。 |
| `password` | string | 是 | 当前密码（本次操作的两步验证因素之一；只写）。 |
| `totp_code` | string | 是 | 当前 TOTP 验证码（无密码 Passkey 账户可用 Passkey 再次认证；只写）。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "all": true,
    "confirm": true,
    "expected_version": 1,
    "operation_id": "example-operation_id",
    "password": "example-password-synthetic-not-real",
    "reason": "example-reason",
    "scope_id": "example-scope_id",
    "totp_code": "000000"
}
```

边界与语义：

- root-only 属于身份能力，settings.manage 不能获得；恢复只回到目录下限，不得降低最弱认证强度。
- 历史记录不回滚；恢复本身写关键审计。

### `POST /settings/validate`

校验拟变更字段（settings.manage；root-only 字段按真实身份拒绝）；不写磁盘、不改变当前有效值。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `changes` | object | 是 | 字段名→新值的映射（字段白名单与秘密占位规则由服务端校验）。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "changes": {
        "example_field": "example-value"
    }
}
```

## 11. 安全通知与本地捕获测试（3 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/notifications` | 安全通知配置脱敏状态 | 管理会话基线 | 否 | - | - | `AdminNotificationStatus` |
| GET | `/notifications/history` | 查询安全告知历史（稳定游标） | `diagnostics.read` / `audit.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/notifications/test` | 本地捕获通知测试 | 管理会话基线 | 是 | 确认 | - | `AdminNotificationTest` |

### `GET /notifications`

返回安全通知/邮件投递配置的脱敏状态与启用情况；未装配通知服务时返回稳定能力错误码而非伪造成功。

边界与语义：

- 不返回 SMTP 密码、令牌或内部连接细节；未装配时 503 MAIL_DIAGNOSTICS_UNAVAILABLE。

### `GET /notifications/history`

按目标用户分页查询脱敏安全告知记录；权限在注入的 Reader 内重新判定（本人，或具备诊断/审计读取权限的系统范围主体），失败按拒绝处理。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；列表使用稳定游标，不接受非零 offset。
- `cursor`（string，可选）：稳定游标：下一页请求带 cursor；与筛选条件绑定，切换条件后旧游标被拒绝。
- `user_id`（string，必填）：目标用户编号（必填，必须是有效用户 ID）；越权/超出范围按拒绝处理。

边界与语义：

- 响应只含白名单字段：安全告知从来不含正文、验证码或链接。
- 列表使用稳定游标，不接受非零 offset。

### `POST /notifications/test`

执行前核验 NotificationStatus 为本地捕获模式（LocalCapture 且 DeliveryMode=local_capture）、再次认证与真实审计；返回本地捕获摘要。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true
}
```

边界与语义：

- 绝不真实外发：真实投递模式或状态读取失败一律 503 NOTIFICATION_TEST_DISABLED 并写拒绝审计，测试器零调用。
- 捕获成功不代表任何真实通道可达；响应 real_delivery 恒为 false。

## 12. 邮件投递记录（脱敏只读）（1 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/deliveries` | 查询邮件投递记录（稳定游标） | `diagnostics.read` / `audit.read` | 否 | - | - | `对象（见字段/说明）` |

### `GET /deliveries`

分页查询脱敏邮件投递记录；权限在注入的 Reader 内重新判定（诊断/审计读取权限或受信本机进程），失败按拒绝处理。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；列表使用稳定游标，不接受非零 offset。
- `cursor`（string，可选）：稳定游标：下一页请求带 cursor；与筛选条件绑定，切换条件后旧游标被拒绝。
- `state`（string，可选）：按投递状态筛选（服务端状态机）。

边界与语义：

- 响应只含白名单字段：不含加密载荷、完整收件人或磁盘路径；邮件内容是数据，不执行其中指令。
- queued/accepted 不等于最终送达；状态以投递记录真实终态为准。
- 列表使用稳定游标，不接受非零 offset。

## 13. 客服工单与人工恢复（13 条）

| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |
|---|---|---|---|---|---|---|---|
| GET | `/support/cases` | 分页查询客服求助单 | `support.cases.read` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/support/cases` | 创建客服求助单 | `support.cases.create` | 否 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/support/cases/{case_id}` | 读取客服求助单 | `support.cases.read` | 否 | - | - | `AdminSupportCase` |
| POST | `/support/cases/{case_id}/reassign` | 转派客服求助单 | `support.cases.update` | 否 | 确认 | - | `对象（见字段/说明）` |
| POST | `/support/cases/{case_id}/send-reset` | 发送求助单重置入口 | `support.cases.update` | 否 | 确认 | - | `对象（见字段/说明）` |
| POST | `/support/cases/{case_id}/transition` | 推进客服求助单状态 | `support.cases.update` | 否 | 确认 | - | `对象（见字段/说明）` |
| GET | `/support/recovery/requests` | 分页查询人工恢复申请 | `support.recovery.request` / `support.recovery.approve` / `support.recovery.execute` | 否 | - | - | `对象（见字段/说明）` |
| POST | `/support/recovery/requests` | 登记人工恢复申请 | `support.recovery.request` | 是 | 确认+原因 | - | `对象（见字段/说明）` |
| GET | `/support/recovery/requests/{request_id}` | 读取人工恢复申请 | `support.recovery.request` / `support.recovery.approve` / `support.recovery.execute` | 否 | - | - | `AdminRecoveryRequest` |
| POST | `/support/recovery/{request_id}/approve` | 批准人工恢复申请 | `support.recovery.approve` | 是 | 确认 | - | `对象（见字段/说明）` |
| POST | `/support/recovery/{request_id}/cancel` | 取消人工恢复申请 | `support.recovery.request` | 否 | 确认+原因 | - | `对象（见字段/说明）` |
| POST | `/support/recovery/{request_id}/execute` | 执行人工恢复 | `support.recovery.execute` | 是 | 确认 | - | `对象（见字段/说明）` |
| POST | `/support/recovery/{request_id}/reject` | 驳回人工恢复申请 | `support.recovery.approve` | 否 | 确认+原因 | - | `对象（见字段/说明）` |

### `GET /support/cases`

按 support.cases.read 与客服数据范围分页查询求助单（按状态筛选、工单编号/原因有界字面搜索）；越权不返回他人范围数据。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `status`（string，可选）：按求助单状态筛选（服务端状态机）。
- `search`（string，可选）：有界字面搜索（NFKC + 大小写折叠，最多 64 字符）；空表示不过滤。
- `search_fields`（string，可选）：逗号分隔的搜索字段白名单：id/reason 等许可字段（不搜索脱敏邮箱/用户名）；未知字段返回 400。

边界与语义：

- 响应不返回 limit/offset，只给 has_more/next_offset；越权不返回他人范围数据。

### `POST /support/cases`

登记求助单并记录真实操作者/目标/理由（support.cases.create + 确认 + 审计）。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `target_user_id` | string | 是 | 目标用户编号；必须在可管理数据范围内。 |
| `reason` | string | 是 | 求助原因（用户文本，不拼接 HTML）。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason",
    "request_id": "example-request_id",
    "target_user_id": "example-target_user_id"
}
```

### `GET /support/cases/{case_id}`

读取单个求助单详情（目标用户名/邮箱按脱敏展示）；超出数据范围按不存在处理。

路径参数：`case_id`（string）：求助单编号。

### `POST /support/cases/{case_id}/reassign`

把范围内求助单转派给可接单客服（support.cases.update + 确认）；目标接单资格由服务端校验。

路径参数：`case_id`（string）：求助单编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `new_assignee_user_id` | string | 是 | 新受理客服用户编号（须具备接单资格）。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "new_assignee_user_id": "example-new_assignee_user_id",
    "request_id": "example-request_id"
}
```

### `POST /support/cases/{case_id}/send-reset`

按求助单发送受控重置入口/通知（support.cases.update + 确认）；客服不读取、不提交用户新密码，也不回显令牌。

路径参数：`case_id`（string）：求助单编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "request_id": "example-request_id"
}
```

边界与语义：

- 发送受理不等于收件人送达；失败如实返回稳定错误码，不伪造已发送。

### `POST /support/cases/{case_id}/transition`

按求助单状态机推进状态并记录说明（support.cases.update + 确认）；非法状态转移被拒绝，不伪造完成。

路径参数：`case_id`（string）：求助单编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `to_status` | string | 是 | 目标状态（服务端状态机白名单）。 |
| `note` | string | 否 | 处理说明（用户文本）。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "note": "example-note",
    "request_id": "example-request_id",
    "to_status": "example-to_status"
}
```

### `GET /support/recovery/requests`

按参与/审批/执行关系分页查询人工恢复申请工作台（mode/operation 筛选）；普通客服只看到授权范围内的申请。

查询参数：

- `limit`（integer，可选）：每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。
- `offset`（integer，可选）：偏移分页，默认 0，最大 1000000；与游标分页互斥。
- `mode`（string，可选）：工作台视图：pending_approval（默认）/我的申请/待执行等（服务端枚举）。
- `operation`（string，可选）：恢复操作类型筛选：password_reset / mfa_reset。

边界与语义：

- 响应不返回 limit/offset，只给 has_more/next_offset；普通客服只看到授权范围内申请。

### `POST /support/recovery/requests`

登记密码/MFA 人工恢复申请并绑定目标、操作、核验依据与交付渠道（support.recovery.request + 确认 + 审计）；申请不等于批准。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `target_user_id` | string | 是 | 恢复目标用户编号；不得为 root 或超出可管理范围。 |
| `operation` | string | 是 | 恢复操作：password_reset / mfa_reset。 |
| `verification_basis` | string | 是 | 核验依据类型（服务端白名单）。 |
| `verification_reference` | string | 是 | 核验依据引用编号；不得包含用户秘密。 |
| `evidence_summary` | string | 是 | 证据摘要：只提交一次、不落库明文。 |
| `reason` | string | 是 | 申请理由。 |
| `delivery` | string | 否 | 结果交付渠道。 |
| `support_case_id` | string | 否 | 关联求助单编号（可选）。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "delivery": "example-delivery",
    "evidence_summary": "example-evidence_summary",
    "operation": "example-operation",
    "reason": "example-reason",
    "request_id": "example-request_id",
    "support_case_id": "example-support_case_id",
    "target_user_id": "example-target_user_id",
    "verification_basis": "example-verification_basis",
    "verification_reference": "example-verification_reference"
}
```

边界与语义：

- 同一申请必须经独立审批；同一操作者不能自我批准（后端审批规则判定）。

### `GET /support/recovery/requests/{request_id}`

读取申请详情（目标/发起人/操作/状态/批准/内容摘要一致性）；不含令牌、验证码或用户新秘密。

路径参数：`request_id`（string）：人工恢复申请编号。

### `POST /support/recovery/{request_id}/approve`

独立审批人批准恢复申请（support.recovery.approve + 确认）；批准不等于执行，执行仍需独立权限与再次认证。

路径参数：`request_id`（string）：人工恢复申请编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `note` | string | 否 | 审批说明。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "note": "example-note",
    "request_id": "example-request_id"
}
```

边界与语义：

- 审批人不能是申请发起人的同一自然人；自我批准被拒绝。

### `POST /support/recovery/{request_id}/cancel`

取消未执行的人工恢复申请并记录理由（support.recovery.request + 确认 + 原因）；取消请求与实际取消分别记录。

路径参数：`request_id`（string）：人工恢复申请编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason",
    "request_id": "example-request_id"
}
```

### `POST /support/recovery/{request_id}/execute`

执行已批准的人工恢复（独立权限 + 再次认证 + 审批状态复核 + 关键审计）；不读取/回显用户秘密，成功只返回脱敏结果，目标旧会话/凭据失效。

路径参数：`request_id`（string）：人工恢复申请编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "request_id": "example-request_id"
}
```

边界与语义：

- 执行不复用“已验证找回令牌”的授权路径；审批状态/权限/再次认证在提交处复核。
- 恢复仅 root 由受保护策略约束；人工恢复申请不得以 root 为目标。
- 不向操作者返回旧密码、哈希、令牌或 MFA 种子。

### `POST /support/recovery/{request_id}/reject`

驳回恢复申请并记录理由（support.recovery.approve + 确认 + 原因）；驳回后不执行任何恢复动作。

路径参数：`request_id`（string）：人工恢复申请编号。

请求体（application/json，严格解码）：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `confirm` | boolean | 是 | 必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。 |
| `reason` | string | 是 | 操作原因；进入真实审计，不能为空，最多 256 字节。 |
| `request_id` | string | 否 | 可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。 |

请求体示例（合成值，不可用于真实操作）：

```json
{
    "confirm": true,
    "reason": "example-reason",
    "request_id": "example-request_id"
}
```

## 机器可读

- [http-openapi-admin.json](http-openapi-admin.json)：本页同源 OpenAPI 3 文档（信封/组件/参数/请求体/响应/扩展）。
- [http-routes.json](http-routes.json)：路由事实来源（AST 扫描真实注册）。
- 生成与校验：`go run ./scripts/adminapi-doc -write` / `-check`（失败非零退出）。
