# 接口参考（人类与 AI 共用）

> 本目录由 `go run ./scripts/reference -write` 生成，**不要手工编辑**。修改生成逻辑请改 `scripts/internal/apidoc/` 后重新生成；`-check` 与 [verify-docs](../guide/README.md) 会逐字节核对，文档与代码漂移会让校验失败。

这里是人类与 AI 共用的**单一接口参考入口**：Go API、HTTP、CLI、权限、错误码、配置与能力映射都以代码为唯一事实来源生成，不维护第二套手写全集。

## 1. 现在先读什么

- **先判断“能不能用 / 已实现到什么程度”**：读 [能力矩阵](../acceptance/capability-matrix.md)（状态）与本页“覆盖范围”。
- **嵌入 Go 程序**：读 [go-api.md](go-api.md)（运行时生命周期与公开接口总览）→ [errors.md](errors.md) → [配置 guide](../guide/configuration.md)。
- **独立部署/运维**：读 [HTTP 契约](http-api.md)、[CLI](cli.md)、[部署文档](../deployment/README.md)。
- **业务接入**：读 [HTTP 契约](http-api.md) 与 [业务接入契约](../deployment/integration.md)。
- **排障**：读 [错误码](errors.md) 与 [排障指南](../guide/troubleshooting.md)。
- **AI/自动化**：直接读 [ai-index.md](ai-index.md) 与全部机器 JSON（生成器当前输出见 ai-index §2）。

## 2. 文件索引

### 2.1 Markdown（稳定锚点，人类与 AI 均可读）

| 文件 | 内容 |
|---|---|
| errors.md | 公开错误码表（48 个注册码 + 公开说明 + 防泄露边界） |
| permissions.md | 内置权限目录（权限键/角色/用户组 + 谁能在什么范围做什么） |
| configuration.md | 配置字段元数据（字段/环境变量/生效分类/秘密标记；语义以 guide 为准） |
| http-api.md | HTTP 契约：管理 JSON API 路由、协议端点契约/例外、页面命名路由、页面与协议 OpenAPI |
| cli.md | CLI 参考：三个程序的命令树、flag 与稳定退出码 |
| go-api.md | 公开 Go API 参考：运行时生命周期与服务接口总览（Phase A 框架，Phase B 方法级补齐） |
| capability-map.md | 能力映射：catalog.json 的 53 项能力 → 参考文档与机器 JSON 锚点 |
| ai-index.md | AI 入口：按任务找文档/机器 JSON/示例与校验命令 |
| change-log.md | 公开接口变更记录（Phase B 迁入完整历史） |

### 2.2 机器可读 JSON（由本工具生成，供程序/AI 直接消费）

| 文件 | 内容 |
|---|---|
| error-codes.json | 错误码：码/分类/HTTP/公开含义/原因/建议/重试 |
| permission-keys.json | 权限键 + 预设角色 + 用户组 + 应用模板 |
| http-routes.json | 管理路由 + 协议路径/端点 + 页面命名路由 |
| http-openapi.json | OpenAPI 3：页面/表单操作（字段/响应/状态转移） |
| protocol-openapi.json | OpenAPI 3：OAuth 2.0 / OIDC 协议端点（标准错误/项目信封/浏览器重定向区分） |
| cli-commands.json | CLI 命令树 + flag + 退出码 |

## 3. 覆盖范围（本次生成盘点）

| 对象 | 数量 |
|---|---|
| 公开错误码 | 48 |
| 内置权限键 | 53（预设角色 5、系统用户组 5、应用角色模板 2、应用用户组模板 2） |
| 配置字段 | 58 |
| 管理 JSON API 路由 | 137 |
| 协议路径 / 端点表 / HTTP 契约 | 17 / 19 / 19 |
| 内置页面命名路由 | 250 |
| 页面/表单 OpenAPI 操作 | 95（未登记契约的页面路由 155） |
| CLI | 4 个程序 / 58 个子命令 / 189 个 flag |
| 公开 Go API（app） | Runtime 方法 45、服务接口 43（方法 270）、公开函数 6、公开类型 468 |
| 公开 Go API（根包） | 类型 447、函数 38 |
| 能力声明 | 53 |

## 4. 与能力矩阵的只读交叉核对

本工具**不重新生成**能力矩阵，只读取 [capability-matrix.json](../acceptance/capability-matrix.json) 的盘点数量做交叉核对；不一致只作为告警（矩阵由能力盘点步骤维护，口径可能不同）。

| 对象 | 能力矩阵盘点 | reference 扫描 |
|---|---|---|
| 管理路由 | 137 | 137 |
| 页面路由 | 250 | 250 |
| 协议路径 | 17 | 17 |
| 协议端点 HTTP 契约 | 19 | 19 |
| CLI 子命令 | 58 | 58 |
| 权限键 | 53 | 53 |
| app 函数（含导出方法） | 340 | 340 |
| 根包公开类型 | 447 | 447 |

无。

## 5. 生成与校验

```powershell
go run ./scripts/reference -write     # 重新生成 docs/reference
go run ./scripts/reference -check     # 校验生成物与源码一致（只读）
go run ./scripts/verify-docs          # 文档总校验（含 reference 检查）
go build ./examples/reference-snippets # 最小示例真实编译
```

生成物约定：确定性排序、LF 行尾、无时间戳、无本机路径；`-write` 原子写入，`-check` 只读。

## 6. 阶段范围与 Phase B 待补

Phase A（步骤 245A）先交付机器 JSON 与稳定领域参考。公开 Go API 的**方法级**参考（每个方法调用身份/应用范围/分页/取消/幂等/任务终态/错误/最小例）等 214/215（目录与 app 类型重组）及 226–235 公开门面稳定后再补齐，避免文档随重构反复改写。

| Phase B 领域 | 待补内容 | 涉及接口数 |
|---|---|---|
| auth-session-mfa | 认证、会话、安全与 MFA 领域的方法级参考待 Phase B | 8 |
| users-account | 账户、资料、密码、注册、邀请、批量与有效期领域的方法级参考待 Phase B | 11 |
| rbac-applications | RBAC、应用、OAuth 客户端与委派领域的方法级参考待 Phase B | 8 |
| audit-reports | 审计与报告领域的方法级参考待 Phase B | 2 |
| backup-restore | 备份、恢复与任务领域的方法级参考待 Phase B | 6 |
| ops-diagnostics | 运维、诊断、设置、客服与协议管理领域的方法级参考待 Phase B | 6 |
| misc-interfaces | 未归类接口（Phase B 复核领域映射）：AdminService、OperationProofService | 2 |

## 7. 维护约定

- 新增/修改公开错误码、权限键、HTTP 路由、页面路由、协议路径、CLI 命令或公开 Go 符号后，运行 `-write` 并提交生成物；`-check` 会阻止漂移。
- 能力声明（catalog.json）中的声明若无法映射到实际符号，`-check` 会失败：先修声明或补实现，再生成文档。
- 214/215 重构会移动页面实现与 app 类型文件；届时只需更新 `scripts/internal/apidoc/sources.go` 的源码路径或扫描目录，再重新生成。
- 文档中的最小示例来自 [examples/reference-snippets](../../examples/reference-snippets/snippets.go)，由 `go build` 真实编译；新增示例必须被文档引用。
- OpenAPI 现含三部分：运行期最小 JSON API（健康/文档端点）、页面/表单操作（账户/资料/会话/注册登录/MFA/三种恢复流程）与协议端点离线段（OAuth/OIDC/设备码/扫码；[protocol-openapi.json](protocol-openapi.json)）。管理 JSON API 契约见 [http-openapi-admin.json](http-openapi-admin.json)；协议端点默认关闭、标准错误与项目信封按 http-api.md §3.4 登记。
