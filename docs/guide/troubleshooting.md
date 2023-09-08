# 错误码与排障

本文说明如何按错误码定位问题，并给出 48 个稳定业务错误码的速查表。**权威细节**
（每个码的可能原因与重试规则）见
`docs/requirements/login_错误码与排障手册.md`；代码注册表是 `error_codes.go`，二者由
测试自动比对，不能只改一边。

## 1. 排障顺序

1. 记录：发生时间、应用、操作、错误码、`request_id`（后台任务另记 `task_id`）。
   **不要**粘贴密码、验证码、Token、私钥或完整个人信息。
2. 查表定位分类与建议；在自己获准范围内查受限审计/任务日志。
3. 区分：权限拒绝、需要用户操作（MFA/再次验证）、等待授权、主动取消、数据质量警告、
   系统故障。不是所有非成功状态都是攻击。
4. 写操作重试前先确认是否已经执行；网络超时**不证明**没有成功。
5. 找不到错误码＝文档或实现缺陷，不要猜，也不要自行发明错误码。

排障时优先使用脱敏诊断（`loginctl diag database|health|certificate|mail`）和
`request_id` 查审计，而不是关闭安全校验“先跑起来”。

## 2. 返回约定

- 业务错误统一信封：`code` + `message` + `request_id`（可带 `task_id`、
  `retry_after_seconds`）。
- 联合校验接口可能在 **HTTP 200** 返回 `allow=false` + `code`（业务拒绝），这不是故障。
- OAuth/OIDC 标准协议错误（如 `invalid_grant`、`authorization_pending`、`slow_down`）
  按协议字段返回，**不套用**统一错误信封，也不在本表内重复定义。
- 后台任务提交成功 ≠ 执行成功；用 task_id 查终态。
- 错误对外不细分匿名登录的“账号不存在 vs 密码错误”，不泄露账户是否存在。

## 3. 稳定错误码速查表（48 个）

“HTTP”是普通受保护业务接口的建议映射；“—”表示后台任务/CLI/警告，不指定统一 HTTP
状态。

| 错误码 | 分类 | HTTP | 直白说明与处理建议 |
|---|---|---|---|
| `REQ_INVALID` | 参数 | 400 | 请求内容不符合要求：按字段提示修正后重试 |
| `AUTH_FAILED` | 认证 | 401 | 无法完成登录：本人核对输入；管理员按请求编号查受限记录；限速内重试 |
| `TOKEN_INVALID` | 令牌 | 401 | 访问凭证无效：确认取的是 Access Token 并校验签名/签发方；重新登录 |
| `TOKEN_EXPIRED` | 令牌 | 401 | 访问凭证已过期：刷新或重新登录，检查服务器时间 |
| `TOKEN_REVOKED` | 令牌 | 401 | 访问凭证已撤销：重新登录；查撤销事件，不复用旧令牌 |
| `TOKEN_AUDIENCE_MISMATCH` | 令牌 | 403 | 令牌不能用于当前资源：核对应用登记与目标资源 audience |
| `CLIENT_AUTH_FAILED` | 应用 | 401 | 调用程序身份验证失败：核对密钥版本/认证方式，日志不要打印密钥 |
| `CLIENT_DISABLED` | 应用 | 403 | 应用已停用：查停用原因，由授权管理员处理 |
| `USER_DISABLED` | 账户 | 403 | 账户当前不可用：管理员查禁用记录；不要向匿名请求暴露细节 |
| `APP_MEMBERSHIP_REQUIRED` | 权限 | 403 | 用户未获准使用此应用：检查应用成员关系 |
| `PERMISSION_REQUIRED` | 权限 | 403 | 缺少当前操作所需权限：检查应用、角色来源与 all/any 要求 |
| `PERMISSION_DISABLED` | 权限 | 403 | 权限已停用：查权限状态与停用审计 |
| `PERMISSION_UNKNOWN` | 权限 | 400 | 请求的权限未登记：核对权限标识；不要自动创建并授权 |
| `APP_SCOPE_MISMATCH` | 权限 | 403 | 请求超出调用应用范围：核对可信调用身份与应用范围 |
| `RESOURCE_FORBIDDEN` | 权限 | 403 | 不能操作该记录：业务服务核对资源归属，不能只查功能权限 |
| `ACCESS_DENIED` | 权限 | 403 | 请求未获准：管理员按请求编号查受限审计 |
| `REAUTH_REQUIRED` | 安全策略 | 403 | 需要再次验证身份：完成指定再次验证流程 |
| `MFA_REQUIRED` | 安全策略 | 403 | 需要完成两步验证：完成允许的验证方式 |
| `MFA_REBIND_REQUIRED` | 恢复 | 403 | 需要重新绑定两步验证：完成新因素绑定；此前只有受限会话 |
| `CHALLENGE_INVALID` | 验证 | 400 | 验证请求无效/失效：重新发起本人需要的验证流程 |
| `REFRESH_REUSE_DETECTED` | 令牌 | 401 | 旧刷新凭证重复使用：撤销关联令牌组并重新登录；检查客户端并发 |
| `RATE_LIMITED` | 限流 | 429 | 请求过于频繁：按 `retry_after_seconds` 等待，不高速循环 |
| `SUPPORT_IDENTITY_UNVERIFIED` | 客服恢复 | 403 | 尚未完成身份核验：使用预先批准的可靠核验方式，不能凭口述跳过 |
| `SUPPORT_TARGET_PROTECTED` | 客服恢复 | 403 | 客服不能恢复该账户：root/高权限账户转本地应急流程，不能原路重试 |
| `RECOVERY_APPROVAL_REQUIRED` | 客服恢复 | 403 | 还需要独立审批：由未发起该申请且具备权限的人审批 |
| `RECOVERY_SELF_APPROVAL_DENIED` | 客服恢复 | 403 | 不能批准自己发起的恢复：换独立审批人 |
| `CONFLICT` | 数据 | 409 | 数据已被其他操作修改：重新读取再决定，不覆盖他人更新 |
| `AUTHZ_UNAVAILABLE` | 权限服务 | 503 | 暂时无法判定访问权限：检查数据库/服务健康；业务端保持拒绝，退避重试 |
| `DB_UNAVAILABLE` | 数据库 | 503 | 数据库暂时不可用：核对连接、空间、锁与受限日志 |
| `AUDIT_WRITE_FAILED` | 审计 | 503 | 关键操作未能可靠记录：修复存储；确认原操作未提交后再试 |
| `MAIL_DELIVERY_FAILED` | 邮件任务 | — | 邮件未成功投递：查受限投递记录；已完成的变更不因此回滚；有界重试 |
| `BACKUP_FAILED` | 备份任务 | — | 备份失败：按 task_id 看安全错误详情与临时文件清理结果 |
| `BACKUP_CANCEL_FORBIDDEN` | 备份 | 403 | 无权取消该任务：确认任务范围与申请者当前权限 |
| `TASK_CANCEL_CONFLICT` | 任务 | 409 | 任务已结束或当前阶段不可取消：读取真实状态，不盲目重试 |
| `TASK_CANCELLED` | 任务结果 | — | 任务已取消（终态，不是故障）：查看取消执行人/来源/原因 |
| `TASK_TIMEOUT` | 任务结果 | — | 任务执行超时：查看执行阶段、负载与残留清理 |
| `BACKUP_INVALID` | 备份 | 422 | 备份文件校验未通过：保留原文件，核对校验和与来源，不要强制恢复 |
| `BACKUP_DECRYPT_FAILED` | 备份 | 422 | 无法解密备份：核对密钥与完整性，不打印密钥 |
| `BACKUP_VERSION_UNSUPPORTED` | 备份 | 422 | 当前工具不支持此备份版本：使用兼容工具，不能改版本号伪装兼容 |
| `RESTORE_MAINTENANCE_REQUIRED` | 恢复 | 409 | 恢复需要维护状态：停写、取得排他锁后重试 |
| `EXPORT_PATH_UNSAFE` | 导出 | 400 | 导出位置不安全（越界/路径穿越）：选择受控目录，不关闭路径检查 |
| `REPORT_GENERATION_FAILED` | 报告任务 | — | 报告未能生成：检查任务阶段与资源，保留错误编号 |
| `REPORT_DATA_INCOMPLETE` | 报告警告 | — | 统计数据不完整：阅读缺失时间范围，不能把缺失当零值 |
| `REPORT_ACCESS_DENIED` | 报告 | 403 | 无权读取此报告：核对报告范围与当前权限（撤销后不可再下载） |
| `CONFIG_INVALID` | 配置 | — | 配置未通过检查：按字段名与说明修正；不要打印秘密值 |
| `INTERNAL_ERROR` | 内部故障 | 500 | 服务发生未预期错误：按请求编号查受限日志，提交脱敏诊断 |
| `WEBHOOK_DELIVERY_FAILED` | Webhook 任务 | — | Webhook 未成功投递：查投递状态码与尝试历史，修复端点后受控重试 |
| `WEBHOOK_ENDPOINT_BLOCKED` | 应用 | 403 | Webhook 地址不被允许：登记公网 https 地址，不关闭出站校验 |

## 4. CLI / 工具的错误码（非上述 48 个业务码）

`loginctl`、`login-backup` 的 JSON 错误壳里会出现工具级稳定码，它们用于区分具体失败，
**不**属于业务错误码注册表。遇到时按退出码与消息处理，不要把工具码写进业务协议：

| 工具错误码（示例） | 出现场景 |
|---|---|
| `USAGE_INVALID` / `CONFIG_FIELD_UNKNOWN` / `CONFIG_FIELD_UNSUPPORTED` | 参数或配置字段用法错误 |
| `CONFIG_FILE_INVALID` / `CONFIG_INVALID` | 配置文件读取失败 / 配置校验失败 |
| `CONFIG_DEFAULT_DATABASE_REFUSED` | 未显式指定就操作默认 `database/login.db`（需 `--allow-default-database`） |
| `DATABASE_NOT_INITIALIZED` / `DATABASE_UNSUPPORTED` / `DATABASE_PATH_INVALID` | 数据库不存在/驱动不支持/路径非法（不会自动创建库） |
| `MAINTENANCE_STATE_UNVERIFIED` | 诊断未提供 `--state-dir` 与 `--keyring-file`，维护状态无法验证 |
| `MAIL_DIAGNOSTICS_UNAVAILABLE` / `NOTIFICATION_UNAVAILABLE` / `NOTIFICATION_TEST_DISABLED` | CLI 未装配发件通道；禁止真实外发测试 |
| `MANAGEMENT_WRITE_NOT_EXPOSED` | 在线管理写动作未开放（依赖宿主装配） |
| `EXPORT_PATH_UNSAFE`（工具同码） | 输出目录不安全或不存在 |

## 5. 常见“看起来坏了”的场景

| 现象 | 结论 |
|---|---|
| `login-server serve` 启动即失败、不监听端口 | 按 stderr 的明确原因处理：配置校验失败、数据库未迁移（需 `--migrate=apply`）、维护状态缺失（先 `login-server init` 或受控 `--init-maintenance-state`）、数据库未初始化（先 `init`；仅开发用 `--allow-uninitialized`）、密钥环/TLS 证书问题；见 [deployment-modes.md](deployment-modes.md) 与 `docs/deployment/standalone-service.md` |
| `diag health` 退出码 1（degraded） | 可能只是维护状态未验证或邮件通道未装配；看具体 check，不要据此断定数据库坏了 |
| `diag mail` 报不可用 | CLI 不持有真实发件通道，不会伪成功、不会发信 |
| 浏览器打不开任何页面 | 当前没有独立服务在监听；内置页面需要宿主 Go 装配，见 `docs/embedding/host_integration.md` |
| `loginctl group/role/app ...` 报未知命令 | 先确认子命令拼写与二进制版本（旧构建没有这些命令组）；当前版本已接通这些命令组，用法见 [root-cli.md](root-cli.md) 第 8 节 |
| 统计数字与审计条数不一致 | 统计是聚合快照（去重、窗口、保留期口径不同），审计是原始事件；先对齐口径再判断 |
| 报告 PDF 失败 | 需要宿主提供中文字体；仓库不随包附带字体 |
| 备份 `create` 报参数/路径错误 | 需先准备受保护输出目录与主密钥环文件；主密钥环由首次初始化 `login-server init --master-key-file <受保护路径>` 生成（只打印路径，不打印密钥材料），`login-backup --key-file` 指向同一文件，并与数据库/备份分开保存（见 [backup-and-restore.md](backup-and-restore.md) 第 3、5 节） |
| 配置改了不生效 | 看字段“分类”：`restart-required` 必须重启进程；`hot-reloadable` 也需要宿主触发重新加载（CLI 不会替你重启） |
| 页面/详情显示“完成通知已受理（待投递）” | 通知已入可靠投递队列（`queued`），**不代表已送达**；查 `mail_deliveries` 投递记录与投递任务终态。不要因为 `queued` 重试恢复流程，也不要把它显示成“已发送” |
| 邮件通知一直 queued / 反复重试 | 检查 `mail.enabled`、SMTP/CA/凭据与投递 worker；`mail.delivery.max_attempts`（默认 3）用尽后为失败终态 `MAIL_DELIVERY_FAILED`，已完成的业务变更不回滚（步骤 197） |

## 6. 安全注意事项

- 不要为了排障关闭配置校验、TLS 校验、Host 校验、权限判定或审计；依赖失败应默认拒绝。
- 不要把 `TRACE`/调试日志、完整错误堆栈、数据库路径或真实用户数据返回给公开调用者。
- 导出错误信息给外部支持时，先移除秘密、Token、完整邮箱/电话与内部地址。
- 发现错误码与手册不一致时，以 `error_codes.go` + 手册自动比对测试为准，并报告文档缺陷；
  不要自行修改已发布的码含义。
