# 公开错误码参考（48 个注册码）

> 由 `errs.RegisteredErrorCodes()` + `errs.LookupErrorCodeGuidance()` 生成；任务导向排障见 [../guide/troubleshooting.md](../guide/troubleshooting.md)，历史错误码手册见 [../requirements/login_错误码与排障手册.md](../requirements/login_错误码与排障手册.md)。

错误码是**协议/业务拒绝**的稳定机器标识；公开响应同时带 `request_id`，用于把用户报错与管理端审计/日志关联。错误文本是公开脱敏文本，不包含内部堆栈、SQL、文件路径或秘密。

## 1. 注册错误码表

| 错误码 | HTTP | 分类 | 公开含义 | 可能原因 | 处理建议 | 重试 |
|---|---|---|---|---|---|---|
| `REQ_INVALID` | 400 | 参数 | 请求内容不符合要求 | 字段缺失或格式不对 | 按字段提示对照接口文档修正 | 修正后 |
| `AUTH_FAILED` | 401 | 认证 | 无法完成登录 | 用户名或凭证不正确；对外不细分账户是否存在 | 本人核对输入；管理员用请求编号查受限记录 | 限速内 |
| `TOKEN_INVALID` | 401 | 令牌 | 访问凭证无效 | 签名、格式、签发方或类型不符合要求 | 检查取得的是 Access Token，核对签发配置；不要跳过签名验证 | 重新登录 |
| `TOKEN_EXPIRED` | 401 | 令牌 | 访问凭证已过期 | 超过有效期或时钟异常 | 按允许流程刷新或重新登录，检查服务器时间 | 刷新后 |
| `TOKEN_REVOKED` | 401 | 令牌 | 访问凭证已被撤销 | 退出、密码恢复或管理员撤销 | 重新登录；查撤销事件，勿恢复旧令牌 | 重新登录 |
| `TOKEN_AUDIENCE_MISMATCH` | 403 | 令牌 | 访问凭证不能用于当前应用资源 | 令牌接收方与业务接口不一致 | 检查应用登记和取得令牌时的目标资源 | 修正后 |
| `CLIENT_AUTH_FAILED` | 401 | 应用 | 调用程序身份验证失败 | 程序密钥错误、失效或配置不符 | 核对密钥版本和认证方式，不在日志打印密钥 | 修正后 |
| `CLIENT_DISABLED` | 403 | 应用 | 应用已停用 | 管理员停用应用 | 查应用状态及停用原因，由授权管理员处理 | 启用后 |
| `USER_DISABLED` | 403 | 账户 | 账户当前不可使用 | 账户已禁用 | 授权管理员检查禁用记录；不对匿名请求暴露该细节 | 处理后 |
| `APP_MEMBERSHIP_REQUIRED` | 403 | 权限 | 用户尚未获准使用此应用 | 未加入或成员关系已停用 | 检查该应用成员状态 | 授权后 |
| `PERMISSION_REQUIRED` | 403 | 权限 | 缺少当前操作所需权限 | 角色未包含或已撤销权限 | 检查当前应用、角色来源与 all/any 要求 | 授权后 |
| `PERMISSION_DISABLED` | 403 | 权限 | 此项权限已停用 | 系统或应用权限处于停用状态 | 查权限状态和停用审计 | 启用后 |
| `PERMISSION_UNKNOWN` | 400 | 权限 | 请求的权限未登记 | 代码拼写错误或未部署权限定义 | 核对该应用权限标识；不要自动创建并授权 | 修正后 |
| `APP_SCOPE_MISMATCH` | 403 | 权限 | 请求超出调用应用范围 | 试图检查或管理其他应用的数据 | 核对可信调用身份及应用范围 | 修正后 |
| `RESOURCE_FORBIDDEN` | 403 | 权限 | 不能操作该记录 | 资源不属于获准范围 | 由业务服务核对记录归属，不仅检查功能权限 | 授权后 |
| `ACCESS_DENIED` | 403 | 权限 | 请求未获准 | 精确原因不可向当前调用者公开 | 管理员使用请求编号查询受限审计 | 查明后 |
| `REAUTH_REQUIRED` | 403 | 安全策略 | 需要再次验证身份 | 认证时间太久或操作风险较高 | 完成指定的再次验证流程 | 验证后 |
| `MFA_REQUIRED` | 403 | 安全策略 | 需要完成两步验证 | 当前登录强度不足 | 完成允许的验证方式 | 验证后 |
| `MFA_REBIND_REQUIRED` | 403 | 恢复 | 需要重新绑定两步验证 | 使用了恢复代码，当前只有受限会话 | 完成新因素绑定；不得发放完整业务访问凭证 | 绑定后 |
| `CHALLENGE_INVALID` | 400 | 验证 | 验证请求无效或已失效 | 超时、用途不符或已使用，对外可合并提示 | 重新发起本人需要的验证流程 | 重新发起 |
| `REFRESH_REUSE_DETECTED` | 401 | 令牌 | 检测到旧刷新凭证重复使用 | 泄露或客户端并发刷新 | 撤销关联令牌组并重新登录；检查客户端并发控制 | 不得复用旧凭证 |
| `RATE_LIMITED` | 429 | 限流 | 请求过于频繁 | 超过用户、应用或地址限制 | 按 retry_after_seconds 等待，不循环高速请求 | 等待后 |
| `SUPPORT_IDENTITY_UNVERIFIED` | 403 | 客服恢复 | 尚未完成身份核验 | 只有电话口述资料或核验不足 | 采用预先批准的可靠方式；不能仅凭主管同意跳过核验 | 核验后 |
| `SUPPORT_TARGET_PROTECTED` | 403 | 客服恢复 | 客服不能恢复该账户 | 目标为 root 或高权限管理账户 | 转交指定管理或本地应急流程 | 不能原路重试 |
| `RECOVERY_APPROVAL_REQUIRED` | 403 | 客服恢复 | 还需要独立审批 | 受控人工恢复未批准 | 由具备权限且未发起该申请的人核验审批 | 批准后 |
| `RECOVERY_SELF_APPROVAL_DENIED` | 403 | 客服恢复 | 不能批准自己发起的恢复 | 发起人与审批人相同 | 改由独立获授权工作人员处理 | 换审批人后 |
| `CONFLICT` | 409 | 数据 | 数据已被其他操作修改 | 版本冲突或唯一值重复 | 重新读取再决定修改，不覆盖他人更新 | 确认后 |
| `AUTHZ_UNAVAILABLE` | 503 | 权限服务 | 暂时无法判定访问权限 | 权限存储或策略服务不可用 | 检查数据库和服务健康；业务端保持拒绝访问 | 退避重试 |
| `DB_UNAVAILABLE` | 503 | 数据库 | 数据库暂时不可用 | 连接、锁、磁盘或服务异常 | 核对连接、空间、锁及受限日志 | 排障后 |
| `AUDIT_WRITE_FAILED` | 503 | 审计 | 关键操作未能可靠记录 | 审计存储不可用 | 修复存储；关键管理变更应未提交，核实状态后再试 | 核实后 |
| `MAIL_DELIVERY_FAILED` | 0 | 邮件任务 | 邮件未成功投递 | 邮箱、邮件服务或网络异常 | 检查受限投递记录；已完成的安全变更不因此回滚 | 有界重试 |
| `BACKUP_FAILED` | 0 | 备份任务 | 备份失败 | 空间、读取、加密或文件写入失败 | 用任务编号查看安全错误详情及临时文件清理结果 | 排障后 |
| `BACKUP_CANCEL_FORBIDDEN` | 403 | 备份 | 无权取消该任务 | 缺少取消权限或超出任务范围 | 确认任务范围与申请取消者的当前权限 | 授权后 |
| `TASK_CANCEL_CONFLICT` | 409 | 任务 | 任务已结束或不能在当前阶段取消 | 取消与完成竞争或阶段不可中断 | 读取真实状态；不得把取消已请求显示为已取消 | 不盲目重试 |
| `TASK_CANCELLED` | 0 | 任务结果 | 任务已取消 | 人工或系统取消 | 查看取消执行人、来源、原因和时间；这是终态而非系统故障 | 按需新建 |
| `TASK_TIMEOUT` | 0 | 任务结果 | 任务执行超时 | 超过墙钟时间限制 | 查看执行阶段、负载和残留清理，不直接无限延长 | 排障后 |
| `BACKUP_INVALID` | 422 | 备份 | 备份文件校验未通过 | 文件损坏或格式不符 | 保留原文件，核对校验和及来源；不要强制恢复 | 更换文件 |
| `BACKUP_DECRYPT_FAILED` | 422 | 备份 | 无法解密备份 | 解密材料错误或文件被修改 | 安全核对密钥和完整性；不打印密钥 | 修正后 |
| `BACKUP_VERSION_UNSUPPORTED` | 422 | 备份 | 当前工具不支持此备份版本 | 版本或数据库格式不支持 | 使用兼容工具，不能直接修改版本号伪装兼容 | 升级后 |
| `RESTORE_MAINTENANCE_REQUIRED` | 409 | 恢复 | 恢复需要维护状态 | 服务仍在写数据或未取得排他锁 | 按手册停止写入、取得锁后重试 | 维护后 |
| `EXPORT_PATH_UNSAFE` | 400 | 导出 | 导出位置不安全 | 越出目标目录或存在路径穿越 | 选择受控目录，不关闭路径检查 | 修正后 |
| `REPORT_GENERATION_FAILED` | 0 | 报告任务 | 报告未能生成 | 数据读取或渲染失败 | 检查任务阶段和运行资源，保留错误编号 | 排障后 |
| `REPORT_DATA_INCOMPLETE` | 0 | 报告警告 | 统计数据不完整 | 保留期不足或采样缺失 | 阅读缺失时间范围，不能将缺失当零值 | 不是失败 |
| `REPORT_ACCESS_DENIED` | 403 | 报告 | 无权读取此报告 | 当前权限不足或已撤销 | 核对报告范围和当前权限 | 授权后 |
| `CONFIG_INVALID` | 0 | 配置 | 配置未通过检查 | 字段无效或安全规则冲突 | 查看配置项名称和说明，避免打印秘密值 | 修正后 |
| `INTERNAL_ERROR` | 500 | 内部故障 | 服务发生未预期错误 | 未分类程序异常 | 用请求编号查询受限日志并提交脱敏诊断 | 先核实状态 |
| `WEBHOOK_DELIVERY_FAILED` | 0 | Webhook 任务 | Webhook 未成功投递 | 端点不可达、超时、拒绝或重试耗尽 | 查看投递记录的状态码与尝试历史；修复端点后受控重试，不把它当作撤销失败 | 修复后 |
| `WEBHOOK_ENDPOINT_BLOCKED` | 403 | 应用 | Webhook 地址不被允许 | 指向回环/内网/保留地址、非 https 或危险重定向 | 登记公网 https 地址；不要关闭出站地址校验 | 修正后 |

## 2. 错误响应与调用边界

- HTTP/协议/Go 门面共用同一套错误码与 `request_id` 关联；错误响应信封与 CSRF/会话约定见 [http-api.md](http-api.md)。
- **防枚举**：登录、注册、找回等公开入口不区分“账户不存在/凭证错误/已禁用”等内部原因；不要依据错误差异探测账户状态。
- **找回令牌预检查统一失败语义（步骤 204）**：`PasswordReset().ValidateToken` / `ValidateTokenWithSource` 是非消费预检查，领域判断的所有失败统一为 `CHALLENGE_INVALID`；调用前校验保持各自稳定码（非法请求编号/来源 → `REQ_INVALID`，限流 → `RATE_LIMITED`，服务未装配 → `CONFIG_INVALID`）。最终 `Complete` 会重新验证完整状态。
- **已授权查询的“未找到”是 app 级公开契约（步骤 207）**：`app.NotFoundCode`、`app.ErrNotFound`、`app.NotFoundError`、`app.IsNotFound(err)`；权限检查先于查询，未授权不会因“未找到”泄露存在性；该码**不加入**根包 48 码注册表，HTTP 层建议映射 404。
- **fail-closed**：认证/授权/审计依赖失败时默认拒绝，不用重试绕过；`AUTHZ_UNAVAILABLE`、`DB_UNAVAILABLE`、`AUDIT_WRITE_FAILED` 表示依赖故障而不是操作结果。
- 日志/审计/支持工单只记录错误码与 `request_id`，不记录完整 Token、密码、恢复码或找回链接。

## 3. 最小可编译示例

```go
// ExampleLookupError 展示如何从公开错误码注册表查询错误码的公开含义与重试建议。
// 根包同时提供 login.LookupErrorCode / login.LookupErrorCodeGuidance 别名。
func ExampleLookupError() {
	definition, ok := errs.LookupErrorCode(errs.CodeRateLimited)
	if !ok {
		return
	}
	guidance, _ := errs.LookupErrorCodeGuidance(errs.CodeRateLimited)
	_ = definition.HTTPStatus
	_ = definition.DefaultMessage
	_ = guidance.Cause
	_ = guidance.Advice
	_ = guidance.Retry
}
```

## 4. 机器可读

- [error-codes.json](error-codes.json)：码/分类/HTTP/公开含义/原因/建议/重试的完整机器表。
- 生成源：`errs.RegisteredErrorCodes()`（顺序与手册一致）与 `errs.LookupErrorCodeGuidance()`。
