package login

// 本文件是错误码公开说明补充（可能原因、处理建议、重试条件），与
// docs/requirements/login_错误码与排障手册.md 第 3 节同一事实源；不另建第二份
// 手工副本。新增或修改错误码说明时必须同时更新手册与本节，测试逐项比较。

// ErrorCodeGuidance 是一个已登记错误码的公开说明补充。这些文本面向有权调用者，
// 不包含内部堆栈、SQL、文件路径或秘密；未知错误码不猜测原因。
type ErrorCodeGuidance struct {
	// Cause 是可能原因（公开粒度，不表示已确认其中某一项）。
	Cause string
	// Advice 是管理员或用户可以做什么。
	Advice string
	// Retry 是重试规则（修正后、授权后、等待后、不得原路重试等）。
	Retry string
}

// errorCodeGuidance 按错误码常量索引公开说明，顺序与手册一致。
var errorCodeGuidance = map[ErrorCode]ErrorCodeGuidance{
	CodeReqInvalid:                 {Cause: "字段缺失或格式不对", Advice: "按字段提示对照接口文档修正", Retry: "修正后"},
	CodeAuthFailed:                 {Cause: "用户名或凭证不正确；对外不细分账户是否存在", Advice: "本人核对输入；管理员用请求编号查受限记录", Retry: "限速内"},
	CodeTokenInvalid:               {Cause: "签名、格式、签发方或类型不符合要求", Advice: "检查取得的是 Access Token，核对签发配置；不要跳过签名验证", Retry: "重新登录"},
	CodeTokenExpired:               {Cause: "超过有效期或时钟异常", Advice: "按允许流程刷新或重新登录，检查服务器时间", Retry: "刷新后"},
	CodeTokenRevoked:               {Cause: "退出、密码恢复或管理员撤销", Advice: "重新登录；查撤销事件，勿恢复旧令牌", Retry: "重新登录"},
	CodeTokenAudienceMismatch:      {Cause: "令牌接收方与业务接口不一致", Advice: "检查应用登记和取得令牌时的目标资源", Retry: "修正后"},
	CodeClientAuthFailed:           {Cause: "程序密钥错误、失效或配置不符", Advice: "核对密钥版本和认证方式，不在日志打印密钥", Retry: "修正后"},
	CodeClientDisabled:             {Cause: "管理员停用应用", Advice: "查应用状态及停用原因，由授权管理员处理", Retry: "启用后"},
	CodeUserDisabled:               {Cause: "账户已禁用", Advice: "授权管理员检查禁用记录；不对匿名请求暴露该细节", Retry: "处理后"},
	CodeAppMembershipRequired:      {Cause: "未加入或成员关系已停用", Advice: "检查该应用成员状态", Retry: "授权后"},
	CodePermissionRequired:         {Cause: "角色未包含或已撤销权限", Advice: "检查当前应用、角色来源与 all/any 要求", Retry: "授权后"},
	CodePermissionDisabled:         {Cause: "系统或应用权限处于停用状态", Advice: "查权限状态和停用审计", Retry: "启用后"},
	CodePermissionUnknown:          {Cause: "代码拼写错误或未部署权限定义", Advice: "核对该应用权限标识；不要自动创建并授权", Retry: "修正后"},
	CodeAppScopeMismatch:           {Cause: "试图检查或管理其他应用的数据", Advice: "核对可信调用身份及应用范围", Retry: "修正后"},
	CodeResourceForbidden:          {Cause: "资源不属于获准范围", Advice: "由业务服务核对记录归属，不仅检查功能权限", Retry: "授权后"},
	CodeAccessDenied:               {Cause: "精确原因不可向当前调用者公开", Advice: "管理员使用请求编号查询受限审计", Retry: "查明后"},
	CodeReauthRequired:             {Cause: "认证时间太久或操作风险较高", Advice: "完成指定的再次验证流程", Retry: "验证后"},
	CodeMFARequired:                {Cause: "当前登录强度不足", Advice: "完成允许的验证方式", Retry: "验证后"},
	CodeMFARebindRequired:          {Cause: "使用了恢复代码，当前只有受限会话", Advice: "完成新因素绑定；不得发放完整业务访问凭证", Retry: "绑定后"},
	CodeChallengeInvalid:           {Cause: "超时、用途不符或已使用，对外可合并提示", Advice: "重新发起本人需要的验证流程", Retry: "重新发起"},
	CodeRefreshReuseDetected:       {Cause: "泄露或客户端并发刷新", Advice: "撤销关联令牌组并重新登录；检查客户端并发控制", Retry: "不得复用旧凭证"},
	CodeRateLimited:                {Cause: "超过用户、应用或地址限制", Advice: "按 retry_after_seconds 等待，不循环高速请求", Retry: "等待后"},
	CodeSupportIdentityUnverified:  {Cause: "只有电话口述资料或核验不足", Advice: "采用预先批准的可靠方式；不能仅凭主管同意跳过核验", Retry: "核验后"},
	CodeSupportTargetProtected:     {Cause: "目标为 root 或高权限管理账户", Advice: "转交指定管理或本地应急流程", Retry: "不能原路重试"},
	CodeRecoveryApprovalRequired:   {Cause: "受控人工恢复未批准", Advice: "由具备权限且未发起该申请的人核验审批", Retry: "批准后"},
	CodeRecoverySelfApprovalDenied: {Cause: "发起人与审批人相同", Advice: "改由独立获授权工作人员处理", Retry: "换审批人后"},
	CodeConflict:                   {Cause: "版本冲突或唯一值重复", Advice: "重新读取再决定修改，不覆盖他人更新", Retry: "确认后"},
	CodeAuthzUnavailable:           {Cause: "权限存储或策略服务不可用", Advice: "检查数据库和服务健康；业务端保持拒绝访问", Retry: "退避重试"},
	CodeDBUnavailable:              {Cause: "连接、锁、磁盘或服务异常", Advice: "核对连接、空间、锁及受限日志", Retry: "排障后"},
	CodeAuditWriteFailed:           {Cause: "审计存储不可用", Advice: "修复存储；关键管理变更应未提交，核实状态后再试", Retry: "核实后"},
	CodeMailDeliveryFailed:         {Cause: "邮箱、邮件服务或网络异常", Advice: "检查受限投递记录；已完成的安全变更不因此回滚", Retry: "有界重试"},
	CodeBackupFailed:               {Cause: "空间、读取、加密或文件写入失败", Advice: "用任务编号查看安全错误详情及临时文件清理结果", Retry: "排障后"},
	CodeBackupCancelForbidden:      {Cause: "缺少取消权限或超出任务范围", Advice: "确认任务范围与申请取消者的当前权限", Retry: "授权后"},
	CodeTaskCancelConflict:         {Cause: "取消与完成竞争或阶段不可中断", Advice: "读取真实状态；不得把取消已请求显示为已取消", Retry: "不盲目重试"},
	CodeTaskCancelled:              {Cause: "人工或系统取消", Advice: "查看取消执行人、来源、原因和时间；这是终态而非系统故障", Retry: "按需新建"},
	CodeTaskTimeout:                {Cause: "超过墙钟时间限制", Advice: "查看执行阶段、负载和残留清理，不直接无限延长", Retry: "排障后"},
	CodeBackupInvalid:              {Cause: "文件损坏或格式不符", Advice: "保留原文件，核对校验和及来源；不要强制恢复", Retry: "更换文件"},
	CodeBackupDecryptFailed:        {Cause: "解密材料错误或文件被修改", Advice: "安全核对密钥和完整性；不打印密钥", Retry: "修正后"},
	CodeBackupVersionUnsupported:   {Cause: "版本或数据库格式不支持", Advice: "使用兼容工具，不能直接修改版本号伪装兼容", Retry: "升级后"},
	CodeRestoreMaintenanceRequired: {Cause: "服务仍在写数据或未取得排他锁", Advice: "按手册停止写入、取得锁后重试", Retry: "维护后"},
	CodeExportPathUnsafe:           {Cause: "越出目标目录或存在路径穿越", Advice: "选择受控目录，不关闭路径检查", Retry: "修正后"},
	CodeReportGenerationFailed:     {Cause: "数据读取或渲染失败", Advice: "检查任务阶段和运行资源，保留错误编号", Retry: "排障后"},
	CodeReportDataIncomplete:       {Cause: "保留期不足或采样缺失", Advice: "阅读缺失时间范围，不能将缺失当零值", Retry: "不是失败"},
	CodeReportAccessDenied:         {Cause: "当前权限不足或已撤销", Advice: "核对报告范围和当前权限", Retry: "授权后"},
	CodeConfigInvalid:              {Cause: "字段无效或安全规则冲突", Advice: "查看配置项名称和说明，避免打印秘密值", Retry: "修正后"},
	CodeInternalError:              {Cause: "未分类程序异常", Advice: "用请求编号查询受限日志并提交脱敏诊断", Retry: "先核实状态"},
	CodeWebhookDeliveryFailed:      {Cause: "端点不可达、超时、拒绝或重试耗尽", Advice: "查看投递记录的状态码与尝试历史；修复端点后受控重试，不把它当作撤销失败", Retry: "修复后"},
	CodeWebhookEndpointBlocked:     {Cause: "指向回环/内网/保留地址、非 https 或危险重定向", Advice: "登记公网 https 地址；不要关闭出站地址校验", Retry: "修正后"},
}

// LookupErrorCodeGuidance 返回已登记错误码的公开说明补充。
func LookupErrorCodeGuidance(code ErrorCode) (ErrorCodeGuidance, bool) {
	guidance, ok := errorCodeGuidance[code]
	return guidance, ok
}
