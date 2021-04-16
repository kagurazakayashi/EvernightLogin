package login

// 本文件是错误码的代码注册表，必须与 docs/requirements/login_错误码与排障手册.md
// 保持一致。46 个设计码是待实现约定：注册不代表模块已实现，未实现模块不得为了
// “产生记录”而伪造这些错误码。新增错误码必须同时更新本表、手册和未来的 OpenAPI，
// 不能改变已发布码的含义。
//
// 标准 OAuth/OIDC 错误（invalid_grant、authorization_pending、slow_down 等）由
// 未来的协议适配层按协议字段映射，不注册到本表，也不被统一 JSON 强行覆盖。

// ErrorCode 是稳定、可对外返回的错误码字符串，例如 "PERMISSION_REQUIRED"。
// 错误码含义由 ErrorCodeDefinition 和手册共同定义；已发布的码不能复用为其他含义。
type ErrorCode string

// ErrorCategory 是错误码的分类。分类值直白中文映射手册“分类”列，用于统计、
// 筛选与排查，不替代错误码本身。
type ErrorCategory string

const (
	// CategoryParameter 表示请求参数问题。
	CategoryParameter ErrorCategory = "参数"
	// CategoryAuth 表示登录认证问题。
	CategoryAuth ErrorCategory = "认证"
	// CategoryToken 表示访问凭证问题。
	CategoryToken ErrorCategory = "令牌"
	// CategoryApplication 表示调用程序或应用状态问题。
	CategoryApplication ErrorCategory = "应用"
	// CategoryAccount 表示账户状态问题。
	CategoryAccount ErrorCategory = "账户"
	// CategoryPermission 表示权限、成员关系或应用范围问题。
	CategoryPermission ErrorCategory = "权限"
	// CategorySecurityPolicy 表示再次认证或 MFA 策略问题。
	CategorySecurityPolicy ErrorCategory = "安全策略"
	// CategoryRecovery 表示账户恢复或维护状态问题。
	CategoryRecovery ErrorCategory = "恢复"
	// CategoryVerification 表示验证请求问题。
	CategoryVerification ErrorCategory = "验证"
	// CategoryRateLimit 表示请求过于频繁。
	CategoryRateLimit ErrorCategory = "限流"
	// CategorySupportRecovery 表示客服恢复流程问题。
	CategorySupportRecovery ErrorCategory = "客服恢复"
	// CategoryData 表示数据版本或唯一性冲突。
	CategoryData ErrorCategory = "数据"
	// CategoryAuthorizationService 表示权限判定服务不可用。
	CategoryAuthorizationService ErrorCategory = "权限服务"
	// CategoryDatabase 表示数据库不可用。
	CategoryDatabase ErrorCategory = "数据库"
	// CategoryAudit 表示审计写入失败。
	CategoryAudit ErrorCategory = "审计"
	// CategoryMailTask 表示邮件投递任务失败。
	CategoryMailTask ErrorCategory = "邮件任务"
	// CategoryBackupTask 表示备份任务失败。
	CategoryBackupTask ErrorCategory = "备份任务"
	// CategoryBackup 表示备份、取消或备份文件问题。
	CategoryBackup ErrorCategory = "备份"
	// CategoryTask 表示任务状态冲突。
	CategoryTask ErrorCategory = "任务"
	// CategoryTaskResult 表示任务结果（取消、超时），不表示系统故障。
	CategoryTaskResult ErrorCategory = "任务结果"
	// CategoryReportTask 表示报告生成任务失败。
	CategoryReportTask ErrorCategory = "报告任务"
	// CategoryReportWarning 表示报告数据不完整警告。
	CategoryReportWarning ErrorCategory = "报告警告"
	// CategoryReport 表示报告读取权限问题。
	CategoryReport ErrorCategory = "报告"
	// CategoryExport 表示导出路径不安全。
	CategoryExport ErrorCategory = "导出"
	// CategoryConfiguration 表示配置检查失败。
	CategoryConfiguration ErrorCategory = "配置"
	// CategoryInternal 表示未分类内部故障。
	CategoryInternal ErrorCategory = "内部故障"
)

// 错误码常量。字符串值必须与错误码手册完全一致，测试会对照手册核验。
const (
	CodeReqInvalid                 ErrorCode = "REQ_INVALID"
	CodeAuthFailed                 ErrorCode = "AUTH_FAILED"
	CodeTokenInvalid               ErrorCode = "TOKEN_INVALID"
	CodeTokenExpired               ErrorCode = "TOKEN_EXPIRED"
	CodeTokenRevoked               ErrorCode = "TOKEN_REVOKED"
	CodeTokenAudienceMismatch      ErrorCode = "TOKEN_AUDIENCE_MISMATCH"
	CodeClientAuthFailed           ErrorCode = "CLIENT_AUTH_FAILED"
	CodeClientDisabled             ErrorCode = "CLIENT_DISABLED"
	CodeUserDisabled               ErrorCode = "USER_DISABLED"
	CodeAppMembershipRequired      ErrorCode = "APP_MEMBERSHIP_REQUIRED"
	CodePermissionRequired         ErrorCode = "PERMISSION_REQUIRED"
	CodePermissionDisabled         ErrorCode = "PERMISSION_DISABLED"
	CodePermissionUnknown          ErrorCode = "PERMISSION_UNKNOWN"
	CodeAppScopeMismatch           ErrorCode = "APP_SCOPE_MISMATCH"
	CodeResourceForbidden          ErrorCode = "RESOURCE_FORBIDDEN"
	CodeAccessDenied               ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired             ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired                ErrorCode = "MFA_REQUIRED"
	CodeMFARebindRequired          ErrorCode = "MFA_REBIND_REQUIRED"
	CodeChallengeInvalid           ErrorCode = "CHALLENGE_INVALID"
	CodeRefreshReuseDetected       ErrorCode = "REFRESH_REUSE_DETECTED"
	CodeRateLimited                ErrorCode = "RATE_LIMITED"
	CodeSupportIdentityUnverified  ErrorCode = "SUPPORT_IDENTITY_UNVERIFIED"
	CodeSupportTargetProtected     ErrorCode = "SUPPORT_TARGET_PROTECTED"
	CodeRecoveryApprovalRequired   ErrorCode = "RECOVERY_APPROVAL_REQUIRED"
	CodeRecoverySelfApprovalDenied ErrorCode = "RECOVERY_SELF_APPROVAL_DENIED"
	CodeConflict                   ErrorCode = "CONFLICT"
	CodeAuthzUnavailable           ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable              ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed           ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed         ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeBackupFailed               ErrorCode = "BACKUP_FAILED"
	CodeBackupCancelForbidden      ErrorCode = "BACKUP_CANCEL_FORBIDDEN"
	CodeTaskCancelConflict         ErrorCode = "TASK_CANCEL_CONFLICT"
	CodeTaskCancelled              ErrorCode = "TASK_CANCELLED"
	CodeTaskTimeout                ErrorCode = "TASK_TIMEOUT"
	CodeBackupInvalid              ErrorCode = "BACKUP_INVALID"
	CodeBackupDecryptFailed        ErrorCode = "BACKUP_DECRYPT_FAILED"
	CodeBackupVersionUnsupported   ErrorCode = "BACKUP_VERSION_UNSUPPORTED"
	CodeRestoreMaintenanceRequired ErrorCode = "RESTORE_MAINTENANCE_REQUIRED"
	CodeExportPathUnsafe           ErrorCode = "EXPORT_PATH_UNSAFE"
	CodeReportGenerationFailed     ErrorCode = "REPORT_GENERATION_FAILED"
	CodeReportDataIncomplete       ErrorCode = "REPORT_DATA_INCOMPLETE"
	CodeReportAccessDenied         ErrorCode = "REPORT_ACCESS_DENIED"
	CodeConfigInvalid              ErrorCode = "CONFIG_INVALID"
	CodeInternalError              ErrorCode = "INTERNAL_ERROR"
)

// ErrorCodeDefinition 是一个错误码的机器可读定义。DefaultMessage 是手册中的
// 直白说明，也是 AppError 未指定消息时的默认公开消息；HTTPStatus 是手册建议的
// 普通受保护业务接口映射，0 表示手册为“—”（后台任务、CLI 或警告，不指定统一
// HTTP 状态）。
type ErrorCodeDefinition struct {
	Code           ErrorCode
	Category       ErrorCategory
	DefaultMessage string
	HTTPStatus     int
}

// errorCodeDefinitions 的顺序与手册表格一致。修改任何字段都必须同步修改手册，
// 文档覆盖测试会逐项比较。
var errorCodeDefinitions = []ErrorCodeDefinition{
	{CodeReqInvalid, CategoryParameter, "请求内容不符合要求", 400},
	{CodeAuthFailed, CategoryAuth, "无法完成登录", 401},
	{CodeTokenInvalid, CategoryToken, "访问凭证无效", 401},
	{CodeTokenExpired, CategoryToken, "访问凭证已过期", 401},
	{CodeTokenRevoked, CategoryToken, "访问凭证已被撤销", 401},
	{CodeTokenAudienceMismatch, CategoryToken, "访问凭证不能用于当前应用资源", 403},
	{CodeClientAuthFailed, CategoryApplication, "调用程序身份验证失败", 401},
	{CodeClientDisabled, CategoryApplication, "应用已停用", 403},
	{CodeUserDisabled, CategoryAccount, "账户当前不可使用", 403},
	{CodeAppMembershipRequired, CategoryPermission, "用户尚未获准使用此应用", 403},
	{CodePermissionRequired, CategoryPermission, "缺少当前操作所需权限", 403},
	{CodePermissionDisabled, CategoryPermission, "此项权限已停用", 403},
	{CodePermissionUnknown, CategoryPermission, "请求的权限未登记", 400},
	{CodeAppScopeMismatch, CategoryPermission, "请求超出调用应用范围", 403},
	{CodeResourceForbidden, CategoryPermission, "不能操作该记录", 403},
	{CodeAccessDenied, CategoryPermission, "请求未获准", 403},
	{CodeReauthRequired, CategorySecurityPolicy, "需要再次验证身份", 403},
	{CodeMFARequired, CategorySecurityPolicy, "需要完成两步验证", 403},
	{CodeMFARebindRequired, CategoryRecovery, "需要重新绑定两步验证", 403},
	{CodeChallengeInvalid, CategoryVerification, "验证请求无效或已失效", 400},
	{CodeRefreshReuseDetected, CategoryToken, "检测到旧刷新凭证重复使用", 401},
	{CodeRateLimited, CategoryRateLimit, "请求过于频繁", 429},
	{CodeSupportIdentityUnverified, CategorySupportRecovery, "尚未完成身份核验", 403},
	{CodeSupportTargetProtected, CategorySupportRecovery, "客服不能恢复该账户", 403},
	{CodeRecoveryApprovalRequired, CategorySupportRecovery, "还需要独立审批", 403},
	{CodeRecoverySelfApprovalDenied, CategorySupportRecovery, "不能批准自己发起的恢复", 403},
	{CodeConflict, CategoryData, "数据已被其他操作修改", 409},
	{CodeAuthzUnavailable, CategoryAuthorizationService, "暂时无法判定访问权限", 503},
	{CodeDBUnavailable, CategoryDatabase, "数据库暂时不可用", 503},
	{CodeAuditWriteFailed, CategoryAudit, "关键操作未能可靠记录", 503},
	{CodeMailDeliveryFailed, CategoryMailTask, "邮件未成功投递", 0},
	{CodeBackupFailed, CategoryBackupTask, "备份失败", 0},
	{CodeBackupCancelForbidden, CategoryBackup, "无权取消该任务", 403},
	{CodeTaskCancelConflict, CategoryTask, "任务已结束或不能在当前阶段取消", 409},
	{CodeTaskCancelled, CategoryTaskResult, "任务已取消", 0},
	{CodeTaskTimeout, CategoryTaskResult, "任务执行超时", 0},
	{CodeBackupInvalid, CategoryBackup, "备份文件校验未通过", 422},
	{CodeBackupDecryptFailed, CategoryBackup, "无法解密备份", 422},
	{CodeBackupVersionUnsupported, CategoryBackup, "当前工具不支持此备份版本", 422},
	{CodeRestoreMaintenanceRequired, CategoryRecovery, "恢复需要维护状态", 409},
	{CodeExportPathUnsafe, CategoryExport, "导出位置不安全", 400},
	{CodeReportGenerationFailed, CategoryReportTask, "报告未能生成", 0},
	{CodeReportDataIncomplete, CategoryReportWarning, "统计数据不完整", 0},
	{CodeReportAccessDenied, CategoryReport, "无权读取此报告", 403},
	{CodeConfigInvalid, CategoryConfiguration, "配置未通过检查", 0},
	{CodeInternalError, CategoryInternal, "服务发生未预期错误", 500},
}

// errorCodeIndex 是查找索引。注册表构造阶段即校验唯一性，重复码会在包初始化
// 时直接失败，避免测试环境之外被静默覆盖；唯一性另有测试覆盖。
var errorCodeIndex = func() map[ErrorCode]ErrorCodeDefinition {
	index := make(map[ErrorCode]ErrorCodeDefinition, len(errorCodeDefinitions))
	for _, definition := range errorCodeDefinitions {
		if definition.Code == "" {
			panic("login: 错误码注册表包含空错误码")
		}
		if _, exists := index[definition.Code]; exists {
			panic("login: 错误码注册表包含重复错误码 " + string(definition.Code))
		}
		index[definition.Code] = definition
	}
	return index
}()

// LookupErrorCode 查询错误码定义。未注册的码返回 false；调用方不得自行返回
// 未登记错误码。
func LookupErrorCode(code ErrorCode) (ErrorCodeDefinition, bool) {
	definition, ok := errorCodeIndex[code]
	return definition, ok
}

// RegisteredErrorCodes 返回按手册顺序排列的全部错误码定义副本。调用方修改
// 返回值不会影响注册表。
func RegisteredErrorCodes() []ErrorCodeDefinition {
	definitions := make([]ErrorCodeDefinition, len(errorCodeDefinitions))
	copy(definitions, errorCodeDefinitions)
	return definitions
}

// Valid 报告错误码是否已注册。
func (c ErrorCode) Valid() bool {
	_, ok := errorCodeIndex[c]
	return ok
}
