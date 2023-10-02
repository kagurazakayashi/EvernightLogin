package login

// 本文件是步骤 212 公共包迁移的兼容别名桥。
//
// errs 包持有错误码注册表、AppError、请求/任务编号与排障指引的唯一实现；根包
// 保留原有公开符号（type/const 别名与薄函数转发），保证既有消费方与外部示例无需
// 改动即可编译。别名桥不复制错误映射或编号生成逻辑。

import "github.com/kagurazakayashi/EvernightLogin/errs"

type AppError = errs.AppError
type ErrorCategory = errs.ErrorCategory
type ErrorCode = errs.ErrorCode
type ErrorCodeDefinition = errs.ErrorCodeDefinition
type ErrorCodeGuidance = errs.ErrorCodeGuidance
type ErrorOption = errs.ErrorOption

const CategoryAccount = errs.CategoryAccount
const CategoryApplication = errs.CategoryApplication
const CategoryAudit = errs.CategoryAudit
const CategoryAuth = errs.CategoryAuth
const CategoryAuthorizationService = errs.CategoryAuthorizationService
const CategoryBackup = errs.CategoryBackup
const CategoryBackupTask = errs.CategoryBackupTask
const CategoryConfiguration = errs.CategoryConfiguration
const CategoryData = errs.CategoryData
const CategoryDatabase = errs.CategoryDatabase
const CategoryExport = errs.CategoryExport
const CategoryInternal = errs.CategoryInternal
const CategoryMailTask = errs.CategoryMailTask
const CategoryParameter = errs.CategoryParameter
const CategoryPermission = errs.CategoryPermission
const CategoryRateLimit = errs.CategoryRateLimit
const CategoryRecovery = errs.CategoryRecovery
const CategoryReport = errs.CategoryReport
const CategoryReportTask = errs.CategoryReportTask
const CategoryReportWarning = errs.CategoryReportWarning
const CategorySecurityPolicy = errs.CategorySecurityPolicy
const CategorySupportRecovery = errs.CategorySupportRecovery
const CategoryTask = errs.CategoryTask
const CategoryTaskResult = errs.CategoryTaskResult
const CategoryToken = errs.CategoryToken
const CategoryVerification = errs.CategoryVerification
const CategoryWebhookTask = errs.CategoryWebhookTask
const CodeAccessDenied = errs.CodeAccessDenied
const CodeAppMembershipRequired = errs.CodeAppMembershipRequired
const CodeAppScopeMismatch = errs.CodeAppScopeMismatch
const CodeAuditWriteFailed = errs.CodeAuditWriteFailed
const CodeAuthFailed = errs.CodeAuthFailed
const CodeAuthzUnavailable = errs.CodeAuthzUnavailable
const CodeBackupCancelForbidden = errs.CodeBackupCancelForbidden
const CodeBackupDecryptFailed = errs.CodeBackupDecryptFailed
const CodeBackupFailed = errs.CodeBackupFailed
const CodeBackupInvalid = errs.CodeBackupInvalid
const CodeBackupVersionUnsupported = errs.CodeBackupVersionUnsupported
const CodeChallengeInvalid = errs.CodeChallengeInvalid
const CodeClientAuthFailed = errs.CodeClientAuthFailed
const CodeClientDisabled = errs.CodeClientDisabled
const CodeConfigInvalid = errs.CodeConfigInvalid
const CodeConflict = errs.CodeConflict
const CodeDBUnavailable = errs.CodeDBUnavailable
const CodeExportPathUnsafe = errs.CodeExportPathUnsafe
const CodeInternalError = errs.CodeInternalError
const CodeMFARebindRequired = errs.CodeMFARebindRequired
const CodeMFARequired = errs.CodeMFARequired
const CodeMailDeliveryFailed = errs.CodeMailDeliveryFailed
const CodePermissionDisabled = errs.CodePermissionDisabled
const CodePermissionRequired = errs.CodePermissionRequired
const CodePermissionUnknown = errs.CodePermissionUnknown
const CodeRateLimited = errs.CodeRateLimited
const CodeReauthRequired = errs.CodeReauthRequired
const CodeRecoveryApprovalRequired = errs.CodeRecoveryApprovalRequired
const CodeRecoverySelfApprovalDenied = errs.CodeRecoverySelfApprovalDenied
const CodeRefreshReuseDetected = errs.CodeRefreshReuseDetected
const CodeReportAccessDenied = errs.CodeReportAccessDenied
const CodeReportDataIncomplete = errs.CodeReportDataIncomplete
const CodeReportGenerationFailed = errs.CodeReportGenerationFailed
const CodeReqInvalid = errs.CodeReqInvalid
const CodeResourceForbidden = errs.CodeResourceForbidden
const CodeRestoreMaintenanceRequired = errs.CodeRestoreMaintenanceRequired
const CodeSupportIdentityUnverified = errs.CodeSupportIdentityUnverified
const CodeSupportTargetProtected = errs.CodeSupportTargetProtected
const CodeTaskCancelConflict = errs.CodeTaskCancelConflict
const CodeTaskCancelled = errs.CodeTaskCancelled
const CodeTaskTimeout = errs.CodeTaskTimeout
const CodeTokenAudienceMismatch = errs.CodeTokenAudienceMismatch
const CodeTokenExpired = errs.CodeTokenExpired
const CodeTokenInvalid = errs.CodeTokenInvalid
const CodeTokenRevoked = errs.CodeTokenRevoked
const CodeUserDisabled = errs.CodeUserDisabled
const CodeWebhookDeliveryFailed = errs.CodeWebhookDeliveryFailed
const CodeWebhookEndpointBlocked = errs.CodeWebhookEndpointBlocked
const MaxCorrelationIDLength = errs.MaxCorrelationIDLength
const MaxPublicMessageLength = errs.MaxPublicMessageLength

// ===== 函数薄转发（唯一实现位于 errs 包） =====

// NewRequestID 生成可对外返回的请求编号。
func NewRequestID() string { return errs.NewRequestID() }

// ValidateRequestID 校验请求编号格式。
func ValidateRequestID(id string) error { return errs.ValidateRequestID(id) }

// ValidateTaskID 校验任务编号格式（规则与请求编号相同）。
func ValidateTaskID(id string) error { return errs.ValidateTaskID(id) }

// ValidateCorrelationID 校验通用关联标识（扩展名等）。
func ValidateCorrelationID(label, id string) error { return errs.ValidateCorrelationID(label, id) }

// WithCause 设置内部原因（不进入公开输出）。
func WithCause(err error) ErrorOption { return errs.WithCause(err) }

// WithRequestID 设置请求编号（非法编号被忽略）。
func WithRequestID(id string) ErrorOption { return errs.WithRequestID(id) }

// WithTaskID 设置任务编号（非法编号被忽略）。
func WithTaskID(id string) ErrorOption { return errs.WithTaskID(id) }

// WithInternalReasonCode 设置受限内部原因码。
func WithInternalReasonCode(code string) ErrorOption {
	return errs.WithInternalReasonCode(code)
}

// NewAppError 构造统一错误（未注册码回退 INTERNAL_ERROR）。
func NewAppError(code ErrorCode, message string, options ...ErrorOption) *AppError {
	return errs.NewAppError(code, message, options...)
}

// AsAppError 在原因链中查找 *AppError。
func AsAppError(err error) (*AppError, bool) { return errs.AsAppError(err) }

// IsErrorCode 报告原因链中是否存在指定错误码。
func IsErrorCode(err error, code ErrorCode) bool { return errs.IsErrorCode(err, code) }

// ErrorCodeOf 返回原因链中第一个 AppError 的错误码。
func ErrorCodeOf(err error) (ErrorCode, bool) { return errs.ErrorCodeOf(err) }

// FromError 把任意错误转为 *AppError。
func FromError(err error) *AppError { return errs.FromError(err) }

// LookupErrorCode 查询错误码定义。
func LookupErrorCode(code ErrorCode) (ErrorCodeDefinition, bool) {
	return errs.LookupErrorCode(code)
}

// RegisteredErrorCodes 返回按手册顺序排列的全部错误码定义副本。
func RegisteredErrorCodes() []ErrorCodeDefinition { return errs.RegisteredErrorCodes() }

// LookupErrorCodeGuidance 查询错误码排障指引。
func LookupErrorCodeGuidance(code ErrorCode) (ErrorCodeGuidance, bool) {
	return errs.LookupErrorCodeGuidance(code)
}

// validateCorrelationID 是根包内部既有调用口径的薄转发（单一实现）。
func validateCorrelationID(label, id string) error { return errs.ValidateCorrelationID(label, id) }
