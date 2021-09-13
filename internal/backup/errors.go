package backup

import (
	"errors"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// 领域错误哨兵。它们只表达失败类别，不包含明文、数据库内容、密钥材料或宿主
// 绝对路径；公开响应与审计只能使用 CodeOf 映射后的稳定错误码。
var (
	// ErrOptionsInvalid 表示服务/请求依赖配置非法或缺失（fail-closed）。
	ErrOptionsInvalid = errors.New("备份服务配置无效")
	// ErrInvalidRequest 表示请求参数或备份文件头结构不合法。
	ErrInvalidRequest = errors.New("备份请求或文件结构无效")
	// ErrAccessDenied 表示调用者没有执行该备份操作的功能权限或系统范围。
	ErrAccessDenied = errors.New("未获准执行该备份操作")
	// ErrCancelForbidden 表示调用者无权取消该备份任务。
	ErrCancelForbidden = errors.New("无权取消该备份任务")
	// ErrCancelConflict 表示备份任务已结束或已经请求过取消。
	ErrCancelConflict = errors.New("备份任务已结束或无法取消")
	// ErrCancelled 表示已接受的取消请求导致备份真实终止。
	ErrCancelled = errors.New("备份已取消")
	// ErrTimeout 表示备份超过墙钟上限被终止（与人工取消分开）。
	ErrTimeout = errors.New("备份执行超时")
	// ErrAuditUnavailable 表示关键审计不可用，操作按 fail-closed 拒绝或回滚。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	// ErrOutputDirUnsafe 表示输出目录不安全（不存在、符号链接、权限过宽）。
	ErrOutputDirUnsafe = errors.New("备份输出目录不安全")
	// ErrFormatInvalid 表示备份文件魔数/版本/头部不合法。
	ErrFormatInvalid = errors.New("备份文件格式无效")
	// ErrVersionUnsupported 表示备份格式版本或数据库版本不受当前工具支持。
	ErrVersionUnsupported = errors.New("当前工具不支持此备份版本")
	// ErrDecryptFailed 表示认证解密失败：错误密钥、头部或密文被篡改统一归入
	// 该类别，不向调用方细分可利用的差异。
	ErrDecryptFailed = errors.New("无法解密备份或认证失败")
	// ErrIntegrityFailed 表示解密成功但清单/摘要/长度校验不通过（损坏或篡改）。
	ErrIntegrityFailed = errors.New("备份完整性校验未通过")
	// ErrTooLarge 表示备份超过配置的容量上限（防止无界写入占满磁盘）。
	ErrTooLarge = errors.New("备份超过允许的大小上限")
	// ErrAttachmentInconsistent 表示数据库快照引用的附件缺失、大小或摘要不符，
	// 或在前一阶段与写入阶段之间被替换。属于可重试的并发不一致，不产出备份。
	ErrAttachmentInconsistent = errors.New("备份附件与数据库快照不一致")
	// ErrSnapshotFailed 表示一致性数据库快照失败。
	ErrSnapshotFailed = errors.New("数据库一致性快照失败")
	// ErrCleanupFailed 表示失败/成功后的临时文件清理未完成，必须如实报告。
	ErrCleanupFailed = errors.New("备份临时文件清理未完成")
	// ErrBackupIO 表示备份数据读写失败（磁盘空间、权限、I/O 错误）；映射为
	// BACKUP_FAILED，而不是伪装成文件校验失败。
	ErrBackupIO = errors.New("备份数据读写失败")
	// ErrStoreUnavailable 表示审计或备份输出存储暂时不可用。
	ErrStoreUnavailable = errors.New("备份存储暂时不可用")
	// ErrInternal 表示未分类内部错误（只用于映射，不外泄细节）。
	ErrInternal = errors.New("备份内部错误")
)

// ErrorCode 是本领域对根包错误码注册表的投影。以下错误码全部已在根包
// error_codes.go 登记，本步骤不新增错误码；新增码必须同步错误码手册与数量断言。
type ErrorCode string

// 错误码常量；与根包已登记码逐字一致。
const (
	CodeReqInvalid               ErrorCode = "REQ_INVALID"
	CodeAccessDenied             ErrorCode = "ACCESS_DENIED"
	CodeConflict                 ErrorCode = "CONFLICT"
	CodeTaskCancelConflict       ErrorCode = "TASK_CANCEL_CONFLICT"
	CodeBackupFailed             ErrorCode = "BACKUP_FAILED"
	CodeBackupCancelForbidden    ErrorCode = "BACKUP_CANCEL_FORBIDDEN"
	CodeBackupInvalid            ErrorCode = "BACKUP_INVALID"
	CodeBackupDecryptFailed      ErrorCode = "BACKUP_DECRYPT_FAILED"
	CodeBackupVersionUnsupported ErrorCode = "BACKUP_VERSION_UNSUPPORTED"
	CodeAuditWriteFailed         ErrorCode = "AUDIT_WRITE_FAILED"
	CodeDBUnavailable            ErrorCode = "DB_UNAVAILABLE"
	CodeExportPathUnsafe         ErrorCode = "EXPORT_PATH_UNSAFE"
	CodeTaskCancelled            ErrorCode = "TASK_CANCELLED"
	CodeTaskTimeout              ErrorCode = "TASK_TIMEOUT"
	CodeInternalError            ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把备份域错误映射为根包已登记错误码。内部包装链保留 errors.Is 语义；
// 无法识别的错误按 INTERNAL_ERROR 处理，不把细节交给调用方。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrCancelForbidden):
		return CodeBackupCancelForbidden
	case errors.Is(err, ErrCancelConflict):
		return CodeTaskCancelConflict
	case errors.Is(err, ErrCancelled):
		return CodeTaskCancelled
	case errors.Is(err, ErrTimeout):
		return CodeTaskTimeout
	case errors.Is(err, ErrDecryptFailed):
		return CodeBackupDecryptFailed
	case errors.Is(err, ErrVersionUnsupported):
		return CodeBackupVersionUnsupported
	case errors.Is(err, ErrFormatInvalid), errors.Is(err, ErrIntegrityFailed):
		return CodeBackupInvalid
	case errors.Is(err, ErrOutputDirUnsafe):
		return CodeExportPathUnsafe
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrSnapshotFailed),
		errors.Is(err, ErrStoreUnavailable):
		if errors.Is(err, storage.ErrBusy) || errors.Is(err, storage.ErrUnavailable) ||
			errors.Is(err, storage.ErrDiskFull) {
			return CodeDBUnavailable
		}
		return CodeBackupFailed
	case errors.Is(err, ErrAttachmentInconsistent),
		errors.Is(err, ErrTooLarge),
		errors.Is(err, ErrCleanupFailed),
		errors.Is(err, ErrBackupIO):
		return CodeBackupFailed
	case errors.Is(err, storage.ErrDiskFull):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// retryable 报告失败是否属于可重试的并发/瞬时不一致。审计不可用、权限、取消、
// 超时、参数错误和磁盘容量错误一律不重试；附件在快照后变化与 SQLite BUSY 属于
// 可重试的瞬时状态。
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAttachmentInconsistent) {
		return true
	}
	if errors.Is(err, storage.ErrBusy) {
		return true
	}
	return false
}
