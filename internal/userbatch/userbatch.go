// Package userbatch 实现有限规模的用户批量导入导出（步骤 61）：CSV 预检查与正式
// 执行、幂等任务、逐行结果报告、受控取消/续跑，复用 internal/account 的创建/查询
// 白名单与 internal/authz 的数据范围判定。它不是任意数据库迁移/备份工具。
//
// 安全不变量：
//   - 导入只走 account.CreateUser 的资料白名单；表头出现密码/哈希/邮箱验证状态/
//     status/is_root/security_version/角色/权限/MFA/恢复代码/令牌等列时整文件拒绝，
//     不静默忽略。root 账户绝不被创建/修改（既有 root 用户命中也拒绝）。
//   - 幂等键绑定调用者身份 + 作用域 + 请求摘要（文件 SHA-256 + 规范化选项）；
//     同键不同摘要 CONFLICT，同键同摘要复用既有任务，不同调用者不能复用。
//   - 导入采用逐行独立事务的分批策略（非全文件原子）：部分成功是可见的，逐行结果
//     记录稳定错误码；任务成功提交不等于全部行成功。
//   - 导出按字段白名单裁剪、逐用户经注入的数据范围授权器判定（缺失/失败 fail-closed），
//     CSV 单元格防公式注入；错误码复用根包已登记码。
package userbatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TaskKindUserBatchImport/Export 是投递任务的稳定类型标识；宿主把 Handler 注册到
// internal/task 执行器。
const (
	TaskKindUserBatchImport = "user.batch.import"
	TaskKindUserBatchExport = "user.batch.export"
)

// 规模与字段边界（Options 可调，硬上限保护）。
const (
	// DefaultMaxFileBytes/MaxHardFileBytes 是导入文件字节上限。
	DefaultMaxFileBytes = 5 * 1024 * 1024
	MaxHardFileBytes    = 5 * 1024 * 1024
	// DefaultMaxImportRows/MaxHardImportRows 是单次导入行数上限。
	DefaultMaxImportRows = 10000
	MaxHardImportRows    = 50000
	// DefaultMaxExportRows/MaxHardExportRows 是单次导出行数上限。
	DefaultMaxExportRows = 10000
	MaxHardExportRows    = 100000
	// DefaultBatchSize 是每批处理行数（也是权限复验间隔）。
	DefaultBatchSize = 50
	// DefaultMaxRowDetails 是逐行明细保留上限（超出置 truncated）。
	DefaultMaxRowDetails = 5000
	// MaxFieldBytes 是单字段长度上限。
	MaxFieldBytes = 2048
	// MaxHeaders 是导入表头列数上限。
	MaxHeaders = 16
	// MaxListLimit 是任务/明细查询单页上限。
	MaxListLimit = 100
	// 编号前缀。
	jobIDPrefix = "ubj_"
	// 敏感操作 ID（internal/policy 目录）。
	OperationImport = "user.bulk.import"
	OperationExport = "user.bulk.export"
	// 权限键（preset 目录已有，不新增预设目录项）。
	PermissionImport = "users.create"
	PermissionExport = "users.export"
	// 摘要域。
	digestDomain = "user-batch/v1"
)

// Kind 是批量任务类型。
type Kind string

const (
	// KindImport 是用户导入。
	KindImport Kind = "import"
	// KindExport 是用户导出。
	KindExport Kind = "export"
)

// Valid 报告任务类型是否已定义。
func (k Kind) Valid() bool { return k == KindImport || k == KindExport }

// JobState 是任务状态；succeeded 只表示任务执行完成，不表示每行都成功（见汇总计数）。
type JobState string

const (
	JobQueued    JobState = "queued"
	JobRunning   JobState = "running"
	JobSucceeded JobState = "succeeded"
	JobPartial   JobState = "partial"
	JobFailed    JobState = "failed"
	JobCancelled JobState = "cancelled"
)

// Valid 报告任务状态是否已定义。
func (s JobState) Valid() bool {
	switch s {
	case JobQueued, JobRunning, JobSucceeded, JobPartial, JobFailed, JobCancelled:
		return true
	}
	return false
}

// Terminal 报告状态是否终态。
func (s JobState) Terminal() bool {
	return s == JobSucceeded || s == JobPartial || s == JobFailed || s == JobCancelled
}

// RowAction 是逐行导入结果。
type RowAction string

const (
	RowCreated  RowAction = "created"
	RowSkipped  RowAction = "skipped"
	RowConflict RowAction = "conflict"
	RowFailed   RowAction = "failed"
	RowDenied   RowAction = "denied"
)

// failure 报告该行是否属于失败结果（任务 partial 判定）。
func (a RowAction) failure() bool {
	return a == RowConflict || a == RowFailed || a == RowDenied
}

// Action 是本包管理动作。
type Action string

const (
	ActionImport Action = "user.batch.import"
	ActionExport Action = "user.batch.export"
	ActionQuery  Action = "user.batch.query"
	ActionCancel Action = "user.batch.cancel"
	ActionRetry  Action = "user.batch.retry"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionImport, ActionExport, ActionQuery, ActionCancel, ActionRetry:
		return true
	}
	return false
}

// 领域错误；宿主用 CodeOf 映射到根包已登记错误码（不新增注册码）。
var (
	ErrOptionsInvalid   = errors.New("批量导入导出配置无效")
	ErrInvalidRequest   = errors.New("批量导入导出请求无效")
	ErrAccessDenied     = errors.New("未获准执行该批量操作")
	ErrConflict         = errors.New("批量任务状态或幂等键冲突")
	ErrNotFound         = errors.New("批量任务不存在")
	ErrStoreUnavailable = errors.New("批量任务存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	ErrFileInvalid      = errors.New("导入文件无效")
	ErrExportPathUnsafe = errors.New("导出位置不安全")
	ErrJobState         = errors.New("批量任务状态不允许该操作")
)

// ErrorCode 是本领域对根包错误码注册表的投影（全部复用既有 48 码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeExportPathUnsafe   ErrorCode = "EXPORT_PATH_UNSAFE"
	CodeReportGeneration   ErrorCode = "REPORT_GENERATION_FAILED"
	CodeReportIncomplete   ErrorCode = "REPORT_DATA_INCOMPLETE"
	CodeReportAccessDenied ErrorCode = "REPORT_ACCESS_DENIED"
	CodeTaskTimeout        ErrorCode = "TASK_TIMEOUT"
	CodeTaskCancelled      ErrorCode = "TASK_CANCELLED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把本领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrFileInvalid), errors.Is(err, ErrNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrConflict), errors.Is(err, ErrJobState):
		return CodeConflict
	case errors.Is(err, ErrExportPathUnsafe):
		return CodeExportPathUnsafe
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Authorizer 判定调用者能否执行批量管理动作；实现必须 fail-closed。
type Authorizer interface {
	Authorize(ctx context.Context, caller account.Caller, action Action, scopeID string) error
}

// UserScopeAuthorizer 逐用户判定导出数据范围（生产适配 internal/authz 的资源检查）；
// 返回 false 表示不在范围内（跳过并计数），错误表示依赖失败（fail-closed 终止）。
type UserScopeAuthorizer interface {
	AuthorizeUser(ctx context.Context, caller account.Caller, permissionKey, userID string) (bool, error)
}

// SensitiveRunner 是步骤 38/39 敏感操作执行前校验（生产 *reauth.Service）。
type SensitiveRunner = reauth.OperationRunner

// AccountService 是本包使用的账户服务最小契约（生产 *account.Service）。
type AccountService interface {
	CreateUser(ctx context.Context, caller account.Caller, request account.CreateRequest) (account.User, error)
	ListUsers(ctx context.Context, caller account.Caller, request account.ListRequest) (account.ListResult, error)
}

// Enqueuer 是任务入队契约（生产 *task.Executor）。
type Enqueuer interface {
	Enqueue(ctx context.Context, request task.EnqueueRequest) (task.Job, error)
}

// Canceller 是任务取消契约（生产 *task.Executor）。
type Canceller interface {
	RequestCancel(ctx context.Context, request task.CancelRequest) (task.CancelResult, error)
}

// AuditRecorder 是安全审计契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Job 是批量任务视图（不含导入文件内容与导出内容）。
type Job struct {
	ID             string
	Kind           Kind
	State          JobState
	OwnerType      audit.ActorKind
	OwnerID        string
	ScopeID        string
	TotalRows      int
	CreatedCount   int
	SkippedCount   int
	ConflictCount  int
	FailedCount    int
	DeniedCount    int
	Truncated      bool
	ExportPath     string
	ExportSHA256   string
	ExportRows     int
	TaskID         string
	ErrorCode      ErrorCode
	RequestID      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     time.Time
	InputAvailable bool
}

// RowResult 是逐行导入结果（不含原始行内容）。
type RowResult struct {
	RowNumber          int
	Action             RowAction
	ErrorCode          ErrorCode
	ReasonCode         string
	UsernameNormalized string
	UserID             string
}

// ParseError 是预检查错误（不包含用户输入原文，避免日志泄露）。
type ParseError struct {
	Line   int
	Column string
	Code   ErrorCode
	Reason string
}

// ParseReport 是导入文件预检查/解析结果。
type ParseReport struct {
	Headers      []string
	TotalRows    int
	RejectedRows int
	CanImport    bool
	Truncated    bool
	Errors       []ParseError
}

// ImportRequest 是正式导入请求。IdempotencyKey 由宿主/调用方按逻辑文件稳定生成。
type ImportRequest struct {
	Caller         account.Caller
	IdempotencyKey string
	Content        []byte
	RequestID      string
}

// ExportRequest 是导出请求；Fields 只允许从默认白名单中减少，IncludeFreeText 需策略。
type ExportRequest struct {
	Caller          account.Caller
	IdempotencyKey  string
	Fields          []string
	IncludeFreeText bool
	MaxRows         int
	RequestID       string
}

// StartResult 是创建任务结果；Duplicate 表示幂等键命中既有任务（未重复执行）。
type StartResult struct {
	Job       Job
	Duplicate bool
	Report    ParseReport
}

// importRow 是解析后的单行导入资料（严格白名单）；无效行保留行号与稳定原因，
// 正式执行时记为 failed 结果而不是静默丢弃。
type importRow struct {
	RowNumber int
	Valid     bool
	ErrorCode ErrorCode
	Reason    string
	Username  string
	Nickname  string
	Biography string
	Language  string
	Timezone  string
}

// importHeader 是导入表头白名单；顺序无关，大小写不敏感。
var importHeader = map[string]bool{
	"username": true, "nickname": true, "biography": true,
	"language": true, "timezone": true,
}

// forbiddenHeader 是出现即整文件拒绝的列（不静默忽略）。
var forbiddenHeader = map[string]bool{
	"user_id": true, "password": true, "password_hash": true, "email": true,
	"email_verified": true, "phone": true, "phone_verified": true, "status": true,
	"is_root": true, "security_version": true, "roles": true, "permissions": true,
	"groups": true, "mfa": true, "totp": true, "passkey": true,
	"recovery_codes": true, "token": true, "client_secret": true,
	"row_version": true, "created_at": true, "updated_at": true,
}

// exportFields 是导出默认字段白名单；调用方只能减少。
var exportFields = map[string]bool{
	"user_id": true, "username": true, "nickname": true, "language": true,
	"timezone": true, "status": true, "created_at": true, "updated_at": true,
}

// freeTextField 是默认不导出、需显式许可的自由文本字段。
const freeTextField = "biography"

// parseImport 校验编码/表头/行数与字段边界，返回解析行与报告。
//
// 安全：文件级错误（空文件、编码、表头未知/禁止列、超限）返回 ErrFileInvalid；
// 逐行错误记入报告 RejectedRows/Errors（不中断整文件，正式执行时该行标 failed）。
func parseImport(content []byte, maxBytes int64, maxRows int) ([]importRow, ParseReport, error) {
	report := ParseReport{}
	if int64(len(content)) == 0 {
		return nil, report, fmt.Errorf("%w: 文件为空", ErrFileInvalid)
	}
	if int64(len(content)) > maxBytes || maxBytes <= 0 {
		return nil, report, fmt.Errorf("%w: 文件超过 %d 字节", ErrFileInvalid, maxBytes)
	}
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(content) {
		return nil, report, fmt.Errorf("%w: 必须是 UTF-8 编码", ErrFileInvalid)
	}
	// 拒绝 UTF-16/UTF-32 的 BOM 残留与 NUL 控制字符（避免编码歧义）。
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) ||
		bytes.ContainsRune(content, 0) {
		return nil, report, fmt.Errorf("%w: 不支持的编码或空字符", ErrFileInvalid)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = false
	header, err := reader.Read()
	if err != nil {
		return nil, report, fmt.Errorf("%w: 表头读取失败", ErrFileInvalid)
	}
	if len(header) == 0 || len(header) > MaxHeaders {
		return nil, report, fmt.Errorf("%w: 表头列数无效", ErrFileInvalid)
	}
	columns := make([]int, len(header))
	for index, value := range header {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" {
			return nil, report, fmt.Errorf("%w: 表头存在空列", ErrFileInvalid)
		}
		if forbiddenHeader[name] {
			return nil, report, fmt.Errorf("%w: 表头包含禁止列 %q", ErrFileInvalid, name)
		}
		if !importHeader[name] {
			return nil, report, fmt.Errorf("%w: 表头包含未知列 %q", ErrFileInvalid, name)
		}
		for previous := 0; previous < index; previous++ {
			if strings.ToLower(strings.TrimSpace(header[previous])) == name {
				return nil, report, fmt.Errorf("%w: 表头列重复", ErrFileInvalid)
			}
		}
		columns[index] = index
	}
	report.Headers = make([]string, 0, len(header))
	for _, value := range header {
		report.Headers = append(report.Headers, strings.ToLower(strings.TrimSpace(value)))
	}
	rows := make([]importRow, 0, 64)
	line := 1
	for {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		line++
		if readErr != nil {
			report.TotalRows++
			report.RejectedRows++
			if len(report.Errors) < 100 {
				report.Errors = append(report.Errors, ParseError{
					Line: line, Code: CodeReqInvalid, Reason: "csv_syntax"})
			}
			continue
		}
		if len(record) != len(header) {
			report.TotalRows++
			report.RejectedRows++
			if len(report.Errors) < 100 {
				report.Errors = append(report.Errors, ParseError{
					Line: line, Code: CodeReqInvalid, Reason: "column_count"})
			}
			continue
		}
		if report.TotalRows >= maxRows {
			report.Truncated = true
			break
		}
		report.TotalRows++
		row, rowErr := rowFromRecord(header, record)
		row.RowNumber = report.TotalRows
		if rowErr.Reason != "" {
			row.Valid = false
			row.ErrorCode = rowErr.Code
			row.Reason = rowErr.Reason
			report.RejectedRows++
			if len(report.Errors) < 100 {
				rowErr.Line = line
				report.Errors = append(report.Errors, rowErr)
			}
		} else {
			row.Valid = true
		}
		rows = append(rows, row)
	}
	report.CanImport = len(rows) > 0 && report.RejectedRows < len(rows)
	return rows, report, nil
}

// rowFromRecord 把 CSV 记录映射为白名单资料并校验字段边界/控制字符。
func rowFromRecord(header, record []string) (importRow, ParseError) {
	row := importRow{}
	for index, column := range header {
		name := strings.ToLower(strings.TrimSpace(column))
		value := record[index]
		if len(value) > MaxFieldBytes {
			return importRow{}, ParseError{Column: name, Code: CodeReqInvalid, Reason: "field_too_long"}
		}
		if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			return importRow{}, ParseError{Column: name, Code: CodeReqInvalid, Reason: "control_character"}
		}
		switch name {
		case "username":
			row.Username = strings.TrimSpace(value)
		case "nickname":
			row.Nickname = strings.TrimSpace(value)
		case "biography":
			row.Biography = strings.TrimSpace(value)
		case "language":
			row.Language = strings.TrimSpace(value)
		case "timezone":
			row.Timezone = strings.TrimSpace(value)
		}
	}
	if row.Username == "" {
		return importRow{}, ParseError{Column: "username", Code: CodeReqInvalid, Reason: "username_required"}
	}
	return row, ParseError{}
}

// sha256Digest 计算导入文件与规范化选项绑定的请求摘要。
func sha256Digest(parts ...[]byte) [32]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(digestDomain))
	_, _ = hasher.Write([]byte{0})
	for _, part := range parts {
		_, _ = hasher.Write(part)
		_, _ = hasher.Write([]byte{0})
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// escapeCSVCell 防电子表格公式注入：首字符是 = + - @ 或 TAB/CR/LF 时前置单引号。
func escapeCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + value
	}
	return value
}

// escapeReportCell 对报告 CSV 单元格使用同一公式注入防护。
func escapeReportCell(value string) string { return escapeCSVCell(value) }
