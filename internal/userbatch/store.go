package userbatch

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// JobRecord 是持久化任务记录（含输入摘要与导入文件 BLOB，不对外暴露内容）。
type JobRecord struct {
	Job
	IdempotencyKey string
	RequestDigest  [32]byte
	// InputCSV 只在导入任务 queued/running 时暂存，终态后由服务清空。
	InputCSV []byte
}

// RowRecord 是逐行导入结果持久化记录。
type RowRecord struct {
	JobID              string
	RowNumber          int
	Action             RowAction
	ErrorCode          string
	ReasonCode         string
	UsernameNormalized string
	UserID             string
	CreatedAt          time.Time
}

// ExistingUser 是导入重复匹配所需的既有账户快照（含内部 root 标记）。
type ExistingUser struct {
	User   account.User
	IsRoot bool
}

// ListJobsQuery 是任务查询条件；OwnerType/OwnerID 用于数据范围过滤。
type ListJobsQuery struct {
	Kind      Kind
	State     JobState
	OwnerType audit.ActorKind
	OwnerID   string
	Limit     int
	// Offset 是受控深分页偏移（步骤 218）：由服务层校验上限后写入 SQL，
	// 与 Limit 一起在数据源处分页，不先读全量再内存裁剪。
	Offset int
}

// FinishJobCommand 是任务终态写入参数；Counts 为最终汇总计数。
type FinishJobCommand struct {
	JobID        string
	State        JobState
	TotalRows    int
	CreatedRows  int
	SkippedRows  int
	ConflictRows int
	FailedRows   int
	DeniedRows   int
	Truncated    bool
	ExportPath   string
	ExportSHA256 []byte
	ExportRows   int
	ErrorCode    ErrorCode
	Now          time.Time
}

// Store 是批量任务持久化契约，由 internal/userbatch/sqlite 提供 SQLite 实现。
// CreateJob 遇到幂等键唯一冲突时返回既有记录与 created=false（调用方比较
// owner/digest 后决定复用或 CONFLICT）；逐行插入遇到 (job_id,row_number) 重复时
// 视为续跑已处理行，忽略并返回 inserted=false。
type Store interface {
	CreateJob(ctx context.Context, job JobRecord, digest [32]byte, input []byte,
	) (JobRecord, bool, error)
	GetJob(ctx context.Context, jobID string) (JobRecord, bool, error)
	ListJobs(ctx context.Context, query ListJobsQuery) ([]JobRecord, error)
	SetTask(ctx context.Context, jobID, taskID string, now time.Time) error
	// Requeue 把 failed 任务条件迁移回 queued（受控重试/续跑）。
	Requeue(ctx context.Context, jobID string, now time.Time) (bool, error)
	MarkRunning(ctx context.Context, jobID string, now time.Time) (bool, error)
	FinishJob(ctx context.Context, command FinishJobCommand) (bool, error)
	ClearInput(ctx context.Context, jobID string) error
	// LookupUserByNormalizedUsername 按规范化用户名读取既有账户（导入重复匹配用）。
	LookupUserByNormalizedUsername(ctx context.Context, normalized string) (ExistingUser, bool, error)
	HasRow(ctx context.Context, jobID string, rowNumber int) (bool, error)
	InsertRow(ctx context.Context, row RowRecord) (bool, error)
	CountRows(ctx context.Context, jobID string) (map[RowAction]int, error)
	// ListRows 按 (job_id,row_number) 顺序分页读取逐行结果。
	ListRows(ctx context.Context, jobID string, offset, limit int) ([]RowRecord, error)
	// FailInterrupted 把崩溃遗留的 running 任务条件迁移为 failed（使 Retry 可达）。
	FailInterrupted(ctx context.Context, jobID string, code ErrorCode, now time.Time) (bool, error)
	// CleanupInputs 清空早于 before 的失败任务导入文件内容（过期保留清理）。
	CleanupInputs(ctx context.Context, before time.Time) (int64, error)
}
