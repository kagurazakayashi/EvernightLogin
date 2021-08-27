package auditops

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// EventQuery 是存储层审计查询参数。它由服务层在授权之后构造：AllData/AppIDs/
// IncludeSystem 描述当前调用者获准的数据范围，存储实现必须把它们直接写进 SQL
// 的 WHERE 子句，禁止先读取全量再在内存中过滤。
type EventQuery struct {
	// Filter 是已校验的业务筛选条件。
	Filter Filter
	// AllData 为 true 表示数据范围不限（仍受系统/应用范围约束）。
	AllData bool
	// AppIDs 是允许查看的应用快照 ID 集合；AllData 为 false 时生效。
	AppIDs []string
	// IncludeSystem 表示是否允许查看没有应用快照（app_id_snapshot 为空）的系统级事件。
	IncludeSystem bool
	// Order 是稳定排序：时间 + 事件 ID 并列决胜。
	Order SortOrder
	// Limit 是单页条数；Offset 是偏移（稳定排序下的受控深分页）。
	Limit  int
	Offset int
}

// EventPage 是存储层查询结果；HasMore 通过多取一条判定，不伪造总数。
type EventPage struct {
	Events  []audit.Event
	HasMore bool
}

// CountResult 是有上限的计数结果；Capped 表示达到上限后截断，不是精确总数。
type CountResult struct {
	Count  int64
	Capped bool
}

// RetentionRecord 是保留策略持久化记录；Version 用于乐观并发。
type RetentionRecord struct {
	RetentionDays int
	Version       int64
	UpdatedBy     audit.Actor
	Reason        string
	UpdatedAt     time.Time
}

// ExportRecord 是审计导出任务持久化记录。FilterJSON/DataScopeJSON 是创建时的
// 筛选与授权范围快照，后续列表变化不会改变已创建任务的语义。
type ExportRecord struct {
	ID            string
	ScopeKind     string
	ScopeID       string
	RequestedBy   audit.Actor
	FilterJSON    string
	DataScopeJSON string
	Format        string
	MaxRows       int
	State         string
	RowCount      int
	Truncated     bool
	TaskID        string
	FileName      string
	FileSHA256    []byte
	FileBytes     int64
	ErrorCode     string
	FailureReason string
	RequestID     string
	// ExecutorID 是真实执行该导出的任务执行器标识（来自 internal/task）。
	ExecutorID string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
	ExpiresAt  time.Time
}

// ExportUpdateCommand 是导出任务状态迁移参数；State 只允许受控枚举。
type ExportUpdateCommand struct {
	ID    string
	State string
	// ExecutorID 仅用于运行日志/诊断；真实执行者由 internal/task 的
	// executed_by 与任务状态审计保存，不在导出记录中重复持久化。
	ExecutorID    string
	RowCount      int
	Truncated     bool
	FileName      string
	FileSHA256    []byte
	FileBytes     int64
	ErrorCode     string
	FailureReason string
	Now           time.Time
}

// ExportListQuery 是导出任务列表查询；ScopeID 必填，其余为可选过滤。
type ExportListQuery struct {
	ScopeID string
	State   string
	Limit   int
	Offset  int
}

// PurgeRunRecord 是清理运行持久化记录。
type PurgeRunRecord struct {
	ID            string
	Kind          string
	ScopeKind     string
	ScopeID       string
	RequestedBy   audit.Actor
	Cutoff        time.Time
	BatchSize     int
	MaxRecords    int
	State         string
	TaskID        string
	Scanned       int
	Cleaned       int
	Skipped       int
	Failed        int
	Batches       int
	LimitReached  bool
	ErrorCode     string
	FailureReason string
	RequestID     string
	// ExecutorID 是真实执行该清理的任务执行器标识（来自 internal/task）。
	ExecutorID string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
}

// PurgeListQuery 是清理运行列表查询。
type PurgeListQuery struct {
	Kind   string
	State  string
	Limit  int
	Offset int
}

// PurgeBatchCommand 是单个清理批次参数。存储实现必须在同一事务内删除一批
// audit_events、累加运行计数并追加受保护清理日志，任何一步失败整体回滚。
type PurgeBatchCommand struct {
	RunID      string
	ScopeKind  string
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	BatchIndex int
	// Remaining 是本次允许继续清理的记录上限余额；删除条数不超过该值。
	Remaining int
	// Actor/RequestID/TaskID 是写入受保护清理日志的真实操作者与关联编号。
	Actor     audit.Actor
	RequestID string
	TaskID    string
	Now       time.Time
}

// PurgedBatch 是单批删除结果。
type PurgedBatch struct {
	Scanned int
	Cleaned int
}

// PurgeFinishCommand 是清理运行终态写入参数；Event 必须在同一事务内写入
// audit_events，确保“结果成功但审计缺失”不可能出现。
type PurgeFinishCommand struct {
	RunID         string
	State         string
	Scanned       int
	Cleaned       int
	Skipped       int
	Failed        int
	Batches       int
	LimitReached  bool
	ErrorCode     string
	FailureReason string
	Now           time.Time
	Event         audit.Event
	// Entry 非空时与终态、审计事件同事务写入受保护清理日志。
	Entry *MaintenanceEntry
}

// MaintenanceEntry 是受保护清理审计记录视图。
type MaintenanceEntry struct {
	ID         string
	RunID      string
	OccurredAt time.Time
	Action     string
	Actor      audit.Actor
	ScopeKind  string
	ScopeID    string
	Cutoff     time.Time
	BatchIndex int
	Scanned    int
	Cleaned    int
	Result     string
	ErrorCode  string
	RequestID  string
	TaskID     string
}

// Store 是审计读取与生命周期持久化契约，由 internal/auditops/sqlite 提供生产
// SQLite 实现。所有查询/删除必须在存储层按数据范围限制；错误不得包含秘密、
// 审计正文或差异值。
type Store interface {
	// QueryEvents 按 EventQuery 的授权范围与筛选读取稳定排序的一页事件。
	QueryEvents(ctx context.Context, query EventQuery) (EventPage, error)
	// GetEvent 按事件 ID 读取单条事件；不存在返回 found=false。
	GetEvent(ctx context.Context, eventID string) (audit.Event, bool, error)
	// CountEvents 返回有上限的计数，用于 root 清理预估；Capped 表示不精确。
	CountEvents(ctx context.Context, query EventQuery, cap int64) (CountResult, error)
	// GetRetention 读取保留策略；未设置时 found=false。
	GetRetention(ctx context.Context) (RetentionRecord, bool, error)
	// SetRetention 用 version CAS 写入保留策略，并在同一事务内追加受保护清理
	// 日志与审计事件（Event）。返回 false 表示版本冲突。
	SetRetention(ctx context.Context, record RetentionRecord, entry MaintenanceEntry,
		event audit.Event) (bool, error)
	// CreateExport 在同一事务内创建导出任务记录与审计事件。
	CreateExport(ctx context.Context, record ExportRecord, event audit.Event) error
	// GetExport 读取导出任务；不存在返回 found=false。
	GetExport(ctx context.Context, exportID string) (ExportRecord, bool, error)
	// SetExportTask 绑定任务编号。
	SetExportTask(ctx context.Context, exportID, taskID string, now time.Time) error
	// UpdateExport 做受控状态迁移并写入审计事件；终态只能写一次。
	UpdateExport(ctx context.Context, command ExportUpdateCommand, event audit.Event) (bool, error)
	// ListExports 按范围/状态列出导出任务（按创建时间倒序）。
	ListExports(ctx context.Context, query ExportListQuery) ([]ExportRecord, error)
	// CreatePurgeRun 在同一事务内创建清理运行、受保护清理日志与审计事件。
	CreatePurgeRun(ctx context.Context, record PurgeRunRecord, entry MaintenanceEntry,
		event audit.Event) error
	// GetPurgeRun 读取清理运行。
	GetPurgeRun(ctx context.Context, runID string) (PurgeRunRecord, bool, error)
	// SetPurgeTask 绑定任务编号。
	SetPurgeTask(ctx context.Context, runID, taskID string, now time.Time) error
	// StartPurgeRun 把 queued 条件迁移为 running 并记录真实执行者。
	StartPurgeRun(ctx context.Context, runID, executorID string, now time.Time) (bool, error)
	// PurgeBatch 删除截止时间之前、授权范围内的一批事件，累加运行计数并追加受保护
	// 清理日志；返回本批实际删除数。
	PurgeBatch(ctx context.Context, command PurgeBatchCommand) (PurgedBatch, error)
	// FinishPurgeRun 写入终态、每个批次计数、审计事件与受保护清理日志；终态只写一次。
	FinishPurgeRun(ctx context.Context, command PurgeFinishCommand) (bool, error)
	// AppendMaintenanceLog 追加一条受保护清理日志（表禁止 UPDATE/DELETE）。
	AppendMaintenanceLog(ctx context.Context, entry MaintenanceEntry) error
	// ListPurgeRuns 列出清理运行（按创建时间倒序）。
	ListPurgeRuns(ctx context.Context, query PurgeListQuery) ([]PurgeRunRecord, error)
	// MaintenanceLog 读取某次清理的受保护审计记录（按时间正序）。
	MaintenanceLog(ctx context.Context, runID string) ([]MaintenanceEntry, error)
}
