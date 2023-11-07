package task

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// NewJob 是存储层创建任务的参数；ID 由执行器用安全随机源生成。
type NewJob struct {
	ID             string
	Kind           string
	Initiator      audit.Actor
	Payload        json.RawMessage
	MutexKey       string
	TimeoutSeconds int
	MaxAttempts    int
	// PermissionRequired 为 true 时执行器必须在每次尝试前调用可信权限复验回调；
	// 没有回调时任务失败而不是放行。
	PermissionRequired bool
	RequestID          string
	CreatedAt          time.Time
}

// Completion 是任务进入终态的参数。State 必须是成功/失败/取消/超时之一；
// 存储实现必须在一条条件 UPDATE 中从 running/cancel_requested 迁移到终态，
// 关闭当前尝试历史，并与审计事件同事务提交。
type Completion struct {
	JobID         string
	State         State
	ExecutorID    string
	ErrorCode     string
	FailureReason string
	Now           time.Time
}

// CancelCommand 是取消请求的持久化参数。
type CancelCommand struct {
	JobID     string
	Actor     audit.Actor
	Reason    string
	RequestID string
	Now       time.Time
}

// RetryCommand 是一次可重试失败后把任务重新排队的参数。Attempt 是刚失败的尝试
// 序号；NextAttemptAt 是退避后的最早可领取时间。存储实现只在任务仍处于
// running 且尝试序号一致时接受，取消请求已接受的任务不会重试。
type RetryCommand struct {
	JobID         string
	ExecutorID    string
	Attempt       int
	ErrorCode     string
	FailureReason string
	NextAttemptAt time.Time
	Now           time.Time
}

// Attempt 是一次任务尝试的历史记录；同一任务编号下按 attempt 升序。
type Attempt struct {
	JobID      string
	Attempt    int
	StartedAt  time.Time
	FinishedAt time.Time
	// Outcome 是尝试结果：succeeded/failed/cancelled/timed_out/interrupted；
	// 尚未结束时为空字符串。
	Outcome   string
	ErrorCode string
}

// Store 是后台任务状态持久化契约，由 internal/task/sqlite 提供生产实现。
//
// 实现约定：
//   - 每个状态变化必须在同一个 SQLite 事务内写入安全审计事件；审计写入失败时
//     拒绝该状态变化（返回可被 errors.Is(err, audit.ErrAuditUnavailable) 识别
//     的错误），不能提交“状态变了但审计缺失”的结果。
//   - Claim 只能领取 state=queued、已到重试时间且互斥键没有 active 冲突的任务，
//     并在同一事务中迁移到 running、递增 attempt、写入尝试历史、记录
//     executed_by/started_at 与审计。
//   - Complete 只能从 running/cancel_requested 迁移到终态；条件不命中返回
//     ErrTransitionRejected，绝不覆盖已有终态；同时关闭当前尝试历史。
//   - Retry 只能从 running 迁移回 queued 并设置 next_attempt_at；取消请求已接受
//     的任务返回 ErrTransitionRejected，由调用方写取消终态；绝不无限重试。
//   - RequestCancel：queued 直接变 cancelled；running 变 cancel_requested；
//     cancel_requested 幂等返回已请求；终态返回 ErrTaskTerminal 并记录被拒绝
//     审计。
//   - RecoverInterrupted 把遗留 running/cancel_requested 标记为 failed
//     （TASK_INTERRUPTED）、关闭未完成尝试并审计，返回恢复数量。
//   - Attempts 返回尝试历史，不返回任务载荷或处理器错误原文之外的秘密。
//   - 所有方法传播 context；错误不得包含任务载荷、处理器错误原文或秘密。
type Store interface {
	Enqueue(ctx context.Context, job NewJob) (Job, error)
	Claim(ctx context.Context, executorID string, now time.Time) (Job, bool, error)
	Complete(ctx context.Context, completion Completion) (Job, error)
	Retry(ctx context.Context, command RetryCommand) (Job, bool, error)
	RequestCancel(ctx context.Context, command CancelCommand) (CancelResult, error)
	RecoverInterrupted(ctx context.Context, executorID string, now time.Time) (int, error)
	Get(ctx context.Context, id string) (Job, bool, error)
	Attempts(ctx context.Context, jobID string) ([]Attempt, error)
	// ListJobs 按稳定排序（created_at_ms,id 倒序）读取一页任务；过滤与 keyset
	// 位置直接写入 SQL，不先读全量再内存过滤；不返回任务载荷以外的额外秘密。
	ListJobs(ctx context.Context, query JobPageQuery) (JobPage, error)
}

// ScheduleStore 是定时计划持久化契约，由 internal/task/sqlite 提供生产实现。
// 它内嵌任务存储，因此同一 SQLite 连接可以既执行任务又调度任务。
//
// 实现约定：
//   - CreateSchedule/SetScheduleEnabled/DeleteSchedule 必须在同一事务中写安全
//     审计事件；审计不可用时拒绝变更。
//   - FireSchedule 用 (schedule_id, scheduled_at_ms) 唯一键去重，并在同一事务内
//     记录触发结果、按需入队任务、推进计划游标与写审计。重复触发返回
//     Fired=false 而不是错误，且不发生任何状态变化。
//   - 暂停/删除计划不修改 jobs 表，已入队或运行中的任务继续按自身状态机执行。
type ScheduleStore interface {
	Store
	CreateSchedule(ctx context.Context, schedule NewSchedule) (Schedule, error)
	GetSchedule(ctx context.Context, id string) (Schedule, bool, error)
	ListSchedules(ctx context.Context, enabledOnly bool) ([]Schedule, error)
	SetScheduleEnabled(ctx context.Context, command ScheduleStateCommand) (Schedule, error)
	DeleteSchedule(ctx context.Context, command ScheduleDeleteCommand) error
	FireSchedule(ctx context.Context, command FireCommand) (FireResult, error)
}
