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
	RequestID      string
	CreatedAt      time.Time
}

// Completion 是任务进入终态的参数。State 必须是成功/失败/取消/超时之一；
// 存储实现必须在一条条件 UPDATE 中从 running/cancel_requested 迁移到终态，
// 并与审计事件同事务提交。
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

// Store 是后台任务状态持久化契约，由 internal/task/sqlite 提供生产实现。
//
// 实现约定：
//   - 每个状态变化必须在同一个 SQLite 事务内写入安全审计事件；审计写入失败时
//     拒绝该状态变化（返回可被 errors.Is(err, audit.ErrAuditUnavailable) 识别
//     的错误），不能提交“状态变了但审计缺失”的结果。
//   - Claim 只能领取 state=queued 且互斥键没有 active 冲突的任务，并在同一事务
//     中迁移到 running、记录 executed_by/started_at 与审计。
//   - Complete 只能从 running/cancel_requested 迁移到终态；条件不命中返回
//     ErrTransitionRejected，绝不覆盖已有终态。
//   - RequestCancel：queued 直接变 cancelled；running 变 cancel_requested；
//     cancel_requested 幂等返回已请求；终态返回 ErrTaskTerminal 并记录被拒绝
//     审计。
//   - RecoverInterrupted 把遗留 running/cancel_requested 标记为 failed
//     （TASK_INTERRUPTED）并审计，返回恢复数量。
//   - 所有方法传播 context；错误不得包含任务载荷、处理器错误原文或秘密。
type Store interface {
	Enqueue(ctx context.Context, job NewJob) (Job, error)
	Claim(ctx context.Context, executorID string, now time.Time) (Job, bool, error)
	Complete(ctx context.Context, completion Completion) (Job, error)
	RequestCancel(ctx context.Context, command CancelCommand) (CancelResult, error)
	RecoverInterrupted(ctx context.Context, executorID string, now time.Time) (int, error)
	Get(ctx context.Context, id string) (Job, bool, error)
}
