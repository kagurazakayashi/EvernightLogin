// Package sqlite 实现 internal/task.Store 的 SQLite 生产持久化。
//
// 表由 migrations/0004_jobs.sql 创建，本包不执行迁移；调用方应在启动或测试中
// 先通过 internal/storage/migrate 应用全部迁移。每次任务状态变化都在同一个
// SQLite 事务内写入安全审计事件，审计写入失败时拒绝状态变化（fail-closed）。
//
// 本包不拥有数据库连接：*sqlite.Store 的关闭由外层负责。构造后不可变，可被
// 多个 goroutine 并发使用（生产上由单实例执行器串行领取任务）。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

const (
	insertJobSQL = `INSERT INTO jobs(
id,kind,state,initiated_by_type,initiated_by_id,executed_by,cancelled_by_type,cancelled_by_id,
cancellation_reason,cancel_requested_at_ms,started_at_ms,finished_at_ms,timeout_seconds,attempt,
max_attempts,permission_required,next_attempt_at_ms,mutex_key,payload_json,request_id,error_code,
failure_reason,created_at_ms,updated_at_ms
) VALUES(?,?,'queued',?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,0,?,?,NULL,?,?,?,NULL,NULL,?,?)`

	jobSelectColumns = `id,kind,state,initiated_by_type,initiated_by_id,executed_by,
cancelled_by_type,cancelled_by_id,cancellation_reason,cancel_requested_at_ms,started_at_ms,
finished_at_ms,timeout_seconds,attempt,max_attempts,permission_required,next_attempt_at_ms,
mutex_key,payload_json,request_id,error_code,failure_reason,created_at_ms,updated_at_ms`

	selectCandidateSQL = `SELECT ` + jobSelectColumns + `
FROM jobs j
WHERE j.state='queued'
AND (j.next_attempt_at_ms IS NULL OR j.next_attempt_at_ms<=?)
AND (j.mutex_key IS NULL OR NOT EXISTS (
  SELECT 1 FROM jobs active
  WHERE active.state IN('running','cancel_requested') AND active.mutex_key = j.mutex_key
))
ORDER BY j.created_at_ms, j.id
LIMIT 1`

	selectJobSQL = `SELECT ` + jobSelectColumns + `
FROM jobs WHERE id=?`

	claimJobSQL = `UPDATE jobs SET state='running',executed_by=?,started_at_ms=?,attempt=?,
next_attempt_at_ms=NULL,updated_at_ms=?
WHERE id=? AND state='queued' AND attempt=? AND (next_attempt_at_ms IS NULL OR next_attempt_at_ms<=?)`

	insertAttemptSQL = `INSERT INTO job_attempts(job_id,attempt,started_at_ms,executor_id) VALUES(?,?,?,?)`

	closeOpenAttemptsSQL = `UPDATE job_attempts SET finished_at_ms=?,outcome=?,error_code=?
WHERE job_id=? AND finished_at_ms IS NULL`

	completeJobSQL = `UPDATE jobs SET state=?,finished_at_ms=?,error_code=?,failure_reason=?,updated_at_ms=?
WHERE id=? AND state IN('running','cancel_requested')`

	cancelQueuedSQL = `UPDATE jobs SET state='cancelled',cancelled_by_type=?,cancelled_by_id=?,
cancellation_reason=?,cancel_requested_at_ms=?,finished_at_ms=?,error_code='TASK_CANCELLED',
failure_reason='任务在排队中被取消',updated_at_ms=?
WHERE id=? AND state='queued'`

	cancelRunningSQL = `UPDATE jobs SET state='cancel_requested',cancelled_by_type=?,cancelled_by_id=?,
cancellation_reason=?,cancel_requested_at_ms=?,updated_at_ms=?
WHERE id=? AND state='running'`

	listInterruptedSQL = `SELECT id,state FROM jobs WHERE state IN('running','cancel_requested') ORDER BY created_at_ms, id`

	recoverJobSQL = `UPDATE jobs SET state='failed',error_code='TASK_INTERRUPTED',failure_reason=?,
finished_at_ms=?,updated_at_ms=? WHERE id=? AND state IN('running','cancel_requested')`
)

// Options 是构造任务存储的选项，主要供测试注入时钟与审计告警器。
type Options struct {
	// Now 是审计事件时间来源；nil 使用 time.Now。
	Now func() time.Time
	// Logger 是运行日志器；nil 使用丢弃输出。
	Logger *slog.Logger
	// Alerter 接收审计写入故障告警；nil 使用 audit 包默认告警。
	Alerter audit.Alerter
}

// Store 是 task.Store 的 SQLite 实现。
type Store struct {
	raw        *storagesqlite.Store
	auditStore audit.Store
	auditor    *audit.Recorder
	now        func() time.Time
}

// New 包装已打开并完成迁移的 SQLite 存储，并构造内部审计写入器。raw 为空时
// 返回 task.ErrOptionsInvalid。
func New(raw *storagesqlite.Store, options Options) (*Store, error) {
	if raw == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", task.ErrOptionsInvalid)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", task.ErrOptionsInvalid, err)
	}
	logger := options.Logger
	now := options.Now
	if now == nil {
		now = time.Now
	}
	auditor, err := audit.New(auditStore, audit.Options{
		Logger:  logger,
		Alerter: options.Alerter,
		Now:     now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", task.ErrOptionsInvalid, err)
	}
	return &Store{raw: raw, auditStore: auditStore, auditor: auditor, now: now}, nil
}

// prepare 填充审计事件 ID/时间并做字段规范化，供直接调用 audit.Store 使用。
func (s *Store) prepare(event audit.Event) (audit.Event, error) {
	return audit.PrepareEvent(event, s.now())
}

// 编译期确认实现 task.Store。
var _ task.Store = (*Store)(nil)

// Enqueue 在同一个事务中插入 queued 任务并写入 jobs.enqueued 审计事件。
func (s *Store) Enqueue(ctx context.Context, job task.NewJob) (task.Job, error) {
	if err := validateNewJob(job); err != nil {
		return task.Job{}, err
	}
	nowMS := job.CreatedAt.UTC().UnixMilli()
	event := jobAuditEvent(job.ID, job.Initiator, "jobs.enqueued", "queued", job.RequestID, "", nil)
	change := func(txCtx context.Context, tx audit.Tx) error {
		return insertJobRow(txCtx, tx, job)
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.Job{}, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		return task.Job{}, mapStoreError(err)
	}
	return task.Job{
		ID:                 job.ID,
		Kind:               job.Kind,
		State:              task.StateQueued,
		Initiator:          job.Initiator,
		Payload:            job.Payload,
		MutexKey:           job.MutexKey,
		TimeoutSeconds:     job.TimeoutSeconds,
		Attempt:            0,
		MaxAttempts:        job.MaxAttempts,
		PermissionRequired: job.PermissionRequired,
		RequestID:          job.RequestID,
		CreatedAt:          time.UnixMilli(nowMS).UTC(),
		UpdatedAt:          time.UnixMilli(nowMS).UTC(),
	}, nil
}

// insertJobRow 在给定事务中插入一条 queued 任务行；Enqueue 与计划触发共用，
// 保证两条入队路径的字段与校验一致。
func insertJobRow(ctx context.Context, tx audit.Tx, job task.NewJob) error {
	nowMS := job.CreatedAt.UTC().UnixMilli()
	permission := 0
	if job.PermissionRequired {
		permission = 1
	}
	_, err := tx.ExecContext(ctx, insertJobSQL,
		job.ID,
		job.Kind,
		string(job.Initiator.Type),
		job.Initiator.ID,
		job.TimeoutSeconds,
		job.MaxAttempts,
		permission,
		nullable(job.MutexKey),
		string(job.Payload),
		nullable(job.RequestID),
		nowMS,
		nowMS,
	)
	return err
}

// Claim 领取一条 queued 任务：必须已到重试时间，互斥键不能与运行中任务冲突；
// 在同一事务中迁移到 running、递增尝试序号、写入尝试历史、记录执行器与开始
// 时间并写入 jobs.started 审计。没有可领取任务时返回 (Job{}, false, nil)。
func (s *Store) Claim(ctx context.Context, executorID string, now time.Time) (task.Job, bool, error) {
	nowMS := now.UTC().UnixMilli()
	rows, err := s.raw.QueryContext(ctx, selectCandidateSQL, nowMS)
	if err != nil {
		return task.Job{}, false, mapStoreError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return task.Job{}, false, mapStoreError(err)
		}
		return task.Job{}, false, nil
	}
	candidate, err := scanJob(rows)
	if err != nil {
		return task.Job{}, false, mapStoreError(err)
	}
	attempt := candidate.Attempt + 1
	changes := []audit.FieldChange{
		{Field: "state", Before: string(task.StateQueued), After: string(task.StateRunning)},
		{Field: "attempt", Before: formatInt(candidate.Attempt), After: formatInt(attempt)},
	}
	event := jobAuditEvent(candidate.ID,
		audit.Actor{Type: audit.ActorSystem, ID: executorID},
		"jobs.started", "running", candidate.RequestID, "", changes)
	change := func(txCtx context.Context, tx audit.Tx) error {
		result, err := tx.ExecContext(txCtx, claimJobSQL,
			executorID, nowMS, attempt, nowMS, candidate.ID, candidate.Attempt, nowMS)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return task.ErrTransitionRejected
		}
		if _, err := tx.ExecContext(txCtx, insertAttemptSQL, candidate.ID, attempt, nowMS, executorID); err != nil {
			return err
		}
		return nil
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.Job{}, false, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		if errors.Is(err, task.ErrTransitionRejected) {
			return task.Job{}, false, nil
		}
		return task.Job{}, false, mapStoreError(err)
	}
	candidate.State = task.StateRunning
	candidate.ExecutorID = executorID
	candidate.Attempt = attempt
	candidate.StartedAt = time.UnixMilli(nowMS).UTC()
	candidate.UpdatedAt = time.UnixMilli(nowMS).UTC()
	candidate.NextAttemptAt = time.Time{}
	return candidate, true, nil
}

// Complete 把 running/cancel_requested 任务条件迁移到终态并写入对应审计事件；
// 条件不命中（已有终态）返回 task.ErrTransitionRejected，绝不覆盖终态。
func (s *Store) Complete(ctx context.Context, completion task.Completion) (task.Job, error) {
	if !completion.State.Terminal() {
		return task.Job{}, fmt.Errorf("%w: 终态不合法", task.ErrInvalidRequest)
	}
	if err := validateJobID(completion.JobID); err != nil {
		return task.Job{}, err
	}
	nowMS := completion.Now.UTC().UnixMilli()
	action := "jobs." + string(completion.State)
	event := jobAuditEvent(completion.JobID,
		audit.Actor{Type: audit.ActorSystem, ID: completion.ExecutorID},
		action, string(completion.State), "", completion.ErrorCode, nil)
	change := func(txCtx context.Context, tx audit.Tx) error {
		result, err := tx.ExecContext(txCtx, completeJobSQL,
			string(completion.State),
			nowMS,
			nullable(completion.ErrorCode),
			nullable(completion.FailureReason),
			nowMS,
			completion.JobID,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return task.ErrTransitionRejected
		}
		if _, err := tx.ExecContext(txCtx, closeOpenAttemptsSQL,
			nowMS,
			string(completion.State),
			nullable(completion.ErrorCode),
			completion.JobID,
		); err != nil {
			return err
		}
		return nil
	}
	prepared, err := s.prepare(event)
	if err != nil {
		return task.Job{}, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		return task.Job{}, mapStoreError(err)
	}
	return s.load(ctx, completion.JobID)
}

// RequestCancel 处理可信取消请求：queued 直接变 cancelled，running 变
// cancel_requested，已请求取消幂等返回，终态返回 task.ErrTaskTerminal 并写被
// 拒绝审计。
func (s *Store) RequestCancel(ctx context.Context, command task.CancelCommand) (task.CancelResult, error) {
	job, found, err := s.loadWithFound(ctx, command.JobID)
	if err != nil {
		return task.CancelResult{}, err
	}
	if !found {
		return task.CancelResult{}, task.ErrTaskNotFound
	}
	if job.State.Terminal() {
		denied := jobAuditEvent(command.JobID, command.Actor, "jobs.cancel_rejected", string(job.State),
			command.RequestID, "", nil)
		denied.Outcome = audit.OutcomeDenied
		denied.ReasonCode = "terminal_state"
		if auditErr := s.auditor.Record(ctx, denied); auditErr != nil && !errors.Is(auditErr, audit.ErrDuplicateEvent) {
			return task.CancelResult{Accepted: false, State: job.State},
				errors.Join(task.ErrTaskTerminal, mapStoreError(auditErr))
		}
		return task.CancelResult{Accepted: false, State: job.State}, task.ErrTaskTerminal
	}
	if job.State == task.StateCancelRequested {
		return task.CancelResult{Accepted: true, AlreadyRequested: true, State: task.StateCancelRequested}, nil
	}
	nowMS := command.Now.UTC().UnixMilli()
	switch job.State {
	case task.StateQueued:
		event := jobAuditEvent(command.JobID, command.Actor, "jobs.cancelled", string(task.StateCancelled),
			command.RequestID, "", stateChange("queued", "cancelled"))
		change := func(txCtx context.Context, tx audit.Tx) error {
			result, err := tx.ExecContext(txCtx, cancelQueuedSQL,
				string(command.Actor.Type), command.Actor.ID, command.Reason,
				nowMS, nowMS, nowMS, command.JobID)
			if err != nil {
				return err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if affected != 1 {
				return task.ErrTransitionRejected
			}
			return nil
		}
		prepared, err := s.prepare(event)
		if err != nil {
			return task.CancelResult{}, mapStoreError(err)
		}
		if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
			return s.resolveCancelRace(ctx, command, err)
		}
		return task.CancelResult{Accepted: true, State: task.StateCancelled}, nil
	case task.StateRunning:
		event := jobAuditEvent(command.JobID, command.Actor, "jobs.cancel_requested", string(task.StateCancelRequested),
			command.RequestID, "", stateChange("running", "cancel_requested"))
		change := func(txCtx context.Context, tx audit.Tx) error {
			result, err := tx.ExecContext(txCtx, cancelRunningSQL,
				string(command.Actor.Type), command.Actor.ID, command.Reason, nowMS, nowMS, command.JobID)
			if err != nil {
				return err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if affected != 1 {
				return task.ErrTransitionRejected
			}
			return nil
		}
		prepared, err := s.prepare(event)
		if err != nil {
			return task.CancelResult{}, mapStoreError(err)
		}
		if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
			return s.resolveCancelRace(ctx, command, err)
		}
		return task.CancelResult{Accepted: true, State: task.StateCancelRequested}, nil
	default:
		return task.CancelResult{Accepted: false, State: job.State}, task.ErrTransitionRejected
	}
}

// resolveCancelRace 在条件取消未命中时重新读取真实状态，避免把取消请求显示为
// 已取消；终态时记录被拒绝审计。
func (s *Store) resolveCancelRace(ctx context.Context, command task.CancelCommand, runErr error) (task.CancelResult, error) {
	if !errors.Is(runErr, task.ErrTransitionRejected) {
		return task.CancelResult{}, mapStoreError(runErr)
	}
	latest, found, err := s.loadWithFound(ctx, command.JobID)
	if err != nil {
		return task.CancelResult{}, err
	}
	if !found {
		return task.CancelResult{}, task.ErrTaskNotFound
	}
	if latest.State == task.StateCancelRequested {
		return task.CancelResult{Accepted: true, AlreadyRequested: true, State: latest.State}, nil
	}
	if latest.State.Terminal() {
		denied := jobAuditEvent(command.JobID, command.Actor, "jobs.cancel_rejected", string(latest.State),
			command.RequestID, "", nil)
		denied.Outcome = audit.OutcomeDenied
		denied.ReasonCode = "terminal_state"
		if auditErr := s.auditor.Record(ctx, denied); auditErr != nil && !errors.Is(auditErr, audit.ErrDuplicateEvent) {
			return task.CancelResult{Accepted: false, State: latest.State},
				errors.Join(task.ErrTaskTerminal, mapStoreError(auditErr))
		}
		return task.CancelResult{Accepted: false, State: latest.State}, task.ErrTaskTerminal
	}
	return task.CancelResult{Accepted: false, State: latest.State}, task.ErrTransitionRejected
}

// RecoverInterrupted 把重启前遗留的 running/cancel_requested 任务标记为 failed
// （TASK_INTERRUPTED）并逐条写入 jobs.recovered 审计，返回恢复数量。
func (s *Store) RecoverInterrupted(ctx context.Context, executorID string, now time.Time) (int, error) {
	rows, err := s.raw.QueryContext(ctx, listInterruptedSQL)
	if err != nil {
		return 0, mapStoreError(err)
	}
	type interruptedJob struct {
		id    string
		state task.State
	}
	var interrupted []interruptedJob
	for rows.Next() {
		var id string
		var state string
		if err := rows.Scan(&id, &state); err != nil {
			rows.Close()
			return 0, mapStoreError(err)
		}
		interrupted = append(interrupted, interruptedJob{id: id, state: task.State(state)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, mapStoreError(err)
	}
	if err := rows.Close(); err != nil {
		return 0, mapStoreError(err)
	}
	nowMS := now.UTC().UnixMilli()
	const interruptedReason = "执行器重启，无法确认遗留运行任务结果"
	systemActor := audit.Actor{Type: audit.ActorSystem, ID: executorID}
	recovered := 0
	for _, entry := range interrupted {
		event := jobAuditEvent(entry.id, systemActor, "jobs.recovered", string(task.StateFailed),
			"", "TASK_INTERRUPTED", stateChange(string(entry.state), string(task.StateFailed)))
		change := func(txCtx context.Context, tx audit.Tx) error {
			result, err := tx.ExecContext(txCtx, recoverJobSQL, interruptedReason, nowMS, nowMS, entry.id)
			if err != nil {
				return err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if affected != 1 {
				return task.ErrTransitionRejected
			}
			if _, err := tx.ExecContext(txCtx, closeOpenAttemptsSQL,
				nowMS, "interrupted", "TASK_INTERRUPTED", entry.id); err != nil {
				return err
			}
			return nil
		}
		prepared, err := s.prepare(event)
		if err != nil {
			return recovered, mapStoreError(err)
		}
		if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
			if errors.Is(err, task.ErrTransitionRejected) {
				continue
			}
			return recovered, mapStoreError(err)
		}
		recovered++
	}
	return recovered, nil
}

// Get 读取任务当前状态；不存在返回 (Job{}, false, nil)。
func (s *Store) Get(ctx context.Context, id string) (task.Job, bool, error) {
	if err := validateJobID(id); err != nil {
		return task.Job{}, false, err
	}
	return s.loadWithFound(ctx, id)
}

// load 读取任务并返回存储错误（不存在视为错误）。
func (s *Store) load(ctx context.Context, id string) (task.Job, error) {
	job, found, err := s.loadWithFound(ctx, id)
	if err != nil {
		return task.Job{}, err
	}
	if !found {
		return task.Job{}, task.ErrTaskNotFound
	}
	return job, nil
}

// loadWithFound 执行单行查询。
func (s *Store) loadWithFound(ctx context.Context, id string) (task.Job, bool, error) {
	rows, err := s.raw.QueryContext(ctx, selectJobSQL, id)
	if err != nil {
		return task.Job{}, false, mapStoreError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return task.Job{}, false, mapStoreError(err)
		}
		return task.Job{}, false, nil
	}
	job, err := scanJob(rows)
	if err != nil {
		return task.Job{}, false, mapStoreError(err)
	}
	return job, true, nil
}

// ListJobs 按稳定排序（created_at_ms DESC,id DESC）读取一页任务。过滤条件与
// keyset 游标都写入 SQL；不读取 payload 以外的额外表。载荷仍由列返回，服务层
// 列表视图会显式剔除（存储层不复制任务状态机）。
func (s *Store) ListJobs(ctx context.Context, query task.JobPageQuery) (task.JobPage, error) {
	clauses := make([]string, 0, 8)
	args := make([]any, 0, 12)
	if query.State != "" {
		clauses = append(clauses, "state=?")
		args = append(args, string(query.State))
	}
	if query.Kind != "" {
		clauses = append(clauses, "kind=?")
		args = append(args, query.Kind)
	}
	if query.RequestID != "" {
		clauses = append(clauses, "request_id=?")
		args = append(args, query.RequestID)
	}
	if query.InitiatorType != "" {
		clauses = append(clauses, "initiated_by_type=?")
		args = append(args, string(query.InitiatorType))
	}
	if query.InitiatorID != "" {
		clauses = append(clauses, "initiated_by_id=?")
		args = append(args, query.InitiatorID)
	}
	if !query.From.IsZero() {
		clauses = append(clauses, "created_at_ms>=?")
		args = append(args, query.From.UTC().UnixMilli())
	}
	if !query.To.IsZero() {
		clauses = append(clauses, "created_at_ms<?")
		args = append(args, query.To.UTC().UnixMilli())
	}
	if query.AfterID != "" {
		clauses = append(clauses, "(created_at_ms<? OR (created_at_ms=? AND id<?))")
		afterMS := query.AfterCreatedAt.UTC().UnixMilli()
		args = append(args, afterMS, afterMS, query.AfterID)
	}
	if len(clauses) == 0 {
		clauses = append(clauses, "1=1")
	}
	limit := query.Limit
	if limit < 1 || limit > task.ListMaxLimit {
		limit = task.ListDefaultLimit
	}
	statement := `SELECT ` + jobSelectColumns + ` FROM jobs WHERE ` +
		strings.Join(clauses, " AND ") +
		` ORDER BY created_at_ms DESC,id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.raw.QueryContext(ctx, statement, args...)
	if err != nil {
		return task.JobPage{}, mapStoreError(err)
	}
	defer rows.Close()
	jobs := make([]task.Job, 0, limit+1)
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			return task.JobPage{}, mapStoreError(scanErr)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return task.JobPage{}, mapStoreError(err)
	}
	page := task.JobPage{}
	if len(jobs) > limit {
		page.HasMore = true
		jobs = jobs[:limit]
	}
	page.Jobs = jobs
	return page, nil
}

// jobAuditEvent 构造任务状态变化的安全审计事件。
func jobAuditEvent(jobID string, actor audit.Actor, action, state, requestID, errorCode string, changes []audit.FieldChange) audit.Event {
	return audit.Event{
		Actor:     actor,
		Action:    action,
		Target:    audit.Target{Type: "job", ID: jobID},
		Outcome:   audit.OutcomeSuccess,
		ErrorCode: errorCode,
		RequestID: requestID,
		TaskID:    jobID,
		Changes:   changes,
	}
}

// stateChange 构造状态变化的脱敏差异。
func stateChange(before, after string) []audit.FieldChange {
	return []audit.FieldChange{{Field: "state", Before: before, After: after}}
}

// nullable 把空字符串映射为 SQL NULL。
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// scanJob 从查询结果扫描任务行。
func scanJob(rows *sql.Rows) (task.Job, error) {
	var (
		job               task.Job
		state             string
		initiatorType     string
		initiatorID       string
		executedBy        sql.NullString
		cancelledByType   sql.NullString
		cancelledByID     sql.NullString
		cancellation      sql.NullString
		cancelRequestedAt sql.NullInt64
		startedAt         sql.NullInt64
		finishedAt        sql.NullInt64
		timeoutSeconds    int
		permission        int
		nextAttemptAt     sql.NullInt64
		mutexKey          sql.NullString
		payload           string
		requestID         sql.NullString
		errorCode         sql.NullString
		failureReason     sql.NullString
		createdAt         int64
		updatedAt         int64
	)
	if err := rows.Scan(
		&job.ID,
		&job.Kind,
		&state,
		&initiatorType,
		&initiatorID,
		&executedBy,
		&cancelledByType,
		&cancelledByID,
		&cancellation,
		&cancelRequestedAt,
		&startedAt,
		&finishedAt,
		&timeoutSeconds,
		&job.Attempt,
		&job.MaxAttempts,
		&permission,
		&nextAttemptAt,
		&mutexKey,
		&payload,
		&requestID,
		&errorCode,
		&failureReason,
		&createdAt,
		&updatedAt,
	); err != nil {
		return task.Job{}, err
	}
	job.State = task.State(state)
	job.Initiator = audit.Actor{Type: audit.ActorKind(initiatorType), ID: initiatorID}
	job.ExecutorID = executedBy.String
	job.PermissionRequired = permission == 1
	if cancelledByType.Valid {
		canceller := audit.Actor{Type: audit.ActorKind(cancelledByType.String), ID: cancelledByID.String}
		job.Canceller = &canceller
	}
	job.CancellationReason = cancellation.String
	job.MutexKey = mutexKey.String
	job.Payload = json.RawMessage(payload)
	job.RequestID = requestID.String
	job.ErrorCode = errorCode.String
	job.FailureReason = failureReason.String
	job.TimeoutSeconds = timeoutSeconds
	job.CreatedAt = time.UnixMilli(createdAt).UTC()
	job.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if cancelRequestedAt.Valid {
		job.CancelRequestedAt = time.UnixMilli(cancelRequestedAt.Int64).UTC()
	}
	if startedAt.Valid {
		job.StartedAt = time.UnixMilli(startedAt.Int64).UTC()
	}
	if nextAttemptAt.Valid {
		job.NextAttemptAt = time.UnixMilli(nextAttemptAt.Int64).UTC()
	}
	if finishedAt.Valid {
		job.FinishedAt = time.UnixMilli(finishedAt.Int64).UTC()
	}
	return job, nil
}

// validateNewJob 校验存储层收到的新任务字段。
func validateNewJob(job task.NewJob) error {
	if err := validateJobID(job.ID); err != nil {
		return err
	}
	if err := validateKind(job.Kind); err != nil {
		return err
	}
	if err := validateTrustedInitiator(job.Initiator); err != nil {
		return err
	}
	if len(job.Payload) == 0 || len(job.Payload) > task.MaxPayloadBytes || !json.Valid(job.Payload) {
		return fmt.Errorf("%w: 任务载荷无效", task.ErrInvalidRequest)
	}
	if job.TimeoutSeconds < task.MinTimeoutSeconds || job.TimeoutSeconds > task.MaxTimeoutSeconds {
		return fmt.Errorf("%w: 任务墙钟上限无效", task.ErrInvalidRequest)
	}
	if job.MaxAttempts < 1 || job.MaxAttempts > task.MaxJobAttempts {
		return fmt.Errorf("%w: 最大尝试次数无效", task.ErrInvalidRequest)
	}
	if job.MutexKey != "" {
		if err := validateSimpleToken("互斥键", job.MutexKey, task.MaxMutexKeyBytes); err != nil {
			return err
		}
	}
	if job.CreatedAt.IsZero() {
		return fmt.Errorf("%w: 任务创建时间不能为空", task.ErrInvalidRequest)
	}
	if job.RequestID != "" {
		if err := validateCorrelation("请求编号", job.RequestID); err != nil {
			return err
		}
	}
	return nil
}

// validateTrustedInitiator 校验发起者类型与稳定 ID，拒绝匿名。
func validateTrustedInitiator(actor audit.Actor) error {
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: %v", task.ErrUntrustedActor, err)
	}
	if actor.Type == audit.ActorAnonymous {
		return fmt.Errorf("%w: 匿名调用者不能创建任务", task.ErrUntrustedActor)
	}
	return nil
}

// validateJobID 校验 job_ 加 32 位十六进制格式。
func validateJobID(id string) error {
	if len(id) != len("job_")+32 || !strings.HasPrefix(id, "job_") {
		return fmt.Errorf("%w: 任务编号格式无效", task.ErrInvalidRequest)
	}
	for i := len("job_"); i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: 任务编号格式无效", task.ErrInvalidRequest)
		}
	}
	return nil
}

// validateKind 校验任务类型标识。
func validateKind(kind string) error {
	return validateSimpleToken("任务类型", kind, task.MaxKindBytes)
}

// validateSimpleToken 校验 ASCII 字母数字与 . _ -。
func validateSimpleToken(name, value string, max int) error {
	if value == "" {
		return fmt.Errorf("%w: %s不能为空", task.ErrInvalidRequest, name)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", task.ErrInvalidRequest, name, max)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", task.ErrInvalidRequest, name)
		}
	}
	return nil
}

// validateCorrelation 校验请求编号。
func validateCorrelation(name, id string) error {
	if len(id) > 64 {
		return fmt.Errorf("%w: %s超过 64 字节", task.ErrInvalidRequest, name)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 {
			if !alnum {
				return fmt.Errorf("%w: %s首字符必须是 ASCII 字母或数字", task.ErrInvalidRequest, name)
			}
			continue
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", task.ErrInvalidRequest, name)
		}
	}
	return nil
}

// mapStoreError 把审计/存储错误统一映射为 task.ErrStoreUnavailable，同时保留
// audit.ErrAuditUnavailable 等底层类别，便于服务层映射 AUDIT_WRITE_FAILED。
func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, task.ErrInvalidRequest) ||
		errors.Is(err, task.ErrUntrustedActor) ||
		errors.Is(err, task.ErrTaskNotFound) ||
		errors.Is(err, task.ErrTaskTerminal) ||
		errors.Is(err, task.ErrTransitionRejected) ||
		errors.Is(err, task.ErrScheduleNotFound) ||
		errors.Is(err, task.ErrScheduleForbidden) ||
		errors.Is(err, task.ErrPermissionCheckRequired) {
		return err
	}
	return fmt.Errorf("%w: %w", task.ErrStoreUnavailable, err)
}

// formatInt 把尝试序号转成审计差异字符串。
func formatInt(value int) string {
	return strconv.Itoa(value)
}
