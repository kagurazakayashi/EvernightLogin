package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

const (
	closeAttemptForRetrySQL = `UPDATE job_attempts SET finished_at_ms=?,outcome='failed',error_code=?
WHERE job_id=? AND attempt=? AND finished_at_ms IS NULL`

	requeueJobSQL = `UPDATE jobs SET state='queued',next_attempt_at_ms=?,error_code=?,failure_reason=?,
updated_at_ms=? WHERE id=? AND state='running' AND attempt=?`

	selectAttemptsSQL = `SELECT job_id,attempt,started_at_ms,finished_at_ms,outcome,error_code
FROM job_attempts WHERE job_id=? ORDER BY attempt`
)

// Retry 把一次可重试失败的任务重新排队：关闭本次尝试历史、按退避时间设置
// next_attempt_at_ms、回到 queued，并在同一事务内写 jobs.retry_scheduled 审计。
//
// 只有任务仍处于 running 且尝试序号一致时才接受；取消请求已接受（
// cancel_requested）或已进入终态时返回 (Job{}, false, nil)，调用方必须读取真实
// 状态并写取消终态，不能把已取消任务重试。
func (s *Store) Retry(ctx context.Context, command task.RetryCommand) (task.Job, bool, error) {
	if command.Attempt < 1 {
		return task.Job{}, false, fmt.Errorf("%w: 尝试序号无效", task.ErrInvalidRequest)
	}
	if err := validateJobID(command.JobID); err != nil {
		return task.Job{}, false, err
	}
	if err := validateSimpleToken("执行器标识", command.ExecutorID, audit.MaxActorIDBytes); err != nil {
		return task.Job{}, false, err
	}
	if command.NextAttemptAt.IsZero() || command.Now.IsZero() {
		return task.Job{}, false, fmt.Errorf("%w: 重试时间不能为空", task.ErrInvalidRequest)
	}
	if len(command.FailureReason) > task.MaxReasonBytes {
		return task.Job{}, false, fmt.Errorf("%w: 失败说明超过 %d 字节", task.ErrInvalidRequest, task.MaxReasonBytes)
	}
	nowMS := command.Now.UTC().UnixMilli()
	nextMS := command.NextAttemptAt.UTC().UnixMilli()
	event := jobAuditEvent(command.JobID,
		audit.Actor{Type: audit.ActorSystem, ID: command.ExecutorID},
		"jobs.retry_scheduled", string(task.StateQueued), "", command.ErrorCode,
		[]audit.FieldChange{
			{Field: "attempt", Before: formatInt(command.Attempt), After: formatInt(command.Attempt)},
			{Field: "next_attempt_at", Before: "", After: command.NextAttemptAt.UTC().Format(time.RFC3339Nano)},
		})
	change := func(txCtx context.Context, tx audit.Tx) error {
		result, err := tx.ExecContext(txCtx, closeAttemptForRetrySQL,
			nowMS, nullable(command.ErrorCode), command.JobID, command.Attempt)
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
		result, err = tx.ExecContext(txCtx, requeueJobSQL,
			nextMS,
			nullable(command.ErrorCode),
			nullable(command.FailureReason),
			nowMS,
			command.JobID,
			command.Attempt,
		)
		if err != nil {
			return err
		}
		affected, err = result.RowsAffected()
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
		return task.Job{}, false, mapStoreError(err)
	}
	if err := s.auditStore.RunCritical(ctx, prepared, change); err != nil {
		if errors.Is(err, task.ErrTransitionRejected) {
			return task.Job{}, false, nil
		}
		return task.Job{}, false, mapStoreError(err)
	}
	job, err := s.load(ctx, command.JobID)
	if err != nil {
		return task.Job{}, false, err
	}
	return job, true, nil
}

// Attempts 返回任务的尝试历史；任务不存在返回 ErrTaskNotFound。
func (s *Store) Attempts(ctx context.Context, jobID string) ([]task.Attempt, error) {
	if err := validateJobID(jobID); err != nil {
		return nil, err
	}
	if _, found, err := s.loadWithFound(ctx, jobID); err != nil {
		return nil, err
	} else if !found {
		return nil, task.ErrTaskNotFound
	}
	rows, err := s.raw.QueryContext(ctx, selectAttemptsSQL, jobID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	defer rows.Close()
	attempts := make([]task.Attempt, 0, 4)
	for rows.Next() {
		var (
			attempt    task.Attempt
			startedAt  int64
			finishedAt sql.NullInt64
			outcome    sql.NullString
			errorCode  sql.NullString
		)
		if err := rows.Scan(&attempt.JobID, &attempt.Attempt, &startedAt, &finishedAt, &outcome, &errorCode); err != nil {
			return nil, mapStoreError(err)
		}
		attempt.StartedAt = time.UnixMilli(startedAt).UTC()
		if finishedAt.Valid {
			attempt.FinishedAt = time.UnixMilli(finishedAt.Int64).UTC()
		}
		attempt.Outcome = outcome.String
		attempt.ErrorCode = errorCode.String
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, mapStoreError(err)
	}
	return attempts, nil
}
