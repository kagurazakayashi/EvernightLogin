// Package sqlite 实现 internal/userbatch.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0039_user_batch.sql 创建；本包不执行迁移、不拥有数据库连接。
// 幂等键唯一约束兼作并发单赢家；逐行结果 (job_id,row_number) 主键使重启续跑可跳过
// 已处理行；导入文件内容在任务终态后由服务清空。
package sqlite

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
)

// Store 是 userbatch.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, userbatch.ErrOptionsInvalid
	}
	return &Store{store: store}, nil
}

var _ userbatch.Store = (*Store)(nil)

const jobColumns = `id,kind,idempotency_key,request_digest,owner_type,owner_id,scope_id,
state,total_rows,created_count,skipped_count,conflict_count,failed_count,denied_count,
truncated,input_csv,export_path,export_sha256,export_rows,task_id,error_code,request_id,
created_at_ms,updated_at_ms,COALESCE(finished_at_ms,0)`

const (
	insertJobSQL = `INSERT INTO user_batch_jobs(
id,kind,idempotency_key,request_digest,owner_type,owner_id,scope_id,state,total_rows,
created_count,skipped_count,conflict_count,failed_count,denied_count,truncated,
input_csv,export_path,export_sha256,export_rows,task_id,error_code,request_id,
created_at_ms,updated_at_ms,finished_at_ms
) VALUES(?,?,?,?,?,?,?, 'queued',0,0,0,0,0,0,0,?,'',NULL,0,'', '', '',?,?,NULL)`
	selectJobSQL      = `SELECT ` + jobColumns + ` FROM user_batch_jobs WHERE id=?`
	selectJobByKeySQL = `SELECT ` + jobColumns + ` FROM user_batch_jobs WHERE idempotency_key=?`
	listJobsBaseSQL   = `SELECT ` + jobColumns + ` FROM user_batch_jobs`
	markRunningSQL    = `UPDATE user_batch_jobs SET state='running',updated_at_ms=?
WHERE id=? AND state='queued'`
	finishJobSQL = `UPDATE user_batch_jobs SET state=?,total_rows=?,created_count=?,
skipped_count=?,conflict_count=?,failed_count=?,denied_count=?,truncated=?,
export_path=?,export_sha256=?,export_rows=?,error_code=?,updated_at_ms=?,
finished_at_ms=? WHERE id=? AND state IN('queued','running')`
	clearInputSQL = `UPDATE user_batch_jobs SET input_csv=NULL WHERE id=?`
	setTaskSQL    = `UPDATE user_batch_jobs SET task_id=?,updated_at_ms=? WHERE id=?`
	requeueJobSQL = `UPDATE user_batch_jobs SET state='queued',updated_at_ms=?,
finished_at_ms=NULL WHERE id=? AND state='failed'`
	hasRowSQL    = `SELECT COUNT(*) FROM user_batch_rows WHERE job_id=? AND row_number=?`
	insertRowSQL = `INSERT INTO user_batch_rows(
job_id,row_number,action,error_code,reason_code,username_normalized,user_id,created_at_ms
) VALUES(?,?,?,?,?,?,?,?)`
	countRowsSQL = `SELECT action,COUNT(*) FROM user_batch_rows WHERE job_id=? GROUP BY action`
	listRowsSQL  = `SELECT job_id,row_number,action,error_code,reason_code,
username_normalized,user_id,created_at_ms FROM user_batch_rows
WHERE job_id=? ORDER BY row_number LIMIT ? OFFSET ?`
	failInterruptedSQL = `UPDATE user_batch_jobs SET state='failed',error_code=?,
updated_at_ms=?,finished_at_ms=? WHERE id=? AND state='running'`
	cleanupInputsSQL = `UPDATE user_batch_jobs SET input_csv=NULL
WHERE input_csv IS NOT NULL AND state='failed' AND updated_at_ms<?`
)

// CreateJob 创建任务；幂等键冲突时返回既有记录与 created=false。
func (s *Store) CreateJob(ctx context.Context, job userbatch.JobRecord,
	digest [32]byte, input []byte) (userbatch.JobRecord, bool, error) {
	if _, err := s.store.ExecContext(ctx, insertJobSQL, job.ID, string(job.Kind),
		job.IdempotencyKey, digest[:], string(job.OwnerType), job.OwnerID, job.ScopeID,
		nullableBytes(input), job.CreatedAt.UTC().UnixMilli(),
		job.UpdatedAt.UTC().UnixMilli()); err != nil {
		// 唯一约束错误类型由驱动包装方式决定：按幂等键回查判断是否重复。
		existing, found, lookupErr := s.getByIdempotencyKey(ctx, job.IdempotencyKey)
		if lookupErr != nil {
			return userbatch.JobRecord{}, false, lookupErr
		}
		if found {
			return existing, false, nil
		}
		return userbatch.JobRecord{}, false, userbatch.ErrStoreUnavailable
	}
	return job, true, nil
}

func (s *Store) getByIdempotencyKey(ctx context.Context,
	key string) (userbatch.JobRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectJobByKeySQL, key)
	if err != nil {
		return userbatch.JobRecord{}, false, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return userbatch.JobRecord{}, false, rows.Err()
	}
	record, scanErr := scanJob(rows)
	if scanErr != nil {
		return userbatch.JobRecord{}, false, userbatch.ErrStoreUnavailable
	}
	return record, true, nil
}

// GetJob 读取任务。
func (s *Store) GetJob(ctx context.Context, jobID string) (userbatch.JobRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectJobSQL, jobID)
	if err != nil {
		return userbatch.JobRecord{}, false, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return userbatch.JobRecord{}, false, rows.Err()
	}
	record, scanErr := scanJob(rows)
	if scanErr != nil {
		return userbatch.JobRecord{}, false, userbatch.ErrStoreUnavailable
	}
	return record, true, nil
}

// ListJobs 分页查询任务。
func (s *Store) ListJobs(ctx context.Context,
	query userbatch.ListJobsQuery) ([]userbatch.JobRecord, error) {
	statement := listJobsBaseSQL
	args := make([]any, 0, 4)
	conditions := make([]string, 0, 3)
	if query.Kind != "" {
		conditions = append(conditions, "kind=?")
		args = append(args, string(query.Kind))
	}
	if query.State != "" {
		conditions = append(conditions, "state=?")
		args = append(args, string(query.State))
	}
	if query.OwnerType != "" {
		conditions = append(conditions, "owner_type=?")
		args = append(args, string(query.OwnerType))
	}
	if query.OwnerID != "" {
		conditions = append(conditions, "owner_id=?")
		args = append(args, query.OwnerID)
	}
	if len(conditions) > 0 {
		statement += " WHERE "
		for index, condition := range conditions {
			if index > 0 {
				statement += " AND "
			}
			statement += condition
		}
	}
	limit := query.Limit
	if limit <= 0 || limit > userbatch.MaxListLimit {
		limit = userbatch.MaxListLimit
	}
	statement += " ORDER BY created_at_ms DESC,id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []userbatch.JobRecord
	for rows.Next() {
		record, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, userbatch.ErrStoreUnavailable
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// MarkRunning 条件迁移 queued→running。
func (s *Store) MarkRunning(ctx context.Context, jobID string, now time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx, markRunningSQL, now.UTC().UnixMilli(), jobID)
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// FinishJob 条件写入终态与汇总计数。
func (s *Store) FinishJob(ctx context.Context, command userbatch.FinishJobCommand) (bool, error) {
	result, err := s.store.ExecContext(ctx, finishJobSQL, string(command.State),
		command.TotalRows, command.CreatedRows, command.SkippedRows, command.ConflictRows,
		command.FailedRows, command.DeniedRows, boolToInt(command.Truncated),
		command.ExportPath, nullableBytes(command.ExportSHA256), command.ExportRows,
		string(command.ErrorCode), command.Now.UTC().UnixMilli(),
		command.Now.UTC().UnixMilli(), command.JobID)
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// ClearInput 清空导入文件内容（终态后调用）。
func (s *Store) ClearInput(ctx context.Context, jobID string) error {
	if _, err := s.store.ExecContext(ctx, clearInputSQL, jobID); err != nil {
		return userbatch.ErrStoreUnavailable
	}
	return nil
}

// SetTask 关联任务 ID（创建任务入队后调用）。
func (s *Store) SetTask(ctx context.Context, jobID, taskID string, now time.Time) error {
	if _, err := s.store.ExecContext(ctx, setTaskSQL, taskID, now.UTC().UnixMilli(), jobID); err != nil {
		return userbatch.ErrStoreUnavailable
	}
	return nil
}

// Requeue 把 failed 条件迁移回 queued。
func (s *Store) Requeue(ctx context.Context, jobID string, now time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx, requeueJobSQL, now.UTC().UnixMilli(), jobID)
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// HasRow 报告某行是否已处理（重启续跑跳过）。
func (s *Store) HasRow(ctx context.Context, jobID string, rowNumber int) (bool, error) {
	rows, err := s.store.QueryContext(ctx, hasRowSQL, jobID, rowNumber)
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return false, rows.Err()
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	return count > 0, nil
}

// InsertRow 插入逐行结果；重复 (job_id,row_number) 返回 inserted=false（续跑幂等）。
func (s *Store) InsertRow(ctx context.Context, row userbatch.RowRecord) (bool, error) {
	_, err := s.store.ExecContext(ctx, insertRowSQL, row.JobID, row.RowNumber,
		string(row.Action), row.ErrorCode, row.ReasonCode, row.UsernameNormalized,
		row.UserID, row.CreatedAt.UTC().UnixMilli())
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, userbatch.ErrStoreUnavailable
	}
	return true, nil
}

// CountRows 汇总各动作计数。
func (s *Store) CountRows(ctx context.Context, jobID string) (map[userbatch.RowAction]int, error) {
	rows, err := s.store.QueryContext(ctx, countRowsSQL, jobID)
	if err != nil {
		return nil, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	counts := make(map[userbatch.RowAction]int)
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			return nil, userbatch.ErrStoreUnavailable
		}
		counts[userbatch.RowAction(action)] = count
	}
	return counts, rows.Err()
}

// ListRows 按 row_number 分页列出逐行结果。
func (s *Store) ListRows(ctx context.Context, jobID string, offset, limit int) ([]userbatch.RowRecord, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > userbatch.MaxListLimit {
		limit = userbatch.MaxListLimit
	}
	rows, err := s.store.QueryContext(ctx, listRowsSQL, jobID, limit, offset)
	if err != nil {
		return nil, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	var records []userbatch.RowRecord
	for rows.Next() {
		var (
			record    userbatch.RowRecord
			action    string
			createdMS int64
		)
		if err := rows.Scan(&record.JobID, &record.RowNumber, &action,
			&record.ErrorCode, &record.ReasonCode, &record.UsernameNormalized,
			&record.UserID, &createdMS); err != nil {
			return nil, userbatch.ErrStoreUnavailable
		}
		record.Action = userbatch.RowAction(action)
		record.CreatedAt = time.UnixMilli(createdMS).UTC()
		records = append(records, record)
	}
	return records, rows.Err()
}

// FailInterrupted 把 running 条件迁移为 failed（崩溃遗留任务对账）。
func (s *Store) FailInterrupted(ctx context.Context, jobID string,
	code userbatch.ErrorCode, now time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx, failInterruptedSQL, string(code),
		now.UTC().UnixMilli(), now.UTC().UnixMilli(), jobID)
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, userbatch.ErrStoreUnavailable
	}
	return affected == 1, nil
}

// CleanupInputs 清理早于 before 的失败任务导入文件内容。
func (s *Store) CleanupInputs(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.store.ExecContext(ctx, cleanupInputsSQL, before.UTC().UnixMilli())
	if err != nil {
		return 0, userbatch.ErrStoreUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, userbatch.ErrStoreUnavailable
	}
	return affected, nil
}

// ===== 扫描辅助 =====

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(rows rowScanner) (userbatch.JobRecord, error) {
	var (
		record     userbatch.JobRecord
		kind       string
		key        string
		digest     []byte
		ownerType  string
		state      string
		truncated  int
		input      []byte
		exportHash []byte
		errorCode  string
		createdMS  int64
		updatedMS  int64
		finishedMS int64
	)
	if err := rows.Scan(&record.ID, &kind, &key, &digest, &ownerType, &record.OwnerID,
		&record.ScopeID, &state, &record.TotalRows, &record.CreatedCount,
		&record.SkippedCount, &record.ConflictCount, &record.FailedCount,
		&record.DeniedCount, &truncated, &input, &record.ExportPath, &exportHash,
		&record.ExportRows, &record.TaskID, &errorCode, &record.RequestID,
		&createdMS, &updatedMS, &finishedMS); err != nil {
		return userbatch.JobRecord{}, err
	}
	record.Kind = userbatch.Kind(kind)
	record.State = userbatch.JobState(state)
	record.OwnerType = audit.ActorKind(ownerType)
	record.Truncated = truncated != 0
	record.InputCSV = input
	record.InputAvailable = len(input) > 0
	record.ErrorCode = userbatch.ErrorCode(errorCode)
	if len(digest) == 32 {
		copy(record.RequestDigest[:], digest)
	}
	if len(exportHash) == 32 {
		record.ExportSHA256 = hex.EncodeToString(exportHash)
	}
	record.CreatedAt = time.UnixMilli(createdMS).UTC()
	record.UpdatedAt = time.UnixMilli(updatedMS).UTC()
	if finishedMS > 0 {
		record.FinishedAt = time.UnixMilli(finishedMS).UTC()
	}
	record.IdempotencyKey = key
	return record, nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	return errors.Is(err, storage.ErrUniqueViolation)
}

// selectUserByNormalizedSQL 读取既有账户快照（含 is_root）用于导入重复匹配。
const selectUserByNormalizedSQL = `SELECT id,username,username_normalized,nickname,
biography,language,timezone,status,row_version,security_version,created_at_ms,
updated_at_ms,is_root FROM users WHERE username_normalized=?`

// LookupUserByNormalizedUsername 按规范化用户名读取既有账户。
func (s *Store) LookupUserByNormalizedUsername(ctx context.Context,
	normalized string) (userbatch.ExistingUser, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserByNormalizedSQL, normalized)
	if err != nil {
		return userbatch.ExistingUser{}, false, userbatch.ErrStoreUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return userbatch.ExistingUser{}, false, rows.Err()
	}
	var (
		existing  userbatch.ExistingUser
		status    string
		createdMS int64
		updatedMS int64
		isRoot    int
	)
	if err := rows.Scan(&existing.User.ID, &existing.User.Username,
		&existing.User.UsernameNormalized, &existing.User.Nickname,
		&existing.User.Biography, &existing.User.Language, &existing.User.Timezone,
		&status, &existing.User.RowVersion, &existing.User.SecurityVersion,
		&createdMS, &updatedMS, &isRoot); err != nil {
		return userbatch.ExistingUser{}, false, userbatch.ErrStoreUnavailable
	}
	existing.User.Status = accountStatus(status)
	existing.User.CreatedAt = time.UnixMilli(createdMS).UTC()
	existing.User.UpdatedAt = time.UnixMilli(updatedMS).UTC()
	existing.IsRoot = isRoot != 0
	return existing, true, nil
}

// accountStatus 把数据库状态文本映射为 account.Status（保持字符串值一致）。
func accountStatus(value string) account.Status { return account.Status(value) }
