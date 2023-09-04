// Package sqlite 实现 internal/manualrecovery.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0027_manual_recovery.sql 创建；本包不执行迁移、不拥有数据库
// 连接、不保存证据明文/密码/MFA 秘密或凭证。状态迁移与执行权分配使用条件更新，
// 保证并发审批/执行只有一方成功。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const insertRequestSQL = `INSERT INTO manual_recovery_requests(
id,target_user_id,initiator_user_id,operation_type,status,verification_basis,
verification_reference,evidence_digest,reason,delivery_channel,delivery_fingerprint,
target_security_version,target_high_privilege,content_digest,support_case_id,expires_at_ms,
closed_reason,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'pending_approval',?,?,?,?,?,?,?,?,?,?,?,NULL,1,?,?)`

const selectRequestSQL = `SELECT id,target_user_id,initiator_user_id,operation_type,status,
verification_basis,verification_reference,evidence_digest,reason,delivery_channel,
delivery_fingerprint,target_security_version,target_high_privilege,content_digest,
COALESCE(support_case_id,''),expires_at_ms,COALESCE(closed_reason,''),row_version,
created_at_ms,updated_at_ms
FROM manual_recovery_requests WHERE id=?`

const transitionRequestSQL = `UPDATE manual_recovery_requests
SET status=?,closed_reason=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND status=?`

const insertApprovalSQL = `INSERT INTO manual_recovery_approvals(
id,request_id,approver_user_id,operation_type,content_digest,status,approved_at_ms,
not_before_ms,expires_at_ms,finished_at_ms,invalidated_reason,row_version)
VALUES(?,?,?,?,?,'active',?,?,?,NULL,NULL,1)`

const selectActiveApprovalSQL = `SELECT id,request_id,approver_user_id,operation_type,
content_digest,status,approved_at_ms,not_before_ms,expires_at_ms,
COALESCE(finished_at_ms,0),COALESCE(invalidated_reason,''),row_version
FROM manual_recovery_approvals WHERE request_id=? AND status='active' LIMIT 1`

const selectLatestApprovalSQL = `SELECT id,request_id,approver_user_id,operation_type,
content_digest,status,approved_at_ms,not_before_ms,expires_at_ms,
COALESCE(finished_at_ms,0),COALESCE(invalidated_reason,''),row_version
FROM manual_recovery_approvals WHERE request_id=?
ORDER BY approved_at_ms DESC, row_version DESC LIMIT 1`

const approverHistorySQL = `SELECT COUNT(*) FROM manual_recovery_approvals
WHERE request_id=? AND approver_user_id=?`

const finishApprovalSQL = `UPDATE manual_recovery_approvals
SET status=?,finished_at_ms=?,invalidated_reason=?,row_version=row_version+1
WHERE id=? AND status='active'`

const claimRequestSQL = `UPDATE manual_recovery_requests
SET status='executing',row_version=row_version+1,updated_at_ms=?
WHERE id=? AND status='approved' AND row_version=? AND expires_at_ms>?`

const insertExecutionSQL = `INSERT INTO manual_recovery_executions(
id,request_id,approval_id,executor_user_id,operation_type,status,sessions_revoked,
factors_reset,reset_credential_issued,notification_state,error_code,started_at_ms,finished_at_ms)
VALUES(?,?,?,?,?,'running',0,0,0,'pending',NULL,?,NULL)`

const selectExecutionSQL = `SELECT id,request_id,approval_id,executor_user_id,operation_type,
status,sessions_revoked,factors_reset,reset_credential_issued,notification_state,
COALESCE(error_code,''),started_at_ms,COALESCE(finished_at_ms,0)
FROM manual_recovery_executions WHERE request_id=? ORDER BY started_at_ms DESC LIMIT 1`

const finishExecutionSQL = `UPDATE manual_recovery_executions
SET status=?,sessions_revoked=?,factors_reset=?,reset_credential_issued=?,
notification_state=?,error_code=?,finished_at_ms=?
WHERE id=? AND status='running'`

const finishRequestSQL = `UPDATE manual_recovery_requests
SET status=?,closed_reason=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND status='executing'`

const finishApprovalForExecutionSQL = `UPDATE manual_recovery_approvals
SET status=?,finished_at_ms=?,row_version=row_version+1
WHERE id=? AND status='active'`

const setNotificationSQL = `UPDATE manual_recovery_executions
SET notification_state=? WHERE request_id=? AND status='succeeded'`

// Store 是 manualrecovery.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", manualrecovery.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ manualrecovery.Store = (*Store)(nil)

// storeError 把驱动错误包装为稳定领域错误，避免原始 SQL 文本外泄。
func storeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s失败", manualrecovery.ErrStoreUnavailable, operation)
}

// InsertRequestTx 在审计事务内创建申请。
func (s *Store) InsertRequestTx(ctx context.Context, tx audit.Tx, record manualrecovery.RequestRecord) error {
	_, err := tx.ExecContext(ctx, insertRequestSQL,
		record.ID, record.TargetUserID, record.InitiatorUserID, string(record.Operation),
		string(record.VerificationBasis), record.VerificationReference, record.EvidenceDigest,
		record.Reason, string(record.Delivery), record.DeliveryFingerprint,
		record.TargetSecurityVersion, boolInt(record.TargetHighPrivilege), record.ContentDigest,
		nullString(record.SupportCaseID),
		record.ExpiresAt.UnixMilli(), record.CreatedAt.UnixMilli(), record.UpdatedAt.UnixMilli())
	if err != nil {
		return storeError("创建人工恢复申请", err)
	}
	return nil
}

// GetRequest 按 ID 读取申请。
func (s *Store) GetRequest(ctx context.Context, requestID string) (manualrecovery.RequestRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRequestSQL, requestID)
	if err != nil {
		return manualrecovery.RequestRecord{}, false, storeError("读取人工恢复申请", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return manualrecovery.RequestRecord{}, false, storeError("读取人工恢复申请", err)
		}
		return manualrecovery.RequestRecord{}, false, nil
	}
	var record manualrecovery.RequestRecord
	var operation, status, basis, delivery string
	var highPrivilege int
	var expiresMS, createdMS, updatedMS int64
	if err := rows.Scan(&record.ID, &record.TargetUserID, &record.InitiatorUserID, &operation,
		&status, &basis, &record.VerificationReference, &record.EvidenceDigest, &record.Reason,
		&delivery, &record.DeliveryFingerprint, &record.TargetSecurityVersion, &highPrivilege,
		&record.ContentDigest, &record.SupportCaseID, &expiresMS, &record.ClosedReason,
		&record.RowVersion, &createdMS, &updatedMS); err != nil {
		return manualrecovery.RequestRecord{}, false, storeError("读取人工恢复申请", err)
	}
	record.Operation = manualrecovery.OperationType(operation)
	record.Status = manualrecovery.Status(status)
	record.VerificationBasis = manualrecovery.VerificationBasis(basis)
	record.Delivery = manualrecovery.DeliveryChannel(delivery)
	record.TargetHighPrivilege = highPrivilege == 1
	record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	record.CreatedAt = time.UnixMilli(createdMS).UTC()
	record.UpdatedAt = time.UnixMilli(updatedMS).UTC()
	return record, true, nil
}

// ListRequests 按状态（可选）与发起者（可选）列出申请；供 188 待办列表只读使用。
func (s *Store) ListRequests(ctx context.Context, statuses []manualrecovery.Status,
	initiatorUserID string, offset, limit int) ([]manualrecovery.RequestRecord, bool, error) {
	if offset < 0 || limit <= 0 {
		return nil, false, storeError("列出入工恢复申请", manualrecovery.ErrInvalidRequest)
	}
	query := `SELECT id,target_user_id,initiator_user_id,operation_type,status,
verification_basis,verification_reference,evidence_digest,reason,delivery_channel,
delivery_fingerprint,target_security_version,target_high_privilege,content_digest,
COALESCE(support_case_id,''),expires_at_ms,COALESCE(closed_reason,''),row_version,
created_at_ms,updated_at_ms
FROM manual_recovery_requests WHERE 1=1`
	args := make([]any, 0, len(statuses)+3)
	if len(statuses) > 0 {
		query += ` AND status IN (?`
		args = append(args, string(statuses[0]))
		for _, status := range statuses[1:] {
			query += `,?`
			args = append(args, string(status))
		}
		query += `)`
	}
	if initiatorUserID != "" {
		query += ` AND initiator_user_id=?`
		args = append(args, initiatorUserID)
	}
	query += ` ORDER BY created_at_ms DESC,id LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, storeError("列出入工恢复申请", err)
	}
	defer rows.Close()
	records := make([]manualrecovery.RequestRecord, 0, limit)
	for rows.Next() {
		var record manualrecovery.RequestRecord
		var operation, status, basis, delivery string
		var highPrivilege int
		var expiresMS, createdMS, updatedMS int64
		if err := rows.Scan(&record.ID, &record.TargetUserID, &record.InitiatorUserID, &operation,
			&status, &basis, &record.VerificationReference, &record.EvidenceDigest, &record.Reason,
			&delivery, &record.DeliveryFingerprint, &record.TargetSecurityVersion, &highPrivilege,
			&record.ContentDigest, &record.SupportCaseID, &expiresMS, &record.ClosedReason,
			&record.RowVersion, &createdMS, &updatedMS); err != nil {
			return nil, false, storeError("列出入工恢复申请", err)
		}
		record.Operation = manualrecovery.OperationType(operation)
		record.Status = manualrecovery.Status(status)
		record.VerificationBasis = manualrecovery.VerificationBasis(basis)
		record.Delivery = manualrecovery.DeliveryChannel(delivery)
		record.TargetHighPrivilege = highPrivilege == 1
		record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
		record.CreatedAt = time.UnixMilli(createdMS).UTC()
		record.UpdatedAt = time.UnixMilli(updatedMS).UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, storeError("列出入工恢复申请", err)
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	return records, hasMore, nil
}

// TransitionRequestTx 条件迁移申请状态。
func (s *Store) TransitionRequestTx(ctx context.Context, tx audit.Tx, requestID string,
	from, to manualrecovery.Status, closedReason string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, transitionRequestSQL, string(to), nullString(closedReason),
		now.UnixMilli(), requestID, string(from))
	if err != nil {
		return false, storeError("迁移人工恢复申请状态", err)
	}
	return rowsAffected(result, "迁移人工恢复申请状态")
}

// InsertApprovalTx 在审计事务内插入批准。
func (s *Store) InsertApprovalTx(ctx context.Context, tx audit.Tx, record manualrecovery.ApprovalRecord) error {
	_, err := tx.ExecContext(ctx, insertApprovalSQL, record.ID, record.RequestID,
		record.ApproverUserID, string(record.Operation), record.ContentDigest,
		record.ApprovedAt.UnixMilli(), record.NotBefore.UnixMilli(), record.ExpiresAt.UnixMilli())
	if err != nil {
		if isUniqueViolation(err) {
			return manualrecovery.ErrExecutionConflict
		}
		return storeError("创建人工恢复批准", err)
	}
	return nil
}

// GetActiveApproval 返回请求当前 active 批准。
func (s *Store) GetActiveApproval(ctx context.Context, requestID string) (manualrecovery.ApprovalRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectActiveApprovalSQL, requestID)
	if err != nil {
		return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
		}
		return manualrecovery.ApprovalRecord{}, false, nil
	}
	var record manualrecovery.ApprovalRecord
	var operation, status string
	var approvedMS, notBeforeMS, expiresMS, finishedMS int64
	if err := rows.Scan(&record.ID, &record.RequestID, &record.ApproverUserID, &operation,
		&record.ContentDigest, &status, &approvedMS, &notBeforeMS, &expiresMS,
		&finishedMS, &record.InvalidatedReason, &record.RowVersion); err != nil {
		return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
	}
	record.Operation = manualrecovery.OperationType(operation)
	record.Status = manualrecovery.ApprovalStatus(status)
	record.ApprovedAt = time.UnixMilli(approvedMS).UTC()
	record.NotBefore = time.UnixMilli(notBeforeMS).UTC()
	record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if finishedMS != 0 {
		record.FinishedAt = time.UnixMilli(finishedMS).UTC()
	}
	return record, true, nil
}

// GetLatestApproval 返回请求最近一次批准（含历史状态）；只读查询。
func (s *Store) GetLatestApproval(ctx context.Context, requestID string) (manualrecovery.ApprovalRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectLatestApprovalSQL, requestID)
	if err != nil {
		return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
		}
		return manualrecovery.ApprovalRecord{}, false, nil
	}
	var record manualrecovery.ApprovalRecord
	var operation, status string
	var approvedMS, notBeforeMS, expiresMS, finishedMS int64
	if err := rows.Scan(&record.ID, &record.RequestID, &record.ApproverUserID, &operation,
		&record.ContentDigest, &status, &approvedMS, &notBeforeMS, &expiresMS,
		&finishedMS, &record.InvalidatedReason, &record.RowVersion); err != nil {
		return manualrecovery.ApprovalRecord{}, false, storeError("读取人工恢复批准", err)
	}
	record.Operation = manualrecovery.OperationType(operation)
	record.Status = manualrecovery.ApprovalStatus(status)
	record.ApprovedAt = time.UnixMilli(approvedMS).UTC()
	record.NotBefore = time.UnixMilli(notBeforeMS).UTC()
	record.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if finishedMS != 0 {
		record.FinishedAt = time.UnixMilli(finishedMS).UTC()
	}
	return record, true, nil
}

// ApproverHistory 报告指定用户是否曾是该请求的审批人（含已消费/失效）。
func (s *Store) ApproverHistory(ctx context.Context, requestID, approverUserID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, approverHistorySQL, requestID, approverUserID)
	if err != nil {
		return false, storeError("读取人工恢复审批历史", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, nil
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, storeError("读取人工恢复审批历史", err)
	}
	return count > 0, nil
}

// FinishApprovalTx 条件结束 active 批准。
func (s *Store) FinishApprovalTx(ctx context.Context, tx audit.Tx, approvalID string,
	status manualrecovery.ApprovalStatus, reason string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, finishApprovalSQL, string(status), now.UnixMilli(),
		nullString(reason), approvalID)
	if err != nil {
		return false, storeError("结束人工恢复批准", err)
	}
	return rowsAffected(result, "结束人工恢复批准")
}

// ClaimExecutionTx 条件分配唯一执行权并创建 running 执行记录。
func (s *Store) ClaimExecutionTx(ctx context.Context, tx audit.Tx, record manualrecovery.RequestRecord,
	execution manualrecovery.ExecutionRecord, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, claimRequestSQL, now.UnixMilli(), record.ID, record.RowVersion, now.UnixMilli())
	if err != nil {
		return false, storeError("占用人工恢复执行权", err)
	}
	claimed, err := rowsAffected(result, "占用人工恢复执行权")
	if err != nil || !claimed {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, insertExecutionSQL, execution.ID, execution.RequestID,
		execution.ApprovalID, execution.ExecutorUserID, string(execution.Operation),
		execution.StartedAt.UnixMilli()); err != nil {
		return false, storeError("创建人工恢复执行记录", err)
	}
	return true, nil
}

// GetExecution 按请求读取执行记录。
func (s *Store) GetExecution(ctx context.Context, requestID string) (manualrecovery.ExecutionRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectExecutionSQL, requestID)
	if err != nil {
		return manualrecovery.ExecutionRecord{}, false, storeError("读取人工恢复执行", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return manualrecovery.ExecutionRecord{}, false, nil
	}
	var record manualrecovery.ExecutionRecord
	var operation string
	var factorsReset, credentialIssued int
	var startedMS, finishedMS int64
	if err := rows.Scan(&record.ID, &record.RequestID, &record.ApprovalID,
		&record.ExecutorUserID, &operation, &record.Status, &record.SessionsRevoked,
		&factorsReset, &credentialIssued, &record.NotificationState, &record.ErrorCode,
		&startedMS, &finishedMS); err != nil {
		return manualrecovery.ExecutionRecord{}, false, storeError("读取人工恢复执行", err)
	}
	record.Operation = manualrecovery.OperationType(operation)
	record.FactorsReset = factorsReset == 1
	record.ResetCredentialIssued = credentialIssued == 1
	record.StartedAt = time.UnixMilli(startedMS).UTC()
	if finishedMS != 0 {
		record.FinishedAt = time.UnixMilli(finishedMS).UTC()
	}
	return record, true, nil
}

// FinishExecutionTx 在同一事务内条件完成执行、请求与批准。
func (s *Store) FinishExecutionTx(ctx context.Context, tx audit.Tx, requestID, executionID, approvalID string,
	executionStatus string, requestStatus manualrecovery.Status, approvalStatus manualrecovery.ApprovalStatus,
	outcome manualrecovery.ExecutionOutcome, errorCode, notificationState string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, finishExecutionSQL, executionStatus, outcome.SessionsRevoked,
		boolInt(outcome.FactorsReset), boolInt(outcome.ResetCredentialIssued), notificationState,
		nullString(errorCode), now.UnixMilli(), executionID)
	if err != nil {
		return false, storeError("完成人工恢复执行", err)
	}
	finished, err := rowsAffected(result, "完成人工恢复执行")
	if err != nil || !finished {
		return false, err
	}
	result, err = tx.ExecContext(ctx, finishRequestSQL, string(requestStatus),
		terminationReason(requestStatus), now.UnixMilli(), requestID)
	if err != nil {
		return false, storeError("结束人工恢复申请", err)
	}
	requestFinished, err := rowsAffected(result, "结束人工恢复申请")
	if err != nil || !requestFinished {
		return false, err
	}
	result, err = tx.ExecContext(ctx, finishApprovalForExecutionSQL, string(approvalStatus), now.UnixMilli(), approvalID)
	if err != nil {
		return false, storeError("结束人工恢复批准", err)
	}
	approvalFinished, err := rowsAffected(result, "结束人工恢复批准")
	if err != nil || !approvalFinished {
		return false, err
	}
	return true, nil
}

// SetNotificationState 在独立事务中记录通知结果。
func (s *Store) SetNotificationState(ctx context.Context, requestID, state string) error {
	if _, err := s.store.ExecContext(ctx, setNotificationSQL, state, requestID); err != nil {
		return storeError("记录人工恢复通知状态", err)
	}
	return nil
}

// terminationReason 返回请求结束原因码（只用于审计/排障，不含秘密）。
func terminationReason(status manualrecovery.Status) string {
	if status == manualrecovery.StatusFailed {
		return "execution_failed"
	}
	return ""
}

// rowsAffected 把条件更新结果转换为“恰好一行生效”。
func rowsAffected(result sql.Result, operation string) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError(operation, err)
	}
	return affected == 1, nil
}

// nullString 把空字符串写成 NULL。
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// boolInt 把布尔值转换为 SQLite 整数。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// isUniqueViolation 识别唯一约束冲突（同一请求并发批准）。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed") || strings.Contains(message, "constraint failed")
}
