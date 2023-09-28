// Package sqlite 实现 internal/reauth.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0019_reauth_and_notifications.sql 创建；本包不执行迁移、
// 不拥有数据库连接。批准令牌只保存 SHA-256 摘要，挑战与批准的状态迁移全部使用
// 条件更新，保证一次性消费与并发竞争下只有一方成功。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const insertChallengeSQL = `INSERT INTO reauth_challenges(
id,user_id,scope_id,operation_id,target_type,target_id,params_sha256,required_strength,
status,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,verified_at_ms
) VALUES(?,?,?,?,?,?,?,?,'pending',?,?,?,?,?,NULL)`

const selectChallengeSQL = `SELECT id,user_id,scope_id,operation_id,target_type,target_id,
params_sha256,required_strength,status,attempts,max_attempts,expires_at_ms,created_at_ms,
updated_at_ms,COALESCE(verified_at_ms,0)
FROM reauth_challenges WHERE id=?`

const increaseAttemptsSQL = `UPDATE reauth_challenges SET attempts=attempts+1,updated_at_ms=?
WHERE id=? AND status='pending'`

const selectAttemptsSQL = `SELECT attempts FROM reauth_challenges WHERE id=?`

const verifyChallengeSQL = `UPDATE reauth_challenges SET status='verified',verified_at_ms=?,
updated_at_ms=? WHERE id=? AND status='pending' AND expires_at_ms>?`

const cancelChallengeSQL = `UPDATE reauth_challenges SET status='cancelled',updated_at_ms=?
WHERE id=? AND status='pending'`

const insertApprovalSQL = `INSERT INTO reauth_approvals(
id,challenge_id,token_sha256,user_id,scope_id,operation_id,target_type,target_id,
params_sha256,granted_strength,authentication_complete,granted_at_ms,expires_at_ms,
consumed_at_ms,created_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)`

const selectApprovalByTokenSQL = `SELECT id,challenge_id,token_sha256,user_id,scope_id,
operation_id,target_type,target_id,params_sha256,granted_strength,
authentication_complete,granted_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0),created_at_ms
FROM reauth_approvals WHERE token_sha256=?`

const consumeApprovalSQL = `UPDATE reauth_approvals SET consumed_at_ms=?
WHERE id=? AND consumed_at_ms IS NULL AND expires_at_ms>?`

// upsertNotificationSQL 是原子幂等写入：dedup_key 非空且已存在时更新同一行，否则插入。
//
//   - 冲突目标必须带 WHERE 子句才能匹配 0050 的“非空 dedup_key”部分唯一索引；
//   - delivery_id 用 COALESCE 保留旧值：关联回写失败后的重试不能把已保存的投递
//     标识清空，否则读取投影会丢失与可靠投递记录的关联；
//   - 其余字段按当前语义更新（状态/错误码/脱敏收件人）。
const upsertNotificationSQL = `INSERT INTO security_notifications(
id,user_id,operation_id,target_type,target_id,outcome,state,error_code,reason_code,
recipient_masked,created_at_ms,delivery_id,dedup_key
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(dedup_key) WHERE dedup_key IS NOT NULL DO UPDATE SET
state=excluded.state,
error_code=excluded.error_code,
reason_code=excluded.reason_code,
recipient_masked=excluded.recipient_masked,
delivery_id=COALESCE(excluded.delivery_id, delivery_id)`

// notificationExistsSQL 用于在影响行数为 0 时区分“方言空更新”与“记录根本不存在”。
const notificationExistsSQL = `SELECT 1 FROM security_notifications WHERE dedup_key=?`

// 只读投影投递记录当前状态；mail_deliveries 归 internal/mailer/sqlite 与迁移 0012
// 所有，本包只做读取关联，不修改投递状态（投递状态机仍由 mailer 独占）。
const notificationDeliveryStateSQL = `SELECT COALESCE(state,''),COALESCE(last_error_code,''),
updated_at_ms FROM mail_deliveries WHERE id=?`

const notificationDeliveryByKeySQL = `SELECT id,COALESCE(state,''),COALESCE(last_error_code,''),
updated_at_ms FROM mail_deliveries WHERE idempotency_key=?`

const listNotificationsSQL = `SELECT n.id,n.user_id,n.operation_id,n.target_type,n.target_id,
n.outcome,n.state,COALESCE(n.error_code,''),COALESCE(n.reason_code,''),n.recipient_masked,
n.created_at_ms,COALESCE(n.delivery_id,''),COALESCE(n.dedup_key,'')
FROM security_notifications n WHERE n.user_id=? ORDER BY n.created_at_ms DESC LIMIT ?`

const verifiedEmailSQL = `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY verified_at_ms DESC LIMIT 1`

const usernameSQL = `SELECT username FROM users WHERE id=?`

const isRootSQL = `SELECT is_root FROM users WHERE id=?`

// Store 是 reauth.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", reauth.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ reauth.Store = (*Store)(nil)

// CreateChallengeTx 在审计事务内创建挑战。
func (s *Store) CreateChallengeTx(ctx context.Context, tx audit.Tx, record reauth.ChallengeRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", reauth.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertChallengeSQL, record.ID, record.UserID, record.ScopeID,
		record.OperationID, record.TargetType, record.TargetID, record.ParamsSHA256,
		string(record.RequiredStrength), record.Attempts, record.MaxAttempts,
		record.ExpiresAt.UTC().UnixMilli(), record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return nil
}

// GetChallenge 读取挑战。
func (s *Store) GetChallenge(ctx context.Context, id string) (reauth.ChallengeRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectChallengeSQL, id)
	if err != nil {
		return reauth.ChallengeRecord{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return reauth.ChallengeRecord{}, false, nil
	}
	var record reauth.ChallengeRecord
	var params []byte
	var strength, state string
	var expiresAt, createdAt, updatedAt, verifiedAt int64
	if err := rows.Scan(&record.ID, &record.UserID, &record.ScopeID, &record.OperationID,
		&record.TargetType, &record.TargetID, &params, &strength, &state, &record.Attempts,
		&record.MaxAttempts, &expiresAt, &createdAt, &updatedAt, &verifiedAt); err != nil {
		return reauth.ChallengeRecord{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	record.ParamsSHA256 = params
	record.RequiredStrength = policy.Strength(strength)
	record.State = reauth.ChallengeState(state)
	record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if verifiedAt > 0 {
		record.VerifiedAt = time.UnixMilli(verifiedAt).UTC()
	}
	return record, true, nil
}

// IncreaseAttempts 原子递增尝试次数并返回新值。
func (s *Store) IncreaseAttempts(ctx context.Context, id string, now time.Time) (int, error) {
	if _, err := s.store.ExecContext(ctx, increaseAttemptsSQL, now.UTC().UnixMilli(), id); err != nil {
		return 0, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	rows, err := s.store.QueryContext(ctx, selectAttemptsSQL, id)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 挑战不存在", reauth.ErrChallengeInvalid)
	}
	var attempts int
	if err := rows.Scan(&attempts); err != nil {
		return 0, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return attempts, nil
}

// CancelChallengeTx 在审计事务内把 pending 挑战条件迁移为 cancelled；已确认/过期/
// 已取消返回 false（取消不是批准，不产生任何可执行能力）。
func (s *Store) CancelChallengeTx(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", reauth.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, cancelChallengeSQL, now.UTC().UnixMilli(), id)
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// ApproveTx 在审计事务内条件迁移挑战状态并写入批准行。
func (s *Store) ApproveTx(ctx context.Context, tx audit.Tx, challengeID string, now time.Time,
	approval reauth.ApprovalRecord) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", reauth.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, verifyChallengeSQL, now.UTC().UnixMilli(),
		now.UTC().UnixMilli(), challengeID, now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, insertApprovalSQL, approval.ID, approval.ChallengeID,
		approval.TokenSHA256, approval.UserID, approval.ScopeID, approval.OperationID,
		approval.TargetType, approval.TargetID, approval.ParamsSHA256,
		string(approval.GrantedStrength), boolInt(approval.Complete),
		approval.GrantedAt.UTC().UnixMilli(), approval.ExpiresAt.UTC().UnixMilli(),
		approval.CreatedAt.UTC().UnixMilli()); err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return true, nil
}

// GetApprovalByTokenDigest 按令牌摘要读取批准。
func (s *Store) GetApprovalByTokenDigest(ctx context.Context, digest []byte) (reauth.ApprovalRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectApprovalByTokenSQL, digest)
	if err != nil {
		return reauth.ApprovalRecord{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return reauth.ApprovalRecord{}, false, nil
	}
	var record reauth.ApprovalRecord
	var token, params []byte
	var strength string
	var complete int
	var grantedAt, expiresAt, consumedAt, createdAt int64
	if err := rows.Scan(&record.ID, &record.ChallengeID, &token, &record.UserID, &record.ScopeID,
		&record.OperationID, &record.TargetType, &record.TargetID, &params, &strength,
		&complete, &grantedAt, &expiresAt, &consumedAt, &createdAt); err != nil {
		return reauth.ApprovalRecord{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	record.TokenSHA256 = token
	record.ParamsSHA256 = params
	record.GrantedStrength = policy.Strength(strength)
	record.Complete = complete == 1
	record.GrantedAt = time.UnixMilli(grantedAt).UTC()
	record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	if consumedAt > 0 {
		record.ConsumedAt = time.UnixMilli(consumedAt).UTC()
	}
	return record, true, nil
}

// ConsumeApprovalTx 在审计事务内一次性消费批准。
func (s *Store) ConsumeApprovalTx(ctx context.Context, tx audit.Tx, approvalID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", reauth.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, consumeApprovalSQL, now.UTC().UnixMilli(), approvalID,
		now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// UpsertNotification 记录或幂等更新一次告知结果。
//
// dedup_key 非空时同一业务事件只保留一条主记录：先 INSERT OR IGNORE，冲突时改用
// 条件 UPDATE。delivery_id 只在新值非空时写入，绝不清空已关联的投递标识——这保证
// “入队成功但关联回写失败”后，同一业务事件的重试/重启可以继续关联同一投递记录
// 而不产生第二封邮件。dedup_key 为空（历史记录/直接发送回退路径）时按新记录插入。
func (s *Store) UpsertNotification(ctx context.Context, record reauth.NotificationRecord) error {
	result, err := s.store.ExecContext(ctx, upsertNotificationSQL, record.ID, record.UserID,
		record.OperationID, record.TargetType, record.TargetID, string(record.Outcome),
		string(record.State), nullString(record.ErrorCode), nullString(record.ReasonCode),
		record.RecipientMasked, record.CreatedAt.UTC().UnixMilli(),
		nullString(record.DeliveryID), nullString(record.DedupKey))
	if err != nil {
		// 约束失败（CHECK/NOT NULL/外键等）必须向上传播：上层不得继续入队或写成功审计。
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	if affected == 1 {
		return nil
	}
	// 影响行数为 0 的 fail-closed 处理：
	//   - SQLite/PostgreSQL/SQL Server 的 upsert 命中并更新时至少影响 1 行；0 行说明
	//     语句没有真正落库（不能当成功）。
	//   - MySQL 的 ON DUPLICATE KEY UPDATE 在“值未变化”时影响 0 行（仓储连接关闭了
	//     CLIENT_FOUND_ROWS），因此再做一次只读存在性核对：只有确认同一 dedup_key 的
	//     记录已存在，才把它视为幂等空更新；否则返回错误，绝不静默吞掉失败。
	if record.DedupKey == "" {
		return fmt.Errorf("%w: 告知记录写入未生效（缺少稳定去重键）", reauth.ErrStoreUnavailable)
	}
	rows, err := s.store.QueryContext(ctx, notificationExistsSQL, record.DedupKey)
	if err != nil {
		return fmt.Errorf("%w: 告知记录写入未生效且无法核对: %w", reauth.ErrStoreUnavailable, err)
	}
	exists := rows.Next()
	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return fmt.Errorf("%w: 告知记录写入未生效且无法核对: %w", reauth.ErrStoreUnavailable, rowsErr)
	}
	_ = rows.Close()
	if !exists {
		return fmt.Errorf("%w: 告知记录写入未生效（记录不存在）", reauth.ErrStoreUnavailable)
	}
	return nil
}

// ListNotifications 按用户读取最近告知记录，并投影关联投递记录的当前状态。
//
// 关联规则：优先按主记录 delivery_id 精确关联；若该列为空（关联回写失败/历史数据）
// 则按稳定去重键查 mail_deliveries.idempotency_key（同一业务事件的幂等键）。两条
// 路径都只读，不触发重发、不修改投递状态。
func (s *Store) ListNotifications(ctx context.Context, userID string, limit int) ([]reauth.NotificationRecord, error) {
	rows, err := s.store.QueryContext(ctx, listNotificationsSQL, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	records := make([]reauth.NotificationRecord, 0, limit)
	for rows.Next() {
		var record reauth.NotificationRecord
		var outcome, state string
		var createdAt int64
		if err := rows.Scan(&record.ID, &record.UserID, &record.OperationID, &record.TargetType,
			&record.TargetID, &outcome, &state, &record.ErrorCode, &record.ReasonCode,
			&record.RecipientMasked, &createdAt, &record.DeliveryID, &record.DedupKey); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
		record.Outcome = reauth.Outcome(outcome)
		record.State = reauth.NotificationState(state)
		record.CreatedAt = time.UnixMilli(createdAt).UTC()
		if err := s.projectDeliveryState(ctx, &record); err != nil {
			_ = rows.Close()
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return records, nil
}

// projectDeliveryState 为一条告知记录只读补充当前投递状态。
func (s *Store) projectDeliveryState(ctx context.Context,
	record *reauth.NotificationRecord) error {
	if record.DeliveryID != "" {
		state, errorCode, updatedAt, found, err := s.lookupDelivery(ctx, record.DeliveryID)
		if err != nil {
			return err
		}
		if found {
			record.DeliveryState = state
			record.DeliveryErrorCode = errorCode
			record.DeliveryUpdatedAt = updatedAt
		}
		return nil
	}
	if record.DedupKey == "" {
		return nil
	}
	deliveryID, state, errorCode, updatedAt, found, err := s.lookupDeliveryByKey(ctx, record.DedupKey)
	if err != nil {
		return err
	}
	if found {
		record.DeliveryID = deliveryID
		record.DeliveryState = state
		record.DeliveryErrorCode = errorCode
		record.DeliveryUpdatedAt = updatedAt
	}
	return nil
}

// lookupDelivery 按投递记录 ID 只读查询状态。
func (s *Store) lookupDelivery(ctx context.Context, deliveryID string) (
	mailer.DeliveryState, string, time.Time, bool, error) {
	rows, err := s.store.QueryContext(ctx, notificationDeliveryStateSQL, deliveryID)
	if err != nil {
		return "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
		return "", "", time.Time{}, false, nil
	}
	var state, errorCode string
	var updatedAt int64
	if err := rows.Scan(&state, &errorCode, &updatedAt); err != nil {
		return "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return mailer.DeliveryState(state), errorCode, time.UnixMilli(updatedAt).UTC(), true, nil
}

// lookupDeliveryByKey 按稳定去重键（邮件入队幂等键）只读查询投递状态。
func (s *Store) lookupDeliveryByKey(ctx context.Context, dedupKey string) (
	string, mailer.DeliveryState, string, time.Time, bool, error) {
	rows, err := s.store.QueryContext(ctx, notificationDeliveryByKeySQL, dedupKey)
	if err != nil {
		return "", "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
		return "", "", "", time.Time{}, false, nil
	}
	var deliveryID, state, errorCode string
	var updatedAt int64
	if err := rows.Scan(&deliveryID, &state, &errorCode, &updatedAt); err != nil {
		return "", "", "", time.Time{}, false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return deliveryID, mailer.DeliveryState(state), errorCode,
		time.UnixMilli(updatedAt).UTC(), true, nil
}

// VerifiedEmail 返回用户最近一个已验证邮箱。
func (s *Store) VerifiedEmail(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, verifiedEmailSQL, userID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var address string
	if err := rows.Scan(&address); err != nil {
		return "", false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return address, address != "", nil
}

// Username 返回用户显示用户名。
func (s *Store) Username(ctx context.Context, userID string) (string, bool, error) {
	return s.queryString(ctx, usernameSQL, userID)
}

// IsRoot 报告用户是否为真实 root 账户。
func (s *Store) IsRoot(ctx context.Context, userID string) (bool, error) {
	var isRoot int
	err := s.store.DB().QueryRowContext(ctx, isRootSQL, userID).Scan(&isRoot)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return isRoot == 1, nil
}

// queryString 读取单列字符串。
func (s *Store) queryString(ctx context.Context, query string, argument string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, argument)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		return "", false, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return value, true, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
