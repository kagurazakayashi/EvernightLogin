// Package sqlite 实现 internal/support.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0026_support_cases.sql 创建；本包不执行迁移、不拥有数据库
// 连接。求助单状态/指派变更使用行版本条件更新，处理历史与变更在同一审计事务内
// 追加（数据库触发器禁止 UPDATE），因此历史不可被业务覆盖。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

const caseSelectColumns = `c.id,c.target_user_id,COALESCE(u.username,''),
c.created_by_user_id,c.assignee_user_id,c.target_masked_email,c.reason,c.status,
c.row_version,c.created_at_ms,c.updated_at_ms`

const getCaseSQL = `SELECT ` + caseSelectColumns + `
FROM support_cases c LEFT JOIN users u ON u.id=c.target_user_id WHERE c.id=?`

const insertCaseSQL = `INSERT INTO support_cases(
id,target_user_id,created_by_user_id,assignee_user_id,reason,status,
target_masked_email,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,1,?,?)`

const insertEventSQL = `INSERT INTO support_case_events(
id,case_id,seq,action,actor_type,actor_id,from_status,to_status,detail,created_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?)`

const nextEventSeqSQL = `SELECT COALESCE(MAX(seq),0)+1 FROM support_case_events WHERE case_id=?`

const listEventsSQL = `SELECT id,case_id,seq,action,actor_type,actor_id,from_status,to_status,
detail,created_at_ms FROM support_case_events WHERE case_id=? ORDER BY seq LIMIT ? OFFSET ?`

const targetSQL = `SELECT u.id,u.username,u.status,u.is_root,
EXISTS(SELECT 1 FROM password_credentials p WHERE p.user_id=u.id),
e.email
FROM users u
LEFT JOIN user_emails e ON e.user_id=u.id AND e.verified_at_ms IS NOT NULL
WHERE u.id=?
ORDER BY COALESCE(e.verified_at_ms,0) DESC LIMIT 1`

// Store 是 support.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", support.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ support.Store = (*Store)(nil)

// CreateCaseTx 在审计事务内创建求助单并追加首条处理历史。
func (s *Store) CreateCaseTx(ctx context.Context, tx audit.Tx, record support.CaseRecord,
	event support.EventRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", support.ErrOptionsInvalid)
	}
	if event.ID == "" || event.CaseID != record.ID {
		return fmt.Errorf("%w: 处理历史事件无效", support.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertCaseSQL, record.ID, record.TargetUserID,
		record.CreatedByUserID, record.AssigneeUserID, record.Reason, string(record.Status),
		record.TargetMaskedEmail, record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	if _, err := tx.ExecContext(ctx, insertEventSQL, event.ID, record.ID, int64(1),
		event.Action, string(event.Actor.Type), event.Actor.ID,
		string(event.FromStatus), string(event.ToStatus), event.Detail,
		event.CreatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	return nil
}

// GetCase 按 ID 读取求助单。
func (s *Store) GetCase(ctx context.Context, caseID string) (support.CaseRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, getCaseSQL, caseID)
	if err != nil {
		return support.CaseRecord{}, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return support.CaseRecord{}, false, nil
	}
	record, err := scanCase(rows)
	if err != nil {
		return support.CaseRecord{}, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	return record, true, nil
}

// ListCases 分页列出求助单；读取 limit+1 行判断是否还有下一页。
func (s *Store) ListCases(ctx context.Context, query support.CaseQuery) ([]support.CaseRecord, bool, error) {
	var builder strings.Builder
	builder.WriteString(`SELECT ` + caseSelectColumns + ` FROM support_cases c
LEFT JOIN users u ON u.id=c.target_user_id WHERE 1=1`)
	args := make([]any, 0, 4)
	if query.AssigneeUserID != "" {
		builder.WriteString(` AND c.assignee_user_id=?`)
		args = append(args, query.AssigneeUserID)
	}
	if len(query.Statuses) > 0 {
		placeholders := make([]string, 0, len(query.Statuses))
		for _, status := range query.Statuses {
			placeholders = append(placeholders, "?")
			args = append(args, string(status))
		}
		builder.WriteString(` AND c.status IN(` + strings.Join(placeholders, ",") + `)`)
	}
	builder.WriteString(` ORDER BY c.updated_at_ms DESC,c.id DESC LIMIT ? OFFSET ?`)
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, builder.String(), args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]support.CaseRecord, 0, query.Limit)
	for rows.Next() {
		record, scanErr := scanCase(rows)
		if scanErr != nil {
			return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	hasMore := len(records) > query.Limit
	if hasMore {
		records = records[:query.Limit]
	}
	return records, hasMore, nil
}

// UpdateCaseTx 按行版本条件更新状态/指派并在同一事务内追加处理历史；求助单已终结、
// 版本不匹配时返回 false（由调用方整体回滚并返回 CONFLICT）。
func (s *Store) UpdateCaseTx(ctx context.Context, tx audit.Tx, update support.CaseUpdate) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", support.ErrOptionsInvalid)
	}
	if update.SetStatus == "" && update.SetAssignee == "" {
		return false, fmt.Errorf("%w: 没有可变更字段", support.ErrOptionsInvalid)
	}
	if update.Event.ID == "" || update.Event.CaseID != update.CaseID {
		return false, fmt.Errorf("%w: 处理历史事件无效", support.ErrOptionsInvalid)
	}
	var builder strings.Builder
	builder.WriteString(`UPDATE support_cases SET row_version=row_version+1,updated_at_ms=?`)
	args := []any{update.UpdatedAt.UTC().UnixMilli()}
	if update.SetStatus != "" {
		builder.WriteString(`,status=?`)
		args = append(args, string(update.SetStatus))
	}
	if update.SetAssignee != "" {
		builder.WriteString(`,assignee_user_id=?`)
		args = append(args, update.SetAssignee)
	}
	builder.WriteString(` WHERE id=? AND row_version=? AND status NOT IN('closed','cancelled')`)
	args = append(args, update.CaseID, update.ExpectedVersion)
	result, err := tx.ExecContext(ctx, builder.String(), args...)
	if err != nil {
		return false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return false, nil
	}
	// 在同一事务内取该求助单下一个历史的序号；行版本条件更新保证只有单赢家写入。
	rows, err := tx.QueryContext(ctx, nextEventSeqSQL, update.CaseID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	var seq int64
	if rows.Next() {
		if scanErr := rows.Scan(&seq); scanErr != nil {
			rows.Close()
			return false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, scanErr)
		}
	}
	rows.Close()
	if seq < 1 {
		return false, fmt.Errorf("%w: 无法分配处理历史序号", support.ErrStoreUnavailable)
	}
	if _, err := tx.ExecContext(ctx, insertEventSQL, update.Event.ID, update.CaseID, seq,
		update.Event.Action, string(update.Event.Actor.Type), update.Event.Actor.ID,
		string(update.Event.FromStatus), string(update.Event.ToStatus), update.Event.Detail,
		update.Event.CreatedAt.UTC().UnixMilli()); err != nil {
		return false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	return true, nil
}

// ListEvents 按序号分页列出处理历史。
func (s *Store) ListEvents(ctx context.Context, caseID string, offset, limit int) ([]support.EventRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, listEventsSQL, caseID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	events := make([]support.EventRecord, 0, limit)
	for rows.Next() {
		var event support.EventRecord
		var actorType, fromStatus, toStatus string
		var createdAt int64
		if err := rows.Scan(&event.ID, &event.CaseID, &event.Seq, &event.Action,
			&actorType, &event.Actor.ID, &fromStatus, &toStatus, &event.Detail,
			&createdAt); err != nil {
			return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
		}
		event.Actor.Type = audit.ActorKind(actorType)
		event.FromStatus = support.CaseStatus(fromStatus)
		event.ToStatus = support.CaseStatus(toStatus)
		event.CreatedAt = time.UnixMilli(createdAt).UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	return events, hasMore, nil
}

// LookupTarget 读取目标账户快照与最近一个已验证邮箱（可能为空）。
func (s *Store) LookupTarget(ctx context.Context, userID string) (support.TargetSnapshot, bool, error) {
	rows, err := s.store.QueryContext(ctx, targetSQL, userID)
	if err != nil {
		return support.TargetSnapshot{}, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return support.TargetSnapshot{}, false, nil
	}
	var target support.TargetSnapshot
	var isRoot, hasPassword int
	var email sql.NullString
	if err := rows.Scan(&target.UserID, &target.Username, &target.Status, &isRoot,
		&hasPassword, &email); err != nil {
		return support.TargetSnapshot{}, false, fmt.Errorf("%w: %w", support.ErrStoreUnavailable, err)
	}
	target.IsRoot = isRoot == 1
	target.HasPassword = hasPassword == 1
	target.HasVerifiedEmail = email.Valid && email.String != ""
	target.VerifiedEmail = email.String
	return target, true, nil
}

// scanCase 扫描一条求助单记录。
func scanCase(rows *sql.Rows) (support.CaseRecord, error) {
	var record support.CaseRecord
	var status string
	var createdAt, updatedAt int64
	if err := rows.Scan(&record.ID, &record.TargetUserID, &record.TargetUsername,
		&record.CreatedByUserID, &record.AssigneeUserID, &record.TargetMaskedEmail,
		&record.Reason, &status, &record.RowVersion, &createdAt, &updatedAt); err != nil {
		return support.CaseRecord{}, err
	}
	record.Status = support.CaseStatus(status)
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return record, nil
}
