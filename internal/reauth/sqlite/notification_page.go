package sqlite

// 步骤 266：安全告知 keyset 分页读取（SQLite 实现）。
//
// 查询与 ListNotifications 共用同一列/投影规则（关联投递只读投影），只把单个 LIMIT
// 换成 keyset 位置条件，便于使用既有索引 ix_security_notifications_user_created
// (user_id, created_at_ms)；同时间以 id 并列键保证不重不漏。不修改任何数据。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

const listNotificationsPageSQL = `SELECT n.id,n.user_id,n.operation_id,n.target_type,n.target_id,
n.outcome,n.state,COALESCE(n.error_code,''),COALESCE(n.reason_code,''),n.recipient_masked,
n.created_at_ms,COALESCE(n.delivery_id,''),COALESCE(n.dedup_key,'')
FROM security_notifications n WHERE n.user_id=?`

// ListNotificationsPage 按用户读取一页告知记录（created_at_ms DESC, id DESC）。
func (s *Store) ListNotificationsPage(ctx context.Context, userID string,
	afterCreatedAt time.Time, afterID string, limit int) ([]reauth.NotificationRecord, error) {
	if limit <= 0 {
		limit = reauth.NotificationPageDefaultLimit
	}
	statement := listNotificationsPageSQL
	args := []any{userID}
	if !afterCreatedAt.IsZero() {
		if afterID != "" {
			statement += ` AND (n.created_at_ms<? OR (n.created_at_ms=? AND n.id<?))`
			createdMS := afterCreatedAt.UTC().UnixMilli()
			args = append(args, createdMS, createdMS, afterID)
		} else {
			statement += ` AND n.created_at_ms<?`
			args = append(args, afterCreatedAt.UTC().UnixMilli())
		}
	}
	statement += ` ORDER BY n.created_at_ms DESC, n.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]reauth.NotificationRecord, 0, limit)
	for rows.Next() {
		var record reauth.NotificationRecord
		var outcome, state string
		var createdAt int64
		if err := rows.Scan(&record.ID, &record.UserID, &record.OperationID, &record.TargetType,
			&record.TargetID, &outcome, &state, &record.ErrorCode, &record.ReasonCode,
			&record.RecipientMasked, &createdAt, &record.DeliveryID, &record.DedupKey); err != nil {
			return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
		}
		record.Outcome = reauth.Outcome(outcome)
		record.State = reauth.NotificationState(state)
		record.CreatedAt = time.UnixMilli(createdAt).UTC()
		if err := s.projectDeliveryState(ctx, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", reauth.ErrStoreUnavailable, err)
	}
	return records, nil
}
