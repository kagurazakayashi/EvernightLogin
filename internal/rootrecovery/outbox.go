package rootrecovery

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// PendingNotifications 读取尚未补发的 root 恢复安全告知（按创建时间升序，最多
// limit 条；limit 为 0 时使用 50，硬上限 200）。宿主/下次启动应调用本方法，通过
// 自己的通知渠道补发后再调用 MarkNotificationDelivered；投递失败调用
// MarkNotificationFailed 记录稳定原因码。事件不含任何秘密材料。
func (s *Service) PendingNotifications(ctx context.Context, limit int) ([]Notification, error) {
	ctx = normalizeContext(ctx)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	store, err := openOutboxStore(ctx, s.opts.DatabasePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = store.Close() }()
	rows, err := store.QueryContext(ctx,
		`SELECT id,root_user_id,operator_id,operator_machine,reason,password_reset,
mfa_reset,passkeys_revoked,notification_attempts,created_at_ms
FROM root_recovery_events WHERE notification_state='pending'
ORDER BY created_at_ms,id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	defer rows.Close()
	notifications := make([]Notification, 0, limit)
	for rows.Next() {
		var (
			notification            Notification
			passwordReset, mfaReset int
			passkeysRevoked         int
			attempts                int
			createdAtMillis         int64
		)
		if err := rows.Scan(&notification.ID, &notification.RootUserID,
			&notification.OperatorID, &notification.OperatorMachine, &notification.Reason,
			&passwordReset, &mfaReset, &passkeysRevoked, &attempts, &createdAtMillis); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
		}
		notification.PasswordReset = passwordReset != 0
		notification.MFAReset = mfaReset != 0
		notification.PasskeysRevoked = passkeysRevoked != 0
		notification.Attempts = attempts
		notification.CreatedAt = time.UnixMilli(createdAtMillis).UTC()
		notifications = append(notifications, notification)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return notifications, nil
}

// MarkNotificationDelivered 把恢复告知标记为已补发；已标记的行幂等返回 nil。
func (s *Service) MarkNotificationDelivered(ctx context.Context, eventID string, now time.Time) error {
	ctx = normalizeContext(ctx)
	if strings.TrimSpace(eventID) == "" {
		return ErrInvalidRequest
	}
	store, err := openOutboxStore(ctx, s.opts.DatabasePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	millis := now.UTC().UnixMilli()
	result, err := store.ExecContext(ctx,
		`UPDATE root_recovery_events SET notification_state='delivered',delivered_at_ms=?,
last_error_code='' WHERE id=? AND notification_state<>'delivered'`, millis, eventID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	if affected == 0 {
		if exists, existsErr := s.notificationExists(ctx, store, eventID); existsErr != nil {
			return existsErr
		} else if !exists {
			return fmt.Errorf("%w: 恢复告知不存在", ErrInvalidRequest)
		}
	}
	return nil
}

// MarkNotificationFailed 记录一次补发失败（只接受大写错误码，便于稳定分类）：
// 未达 MaxNotificationAttempts 时事件保持 pending 供宿主重试；达到上限后迁移为
// failed 终态，避免无限重试。补发为**至少一次**语义：宿主投递成功后若标记失败/崩溃，
// 下次仍可能重复补发，通知消费者必须按事件 ID 幂等。
func (s *Service) MarkNotificationFailed(ctx context.Context, eventID, errorCode string, now time.Time) error {
	ctx = normalizeContext(ctx)
	if strings.TrimSpace(eventID) == "" {
		return ErrInvalidRequest
	}
	code := sanitizeErrorCode(errorCode)
	if code == "" {
		return fmt.Errorf("%w: 通知失败错误码无效", ErrInvalidRequest)
	}
	store, err := openOutboxStore(ctx, s.opts.DatabasePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	// 第一步累计尝试次数与失败原因码；已 delivered 的事件保持不变（幂等）。
	result, err := store.ExecContext(ctx,
		`UPDATE root_recovery_events SET notification_attempts=notification_attempts+1,
last_error_code=? WHERE id=? AND notification_state<>'delivered'`, code, eventID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	if affected == 0 {
		exists, existsErr := s.notificationExists(ctx, store, eventID)
		if existsErr != nil {
			return existsErr
		}
		if !exists {
			return fmt.Errorf("%w: 恢复告知不存在", ErrInvalidRequest)
		}
		// 已送达事件上的失败标记是幂等无操作。
		return nil
	}
	// 第二步在达到尝试上限时迁移 failed 终态，避免无限重试。补发是至少一次语义，
	// 宿主必须按事件 ID 幂等；两条 outbox 状态更新不是安全关键事务。
	if _, err := store.ExecContext(ctx,
		`UPDATE root_recovery_events SET notification_state='failed'
WHERE id=? AND notification_state='pending' AND notification_attempts>=?`,
		eventID, MaxNotificationAttempts); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}

func (s *Service) notificationExists(ctx context.Context, store *storagesqlite.Store, eventID string) (bool, error) {
	count, err := queryIntTx(ctx, store, `SELECT COUNT(*) FROM root_recovery_events WHERE id=?`, eventID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

func openOutboxStore(ctx context.Context, path string) (*storagesqlite.Store, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, fmt.Errorf("%w: 数据库文件不存在或为空", ErrStoreUnavailable)
	}
	options := storagesqlite.DefaultOptions(path)
	// 不主动切换 journal_mode（WAL=false 只是不设置 PRAGMA WAL），避免在只读轮询
	// outbox 时改写数据库头部。
	options.WAL = false
	options.MaxOpenConns = 1
	options.MaxIdleConns = 1
	store, err := storagesqlite.Open(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开数据库", ErrStoreUnavailable)
	}
	return store, nil
}

// sanitizeErrorCode 只接受大写字母/数字/下划线且长度有界的原因码，避免把自由文本
// 写入恢复记录并造成日志注入。
func sanitizeErrorCode(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 64 {
		return ""
	}
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return ""
	}
	return trimmed
}
