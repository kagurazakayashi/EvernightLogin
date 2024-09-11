package reauth

// 步骤 266：安全告知（security_notifications）的 keyset 有界分页读取。
//
// 背景：`Notifications` 只支持 limit（≤100），无法支撑“继续读取”；本文件在不改变
// 告知写入路径与投递关联投影的前提下，补只读分页：
//   - 排序固定 created_at_ms DESC, id DESC（同一时间以稳定告知 ID 并列）；
//   - 游标是不透明 base64url JSON，绑定**目标用户**（同一用户才能续读，换用户/
//     篡改一律拒绝），不从其他用户范围继续；
//   - 每条记录仍按既有规则投影关联投递的当前状态（queued/sending/succeeded/
//     failed/cancelled），入队成功不等于送达；
//   - 授权语义与 Notifications 完全一致：本人、受信系统/本地通道、真实 root 可读；
//     其他用户一律 ErrAccessDenied（fail-closed）。

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 安全告知分页默认/上限。
const (
	NotificationPageDefaultLimit = 20
	NotificationPageMaxLimit     = 100
	notificationCursorVersion    = 1
)

// 分页游标错误哨兵；协议层映射为统一分页参数错误。
var (
	// ErrNotificationCursorInvalid 表示安全告知列表游标非法/被篡改。
	ErrNotificationCursorInvalid = errors.New("安全告知列表游标无效，请从第一页重新开始")
	// ErrNotificationCursorMismatch 表示游标与当前读取的用户不一致。
	ErrNotificationCursorMismatch = errors.New("安全告知列表游标与当前用户不一致，请从第一页重新开始")
)

// NotificationPage 是一页安全告知记录（含投递状态投影，不含正文/秘密）。
type NotificationPage struct {
	Records    []NotificationRecord
	HasMore    bool
	Limit      int
	NextCursor string
}

// notificationCursorEnvelope 是游标内部载荷（不透明，调用方不解析）。
type notificationCursorEnvelope struct {
	Version   int    `json:"v"`
	User      string `json:"u"`
	CreatedMS int64  `json:"t"`
	ID        string `json:"id"`
}

// notificationFilterFingerprint 计算游标绑定摘要（目标用户）。
func notificationFilterFingerprint(userID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(userID)))
	return hex.EncodeToString(digest[:16])
}

// encodeNotificationCursor 生成下一页游标。
func encodeNotificationCursor(userID string, last NotificationRecord) (string, error) {
	if last.ID == "" || last.CreatedAt.IsZero() {
		return "", fmt.Errorf("%w: 游标位置缺少告知标识/时间", ErrInvalidRequest)
	}
	envelope := notificationCursorEnvelope{Version: notificationCursorVersion,
		User:      notificationFilterFingerprint(userID),
		CreatedMS: last.CreatedAt.UTC().UnixMilli(), ID: last.ID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: 安全告知游标编码失败", ErrInvalidRequest)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// decodeNotificationCursor 解码并校验游标绑定的是同一用户。
func decodeNotificationCursor(cursor, userID string) (notificationCursorEnvelope, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cursor))
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return notificationCursorEnvelope{}, ErrNotificationCursorInvalid
	}
	var envelope notificationCursorEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return notificationCursorEnvelope{}, ErrNotificationCursorInvalid
	}
	if envelope.Version != notificationCursorVersion || envelope.ID == "" || envelope.CreatedMS <= 0 {
		return notificationCursorEnvelope{}, ErrNotificationCursorInvalid
	}
	if envelope.User != notificationFilterFingerprint(userID) {
		return notificationCursorEnvelope{}, ErrNotificationCursorMismatch
	}
	return envelope, nil
}

// NotificationsPage 读取目标用户的安全告知记录（keyset 分页，读取时投影投递状态）。
//
// 权限与 Notifications 相同；limit 约束到 1..100（默认 20）；cursor 为空表示第一页，
// 非空时必须是同一用户的上一页游标。
func (s *Service) NotificationsPage(ctx context.Context, caller Caller, userID string,
	cursor string, limit int) (NotificationPage, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return NotificationPage{}, ErrAccessDenied
	}
	if !account.ValidUserID(userID) {
		return NotificationPage{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if limit <= 0 {
		limit = NotificationPageDefaultLimit
	}
	if limit > NotificationPageMaxLimit {
		limit = NotificationPageMaxLimit
	}
	self := caller.IsUser() && caller.actor.ID == userID
	if !self {
		allowed := caller.actor.Type == audit.ActorSystem || caller.actor.Type == audit.ActorLocalAdmin
		if !allowed && caller.IsUser() {
			isRoot, rootErr := s.opts.Store.IsRoot(ctx, caller.actor.ID)
			if rootErr != nil {
				return NotificationPage{}, ErrStoreUnavailable
			}
			allowed = isRoot
		}
		if !allowed {
			return NotificationPage{}, ErrAccessDenied
		}
	}
	var afterCreatedAt time.Time
	var afterID string
	if strings.TrimSpace(cursor) != "" {
		position, err := decodeNotificationCursor(cursor, userID)
		if err != nil {
			return NotificationPage{}, err
		}
		afterCreatedAt = time.UnixMilli(position.CreatedMS).UTC()
		afterID = position.ID
	}
	records, err := s.opts.Store.ListNotificationsPage(ctx, userID, afterCreatedAt,
		afterID, limit+1)
	if err != nil {
		return NotificationPage{}, ErrStoreUnavailable
	}
	page := NotificationPage{Limit: limit, Records: records}
	if len(records) > limit {
		page.Records = records[:limit]
		page.HasMore = true
		next, cursorErr := encodeNotificationCursor(userID, page.Records[len(page.Records)-1])
		if cursorErr != nil {
			return NotificationPage{}, cursorErr
		}
		page.NextCursor = next
	}
	return page, nil
}
