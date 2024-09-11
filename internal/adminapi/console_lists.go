package adminapi

// 步骤 266：安全告知与邮件投递记录的只读管理端点（R10-23「安全通知分页」与
// 「邮件投递记录端点/权限」的 HTTP 闭环）。
//
// 边界：
//   - 权限判定在宿主注入的 Reader 实现内完成（本包只传可信 caller 与参数）；
//     Reader 必须重新判定权限/数据范围，失败一律按拒绝处理，不能依赖"管理会话"。
//   - 响应只含白名单字段：安全告知从来不含正文/验证码/链接；投递记录不含加密
//     载荷、完整收件人（脱敏）或磁盘路径。
//   - 分页使用稳定游标（不接受 offset）与统一 limit 1..200；游标由领域层生成并
//     绑定用户/筛选/数据范围，切换条件后旧游标必须由领域层拒绝。

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// SecurityNotificationListQuery 是安全告知分页查询（user_id 必填）。
type SecurityNotificationListQuery struct {
	UserID string
	Cursor string
	Limit  int
}

// SecurityNotificationView 是安全告知的白名单展示字段（脱敏，不含正文/秘密）。
type SecurityNotificationView struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	OperationID       string    `json:"operation_id"`
	TargetType        string    `json:"target_type"`
	TargetID          string    `json:"target_id"`
	Outcome           string    `json:"outcome"`
	State             string    `json:"state"`
	ErrorCode         string    `json:"error_code,omitempty"`
	ReasonCode        string    `json:"reason_code,omitempty"`
	RecipientMasked   string    `json:"recipient_masked"`
	DeliveryID        string    `json:"delivery_id,omitempty"`
	DeliveryState     string    `json:"delivery_state,omitempty"`
	DeliveryErrorCode string    `json:"delivery_error_code,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// SecurityNotificationList 是一页安全告知。
type SecurityNotificationList struct {
	Notifications []SecurityNotificationView
	HasMore       bool
	NextCursor    string
}

// SecurityNotificationReader 读取安全告知分页；实现必须重新判定权限：本人，或
// 具备诊断/审计读取权限的系统范围主体。错误按 ErrAccessDenied/ErrInvalidRequest
// 返回，本包映射为稳定响应。
type SecurityNotificationReader interface {
	ListSecurityNotifications(ctx context.Context, caller account.Caller,
		query SecurityNotificationListQuery) (SecurityNotificationList, error)
}

// MailDeliveryListQuery 是邮件投递记录分页查询。
type MailDeliveryListQuery struct {
	State  string
	Cursor string
	Limit  int
}

// MailDeliveryView 是投递记录白名单字段（不含加密载荷/完整收件人/路径）。
type MailDeliveryView struct {
	DeliveryID      string    `json:"delivery_id"`
	Kind            string    `json:"kind"`
	State           string    `json:"state"`
	RecipientMasked string    `json:"recipient_masked"`
	OwnerType       string    `json:"owner_type"`
	OwnerID         string    `json:"owner_id"`
	Attempts        int       `json:"attempts"`
	MaxAttempts     int       `json:"max_attempts"`
	LastErrorCode   string    `json:"last_error_code,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// MailDeliveryList 是一页投递记录。
type MailDeliveryList struct {
	Deliveries []MailDeliveryView
	HasMore    bool
	NextCursor string
}

// MailDeliveryReader 读取邮件投递记录分页；实现必须要求诊断/审计读取权限
// （或受信本机进程），并返回脱敏字段。
type MailDeliveryReader interface {
	ListMailDeliveries(ctx context.Context, caller account.Caller,
		query MailDeliveryListQuery) (MailDeliveryList, error)
}

// handleSecurityNotificationHistory 处理 GET /notifications/history。
func (s *Server) handleSecurityNotificationHistory(c *callContext) error {
	if s.securityNotifications == nil {
		return s.notFoundProblem()
	}
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	if offset != 0 {
		return fmt.Errorf("%w: 安全告知列表使用稳定游标，不接受非零 offset", ErrInvalidRequest)
	}
	cursor, err := queryString(c.request, "cursor", 4096)
	if err != nil {
		return err
	}
	userID, err := queryString(c.request, "user_id", 64)
	if err != nil {
		return err
	}
	if userID == "" || !account.ValidUserID(userID) {
		return fmt.Errorf("%w: user_id 必须是有效用户 ID", ErrInvalidRequest)
	}
	page, listErr := s.securityNotifications.ListSecurityNotifications(
		c.request.Context(), c.caller, SecurityNotificationListQuery{
			UserID: userID, Cursor: cursor, Limit: limit})
	if listErr != nil {
		return mapHistoryListError(listErr)
	}
	items := make([]SecurityNotificationView, 0, len(page.Notifications))
	for _, record := range page.Notifications {
		items = append(items, record)
	}
	payload := map[string]any{
		"notifications": items, "has_more": page.HasMore, "limit": limit,
	}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	}
	s.writeSuccess(c.writer, c.requestID, payload)
	return nil
}

// handleMailDeliveryList 处理 GET /deliveries。
func (s *Server) handleMailDeliveryList(c *callContext) error {
	if s.mailDeliveries == nil {
		return s.notFoundProblem()
	}
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	if offset != 0 {
		return fmt.Errorf("%w: 投递记录列表使用稳定游标，不接受非零 offset", ErrInvalidRequest)
	}
	cursor, err := queryString(c.request, "cursor", 4096)
	if err != nil {
		return err
	}
	state, err := queryString(c.request, "state", 32)
	if err != nil {
		return err
	}
	page, listErr := s.mailDeliveries.ListMailDeliveries(c.request.Context(), c.caller,
		MailDeliveryListQuery{State: state, Cursor: cursor, Limit: limit})
	if listErr != nil {
		return mapHistoryListError(listErr)
	}
	items := make([]MailDeliveryView, 0, len(page.Deliveries))
	for _, record := range page.Deliveries {
		items = append(items, record)
	}
	payload := map[string]any{
		"deliveries": items, "has_more": page.HasMore, "limit": limit,
	}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	}
	s.writeSuccess(c.writer, c.requestID, payload)
	return nil
}

// mapHistoryListError 把宿主 Reader 的拒绝/参数错误映射为稳定管理 API 错误；
// 其余错误统一按内部错误（不回显细节）。
func mapHistoryListError(err error) error {
	switch {
	case errors.Is(err, ErrAccessDenied):
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	case errors.Is(err, ErrInvalidRequest):
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	default:
		return err
	}
}
