package serverapp

// 步骤 266：管理 API「安全告知分页」与「邮件投递记录」的宿主适配器。
//
// 权限（不新造权限键）：
//   - 安全告知：本人可读本人；受信本机进程（LocalAdmin/真实宿主）与具备系统范围
//     diagnostics.read 的主体可读指定用户。读取用系统/用户可信主体调用 reauth 领域
//     层，领域层再执行同一授权判定（双重 fail-closed）。
//   - 邮件投递记录：受信本机进程放行；其余主体要求系统范围 diagnostics.read
//     （与任务列表/诊断入口一致）。读取用 mailer.SystemCaller 执行领域查询，避免
//     管理会话被当成投递数据范围授权。
//
// 数据边界：只返回白名单字段；收件人一律脱敏；不含加密载荷、正文/链接/路径。

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// securityNotificationHistoryReader 实现 adminapi.SecurityNotificationReader。
type securityNotificationHistoryReader struct {
	reauth  *reauth.Service
	checker *permissionChecker
}

// ListSecurityNotifications 读取指定用户的安全告知分页（脱敏字段 + 投递状态投影）。
func (r securityNotificationHistoryReader) ListSecurityNotifications(ctx context.Context,
	caller account.Caller, query adminapi.SecurityNotificationListQuery) (adminapi.SecurityNotificationList, error) {
	if r.reauth == nil {
		return adminapi.SecurityNotificationList{}, fmt.Errorf("%w: 安全告知服务未装配", adminapi.ErrInvalidRequest)
	}
	actor := caller.Actor()
	self := actor.Type == audit.ActorUser && actor.ID == query.UserID
	if !self {
		trusted := r.checker != nil && r.checker.roots != nil &&
			r.checker.roots.trustedProcessActor(actor)
		if !trusted {
			if r.checker == nil {
				return adminapi.SecurityNotificationList{}, adminapi.ErrAccessDenied
			}
			if err := r.checker.check(ctx, actor.ID, "diagnostics.read", "system"); err != nil {
				return adminapi.SecurityNotificationList{}, fmt.Errorf("%w: %w",
					adminapi.ErrAccessDenied, err)
			}
		}
	}
	var reauthCaller reauth.Caller
	var callerErr error
	if self {
		reauthCaller, callerErr = reauth.UserCaller(actor.ID)
	} else {
		reauthCaller, callerErr = reauth.SystemCaller("admin-notification-history")
	}
	if callerErr != nil {
		return adminapi.SecurityNotificationList{}, adminapi.ErrAccessDenied
	}
	page, err := r.reauth.NotificationsPage(ctx, reauthCaller, query.UserID, query.Cursor, query.Limit)
	if err != nil {
		switch {
		case errors.Is(err, reauth.ErrAccessDenied):
			return adminapi.SecurityNotificationList{}, adminapi.ErrAccessDenied
		case errors.Is(err, reauth.ErrInvalidRequest),
			errors.Is(err, reauth.ErrNotificationCursorInvalid),
			errors.Is(err, reauth.ErrNotificationCursorMismatch):
			return adminapi.SecurityNotificationList{}, adminapi.ErrInvalidRequest
		default:
			return adminapi.SecurityNotificationList{}, err
		}
	}
	list := adminapi.SecurityNotificationList{HasMore: page.HasMore,
		NextCursor:    page.NextCursor,
		Notifications: make([]adminapi.SecurityNotificationView, 0, len(page.Records))}
	for _, record := range page.Records {
		list.Notifications = append(list.Notifications, adminapi.SecurityNotificationView{
			ID: record.ID, UserID: record.UserID, OperationID: record.OperationID,
			TargetType: record.TargetType, TargetID: record.TargetID,
			Outcome: string(record.Outcome), State: string(record.State),
			ErrorCode: record.ErrorCode, ReasonCode: record.ReasonCode,
			RecipientMasked: record.RecipientMasked,
			DeliveryID:      record.DeliveryID, DeliveryState: string(record.DeliveryState),
			DeliveryErrorCode: record.DeliveryErrorCode, CreatedAt: record.CreatedAt,
		})
	}
	return list, nil
}

// mailDeliveryHistoryReader 实现 adminapi.MailDeliveryReader。
type mailDeliveryHistoryReader struct {
	provider func() *mailer.DeliveryService
	checker  *permissionChecker
}

// ListMailDeliveries 读取邮件投递记录分页（脱敏白名单字段）。
func (r mailDeliveryHistoryReader) ListMailDeliveries(ctx context.Context,
	caller account.Caller, query adminapi.MailDeliveryListQuery) (adminapi.MailDeliveryList, error) {
	actor := caller.Actor()
	trusted := r.checker != nil && r.checker.roots != nil &&
		r.checker.roots.trustedProcessActor(actor)
	if !trusted {
		if r.checker == nil {
			return adminapi.MailDeliveryList{}, adminapi.ErrAccessDenied
		}
		if err := r.checker.check(ctx, actor.ID, "diagnostics.read", "system"); err != nil {
			return adminapi.MailDeliveryList{}, fmt.Errorf("%w: %w",
				adminapi.ErrAccessDenied, err)
		}
	}
	if r.provider == nil {
		return adminapi.MailDeliveryList{}, fmt.Errorf("%w: 邮件投递服务未装配", adminapi.ErrInvalidRequest)
	}
	delivery := r.provider()
	if delivery == nil {
		return adminapi.MailDeliveryList{}, fmt.Errorf("%w: 邮件投递服务未就绪", adminapi.ErrInvalidRequest)
	}
	system, err := mailer.SystemCaller("admin-delivery-history")
	if err != nil {
		return adminapi.MailDeliveryList{}, adminapi.ErrAccessDenied
	}
	page, err := delivery.ListPage(ctx, system, mailer.DeliveryPageQuery{
		State:  mailer.DeliveryState(strings.TrimSpace(query.State)),
		Cursor: query.Cursor, Limit: query.Limit})
	if err != nil {
		switch {
		case errors.Is(err, mailer.ErrAccessDenied):
			return adminapi.MailDeliveryList{}, adminapi.ErrAccessDenied
		case errors.Is(err, mailer.ErrInvalidMessage),
			errors.Is(err, mailer.ErrDeliveryCursorInvalid),
			errors.Is(err, mailer.ErrDeliveryCursorMismatch):
			return adminapi.MailDeliveryList{}, adminapi.ErrInvalidRequest
		default:
			return adminapi.MailDeliveryList{}, err
		}
	}
	list := adminapi.MailDeliveryList{HasMore: page.HasMore, NextCursor: page.NextCursor,
		Deliveries: make([]adminapi.MailDeliveryView, 0, len(page.Records))}
	for _, record := range page.Records {
		list.Deliveries = append(list.Deliveries, adminapi.MailDeliveryView{
			DeliveryID: record.ID, Kind: string(record.Kind), State: string(record.State),
			RecipientMasked: maskMailRecipient(record.Recipient),
			OwnerType:       string(record.OwnerType), OwnerID: record.OwnerID,
			Attempts: record.Attempts, MaxAttempts: record.MaxAttempts,
			LastErrorCode: record.LastErrorCode, RequestID: record.RequestID,
			CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		})
	}
	return list, nil
}

// maskMailRecipient 把收件地址脱敏为 "***@domain"（无 @ 时整体替换）；管理 API
// 不返回完整收件人。空地址返回空串（不伪造地址）。
func maskMailRecipient(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	at := strings.LastIndex(trimmed, "@")
	if at <= 0 || at == len(trimmed)-1 {
		return "***"
	}
	return "***@" + trimmed[at+1:]
}

// newMailDeliveryHistoryReader 构造投递记录只读适配器；mail 能力未装配
// （无 MailDeliveryProvider）时返回 nil，对应路由不挂载（fail-closed）。
func newMailDeliveryHistoryReader(deps Deps, checker *permissionChecker) adminapi.MailDeliveryReader {
	if deps.MailDeliveryProvider == nil {
		return nil
	}
	return mailDeliveryHistoryReader{provider: deps.MailDeliveryProvider, checker: checker}
}
