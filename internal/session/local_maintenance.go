package session

// 步骤 288/290（本地维护控制台）：按目标用户有界列出会话（只读）。
//
// 普通入口只有“本人 secret 列表”或“管理会话 AdminListUserSessions”；本地维护
// 身份没有 Evernight 管理会话，因此提供本窄方法：复用同一 store.ListUserSessions
// 与 SessionSummary 映射，只读、稳定排序、有界分页，写一条本地读取审计。
//
// 强制下线复用既有系统路径（Service.RevokeAllForUser），不新增会话表/撤销实现。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护身份；只应由 cmd/login-setup（经
// internal/setupconsole）调用，不代表 Evernight 账户/HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalMaintenanceSessionSummary 是目标用户会话的脱敏摘要（不含秘密/令牌）。
type LocalMaintenanceSessionSummary struct {
	ID                string
	AppID             string
	Kind              Kind
	Reason            Reason
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	Address           string
	UserAgent         string
}

// LocalMaintenanceRevokeAllSessions 由本地维护身份强制目标用户下线：复用既有
// 批量撤销事务，但审计 actor 记录本地 OS 操作者与调用方给出的理由（不伪装系统）。
func (s *Service) LocalMaintenanceRevokeAllSessions(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, reason, requestID string) (int64, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if caller.operatorID == "" {
		return 0, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) || !validRevokeReason(reason) ||
		account.ValidateRequestID(requestID) != nil {
		return 0, fmt.Errorf("%w: 参数无效", ErrInvalidRequest)
	}
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.operatorID}
	return s.revokeAllForUser(ctx, targetUserID, reason, ActionSessionRevoke, actor,
		"session_local_maintenance_revoke_failed")
}

// LocalMaintenanceListUserSessions 按目标用户有界列出活动会话；返回当前页与
// HasMore。只读：不改变会话状态，不返回会话秘密/令牌；审计不可用时拒绝返回数据。
func (s *Service) LocalMaintenanceListUserSessions(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID string, limit, offset int) (
	[]LocalMaintenanceSessionSummary, bool, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if caller.operatorID == "" {
		return nil, false, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) {
		return nil, false, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	result, err := s.store.ListUserSessions(ctx, UserSessionQuery{
		UserID: targetUserID, Now: s.clockNow(), Offset: offset, PageSize: limit})
	if err != nil {
		return nil, false, s.storeFailure(ctx, "读取目标用户会话列表", err)
	}
	summaries := make([]LocalMaintenanceSessionSummary, 0, len(result.Records))
	for _, record := range result.Records {
		summary := record.summary(false)
		summaries = append(summaries, LocalMaintenanceSessionSummary{
			ID: summary.ID, AppID: summary.AppID, Kind: summary.Kind,
			Reason: summary.Reason, CreatedAt: summary.CreatedAt,
			LastSeenAt: summary.LastSeenAt, IdleExpiresAt: summary.IdleExpiresAt,
			AbsoluteExpiresAt: summary.AbsoluteExpiresAt,
			Address:           summary.Client.Address, UserAgent: summary.Client.UserAgent})
	}
	if err := s.audit.Record(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.operatorID},
		Action:  "session.local_maintenance_list",
		Target:  audit.Target{Type: "user", ID: targetUserID},
		Outcome: audit.OutcomeSuccess,
	}); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	consumed := int64(offset + len(summaries))
	return summaries, consumed < result.Total, nil
}
