package recovery

// 步骤 288（本地维护控制台）：恢复代码只读状态与本地撤销。
//
// 本地维护在用户丢失 MFA/恢复代码的救援场景需要撤销目标用户当前恢复代码组；普通
// 流程只有用户本人（近期强认证）重新生成覆盖。本窄方法复用同一 Store 事务与审计：
//   - 把当前 active 组条件迁移为 GroupRevoked（显式本地撤销，不伪装成 superseded）；
//   - 同一事务递增 security_version，使旧恢复授权/会话立即失效；
//   - 提交后按既有系统路径撤销会话（失败只告警，安全版本已保证失效）。
//
// 边界：不生成新代码、不读取代码/摘要、不改变 MFA 因素；root 恢复仍按受控本地通道。

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

// LocalMaintenanceRecoveryStatus 是恢复代码只读状态（不含代码）。
type LocalMaintenanceRecoveryStatus struct {
	HasActiveGroup bool
	GroupID        string
	Generation     int64
	RemainingCodes int
	CreatedAt      time.Time
}

// LocalMaintenanceRecoveryStatus 读取目标用户当前恢复代码组状态。
func (s *Service) LocalMaintenanceRecoveryStatus(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID string) (LocalMaintenanceRecoveryStatus, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return LocalMaintenanceRecoveryStatus{}, err
	}
	if caller.operatorID == "" {
		return LocalMaintenanceRecoveryStatus{}, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) {
		return LocalMaintenanceRecoveryStatus{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	group, found, err := s.opts.Store.ActiveGroup(ctx, targetUserID)
	if err != nil {
		return LocalMaintenanceRecoveryStatus{}, ErrStoreUnavailable
	}
	if !found {
		return LocalMaintenanceRecoveryStatus{}, nil
	}
	codes, err := s.opts.Store.ListUnusedCodes(ctx, targetUserID)
	if err != nil {
		return LocalMaintenanceRecoveryStatus{}, ErrStoreUnavailable
	}
	return LocalMaintenanceRecoveryStatus{HasActiveGroup: true, GroupID: group.ID,
		Generation: group.Generation, RemainingCodes: len(codes),
		CreatedAt: group.CreatedAt}, nil
}

// LocalMaintenanceRevokeRecoveryCodes 撤销目标用户当前恢复代码组（无本人/再次
// 认证；本地救援专用）。没有 active 组时返回 ErrNoActiveGroup。
func (s *Service) LocalMaintenanceRevokeRecoveryCodes(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID, requestID string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if caller.operatorID == "" {
		return ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) || account.ValidateRequestID(requestID) != nil {
		return fmt.Errorf("%w: 参数无效", ErrInvalidRequest)
	}
	group, found, err := s.opts.Store.ActiveGroup(ctx, targetUserID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrNoActiveGroup
	}
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.operatorID}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: "recovery.codes_local_revoked",
			Target:    audit.Target{Type: "user", ID: targetUserID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "group_id", Before: group.ID, After: "revoked"},
				{Field: "maintenance", After: "local_console"}},
		},
		FailureReasonCode:   "recovery.codes_local_revoke_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(err)) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		invalidated, invalidateErr := s.opts.Store.InvalidateGroupTx(txCtx, tx, group.ID,
			GroupRevoked, now)
		if invalidateErr != nil {
			return invalidateErr
		}
		if !invalidated {
			return ErrConcurrentRotation
		}
		_, versionErr := s.opts.Store.IncrementSecurityVersionTx(txCtx, tx, targetUserID, now)
		return versionErr
	})
	if err != nil {
		return s.mapStoreError(err)
	}
	if !isNilInterface(s.opts.Sessions) {
		if revoker, ok := s.opts.Sessions.(interface {
			RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error)
		}); ok {
			if _, revokeErr := revoker.RevokeAllForUser(ctx, targetUserID,
				"recovery_codes_local_revoked"); revokeErr != nil {
				s.logger.Warn("本地撤销恢复代码后撤销会话失败", "error", revokeErr)
			}
		}
	}
	return nil
}
