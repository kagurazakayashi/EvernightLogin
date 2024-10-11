package totp

// 步骤 288（本地维护控制台）：TOTP 因素只读列举与本地维护删除。
//
// 普通入口 RemoveBinding 要求用户本人 + 当前验证码 + 再次认证；本地维护控制台在
// 丢失 MFA 的救援场景下没有这些因素，用户已授权其以 OS 访问权限直接清除。本文件
// 提供显式 LocalMaintenanceCaller 窄方法：
//   - 列举目标用户绑定元数据（无种子/密文）；
//   - 删除指定/全部 TOTP 绑定：跳过用户验证码/再次认证，但仍写关键审计、同一
//     事务递增 security_version、并按既有系统路径撤销会话，保持与普通删除相同的
//     失效语义（不新增第二套因素存储/事务）。
//
// 边界：本地绝对权限不等于跳过策略/一致性；删除最后一个因素由调用方画面显式确认
// 并提示重绑路径（控制台不是永久远程免 MFA）。

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

// LocalMaintenanceBinding 是 TOTP 绑定元数据（脱敏）。
type LocalMaintenanceBinding struct {
	ID          string
	Status      string
	Algorithm   string
	Digits      int
	CreatedAt   time.Time
	ActivatedAt time.Time
}

// LocalMaintenanceListBindings 列出目标用户全部 TOTP 绑定元数据。
func (s *Service) LocalMaintenanceListBindings(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID string) ([]LocalMaintenanceBinding, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if caller.operatorID == "" {
		return nil, ErrAccessDenied
	}
	if !account.ValidUserID(targetUserID) {
		return nil, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	bindings, err := s.opts.Store.List(ctx, targetUserID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	result := make([]LocalMaintenanceBinding, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, LocalMaintenanceBinding{ID: binding.ID,
			Status: string(binding.Status), Algorithm: string(binding.Algorithm),
			Digits: binding.Digits, CreatedAt: binding.CreatedAt,
			ActivatedAt: binding.ActivatedAt})
	}
	return result, nil
}

// LocalMaintenanceRemoveBinding 删除目标用户当前 active TOTP 绑定（无验证码/
// 再次认证；本地救援专用）。已有绑定不存在时返回 ErrBindingNotFound；成功后
// 同事务递增 security_version 并以系统路径撤销会话（失败只告警，安全版本已保证
// 会话失效）。
func (s *Service) LocalMaintenanceRemoveBinding(ctx context.Context,
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
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.operatorID}
	active, found, err := s.opts.Store.GetActive(ctx, targetUserID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrBindingNotFound
	}
	now := s.now()
	critical := s.critical("mfa.totp_local_removed", actor, active.ID, requestID,
		[]audit.FieldChange{{Field: "status", Before: "active", After: "disabled"},
			{Field: "target_user", After: targetUserID},
			{Field: "maintenance", After: "local_console"}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		disabled, disableErr := s.opts.Store.DisableActiveTx(txCtx, tx, targetUserID, now)
		if disableErr != nil {
			return disableErr
		}
		if !disabled {
			return ErrBindingNotFound
		}
		return s.opts.Store.IncrementUserSecurityVersionTx(txCtx, tx, targetUserID, now)
	}); err != nil {
		return mapCriticalError(err)
	}
	if !isNil(s.opts.SessionInvalidator) {
		if _, revokeErr := s.opts.SessionInvalidator.RevokeAllForUser(ctx,
			targetUserID, "totp_local_removed"); revokeErr != nil {
			s.opts.Logger.Warn("本地维护解除 TOTP 后撤销会话失败", "error", revokeErr)
		}
	}
	return nil
}
