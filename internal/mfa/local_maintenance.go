package mfa

// 步骤 288（本地维护控制台）：邮件第二因素本地维护列举/删除。
//
// 普通 RemoveEmailFactor 要求调用者本人；本地维护在丢失因素场景以 OS 访问权限
// 直接清除。本窄方法复用同一 Store.RemoveFactorTx 与审计事务，跳过本人/再次认证；
// 删除后按既有系统路径撤销会话（安全版本语义与既有因素删除保持一致，不新增表）。
//
// 边界：不允许通过本方法读取邮件地址/验证码；不改变其他因素；不把“清除因素”
// 变成永久远程免 MFA（下一次远程登录仍按安全策略受限重绑）。

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

// LocalMaintenanceFactor 是因素只读摘要（脱敏）。
type LocalMaintenanceFactor struct {
	ID        string
	Type      FactorType
	State     string
	CreatedAt time.Time
}

// LocalMaintenanceFactors 列出目标用户全部因素（活动与停用）。
func (s *Service) LocalMaintenanceFactors(ctx context.Context,
	caller LocalMaintenanceCaller, targetUserID string) ([]LocalMaintenanceFactor, error) {
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
	factors, err := s.opts.Store.GetFactors(ctx, targetUserID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	result := make([]LocalMaintenanceFactor, 0, len(factors))
	for _, factor := range factors {
		result = append(result, LocalMaintenanceFactor{ID: factor.ID,
			Type: factor.Type, State: factor.State, CreatedAt: factor.CreatedAt})
	}
	return result, nil
}

// LocalMaintenanceRemoveEmailFactor 停用目标用户的邮件第二因素（无本人/验证码；
// 本地救援专用）。没有活动邮件因素时返回 ErrFactorNotFound。
//
// 语义说明（DEFERRED-M2A-1）：MFA 存储接口没有 security_version 递增操作；本方法
// 复用既有因素删除事务后仅能尽力批量撤销会话（真实 session.Service 实现可选接口），
// 与普通 RemoveEmailFactor 的安全版本语义保持一致，未额外伪造版本递增。
func (s *Service) LocalMaintenanceRemoveEmailFactor(ctx context.Context,
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
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: "mfa.factor_local_removed",
			Target:    audit.Target{Type: "user", ID: targetUserID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "factor_type", Before: string(FactorEmail), After: "disabled"},
				{Field: "maintenance", After: "local_console"}},
		},
		FailureReasonCode:   "mfa.factor_local_remove_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, removeErr := s.opts.Store.RemoveFactorTx(txCtx, tx, targetUserID,
			FactorEmail)
		if removeErr != nil {
			return removeErr
		}
		if !removed {
			return ErrFactorNotFound
		}
		return nil
	})
	if err != nil {
		return mapCriticalError(err)
	}
	// 会话批量撤销是可选的宿主能力：真实 *session.Service 实现该接口；测试替身
	// 未实现时跳过（安全版本/策略仍由后续登录校验兜底），不伪造撤销成功。
	type bulkSessionRevoker interface {
		RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error)
	}
	if !isNil(s.opts.Sessions) {
		if revoker, ok := s.opts.Sessions.(bulkSessionRevoker); ok {
			if _, revokeErr := revoker.RevokeAllForUser(ctx, targetUserID,
				"email_factor_local_removed"); revokeErr != nil {
				s.opts.Logger.Warn("本地维护移除邮件因素后撤销会话失败", "error", revokeErr)
			}
		}
	}
	return nil
}
