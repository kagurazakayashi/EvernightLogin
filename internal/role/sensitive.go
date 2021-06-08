package role

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// SensitiveRunner 是敏感操作收敛入口（生产实现 *reauth.Service）。nil 时保持既有
// Authorizer/委派 Guard 保守校验；接线后角色/权限变更作为额外前置必须通过策略。
type SensitiveRunner = reauth.OperationRunner

// authorizeSensitive 执行敏感策略前置判定；任何失败都 fail-closed 为 ACCESS_DENIED，
// 不替代也不绕过既有的委派 Guard 事务内检查。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID, targetType,
	targetID string, params map[string]string) (reauth.Result, error) {
	if s.sensitive == nil {
		if s.allowLegacy {
			// 显式过渡开关：沿用既有 Authorizer/委派 Guard 保守校验。
			return reauth.Result{}, nil
		}
		// 未装配敏感策略时默认拒绝敏感操作，不静默跳过步骤 38 策略。
		return reauth.Result{}, ErrAccessDenied
	}
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: targetType, TargetID: targetID,
		Params: params, Description: "角色与权限变更", RequestID: caller.requestID,
	})
	if err != nil {
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// notifySensitive 发送成功告知；失败不回滚已完成变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if s.sensitive == nil || result.OperationID == "" {
		return
	}
	if err := s.sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.logger.Warn("角色变更安全告知未完成", "error", err)
	}
}
