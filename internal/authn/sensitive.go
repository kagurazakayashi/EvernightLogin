package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// SensitiveRunner 是敏感操作收敛入口（生产实现 *reauth.Service）。
type SensitiveRunner = reauth.OperationRunner

// authorizeSensitive 在设置/修改密码前执行步骤 38 敏感策略判定。
// 未注入时默认拒绝（fail-closed），只有显式 AllowLegacyWithoutSensitive 才沿用
// 既有“当前密码复核”逻辑；MFA/更强认证要求不可满足时由 reauth 拒绝，不降级。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, targetUserID, requestID string) (reauth.Result, error) {
	if s.sensitive == nil {
		if s.allowLegacy {
			return reauth.Result{}, nil
		}
		return reauth.Result{}, ErrAccessDenied
	}
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	operationID := "password.change"
	if caller.actorKind() != audit.ActorUser {
		operationID = "password.admin_reset"
	}
	result, err := s.sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID,
		TargetType: "user", TargetID: targetUserID,
		Params:      map[string]string{"target_user_id": targetUserID},
		Description: "修改密码", RequestID: requestID,
	})
	if err != nil {
		if errors.Is(err, reauth.ErrRateLimited) {
			return reauth.Result{}, ErrRateLimited
		}
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// notifySensitive 发送密码变更成功告知；失败只记录日志，不回滚已成功变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if s.sensitive == nil || result.OperationID == "" {
		return
	}
	if err := s.sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.logger.Warn("密码变更安全告知未完成", "error", err)
	}
}
