package emailchange

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// SensitiveRunner 是敏感操作收敛入口（生产实现 *reauth.Service）。默认 nil 时
// 敏感操作直接拒绝（fail-closed）；仅显式 AllowLegacyWithoutSensitive 才回退既有
// 近期身份验证闸门。接线后额外经步骤 38 策略判定。
type SensitiveRunner = reauth.OperationRunner

// reauthVerifyResult 是确认邮箱变更时保存的执行前结果，供成功后告知使用。
type reauthVerifyResult struct {
	result reauth.Result
	ok     bool
}

// authorizeSensitive 在申请邮箱变更前执行敏感策略判定；Sensitive 未注入时默认拒绝，
// 仅 AllowLegacyWithoutSensitive 显式开启才回退既有 ReauthVerifier 闸门（fail-closed）。
func (s *Service) authorizeSensitive(ctx context.Context, caller Caller, operationID, targetType,
	targetID string, params map[string]string) (reauth.Result, error) {
	if s.opts.Sensitive == nil {
		if s.allowLegacy {
			// 显式过渡开关：沿用既有近期身份验证 fail-closed 闸门。
			return reauth.Result{}, nil
		}
		return reauth.Result{}, ErrAccessDenied
	}
	guardCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: targetType, TargetID: targetID,
		Params: params, Description: "邮箱变更", RequestID: params["request_id"],
	})
	if err != nil {
		return reauth.Result{}, mapReauthError(err)
	}
	return result, nil
}

// authorizeSensitiveVerify 在确认令牌切换邮箱前按策略判定；令牌持有者是操作主体。
func (s *Service) authorizeSensitiveVerify(ctx context.Context, userID, requestID string) (reauthVerifyResult, error) {
	if s.opts.Sensitive == nil {
		if s.allowLegacy {
			return reauthVerifyResult{}, nil
		}
		return reauthVerifyResult{}, ErrAccessDenied
	}
	guardCaller, err := reauth.UserCaller(userID)
	if err != nil {
		return reauthVerifyResult{}, ErrAccessDenied
	}
	result, err := s.opts.Sensitive.Authorize(ctx, guardCaller, reauth.Request{
		ScopeID: "system", OperationID: "email.change.verify",
		TargetType: "user", TargetID: userID,
		Params:      map[string]string{"request_id": requestID},
		Description: "确认邮箱变更", RequestID: requestID,
	})
	if err != nil {
		return reauthVerifyResult{}, mapReauthError(err)
	}
	return reauthVerifyResult{result: result, ok: true}, nil
}

// notifySensitive 发送成功告知；告知失败不回滚已经成功的业务变更。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if s.opts.Sensitive == nil || result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("邮箱变更安全告知未完成", "error", err)
	}
}

// notifySensitiveVerify 发送确认邮箱变更后的安全告知。
func (s *Service) notifySensitiveVerify(ctx context.Context, verified reauthVerifyResult) {
	if !verified.ok {
		return
	}
	s.notifySensitive(ctx, verified.result)
}

// mapReauthError 把再次认证错误映射为邮箱变更领域既有错误，保持 API 语义。
func mapReauthError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, reauth.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, reauth.ErrReauthRequired), errors.Is(err, reauth.ErrConfirmationRequired),
		errors.Is(err, reauth.ErrMFARequired), errors.Is(err, reauth.ErrAuthenticationFailed),
		errors.Is(err, reauth.ErrChallengeInvalid), errors.Is(err, reauth.ErrChallengeExpired),
		errors.Is(err, reauth.ErrAttemptsExceeded), errors.Is(err, reauth.ErrApprovalInvalid),
		errors.Is(err, reauth.ErrApprovalExpired), errors.Is(err, reauth.ErrApprovalConsumed),
		errors.Is(err, reauth.ErrRateLimited):
		return ErrReauthRequired
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}
