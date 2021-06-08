package authn

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// ReauthPasswordVerifier 把正式密码认证服务适配为 internal/reauth.PasswordVerifier。
//
// 它复用 Authenticate 的真实密码校验、失败限流与审计：只有密码确实正确且返回的
// 账户与挑战绑定账户一致时才返回完成事实；待第二因素/待改密等受限结果会带上
// Complete=false，由再次认证层限制高权限操作。MFA/Passkey 未实现，因此这里不会
// 声称强认证强度；强认证要求由敏感策略在再次认证层 fail-closed。
type ReauthPasswordVerifier struct {
	Service *Service
}

var _ reauth.PasswordVerifier = ReauthPasswordVerifier{}

// VerifyPassword 实现 reauth.PasswordVerifier。
func (v ReauthPasswordVerifier) VerifyPassword(ctx context.Context,
	request reauth.PasswordVerifyRequest) (reauth.PasswordVerifyResult, error) {
	if v.Service == nil {
		// 未接线时不得把挑战当作已通过：fail-closed。
		return reauth.PasswordVerifyResult{}, fmt.Errorf("%w: 未配置密码认证服务", reauth.ErrMFARequired)
	}
	result, err := v.Service.Authenticate(ctx, AuthenticateRequest{
		Identifier: request.Username,
		Password:   request.Password,
		RequestID:  request.RequestID,
	})
	if err != nil {
		// 统一公开失败原因，不细分账户是否存在或密码错误。
		return reauth.PasswordVerifyResult{}, fmt.Errorf("%w: %w", reauth.ErrAuthenticationFailed, err)
	}
	if result.UserID != request.UserID {
		return reauth.PasswordVerifyResult{}, reauth.ErrAuthenticationFailed
	}
	complete := result.IsComplete() && len(result.RequiredSteps) == 0 && !result.Restricted
	return reauth.PasswordVerifyResult{
		UserID:      result.UserID,
		CompletedAt: result.CompletedAt,
		Complete:    complete,
	}, nil
}
