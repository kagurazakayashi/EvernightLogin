package serverapp

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// reauthStrongFactorVerifier 用真实 TOTP 服务验证再次认证要求的第二因素。
// 只接受已绑定且处于 active 的 TOTP；没有 TOTP 的账户（例如仅 Passkey）在页面
// 层面暂时无法走此路径，会 fail-closed 而不是降级为密码。
type reauthStrongFactorVerifier struct {
	totp *totp.Service
	now  func() time.Time
}

// VerifyStrongFactor 实现 reauth.StrongFactorVerifier。
func (v *reauthStrongFactorVerifier) VerifyStrongFactor(ctx context.Context,
	request reauth.StrongFactorVerifyRequest) (reauth.StrongFactorVerifyResult, error) {
	if v == nil || v.totp == nil {
		return reauth.StrongFactorVerifyResult{}, fmt.Errorf("强因素验证器未装配")
	}
	active, err := v.totp.HasActive(ctx, request.UserID)
	if err != nil {
		return reauth.StrongFactorVerifyResult{}, err
	}
	if !active {
		return reauth.StrongFactorVerifyResult{}, fmt.Errorf("账户未绑定 TOTP 强因素")
	}
	if err := v.totp.VerifyLoginCode(ctx, request.UserID, request.TOTPCode); err != nil {
		return reauth.StrongFactorVerifyResult{}, err
	}
	now := time.Now()
	if v.now != nil {
		now = v.now()
	}
	return reauth.StrongFactorVerifyResult{UserID: request.UserID, CompletedAt: now,
		Method: "totp", UserVerified: true}, nil
}
