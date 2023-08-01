package serverapp

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
)

// recoveryPasskeyBinder 用真实 Passkey WebAuthn 注册完成恢复流程的新强因素绑定；
// 客户端响应必须由 passkey 服务真实校验，未验证不会产生 FactorProof。
type recoveryPasskeyBinder struct {
	passkeys *passkey.Service
	now      func() time.Time
}

var _ recovery.FactorBinder = (*recoveryPasskeyBinder)(nil)

func (b *recoveryPasskeyBinder) BeginRebind(ctx context.Context,
	request recovery.FactorBindRequest) (recovery.FactorBindStart, error) {
	if b == nil || b.passkeys == nil {
		return recovery.FactorBindStart{}, fmt.Errorf("Passkey 恢复绑定未装配")
	}
	if request.Method != recovery.MethodPasskey {
		return recovery.FactorBindStart{}, recovery.ErrMethodNotAllowed
	}
	caller, err := passkey.UserCaller(request.UserID)
	if err != nil {
		return recovery.FactorBindStart{}, recovery.ErrBinderUnavailable
	}
	start, err := b.passkeys.BeginRegistrationWithPurpose(ctx, caller,
		request.RequestID, passkey.PurposeBoth)
	if err != nil {
		return recovery.FactorBindStart{}, err
	}
	return recovery.FactorBindStart{Method: recovery.MethodPasskey, BindingID: start.CeremonyID,
		PublicData: []byte(start.PublicKey), ExpiresAt: start.ExpiresAt}, nil
}

func (b *recoveryPasskeyBinder) VerifyRebind(ctx context.Context,
	request recovery.FactorVerifyRequest) (recovery.FactorProof, error) {
	if b == nil || b.passkeys == nil {
		return recovery.FactorProof{}, fmt.Errorf("Passkey 恢复绑定未装配")
	}
	if request.Method != recovery.MethodPasskey {
		return recovery.FactorProof{}, recovery.ErrMethodNotAllowed
	}
	caller, err := passkey.UserCaller(request.UserID)
	if err != nil {
		return recovery.FactorProof{}, recovery.ErrBinderUnavailable
	}
	credential, err := b.passkeys.FinishRegistrationTrusted(ctx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: request.BindingID,
			Response: request.Response, RequestID: request.RequestID})
	if err != nil {
		return recovery.FactorProof{}, err
	}
	now := time.Now()
	if b.now != nil {
		now = b.now()
	}
	return recovery.FactorProof{Method: recovery.MethodPasskey, FactorRef: credential.ID,
		UserVerified: true, VerifiedAt: now}, nil
}
