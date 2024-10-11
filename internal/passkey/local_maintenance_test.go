package passkey_test

// 步骤 288 本地维护 Passkey 凭证列举/撤销定向测试。
//
// 覆盖：注册凭证后本地维护可列举、撤销（无本人再次认证）、重复撤销失败、非法
// 目标/空身份拒绝；撤销后凭证不再出现在活动列表。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
)

// TestLocalMaintenancePasskey 覆盖本地维护 Passkey 列举与撤销。
func TestLocalMaintenancePasskey(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	meta := env.registerCredential(aliceID, "我的手机", simulator)
	localCaller, err := passkey.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	credentials, err := env.service.LocalMaintenanceListCredentials(env.ctx,
		localCaller, aliceID)
	if err != nil {
		t.Fatalf("列举凭证: %v", err)
	}
	if len(credentials) != 1 || credentials[0].ID != meta.ID {
		t.Fatalf("凭证列表异常: %+v meta=%+v", credentials, meta)
	}
	if err := env.service.LocalMaintenanceRevokeCredential(env.ctx, localCaller,
		aliceID, meta.ID, "req-local-passkey-revoke"); err != nil {
		t.Fatalf("本地撤销凭证: %v", err)
	}
	credentials, err = env.service.LocalMaintenanceListCredentials(env.ctx,
		localCaller, aliceID)
	if err != nil {
		t.Fatalf("撤销后列举: %v", err)
	}
	if len(credentials) != 0 {
		t.Fatalf("撤销后不应有活动凭证: %+v", credentials)
	}
	if err := env.service.LocalMaintenanceRevokeCredential(env.ctx, localCaller,
		aliceID, meta.ID, "req-local-passkey-revoke-again"); !errors.Is(
		err, passkey.ErrCredentialNotFound) {
		t.Fatalf("重复撤销错误 = %v，期望 ErrCredentialNotFound", err)
	}
	if _, err := env.service.LocalMaintenanceListCredentials(env.ctx, localCaller,
		"bad-id"); !errors.Is(err, passkey.ErrInvalidRequest) {
		t.Fatalf("非法目标错误 = %v，期望 ErrInvalidRequest", err)
	}
	if err := env.service.LocalMaintenanceRevokeAllCredentials(env.ctx,
		passkey.LocalMaintenanceCaller{}, aliceID, "req-x"); !errors.Is(
		err, passkey.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
}
