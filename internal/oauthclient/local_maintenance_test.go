package oauthclient_test

// 步骤 290 本地维护 OAuth 客户端凭证窄方法定向测试。
//
// 覆盖：本地维护登记保密客户端（一次性秘密）、读取状态、轮换秘密（新明文一次）、
// 撤销秘密；空本地身份/非法客户端明确失败。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// TestLocalMaintenanceOAuthClient 覆盖本地维护客户端登记/轮换/撤销。
func TestLocalMaintenanceOAuthClient(t *testing.T) {
	env := newTestEnv(t, nil)
	caller, err := oauthclient.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	result, err := env.svc.LocalMaintenanceRegisterClient(env.ctx, caller,
		oauthclient.RegisterRequest{ClientID: appConfidential,
			ClientType:   oauthclient.ClientTypeConfidential,
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			RedirectURIs: []string{"https://client.example.test/callback"},
			Audiences:    []string{"https://api.example.test"},
			AuthMethods:  []string{"client_secret_basic"},
			RequestID:    "req-local-oauth-register"})
	if err != nil {
		t.Fatalf("本地登记客户端: %v", err)
	}
	if result.Secret == nil || result.Secret.Secret == "" {
		t.Fatalf("登记应一次性返回秘密: %+v", result)
	}
	state, err := env.svc.LocalMaintenanceClientState(env.ctx, caller, appConfidential)
	if err != nil {
		t.Fatalf("读取客户端状态: %v", err)
	}
	if !state.Registered || state.ClientType != oauthclient.ClientTypeConfidential ||
		len(state.Secrets) == 0 {
		t.Fatalf("客户端状态异常: %+v", state)
	}
	rotated, err := env.svc.LocalMaintenanceRotateClientSecret(env.ctx, caller,
		appConfidential, "req-local-oauth-rotate")
	if err != nil {
		t.Fatalf("本地轮换秘密: %v", err)
	}
	if rotated.Secret == "" || rotated.Secret == result.Secret.Secret {
		t.Fatalf("轮换秘密异常: %+v", rotated)
	}
	if err := env.svc.LocalMaintenanceRevokeClientSecret(env.ctx, caller,
		appConfidential, rotated.Info.ID, "req-local-oauth-revoke"); err != nil {
		t.Fatalf("本地撤销秘密: %v", err)
	}
	// 空本地身份/非法客户端明确失败。
	if _, err := env.svc.LocalMaintenanceClientState(env.ctx,
		oauthclient.LocalMaintenanceCaller{}, appConfidential); !errors.Is(
		err, oauthclient.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.svc.LocalMaintenanceClientState(env.ctx, caller,
		"bad-client"); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("非法客户端错误 = %v，期望 ErrInvalidRequest", err)
	}
}
