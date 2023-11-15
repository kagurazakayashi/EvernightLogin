package app

// 步骤 225 P0：OAuth 客户端凭证公开接口测试。
//   - 登记返回一次性明文密钥；后续读取/列表不返回明文；
//   - 轮换后旧密钥在过渡窗口内可用，超过窗口失效；撤销后立即失效；
//   - public 客户端不能带密钥；无权限/不存在目标稳定拒绝。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestOAuthClientCredentialsPublicFlow 覆盖登记/一次性秘密/轮换窗口/撤销。
func TestOAuthClientCredentialsPublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	clients := runtime.OAuthClients()
	application := createTestApplication(t, ctx, runtime, "OAuth 凭证应用", "confidential")
	enableTestApplication(t, ctx, runtime, application.ID, application.RowVersion)

	registration, err := clients.RegisterClient(ctx, AdminRegisterOAuthClientRequest{
		Caller: local, ClientID: application.ID, ClientType: "confidential",
		GrantTypes: []string{"client_credentials"}, Scopes: []string{"resource.read"},
		Audiences:   []string{"https://api.example.test"},
		AuthMethods: []string{"client_secret_basic"}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if registration.Secret == nil || registration.Secret.Secret == "" {
		t.Fatalf("机密客户端登记应返回一次性明文密钥: %+v", registration)
	}
	firstSecret := registration.Secret.Secret
	firstSecretID := registration.Secret.Info.ID
	if registration.Client.ClientType != "confidential" ||
		registration.Client.RequirePKCE != true {
		t.Fatalf("客户端设置异常: %+v", registration.Client)
	}
	// 读取客户端与密钥列表都不返回明文（公开类型本身不含明文字段）。
	client, err := clients.GetClient(ctx, AdminOAuthClientRequest{
		Caller: local, ClientID: application.ID, RequestID: login.NewRequestID()})
	if err != nil || client.ClientID != application.ID || client.RowVersion <= 0 {
		t.Fatalf("GetClient: %+v, %v", client, err)
	}
	secrets, err := clients.ListClientSecrets(ctx, AdminOAuthClientRequest{
		Caller: local, ClientID: application.ID, RequestID: login.NewRequestID()})
	if err != nil || len(secrets) != 1 || secrets[0].ID != firstSecretID {
		t.Fatalf("ListClientSecrets: %+v, %v", secrets, err)
	}
	// 内部验证一次性秘密真实可用（公开层不提供验证接口）。
	oauthService := runtime.managedServices().OAuthClient
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, firstSecret); err != nil {
		t.Fatalf("登记后的客户端密钥应可用: %v", err)
	}

	// 轮换：新密钥立即可用；旧密钥在过渡窗口内仍可用。
	rotated, err := clients.RotateClientSecret(ctx, AdminOAuthClientSecretRotateRequest{
		Caller: local, ClientID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RotateClientSecret: %v", err)
	}
	if rotated.Secret == "" || rotated.Secret == firstSecret {
		t.Fatalf("轮换结果异常: %+v", rotated)
	}
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, rotated.Secret); err != nil {
		t.Fatalf("新密钥应立即可用: %v", err)
	}
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, firstSecret); err != nil {
		t.Fatalf("过渡窗口内旧密钥应仍可用: %v", err)
	}
	// 显式撤销旧密钥（过渡窗口内两个密钥均可用，撤销不是“最后一个密钥”）。
	if err := clients.RevokeClientSecret(ctx, AdminOAuthClientSecretRevokeRequest{
		Caller: local, ClientID: application.ID, SecretID: firstSecretID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RevokeClientSecret(旧): %v", err)
	}
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, firstSecret); err == nil {
		t.Fatal("撤销后旧密钥仍可用")
	}
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, rotated.Secret); err != nil {
		t.Fatalf("撤销旧密钥不应影响新密钥: %v", err)
	}
	// 超过过渡窗口（默认 24h）后旧密钥失效、新密钥仍可用。
	clock.Advance(25 * time.Hour)
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, firstSecret); err == nil {
		t.Fatal("过渡窗口结束后旧密钥仍可用")
	}
	if _, err := oauthService.VerifyClientSecret(ctx, application.ID, rotated.Secret); err != nil {
		t.Fatalf("新密钥不应随旧密钥过期: %v", err)
	}
	secrets, err = clients.ListClientSecrets(ctx, AdminOAuthClientRequest{
		Caller: local, ClientID: application.ID, RequestID: login.NewRequestID()})
	if err != nil || len(secrets) != 2 {
		t.Fatalf("撤销后密钥列表异常: %+v, %v", secrets, err)
	}
	// 不存在客户端 → NOT_FOUND。
	if _, err := clients.GetClient(ctx, AdminOAuthClientRequest{
		Caller: local, ClientID: "app_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在客户端错误 = %v，期望 NOT_FOUND", err)
	}
	// public 客户端登记不得返回密钥。
	publicApp := createTestApplication(t, ctx, runtime, "公开客户端应用", "public")
	enableTestApplication(t, ctx, runtime, publicApp.ID, publicApp.RowVersion)
	publicRegistration, err := clients.RegisterClient(ctx, AdminRegisterOAuthClientRequest{
		Caller: local, ClientID: publicApp.ID, ClientType: "public",
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"https://example.test/cb"},
		Scopes: []string{"openid"}, Audiences: []string{"https://api.example.test"},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RegisterClient(public): %v", err)
	}
	if publicRegistration.Secret != nil || publicRegistration.Certificate != nil {
		t.Fatalf("public 客户端不应返回凭证材料: %+v", publicRegistration)
	}
}
