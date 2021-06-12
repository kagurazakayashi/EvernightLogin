package passkey_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
)

// newMFAWithRealPasskey 在 passkey 测试环境上装配真实依赖的 mfa 服务：Passkeys 使用
// 真实 *passkey.Service（真实 WebAuthn ceremony），只有邮件发送器用测试替身（本用例
// 不走邮件因素）。这是 internal/mfa 第二因素与真实 passkey ceremony 的端到端联调。
func newMFAWithRealPasskey(t *testing.T, env *testEnv) *mfa.Service {
	t.Helper()
	keyring, err := secrets.GenerateKeyring("k1", seedTime)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	totpStore, err := totpsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("TOTP 存储: %v", err)
	}
	totpService, err := totp.New(totp.Options{
		Store: totpStore, Audit: env.recorder, Sealer: sealer, Reauth: env.runner,
		IssuerName: "登录服务", Now: func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("TOTP 服务: %v", err)
	}
	mfaStore, err := mfasqlite.New(env.raw)
	if err != nil {
		t.Fatalf("MFA 存储: %v", err)
	}
	service, err := mfa.New(mfa.Options{
		Store: mfaStore, Audit: env.recorder, Credentials: credentialService,
		Sessions: env.session, Mailer: mailer.SenderFunc(func(ctx context.Context, message mailer.Message) error {
			return nil // 本用例只走安全密钥第二步，不发送邮件。
		}),
		TOTP: totpService, Passkeys: env.service,
		FromAddress: "security@example.com", AppName: "登录服务",
		SupportURL: "https://example.com/support",
		Now:        func() time.Time { return env.now },
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("MFA 服务: %v", err)
	}
	return service
}

// TestMFASecurityKeySecondFactorWithRealPasskeyCeremony 是真实链路端到端用例：
// 密码认证结果 → mfa 选择安全密钥第二步 → 真实 internal/passkey WebAuthn 注册/断言
// （ECDSA 模拟认证器，不是真机）→ 完整会话与强认证时间 → 管理访问闸门通过。
func TestMFASecurityKeySecondFactorWithRealPasskeyCeremony(t *testing.T) {
	env := newTestEnv(t, nil)
	simulator := newAuthenticator(t)
	purpose := env.registerCredentialWithPurpose(aliceID, "安全密钥",
		passkey.PurposeSecondFactor, simulator)
	if purpose.ID == "" {
		t.Fatal("注册第二步凭证失败")
	}
	mfaService := newMFAWithRealPasskey(t, env)
	base := authn.AuthenticateResult{
		UserID: aliceID, Username: "alice",
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      env.now, SecurityVersion: 1,
	}
	start, err := mfaService.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: base, RequestID: "req-e2e-1"})
	if err != nil {
		t.Fatalf("启动安全密钥第二步: %v", err)
	}
	if start.FactorType != mfa.FactorPasskey || start.PasskeyCeremonyID == "" ||
		len(start.PasskeyOptions) == 0 {
		t.Fatalf("未选择真实安全密钥第二步: %+v", start)
	}
	response := simulator.assertionResponse(t, start.PasskeyOptions, testOrigin, "", 1, nil)
	result, err := mfaService.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		PasskeyCeremonyID: start.PasskeyCeremonyID, PasskeyResponse: response,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-e2e-2"})
	if err != nil {
		t.Fatalf("真实安全密钥第二步验证: %v", err)
	}
	if result.Session.Session.IsRestricted() || result.Authenticated.StrongAuthCompletedAt.IsZero() {
		t.Fatalf("应签发完整会话并记录强认证时间: %+v", result.Session.Session)
	}
	if !containsMethod(result.Authenticated.CompletedMethods, authn.MethodSecurityKey) {
		t.Fatalf("完整认证结果应包含安全密钥方法: %v", result.Authenticated.CompletedMethods)
	}
	validated, err := env.session.Validate(env.ctx, result.Session.Secret.Reveal())
	if err != nil {
		t.Fatalf("校验完整会话: %v", err)
	}
	if _, err := env.session.AuthorizeManagement(env.ctx, result.Session.Secret.Reveal()); err != nil {
		t.Fatalf("安全密钥强认证应通过管理闸门: %v", err)
	}
	if validated.UserID != aliceID {
		t.Fatalf("会话用户异常: %s", validated.UserID)
	}
	// 同一挑战重放拒绝。
	if _, err := mfaService.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		PasskeyCeremonyID: start.PasskeyCeremonyID, PasskeyResponse: response,
		ExistingSession: start.RestrictedSession.Secret.Reveal(),
		RequestID:       "req-e2e-3"}); err == nil {
		t.Fatal("第二步重放应被拒绝")
	}
}

func containsMethod(methods []authn.Method, want authn.Method) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}
