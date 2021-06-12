package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// TestStrongAuthTimestampGatesManagement 验证强认证时间只能出现在完整、非受限的
// 认证结果中，并决定会话能否通过管理访问的强认证闸门（步骤 43 与 39/30 衔接）。
func TestStrongAuthTimestampGatesManagement(t *testing.T) {
	env := newTestEnv(t)
	const userID = "usr_00000000000000000000000000000043"
	env.insertUser(userID, "stronguser", account.StatusActive, 1)
	now := env.clock.Now()
	complete := authn.AuthenticateResult{
		UserID: userID, Username: "stronguser",
		Outcome:               authn.OutcomeComplete,
		CompletedMethods:      []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
		CompletedAt:           now,
		StrongAuthCompletedAt: now,
		SecurityVersion:       1,
	}
	issued, err := env.session.Login(env.ctx, session.LoginRequest{Result: complete})
	if err != nil {
		t.Fatalf("强认证完整登录: %v", err)
	}
	validated, err := env.session.Validate(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("校验强认证会话: %v", err)
	}
	if !validated.CanAccessManagement() {
		t.Fatal("Passkey/安全密钥强认证会话应满足管理访问强认证要求")
	}
	if _, err := env.session.AuthorizeManagement(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("强认证有效期内管理访问应通过: %v", err)
	}
	// 强认证新鲜度窗口：强认证时间早于 Options.StrongAuthMaxAge 时管理访问必须
	// 重新强认证（会话本身仍活跃，证明不是简单把会话判过期）。
	oldStrong := complete
	oldStrong.StrongAuthCompletedAt = now.Add(-session.DefaultStrongAuthMaxAge - time.Minute)
	oldIssued, err := env.session.Login(env.ctx, session.LoginRequest{Result: oldStrong})
	if err != nil {
		t.Fatalf("旧强认证时间会话签发: %v", err)
	}
	if _, err := env.session.AuthorizeManagement(env.ctx, oldIssued.Secret.Reveal()); !errors.Is(err, session.ErrStrongAuthRequired) {
		t.Fatalf("强认证过期后管理访问应要求重新强认证: %v", err)
	}
	// 不带强认证时间的完整会话：可用于业务，但管理访问仍要求强认证。
	noStrong := complete
	noStrong.StrongAuthCompletedAt = time.Time{}
	plain, err := env.session.Login(env.ctx, session.LoginRequest{Result: noStrong})
	if err != nil {
		t.Fatalf("普通完整登录: %v", err)
	}
	plainValidated, err := env.session.Validate(env.ctx, plain.Secret.Reveal())
	if err != nil {
		t.Fatalf("校验普通会话: %v", err)
	}
	if plainValidated.CanAccessManagement() {
		t.Fatal("未完成强认证的会话不能访问管理接口")
	}
	// 受限认证结果不得携带强认证时间（防伪造/降级）。
	restricted := authn.AuthenticateResult{
		UserID: userID, Username: "stronguser",
		Outcome:               authn.OutcomePendingSecondFactor,
		CompletedMethods:      []authn.Method{authn.MethodPassword},
		CompletedAt:           now,
		RequiredSteps:         []authn.Step{authn.StepSecondFactor},
		Restricted:            true,
		StrongAuthCompletedAt: now,
		SecurityVersion:       1,
	}
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: restricted}); err == nil {
		t.Fatal("受限结果携带强认证时间应被拒绝")
	}
}
