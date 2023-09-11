package app

// 公开会话校验门面的回归测试：签名/内容、CSRF、过期、撤销、受限会话拒绝。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestSessionServiceValidateAndCSRF(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC))
	runtime := openTestRuntime(t, Options{Now: clock.Now})
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	const password = "K8$wR3!nB6@yF1#v"
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "alice", Password: password, Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	loggedIn, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "alice", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loggedIn.Restricted || len(loggedIn.SessionSecret) == 0 || len(loggedIn.CSRFSecret) == 0 {
		t.Fatalf("无因素账户应得到完整会话与 CSRF 秘密: %+v", loggedIn)
	}
	info, err := runtime.Sessions().Validate(ctx, loggedIn.SessionSecret)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if info.UserID != user.ID || info.SessionID != loggedIn.SessionID {
		t.Fatalf("会话快照不匹配: %+v", info)
	}
	if info.ExpiresAt.IsZero() || info.IdleExpiresAt.IsZero() || info.CreatedAt.IsZero() {
		t.Fatalf("会话时间线不完整: %+v", info)
	}
	if len(info.AuthMethods) == 0 {
		t.Fatalf("完整会话应带认证方法: %+v", info)
	}
	if err := runtime.Sessions().ValidateCSRF(ctx, loggedIn.SessionSecret,
		string(loggedIn.CSRFSecret)); err != nil {
		t.Fatalf("正确 CSRF 应通过: %v", err)
	}
	if err := runtime.Sessions().ValidateCSRF(ctx, loggedIn.SessionSecret, "wrong"); err == nil {
		t.Fatal("错误 CSRF 应被拒绝")
	}
	if _, err := runtime.Sessions().Validate(ctx, []byte("not-a-session")); err == nil {
		t.Fatal("伪造会话应被拒绝")
	}
	if err := runtime.Sessions().ValidateCSRF(ctx, loggedIn.SessionSecret, ""); err == nil {
		t.Fatal("空 CSRF 应被拒绝")
	}
	if err := runtime.Sessions().Revoke(ctx, loggedIn.SessionSecret); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := runtime.Sessions().Validate(ctx, loggedIn.SessionSecret); err == nil {
		t.Fatal("撤销后会话必须失效")
	}
	if err := runtime.Sessions().ValidateCSRF(ctx, loggedIn.SessionSecret,
		string(loggedIn.CSRFSecret)); err == nil {
		t.Fatal("撤销后 CSRF 也必须失效")
	}
}

func TestSessionServiceValidateExpiry(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC))
	runtime := openTestRuntime(t, Options{Now: clock.Now})
	const password = "K8$wR3!nB6@yF1#v"
	if _, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "expiry-user", Password: password, Nickname: "Expiry",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	loggedIn, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "expiry-user", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := runtime.Sessions().Validate(ctx, loggedIn.SessionSecret); err != nil {
		t.Fatalf("登录后立即校验应通过: %v", err)
	}
	// 默认空闲到期 30 分钟；不调用 Renew，推进 31 分钟后必须失效。
	clock.Advance(31 * time.Minute)
	if _, err := runtime.Sessions().Validate(ctx, loggedIn.SessionSecret); err == nil {
		t.Fatal("空闲过期后会话必须失效")
	}
}

func TestSessionServiceValidateRejectsRestricted(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	runtime := openTestRuntime(t, Options{Now: clock.Now})
	const password = "K8$wR3!nB6@yF1#v"
	setupUserWithTOTP(t, runtime, clock, "restricted-user", password)
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "restricted-user", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !restricted.Restricted || len(restricted.SessionSecret) == 0 {
		t.Fatalf("启用 TOTP 后登录应返回受限会话: %+v", restricted)
	}
	if _, err := runtime.Sessions().Validate(ctx, restricted.SessionSecret); err == nil {
		t.Fatal("受限会话不能通过业务会话校验")
	}
}
