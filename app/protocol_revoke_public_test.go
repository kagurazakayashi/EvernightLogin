package app

// 步骤 228：OAuth 令牌撤销公开 Go 入口与失效传播测试。
//   - RFC 7009：错误客户端拒绝、未知/他人令牌静默成功不枚举、重复撤销幂等；
//   - 撤销自己的访问令牌后在线内省 inactive；
//   - 用户会话注销当前会话成功，撤权/退出缺少会话时 fail-closed；
//   - 全部复用同一 oauthflow 撤销服务，公开类型不含令牌原文/路径。

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

func TestProtocolPublicRevocation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clock := newTestClock(time.Date(2026, 11, 25, 15, 0, 0, 0, time.UTC))
	databasePath := filepath.Join(dir, "login.db")
	masterKeyPath := filepath.Join(dir, "master.key")
	open := func(cfg login.Config) *Runtime {
		t.Helper()
		runtime, err := Open(ctx, Options{Config: &cfg, DatabasePath: databasePath,
			MasterKeyFile: masterKeyPath, CreateMasterKey: true, Migrate: true,
			OperatorID: "revoke-test", Now: clock.Now})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return runtime
	}
	first := open(testConfig())
	t.Cleanup(func() { _ = first.Close(context.Background()) })
	user, err := first.Users().Create(ctx, CreateUserRequest{
		Username: "revoke-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建撤销用户: %v", err)
	}
	local := first.LocalAdmin()
	newApp := func(name, clientType string) (string, int64) {
		t.Helper()
		app, appErr := first.Admin().CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, OwnerUserID: user.ID,
			ClientType: clientType, RequestID: login.NewRequestID()})
		if appErr != nil {
			t.Fatalf("创建应用 %s: %v", name, appErr)
		}
		if _, appErr = first.Admin().SetApplicationEnabled(ctx,
			AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: app.ID,
				Enabled: true, ExpectedRowVersion: app.RowVersion,
				RequestID: login.NewRequestID()}); appErr != nil {
			t.Fatalf("启用应用 %s: %v", name, appErr)
		}
		if appErr = first.Admin().AddApplicationMember(ctx, AdminAddMemberRequest{
			Caller: local, ApplicationID: app.ID, UserID: user.ID,
			RequestID: login.NewRequestID()}); appErr != nil {
			t.Fatalf("加入应用 %s: %v", name, appErr)
		}
		return app.ID, app.RowVersion
	}
	clientID, _ := newApp("撤销客户端", "confidential")
	const audience = "https://resource.example.test/api"
	registration, err := first.OAuthClients().RegisterClient(ctx,
		AdminRegisterOAuthClientRequest{Caller: local, ClientID: clientID,
			ClientType: "confidential", GrantTypes: []string{"authorization_code", "refresh_token"},
			RedirectURIs: []string{"https://client.example.test/callback"},
			Scopes:       []string{"profile"}, Audiences: []string{audience},
			AuthMethods: []string{"client_secret_basic"}, RequestID: login.NewRequestID()})
	if err != nil || registration.Secret == nil {
		t.Fatalf("登记撤销客户端: %+v err=%v", registration, err)
	}
	clientSecret := registration.Secret.Secret
	// 第二个公开客户端：仅用于验证跨客户端撤销静默且不生效。
	otherClientID, _ := newApp("其他客户端", "public")
	if _, err := first.OAuthClients().RegisterClient(ctx, AdminRegisterOAuthClientRequest{
		Caller: local, ClientID: otherClientID, ClientType: "public",
		GrantTypes:   []string{"authorization_code"},
		RedirectURIs: []string{"https://other.example.test/callback"},
		Scopes:       []string{"profile"}, Audiences: []string{audience},
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("登记其他客户端: %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("关闭第一实例: %v", err)
	}

	cfg := testConfig()
	cfg.Protocol.Enabled = true
	cfg.Protocol.Issuer = "http://127.0.0.1:19092"
	cfg.Protocol.EnableIntrospection = true
	cfg.Protocol.ResourceServices = []login.ResourceServiceConfig{{
		ServiceID: "resource-api", ClientID: clientID, Audience: audience}}
	cfg.Server.PublicBaseURL = cfg.Protocol.Issuer
	second := open(cfg)
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	userCaller, err := token.UserCaller(user.ID)
	if err != nil {
		t.Fatalf("构造令牌调用者: %v", err)
	}
	issue := func() token.IssuedToken {
		t.Helper()
		issued, issueErr := second.base.Protocol.Tokens.IssueAccessToken(ctx, userCaller,
			token.IssueAccessTokenRequest{ClientID: clientID, SubjectUserID: user.ID,
				GrantType: token.GrantAuthorizationCode, Scopes: []string{"profile"},
				Audiences: []string{audience}, RequestID: login.NewRequestID()})
		if issueErr != nil {
			t.Fatalf("签发访问令牌: %v", issueErr)
		}
		return issued
	}
	protocol := second.Protocol()
	revocation := second.ProtocolRevocation()
	introspect := func(tokenValue string) ProtocolTokenInspection {
		t.Helper()
		inspection, inspectErr := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
			ServiceID: "resource-api", Token: tokenValue,
			RequestID: login.NewRequestID()})
		if inspectErr != nil {
			t.Fatalf("内省令牌: %v", inspectErr)
		}
		return inspection
	}
	firstToken := issue()
	if !introspect(firstToken.Token.Reveal()).Active {
		t.Fatal("撤销前令牌应 active")
	}
	// 错误客户端凭证：拒绝且不泄露令牌状态。
	_, wrongErr := revocation.RevokeToken(ctx, ProtocolRevokeTokenRequest{ClientID: clientID,
		ClientSecret: "wrong-secret", Token: firstToken.Token.Reveal(),
		RequestID: login.NewRequestID()})
	if !login.IsErrorCode(wrongErr, login.CodeClientAuthFailed) {
		t.Fatalf("错误客户端撤销错误 = %v，期望 CLIENT_AUTH_FAILED", wrongErr)
	}
	// 跨客户端：静默成功但不撤销他人令牌（RFC 7009 防枚举）。
	if accepted, err := revocation.RevokeToken(ctx, ProtocolRevokeTokenRequest{
		ClientID: otherClientID, Token: firstToken.Token.Reveal(),
		RequestID: login.NewRequestID()}); err != nil || !accepted.Accepted {
		t.Fatalf("跨客户端撤销 = %+v err=%v，期望静默成功", accepted, err)
	}
	if !introspect(firstToken.Token.Reveal()).Active {
		t.Fatal("跨客户端撤销不得使他人令牌失效")
	}
	// 自己的令牌撤销：成功；重复撤销幂等；未知令牌静默成功。
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := revocation.RevokeToken(ctx, ProtocolRevokeTokenRequest{
			ClientID: clientID, ClientSecret: clientSecret,
			Token: firstToken.Token.Reveal(), TokenTypeHint: "access_token",
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("撤销自己的访问令牌(第 %d 次): %v", attempt+1, err)
		}
	}
	if introspect(firstToken.Token.Reveal()).Active {
		t.Fatal("撤销后在线内省应 inactive")
	}
	if accepted, err := revocation.RevokeToken(ctx, ProtocolRevokeTokenRequest{
		ClientID: clientID, ClientSecret: clientSecret, Token: "not-a-real-token",
		RequestID: login.NewRequestID()}); err != nil || !accepted.Accepted {
		t.Fatalf("未知令牌撤销 = %+v err=%v，期望静默成功", accepted, err)
	}
	// 用户会话退出：真实登录后注销当前会话；再次使用会话验证应失效。
	loginResult, err := second.Auth().Login(ctx, LoginRequest{Username: "revoke-user",
		Password: "T4!kR8#wQ2@mN6$z", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted {
		t.Fatalf("登录撤销用户: %+v err=%v", loginResult, err)
	}
	logout, err := revocation.Logout(ctx, ProtocolLogoutRequest{
		SessionSecret: loginResult.SessionSecret, Scope: "current_session",
		RequestID: login.NewRequestID()})
	if err != nil || !logout.Accepted || logout.AppSessions != 1 {
		t.Fatalf("公开 Go 退出当前会话 = %+v err=%v", logout, err)
	}
	if _, err := second.Sessions().Validate(ctx, loginResult.SessionSecret); err == nil {
		t.Fatal("退出后会话仍有效")
	}
	// 无会话/非法范围 fail-closed。
	if _, err := revocation.RevokeAuthorization(ctx, ProtocolRevokeAuthorizationRequest{
		AuthorizationID: "oar_missing", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("无会话撤回授权错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := revocation.Logout(ctx, ProtocolLogoutRequest{
		SessionSecret: loginResult.SessionSecret, Scope: "invalid_scope",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法退出范围错误 = %v，期望 REQ_INVALID", err)
	}
	// 协议未启用/空参数 fail-closed。
	if _, err := (&protocolRevocationFacade{r: &Runtime{}}).RevokeToken(ctx,
		ProtocolRevokeTokenRequest{ClientID: "x", Token: "y",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeConfigInvalid) {
		t.Fatalf("协议未启用撤销错误 = %v，期望 CONFIG_INVALID", err)
	}
	if _, err := revocation.RevokeToken(ctx, ProtocolRevokeTokenRequest{
		ClientID: clientID, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("空令牌撤销错误 = %v，期望 REQ_INVALID", err)
	}
}
