package app

// 步骤 227：OAuth 令牌状态查询公开 Go 入口的真实装配测试。
//   - 配置启用协议后，宿主可信代码用已登记 resource_services.service_id 查询令牌；
//   - 复用同一 oauthflow.InspectToken：active/过期/未知令牌/跨资源/错误服务标识；
//   - 默认不披露 subject，不返回令牌原文或宿主路径。

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

func TestProtocolPublicIntrospection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clock := newTestClock(time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC))
	databasePath := filepath.Join(dir, "login.db")
	masterKeyPath := filepath.Join(dir, "master.key")
	open := func(cfg login.Config) *Runtime {
		t.Helper()
		runtime, err := Open(ctx, Options{Config: &cfg, DatabasePath: databasePath,
			MasterKeyFile: masterKeyPath, CreateMasterKey: true, Migrate: true,
			OperatorID: "protocol-test", Now: clock.Now})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return runtime
	}
	cfg := testConfig()
	first := open(cfg)
	t.Cleanup(func() { _ = first.Close(context.Background()) })
	user, err := first.Users().Create(ctx, CreateUserRequest{
		Username: "protocol-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建协议用户: %v", err)
	}
	local := first.LocalAdmin()
	application, err := first.Admin().CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "令牌状态资源应用", OwnerUserID: user.ID,
		ClientType: "confidential", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建资源应用: %v", err)
	}
	if _, err := first.Admin().SetApplicationEnabled(ctx,
		AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: application.ID,
			Enabled: true, ExpectedRowVersion: application.RowVersion,
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("启用资源应用: %v", err)
	}
	if err := first.Admin().AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: application.ID, UserID: user.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入资源应用: %v", err)
	}
	const audience = "https://resource.example.test/api"
	if _, err := first.OAuthClients().RegisterClient(ctx, AdminRegisterOAuthClientRequest{
		Caller: local, ClientID: application.ID, ClientType: "confidential",
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{"https://client.example.test/callback"},
		Scopes:       []string{"profile"}, Audiences: []string{audience},
		AuthMethods: []string{"client_secret_basic"},
		RequestID:   login.NewRequestID()}); err != nil {
		t.Fatalf("登记资源客户端: %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("关闭第一实例: %v", err)
	}

	// 同一数据库重新打开并启用协议：验证公开 Go 查询入口使用真实装配与启动配置登记。
	cfg = testConfig()
	cfg.Protocol.Enabled = true
	cfg.Protocol.Issuer = "http://127.0.0.1:19091"
	cfg.Protocol.EnableIntrospection = true
	cfg.Protocol.ResourceServices = []login.ResourceServiceConfig{{
		ServiceID: "resource-api", ClientID: application.ID, Audience: audience}}
	cfg.Server.PublicBaseURL = cfg.Protocol.Issuer
	second := open(cfg)
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	if second.base == nil || second.base.Protocol == nil ||
		second.base.Protocol.OAuthFlow == nil {
		t.Fatal("协议域未装配")
	}
	userCaller, err := token.UserCaller(user.ID)
	if err != nil {
		t.Fatalf("构造令牌调用者: %v", err)
	}
	issued, err := second.base.Protocol.Tokens.IssueAccessToken(ctx,
		userCaller, token.IssueAccessTokenRequest{
			ClientID: application.ID, SubjectUserID: user.ID,
			GrantType: token.GrantAuthorizationCode, Scopes: []string{"profile"},
			Audiences: []string{audience}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发访问令牌: %v", err)
	}
	protocol := second.Protocol()
	inspection, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: issued.Token.Reveal(),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("公开 Go 状态查询: %v", err)
	}
	if !inspection.Active || inspection.TokenType != "access_token" ||
		inspection.ClientID != application.ID ||
		len(inspection.Audience) != 1 || inspection.Audience[0] != audience {
		t.Fatalf("状态查询结果 = %+v", inspection)
	}
	// 标准 introspection 默认不披露跨应用用户主体。
	if inspection.Subject != "" || inspection.SubjectType != "" {
		t.Fatalf("默认不应披露用户主体: %+v", inspection)
	}
	// 未知令牌按协议返回 inactive，不提供枚举差异。
	unknown, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: "not-a-real-token",
		RequestID: login.NewRequestID()})
	if err != nil || unknown.Active {
		t.Fatalf("未知令牌 = %+v err=%v", unknown, err)
	}
	// 未登记 service_id 与跨资源 audience 均拒绝。
	if _, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "unknown-service", Token: issued.Token.Reveal(),
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("未登记 service_id 错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: issued.Token.Reveal(),
		Audience:  "https://other.example.test/api",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("跨资源 audience 错误 = %v，期望 REQ_INVALID", err)
	}
	// 过期由同一在线状态服务判断。
	clock.Advance(2 * time.Hour)
	expired, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: issued.Token.Reveal(),
		RequestID: login.NewRequestID()})
	if err != nil || expired.Active {
		t.Fatalf("过期令牌 = %+v err=%v", expired, err)
	}
	// 账户状态：新签发令牌在用户被禁用后必须 inactive（TokenStateChecker 在线复核）。
	clock.Advance(-2 * time.Hour)
	fresh, err := second.base.Protocol.Tokens.IssueAccessToken(ctx, userCaller,
		token.IssueAccessTokenRequest{ClientID: application.ID, SubjectUserID: user.ID,
			GrantType: token.GrantAuthorizationCode, Scopes: []string{"profile"},
			Audiences: []string{audience}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发账户状态令牌: %v", err)
	}
	beforeDisable, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: fresh.Token.Reveal(),
		RequestID: login.NewRequestID()})
	if err != nil || !beforeDisable.Active {
		t.Fatalf("禁用前令牌 = %+v err=%v", beforeDisable, err)
	}
	userState, err := second.UserLifecycle().GetUser(ctx, AdminUserRequest{
		Caller: second.LocalAdmin(), UserID: user.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取用户状态: %v", err)
	}
	if _, err := second.UserLifecycle().DisableUser(ctx, AdminUserStateRequest{
		Caller: second.LocalAdmin(), UserID: user.ID,
		ExpectedRowVersion: userState.RowVersion, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("禁用用户: %v", err)
	}
	afterDisable, err := protocol.IntrospectToken(ctx, ProtocolIntrospectRequest{
		ServiceID: "resource-api", Token: fresh.Token.Reveal(),
		RequestID: login.NewRequestID()})
	if err != nil || afterDisable.Active {
		t.Fatalf("禁用后令牌 = %+v err=%v", afterDisable, err)
	}
	// 协议启用但状态查询未显式启用：公开入口 fail-closed，不返回“空但成功”。
	if err := second.Close(ctx); err != nil {
		t.Fatalf("关闭协议实例: %v", err)
	}
	cfgDisabled := testConfig()
	cfgDisabled.Protocol.Enabled = true
	cfgDisabled.Protocol.Issuer = "http://127.0.0.1:19091"
	cfgDisabled.Server.PublicBaseURL = cfgDisabled.Protocol.Issuer
	disabledRuntime := open(cfgDisabled)
	t.Cleanup(func() { _ = disabledRuntime.Close(context.Background()) })
	if _, err := disabledRuntime.Protocol().IntrospectToken(ctx,
		ProtocolIntrospectRequest{ServiceID: "resource-api", Token: "x",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeConfigInvalid) {
		t.Fatalf("状态查询未启用错误 = %v，期望 CONFIG_INVALID", err)
	}
	// 协议未启用实例的公开入口 fail-closed。
	if _, err := (&protocolPublicFacade{r: &Runtime{}}).IntrospectToken(ctx,
		ProtocolIntrospectRequest{ServiceID: "resource-api", Token: "x",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeConfigInvalid) {
		t.Fatalf("协议未启用错误 = %v，期望 CONFIG_INVALID", err)
	}
}
