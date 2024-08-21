package serverapp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// TestResourceAuthorizeAndIntrospectE2E 使用真实 SQLite、真实领域服务与真实
// loopback HTTP 服务验证 144/145 的联合判定与标准 introspection（不启动 CLI，
// 不监听固定端口，不真实外发）。
func TestResourceAuthorizeAndIntrospectE2E(t *testing.T) {
	ctx := context.Background()
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	cfg := login.Default()
	cfg.Database.Path = "unused.db"
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	cfg.Protocol.Enabled = true
	cfg.Protocol.Issuer = "http://127.0.0.1:18080"
	clockNow := testNow
	deps := Deps{Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder,
		Logger: testLogger(), Now: func() time.Time { return clockNow }}
	services, err := BuildServices(deps)
	if err != nil {
		t.Fatalf("BuildServices: %v", err)
	}
	gate, err := BuildSecurityGate(deps, services.BootstrapStore, services.Authn, false)
	if err != nil {
		t.Fatalf("BuildSecurityGate: %v", err)
	}
	tasks, err := NewTaskRuntime(deps, gate)
	if err != nil {
		t.Fatalf("NewTaskRuntime: %v", err)
	}
	t.Cleanup(func() { _ = tasks.Close(context.Background()) })
	bootstrapService, bootstrapCaller, bootErr := BuildBootstrapService(deps, "embedded-operator")
	if bootErr != nil {
		t.Fatalf("BuildBootstrapService: %v", bootErr)
	}
	initialized, bootErr := bootstrapService.Initialize(ctx, bootstrapCaller, bootstrap.InitializeRequest{})
	if bootErr != nil {
		t.Fatalf("bootstrap Initialize: %v", bootErr)
	}
	grant, bootErr := bootstrapService.RedeemSetupCredential(ctx, bootstrapCaller,
		bootstrap.RedeemSetupCredentialRequest{CredentialID: initialized.SetupCredential.ID,
			Secret: initialized.SetupCredential.Secret.Reveal()})
	if bootErr != nil {
		t.Fatalf("bootstrap Redeem: %v", bootErr)
	}
	rootCaller, _ := authn.LocalAdminCaller("embedded-operator")
	if _, bootErr := services.Authn.SetRootPassword(ctx, rootCaller,
		authn.SetRootPasswordRequest{RootUserID: grant.RootUserID,
			NewPassword: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID()}); bootErr != nil {
		t.Fatalf("SetRootPassword: %v", bootErr)
	}
	managed, err := BuildManagedServices(deps, services, tasks, gate)
	if err != nil {
		t.Fatalf("BuildManagedServices: %v", err)
	}

	oper := "embedded-operator"
	accountCaller, _ := account.LocalBootstrapCaller(oper)
	registered, err := services.Registration.Register(ctx, registration.RegisterRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	user, err := managed.Account.GetUser(ctx, accountCaller, registered.UserID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	appCaller, _ := app.LocalBootstrapCaller(oper)
	subjectApp, err := managed.App.CreateApplication(ctx, appCaller, app.CreateRequest{
		Name: "subject-app", OwnerUserID: user.ID, ClientType: app.ClientTypePublic})
	if err != nil {
		t.Fatalf("CreateApplication subject: %v", err)
	}
	resourceApp, err := managed.App.CreateApplication(ctx, appCaller, app.CreateRequest{
		Name: "resource-app", OwnerUserID: user.ID, ClientType: app.ClientTypeConfidential})
	if err != nil {
		t.Fatalf("CreateApplication resource: %v", err)
	}
	for _, target := range []struct {
		id         string
		rowVersion int64
	}{
		{subjectApp.ID, subjectApp.RowVersion}, {resourceApp.ID, resourceApp.RowVersion}} {
		if _, err := managed.App.EnableApplication(ctx, appCaller, app.StatusRequest{
			ApplicationID: target.id, ExpectedRowVersion: target.rowVersion}); err != nil {
			t.Fatalf("EnableApplication %s: %v", target.id, err)
		}
	}
	for _, appID := range []string{subjectApp.ID, resourceApp.ID} {
		if _, err := managed.App.AddApplicationMember(ctx, appCaller, app.AddMemberRequest{
			ApplicationID: appID, UserID: user.ID}); err != nil {
			t.Fatalf("AddApplicationMember %s: %v", appID, err)
		}
	}
	audience := "https://resource.example.test/api"
	resourceSecret := "resource-secret-for-e2e-9x!"
	nowMS := testNow.UnixMilli()
	insertOAuthClient(t, store, subjectApp.ID, "public", []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		[]string{"https://subject.example.test/callback"}, []string{audience},
		[]string{"openid", "profile"}, []string{}, true, nowMS)
	insertOAuthClient(t, store, resourceApp.ID, "confidential", []string{"client_credentials"},
		[]string{}, []string{audience}, []string{"profile"},
		[]string{"client_secret_basic"}, false, nowMS)
	digest := sha256.Sum256([]byte(resourceSecret))
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO oauth_client_secrets
(id, client_id, secret_prefix, secret_digest, created_at_ms, expires_at_ms)
VALUES(?,?,?,?,?,?)`, "ocs_e2e_resource", resourceApp.ID, resourceSecret[:8], digest[:],
		nowMS, nowMS+3600_000); err != nil {
		t.Fatalf("插入资源客户端密钥: %v", err)
	}

	cfg.Protocol.ResourceServices = []login.ResourceServiceConfig{{
		ServiceID: "resource-api", ClientID: resourceApp.ID, Audience: audience}}
	cfg.Protocol.EnableIntrospection = true
	cfg.Protocol.DeviceCodeEnabled = true
	cfg.Server.PublicBaseURL = cfg.Protocol.Issuer
	cfg.AppQRLogin.Enabled = true
	cfg.AppQRLogin.AllowedClientIDs = []string{subjectApp.ID}
	deps.Config = cfg
	protocolDomains, err := BuildProtocolDomains(deps, services, managed, gate)
	if err != nil {
		t.Fatalf("BuildProtocolDomains: %v", err)
	}
	if protocolDomains.QRLogin == nil {
		t.Fatal("QR 服务未装配")
	}
	// 页面层在完成再次认证后会把可信信号注入请求上下文；测试用同一真实信号契约
	// 模拟该边界（QR 服务仍自行校验会话/请求绑定/policy，不信任请求参数）。
	trustedSignals := reauth.Signals{VerifiedAt: testNow, Strength: policy.StrengthPassword,
		Complete: true, Confirmed: true}
	protocolHandler := protocolDomains.Protocol.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		protocolHandler.ServeHTTP(writer, request.WithContext(
			reauth.WithSignals(request.Context(), trustedSignals)))
	}))
	// 页面层：真实 WebUI + 真实 uiauthadapter，验证设备确认页表单/CSRF。
	pageState, stateErr := pagestate.New(pagestate.Options{
		Keyring: keyring, TTL: 15 * time.Minute, Now: func() time.Time { return testNow }})
	if stateErr != nil {
		t.Fatalf("page state: %v", stateErr)
	}
	authAdapter, adapterErr := uiauthadapter.New(uiauthadapter.Options{
		Authn: services.Authn, Sessions: services.Sessions, Registration: services.Registration,
		Onboarding: services.Onboarding, RegistrationStore: services.RegistrationStore,
		Credential: services.Credential, PageState: pageState,
		OAuth: protocolDomains.OAuthFlow, QR: protocolDomains.QRLogin,
		QRClientID: protocolDomains.QRClientID, ApplicationNames: protocolDomains.QRApplicationNames,
		App: managed.App, Account: managed.Account,
		Now: func() time.Time { return testNow }, Logger: deps.Logger,
	})
	if adapterErr != nil {
		t.Fatalf("uiauthadapter: %v", adapterErr)
	}
	csrfProvider, csrfErr := pagecsrf.New(pagecsrf.Options{
		Keyring: keyring, TTL: 15 * time.Minute, Now: func() time.Time { return testNow }})
	if csrfErr != nil {
		t.Fatalf("pagecsrf: %v", csrfErr)
	}
	webUI, uiErr := ui.NewWebUI(ui.WebUIOptions{
		Prefix: "", Session: pageSessions{service: services.Sessions, gate: gate, pathPrefix: ""},
		FormTokens: csrfProvider,
		PageOAuth:  &ui.UIPageOAuthOptions{Backend: authAdapter, LoginPath: "/login", PostLoginPath: "/home"},
		Now:        func() time.Time { return testNow }, Logger: deps.Logger,
	})
	if uiErr != nil {
		t.Fatalf("NewWebUI: %v", uiErr)
	}
	webServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		webUI.ServeHTTP(writer, request.WithContext(
			reauth.WithSignals(request.Context(), trustedSignals)))
	}))
	t.Cleanup(server.Close)

	tokenService := protocolDomains.Tokens
	userCaller, _ := token.UserCaller(user.ID)
	issued, err := tokenService.IssueAccessToken(ctx, userCaller, token.IssueAccessTokenRequest{
		ClientID: subjectApp.ID, SubjectUserID: user.ID,
		GrantType: token.GrantAuthorizationCode, Scopes: []string{"profile"},
		Audiences: []string{audience}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	accessToken := issued.Token.Reveal()
	idToken, err := tokenService.IssueIDToken(ctx, userCaller, token.IssueIDTokenRequest{
		ClientID: subjectApp.ID, SubjectUserID: user.ID,
		Nonce: "nonce1234567890", AuthTime: testNow, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	postJSON := func(path, clientID, secret string, body map[string]any) (int, map[string]any) {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth(clientID, secret)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", path, err)
		}
		defer response.Body.Close()
		payload := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&payload)
		return response.StatusCode, payload
	}

	status, payload := postJSON("/oauth/token/authorize", resourceApp.ID, resourceSecret, map[string]any{
		"access_token": accessToken, "permissions": []string{"authorization.check"},
		"audience": audience})
	if status != http.StatusOK {
		t.Fatalf("联合判定状态 %d: %+v", status, payload)
	}
	if payload["allow"] != false {
		t.Fatalf("未授权权限应拒绝: %+v", payload)
	}
	if payload["code"] == "" {
		t.Fatalf("拒绝缺少稳定 code: %+v", payload)
	}

	if status, _ := postJSON("/oauth/token/authorize", resourceApp.ID, "wrong-secret", map[string]any{
		"access_token": accessToken, "permissions": []string{"x.read"}}); status != http.StatusUnauthorized {
		t.Fatalf("错误认证应为 401，得到 %d", status)
	}
	if status, _ := postJSON("/oauth/token/authorize", resourceApp.ID, resourceSecret, map[string]any{
		"access_token": accessToken, "permissions": []string{"x.read"},
		"audience": "https://evil.example.test/api"}); status != http.StatusForbidden {
		t.Fatalf("跨 audience 应为 403，得到 %d", status)
	}
	status, payload = postJSON("/oauth/token/authorize", resourceApp.ID, resourceSecret, map[string]any{
		"access_token": idToken.Token.Reveal(), "permissions": []string{"x.read"}, "audience": audience})
	if status != http.StatusOK || payload["allow"] != false {
		t.Fatalf("ID Token 混用必须拒绝: %d %+v", status, payload)
	}

	introspect := func(clientID, secret, tokenValue, aud string) (int, map[string]any) {
		t.Helper()
		form := "token=" + tokenValue
		if aud != "" {
			form += "&audience=" + aud
		}
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/oauth/introspect", strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth(clientID, secret)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("introspect 请求失败: %v", err)
		}
		defer response.Body.Close()
		payload := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&payload)
		return response.StatusCode, payload
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, accessToken, audience)
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("有效令牌 introspect 应 active: %d %+v", status, payload)
	}
	if _, leaked := payload["sub"]; leaked {
		t.Fatalf("跨资源不应返回 sub: %+v", payload)
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, accessToken, "https://evil.example.test/api")
	if status == http.StatusOK && payload["active"] == true {
		t.Fatalf("跨资源 audience 不应 active: %d %+v", status, payload)
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, idToken.Token.Reveal(), audience)
	if status == http.StatusOK && payload["active"] == true {
		t.Fatalf("ID Token 作为 access token 不应 active: %d %+v", status, payload)
	}
	if status, _ := introspect(resourceApp.ID, "wrong", accessToken, audience); status != http.StatusUnauthorized {
		t.Fatalf("错误认证 introspect 应为 401，得到 %d", status)
	}

	status, payload = introspect(resourceApp.ID, resourceSecret, "not-a-real-token", audience)
	if status != http.StatusOK || payload["active"] != false {
		t.Fatalf("未知令牌应 inactive: %d %+v", status, payload)
	}
	// 撤销访问令牌后：introspection 必须 inactive（真实在线撤销）。
	if err := protocolDomains.OAuthFlow.RevokeToken(ctx, oauthflow.RevokeTokenRequest{
		ClientID: subjectApp.ID, Token: accessToken, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤销访问令牌: %v", err)
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, accessToken, audience)
	if status != http.StatusOK || payload["active"] != false {
		t.Fatalf("撤销后应 inactive: %d %+v", status, payload)
	}
	// 撤销后联合业务授权判定也必须拒绝（在线撤销联动，而非仅内省视图）。
	status, payload = postJSON("/oauth/token/authorize", resourceApp.ID, resourceSecret,
		map[string]any{"access_token": accessToken,
			"permissions": []string{"authorization.check"}, "audience": audience})
	if status != http.StatusOK || payload["allow"] != false ||
		payload["code"] != "TOKEN_REVOKED" {
		t.Fatalf("撤销后业务授权应拒绝 TOKEN_REVOKED: %d %+v", status, payload)
	}

	// 扫码登录：匿名创建、二维码载荷不含领取绑定、错误绑定/匿名确认被拒。
	qrPost := func(path string, body map[string]any, bearer string) (int, map[string]any, http.Header) {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("QR 请求 %s 失败: %v", path, err)
		}
		defer response.Body.Close()
		payload := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&payload)
		return response.StatusCode, payload, response.Header
	}
	statusQ, begin, _ := qrPost("/oauth/qr/request", map[string]any{
		"client_id": subjectApp.ID, "scopes": []string{"openid"}}, "")
	if statusQ != http.StatusOK {
		t.Fatalf("QR begin 应 200: %d %+v paths=%v", statusQ, begin, protocolDomains.Protocol.Paths())
	}
	requestID, _ := begin["request_id"].(string)
	claimSecret, _ := begin["claim_secret"].(string)
	qrPayload, _ := begin["qr_payload"].(string)
	if requestID == "" || claimSecret == "" || qrPayload == "" {
		t.Fatalf("QR begin 响应缺少字段: %+v", begin)
	}
	if strings.Contains(qrPayload, claimSecret) {
		t.Fatalf("二维码载荷不得包含领取绑定")
	}
	if statusQ, payloadQ, _ := qrPost("/oauth/qr/status", map[string]any{
		"request_id": requestID, "claim_secret": "wrong-claim-secret"}, ""); statusQ == http.StatusOK {
		t.Fatalf("错误领取绑定不应成功: %+v", payloadQ)
	}
	if statusQ, _, _ := qrPost("/oauth/qr/status", map[string]any{
		"request_id": requestID, "claim_secret": claimSecret}, ""); statusQ != http.StatusOK {
		t.Fatalf("正确领取绑定状态查询应 200，得到 %d", statusQ)
	}
	promptRequest, _ := http.NewRequest(http.MethodGet,
		server.URL+"/oauth/qr/prompt?request_id="+requestID, nil)
	promptResponse, promptErr := server.Client().Do(promptRequest)
	if promptErr != nil {
		t.Fatalf("QR prompt 请求失败: %v", promptErr)
	}
	promptResponse.Body.Close()
	if promptResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("匿名 QR 确认上下文应 401，得到 %d", promptResponse.StatusCode)
	}
	if statusQ, _, _ := qrPost("/oauth/qr/decision", map[string]any{
		"request_id": requestID, "decision": "approve"}, ""); statusQ != http.StatusUnauthorized {
		t.Fatalf("匿名 QR 确认决定应 401，得到 %d", statusQ)
	}
	if statusQ, _, _ := qrPost("/oauth/qr/claim", map[string]any{
		"request_id": requestID, "claim_secret": claimSecret}, ""); statusQ == http.StatusOK {
		t.Fatalf("未确认的 QR 请求不应被领取")
	}

	// 完整闭环：真实密码账户登录 → 扫码确认页批准 → 原发起端领取会话。
	// 本用例聚焦扫码闭环；密码登录本身已有独立真实测试（app/runtime_test.go）。
	// 这里以 session 服务的可信认证事实接口构造“已登录 + 强认证”会话，
	// session.Login 仍会重读账户/应用/成员并绑定 security_version。
	authResult := authn.AuthenticateResult{
		UserID: user.ID, Username: user.Username, Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testNow, StrongAuthCompletedAt: testNow,
		SecurityVersion: user.SecurityVersion,
	}
	issuedSession, err := services.Sessions.Login(ctx, session.LoginRequest{
		Result: authResult, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("session.Login: %T %v security_version=%d outcome=%v", err, err, user.SecurityVersion, authResult.Outcome)
	}
	confirmSecret := issuedSession.Secret.Reveal()
	if confirmSecret == "" {
		t.Fatal("确认端会话秘密为空")
	}

	qrRequest := func(method, path string, body map[string]any, bearer, origin string) *httpResult2 {
		t.Helper()
		var reader *strings.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			reader = strings.NewReader(string(data))
		} else {
			reader = strings.NewReader("")
		}
		request, _ := http.NewRequest(method, server.URL+path, reader)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("QR 请求 %s 失败: %v", path, err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return &httpResult2{Status: response.StatusCode, Body: data, Header: response.Header.Clone()}
	}

	prompt := qrRequest(http.MethodGet, "/oauth/qr/prompt?request_id="+requestID, nil,
		confirmSecret, "")
	if prompt.Status != http.StatusOK {
		t.Fatalf("确认页上下文应 200，得到 %d %s", prompt.Status, prompt.Body)
	}
	var promptBody struct {
		Version int64  `json:"version"`
		Status  string `json:"status"`
	}
	_ = json.Unmarshal(prompt.Body, &promptBody)
	issuerOrigin := cfg.Protocol.Issuer
	approved := qrRequest(http.MethodPost, "/oauth/qr/decision", map[string]any{
		"request_id": requestID, "approve": true, "expected_version": promptBody.Version},
		confirmSecret, issuerOrigin)
	if approved.Status != http.StatusOK {
		t.Fatalf("QR 批准应 200，得到 %d %s", approved.Status, approved.Body)
	}
	repeated := qrRequest(http.MethodPost, "/oauth/qr/decision", map[string]any{
		"request_id": requestID, "approve": true, "expected_version": promptBody.Version},
		confirmSecret, issuerOrigin)
	if repeated.Status == http.StatusOK {
		t.Fatal("重复确认不应成功")
	}
	claimed := qrRequest(http.MethodPost, "/oauth/qr/claim", map[string]any{
		"request_id": requestID, "claim_secret": claimSecret}, "", "")
	if claimed.Status != http.StatusOK {
		t.Fatalf("批准后原发起端领取应 200，得到 %d %s", claimed.Status, claimed.Body)
	}
	if len(claimed.Header.Values("Set-Cookie")) == 0 {
		t.Fatal("领取成功应写入会话 Cookie")
	}
	if strings.Contains(string(claimed.Body), confirmSecret) {
		t.Fatal("领取响应不得回显确认端会话秘密")
	}
	reclaimed := qrRequest(http.MethodPost, "/oauth/qr/claim", map[string]any{
		"request_id": requestID, "claim_secret": claimSecret}, "", "")
	if reclaimed.Status == http.StatusOK {
		t.Fatal("重复领取不应成功")
	}
	// 另一个浏览器（错误的领取绑定）不能窃领。
	statusQ, stolenBegin, _ := qrPost("/oauth/qr/request", map[string]any{
		"client_id": subjectApp.ID, "scopes": []string{"openid"}}, "")
	if statusQ != http.StatusOK {
		t.Fatalf("QR 第二请求失败: %d", statusQ)
	}
	_ = stolenBegin
	if forged := qrRequest(http.MethodPost, "/oauth/qr/claim", map[string]any{
		"request_id": requestID, "claim_secret": "wrong-claim-secret"}, "", ""); forged.Status == http.StatusOK {
		t.Fatal("错误领取绑定不应领走已批准请求")
	}
	// 拒绝路径：批准=false 后不能领取。
	statusQ, denyBegin, _ := qrPost("/oauth/qr/request", map[string]any{
		"client_id": subjectApp.ID, "scopes": []string{"openid"}}, "")
	if statusQ != http.StatusOK {
		t.Fatalf("QR 拒绝用例创建失败: %d", statusQ)
	}
	denyRequestID, _ := denyBegin["request_id"].(string)
	denyClaimSecret, _ := denyBegin["claim_secret"].(string)
	denyPrompt := qrRequest(http.MethodGet, "/oauth/qr/prompt?request_id="+denyRequestID,
		nil, confirmSecret, "")
	if denyPrompt.Status != http.StatusOK {
		t.Fatalf("拒绝用例 prompt 失败: %d", denyPrompt.Status)
	}
	var denyPromptBody struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(denyPrompt.Body, &denyPromptBody)
	if denied := qrRequest(http.MethodPost, "/oauth/qr/decision", map[string]any{
		"request_id": denyRequestID, "approve": false,
		"expected_version": denyPromptBody.Version}, confirmSecret, issuerOrigin); denied.Status != http.StatusOK {
		t.Fatalf("QR 拒绝应 200，得到 %d", denied.Status)
	}
	if deniedClaim := qrRequest(http.MethodPost, "/oauth/qr/claim", map[string]any{
		"request_id": denyRequestID, "claim_secret": denyClaimSecret}, "", ""); deniedClaim.Status == http.StatusOK {
		t.Fatal("被拒绝的 QR 请求不应可领取")
	}
	// 白名单外应用不能发起 QR。
	if outside := qrRequest(http.MethodPost, "/oauth/qr/request", map[string]any{
		"client_id": resourceApp.ID, "scopes": []string{"openid"}}, "", ""); outside.Status == http.StatusOK {
		t.Fatal("白名单外应用不应能创建 QR 请求")
	}

	// 设备码：HTTP 申请/pending/确认/一次兑换/取消真实链路。
	deviceForm := func(path string, values map[string]string) (int, map[string]any) {
		t.Helper()
		form := url.Values{}
		for key, value := range values {
			form.Set(key, value)
		}
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("设备码请求 %s 失败: %v", path, err)
		}
		defer response.Body.Close()
		payload := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&payload)
		return response.StatusCode, payload
	}
	statusD, deviceBegin := deviceForm("/oauth/device_authorization", map[string]string{
		"client_id": subjectApp.ID})
	if statusD != http.StatusOK {
		t.Fatalf("设备码申请应 200: %d %+v", statusD, deviceBegin)
	}
	deviceCode, _ := deviceBegin["device_code"].(string)
	userCode, _ := deviceBegin["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("设备码响应缺少字段: %+v", deviceBegin)
	}
	if verification, _ := deviceBegin["verification_uri"].(string); !strings.Contains(verification, "/oauth/device") {
		t.Fatalf("verification_uri 异常: %+v", deviceBegin)
	}
	if _, decideErr := protocolDomains.OAuthFlow.DecideDeviceAuthorization(
		reauth.WithSignals(ctx, trustedSignals), confirmSecret, oauthflow.DeviceDecisionRequest{
			UserCode: userCode, Approve: true, RequestID: login.NewRequestID()}); decideErr != nil {
		t.Fatalf("设备码确认失败: %v", decideErr)
	}
	// RFC 8628 最小轮询间隔为 5 秒；真实服务强制 slow_down，测试等待后领取。
	time.Sleep(5100 * time.Millisecond)
	statusD, issuedDevice := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode, "client_id": subjectApp.ID})
	if statusD != http.StatusOK || issuedDevice["access_token"] == nil {
		t.Fatalf("确认后设备令牌应签发: %d %+v", statusD, issuedDevice)
	}
	if _, replay := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode, "client_id": subjectApp.ID}); replay["error"] != "invalid_grant" {
		t.Fatalf("设备码重放应 invalid_grant: %+v", replay)
	}
	statusD, cancelBegin := deviceForm("/oauth/device_authorization", map[string]string{
		"client_id": subjectApp.ID})
	if statusD != http.StatusOK {
		t.Fatalf("取消用例申请失败: %d", statusD)
	}
	cancelDevice, _ := cancelBegin["device_code"].(string)
	if cancelErr := protocolDomains.OAuthFlow.CancelDeviceAuthorization(ctx, oauthflow.DeviceCancelRequest{
		ClientID: subjectApp.ID, DeviceCode: cancelDevice,
		RequestID: login.NewRequestID()}); cancelErr != nil {
		t.Fatalf("设备码取消失败: %v", cancelErr)
	}
	statusPending, pendingBegin := deviceForm("/oauth/device_authorization", map[string]string{
		"client_id": subjectApp.ID})
	if statusPending != http.StatusOK {
		t.Fatalf("pending 用例申请失败: %d", statusPending)
	}
	pendingDevice, _ := pendingBegin["device_code"].(string)
	if statusD, pending := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": pendingDevice, "client_id": subjectApp.ID}); statusD == http.StatusOK ||
		pending["error"] != "authorization_pending" {
		t.Fatalf("未确认设备码应 authorization_pending: %d %+v", statusD, pending)
	}
	if _, slow := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": pendingDevice, "client_id": subjectApp.ID}); slow["error"] != "slow_down" {
		t.Fatalf("过快轮询应 slow_down: %+v", slow)
	}
	if _, cancelled := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": cancelDevice, "client_id": subjectApp.ID}); cancelled["error"] == "" {
		t.Fatalf("取消后的设备码应拒绝: %+v", cancelled)
	}
	// 错误客户端不能取消他人的设备码。
	if wrongStatus, wrong := deviceForm("/oauth/device/cancel", map[string]string{
		"client_id": resourceApp.ID, "client_secret": resourceSecret,
		"device_code": pendingDevice}); wrongStatus == http.StatusOK {
		t.Fatalf("错误客户端取消不应成功: %+v", wrong)
	}

	// 页面表单/CSRF：真实 /oauth/device GET/POST 与 /oauth/device/confirm 批准/拒绝。
	devicePageForm := func(path string, values url.Values, cookie string) (*http.Response, string) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodPost, webServer.URL+path, strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", webServer.URL)
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		response, err := webServer.Client().Do(request)
		if err != nil {
			t.Fatalf("页面表单 %s 失败: %v", path, err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response, string(data)
	}
	pageGet, _ := webServer.Client().Get(webServer.URL + "/oauth/device")
	pageHTML, _ := io.ReadAll(pageGet.Body)
	pageGet.Body.Close()
	if pageGet.StatusCode != http.StatusOK {
		t.Fatalf("设备码页面 GET 应 200，得到 %d", pageGet.StatusCode)
	}
	csrfToken := extractCSRFToken(string(pageHTML))
	if csrfToken == "" {
		t.Fatalf("设备码页面缺少 CSRF token: %s", truncateForTest(string(pageHTML), 300))
	}
	// 新申请一个设备码，用真实页面描述并批准。
	statusPage, pageBegin := deviceForm("/oauth/device_authorization", map[string]string{"client_id": subjectApp.ID})
	if statusPage != http.StatusOK {
		t.Fatalf("页面用例设备码申请失败: %d", statusPage)
	}
	pageUserCode, _ := pageBegin["user_code"].(string)
	sessionCookie := session.DefaultCookieName + "=" + confirmSecret
	describeResponse, describeHTML := devicePageForm("/oauth/device", url.Values{
		"csrf_token": {csrfToken}, "user_code": {pageUserCode}}, sessionCookie)
	if describeResponse.StatusCode != http.StatusOK {
		t.Fatalf("设备码页面描述应 200，得到 %d: %s", describeResponse.StatusCode, truncateForTest(describeHTML, 300))
	}
	confirmCSRF := extractCSRFToken(describeHTML)
	if confirmCSRF == "" {
		confirmCSRF = csrfToken
	}
	approveResponse, approveHTML := devicePageForm("/oauth/device/confirm", url.Values{
		"csrf_token": {confirmCSRF}, "user_code": {pageUserCode}, "approve": {"true"}}, sessionCookie)
	if approveResponse.StatusCode != http.StatusOK {
		t.Fatalf("设备码页面批准应 200，得到 %d: %s", approveResponse.StatusCode, truncateForTest(approveHTML, 300))
	}
	// 缺 CSRF 必须拒绝。
	if invalid, _ := devicePageForm("/oauth/device/confirm", url.Values{
		"user_code": {pageUserCode}, "approve": {"true"}}, sessionCookie); invalid.StatusCode == http.StatusOK {
		t.Fatal("缺少 CSRF 的确认表单不应成功")
	}

	// 页面拒绝：approve=false 后 token 轮询 access_denied。
	statusDeny, denyBeginPage := deviceForm("/oauth/device_authorization", map[string]string{"client_id": subjectApp.ID})
	if statusDeny != http.StatusOK {
		t.Fatalf("页面拒绝用例申请失败: %d", statusDeny)
	}
	denyUserCode, _ := denyBeginPage["user_code"].(string)
	pageGetDeny, _ := webServer.Client().Get(webServer.URL + "/oauth/device")
	denyHTML, _ := io.ReadAll(pageGetDeny.Body)
	pageGetDeny.Body.Close()
	denyCSRF := extractCSRFToken(string(denyHTML))
	if denyCSRF == "" {
		t.Fatalf("页面拒绝用例缺少 CSRF")
	}
	denyDescribe, denyDescribeHTML := devicePageForm("/oauth/device", url.Values{
		"csrf_token": {denyCSRF}, "user_code": {denyUserCode}}, sessionCookie)
	if denyDescribe.StatusCode != http.StatusOK {
		t.Fatalf("页面拒绝描述失败: %d", denyDescribe.StatusCode)
	}
	denyFormCSRF := extractCSRFToken(denyDescribeHTML)
	if denyFormCSRF == "" {
		denyFormCSRF = denyCSRF
	}
	deniedResponse, deniedHTML := devicePageForm("/oauth/device/confirm", url.Values{
		"csrf_token": {denyFormCSRF}, "user_code": {denyUserCode}, "approve": {"false"}}, sessionCookie)
	if deniedResponse.StatusCode != http.StatusOK {
		t.Fatalf("页面拒绝确认应 200，得到 %d: %s", deniedResponse.StatusCode, truncateForTest(deniedHTML, 300))
	}
	if _, deniedToken := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": denyBeginPage["device_code"].(string), "client_id": subjectApp.ID}); deniedToken["error"] != "access_denied" {
		t.Fatalf("页面拒绝后应 access_denied: %+v", deniedToken)
	}

	// 过期：推进可注入时钟后，未确认设备码轮询必须 expired_token。
	statusExp, expBegin := deviceForm("/oauth/device_authorization", map[string]string{
		"client_id": subjectApp.ID})
	if statusExp != http.StatusOK {
		t.Fatalf("过期用例申请失败: %d", statusExp)
	}
	expDevice, _ := expBegin["device_code"].(string)
	clockNow = testNow.Add(2 * time.Hour)
	if _, expired := deviceForm("/oauth/token", map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": expDevice, "client_id": subjectApp.ID}); expired["error"] != "expired_token" {
		t.Fatalf("过期设备码应 expired_token: %+v", expired)
	}
	clockNow = testNow

	discovery, err := server.Client().Get(server.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	defer discovery.Body.Close()
	var document map[string]any
	_ = json.NewDecoder(discovery.Body).Decode(&document)
	if document["introspection_endpoint"] == nil || document["introspection_endpoint"] == "" {
		t.Fatalf("Discovery 缺少 introspection_endpoint: %+v", document)
	}
	// 用户停用后：新签发的有效令牌也必须 inactive（TokenStateChecker 当前状态复核）。
	freshToken, freshErr := tokenService.IssueAccessToken(ctx, userCaller, token.IssueAccessTokenRequest{
		ClientID: subjectApp.ID, SubjectUserID: user.ID,
		GrantType: token.GrantAuthorizationCode, Scopes: []string{"profile"},
		Audiences: []string{audience}, RequestID: login.NewRequestID()})
	if freshErr != nil {
		t.Fatalf("IssueAccessToken fresh: %v", freshErr)
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, freshToken.Token.Reveal(), audience)
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("停用前新令牌应 active: %d %+v", status, payload)
	}
	if _, err := managed.Account.DisableUser(ctx, accountCaller, account.StateCommandRequest{
		UserID: user.ID, ExpectedRowVersion: user.RowVersion}); err != nil {
		t.Fatalf("停用用户: %v", err)
	}
	status, payload = introspect(resourceApp.ID, resourceSecret, freshToken.Token.Reveal(), audience)
	if status != http.StatusOK || payload["active"] != false {
		t.Fatalf("停用用户后应 inactive: %d %+v", status, payload)
	}
	_ = fmt.Sprint(document)
}

func boolPtr(value bool) *bool { return &value }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// insertOAuthClient 直接写入测试客户端的真实登记行（真实 SQLite schema），
// 避免测试依赖带强认证闸门的管理写入路径。
func insertOAuthClient(t *testing.T, store interface{ DB() *sql.DB }, clientID, clientType string,
	grants, redirects, audiences, scopes, authMethods []string, requirePKCE bool, nowMS int64) {
	t.Helper()
	encode := func(value []string) string {
		data, _ := json.Marshal(value)
		return string(data)
	}
	if _, err := store.DB().Exec(`INSERT INTO oauth_clients
(client_id, client_type, grant_types_json, redirect_uris_json, post_logout_redirect_uris_json,
scopes_json, audiences_json, auth_methods_json, require_pkce, row_version, created_at_ms, updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`, clientID, clientType, encode(grants), encode(redirects),
		encode([]string{}), encode(scopes), encode(audiences), encode(authMethods),
		boolInt(requirePKCE), nowMS, nowMS); err != nil {
		t.Fatalf("插入 OAuth 客户端 %s: %v", clientID, err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// httpResult2 是 QR 测试的 HTTP 响应快照（测试局部）。
type httpResult2 struct {
	Status int
	Body   []byte
	Header http.Header
}

func extractCSRFToken(html string) string {
	const needle = `name="csrf_token" value="`
	index := strings.Index(html, needle)
	if index < 0 {
		return ""
	}
	rest := html[index+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func truncateForTest(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
