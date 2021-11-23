package qrlogin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	apps "github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	. "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	qrsqlite "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testUser      = "usr_00000000000000000000000000000001"
	testOtherUser = "usr_00000000000000000000000000000002"
	testAppOne    = "app_00000000000000000000000000000001"
	testAppTwo    = "app_00000000000000000000000000000002"
	testScopeOne  = "openid"
	testScopeTwo  = "profile"
)

var testStart = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// testClock 是确定性时钟。
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// fakeReauth 记录再次认证调用并可注入拒绝。
type fakeReauth struct {
	mu    sync.Mutex
	allow bool
	calls int
}

func (f *fakeReauth) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !f.allow {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description,
		UserID: "usr_00000000000000000000000000000001", RequestID: request.RequestID}, nil
}

func (f *fakeReauth) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// testEnv 是真实 SQLite + 真实会话服务的扫码登录测试环境。
type testEnv struct {
	t            *testing.T
	ctx          context.Context
	raw          *storagesqlite.Store
	service      *Service
	sessions     *session.Service
	clock        *testClock
	reauth       *fakeReauth
	audit        *audit.Recorder
	qrStore      *qrsqlite.Store
	keyring      *secrets.Keyring
	appOneSecret string
}

// newTestEnv 创建临时数据库、执行全部迁移并装配真实服务。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "qrlogin.db")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	clock := &testClock{now: testStart}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储失败: %v", err)
	}
	auditRecorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: clock.Now})
	if err != nil {
		t.Fatalf("审计服务失败: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("密钥环失败: %v", err)
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("会话存储失败: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: auditRecorder, Keyring: keyring,
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 2 * time.Hour,
		AllowLegacyWithoutSensitive: true, Logger: logger, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("会话服务失败: %v", err)
	}
	appStore, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("应用存储失败: %v", err)
	}
	clientStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		t.Fatalf("客户端存储失败: %v", err)
	}
	qrStore, err := qrsqlite.New(raw)
	if err != nil {
		t.Fatalf("扫码登录存储失败: %v", err)
	}
	fake := &fakeReauth{allow: true}
	service, err := New(Options{
		Store: qrStore, Audit: auditRecorder, Clients: clientStore, Applications: appStore,
		Sessions: sessionService, SessionIssuer: sessionService, Reauth: fake,
		Keyring: keyring, Enabled: true, AllowedClientIDs: []string{testAppOne},
		RequestTTL: 2 * time.Minute, ClaimInterval: time.Second,
		Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("扫码登录服务失败: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, service: service, sessions: sessionService,
		clock: clock, reauth: fake, audit: auditRecorder, qrStore: qrStore, keyring: keyring}
	env.insertFixtures()
	return env
}

// insertFixtures 插入用户、应用、成员、客户端登记与 scope。
func (e *testEnv) insertFixtures() {
	e.t.Helper()
	now := testStart.UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(e.ctx, query, args...); err != nil {
			e.t.Fatalf("插入测试数据失败: %v\nSQL: %s", err, query)
		}
	}
	insertUser := func(userID, username string) {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, username, username, now, now)
	}
	insertUser(testUser, "qruser")
	insertUser(testOtherUser, "qruser2")
	insertApplication := func(applicationID, name, status string) {
		exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',?,'public',1,?,?)`, applicationID, name, status, now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, applicationID, applicationID)
	}
	insertApplication(testAppOne, "扫码演示应用", "active")
	insertApplication(testAppTwo, "其它应用", "active")
	insertMembership := func(applicationID, userID string) {
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, applicationID, userID, now, now)
	}
	insertMembership(testAppOne, testUser)
	insertMembership(testAppTwo, testUser)
	insertClient := func(applicationID string) {
		exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms)
VALUES(?,'public','["authorization_code"]','[]','[]','["openid","profile"]','[]','[]',1,1,?,?)`,
			applicationID, now, now)
	}
	insertClient(testAppOne)
	insertClient(testAppTwo)
}

// completeResult 构造完整认证结果。
func completeResult(userID string) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID: userID, Username: "qruser", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testStart, SecurityVersion: 1,
	}
}

// loginApp 以应用作用域签发普通会话（模拟已登录 APP）。
func (e *testEnv) loginApp(userID, appID string) session.IssuedSession {
	e.t.Helper()
	issued, err := e.sessions.Login(e.ctx, session.LoginRequest{
		Result: completeResult(userID), AppID: appID, RequestID: "req_app_login",
	})
	if err != nil {
		e.t.Fatalf("签发 APP 会话失败: %v", err)
	}
	return issued
}

// begin 创建一次扫码请求。
func (e *testEnv) begin() BeginResult {
	e.t.Helper()
	result, err := e.service.Begin(e.ctx, BeginRequest{
		ClientID: testAppOne, Scopes: []string{testScopeOne},
		RequestID: "req_begin", Requester: RequesterInfo{UserAgent: "TestBrowser/1.0", Address: "127.0.0.1"},
	})
	if err != nil {
		e.t.Fatalf("创建扫码请求失败: %v", err)
	}
	return result
}

// claimRequest 构造领取请求。
func claimRequest(begin BeginResult) ClaimedRequest {
	return ClaimedRequest{ClaimSecret: begin.ClaimSecret, RequestID: begin.RequestID,
		AuditRequestID: "req_claim"}
}

// approve 完成一次批准。
func (e *testEnv) approve(begin BeginResult, appSecret string) {
	e.t.Helper()
	if _, err := e.service.Approve(e.ctx, DecideRequest{
		SessionSecret: appSecret, RequestID: begin.RequestID,
		ExpectedVersion: begin.Version, AuditRequestID: "req_approve",
	}); err != nil {
		e.t.Fatalf("批准扫码请求失败: %v", err)
	}
}

// TestNewRequiresDependencies 验证缺依赖（含 typed-nil）拒绝构造。
func TestNewRequiresDependencies(t *testing.T) {
	env := newTestEnv(t)
	base := func() Options {
		return Options{
			Store: env.qrStore, Audit: env.audit, Clients: &fakeClientReader{}, Applications: &fakeAppReader{},
			Sessions: &fakeSessions{}, SessionIssuer: &fakeIssuer{}, Keyring: env.keyring,
			Enabled: true, AllowedClientIDs: []string{testAppOne},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"store", func(o *Options) { o.Store = nil }},
		{"audit", func(o *Options) { o.Audit = nil }},
		{"clients", func(o *Options) { o.Clients = nil }},
		{"applications", func(o *Options) { o.Applications = nil }},
		{"sessions", func(o *Options) { o.Sessions = nil }},
		{"issuer", func(o *Options) { o.SessionIssuer = nil }},
		{"keyring", func(o *Options) { o.Keyring = nil }},
		{"typed nil clients", func(o *Options) { o.Clients = (*fakeClientReader)(nil) }},
		{"typed nil sessions", func(o *Options) { o.Sessions = (*fakeSessions)(nil) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := base()
			options.Keyring = env.keyring
			test.mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
				t.Fatalf("缺依赖应拒绝构造，实际 %v", err)
			}
		})
	}
	// 非法参数。
	options := base()
	options.Keyring = env.keyring
	options.RequestTTL = time.Second
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("非法 TTL 应拒绝构造")
	}
	options = base()
	options.Keyring = env.keyring
	options.AllowedClientIDs = []string{"app_bad"}
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("非法白名单应拒绝构造")
	}
}

// TestQRPayloadStrictParsing 验证二维码载荷只含请求标识且严格解析。
func TestQRPayloadStrictParsing(t *testing.T) {
	requestID := "qrl_0123456789abcdef0123456789abcdef"
	payload, err := EncodeQRPayload(requestID)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if strings.Contains(payload, "token") || !strings.Contains(payload, requestID) {
		t.Fatalf("二维码载荷内容不正确: %s", payload)
	}
	parsed, err := ParseQRPayload(payload)
	if err != nil || parsed.RequestID != requestID || parsed.Version != 1 {
		t.Fatalf("解析失败: %+v err=%v", parsed, err)
	}
	invalid := []string{
		"",
		"https://evil.example.com/login?r=" + requestID,
		"evernight-login://app-qr?v=1&r=" + requestID + "&redirect=https://evil.example.com",
		"evernight-login://app-qr?v=2&r=" + requestID,
		"evernight-login://app-qr?v=1",
		"evernight-login://app-qr?v=1&r=bad",
		"evernight-login://user@app-qr?v=1&r=" + requestID,
		"evernight-login://app-qr/path?v=1&r=" + requestID,
		"evernight-login://app-qr?v=1&r=" + requestID + "#fragment",
		"evernight-login://app-qr?v=1&v=1&r=" + requestID,
	}
	for _, raw := range invalid {
		if _, err := ParseQRPayload(raw); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("应拒绝二维码载荷 %q，实际 %v", raw, err)
		}
	}
}

// TestBeginValidationAndSecretRedaction 验证创建请求的开关/白名单/scope 校验与
// 领取绑定只出现一次且默认脱敏。
func TestBeginValidationAndSecretRedaction(t *testing.T) {
	env := newTestEnv(t)
	begin := env.begin()
	if begin.RequestID == "" || !begin.ClaimSecret.IsSet() || begin.QRPayload == "" ||
		begin.Version != 1 || begin.PollIntervalSeconds < 1 {
		t.Fatalf("创建结果不完整: %+v", begin)
	}
	// 领取绑定默认脱敏（JSON/格式化都不泄露原文）。
	encoded, err := json.Marshal(begin)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if strings.Contains(string(encoded), begin.ClaimSecret.Reveal()) {
		t.Fatal("创建结果的 JSON 泄露领取绑定明文")
	}
	if !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("创建结果应标记脱敏，实际 %s", encoded)
	}
	// 应用未列入白名单 → 拒绝。
	if _, err := env.service.Begin(env.ctx, BeginRequest{ClientID: testAppTwo,
		RequestID: "req_other"}); !errors.Is(err, ErrQRLoginDisabled) {
		t.Fatalf("白名单外应用应拒绝，实际 %v", err)
	}
	// 非法应用 ID → 参数错误。
	if _, err := env.service.Begin(env.ctx, BeginRequest{ClientID: "app_bad",
		RequestID: "req_bad"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法应用 ID 应返回参数错误，实际 %v", err)
	}
	// 未登记 scope → 参数错误。
	if _, err := env.service.Begin(env.ctx, BeginRequest{ClientID: testAppOne,
		Scopes: []string{"admin"}, RequestID: "req_scope"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未登记 scope 应拒绝，实际 %v", err)
	}
	// 限流：默认每分钟 10 次；继续创建直到被限流。
	limited := false
	for index := 0; index < 20; index++ {
		if _, err := env.service.Begin(env.ctx, BeginRequest{ClientID: testAppOne,
			RequestID: "req_rate"}); errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("创建请求限流未生效")
	}
}

// TestApproveAndClaimFlow 验证正常闭环：创建 → APP 查看/批准 → 发起端领取会话，
// 结果只能成功领取一次。
func TestApproveAndClaimFlow(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	begin := env.begin()
	prompt, err := env.service.Describe(env.ctx, PromptRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
		AuditRequestID: "req_describe"})
	if err != nil {
		t.Fatalf("APP 读取请求失败: %v", err)
	}
	if prompt.ApplicationName != "扫码演示应用" || prompt.Status != StatusPending ||
		prompt.Warning == "" || prompt.Requester.UserAgent != "TestBrowser/1.0" {
		t.Fatalf("确认上下文不完整: %+v", prompt)
	}
	if prompt.Version != begin.Version {
		t.Fatalf("确认版本不一致: %d vs %d", prompt.Version, begin.Version)
	}
	// 旧版本批准 → 冲突。
	if _, err := env.service.Approve(env.ctx, DecideRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
		ExpectedVersion: begin.Version + 1, AuditRequestID: "req_bad_version",
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("版本冲突应拒绝，实际 %v", err)
	}
	env.approve(begin, appSession.Secret.Reveal())
	status, err := env.service.Status(env.ctx, claimRequest(begin))
	if err != nil {
		t.Fatalf("查询状态失败: %v", err)
	}
	if status.Status != QueryApproved {
		t.Fatalf("批准后状态应为 approved，实际 %s", status.Status)
	}
	// 已批准后 APP 再读取应按不存在处理。
	if _, err := env.service.Describe(env.ctx, PromptRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
	}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("已批准的请求不应再次展示为待确认，实际 %v", err)
	}
	issued, err := env.service.Claim(env.ctx, claimRequest(begin))
	if err != nil {
		t.Fatalf("领取登录结果失败: %v", err)
	}
	if issued.Session.UserID != testUser || issued.Session.AppID != testAppOne ||
		issued.Session.Kind != session.KindNormal {
		t.Fatalf("领取的会话不正确: %+v", issued.Session)
	}
	validated, err := env.sessions.AuthorizeBusiness(env.ctx, issued.Secret.Reveal())
	if err != nil || validated.UserID != testUser {
		t.Fatalf("领取的会话应可访问业务接口: %+v err=%v", validated, err)
	}
	// 重复领取 → 已领取，且不会签发第二个会话。
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("重复领取应拒绝，实际 %v", err)
	}
	env.clock.Advance(2 * time.Second)
	status, err = env.service.Status(env.ctx, claimRequest(begin))
	if err != nil {
		t.Fatalf("查询最终状态失败: %v", err)
	}
	if status.Status != QueryClaimed {
		t.Fatalf("最终状态应为 claimed，实际 %s", status.Status)
	}
	// 审计：创建/批准/领取都有记录，且不含领取绑定明文。
	for _, action := range []string{"app_qr_login.request_created", "app_qr_login.approved",
		"app_qr_login.claimed"} {
		if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=?`, action); got == 0 {
			t.Fatalf("缺少审计动作 %s", action)
		}
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`,
		"%"+begin.ClaimSecret.Reveal()+"%"); got != 0 {
		t.Fatal("审计不应包含领取绑定明文")
	}
	// 会话签发审计来自 session 包。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=?`,
		string(session.ActionSessionLoginGrantIssued)); got != 1 {
		t.Fatalf("应写 1 条登录批准会话签发审计，实际 %d", got)
	}
}

// TestWrongEndAndCopiedQRCode 验证错误领取绑定/错误请求 ID/仅二维码不能领取。
func TestWrongEndAndCopiedQRCode(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	begin := env.begin()
	env.approve(begin, appSession.Secret.Reveal())
	// 只有二维码中的 request_id（无领取绑定）不能领取。
	if _, err := env.service.Claim(env.ctx, ClaimedRequest{RequestID: begin.RequestID}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("缺少领取绑定应拒绝，实际 %v", err)
	}
	// 另一个请求的合法领取绑定（错误绑定）。
	otherBegin := env.begin()
	if _, err := env.service.Claim(env.ctx, ClaimedRequest{ClaimSecret: otherBegin.ClaimSecret,
		RequestID: begin.RequestID}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("错误领取绑定应拒绝，实际 %v", err)
	}
	// 正确绑定但错误请求 ID（跨请求替换）应拒绝。
	if _, err := env.service.Claim(env.ctx, ClaimedRequest{ClaimSecret: begin.ClaimSecret,
		RequestID: otherBegin.RequestID}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("错误请求 ID 应拒绝，实际 %v", err)
	}
}

// TestDenyCancelRegenerateExpiry 验证拒绝/取消/重新生成/过期状态与旧二维码失效。
func TestDenyCancelRegenerateExpiry(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	// 拒绝。
	begin := env.begin()
	if _, err := env.service.Deny(env.ctx, DecideRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
		ExpectedVersion: begin.Version, AuditRequestID: "req_deny"}); err != nil {
		t.Fatalf("拒绝失败: %v", err)
	}
	status, err := env.service.Status(env.ctx, claimRequest(begin))
	if err != nil || status.Status != QueryDenied {
		t.Fatalf("拒绝后状态应为 denied: %+v err=%v", status, err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrRequestDenied) {
		t.Fatalf("已拒绝请求领取应返回 ErrRequestDenied，实际 %v", err)
	}
	// 取消。
	begin = env.begin()
	if _, err := env.service.Cancel(env.ctx, claimRequest(begin)); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrRequestCancelled) {
		t.Fatalf("已取消请求领取应返回 ErrRequestCancelled，实际 %v", err)
	}
	// 重新生成：旧二维码/旧领取绑定失效，新二维码可用。
	old := env.begin()
	regenerated, err := env.service.Regenerate(env.ctx, claimRequest(old))
	if err != nil {
		t.Fatalf("重新生成失败: %v", err)
	}
	if regenerated.RequestID == old.RequestID || regenerated.ClaimSecret.Reveal() == old.ClaimSecret.Reveal() {
		t.Fatal("重新生成必须换新请求标识与领取绑定")
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(old)); !errors.Is(err, ErrRequestCancelled) {
		t.Fatalf("旧请求领取应返回 ErrRequestCancelled，实际 %v", err)
	}
	env.approve(regenerated, appSession.Secret.Reveal())
	if _, err := env.service.Claim(env.ctx, claimRequest(regenerated)); err != nil {
		t.Fatalf("新请求应可领取: %v", err)
	}
	// 过期。
	expiring := env.begin()
	env.clock.Advance(3 * time.Minute)
	status, err = env.service.Status(env.ctx, claimRequest(expiring))
	if err != nil || status.Status != QueryExpired {
		t.Fatalf("过期请求状态应为 expired: %+v err=%v", status, err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(expiring)); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("过期请求领取应返回 ErrRequestExpired，实际 %v", err)
	}
	if _, err := env.service.Approve(env.ctx, DecideRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: expiring.RequestID,
		ExpectedVersion: expiring.Version, AuditRequestID: "req_expired_approve",
	}); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("过期请求批准应返回 ErrRequestExpired，实际 %v", err)
	}
}

// TestConfirmSessionScopeAndRevocation 验证确认端会话跨应用拒绝、撤销后领取拒绝。
func TestConfirmSessionScopeAndRevocation(t *testing.T) {
	env := newTestEnv(t)
	appOneSession := env.loginApp(testUser, testAppOne)
	appTwoSession := env.loginApp(testUser, testAppTwo)
	begin := env.begin()
	// 其它应用作用域会话不能确认本应用请求。
	if _, err := env.service.Describe(env.ctx, PromptRequest{
		SessionSecret: appTwoSession.Secret.Reveal(), RequestID: begin.RequestID,
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("跨应用会话应拒绝，实际 %v", err)
	}
	// 受限会话不能确认（这里用未完成认证构造受限会话）。
	restrictedResult := authn.AuthenticateResult{
		UserID: testUser, Username: "qruser", Outcome: authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: testStart,
		RequiredSteps: []authn.Step{authn.StepSecondFactor}, Restricted: true,
		SecurityVersion: 1,
	}
	restricted, err := env.sessions.Login(env.ctx, session.LoginRequest{Result: restrictedResult})
	if err != nil {
		t.Fatalf("签发受限会话失败: %v", err)
	}
	if _, err := env.service.Describe(env.ctx, PromptRequest{
		SessionSecret: restricted.Secret.Reveal(), RequestID: begin.RequestID,
	}); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("受限会话应拒绝，实际 %v", err)
	}
	// 批准后撤销确认端会话 → 领取拒绝。
	env.approve(begin, appOneSession.Secret.Reveal())
	if err := env.sessions.Logout(env.ctx, appOneSession.Secret.Reveal()); err != nil {
		t.Fatalf("撤销 APP 会话失败: %v", err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("确认端会话撤销后领取应拒绝，实际 %v", err)
	}
}

// TestConcurrentApproveAndClaim 验证并发批准/领取单赢家。
func TestConcurrentApproveAndClaim(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	begin := env.begin()
	var wg sync.WaitGroup
	var mu sync.Mutex
	approveSuccess := 0
	for index := 0; index < 4; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := env.service.Approve(env.ctx, DecideRequest{
				SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
				ExpectedVersion: begin.Version, AuditRequestID: "req_concurrent_approve",
			}); err == nil {
				mu.Lock()
				approveSuccess++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if approveSuccess != 1 {
		t.Fatalf("并发批准应只有 1 个成功，实际 %d", approveSuccess)
	}
	claimSuccess := 0
	for index := 0; index < 4; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := env.service.Claim(env.ctx, claimRequest(begin)); err == nil {
				mu.Lock()
				claimSuccess++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claimSuccess != 1 {
		t.Fatalf("并发领取应只有 1 个成功，实际 %d", claimSuccess)
	}
	// 会话总数 = APP 会话 + 领取会话。
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 2 {
		t.Fatalf("会话总数应为 2（APP + 领取），实际 %d", got)
	}
}

// TestGlobalSessionMayConfirm 验证未绑定应用的全局普通会话可确认（沿用步骤 57
// 会话语义：用户身份来自真实会话，不由请求参数自称）；应用作用域会话需匹配。
func TestGlobalSessionMayConfirm(t *testing.T) {
	env := newTestEnv(t)
	global, err := env.sessions.Login(env.ctx, session.LoginRequest{Result: completeResult(testUser)})
	if err != nil {
		t.Fatalf("签发全局会话失败: %v", err)
	}
	begin := env.begin()
	if _, err := env.service.Describe(env.ctx, PromptRequest{
		SessionSecret: global.Secret.Reveal(), RequestID: begin.RequestID}); err != nil {
		t.Fatalf("全局会话应可读取待确认请求: %v", err)
	}
	env.approve(begin, global.Secret.Reveal())
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); err != nil {
		t.Fatalf("全局会话确认后应可领取: %v", err)
	}
}

// TestClaimRechecksClientState 验证批准后应用停用/白名单外时领取 fail-closed。
func TestClaimRechecksClientState(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	begin := env.begin()
	env.approve(begin, appSession.Secret.Reveal())
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE applications SET status='disabled',row_version=row_version+1 WHERE id=?`,
		testAppOne); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrClientUnavailable) {
		t.Fatalf("应用停用后领取应返回 ErrClientUnavailable，实际 %v", err)
	}
}

// TestRequiredReauthAndDisabled 验证再次认证缺失/拒绝时不能批准，功能关闭时拒绝。
func TestRequiredReauthAndDisabled(t *testing.T) {
	env := newTestEnv(t)
	appSession := env.loginApp(testUser, testAppOne)
	begin := env.begin()
	env.reauth.allow = false
	if _, err := env.service.Approve(env.ctx, DecideRequest{
		SessionSecret: appSession.Secret.Reveal(), RequestID: begin.RequestID,
		ExpectedVersion: begin.Version, AuditRequestID: "req_reauth_denied",
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("再次认证拒绝时应拒绝批准，实际 %v", err)
	}
	if status, err := env.service.Status(env.ctx, claimRequest(begin)); err != nil || status.Status != QueryPending {
		t.Fatalf("批准失败后请求应仍为 pending: %+v err=%v", status, err)
	}
	// 重新构造关闭开关的服务（同一存储）：创建/领取一律拒绝。
	disabled, err := New(Options{
		Store: env.qrStore, Audit: env.audit, Clients: &fakeClientReader{},
		Applications: &fakeAppReader{}, Sessions: &fakeSessions{}, SessionIssuer: &fakeIssuer{},
		Keyring: env.keyring, Enabled: false, AllowedClientIDs: nil,
		Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造关闭服务失败: %v", err)
	}
	if _, err := disabled.Begin(env.ctx, BeginRequest{ClientID: testAppOne}); !errors.Is(err, ErrQRLoginDisabled) {
		t.Fatalf("功能关闭时创建应拒绝，实际 %v", err)
	}
	if _, err := disabled.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrQRLoginDisabled) {
		t.Fatalf("功能关闭时领取应拒绝，实际 %v", err)
	}
}

// queryInt 执行计数查询。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatal("查询没有结果")
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		e.t.Fatalf("扫描结果失败: %v", err)
	}
	return count
}

// 以下为测试替身：仅用于构造校验/关闭开关用例，不作为生产实现。
type fakeClientReader struct{}

func (f *fakeClientReader) GetClient(context.Context, string) (oauthclient.ClientRecord, bool, error) {
	return oauthclient.ClientRecord{}, false, nil
}

type fakeAppReader struct{}

func (f *fakeAppReader) GetApplication(context.Context, string) (apps.Application, error) {
	return apps.Application{}, apps.ErrApplicationNotFound
}

type fakeSessions struct{}

func (f *fakeSessions) Validate(context.Context, string) (session.Session, error) {
	return session.Session{}, session.ErrSessionInvalid
}
func (f *fakeSessions) VerifyActiveSession(context.Context, string, string) error {
	return session.ErrSessionInvalid
}

type fakeIssuer struct{}

func (f *fakeIssuer) IssueLoginGrantSession(context.Context, session.LoginGrantRequest,
	session.LoginGrantGate) (session.IssuedSession, error) {
	return session.IssuedSession{}, session.ErrLoginGrantDenied
}
