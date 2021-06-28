package tokenauthz_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	. "github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
)

const (
	testUser       = "usr_00000000000000000000000000000001"
	testAppOne     = "app_00000000000000000000000000000001"
	testAppTwo     = "app_00000000000000000000000000000002"
	testClient     = testAppOne
	testAudience   = "https://api.example.test"
	testOtherAud   = "https://other.example.test"
	testPermission = "invoices.approve"
	testRequestID  = "req_0001"
	testServiceID  = "billing-api"
)

// 编译期确认生产实现满足接口（真实装配时的替换不改变契约）。
var (
	_ TokenVerifier     = (*token.Service)(nil)
	_ RevocationChecker = (*oauthflow.Service)(nil)
)

// fakeVerifier 是访问凭证验证替身（仅测试路径）。
type fakeVerifier struct {
	mu     sync.Mutex
	claims token.AccessClaims
	err    error
	calls  int
}

func (f *fakeVerifier) VerifyAccessToken(_ context.Context, _ string, _ string) (token.AccessClaims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return token.AccessClaims{}, f.err
	}
	return f.claims, nil
}

// fakeClients 是客户端登记替身。
type fakeClients struct {
	mu      sync.Mutex
	clients map[string]token.ClientInfo
	err     error
}

func (f *fakeClients) LoadClient(_ context.Context, clientID string) (token.ClientInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return token.ClientInfo{}, f.err
	}
	client, found := f.clients[clientID]
	if !found {
		return token.ClientInfo{}, token.ErrClientNotFound
	}
	return client, nil
}

func (f *fakeClients) set(clientID string, client token.ClientInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients == nil {
		f.clients = map[string]token.ClientInfo{}
	}
	f.clients[clientID] = client
}

// fakeRevocations 是在线撤销检查替身。
type fakeRevocations struct {
	mu      sync.Mutex
	revoked bool
	err     error
}

func (f *fakeRevocations) AccessTokenRevoked(_ context.Context, _ token.AccessClaims) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked, f.err
}

// fakeEngine 是当前权限计算替身；mutate 每次调用前运行，便于模拟权限被撤销。
type fakeEngine struct {
	mu     sync.Mutex
	result authz.CheckResult
	err    error
	calls  int
	mutate func()
	last   authz.CheckRequest
	caller authz.Caller
}

func (f *fakeEngine) Check(_ context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = request
	f.caller = caller
	if f.mutate != nil {
		f.mutate()
	}
	if f.err != nil {
		return authz.CheckResult{}, f.err
	}
	return f.result, nil
}

func (f *fakeEngine) setResult(result authz.CheckResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = result
}

// fakeAudit 记录失败审计事件。
type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (f *fakeAudit) RecordFailure(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return f.err
}

// fakePolicy 是服务主体权限策略替身。
type fakePolicy struct {
	mu       sync.Mutex
	decision ServicePrincipalDecision
	err      error
	calls    int
	last     ServicePermissionRequest
}

func (f *fakePolicy) AuthorizeServicePrincipal(_ context.Context, _ ResourceService,
	_ ServicePrincipal, request ServicePermissionRequest) (ServicePrincipalDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = request
	if f.err != nil {
		return ServicePrincipalDecision{}, f.err
	}
	return f.decision, nil
}

// testEnv 聚合测试替身并构造判定服务。
type testEnv struct {
	t          *testing.T
	service    *Service
	verifier   *fakeVerifier
	clients    *fakeClients
	revocation *fakeRevocations
	engine     *fakeEngine
	audit      *fakeAudit
	policy     *fakePolicy
}

// newEnv 构造默认全部允许通过、需要显式设置判定结果的环境。
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{
		t:          t,
		verifier:   &fakeVerifier{claims: userClaims(testUser, testClient, testAudience)},
		clients:    &fakeClients{},
		revocation: &fakeRevocations{},
		engine: &fakeEngine{result: authz.CheckResult{
			Allowed: true,
		}},
		audit:  &fakeAudit{},
		policy: &fakePolicy{},
	}
	env.clients.set(testClient, token.ClientInfo{
		ClientID: testClient, ApplicationID: testAppOne, ClientType: "public", AppActive: true,
		Audiences: []string{testAudience},
	})
	service, err := New(Options{
		Verifier: env.verifier, Clients: env.clients, Revocations: env.revocation,
		Permissions: env.engine, ServicePrincipals: env.policy, Audit: env.audit,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random: strings.NewReader(strings.Repeat("a", 64)),
	})
	if err != nil {
		t.Fatalf("构造判定服务失败: %v", err)
	}
	env.service = service
	return env
}

func userClaims(subject, clientID, audience string) token.AccessClaims {
	return token.AccessClaims{
		Issuer: "https://issuer.example.test", Subject: subject, Audience: []string{audience},
		ClientID: clientID, Scopes: []string{"openid", "profile"}, TokenID: "jti_0001",
		TokenUse: token.TokenUseAccess, SubjectType: token.TokenSubjectTypeUser,
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute),
	}
}

func serviceClaims(clientID, audience string) token.AccessClaims {
	claims := userClaims(clientID, clientID, audience)
	claims.SubjectType = token.TokenSubjectTypeService
	return claims
}

// resource 构造默认可信资源服务身份（应用一 + 默认 audience）。
func resource(t *testing.T) ResourceService {
	t.Helper()
	service, err := NewResourceService(testServiceID, testAppOne, testAudience)
	if err != nil {
		t.Fatalf("构造资源服务身份失败: %v", err)
	}
	return service
}

// request 构造默认合法请求。
func request(permissions ...string) Request {
	if len(permissions) == 0 {
		permissions = []string{testPermission}
	}
	return Request{AccessToken: "jwt", Permissions: permissions, RequestID: testRequestID}
}

// assertDenied 断言业务拒绝、错误码、原因与审计事件。
func assertDenied(t *testing.T, decision Decision, wantCode ErrorCode) {
	t.Helper()
	if decision.Allow {
		t.Fatalf("判定应拒绝，实际允许: %+v", decision)
	}
	if decision.Code != wantCode {
		t.Fatalf("拒绝码 = %q，期望 %q（reason=%q）", decision.Code, wantCode, decision.Reason)
	}
	if decision.Message == "" {
		t.Fatal("拒绝结果缺少直白 message")
	}
	if decision.RequestID == "" {
		t.Fatal("拒绝结果缺少 request_id")
	}
}

// TestNewRequiresAllDependencies 验证缺依赖（含 typed-nil）拒绝构造。
func TestNewRequiresAllDependencies(t *testing.T) {
	base := func() Options {
		return Options{
			Verifier: &fakeVerifier{}, Clients: &fakeClients{}, Revocations: &fakeRevocations{},
			Permissions: &fakeEngine{}, Audit: &fakeAudit{},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"verifier", func(o *Options) { o.Verifier = nil }},
		{"typed-nil verifier", func(o *Options) { o.Verifier = (*fakeVerifier)(nil) }},
		{"clients", func(o *Options) { o.Clients = nil }},
		{"typed-nil clients", func(o *Options) { o.Clients = (*fakeClients)(nil) }},
		{"revocations", func(o *Options) { o.Revocations = nil }},
		{"permissions", func(o *Options) { o.Permissions = nil }},
		{"audit", func(o *Options) { o.Audit = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := base()
			test.mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
				t.Fatalf("缺依赖应拒绝构造并返回 ErrOptionsInvalid，实际 %v", err)
			}
		})
	}
	// 服务主体策略是可选项：允许使用未注入策略的服务构造（对服务主体权限要求拒绝）。
	options := base()
	options.ServicePrincipals = nil
	if _, err := New(options); err != nil {
		t.Fatalf("未注入服务主体策略不应阻止构造（应在判定时拒绝）: %v", err)
	}
}

// TestResourceServiceValidation 验证可信身份构造校验与零值拒绝。
func TestResourceServiceValidation(t *testing.T) {
	if _, err := NewResourceService("", testAppOne, testAudience); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("空服务标识应拒绝")
	}
	if _, err := NewResourceService("billing api", testAppOne, testAudience); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("含空格的服标识应拒绝")
	}
	if _, err := NewResourceService(testServiceID, "app_bad", testAudience); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("非法应用标识应拒绝")
	}
	if _, err := NewResourceService(testServiceID, testAppOne, "not-a-uri"); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("非法 audience 应拒绝")
	}
	env := newEnv(t)
	if _, err := env.service.Decide(context.Background(), ResourceService{}, request()); !errors.Is(err, ErrCallerUntrusted) {
		t.Fatalf("零值资源服务身份应拒绝，实际 %v", err)
	}
	if len(env.audit.events) != 1 || env.audit.events[0].Actor.Type != audit.ActorAnonymous {
		t.Fatalf("不可信调用者应写匿名失败审计，实际 %+v", env.audit.events)
	}
}

// TestRequestValidation 验证参数错误在令牌验证前拒绝（协议层错误，不写业务拒绝审计）。
func TestRequestValidation(t *testing.T) {
	cases := []struct {
		name    string
		request Request
	}{
		{"空令牌", Request{Permissions: []string{testPermission}}},
		{"空权限", Request{AccessToken: "jwt"}},
		{"权限键非法", Request{AccessToken: "jwt", Permissions: []string{"bad key"}}},
		{"模式非法", Request{AccessToken: "jwt", Permissions: []string{testPermission}, Mode: authz.Mode("xor")}},
		{"资源标识含控制字符", Request{AccessToken: "jwt", Permissions: []string{testPermission}, ResourceID: "a\x01b"}},
		{"请求编号非法", Request{AccessToken: "jwt", Permissions: []string{testPermission}, RequestID: "bad id"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newEnv(t)
			if _, err := env.service.Decide(context.Background(), resource(t), test.request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("应返回 ErrInvalidRequest，实际 %v", err)
			}
			if env.verifier.calls != 0 {
				t.Fatal("参数错误时不应验证令牌")
			}
		})
	}
	// 超过权限数量上限。
	env := newEnv(t)
	many := make([]string, authz.MaxRequirements+1)
	env.verifier.claims = userClaims(testUser, testClient, testAudience)
	req := Request{AccessToken: "jwt", Permissions: many}
	if _, err := env.service.Decide(context.Background(), resource(t), req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超量权限应拒绝，实际 %v", err)
	}
}

// TestTokenRejections 验证令牌无效/过期/audience 不匹配/类型混用均映射为稳定业务拒绝。
func TestTokenRejections(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode ErrorCode
	}{
		{"格式/签名/类型无效（含 ID Token 混用、会话秘密）", token.ErrWrongType, CodeTokenInvalid},
		{"签名无效", token.ErrSignatureInvalid, CodeTokenInvalid},
		{"算法不允许", token.ErrWrongAlgorithm, CodeTokenInvalid},
		{"已过期", token.ErrTokenExpired, CodeTokenExpired},
		{"audience 不匹配", token.ErrAudienceMismatch, CodeTokenAudienceMismatch},
		{"签名密钥被撤销", token.ErrKeyRevoked, CodeTokenRevoked},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newEnv(t)
			env.verifier.err = test.err
			decision, err := env.service.Decide(context.Background(), resource(t), request())
			if err != nil {
				t.Fatalf("令牌无效应为业务拒绝而非协议错误: %v", err)
			}
			assertDenied(t, decision, test.wantCode)
			if decision.Subject != "" || decision.ClientID != "" {
				t.Fatal("令牌验证失败时不应披露主体或客户端")
			}
			if len(env.audit.events) != 1 || env.audit.events[0].ErrorCode != string(test.wantCode) {
				t.Fatalf("拒绝应写失败审计，实际 %+v", env.audit.events)
			}
			if env.engine.calls != 0 {
				t.Fatal("令牌验证失败时不应计算权限")
			}
		})
	}
}

// TestRevokedTokenRejected 验证在线撤销标记命中后拒绝。
func TestRevokedTokenRejected(t *testing.T) {
	env := newEnv(t)
	env.revocation.revoked = true
	decision, err := env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("撤销应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodeTokenRevoked)
	if env.engine.calls != 0 {
		t.Fatal("令牌已撤销时不应计算权限")
	}
}

// TestClientMappingRejections 验证 client_id→资源 audience 映射与跨应用拒绝。
func TestClientMappingRejections(t *testing.T) {
	cases := []struct {
		name     string
		client   token.ClientInfo
		wantCode ErrorCode
	}{
		{"跨应用令牌", token.ClientInfo{ClientID: testClient, ApplicationID: testAppTwo, AppActive: true,
			Audiences: []string{testAudience}}, CodeAppScopeMismatch},
		{"应用停用", token.ClientInfo{ClientID: testClient, ApplicationID: testAppOne, AppActive: false,
			Audiences: []string{testAudience}}, CodeClientDisabled},
		{"audience 已从登记移除", token.ClientInfo{ClientID: testClient, ApplicationID: testAppOne, AppActive: true,
			Audiences: []string{testOtherAud}}, CodeTokenAudienceMismatch},
		{"客户端注销", token.ClientInfo{}, CodeTokenInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newEnv(t)
			env.clients.clients = map[string]token.ClientInfo{}
			if test.name != "客户端注销" {
				env.clients.set(testClient, test.client)
			}
			decision, err := env.service.Decide(context.Background(), resource(t), request())
			if err != nil {
				t.Fatalf("客户端映射失败应为业务拒绝: %v", err)
			}
			assertDenied(t, decision, test.wantCode)
		})
	}
}

// TestPermissionAllAnyAndCodes 验证 all/any 组合、逐项结果与错误码透传。
func TestPermissionAllAnyAndCodes(t *testing.T) {
	env := newEnv(t)
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodePermissionRequired,
		Reason: "permission_not_granted", Permissions: []authz.PermissionDecision{
			{Key: testPermission, Allowed: false, Code: authz.CodePermissionRequired, Reason: "permission_not_granted"},
		}})
	decision, err := env.service.Decide(context.Background(), resource(t), request(testPermission))
	if err != nil {
		t.Fatalf("权限不足应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodePermissionRequired)
	if len(decision.Permissions) != 1 || decision.Permissions[0].Key != testPermission {
		t.Fatalf("应返回逐权限判定，实际 %+v", decision.Permissions)
	}
	// any 模式透传到权限引擎。
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodePermissionRequired,
		Reason: "permission_not_granted"})
	req := request(testPermission, "invoices.read")
	req.Mode = authz.ModeAny
	if _, err := env.service.Decide(context.Background(), resource(t), req); err != nil {
		t.Fatalf("any 判定失败: %v", err)
	}
	if env.engine.last.Mode != authz.ModeAny || len(env.engine.last.Permissions) != 2 {
		t.Fatalf("any 模式与权限列表应原样传给权限引擎，实际 %+v", env.engine.last)
	}
	// 未登记码不得外泄：统一按 PERMISSION_REQUIRED。
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.ErrorCode("NOT_REGISTERED")})
	decision, err = env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("未知码应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodePermissionRequired)
	// 账户停用/成员缺失码透传。
	for _, code := range []authz.ErrorCode{authz.CodeUserDisabled, authz.CodeAppMembershipRequired,
		authz.CodePermissionDisabled, authz.CodePermissionUnknown, authz.CodeAccessDenied} {
		env.engine.setResult(authz.CheckResult{Allowed: false, Code: code})
		decision, err = env.service.Decide(context.Background(), resource(t), request())
		if err != nil || decision.Code != ErrorCode(code) {
			t.Fatalf("错误码 %q 应透传，实际 %+v err=%v", code, decision, err)
		}
	}
}

// TestAllowedDecisionFields 验证允许结果披露主体与应用范围、但不含秘密。
func TestAllowedDecisionFields(t *testing.T) {
	env := newEnv(t)
	decision, err := env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if !decision.Allow || decision.Code != "" {
		t.Fatalf("应允许，实际 %+v", decision)
	}
	if decision.Subject != testUser || decision.SubjectType != token.TokenSubjectTypeUser ||
		decision.ClientID != testClient || decision.ApplicationID != testAppOne {
		t.Fatalf("允许结果的主体/应用信息不正确: %+v", decision)
	}
	if decision.RequestID != testRequestID {
		t.Fatalf("request_id 应为 %q，实际 %q", testRequestID, decision.RequestID)
	}
	if len(env.audit.events) != 0 {
		t.Fatal("成功判定不写拒绝审计")
	}
}

// TestResourceDataScope 验证可选资源标识按数据范围契约判定。
func TestResourceDataScope(t *testing.T) {
	permissionDecision := func(scope authz.DataScope) authz.CheckResult {
		return authz.CheckResult{Allowed: true, Permissions: []authz.PermissionDecision{
			{Key: testPermission, Allowed: true, DataScope: scope},
		}}
	}
	cases := []struct {
		name       string
		scope      authz.DataScope
		resourceID string
		wantAllow  bool
		wantReason string
	}{
		{"未声明数据范围拒绝", authz.DataScope{Mode: authz.DataScopeUndefined}, "invoice-1", false, "data_scope_undefined"},
		{"none 拒绝", authz.DataScope{Mode: authz.DataScopeNone}, "invoice-1", false, "data_scope_none"},
		{"资源不在集合内拒绝", authz.DataScope{Mode: authz.DataScopeResources, Resources: []string{"invoice-2"}}, "invoice-1", false, "resource_not_in_scope"},
		{"资源在集合内允许", authz.DataScope{Mode: authz.DataScopeResources, Resources: []string{"invoice-1"}}, "invoice-1", true, ""},
		{"all 允许", authz.DataScope{Mode: authz.DataScopeAll}, "invoice-1", true, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newEnv(t)
			env.engine.setResult(permissionDecision(test.scope))
			req := request()
			req.ResourceID = test.resourceID
			decision, err := env.service.Decide(context.Background(), resource(t), req)
			if err != nil {
				t.Fatalf("资源判定失败: %v", err)
			}
			if decision.Allow != test.wantAllow {
				t.Fatalf("allow = %v，期望 %v（%+v）", decision.Allow, test.wantAllow, decision)
			}
			if !test.wantAllow {
				if decision.Code != CodeResourceForbidden || decision.Reason != test.wantReason {
					t.Fatalf("资源拒绝码/原因不正确: %+v", decision)
				}
			}
		})
	}
	// any 模式：任一权限的数据范围允许即可。
	env := newEnv(t)
	env.engine.setResult(authz.CheckResult{Allowed: true, Permissions: []authz.PermissionDecision{
		{Key: testPermission, Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeNone}},
		{Key: "invoices.read", Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeAll}},
	}})
	req := request(testPermission, "invoices.read")
	req.Mode = authz.ModeAny
	req.ResourceID = "invoice-1"
	decision, err := env.service.Decide(context.Background(), resource(t), req)
	if err != nil || !decision.Allow || !decision.ResourceAllowed {
		t.Fatalf("any 模式任一资源允许即可通过，实际 %+v err=%v", decision, err)
	}
}

// TestServicePrincipalModel 验证服务主体使用独立权限模型、默认拒绝。
func TestServicePrincipalModel(t *testing.T) {
	// 未注入策略：服务主体权限要求一律拒绝。
	env := newEnv(t)
	env.verifier.claims = serviceClaims(testClient, testAudience)
	options := Options{
		Verifier: env.verifier, Clients: env.clients, Revocations: env.revocation,
		Permissions: env.engine, Audit: env.audit,
	}
	withoutPolicy, err := New(options)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	decision, err := withoutPolicy.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("服务主体拒绝应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodePermissionRequired)
	if decision.Reason != "service_principal_policy_missing" {
		t.Fatalf("缺少服务主体策略的原因码不正确: %q", decision.Reason)
	}
	if env.engine.calls != 0 {
		t.Fatal("服务主体不应走用户权限引擎（不能借用用户身份）")
	}
	// 策略拒绝。
	env = newEnv(t)
	env.verifier.claims = serviceClaims(testClient, testAudience)
	env.policy.decision = ServicePrincipalDecision{Allow: false, Code: CodePermissionRequired, Reason: "not_entitled"}
	decision, err = env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("策略拒绝应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodePermissionRequired)
	if env.policy.calls != 1 || len(env.policy.last.Permissions) != 1 {
		t.Fatalf("服务主体策略应收到业务要求，实际 %+v", env.policy.last)
	}
	// 策略允许：服务主体令牌可以作为服务身份通过。
	env = newEnv(t)
	env.verifier.claims = serviceClaims(testClient, testAudience)
	env.policy.decision = ServicePrincipalDecision{Allow: true}
	decision, err = env.service.Decide(context.Background(), resource(t), request())
	if err != nil || !decision.Allow {
		t.Fatalf("策略允许时应通过，实际 %+v err=%v", decision, err)
	}
	if decision.SubjectType != token.TokenSubjectTypeService || decision.Subject != testClient {
		t.Fatalf("服务主体结果不正确: %+v", decision)
	}
	if env.engine.calls != 0 {
		t.Fatal("服务主体不应计算用户权限")
	}
}

// TestDependencyUnavailable 验证依赖故障按不可用拒绝（不允许）。
func TestDependencyUnavailable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testEnv)
	}{
		{"令牌存储不可用", func(env *testEnv) { env.verifier.err = token.ErrStoreUnavailable }},
		{"撤销检查不可用", func(env *testEnv) { env.revocation.err = errors.New("db down") }},
		{"客户端存储不可用", func(env *testEnv) { env.clients.err = token.ErrStoreUnavailable }},
		{"权限存储不可用", func(env *testEnv) { env.engine.err = errors.New("db down") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newEnv(t)
			test.mutate(env)
			decision, err := env.service.Decide(context.Background(), resource(t), request())
			if err == nil {
				t.Fatalf("依赖故障必须返回错误（业务默认拒绝），实际允许=%v", decision.Allow)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("应返回 ErrUnavailable，实际 %v", err)
			}
			if CodeOf(err) != CodeAuthzUnavailable {
				t.Fatalf("错误码应为 AUTHZ_UNAVAILABLE，实际 %q", CodeOf(err))
			}
		})
	}
	// 服务主体策略故障同样 fail-closed。
	env := newEnv(t)
	env.verifier.claims = serviceClaims(testClient, testAudience)
	env.policy.err = errors.New("policy down")
	if _, err := env.service.Decide(context.Background(), resource(t), request()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("服务主体策略故障应返回 ErrUnavailable，实际 %v", err)
	}
}

// TestNoPermissionCache 验证权限撤销后下一次判定立即生效（无缓存失效窗口）。
func TestNoPermissionCache(t *testing.T) {
	env := newEnv(t)
	first, err := env.service.Decide(context.Background(), resource(t), request())
	if err != nil || !first.Allow {
		t.Fatalf("初始应允许: %+v err=%v", first, err)
	}
	// 模拟权限被撤销（删除角色组合/停用权限后，下一次判定必须立即反映）。
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodePermissionRequired})
	second, err := env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("撤销后判定失败: %v", err)
	}
	assertDenied(t, second, CodePermissionRequired)
	if env.engine.calls != 2 {
		t.Fatalf("每次判定都应实时查询当前权限（无缓存），实际调用 %d 次", env.engine.calls)
	}
}

// TestDenialAuditAndRequestID 验证拒绝审计内容与请求编号生成。
func TestDenialAuditAndRequestID(t *testing.T) {
	env := newEnv(t)
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodeAppMembershipRequired,
		Reason: "membership_required"})
	req := request()
	req.RequestID = ""
	decision, err := env.service.Decide(context.Background(), resource(t), req)
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	assertDenied(t, decision, CodeAppMembershipRequired)
	if !strings.HasPrefix(decision.RequestID, "azreq_") || len(decision.RequestID) != len("azreq_")+32 {
		t.Fatalf("未提供请求编号时应生成稳定格式编号，实际 %q", decision.RequestID)
	}
	if len(env.audit.events) != 1 {
		t.Fatalf("应写 1 条失败审计，实际 %d", len(env.audit.events))
	}
	event := env.audit.events[0]
	if event.Actor.ID != testServiceID || event.Actor.Type != audit.ActorSystem {
		t.Fatalf("审计主体应为可信资源服务，实际 %+v", event.Actor)
	}
	if event.Target.Type != "user" || event.Target.ID != testUser {
		t.Fatalf("审计目标应为用户，实际 %+v", event.Target)
	}
	if event.ErrorCode != string(CodeAppMembershipRequired) || event.ReasonCode != "membership_required" ||
		event.RequestID != decision.RequestID || event.Outcome != audit.OutcomeFailure {
		t.Fatalf("审计事件内容不正确: %+v", event)
	}
}

// TestAuditFailureDoesNotChangeDecision 验证审计写入失败不改变拒绝结论。
func TestAuditFailureDoesNotChangeDecision(t *testing.T) {
	env := newEnv(t)
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodePermissionRequired})
	env.audit.err = errors.New("audit down")
	decision, err := env.service.Decide(context.Background(), resource(t), request())
	if err != nil {
		t.Fatalf("审计失败不应改变拒绝判定: %v", err)
	}
	assertDenied(t, decision, CodePermissionRequired)
}

// TestRequiredScopeIntersection 验证令牌 scope 与业务额外要求取交集（scope 不作为
// 角色权限，但令牌授权范围不足时拒绝）。
func TestRequiredScopeIntersection(t *testing.T) {
	env := newEnv(t)
	req := request()
	req.RequiredScopes = []string{"openid"}
	if _, err := env.service.Decide(context.Background(), resource(t), req); err != nil {
		t.Fatalf("令牌 scope 覆盖所需 scope 时应允许: %v", err)
	}
	req = request()
	req.RequiredScopes = []string{"openid", "invoices.write"}
	decision, err := env.service.Decide(context.Background(), resource(t), req)
	if err != nil {
		t.Fatalf("scope 不足应为业务拒绝: %v", err)
	}
	assertDenied(t, decision, CodeAccessDenied)
	if decision.Reason != "insufficient_scope" {
		t.Fatalf("scope 不足原因码不正确: %q", decision.Reason)
	}
	if len(env.audit.events) != 1 || env.audit.events[0].ReasonCode != "insufficient_scope" {
		t.Fatalf("scope 不足应写失败审计，实际 %+v", env.audit.events)
	}
	// 非法 scope 参数按协议错误拒绝（不进入令牌验证）。
	req = request()
	req.RequiredScopes = []string{"bad scope"}
	if _, err := env.service.Decide(context.Background(), resource(t), req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法所需 scope 应返回 ErrInvalidRequest，实际 %v", err)
	}
}

// TestPermissionEngineCallerIsSubject 验证权限检查使用被判定用户本人身份。
func TestPermissionEngineCallerIsSubject(t *testing.T) {
	env := newEnv(t)
	if _, err := env.service.Decide(context.Background(), resource(t), request()); err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if env.engine.last.SubjectUserID != testUser || env.engine.last.ScopeID != testAppOne {
		t.Fatalf("权限检查应针对令牌主体与资源应用作用范围，实际 %+v", env.engine.last)
	}
}
