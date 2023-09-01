package serverapp

// 步骤 186：CLI 一次性再认证/确认通道集成测试。
//
// 使用真实 SQLite、真实 internal/reauth + policy + session 服务与真实 HTTP handler；
// 下游“敏感操作”处理器执行真实 reauth.Authorize（不绕过策略/审批），以验证证明
// 注入链路、一次性消费、会话/请求绑定与取消语义。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// cliSensitiveProbe 是下游“现有敏感操作”的最小真实执行器：用真实
// gate.Reauth.Authorize 复核操作/目标/参数（不跳过策略与一次性批准）。
type cliSensitiveProbe struct {
	gate                   *SecurityGate
	userID                 string
	scopeID                string
	operation              string
	targetType             string
	targetID               string
	params                 map[string]string
	lastSignals            reauth.Signals
	lastConfirmationHeader string
	called                 int
}

func (p *cliSensitiveProbe) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	p.called++
	p.lastSignals = reauth.SignalsFromContext(request.Context())
	p.lastConfirmationHeader = request.Header.Get(cliConfirmationHeader)
	caller, _ := reauth.UserCaller(p.userID)
	requestID := request.Header.Get("X-Request-ID")
	if account.ValidateRequestID(requestID) != nil {
		requestID = login.NewRequestID()
	}
	caller, _ = caller.WithRequestID(requestID)
	params := p.params
	if params == nil {
		params = map[string]string{}
	}
	_, err := p.gate.Reauth.Authorize(request.Context(), caller, reauth.Request{
		ScopeID: p.scopeID, OperationID: p.operation, TargetType: p.targetType,
		TargetID: p.targetID, Params: params, RequestID: requestID})
	writer.Header().Set("Content-Type", "application/json")
	if err != nil {
		writer.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false,
			"code": string(reauth.CodeOf(err))})
		return
	}
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true})
}

// cliReauthTestEnv 是测试环境。
type cliReauthTestEnv struct {
	ctx              context.Context
	handler          http.Handler
	probe            *cliSensitiveProbe
	managementSecret string
	normalSecret     string
	restrictedSecret string
	userID           string
	sessions         *session.Service
	clockNow         time.Time
	advance          func(time.Duration)
}

// newCLIReauthTestEnv 构造真实装配的测试环境。
func newCLIReauthTestEnv(t *testing.T) *cliReauthTestEnv {
	t.Helper()
	ctx := context.Background()
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	cfg := login.Default()
	cfg.Database.Path = "unused.db"
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	clockNow := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	clock := &clockNow
	deps := Deps{Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder,
		Logger: testLogger(), Now: func() time.Time { return *clock }}
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
	if _, err := BuildManagedServices(deps, services, tasks, gate); err != nil {
		t.Fatalf("BuildManagedServices: %v", err)
	}
	registered, err := services.Registration.Register(ctx, registration.RegisterRequest{
		Username: "cli-alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "CLI Alice",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	management, err := services.Sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: registered.UserID, Username: "cli-alice",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
			CompletedAt:      clockNow, StrongAuthCompletedAt: clockNow, SecurityVersion: 1},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发管理会话: %v", err)
	}
	normal, err := services.Sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: registered.UserID, Username: "cli-alice",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      clockNow, SecurityVersion: 1},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发普通会话: %v", err)
	}
	restricted, err := services.Sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: registered.UserID, Username: "cli-alice",
			Outcome:          authn.OutcomePendingSecondFactor,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      clockNow, SecurityVersion: 1, Restricted: true,
			RequiredSteps: []authn.Step{authn.StepSecondFactor}},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发受限会话: %v", err)
	}
	probe := &cliSensitiveProbe{gate: gate, userID: registered.UserID, scopeID: "system",
		operation: "password.change", targetType: "user", targetID: registered.UserID,
		params: map[string]string{"user_id": registered.UserID}}
	handler, err := newCLIReauthHandler(deps, services, gate, nil, "/admin/v1")
	if err != nil {
		t.Fatalf("newCLIReauthHandler: %v", err)
	}
	return &cliReauthTestEnv{ctx: ctx, handler: handler.wrap(probe), probe: probe,
		managementSecret: management.Secret.Reveal(), normalSecret: normal.Secret.Reveal(),
		restrictedSecret: restricted.Secret.Reveal(),
		userID:           registered.UserID, sessions: services.Sessions, clockNow: clockNow,
		advance: func(delta time.Duration) { *clock = clock.Add(delta) }}
}

// cliResponse 是被测 HTTP 响应。
type cliResponse struct {
	status int
	data   map[string]any
	code   string
	body   string
}

// cliCall 发起一次管理 API 形态的请求。
func (e *cliReauthTestEnv) call(t *testing.T, method, path string, body any,
	secret, confirmation string) cliResponse {
	t.Helper()
	var payload string
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("请求体序列化: %v", err)
		}
		payload = string(encoded)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", login.NewRequestID())
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	if confirmation != "" {
		request.Header.Set(cliConfirmationHeader, confirmation)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	result := recorder.Result()
	defer result.Body.Close()
	response := cliResponse{status: result.StatusCode, body: recorder.Body.String()}
	var envelope map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err == nil {
		if raw, ok := envelope["data"].(map[string]any); ok {
			response.data = raw
		}
		if code, ok := envelope["code"].(string); ok {
			response.code = code
		}
	}
	return response
}

// begin 创建绑定确认（默认绑定 password.change 与 /users/me/password）。
func (e *cliReauthTestEnv) begin(t *testing.T, secret string,
	body string) cliResponse {
	t.Helper()
	return e.call(t, http.MethodPost, "/admin/v1/reauth/begin", map[string]any{
		"scope_id": "system", "operation_id": e.probe.operation,
		"target_type": e.probe.targetType, "target_id": e.probe.targetID,
		"params": e.probe.params, "method": http.MethodPut,
		"path": "/users/me/password", "body": body}, secret, "")
}

// verify 用密码完成真实再次认证并返回一次性确认证明。
func (e *cliReauthTestEnv) verify(t *testing.T, secret, confirmationID string) (string, cliResponse) {
	t.Helper()
	response := e.call(t, http.MethodPost, "/admin/v1/reauth/verify", map[string]any{
		"confirmation_id": confirmationID, "password": "K8$wR3!nB6@yF1#v"},
		secret, "")
	token, _ := response.data["confirmation_token"].(string)
	return token, response
}

const cliProbeBody = `{"new_password":"N3w!Passw0rd#2026"}`

// TestCLIReauthConfirmationBinding 覆盖正常证明执行与一次性/请求/会话绑定。
func TestCLIReauthConfirmationBinding(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	begin := env.begin(t, env.managementSecret, cliProbeBody)
	if begin.status != http.StatusOK {
		t.Fatalf("begin 状态 = %d body=%s", begin.status, begin.body)
	}
	confirmationID, _ := begin.data["confirmation_id"].(string)
	if confirmationID == "" {
		t.Fatalf("begin 未返回确认编号: %s", begin.body)
	}
	token, verify := env.verify(t, env.managementSecret, confirmationID)
	if verify.status != http.StatusOK || token == "" {
		t.Fatalf("verify 失败: status=%d body=%s", verify.status, verify.body)
	}
	// 正确执行：一次成功并注入一次性批准令牌。
	execute := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, env.managementSecret, token)
	if execute.status != http.StatusOK {
		t.Fatalf("执行敏感操作失败: status=%d body=%s", execute.status, execute.body)
	}
	if env.probe.lastSignals.ApprovalToken == "" {
		t.Fatal("下游未收到一次性批准令牌信号")
	}
	if env.probe.lastConfirmationHeader != "" {
		t.Fatal("下游仍能看到已消费的 X-Login-Confirmation 头（防御纵深失败）")
	}
	// 重复消费同一证明：拒绝且不执行。
	again := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, env.managementSecret, token)
	if again.status != http.StatusForbidden || again.code != "TOKEN_INVALID" {
		t.Fatalf("重复使用证明应 403 TOKEN_INVALID，实际 %d/%s", again.status, again.code)
	}
	// 不同请求体：证明不匹配，拒绝；且不消费证明（随后正确请求仍可用）。
	secondBegin := env.begin(t, env.managementSecret, cliProbeBody)
	secondID, _ := secondBegin.data["confirmation_id"].(string)
	secondToken, secondVerify := env.verify(t, env.managementSecret, secondID)
	if secondVerify.status != http.StatusOK {
		t.Fatalf("第二次 verify 失败: %d/%s", secondVerify.status, secondVerify.body)
	}
	mismatch := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "other-password#2026"}, env.managementSecret, secondToken)
	if mismatch.status != http.StatusForbidden || mismatch.code != "TOKEN_INVALID" {
		t.Fatalf("不同请求体应 403 TOKEN_INVALID，实际 %d/%s", mismatch.status, mismatch.code)
	}
	correct := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, env.managementSecret, secondToken)
	if correct.status != http.StatusOK {
		t.Fatalf("不匹配不应消费证明；正确请求应成功，实际 %d/%s", correct.status, correct.body)
	}
	// 不同会话：证明与签发它的管理会话绑定。
	thirdBegin := env.begin(t, env.managementSecret, cliProbeBody)
	thirdID, _ := thirdBegin.data["confirmation_id"].(string)
	thirdToken, thirdVerify := env.verify(t, env.managementSecret, thirdID)
	if thirdVerify.status != http.StatusOK {
		t.Fatalf("第三次 verify 失败: %d/%s", thirdVerify.status, thirdVerify.body)
	}
	otherSession, err := newSecondManagementSession(t, env)
	if err != nil {
		t.Fatalf("签发第二个管理会话: %v", err)
	}
	crossSession := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, otherSession, thirdToken)
	if crossSession.status != http.StatusForbidden || crossSession.code != "TOKEN_INVALID" {
		t.Fatalf("跨会话使用证明应 403 TOKEN_INVALID，实际 %d/%s",
			crossSession.status, crossSession.code)
	}
}

// newSecondManagementSession 用同一真实会话服务签发另一个管理会话（同主体），
// 用于验证证明不能跨会话复用。
func newSecondManagementSession(t *testing.T, env *cliReauthTestEnv) (string, error) {
	t.Helper()
	issued, err := env.sessions.Login(env.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: env.userID, Username: "cli-alice",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
			CompletedAt:      env.clockNow, StrongAuthCompletedAt: env.clockNow, SecurityVersion: 1},
		RequestID: login.NewRequestID()})
	if err != nil {
		return "", err
	}
	return issued.Secret.Reveal(), nil
}

// TestCLIReauthRestrictedSessionCannotBegin 验证受限会话不能冒充管理会话。
func TestCLIReauthRestrictedSessionCannotBegin(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	response := env.begin(t, env.restrictedSecret, cliProbeBody)
	if response.status != http.StatusForbidden {
		t.Fatalf("受限会话 begin 应 403，实际 %d/%s", response.status, response.code)
	}
	if env.probe.called != 0 {
		t.Fatal("受限会话不应触发下游敏感操作")
	}
}

// TestCLIReauthNormalSessionCannotBegin 验证普通会话不能冒充管理会话。
func TestCLIReauthNormalSessionCannotBegin(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	response := env.begin(t, env.normalSecret, cliProbeBody)
	if response.status != http.StatusForbidden || response.code != "REAUTH_REQUIRED" {
		t.Fatalf("普通会话 begin 应 403 REAUTH_REQUIRED，实际 %d/%s",
			response.status, response.code)
	}
	if env.probe.called != 0 {
		t.Fatal("普通会话不应触发下游敏感操作")
	}
}

// TestCLIReauthCancelDoesNotExecute 验证取消后验证失败且下游不执行。
func TestCLIReauthCancelDoesNotExecute(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	begin := env.begin(t, env.managementSecret, cliProbeBody)
	confirmationID, _ := begin.data["confirmation_id"].(string)
	cancel := env.call(t, http.MethodPost, "/admin/v1/reauth/cancel",
		map[string]any{"confirmation_id": confirmationID}, env.managementSecret, "")
	if cancel.status != http.StatusOK {
		t.Fatalf("取消失败: %d/%s", cancel.status, cancel.body)
	}
	_, verify := env.verify(t, env.managementSecret, confirmationID)
	if verify.code != "CHALLENGE_INVALID" {
		t.Fatalf("取消后 verify 应 CHALLENGE_INVALID，实际 %d/%s", verify.status, verify.code)
	}
	if env.probe.called != 0 {
		t.Fatal("取消后不应执行任何敏感操作")
	}
}

// TestCLIReauthExpiryRejected 验证证明过期后不可用。
func TestCLIReauthExpiryRejected(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	begin := env.begin(t, env.managementSecret, cliProbeBody)
	confirmationID, _ := begin.data["confirmation_id"].(string)
	token, verify := env.verify(t, env.managementSecret, confirmationID)
	if verify.status != http.StatusOK {
		t.Fatalf("verify 失败: %d/%s", verify.status, verify.body)
	}
	env.advance(6 * time.Minute)
	expired := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, env.managementSecret, token)
	if expired.status != http.StatusForbidden || expired.code != "TOKEN_INVALID" {
		t.Fatalf("过期证明应 403 TOKEN_INVALID，实际 %d/%s", expired.status, expired.code)
	}
}

// TestCLIReauthTargetBindingRejected 验证下游操作目标/参数与确认不一致时被拒绝。
func TestCLIReauthTargetBindingRejected(t *testing.T) {
	env := newCLIReauthTestEnv(t)
	begin := env.begin(t, env.managementSecret, cliProbeBody)
	confirmationID, _ := begin.data["confirmation_id"].(string)
	token, verify := env.verify(t, env.managementSecret, confirmationID)
	if verify.status != http.StatusOK {
		t.Fatalf("verify 失败: %d/%s", verify.status, verify.body)
	}
	// 下游切换为不同的稳定目标：一次性批准的目标/参数摘要不匹配，必须拒绝。
	env.probe.targetID = "usr_other_target_0000000000000000"
	response := env.call(t, http.MethodPut, "/admin/v1/users/me/password",
		map[string]any{"new_password": "N3w!Passw0rd#2026"}, env.managementSecret, token)
	if response.status != http.StatusForbidden {
		t.Fatalf("目标不一致应被下游拒绝，实际 %d/%s", response.status, response.body)
	}
}
