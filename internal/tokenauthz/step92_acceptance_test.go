package tokenauthz_test

// 步骤 92 验收探针：在真实进程内以真实 net/http 端点（httptest.NewServer）验收
// 「令牌 + 当前权限」联合判定，覆盖：
//   - 受信资源服务身份（HTTP 调用者认证，不使用请求体自述身份）；
//   - 真实签名 JWT + 真实 SQLite 权限引擎 + 真实审计；
//   - 当前权限撤销后下一次 HTTP 判定立即拒绝（无缓存窗口）；
//   - 跨应用令牌不能用于其它应用的资源服务；
//   - required_scopes 与令牌 scope 的交集判定；
//   - 类型混用：ID Token 冒充 Access Token；
//   - 在线撤销标记命中后拒绝；
//   - 标准 HTTP 客户端（net/http）与真实 curl CLI 各一条。
//
// 边界：这是测试进程内的真实 Handler，不是部署后的服务；调用者认证器由测试提供
// （生产必须由 mTLS/客户端凭证等可信边界实现），不打开真实端口到外部网络。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	. "github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
)

// step92ResourceAuthenticator 是测试用可信边界：只按传输层 header 映射资源服务身份，
// 与请求体内容无关（请求体里的 app_id/audience 一律不参与身份构造）。
type step92ResourceAuthenticator struct{}

func (step92ResourceAuthenticator) AuthenticateResourceService(_ context.Context,
	request *http.Request) (ResourceService, error) {
	switch strings.TrimSpace(request.Header.Get("X-Step92-Resource")) {
	case "app-one":
		return NewResourceService("step92-billing", testAppOne, testAudience)
	case "app-two":
		return NewResourceService("step92-billing", testAppTwo, testAudience)
	default:
		return ResourceService{}, fmt.Errorf("未知的测试资源服务身份")
	}
}

// step92HTTPEnv 是真实判决服务 + 真实 net/http 端点的验收环境。
type step92HTTPEnv struct {
	env    *integrationEnv
	server *httptest.Server
	client *http.Client
}

func newStep92HTTPEnv(t *testing.T) *step92HTTPEnv {
	t.Helper()
	env := newIntegrationEnv(t)
	handler, err := NewHTTPHandler(HTTPOptions{
		Service: env.combined, Authenticator: step92ResourceAuthenticator{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造真实 HTTP 判定端点失败: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &step92HTTPEnv{env: env, server: server, client: server.Client()}
}

type step92HTTPResponse struct {
	status   int
	decision Decision
	raw      string
}

func (e *step92HTTPEnv) post(t *testing.T, resource, accessToken string,
	permissions, requiredScopes []string) step92HTTPResponse {
	t.Helper()
	payload := map[string]any{"access_token": accessToken}
	if len(permissions) > 0 {
		payload["permissions"] = permissions
	}
	if len(requiredScopes) > 0 {
		payload["required_scopes"] = requiredScopes
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("编码请求体失败: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, e.server.URL+"/api/v1/token-authorization",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("构造 HTTP 请求失败: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Step92-Resource", resource)
	response, err := e.client.Do(request)
	if err != nil {
		t.Fatalf("标准 HTTP 客户端请求失败: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var decision Decision
	_ = json.Unmarshal(raw, &decision)
	return step92HTTPResponse{status: response.StatusCode, decision: decision, raw: string(raw)}
}

// TestStep92HTTPJointAuthorization 覆盖 HTTP 层联合判定的正负路径与权限撤销即时生效。
func TestStep92HTTPJointAuthorization(t *testing.T) {
	env := newStep92HTTPEnv(t)
	tokenOne := env.env.issueUserToken(testAppOne)

	// 1) 真实令牌 + 当前权限 → 允许。
	allowed := env.post(t, "app-one", tokenOne, []string{testPermission}, nil)
	if allowed.status != http.StatusOK || !allowed.decision.Allow ||
		allowed.decision.Subject != testUser || allowed.decision.ClientID != testAppOne ||
		allowed.decision.ApplicationID != testAppOne {
		t.Fatalf("真实令牌应允许: status=%d body=%s", allowed.status, allowed.raw)
	}

	// 2) 跨应用资源服务：应用一令牌不能用于应用二资源。
	cross := env.post(t, "app-two", tokenOne, []string{testPermission}, nil)
	if cross.status != http.StatusOK || cross.decision.Allow {
		t.Fatalf("跨应用令牌应被拒绝: status=%d body=%s", cross.status, cross.raw)
	}
	if cross.decision.Code != CodeAppScopeMismatch && cross.decision.Code != CodePermissionRequired &&
		cross.decision.Code != CodeTokenAudienceMismatch {
		t.Fatalf("跨应用拒绝码不符合预期: %+v", cross.decision)
	}

	// 3) required_scopes 与令牌 scope 的交集：令牌无 scope，要求 profile.read → 拒绝。
	scopeDenied := env.post(t, "app-one", tokenOne, []string{testPermission}, []string{"profile.read"})
	if scopeDenied.decision.Allow || scopeDenied.decision.Code != CodeAccessDenied ||
		scopeDenied.decision.Reason != "insufficient_scope" {
		t.Fatalf("scope 不足应拒绝: %+v", scopeDenied.decision)
	}

	// 4) 当前权限撤销 → 下一次 HTTP 判定立即拒绝（核心验收项）。
	if _, err := env.env.raw.ExecContext(env.env.ctx,
		`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		testRoleAppOne, testPermOne); err != nil {
		t.Fatalf("撤销权限失败: %v", err)
	}
	revoked := env.post(t, "app-one", tokenOne, []string{testPermission}, nil)
	if revoked.status != http.StatusOK || revoked.decision.Allow ||
		revoked.decision.Code != CodePermissionRequired {
		t.Fatalf("权限撤销后应立即拒绝: status=%d body=%s", revoked.status, revoked.raw)
	}

	// 5) 未建立可信调用者身份 → 401（不允许匿名判定）。
	request, _ := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/token-authorization",
		strings.NewReader(`{"access_token":"`+tokenOne+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := env.client.Do(request)
	if err != nil {
		t.Fatalf("匿名请求失败: %v", err)
	}
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), string(CodeClientAuthFailed)) {
		t.Fatalf("匿名判定应 401: status=%d body=%s", response.StatusCode, raw)
	}
}

// TestStep92HTTPTokenTypeConfusion 覆盖令牌类型混用：ID Token 不能当 Access Token 用。
func TestStep92HTTPTokenTypeConfusion(t *testing.T) {
	env := newStep92HTTPEnv(t)
	caller, err := token.SystemCaller("step92-acceptance")
	if err != nil {
		t.Fatalf("构造签发调用者失败: %v", err)
	}
	issued, err := env.env.tokens.IssueIDToken(env.env.ctx, caller, token.IssueIDTokenRequest{
		ClientID: testAppOne, SubjectUserID: testUser, Nonce: "step92-nonce",
		AuthTime: time.Now(), RequestID: "req_step92_id",
	})
	if err != nil {
		t.Fatalf("签发 ID Token 失败: %v", err)
	}
	confused := env.post(t, "app-one", issued.Token.Reveal(), []string{testPermission}, nil)
	if confused.status != http.StatusOK || confused.decision.Allow ||
		confused.decision.Code != CodeTokenInvalid {
		t.Fatalf("ID Token 冒充 Access Token 应 TOKEN_INVALID: status=%d body=%s",
			confused.status, confused.raw)
	}
}

// TestStep92HTTPRevokedToken 覆盖在线撤销标记命中后拒绝（撤销检查为宿主契约替身）。
func TestStep92HTTPRevokedToken(t *testing.T) {
	env := newStep92HTTPEnv(t)
	tokenOne := env.env.issueUserToken(testAppOne)
	env.env.revocation.mu.Lock()
	env.env.revocation.revoked = true
	env.env.revocation.mu.Unlock()
	response := env.post(t, "app-one", tokenOne, []string{testPermission}, nil)
	if response.status != http.StatusOK || response.decision.Allow ||
		response.decision.Code != CodeTokenRevoked {
		t.Fatalf("已撤销令牌应 TOKEN_REVOKED: status=%d body=%s", response.status, response.raw)
	}
}

// TestStep92CurlStandardClient 用本机真实 curl CLI 调用同一 HTTP 端点，验证标准 HTTP
// 客户端互操作；curl 不存在时如实跳过（不伪造通过）。
func TestStep92CurlStandardClient(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("本机无 curl CLI，标准客户端维度记为未测")
	}
	env := newStep92HTTPEnv(t)
	tokenOne := env.env.issueUserToken(testAppOne)
	body := fmt.Sprintf(`{"access_token":%q,"permissions":[%q]}`, tokenOne, testPermission)
	command := exec.CommandContext(env.env.ctx, curl, "-sS", "--max-time", "10",
		"-X", "POST", env.server.URL+"/api/v1/token-authorization",
		"-H", "Content-Type: application/json",
		"-H", "X-Step92-Resource: app-one", "-d", body)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("curl 标准客户端调用失败: %v 输出=%s", err, output)
	}
	var decision Decision
	if err := json.Unmarshal(output, &decision); err != nil {
		t.Fatalf("curl 响应不是合法 JSON: %v 输出=%s", err, output)
	}
	if !decision.Allow || decision.Subject != testUser || decision.ClientID != testAppOne {
		t.Fatalf("curl 调用应在真实服务上允许: %+v", decision)
	}
}
