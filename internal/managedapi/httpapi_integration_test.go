package managedapi_test

// 步骤 147 真实集成测试：真实临时 SQLite + 真实 account/app/role/group/permission/
// session/oauthclient/audit + 真实 managedapi.Service，经 httpapi.Handler 和外部
// stdlib HTTP 客户端完成应用范围读取、A/B 隔离、字段拒绝、撤权即拒与幂等 replay。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	. "github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

func newHTTPAPITestServer(t *testing.T, env *testEnv) (*httptest.Server,
	*session.IssuedSession) {
	t.Helper()
	idempotency, err := httpapi.NewSQLIdempotencyStore(env.raw)
	if err != nil {
		t.Fatalf("构造幂等存储: %v", err)
	}
	handler, err := httpapi.New(httpapi.Options{
		Service: env.service, Sessions: env.sessions, Idempotency: idempotency,
		Now: func() time.Time { return testStart },
	})
	if err != nil {
		t.Fatalf("构造 HTTP handler: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	issued := env.userSession(testAdmin, testAppOne)
	return server, &issued
}

func apiRequest(t *testing.T, method, target, secret string, body []byte,
	idempotencyKey string) (int, []byte, http.Header) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("X-Evernight-API-Version", "v1")
	request.Header.Set("X-Request-Id", "req_147_integration")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("请求 %s: %v", target, err)
	}
	defer response.Body.Close()
	payload := make([]byte, 0)
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			payload = append(payload, buffer[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	return response.StatusCode, payload, response.Header
}

func TestManagedAPIHTTPRealServices(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne,
		[]string{"status", "username", "display_name"},
		[]string{"display_name"}))
	server, session := newHTTPAPITestServer(t, env)
	base := server.URL + "/api/managed/v1/applications/" + testAppOne

	status, payload, _ := apiRequest(t, http.MethodGet, base, session.Secret.Reveal(), nil, "")
	if status != http.StatusOK || !bytes.Contains(payload, []byte(`"name"`)) {
		t.Fatalf("应用读取 = %d %s", status, payload)
	}
	var envelope struct {
		RequestID string `json:"request_id"`
		Data      struct {
			Fields map[string]any `json:"fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil ||
		envelope.RequestID != "req_147_integration" || envelope.Data.Fields["name"] == nil {
		t.Fatalf("envelope = %s err=%v", payload, err)
	}

	// 应用 B 作用域会话访问应用 A：传输层拒绝，不泄露 A 数据。
	appTwoSession := env.userSession(testAdmin, testAppTwo)
	status, payload, _ = apiRequest(t, http.MethodGet, base,
		appTwoSession.Secret.Reveal(), nil, "")
	if status != http.StatusForbidden || !bytes.Contains(payload, []byte("APP_SCOPE_MISMATCH")) {
		t.Fatalf("跨应用会话 = %d %s", status, payload)
	}

	// 创建新用户并建立本应用成员关系；幂等 replay 返回同一响应。
	createBody := []byte(`{"username":"http-integration-new"}`)
	status, firstPayload, _ := apiRequest(t, http.MethodPost,
		base+"/users", session.Secret.Reveal(), createBody, "idem-http-create")
	if status != http.StatusOK || !bytes.Contains(firstPayload, []byte("http-integration-new")) {
		t.Fatalf("创建用户 = %d %s", status, firstPayload)
	}
	status, replayPayload, headers := apiRequest(t, http.MethodPost,
		base+"/users", session.Secret.Reveal(), createBody, "idem-http-create")
	if status != http.StatusOK || headers.Get("Idempotent-Replayed") != "true" ||
		!bytes.Equal(firstPayload, replayPayload) {
		t.Fatalf("幂等 replay = %d header=%q", status, headers.Get("Idempotent-Replayed"))
	}
	// 同 key 不同请求内容冲突。
	status, _, _ = apiRequest(t, http.MethodPost, base+"/users",
		session.Secret.Reveal(), []byte(`{"username":"different-new"}`), "idem-http-create")
	if status != http.StatusConflict {
		t.Fatalf("幂等冲突 = %d", status)
	}

	// 系统字段 is_root 被严格 JSON 拒绝，不进入领域服务。
	memberBody := []byte(`{"expected_row_version":1,"display_name":"x","is_root":true}`)
	status, _, _ = apiRequest(t, http.MethodPatch,
		base+"/members/"+testWorker, session.Secret.Reveal(), memberBody, "idem-http-field")
	if status != http.StatusBadRequest {
		t.Fatalf("系统字段拒绝 = %d", status)
	}

	// 撤销策略中的 users.create 后，同一主体下一次请求立即拒绝（不缓存授权）。
	revoked := policyFor(testAppOne, []string{"status", "username", "display_name"},
		[]string{"display_name"})
	revoked.Operations.Allowed = removeString(revoked.Operations.Allowed, OpUsersCreate)
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: "root-admin"}
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: revoked, ExpectedRowVersion: 1,
		RequestID: "req_147_revoke"}); err != nil {
		t.Fatalf("撤销策略失败: %v", err)
	}
	status, payload, _ = apiRequest(t, http.MethodPost, base+"/users",
		session.Secret.Reveal(), []byte(`{"username":"denied-after-revoke"}`),
		"idem-http-revoked")
	if status != http.StatusForbidden || !bytes.Contains(payload, []byte("ACCESS_DENIED")) {
		t.Fatalf("撤权后写 = %d %s", status, payload)
	}
	_ = context.Background()
}

func removeString(values []string, target string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
