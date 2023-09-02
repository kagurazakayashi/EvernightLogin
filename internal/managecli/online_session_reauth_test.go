package managecli

// 步骤 187 CLI 契约测试：session admin-list 与 admin-revoke 的再次认证重试。
// 用受控 HTTP 服务精确模拟 186 契约（/reauth/begin|verify + X-Login-Confirmation），
// 验证 187 CLI 只调用真实管理 API、证明只在内存中使用、不进入输出。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// runCLIWithInput 使用指定 stdin 调用 CLI（用于需要交互输入再次认证密码的用例）。
func runCLIWithInput(t *testing.T, input string, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := RunWithOptions(args, strings.NewReader(input), &stdout, &stderr,
		Options{Now: func() time.Time { return testNow },
			LookupEnv: func(string) (string, bool) { return "", false }})
	return stdout.String(), stderr.String(), exit
}

// newSessionReauthTestServer 构造模拟 186 通道与 187 撤销路由的受控服务。
func newSessionReauthTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	revoked := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_list",
				"data": map[string]any{
					"target_user_id": r.URL.Query().Get("target_user_id"),
					"scope_app_id":   "system", "page": 1, "page_size": 20, "total": 1,
					"sessions": []any{map[string]any{
						"id": "ses_00000000000000000000000000000001", "kind": "normal",
						"created_at": "2026-11-23T00:00:00Z", "last_seen_at": "2026-11-23T00:00:00Z",
					}},
				}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_hit"})
	})
	mux.HandleFunc("/admin/v1/sessions/revoke", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get("X-Login-Confirmation"))
		if token == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"code": "REAUTH_REQUIRED", "message": "需要再次验证身份", "request_id": "req_1"})
			return
		}
		if token != "auto-proof-token" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"code": "TOKEN_INVALID", "message": "确认证明无效", "request_id": "req_2"})
			return
		}
		revoked++
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_3",
			"data": map[string]any{"revoked": 1, "scope_app_id": "system", "request_id": "req_3"}})
	})
	mux.HandleFunc("/admin/v1/reauth/begin", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		params, _ := body["params"].(map[string]any)
		if body["operation_id"] != "session.revoke.other" ||
			body["method"] != "POST" || body["path"] != "/sessions/revoke" ||
			params["target_user_id"] == nil || body["body"] == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false,
				"code": "REQ_INVALID", "message": "绑定参数不符", "request_id": "req_4"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_5",
			"data": map[string]any{"confirmation_id": "cfm_00000000000000000000000000000001",
				"challenge_id": "chg_00000000000000000000000000000001", "required": true,
				"required_strength": "strong", "methods": []string{"password"},
				"expires_at": "2026-11-23T00:05:00Z"}})
	})
	mux.HandleFunc("/admin/v1/reauth/verify", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body["password"] != "correct-password" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"code": "AUTH_FAILED", "message": "认证失败", "request_id": "req_6"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_7",
			"data": map[string]any{"confirmation_token": "auto-proof-token",
				"method": "password", "expires_at": "2026-11-23T00:05:00Z"}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// writeJSON 输出裸管理 API envelope（测试替身，不是生产编码器）。
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// TestSessionAdminListCLI 验证 admin-list 查询参数与脱敏输出。
func TestSessionAdminListCLI(t *testing.T) {
	fixture := newOnlineFixture(t)
	server := newSessionReauthTestServer(t)
	fixture.server = server
	stdout, stderr, exit := fixture.runWithSession(fixture.sessionFile,
		"session", "admin-list", "--user", "usr_00000000000000000000000000000002", "--json")
	if exit != ExitOK {
		t.Fatalf("admin-list 失败: exit=%d stderr=%s", exit, stderr)
	}
	envelope := decodeEnvelope(t, stdout)
	data, _ := envelope["data"].(map[string]any)
	if data["target_user_id"] != "usr_00000000000000000000000000000002" {
		t.Fatalf("admin-list 目标不符: %v", data)
	}
	fixture.requireNoSecretLeak(stdout, stderr)
}

// TestSessionAdminRevokeCLIReauthRetry 验证 REAUTH_REQUIRED 后按 186 契约自动完成
// 一次性再次认证并重试同一撤销请求；证明不进入 stdout/stderr。
func TestSessionAdminRevokeCLIReauthRetry(t *testing.T) {
	fixture := newOnlineFixture(t)
	server := newSessionReauthTestServer(t)
	fixture.server = server
	stdout, stderr, exit := runCLIWithInput(t, "correct-password\n",
		"session", "admin-revoke", "--user", "usr_00000000000000000000000000000002",
		"--reason", "security incident response", "--confirm", "ADMIN-REVOKE",
		"--server", server.URL, "--api-path", "/admin/v1",
		"--session-file", fixture.sessionFile)
	if exit != ExitOK {
		t.Fatalf("再次认证重试应成功: exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	if !strings.Contains(stdout, "已撤销会话数=1") || !strings.Contains(stdout, "一次性再次认证") {
		t.Fatalf("输出不符: %s", stdout)
	}
	if strings.Contains(stdout+stderr, "auto-proof-token") {
		t.Fatal("输出泄露了一次性确认证明")
	}
	fixture.requireNoSecretLeak(stdout, stderr)
}

// TestSessionAdminRevokeCLIApprovalFile 验证显式 --approval-file 路径：证明只从
// 受保护文件读取并作为请求头使用，输出不含证明。
func TestSessionAdminRevokeCLIApprovalFile(t *testing.T) {
	fixture := newOnlineFixture(t)
	server := newSessionReauthTestServer(t)
	fixture.server = server
	proofFile := writeProtectedSecretFile(t, "admin-revoke-proof.secret", "auto-proof-token")
	stdout, stderr, exit := runCLIWithInput(t, "",
		"session", "admin-revoke", "--user", "usr_00000000000000000000000000000002",
		"--reason", "security incident response", "--confirm", "ADMIN-REVOKE",
		"--approval-file", proofFile,
		"--server", server.URL, "--api-path", "/admin/v1",
		"--session-file", fixture.sessionFile)
	if exit != ExitOK || !strings.Contains(stdout, "已撤销会话数=1") {
		t.Fatalf("显式证明应成功: exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, "auto-proof-token") {
		t.Fatal("输出泄露了一次性确认证明")
	}
}
