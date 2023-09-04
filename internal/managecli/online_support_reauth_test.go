package managecli

// 步骤 188 CLI 契约测试：support recovery request/approve/execute 在真实管理 API
// 形态（含 186 confirm 通道）上的 REAUTH 自动重试与参数绑定；证明不输出。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newSupportReauthServer 模拟 adminapi support/recovery 路由 + 186 确认通道。
func newSupportReauthServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	succeed := func(w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_ok",
			"data": map[string]any{"id": "mrr_00000000000000000000000000000001",
				"status": "completed", "sessions_revoked": 2, "factors_reset": false}})
	}
	requireProof := func(w http.ResponseWriter, r *http.Request) bool {
		if strings.TrimSpace(r.Header.Get("X-Login-Confirmation")) != "support-proof" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"code": "REAUTH_REQUIRED", "message": "需要再次验证身份", "request_id": "req_r"})
			return false
		}
		return true
	}
	mux.HandleFunc("/admin/v1/support/recovery/requests/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_detail",
				"data": map[string]any{"id": "mrr_00000000000000000000000000000001",
					"target_user_id": "usr_00000000000000000000000000000002",
					"operation":      "password_reset", "content_digest": "abc123",
					"approval_id": "mra_00000000000000000000000000000001"}})
			return
		}
		if !requireProof(w, r) {
			return
		}
		succeed(w)
	})
	mux.HandleFunc("/admin/v1/reauth/begin", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		params, _ := body["params"].(map[string]any)
		allowed := body["operation_id"] == "support.recovery.request" ||
			body["operation_id"] == "support.recovery.approve" ||
			body["operation_id"] == "support.recovery.execute"
		if !allowed || body["method"] != "POST" || body["body"] == "" || params == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false,
				"code": "REQ_INVALID", "message": "绑定参数不符", "request_id": "req_b"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_begin",
			"data": map[string]any{"confirmation_id": "cfm_support_1", "required": true,
				"required_strength": "strong", "methods": []string{"password"},
				"expires_at": "2026-11-23T00:05:00Z"}})
	})
	mux.HandleFunc("/admin/v1/reauth/verify", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["password"] != "correct-password" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"code": "AUTH_FAILED", "message": "认证失败", "request_id": "req_v"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": "req_verify",
			"data": map[string]any{"confirmation_token": "support-proof",
				"method": "password", "expires_at": "2026-11-23T00:05:00Z"}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// TestSupportRecoveryCLIReauth 覆盖 request/approve/execute 的 186 重试。
func TestSupportRecoveryCLIReauth(t *testing.T) {
	fixture := newOnlineFixture(t)
	server := newSupportReauthServer(t)
	fixture.server = server
	common := []string{"--server", server.URL, "--api-path", "/admin/v1",
		"--session-file", fixture.sessionFile}
	requestArgs := append([]string{
		"support", "recovery", "request", "--target", "usr_00000000000000000000000000000002",
		"--operation", "password_reset", "--basis", "notarized_declaration",
		"--reference", "notary-188-001", "--evidence", "线下核验记录",
		"--reason", "用户丢失密码"}, common...)
	stdout, stderr, exit := runCLIWithInput(t, "correct-password\n", requestArgs...)
	if exit != ExitOK {
		t.Fatalf("support recovery request 失败: exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	for _, sub := range [][]string{{"approve"}, {"execute"}} {
		args := append([]string{"support", "recovery", sub[0],
			"mrr_00000000000000000000000000000001"}, common...)
		stdout, stderr, exit = runCLIWithInput(t, "correct-password\n", args...)
		if exit != ExitOK {
			t.Fatalf("support recovery %s 失败: exit=%d stdout=%s stderr=%s", sub[0], exit, stdout, stderr)
		}
	}
	if strings.Contains(stdout+stderr, "support-proof") {
		t.Fatal("输出泄露了一次性确认证明")
	}
}
