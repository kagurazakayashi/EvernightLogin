package managecli

// 步骤 259：admin reset-password 在线命令的传输契约测试（假管理 API 只验证 CLI 的
// 两步验证编排、秘密输入方式、证明只提交一次与输出脱敏；真实授权/证明/事务由
// 根包与 internal/serverapp 测试覆盖）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetPasswordFakeAPI 是最小管理 API 传输契约替身。
type resetPasswordFakeAPI struct {
	mu             sync.Mutex
	mfaAttempts    int
	requireMFA     bool
	beginPassword  string
	adminPassword  string
	totp           string
	proofSubmitted string
	committed      bool
}

func newResetPasswordFakeAPI(t *testing.T) (*resetPasswordFakeAPI, *httptest.Server) {
	t.Helper()
	api := &resetPasswordFakeAPI{requireMFA: true}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(request.URL.Path, "/admin/v1")
		encode := func(payload map[string]any) {
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"request_id": "req_reset_test", "data": payload})
		}
		encodeError := func(code string) {
			writer.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false,
				"request_id": "req_reset_test", "code": code, "message": "denied"})
		}
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/password-verification"):
			var body struct {
				NewPassword string `json:"new_password"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.beginPassword = body.NewPassword
			encode(map[string]any{"challenge_id": "chl_pw_1",
				"operation": "user.password.reset.other", "target_user_id": "usr_target",
				"required_strength": "strong", "max_attempts": 5,
				"expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/password-verification/confirm"):
			var body struct {
				Password string `json:"password"`
				TOTPCode string `json:"totp_code"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.mfaAttempts++
			api.adminPassword = body.Password
			if api.requireMFA && api.mfaAttempts == 1 && body.TOTPCode == "" {
				encodeError("MFA_REQUIRED")
				return
			}
			api.totp = body.TOTPCode
			encode(map[string]any{"proof_token": "proof-reset-once",
				"operation": "user.password.reset.other", "target_user_id": "usr_target",
				"granted_strength": "strong"})
		case request.Method == http.MethodPost && path == "/users/usr_target/password":
			var body struct {
				NewPassword string `json:"new_password"`
				Reason      string `json:"reason"`
				ProofToken  string `json:"proof_token"`
				Confirm     bool   `json:"confirm"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.proofSubmitted = body.ProofToken
			if !body.Confirm || body.NewPassword != "N3w!Passw0rd#259" ||
				body.Reason != "用户申请" || body.ProofToken != "proof-reset-once" {
				encodeError("REQ_INVALID")
				return
			}
			api.committed = true
			encode(map[string]any{"user_id": "usr_target", "security_version": 8,
				"must_change": true, "sessions_revoked": 3,
				"old_reset_requests_cancelled": 2, "old_reset_credentials_revoked": 2})
		default:
			http.NotFound(writer, request)
		}
	}))
	return api, server
}

// TestAdminResetPasswordFlow 覆盖一次两步验证（含 MFA 二次提示）+ 新口令两次输入；
// 输出/JSON 不含新口令、管理密码、动态码或证明。
func TestAdminResetPasswordFlow(t *testing.T) {
	api, server := newResetPasswordFakeAPI(t)
	defer server.Close()
	sessionFile := writeProtectedSecretFile(t, "reset-session.secret", "session-secret")
	args := []string{"admin", "reset-password", "usr_target", "--reason", "用户申请",
		"--confirm", "RESET-PASSWORD", "--json",
		"--server", server.URL, "--session-file", sessionFile}
	var stdout, stderr strings.Builder
	// stdin 顺序：新口令、确认新口令、管理密码、动态码。
	exit := RunWithOptions(args, strings.NewReader(
		"N3w!Passw0rd#259\nN3w!Passw0rd#259\nAdminP@ss1\n654321\n"),
		&stdout, &stderr, Options{})
	if exit != ExitOK {
		t.Fatalf("reset-password 退出码 = %d，stderr=%s stdout=%s", exit, stderr.String(), stdout.String())
	}
	if !api.committed || api.beginPassword != "N3w!Passw0rd#259" ||
		api.adminPassword != "AdminP@ss1" || api.totp != "654321" ||
		api.proofSubmitted != "proof-reset-once" {
		t.Fatalf("服务端收到参数异常: %+v", api)
	}
	output := stdout.String() + stderr.String()
	for _, secret := range []string{"N3w!Passw0rd#259", "AdminP@ss1", "654321", "proof-reset-once"} {
		if strings.Contains(output, secret) {
			t.Fatalf("输出泄露秘密 %q: %s", secret, output)
		}
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &envelope); err != nil {
		t.Fatalf("JSON 输出无效: %v (%s)", err, stdout.String())
	}
	data, _ := envelope["data"].(map[string]any)
	if data["must_change"] != true || data["sessions_revoked"] != float64(3) {
		t.Fatalf("JSON data = %+v", data)
	}
}

// TestAdminResetPasswordFileAndGuards 覆盖 --new-password-file、缺 --confirm 与两次输入不一致。
func TestAdminResetPasswordFileAndGuards(t *testing.T) {
	api, server := newResetPasswordFakeAPI(t)
	api.requireMFA = false
	defer server.Close()
	sessionFile := writeProtectedSecretFile(t, "reset-session2.secret", "session-secret")
	passwordFile := writeProtectedSecretFile(t, "reset-newpassword.secret", "N3w!Passw0rd#259")
	args := []string{"admin", "reset-password", "usr_target", "--reason", "用户申请",
		"--confirm", "RESET-PASSWORD", "--new-password-file", passwordFile, "--json",
		"--server", server.URL, "--session-file", sessionFile}
	var stdout, stderr strings.Builder
	exit := RunWithOptions(args, strings.NewReader("AdminP@ss1\n"),
		&stdout, &stderr, Options{})
	if exit != ExitOK || !api.committed {
		t.Fatalf("--new-password-file 退出码 = %d stderr=%s", exit, stderr.String())
	}
	// 缺 --confirm：用法错误（退出码 2），不发起请求。
	missingConfirm := []string{"admin", "reset-password", "usr_target",
		"--reason", "用户申请", "--server", server.URL, "--session-file", sessionFile}
	var out2, err2 strings.Builder
	if exit := RunWithOptions(missingConfirm, strings.NewReader(""), &out2, &err2,
		Options{}); exit != ExitUsage {
		t.Fatalf("缺 --confirm 退出码 = %d，期望 %d", exit, ExitUsage)
	}
	// 两次新口令不一致：用法错误。
	mismatch := []string{"admin", "reset-password", "usr_target", "--reason", "用户申请",
		"--confirm", "RESET-PASSWORD", "--server", server.URL, "--session-file", sessionFile}
	var out3, err3 strings.Builder
	if exit := RunWithOptions(mismatch,
		strings.NewReader("password-one\npassword-two\n"), &out3, &err3,
		Options{}); exit != ExitUsage {
		t.Fatalf("口令不一致退出码 = %d，期望 %d", exit, ExitUsage)
	}
	for _, output := range []string{out2.String(), err2.String(), out3.String(), err3.String()} {
		if strings.Contains(output, "password-one") || strings.Contains(output, "password-two") {
			t.Fatalf("用法错误输出泄露口令: %s", output)
		}
	}
}
