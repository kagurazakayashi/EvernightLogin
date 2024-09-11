package managecli

// 步骤 258：admin rename-user 在线命令的传输契约测试（假管理 API 只验证 CLI 的
// 两步验证编排、秘密输入、证明只提交一次与输出脱敏；真实授权/证明/事务由
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

// renameUserFakeAPI 是最小管理 API 传输契约替身。
type renameUserFakeAPI struct {
	mu             sync.Mutex
	mfaAttempts    int
	password       string
	totp           string
	proofToken     string
	proofSubmitted bool
	committed      bool
	rowVersion     float64
}

func newRenameUserFakeAPI(t *testing.T) (*renameUserFakeAPI, *httptest.Server) {
	t.Helper()
	api := &renameUserFakeAPI{rowVersion: 7}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(request.URL.Path, "/admin/v1")
		encode := func(payload map[string]any) {
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"request_id": "req_rename_test", "data": payload})
		}
		encodeError := func(code string) {
			writer.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false,
				"request_id": "req_rename_test", "code": code,
				"message": "denied"})
		}
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/username-verification"):
			encode(map[string]any{"challenge_id": "chl_rename_1",
				"operation": "user.username.change.other", "target_user_id": "usr_target",
				"required_strength": "strong", "max_attempts": 5,
				"expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/username-verification/confirm"):
			var body struct {
				ChallengeID string `json:"challenge_id"`
				Password    string `json:"password"`
				TOTPCode    string `json:"totp_code"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.password = body.Password
			api.mfaAttempts++
			if api.mfaAttempts == 1 && body.TOTPCode == "" {
				encodeError("MFA_REQUIRED")
				return
			}
			api.totp = body.TOTPCode
			encode(map[string]any{"proof_token": "proof-once-258",
				"operation": "user.username.change.other", "target_user_id": "usr_target",
				"granted_strength": "strong",
				"expires_at":       time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
		case request.Method == http.MethodGet && path == "/users/usr_target":
			encode(map[string]any{"user": map[string]any{"id": "usr_target",
				"username": "old-name", "row_version": api.rowVersion}})
		case request.Method == http.MethodPost && path == "/users/usr_target/username":
			var body struct {
				NewUsername        string `json:"new_username"`
				ExpectedRowVersion int64  `json:"expected_row_version"`
				Reason             string `json:"reason"`
				ProofToken         string `json:"proof_token"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.proofToken = body.ProofToken
			api.proofSubmitted = true
			if body.ExpectedRowVersion != 7 || body.NewUsername != "new-name" ||
				body.Reason != "用户申请" || body.ProofToken != "proof-once-258" {
				encodeError("REQ_INVALID")
				return
			}
			api.committed = true
			encode(map[string]any{"user": map[string]any{"id": "usr_target",
				"username": "new-name", "row_version": 8}})
		default:
			http.NotFound(writer, request)
		}
	}))
	return api, server
}

// TestAdminRenameUserFlow 覆盖一次两步验证（含 MFA_REQUIRED 二次提示）→ 自动读取
// 行版本 → 提交一次；密码/TOTP/证明不出现在输出与 JSON 中。
func TestAdminRenameUserFlow(t *testing.T) {
	api, server := newRenameUserFakeAPI(t)
	defer server.Close()
	sessionFile := writeProtectedSecretFile(t, "rename-session.secret", "session-secret")
	baseArgs := []string{"--server", server.URL, "--session-file", sessionFile, "--json"}
	args := append([]string{"admin", "rename-user", "usr_target",
		"--new-username", "new-name", "--reason", "用户申请",
		"--confirm", "RENAME-USER"}, baseArgs...)
	var stdout, stderr strings.Builder
	exit := RunWithOptions(args, strings.NewReader("secret-password\n654321\n"),
		&stdout, &stderr, Options{})
	if exit != ExitOK {
		t.Fatalf("rename-user 退出码 = %d，stderr=%s stdout=%s", exit, stderr.String(), stdout.String())
	}
	if !api.committed || api.proofToken != "proof-once-258" || api.totp != "654321" ||
		api.password != "secret-password" {
		t.Fatalf("服务端收到参数异常: %+v", api)
	}
	output := stdout.String() + stderr.String()
	for _, secret := range []string{"secret-password", "654321", "proof-once-258"} {
		if strings.Contains(output, secret) {
			t.Fatalf("输出泄露秘密 %q: %s", secret, output)
		}
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &envelope); err != nil {
		t.Fatalf("JSON 输出无效: %v (%s)", err, stdout.String())
	}
	data, _ := envelope["data"].(map[string]any)
	user, _ := data["user"].(map[string]any)
	if user["username"] != "new-name" || user["id"] != "usr_target" {
		t.Fatalf("JSON data = %+v", data)
	}
}

// TestAdminRenameUserProofFile 覆盖外部已取得的证明文件：跳过交互验证，令牌只用于
// 一次提交。
func TestAdminRenameUserProofFile(t *testing.T) {
	api, server := newRenameUserFakeAPI(t)
	defer server.Close()
	sessionFile := writeProtectedSecretFile(t, "rename-session2.secret", "session-secret")
	proofFile := writeProtectedSecretFile(t, "rename-proof.secret", "proof-once-258")
	args := []string{"admin", "rename-user", "usr_target", "--new-username", "new-name",
		"--reason", "用户申请", "--confirm", "RENAME-USER", "--expected-row-version", "7",
		"--proof-file", proofFile, "--json",
		"--server", server.URL, "--session-file", sessionFile}
	var stdout, stderr strings.Builder
	exit := RunWithOptions(args, strings.NewReader(""), &stdout, &stderr, Options{})
	if exit != ExitOK {
		t.Fatalf("rename-user --proof-file 退出码 = %d，stderr=%s", exit, stderr.String())
	}
	if api.mfaAttempts != 0 {
		t.Fatalf("使用证明文件时不应再交互验证: %d", api.mfaAttempts)
	}
	if !api.committed || api.proofSubmitted == false {
		t.Fatal("未提交改名")
	}
}

// TestAdminRenameUserMissingArgs 覆盖必需参数与拒绝路径的退出码。
func TestAdminRenameUserMissingArgs(t *testing.T) {
	for _, args := range [][]string{
		{"admin", "rename-user", "usr_target", "--reason", "r", "--new-username", "n"},
		{"admin", "rename-user", "--new-username", "n", "--reason", "r"},
	} {
		var stdout, stderr strings.Builder
		if exit := RunWithOptions(args, strings.NewReader(""), &stdout, &stderr, Options{}); exit == ExitOK {
			t.Fatalf("缺少参数应失败: %v", args)
		}
	}
}
