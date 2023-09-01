package managecli

// 步骤 186：CLI 确认命令的行为测试（假管理 API 只用于传输契约验证；真实服务端
// 绑定/策略/审计由 internal/serverapp 的集成测试覆盖）。
// 重点：秘密只从 stdin/受保护文件读取、--json 不泄露证明、证明通过受控请求头
// 发送且只发送一次。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const confirmTestProof = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// confirmFakeAPI 是最小管理 API 传输契约替身。
type confirmFakeAPI struct {
	mu             sync.Mutex
	beginCalls     int
	verifyPassword string
	lastHeader     string
	lastPath       string
	lastMethod     string
	verified       bool
	proofDelivered bool
}

func newConfirmFakeAPI(t *testing.T) (*confirmFakeAPI, *httptest.Server) {
	t.Helper()
	api := &confirmFakeAPI{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(request.URL.Path, "/admin/v1")
		switch {
		case path == "/reauth/begin":
			api.beginCalls++
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"data": map[string]any{"confirmation_id": "cfm_0123456789abcdef0123456789abcdef",
					"challenge_id": "chl_0123456789abcdef0123456789abcdef",
					"required":     true, "required_strength": "password",
					"methods":    []string{"password"},
					"expires_at": time.Now().Add(3 * time.Minute).UTC().Format(time.RFC3339)}})
		case path == "/reauth/verify":
			var body struct {
				Password string `json:"password"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			api.verifyPassword = body.Password
			api.verified = true
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"data": map[string]any{"confirmation_id": "cfm_0123456789abcdef0123456789abcdef",
					"confirmation_token": confirmTestProof,
					"expires_at":         time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
					"method":             "password"}})
		case path == "/reauth/cancel":
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"data": map[string]any{"cancelled": true, "state": "cancelled"}})
		case path == "/reauth/status":
			payload := map[string]any{"confirmation_id": "cfm_0123456789abcdef0123456789abcdef",
				"state": "verified"}
			if !api.proofDelivered {
				api.proofDelivered = true
				payload["confirmation_token"] = confirmTestProof
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "data": payload})
		default:
			api.lastHeader = request.Header.Get("X-Login-Confirmation")
			api.lastPath = request.URL.Path
			api.lastMethod = request.Method
			if api.lastHeader != confirmTestProof {
				writer.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false,
					"code": "TOKEN_INVALID", "message": "缺少确认证明"})
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true,
				"data": map[string]any{"changed": true}})
		}
	}))
	t.Cleanup(server.Close)
	return api, server
}

// confirmTestArgs 返回公共在线参数。
func confirmTestArgs(server *httptest.Server, sessionFile string) []string {
	return []string{"--server", server.URL, "--session-file", sessionFile}
}

// TestConfirmBeginVerifyAndExecute 覆盖 begin→verify→带证明执行的主链与脱敏输出。
func TestConfirmBeginVerifyAndExecute(t *testing.T) {
	api, server := newConfirmFakeAPI(t)
	sessionFile := writeProtectedSecretFile(t, "confirm-session.secret", "session-secret")
	approvalFile := filepath.Join(t.TempDir(), "approval.secret")

	beginArgs := append([]string{"confirm", "begin", "--operation", "password.change",
		"--method", "PUT", "--path", "/users/me/password",
		"--body", `{"new_password":"N3w!Passw0rd#2026"}`}, confirmTestArgs(server, sessionFile)...)
	var beginStdout, beginStderr strings.Builder
	exit := RunWithOptions(beginArgs, strings.NewReader(""), &beginStdout, &beginStderr, Options{})
	if exit != ExitOK {
		t.Fatalf("confirm begin 退出码=%d stderr=%s", exit, beginStderr.String())
	}
	if !strings.Contains(beginStdout.String(), "cfm_0123456789abcdef0123456789abcdef") {
		t.Fatalf("begin 未输出确认编号: %s", beginStdout.String())
	}

	verifyArgs := append([]string{"confirm", "verify",
		"--confirmation-id", "cfm_0123456789abcdef0123456789abcdef",
		"--approval-out", approvalFile, "--json"}, confirmTestArgs(server, sessionFile)...)
	var verifyStdout, verifyStderr strings.Builder
	// 密码从 stdin 读取；命令行/JSON 输出都不应出现它。
	exit = RunWithOptions(verifyArgs, strings.NewReader("correct horse battery\n"),
		&verifyStdout, &verifyStderr, Options{})
	if exit != ExitOK {
		t.Fatalf("confirm verify 退出码=%d stderr=%s", exit, verifyStderr.String())
	}
	if api.verifyPassword != "correct horse battery" {
		t.Fatalf("服务端收到的密码不正确（不应把密码写进 argv）")
	}
	if strings.Contains(verifyStdout.String(), "correct horse battery") {
		t.Fatal("--json 输出泄露了密码")
	}
	if strings.Contains(verifyStdout.String(), confirmTestProof) {
		t.Fatal("--json 输出泄露了一次性确认证明")
	}
	if strings.Contains(verifyStderr.String(), confirmTestProof) {
		t.Fatal("stderr 泄露了一次性确认证明")
	}
	raw, err := os.ReadFile(approvalFile)
	if err != nil {
		t.Fatalf("读取证明文件失败: %v", err)
	}
	if strings.TrimSpace(string(raw)) != confirmTestProof {
		t.Fatal("证明文件内容不是一次性确认证明")
	}
	// 已存在的证明文件不能被覆盖（防重放/误覆盖）。
	verifyAgainArgs := append([]string{"confirm", "verify",
		"--confirmation-id", "cfm_0123456789abcdef0123456789abcdef",
		"--approval-out", approvalFile}, confirmTestArgs(server, sessionFile)...)
	var againOut, againErr strings.Builder
	if exit := RunWithOptions(verifyAgainArgs, strings.NewReader("correct horse battery\n"),
		&againOut, &againErr, Options{}); exit == ExitOK {
		t.Fatal("已存在的证明文件不应被覆盖")
	}

	// 带证明的执行：CLI 只从受保护文件读取并注入受控请求头。
	writeArgs := append([]string{"admin", "write", "/users/me/password",
		"--method", "PUT", "--body", `{"new_password":"N3w!Passw0rd#2026"}`,
		"--confirm", "ADMIN-WRITE", "--approval-file", approvalFile},
		confirmTestArgs(server, sessionFile)...)
	var writeStdout, writeStderr strings.Builder
	if exit := RunWithOptions(writeArgs, strings.NewReader(""), &writeStdout, &writeStderr,
		Options{}); exit != ExitOK {
		t.Fatalf("带证明的管理写失败: exit=%d stderr=%s", exit, writeStderr.String())
	}
	if api.lastHeader != confirmTestProof {
		t.Fatalf("管理写未发送 X-Login-Confirmation 头，实际 %q", api.lastHeader)
	}

	// 取消路径：不影响既有证明，只取消新确认。
	cancelArgs := append([]string{"confirm", "cancel",
		"--confirmation-id", "cfm_0123456789abcdef0123456789abcdef"},
		confirmTestArgs(server, sessionFile)...)
	var cancelOut, cancelErr strings.Builder
	if exit := RunWithOptions(cancelArgs, strings.NewReader(""), &cancelOut, &cancelErr,
		Options{}); exit != ExitOK {
		t.Fatalf("confirm cancel 失败: exit=%d stderr=%s", exit, cancelErr.String())
	}
}

// TestConfirmStatusWaitsForWebAuthn 覆盖 WebAuthn 轮询取回一次性证明与脱敏输出。
func TestConfirmStatusWaitsForWebAuthn(t *testing.T) {
	_, server := newConfirmFakeAPI(t)
	sessionFile := writeProtectedSecretFile(t, "confirm-session.secret", "session-secret")
	approvalFile := filepath.Join(t.TempDir(), "webauthn-approval.secret")
	args := append([]string{"confirm", "status",
		"--confirmation-id", "cfm_0123456789abcdef0123456789abcdef",
		"--wait", "10s", "--approval-out", approvalFile, "--json"},
		confirmTestArgs(server, sessionFile)...)
	var stdout, stderr strings.Builder
	if exit := RunWithOptions(args, strings.NewReader(""), &stdout, &stderr,
		Options{}); exit != ExitOK {
		t.Fatalf("confirm status 退出码=%d stderr=%s", exit, stderr.String())
	}
	if strings.Contains(stdout.String(), confirmTestProof) {
		t.Fatal("status --json 输出泄露了一次性确认证明")
	}
	raw, err := os.ReadFile(approvalFile)
	if err != nil || strings.TrimSpace(string(raw)) != confirmTestProof {
		t.Fatalf("WebAuthn 证明文件写入异常: err=%v", err)
	}
}
