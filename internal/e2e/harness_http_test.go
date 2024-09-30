package e2e

// 步骤 274 收尾：HTTP/CLI 入口与文档/游标/资源范围矩阵的公共夹具。
//
// 全部使用真实公开装配：app.Open（含 HTTP 管理 API/页面挂载）+ httptest 服务 +
// 真实管理会话（Bearer 会话秘密），不走内部状态旁路。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// openEnvHTTP 打开装配了真实 HTTP 管理 API 与页面挂载的运行时。
func openEnvHTTP(t *testing.T) *harnessEnv {
	t.Helper()
	clock := newTestClock(time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	// 嵌入式 HTTP 需要合法公开来源（表单 Origin 校验）；回环地址仅测试使用。
	cfg.Server.PublicBaseURL = "http://127.0.0.1:18080"
	dbPath := filepath.Join(dir, "login.db")
	masterKey := filepath.Join(dir, "master.key")
	runtime, err := loginapp.Open(context.Background(), loginapp.Options{
		Config: &cfg, DatabasePath: dbPath, MasterKeyFile: masterKey,
		CreateMasterKey: true, Migrate: true, OperatorID: "step274-e2e-http",
		Logger: slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1})),
		Now:  clock.Now,
		HTTP: &loginapp.HTTPOptions{EnableAdminAPI: true},
	})
	if err != nil {
		t.Fatalf("打开含 HTTP 的测试运行时: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return &harnessEnv{Runtime: runtime, Clock: clock, Dir: dir, DBPath: dbPath,
		MasterKey: masterKey, Config: cfg}
}

// startHTTP 启动真实 httptest 服务并返回服务与关闭函数。
func startHTTP(t *testing.T, runtime *loginapp.Runtime) *httptest.Server {
	t.Helper()
	handler := runtime.Handler()
	if handler == nil {
		t.Fatal("运行时未装配 HTTP 处理器")
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// httpEnvelope 是管理 API 统一响应外壳（测试侧解析）。
type httpEnvelope struct {
	Status    int
	OK        bool           `json:"ok"`
	RequestID string         `json:"request_id"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data"`
	Raw       string
}

// httpCall 发起一次管理 API 请求；bearer 为空表示匿名。返回解析后的外壳与原始响应体。
func httpCall(t *testing.T, server *httptest.Server, method, path, bearer string,
	body any) httpEnvelope {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("编码请求体: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	request.Header.Set("Accept", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	rawBytes, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	envelope := httpEnvelope{Status: response.StatusCode, Raw: string(rawBytes)}
	if len(rawBytes) > 0 {
		_ = json.Unmarshal(rawBytes, &envelope)
	}
	return envelope
}

// requireHTTPData 断言状态 2xx 且有 data。
func requireHTTPData(t *testing.T, envelope httpEnvelope, label string) map[string]any {
	t.Helper()
	if envelope.Status < 200 || envelope.Status >= 300 || !envelope.OK {
		t.Fatalf("%s: HTTP %d ok=%v code=%q raw=%s", label, envelope.Status,
			envelope.OK, envelope.Code, truncate(envelope.Raw))
	}
	return envelope.Data
}

// requireHTTPFailure 断言非 2xx，并返回稳定错误码。
func requireHTTPFailure(t *testing.T, envelope httpEnvelope, label string) string {
	t.Helper()
	if envelope.Status >= 200 && envelope.Status < 300 && envelope.OK {
		t.Fatalf("%s: 期望失败但 HTTP %d ok=true raw=%s", label, envelope.Status,
			truncate(envelope.Raw))
	}
	if envelope.Code == "" {
		t.Fatalf("%s: 失败响应缺少稳定错误码 raw=%s", label, truncate(envelope.Raw))
	}
	return envelope.Code
}

func truncate(value string) string {
	if len(value) <= 400 {
		return value
	}
	return value[:400] + "...(truncated)"
}

// writeProtectedSecret 写入平台受保护的秘密文件（与 CLI 会话/口令文件要求一致）。
func writeProtectedSecret(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("写入受保护秘密文件: %v", err)
	}
	if err := secrets.ProtectFile(path); err != nil {
		t.Fatalf("收紧秘密文件权限: %v", err)
	}
	return path
}

// repoRoot 向上查找 go.mod，返回仓库根目录。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("读取工作目录: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("未找到仓库根目录（go.mod）")
		}
		dir = parent
	}
}

// CLI 二进制构建只做一次，供 CLI 矩阵复用。
var (
	loginctlBuildOnce sync.Once
	loginctlBuildPath string
	loginctlBuildErr  error
)

// buildLoginctl 用当前源码构建自包含 CLI 二进制（真实二进制，非替身）。
func buildLoginctl(t *testing.T) string {
	t.Helper()
	loginctlBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "r11-274-loginctl-*")
		if err != nil {
			loginctlBuildErr = err
			return
		}
		name := "loginctl"
		if strings.EqualFold(os.Getenv("GOOS"), "windows") ||
			strings.Contains(strings.ToLower(runtimeGOOS()), "windows") {
			name += ".exe"
		}
		target := filepath.Join(dir, name)
		command := exec.Command("go", "build", "-trimpath", "-o", target,
			"./cmd/loginctl")
		command.Dir = repoRoot(t)
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			loginctlBuildErr = fmt.Errorf("构建 loginctl 失败: %v：%s", err,
				truncate(string(output)))
			return
		}
		loginctlBuildPath = target
	})
	if loginctlBuildErr != nil {
		t.Fatalf("%v", loginctlBuildErr)
	}
	return loginctlBuildPath
}

// cliResult 是一次 CLI 调用结果。
type cliResult struct {
	Exit   int
	Stdout string
	Stderr string
}

// runCLI 运行自建 CLI 二进制，stdin 作为交互输入（密码/TOTP 或确认行）。
func runCLI(t *testing.T, binary string, args []string, stdin string) cliResult {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Dir = t.TempDir()
	command.Env = os.Environ()
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exit := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exit = exitError.ExitCode()
		} else {
			t.Fatalf("运行 CLI: %v", err)
		}
	}
	return cliResult{Exit: exit, Stdout: stdout.String(), Stderr: stderr.String()}
}

// runtimeGOOS 返回构建目标平台（仅用于加 .exe 后缀）。
func runtimeGOOS() string {
	if value := os.Getenv("GOOS"); value != "" {
		return value
	}
	return "windows"
}

// cliOutputContains 在 stdout+stderr 中查找明文（用于断言不泄露秘密）。
func cliOutputContains(result cliResult, needle string) bool {
	return strings.Contains(result.Stdout+result.Stderr, needle)
}

// issueStrongManagementSession 为指定用户签发一个**真实强认证测试会话**（测试夹具）。
//
// 管理 HTTP API 要求会话携带未过期的强认证时间；本测试套件的操作者只绑定 TOTP，
// 而产品默认不允许“密码+TOTP”满足管理强认证（AllowTOTPForStrongAuth=false），
// 因此按既有 app 测试的做法，用共享装配的 session.Service 为同一临时库签发带
// StrongAuthCompletedAt 的完整会话（等价于已注册 Passkey 的成功登录），仅用于测试
// 夹具；管理 API 的授权/证明/目标校验仍全部真实执行，不绕过。
func issueStrongManagementSession(t *testing.T, env *harnessEnv, userID, username string) []byte {
	t.Helper()
	ctx := context.Background()
	baseConfig, err := appcore.PrepareConfig(env.Config, env.DBPath)
	if err != nil {
		t.Fatalf("准备内部配置: %v", err)
	}
	base, err := serverapp.OpenBase(ctx, serverapp.BaseOptions{
		Config: baseConfig, Build: login.CurrentBuildInfo(),
		MasterKeyFile: env.MasterKey, CreateMasterKey: false, Migrate: false,
		Logger: slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1})),
		Now: env.Clock.Now,
	})
	if err != nil {
		t.Fatalf("打开共享装配（强认证会话夹具）: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	var securityVersion int64
	queryOne(t, env.DBPath, `SELECT security_version FROM users WHERE id=?`,
		[]any{userID}, &securityVersion)
	if securityVersion <= 0 {
		t.Fatalf("用户 %s 安全版本无效", userID)
	}
	now := env.Clock.Now().UTC()
	issued, err := base.Services.Sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: userID, Username: username,
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
			CompletedAt:      now, StrongAuthCompletedAt: now,
			SecurityVersion: securityVersion},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("签发强认证测试会话: %v", err)
	}
	secret := issued.Secret.Reveal()
	if secret == "" {
		t.Fatal("强认证测试会话秘密为空")
	}
	return []byte(secret)
}
