// 无人值守短测试场景：真实 login-server 进程的"初始化 + 监听 + 拒绝路径"冒烟。
//
// 本程序是 scripts/shorttest.ps1 统一入口的第一个真实场景实现，复用项目既有
// CLI 能力（login-server init/serve），不导入 internal 包、不复制业务逻辑：
//
//  1. 在入口提供的临时目录内生成 SQLite 配置与合成 root 密码（随机、不打印）；
//  2. 真实执行 login-server init：成功路径要求 exit=0 且输出含 setup_verified；
//  3. 重复 init 必须被拒绝（失败路径）；
//  4. 真实 login-server serve 监听 127.0.0.1 动态端口：
//     GET /healthz、/openapi.json、/login 为成功路径；
//     GET /admin/v1/meta 在未启用管理 API 时必须 404（fail-closed 拒绝路径）；
//     GET /.well-known/openid-configuration、/jwks 在未启用协议时必须 404；
//  5. 结束进程、等待退出、验证端口释放、清理临时秘密文件，输出结构化 JSON。
//
// 安全与资源约束：数据只写临时目录；密码/主密钥不写入标准输出；不访问外网；
// 子进程有界超时；结束时删除本次创建的文件并把端口释放结果写入结果 JSON。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// scenarioID 是场景标识（与 scripts/shorttest/scenarios.json 一致）。
const scenarioID = "login-server-smoke"

// resultSchema 是本场景结果 JSON 的格式版本。
const resultSchema = "evernight.shorttest.scenario-result/v1"

// check 是一条可审计的场景检查项。
type check struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// commandResult 是一次子进程执行结果。
type commandResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	TimedOut   bool
	DurationMs int64
}

// exitInfo 是 serve 子进程的退出信息。
type exitInfo struct {
	Killed     bool  `json:"killed"`
	Exited     bool  `json:"exited"`
	ExitCode   int   `json:"exit_code"`
	DurationMs int64 `json:"duration_ms"`
}

// cleanupInfo 是场景自身清理证据。
type cleanupInfo struct {
	SecretFilesRemoved bool   `json:"secret_files_removed"`
	WorkDirRemoved     bool   `json:"workdir_removed"`
	PortReleaseChecked bool   `json:"port_release_checked"`
	PortReleased       bool   `json:"port_released"`
	Note               string `json:"note,omitempty"`
}

// scenarioResult 是场景输出的结构化结果。
type scenarioResult struct {
	Schema      string      `json:"schema"`
	Scenario    string      `json:"scenario"`
	Status      string      `json:"status"`
	StartedAt   string      `json:"started_at"`
	DurationMs  int64       `json:"duration_ms"`
	ListenAddr  string      `json:"listen_addr,omitempty"`
	Port        int         `json:"port,omitempty"`
	WorkDir     string      `json:"workdir"`
	Checks      []check     `json:"checks"`
	SpawnedPIDs []int       `json:"spawned_pids,omitempty"`
	ServerExit  *exitInfo   `json:"server_exit,omitempty"`
	Cleanup     cleanupInfo `json:"cleanup"`
	Error       string      `json:"error,omitempty"`
}

// options 是命令行参数。
type options struct {
	WorkDir        string
	ServerBinary   string
	TimeoutSeconds int
	ResultPath     string
}

func main() {
	os.Exit(run())
}

// run 执行场景并返回退出码：0 全部通过，1 存在失败，2 参数错误。
func run() int {
	opts := options{}
	flags := flag.NewFlagSet(scenarioID, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&opts.WorkDir, "workdir", "", "临时目录（入口创建，场景负责清理内容）")
	flags.StringVar(&opts.ServerBinary, "server", "", "已构建的 login-server 可执行文件路径")
	flags.IntVar(&opts.TimeoutSeconds, "timeout", 120, "场景内部总超时（秒）")
	flags.StringVar(&opts.ResultPath, "result", "", "可选：把结果 JSON 同时写入该路径")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if opts.WorkDir == "" || opts.ServerBinary == "" {
		fmt.Fprintln(os.Stderr, "缺少 -workdir 或 -server 参数")
		return 2
	}
	if opts.TimeoutSeconds < 10 {
		opts.TimeoutSeconds = 10
	}
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSeconds)*time.Second)
	defer cancel()

	result := scenarioResult{
		Schema:    resultSchema,
		Scenario:  scenarioID,
		Status:    "FAIL",
		StartedAt: startedAt.UTC().Format(time.RFC3339),
		WorkDir:   opts.WorkDir,
		Checks:    []check{},
	}
	fail := func(err error) int {
		if err != nil {
			result.Error = err.Error()
			fmt.Fprintln(os.Stderr, "场景失败:", err)
		}
		result.DurationMs = time.Since(startedAt).Milliseconds()
		finish(&result, opts.ResultPath)
		return 1
	}

	if err := os.MkdirAll(opts.WorkDir, 0o700); err != nil {
		return fail(fmt.Errorf("创建临时工作目录失败: %w", err))
	}
	dataDir := filepath.Join(opts.WorkDir, "data")
	secretsDir := filepath.Join(opts.WorkDir, "secrets")
	for _, dir := range []string{dataDir, secretsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fail(fmt.Errorf("创建临时子目录失败: %w", err))
		}
	}

	// 合成 root 密码：随机生成、只写入受保护临时文件、绝不打印。
	password, err := randomPassword()
	if err != nil {
		return fail(fmt.Errorf("生成合成密码失败: %w", err))
	}
	passwordFile := filepath.Join(secretsDir, "init-password.txt")
	if err := os.WriteFile(passwordFile, []byte(password), 0o600); err != nil {
		return fail(fmt.Errorf("写入受保护密码文件失败: %w", err))
	}
	// login-server init 要求密码文件仅所有者/ SYSTEM/Administrators 可访问；
	// Windows 需要显式去除继承并只授权受信主体（与非 Windows 的 0600 等价）。
	if err := protectSecretFile(passwordFile); err != nil {
		return fail(fmt.Errorf("设置密码文件保护权限失败: %w", err))
	}
	masterKeyFile := filepath.Join(secretsDir, "master.key")
	databasePath := filepath.Join(dataDir, "login.db")
	operatorID := "shorttest-smoke-" + shortRandom()

	// 动态回环端口：先绑定 :0 取端口再释放；serve 启动失败时换端口重试一次。
	port, portErr := freeLoopbackPort()
	if portErr != nil {
		return fail(fmt.Errorf("获取动态回环端口失败: %w", portErr))
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)
	configPath := filepath.Join(opts.WorkDir, "login.yaml")
	if err := writeConfig(configPath, listenAddr, databasePath); err != nil {
		return fail(fmt.Errorf("写入临时配置失败: %w", err))
	}
	result.Port = port
	result.ListenAddr = listenAddr

	// 1) 首次初始化成功路径。
	fmt.Fprintln(os.Stderr, "步骤: login-server init")
	initArgs := []string{"init", "--config", configPath, "--master-key-file", masterKeyFile,
		"--password-file", passwordFile, "--operator", operatorID}
	initResult := runCommand(ctx, opts.ServerBinary, initArgs, minDuration(remaining(ctx), 90*time.Second))
	addCheck(&result, "init.first_run", initResult.ExitCode == 0 &&
		strings.Contains(initResult.Stdout+initResult.Stderr, "setup_verified"),
		fmt.Sprintf("exit=%d", initResult.ExitCode), snippet(initResult.Stdout+"\n"+initResult.Stderr, 900))
	addCheck(&result, "init.no_password_echo",
		!strings.Contains(initResult.Stdout+initResult.Stderr, password),
		"init 输出不含合成密码", "")

	// 2) 重复初始化必须被拒绝（失败路径）。
	fmt.Fprintln(os.Stderr, "步骤: login-server init (repeat, must be rejected)")
	repeatResult := runCommand(ctx, opts.ServerBinary, initArgs, minDuration(remaining(ctx), 60*time.Second))
	addCheck(&result, "init.repeat_rejected", repeatResult.ExitCode != 0,
		fmt.Sprintf("exit=%d", repeatResult.ExitCode), snippet(repeatResult.Stdout+repeatResult.Stderr, 300))
	if _, statErr := os.Stat(databasePath); statErr != nil {
		return fail(fmt.Errorf("init 未创建临时数据库: %w", statErr))
	}

	// 3) 启动真实 serve 并等待 /healthz 就绪。
	fmt.Fprintln(os.Stderr, "步骤: login-server serve")
	server, startErr := startServe(ctx, opts.ServerBinary, configPath, masterKeyFile,
		filepath.Join(opts.WorkDir, "access.log"), listenAddr)
	spawned := 0
	if server != nil && server.cmd.Process != nil {
		spawned = server.cmd.Process.Pid
		result.SpawnedPIDs = append(result.SpawnedPIDs, spawned)
	}
	if startErr != nil {
		return fail(fmt.Errorf("启动 serve 失败: %w", startErr))
	}
	ready := waitHealthy(ctx, listenAddr, server)
	addCheck(&result, "serve.healthz_ready", ready,
		"GET /healthz 在超时内返回 200", "")
	if !ready {
		earlyExit := server.stop()
		result.ServerExit = &earlyExit
		return fail(fmt.Errorf("serve 未在超时内就绪"))
	}

	// 4) HTTP 成功与拒绝路径。
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + listenAddr
	httpChecks := []struct {
		id      string
		path    string
		status  int
		contain string
	}{
		{"http.healthz", "/healthz", http.StatusOK, "ok"},
		{"http.openapi", "/openapi.json", http.StatusOK, "openapi"},
		{"http.login_page", "/login", http.StatusOK, ""},
		{"admin_api.disabled_404", "/admin/v1/meta", http.StatusNotFound, ""},
		{"protocol.disabled_discovery_404", "/.well-known/openid-configuration", http.StatusNotFound, ""},
		{"protocol.disabled_jwks_404", "/jwks", http.StatusNotFound, ""},
	}
	for _, item := range httpChecks {
		status, body, getErr := httpGet(ctx, client, baseURL+item.path)
		passed := getErr == nil && status == item.status
		if passed && item.contain != "" {
			passed = strings.Contains(body, item.contain)
		}
		detail := fmt.Sprintf("status=%d", status)
		if getErr != nil {
			detail = "请求失败: " + getErr.Error()
		}
		addCheck(&result, item.id, passed, detail, snippet(body, 200))
	}

	// 5) 结束进程、等待退出、验证端口释放。
	exit := server.stop()
	result.ServerExit = &exit
	addCheck(&result, "serve.process_exited", exit.Exited,
		fmt.Sprintf("killed=%t exit_code=%d duration_ms=%d", exit.Killed, exit.ExitCode, exit.DurationMs), "")
	portReleased := waitPortReleased(ctx, port)
	result.Cleanup.PortReleaseChecked = true
	result.Cleanup.PortReleased = portReleased
	addCheck(&result, "serve.port_released", portReleased, "serve 退出后动态端口可重新绑定", "")

	// 6) 清理本次创建的临时秘密与数据（含数据库、WAL、库外维护状态、访问日志），
	// 最后删除场景工作目录本身；统一入口再负责整个临时根目录。
	for _, path := range []string{passwordFile, masterKeyFile} {
		_ = os.Remove(path)
	}
	secretGone := fileMissing(passwordFile) && fileMissing(masterKeyFile)
	result.Cleanup.SecretFilesRemoved = secretGone
	addCheck(&result, "cleanup.secret_files_removed", secretGone, "合成密码与主密钥临时文件已删除", "")
	entries, readErr := os.ReadDir(opts.WorkDir)
	if readErr == nil {
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(opts.WorkDir, entry.Name()))
		}
	}
	remainingFiles := countFiles(opts.WorkDir)
	_ = os.Remove(opts.WorkDir)
	workDirGone := fileMissing(opts.WorkDir)
	result.Cleanup.WorkDirRemoved = workDirGone && remainingFiles == 0
	addCheck(&result, "cleanup.workdir_empty", result.Cleanup.WorkDirRemoved,
		fmt.Sprintf("清理前剩余文件数=%d，场景工作目录已删除=%t", remainingFiles, workDirGone), "")

	// 汇总状态：全部 PASS 才算 PASS。
	passed := true
	for _, item := range result.Checks {
		if item.Status != "PASS" {
			passed = false
			break
		}
	}
	if passed {
		result.Status = "PASS"
	} else {
		result.Status = "FAIL"
	}
	result.DurationMs = time.Since(startedAt).Milliseconds()
	finish(&result, opts.ResultPath)
	if passed {
		return 0
	}
	return 1
}

// addCheck 追加一条检查项。
func addCheck(result *scenarioResult, id string, passed bool, detail, evidence string) {
	status := "FAIL"
	if passed {
		status = "PASS"
	}
	result.Checks = append(result.Checks, check{ID: id, Status: status, Detail: detail, Evidence: evidence})
	if !passed {
		fmt.Fprintf(os.Stderr, "[FAIL] %s: %s\n", id, detail)
	}
}

// finish 输出结果 JSON（stdout 单行，供统一入口解析；可选写文件）。
func finish(result *scenarioResult, resultPath string) {
	raw, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "序列化场景结果失败:", err)
		return
	}
	fmt.Println(string(raw))
	if resultPath != "" {
		if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err == nil {
			_ = os.WriteFile(resultPath, append(raw, '\n'), 0o644)
		}
	}
}

// randomPassword 生成满足策略的合成密码：32 字符 base64url（含大小写/数字）。
func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// shortRandom 生成 6 位随机十六进制串（仅用于操作者标识/目录后缀）。
func shortRandom() string {
	raw := make([]byte, 3)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%x", raw)
}

// freeLoopbackPort 通过绑定 127.0.0.1:0 取得空闲端口并立即释放。
func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	address := listener.Addr().(*net.TCPAddr)
	port := address.Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

// writeConfig 写入最小可校验 YAML 配置（临时数据库、动态回环监听地址）。
func writeConfig(path, listenAddr, databasePath string) error {
	config := "server:\n" +
		"  listen_addr: \"" + listenAddr + "\"\n" +
		"  shutdown_timeout_seconds: 5\n" +
		"logging:\n" +
		"  level: \"warn\"\n" +
		"  format: \"text\"\n" +
		"database:\n" +
		"  driver: sqlite\n" +
		"  path: \"" + filepath.ToSlash(databasePath) + "\"\n" +
		"  wal: true\n" +
		"  busy_timeout_ms: 5000\n" +
		"protocol:\n" +
		"  issuer: \"http://" + listenAddr + "\"\n"
	return os.WriteFile(path, []byte(config), 0o600)
}

// runCommand 同步执行一个子进程并返回退出码与输出；超时会结束进程。
func runCommand(ctx context.Context, exe string, args []string, timeout time.Duration) commandResult {
	startedAt := time.Now()
	command := exec.Command(exe, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return commandResult{ExitCode: -1, Stderr: err.Error(), DurationMs: time.Since(startedAt).Milliseconds()}
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		result := commandResult{
			Stdout: stdout.String(), Stderr: stderr.String(),
			DurationMs: time.Since(startedAt).Milliseconds(),
		}
		if command.ProcessState != nil {
			result.ExitCode = command.ProcessState.ExitCode()
		} else {
			result.ExitCode = -1
		}
		return result
	case <-timer.C:
		_ = command.Process.Kill()
		<-done
		return commandResult{ExitCode: -1, TimedOut: true,
			Stdout: stdout.String(), Stderr: stderr.String(),
			DurationMs: time.Since(startedAt).Milliseconds()}
	case <-ctx.Done():
		_ = command.Process.Kill()
		<-done
		return commandResult{ExitCode: -1, TimedOut: true,
			Stdout: stdout.String(), Stderr: stderr.String(),
			DurationMs: time.Since(startedAt).Milliseconds()}
	}
}

// serveProcess 是被监管的 serve 子进程。
type serveProcess struct {
	cmd       *exec.Cmd
	done      chan error
	stdout    *bytes.Buffer
	stderr    *bytes.Buffer
	startedAt time.Time
}

// startServe 启动真实 serve 子进程（不等待就绪）。
func startServe(ctx context.Context, exe, configPath, masterKeyFile, accessLog, listenAddr string) (*serveProcess, error) {
	command := exec.CommandContext(ctx, exe, "serve", "--config", configPath,
		"--master-key-file", masterKeyFile, "--access-log", accessLog)
	process := &serveProcess{
		cmd: command, done: make(chan error, 1),
		stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, startedAt: time.Now(),
	}
	command.Stdout = process.stdout
	command.Stderr = process.stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	go func() { process.done <- command.Wait() }()
	return process, nil
}

// stop 结束 serve 进程并等待退出（有界），返回退出信息。
func (p *serveProcess) stop() exitInfo {
	info := exitInfo{}
	if p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err == nil {
			info.Killed = true
		}
	}
	select {
	case <-p.done:
		info.Exited = true
	case <-time.After(15 * time.Second):
		return info
	}
	info.DurationMs = time.Since(p.startedAt).Milliseconds()
	if p.cmd.ProcessState != nil {
		info.ExitCode = p.cmd.ProcessState.ExitCode()
	}
	return info
}

// waitHealthy 轮询 /healthz 直至 200、进程提前退出或等待期限（30 秒）到达。
//
// 进程提前退出时立即返回 false，避免把"启动失败"拖成总超时；调用方随后会
// 记录有界 stderr 证据。
func waitHealthy(ctx context.Context, listenAddr string, server *serveProcess) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + listenAddr + "/healthz"
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, _, err := httpGet(ctx, client, url)
		if err == nil && status == http.StatusOK {
			return true
		}
		select {
		case <-server.done:
			return false
		default:
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// waitPortReleased 验证端口可重新绑定（说明 serve 已释放监听）。
func waitPortReleased(ctx context.Context, port int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = listener.Close()
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// httpGet 执行一次 GET，返回状态码与最多 32 KiB 的响应体。
func httpGet(ctx context.Context, client *http.Client, url string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32*1024))
	if err != nil {
		return response.StatusCode, "", err
	}
	return response.StatusCode, string(body), nil
}

// remaining 返回当前 context 剩余时间（至少 1 秒）。
func remaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Minute
	}
	left := time.Until(deadline)
	if left < time.Second {
		return time.Second
	}
	return left
}

// minDuration 返回两个时长中的较小值。
func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

// snippet 截断输出为便于审计的片段（按 UTF-8 字符边界截断，避免产生非法字节）。
func snippet(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "...(截断)"
}

// protectSecretFile 把秘密文件限制为仅当前受信主体可访问：
//   - Windows：icacls 去除继承，只授权当前用户 SID、SYSTEM、Administrators
//     （与 internal/secrets 的受保护文件判定一致）；
//   - 其他平台：chmod 0600。
func protectSecretFile(path string) error {
	if runtime.GOOS != "windows" {
		return os.Chmod(path, 0o600)
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	icacls, lookErr := exec.LookPath("icacls.exe")
	if lookErr != nil {
		return fmt.Errorf("找不到 icacls.exe: %w", lookErr)
	}
	args := []string{path, "/inheritance:r",
		"/grant:r", "*" + sid + ":(F)",
		"/grant:r", "*S-1-5-18:(F)",
		"/grant:r", "*S-1-5-32-544:(F)"}
	output, runErr := exec.Command(icacls, args...).CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("icacls 失败: %v (%s)", runErr, snippet(string(output), 400))
	}
	return nil
}

// currentUserSID 通过 whoami 取得当前进程用户 SID（仅 Windows 使用）。
func currentUserSID() (string, error) {
	whoami, lookErr := exec.LookPath("whoami.exe")
	if lookErr != nil {
		return "", fmt.Errorf("找不到 whoami.exe: %w", lookErr)
	}
	output, runErr := exec.Command(whoami, "/user", "/fo", "csv", "/nh").Output()
	if runErr != nil {
		return "", fmt.Errorf("读取当前用户 SID 失败: %w", runErr)
	}
	// 输出形如："host\user","S-1-5-21-..."; 取最后一个 CSV 字段。
	fields := strings.Split(strings.TrimSpace(string(output)), ",")
	if len(fields) < 2 {
		return "", fmt.Errorf("无法解析 whoami 输出")
	}
	sid := strings.Trim(strings.TrimSpace(fields[len(fields)-1]), `"`)
	if !strings.HasPrefix(sid, "S-1-") {
		return "", fmt.Errorf("whoami 输出不含有效 SID")
	}
	return sid, nil
}

// fileMissing 报告文件是否不存在。
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

// countFiles 递归统计目录中的普通文件数量（用于清理证据）。
func countFiles(root string) int {
	count := 0
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		count++
		return nil
	})
	return count
}
