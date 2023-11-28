// 无人值守短测试场景：宿主自定义页面与资料同步示例（examples/custom-pages-profile-sync）。
//
// 本程序是 scripts/shorttest.ps1 统一入口的场景实现（只使用标准库）：
//
//  1. 在入口提供的临时目录内，用 `go build` 构建真正的外部 Module
//     examples/custom-pages-profile-sync（它只导入公开包，不导入 internal/）；
//  2. 作为子进程运行示例的 `-self-test -json`：示例自己使用临时 SQLite、
//     127.0.0.1 动态回环端口与进程内本地邮件捕获器，覆盖宿主自定义页面与
//     Evernight 页面并存、匿名 CSRF 拒绝、注册/邮箱验证/登录、资料读取与白名单
//     更新、受控改名与业务投影同步、跨用户拒绝、找回密码与密码重置、MFA 受限
//     会话不建立宿主会话、显式启停与关闭清理；
//  3. 解析示例输出的单行 JSON，逐项断言 PASS，并独立验证：示例临时数据目录已被
//     删除、HTTP 动态端口与本地邮件捕获器端口已释放、本场景构建产物已清理、
//     临时目录无残留；
//  4. 输出单行结构化 JSON（可选同时写 -result），退出码 0=通过、1=失败、2=参数错误。
//
// 安全与资源约束：只写入口临时目录、只监听 127.0.0.1、不访问外网；不打印密码或
// 会话秘密（示例 JSON 本身不含秘密）；子进程有界超时；结束前删除本场景构建产物。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// scenarioID 是场景标识（与 scripts/shorttest/scenarios.json 一致）。
	scenarioID = "custom-pages-profile-sync-selftest"
	// resultSchema 是本场景结果 JSON 的格式版本。
	resultSchema = "evernight.shorttest.scenario-result/v1"
	// exampleModuleDir 是示例模块相对仓库根的路径。
	exampleModuleDir = "examples/custom-pages-profile-sync"
	// exampleResultSchema 是示例自检 JSON 的格式版本（本场景负责核对）。
	exampleResultSchema = "evernight.custom-pages-profile-sync.selftest/v1"
	// minExampleChecks 是期望示例至少输出的检查项数量（防止悄悄跳过检查）。
	minExampleChecks = 20
)

// check 是一条可审计的场景检查项。
type check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// exampleSelfTestResult 是示例 `-self-test -json` 的结构化结果（只取本场景需要的字段）。
type exampleSelfTestResult struct {
	Schema         string  `json:"schema"`
	Status         string  `json:"status"`
	Mode           string  `json:"mode"`
	ListenAddr     string  `json:"listen_addr"`
	Port           int     `json:"port"`
	HTTPPrefix     string  `json:"http_prefix"`
	MailSinkAddr   string  `json:"mail_sink_addr"`
	DataDir        string  `json:"data_dir"`
	DataDirRemoved bool    `json:"data_dir_removed"`
	Checks         []check `json:"checks"`
	DurationMS     int64   `json:"duration_ms"`
	Error          string  `json:"error"`
}

// cleanupInfo 是本场景独立核验的清理证据。
type cleanupInfo struct {
	ExampleDataDir         string `json:"example_data_dir,omitempty"`
	ExampleDataDirRemoved  bool   `json:"example_data_dir_removed"`
	PortReleaseChecked     bool   `json:"port_release_checked"`
	PortReleased           bool   `json:"port_released"`
	MailPortReleaseChecked bool   `json:"mail_port_release_checked"`
	MailPortReleased       bool   `json:"mail_port_released"`
	BuildArtifactRemoved   bool   `json:"build_artifact_removed"`
	WorkDirFilesAfterClean int    `json:"workdir_files_after_clean"`
}

// logs 是失败时用于定位的日志尾部（有界）。
type logs struct {
	BuildStderrTail string `json:"build_stderr_tail,omitempty"`
	RunStderrTail   string `json:"run_stderr_tail,omitempty"`
	RunStdoutTail   string `json:"run_stdout_tail,omitempty"`
}

// scenarioResult 是本场景输出的结构化结果。
type scenarioResult struct {
	Schema       string                 `json:"schema"`
	Scenario     string                 `json:"scenario"`
	Status       string                 `json:"status"`
	StartedAt    string                 `json:"started_at"`
	DurationMs   int64                  `json:"duration_ms"`
	Port         int                    `json:"port,omitempty"`
	ListenAddr   string                 `json:"listen_addr,omitempty"`
	MailSinkAddr string                 `json:"mail_sink_addr,omitempty"`
	Checks       []check                `json:"checks"`
	SpawnedPIDs  []int                  `json:"spawned_pids,omitempty"`
	Example      *exampleSelfTestResult `json:"example_result,omitempty"`
	Cleanup      cleanupInfo            `json:"cleanup"`
	Logs         logs                   `json:"logs"`
	Error        string                 `json:"error,omitempty"`
}

// commandResult 是一次子进程执行结果。
type commandResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	TimedOut   bool
	DurationMs int64
}

// options 是命令行参数。
type options struct {
	WorkDir        string
	TimeoutSeconds int
	ResultPath     string
}

func main() {
	os.Exit(run())
}

// run 执行场景并返回退出码：0 通过，1 失败，2 参数错误。
func run() int {
	opts := options{}
	flags := flag.NewFlagSet(scenarioID, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&opts.WorkDir, "workdir", "", "临时目录（入口创建，场景只写这里）")
	flags.IntVar(&opts.TimeoutSeconds, "timeout", 180, "场景内部总超时（秒）")
	flags.StringVar(&opts.ResultPath, "result", "", "可选：把结果 JSON 同时写入该路径")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if opts.WorkDir == "" || opts.TimeoutSeconds < 10 {
		fmt.Fprintln(os.Stderr, "参数错误：需要 -workdir，且 -timeout 至少 10 秒")
		return 2
	}
	workDir, err := filepath.Abs(opts.WorkDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析临时目录失败:", err)
		return 2
	}
	// 统一入口只创建临时根目录，场景自己创建工作子目录（与既有场景一致）。
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "创建临时工作目录失败:", err)
		return 2
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "定位仓库根失败:", err)
		return 2
	}

	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(opts.TimeoutSeconds)*time.Second)
	defer cancel()
	report := scenarioResult{
		Schema:    resultSchema,
		Scenario:  scenarioID,
		Status:    "FAIL",
		StartedAt: startedAt.UTC().Format(time.RFC3339),
	}
	buildBinary := filepath.Join(workDir, "custom-pages-profile-sync.exe")
	// 无论成功失败，都删除本场景创建的构建产物（入口负责最终删除临时根目录）。
	defer func() { _ = os.Remove(buildBinary) }()

	markFailed := func(id string, checkErr error) {
		report.Checks = append(report.Checks,
			check{ID: id, Status: "FAIL", Detail: checkErr.Error()})
		if report.Error == "" {
			report.Error = id + ": " + checkErr.Error()
		}
	}
	addCheck := func(id, status, detail string) {
		report.Checks = append(report.Checks, check{ID: id, Status: status, Detail: detail})
	}

	// ===== 1) 构建示例模块（外部 Module）=====
	budget := concurrencyBudget()
	buildBudget := remainingBudget(ctx) - 20*time.Second
	if buildBudget < 15*time.Second {
		markFailed("example.build", errors.New("总超时预算不足，无法完成构建"))
		return finish(report, startedAt, opts, 1)
	}
	if buildBudget > 120*time.Second {
		buildBudget = 120 * time.Second
	}
	build := runCommand(ctx, buildBudget, filepath.Join(repoRoot, exampleModuleDir),
		"go", []string{"build", "-trimpath", "-p", strconv.Itoa(budget),
			"-o", buildBinary, "."})
	report.Logs.BuildStderrTail = logTail(build.Stderr, 1200)
	if build.TimedOut || build.ExitCode != 0 {
		markFailed("example.build", fmt.Errorf("EXIT=%d timed_out=%t: %s",
			build.ExitCode, build.TimedOut, logTail(build.Stderr, 600)))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("example.build", "PASS",
		fmt.Sprintf("EXIT=0 duration_ms=%d binary=%s", build.DurationMs, buildBinary))

	// ===== 2) 运行示例有界自检（子进程，有自身总超时）=====
	runBudget := remainingBudget(ctx) - 10*time.Second
	if runBudget < 10*time.Second {
		markFailed("example.run", errors.New("总超时预算不足，无法运行自检"))
		return finish(report, startedAt, opts, 1)
	}
	exampleTimeoutSeconds := int(runBudget.Seconds())
	if exampleTimeoutSeconds < 10 {
		exampleTimeoutSeconds = 10
	}
	runResult := runCommand(ctx, runBudget, workDir, buildBinary,
		[]string{"-self-test", "-json", "-timeout", strconv.Itoa(exampleTimeoutSeconds) + "s"})
	report.Logs.RunStderrTail = logTail(runResult.Stderr, 1200)
	report.Logs.RunStdoutTail = logTail(runResult.Stdout, 600)
	if runResult.TimedOut {
		markFailed("example.run", fmt.Errorf("自检子进程超时（%dms）", runResult.DurationMs))
		return finish(report, startedAt, opts, 1)
	}
	if runResult.ExitCode != 0 {
		markFailed("example.run", fmt.Errorf("自检子进程 EXIT=%d: %s",
			runResult.ExitCode, logTail(runResult.Stderr, 600)))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("example.run", "PASS",
		fmt.Sprintf("EXIT=0 duration_ms=%d", runResult.DurationMs))

	// ===== 3) 解析并核对示例结构化结果（缺失/非法 JSON 视为失败）=====
	stdout := strings.TrimSpace(runResult.Stdout)
	var example exampleSelfTestResult
	if err := json.Unmarshal([]byte(stdout), &example); err != nil {
		markFailed("example.result_json",
			fmt.Errorf("示例 stdout 不是合法 JSON: %v；内容尾部: %s",
				err, logTail(stdout, 400)))
		return finish(report, startedAt, opts, 1)
	}
	report.Example = &example
	report.Port = example.Port
	report.ListenAddr = example.ListenAddr
	report.MailSinkAddr = example.MailSinkAddr
	if example.Schema != exampleResultSchema {
		markFailed("example.result_schema",
			fmt.Errorf("schema=%q，期望 %q", example.Schema, exampleResultSchema))
		return finish(report, startedAt, opts, 1)
	}
	if example.Status != "PASS" {
		markFailed("example.result_schema",
			fmt.Errorf("示例自检状态=%q 错误=%q", example.Status, example.Error))
		return finish(report, startedAt, opts, 1)
	}
	if len(example.Checks) < minExampleChecks {
		markFailed("example.result_schema",
			fmt.Errorf("示例只输出 %d 项检查，少于期望的 %d 项",
				len(example.Checks), minExampleChecks))
		return finish(report, startedAt, opts, 1)
	}
	failedChecks := make([]string, 0)
	for _, exampleCheck := range example.Checks {
		if exampleCheck.Status != "PASS" {
			failedChecks = append(failedChecks,
				exampleCheck.ID+"="+exampleCheck.Status+" ("+exampleCheck.Detail+")")
		}
	}
	if len(failedChecks) > 0 {
		markFailed("example.result_schema",
			fmt.Errorf("示例检查项未全部通过: %s", strings.Join(failedChecks, "; ")))
		return finish(report, startedAt, opts, 1)
	}
	if example.Port <= 0 || example.ListenAddr == "" || example.HTTPPrefix == "" ||
		example.MailSinkAddr == "" {
		markFailed("example.result_schema", errors.New(
			"示例结果缺少动态端口/监听地址/HTTP 前缀/本地邮件捕获器地址"))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("example.result_schema", "PASS",
		fmt.Sprintf("status=PASS checks=%d prefix=%s listen=%s mail=%s",
			len(example.Checks), example.HTTPPrefix, example.ListenAddr,
			example.MailSinkAddr))

	// ===== 4) 独立核验清理：示例数据目录、端口、构建产物、临时目录残留 =====
	// 4.1 示例自己的临时数据目录必须已删除（示例 JSON 声明 + 本场景独立 stat）。
	removed := example.DataDir != "" && !pathExists(example.DataDir)
	report.Cleanup.ExampleDataDir = example.DataDir
	report.Cleanup.ExampleDataDirRemoved = removed
	if !removed || !example.DataDirRemoved {
		markFailed("cleanup.example_data_dir", fmt.Errorf(
			"示例临时数据目录未删除: dir=%q exists=%t declared_removed=%t",
			example.DataDir, pathExists(example.DataDir), example.DataDirRemoved))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("cleanup.example_data_dir", "PASS",
		"示例临时 SQLite 数据目录已删除: "+example.DataDir)

	// 4.2 本地邮件捕获器端口也必须已释放（示例自检关闭捕获器后由本场景实际绑定验证）。
	mailPort := portFromAddress(example.MailSinkAddr)
	report.Cleanup.MailPortReleaseChecked = mailPort > 0
	report.Cleanup.MailPortReleased = portReleased(mailPort)
	if mailPort <= 0 || !report.Cleanup.MailPortReleased {
		markFailed("cleanup.mail_port_released",
			fmt.Errorf("本地邮件捕获器端口未释放: addr=%q port=%d",
				example.MailSinkAddr, mailPort))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("cleanup.mail_port_released", "PASS",
		fmt.Sprintf("本地邮件捕获器端口 %d 已释放", mailPort))

	// 4.3 动态回环 HTTP 端口必须已释放（示例声明 + 本场景实际绑定验证）。
	released := portReleased(example.Port)
	report.Cleanup.PortReleaseChecked = true
	report.Cleanup.PortReleased = released
	if !released {
		markFailed("cleanup.port_released",
			fmt.Errorf("动态端口 %d 未被释放", example.Port))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("cleanup.port_released", "PASS",
		fmt.Sprintf("端口 %d 已释放", example.Port))

	// 4.4 本场景构建产物删除后，临时目录不应有残留文件。
	if err := os.Remove(buildBinary); err != nil && !os.IsNotExist(err) {
		markFailed("cleanup.artifact", fmt.Errorf("删除构建产物失败: %w", err))
		return finish(report, startedAt, opts, 1)
	}
	report.Cleanup.BuildArtifactRemoved = !pathExists(buildBinary)
	if !report.Cleanup.BuildArtifactRemoved {
		markFailed("cleanup.artifact", errors.New("本场景构建产物仍然存在"))
		return finish(report, startedAt, opts, 1)
	}
	fileCount := countFiles(workDir)
	report.Cleanup.WorkDirFilesAfterClean = fileCount
	if fileCount != 0 {
		markFailed("cleanup.workdir_residue",
			fmt.Errorf("临时目录在清理后仍有 %d 个文件", fileCount))
		return finish(report, startedAt, opts, 1)
	}
	addCheck("cleanup.workdir_residue", "PASS",
		"构建产物已删除，临时目录无残留文件")

	report.Status = "PASS"
	return finish(report, startedAt, opts, 0)
}

// finish 汇总耗时并写出结果 JSON，返回退出码。
func finish(report scenarioResult, startedAt time.Time, opts options, exitCode int) int {
	report.DurationMs = time.Since(startedAt).Milliseconds()
	payload, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "编码场景结果失败:", err)
		return 1
	}
	fmt.Println(string(payload))
	if opts.ResultPath != "" {
		if writeErr := os.WriteFile(opts.ResultPath, append(payload, '\n'), 0o600); writeErr != nil {
			fmt.Fprintln(os.Stderr, "写入结果文件失败:", writeErr)
			return 1
		}
	}
	if report.Status != "PASS" && report.Error != "" {
		fmt.Fprintln(os.Stderr, "场景失败:", report.Error)
	}
	return exitCode
}

// runCommand 在指定目录执行命令并捕获输出；超时结束进程并标记 TimedOut。
func runCommand(ctx context.Context, timeout time.Duration, dir, name string,
	args []string) commandResult {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(runCtx, name, args...)
	command.Dir = dir
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.WaitDelay = 5 * time.Second
	startedAt := time.Now()
	runErr := command.Run()
	result := commandResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMs: time.Since(startedAt).Milliseconds(),
	}
	if runCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		return result
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Stderr += "\n启动命令失败: " + runErr.Error()
		}
	}
	return result
}

// remainingBudget 返回距离场景总截止时间还剩多少时间。
func remainingBudget(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}

// concurrencyBudget 计算并发预算：不超过逻辑处理器一半，最少 1（本机 4 -> 2）。
func concurrencyBudget() int {
	budget := runtime.NumCPU() / 2
	if budget < 1 {
		budget = 1
	}
	return budget
}

// findRepoRoot 从当前工作目录向上查找仓库根（含本模块 go.mod 的目录）。
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if content, readErr := os.ReadFile(goModPath); readErr == nil &&
			strings.Contains(string(content), "module github.com/kagurazakayashi/EvernightLogin") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("未找到仓库根（含 EvernightLogin go.mod 的目录）")
		}
		dir = parent
	}
}

// portFromAddress 从 host:port 地址解析端口；非法地址返回 0。
func portFromAddress(address string) int {
	_, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

// portReleased 尝试绑定回环端口以验证监听已释放（最多等待 5 秒）。
func portReleased(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			_ = listener.Close()
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// countFiles 统计目录下的普通文件数量（用于残留检查）。
func countFiles(root string) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return -1
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count += countFiles(filepath.Join(root, entry.Name()))
			continue
		}
		count++
	}
	return count
}

// pathExists 报告路径是否存在。
func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// logTail 截取日志尾部并限制长度，避免结果 JSON 过大。
func logTail(text string, limit int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= limit {
		return trimmed
	}
	return "..." + trimmed[len(trimmed)-limit:]
}
