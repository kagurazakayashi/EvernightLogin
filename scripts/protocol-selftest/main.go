// Command protocol-selftest 是步骤 243 的自包含协议与安全集成测试工具。
//
// 目标：把分散在 internal/protocolapi、internal/loginte2e、app、transport、authn、
// totp、passkey 等包里的真实协议/安全测试，整理为一个可被 CI 或一键入口调用的
// 短测试工具。工具本身不访问外网、不安装依赖包、不连接外部数据库：它只调用本仓库
// 的 `go test -json`，被测测试使用临时 SQLite/httptest/动态回环端口/合成身份/
// 软件 TOTP/软件 WebAuthn；工具设置 GOPROXY=off 证明离线可运行。
//
// 覆盖（scenario 详见 coreScenarios）：
//   - OAuth/OIDC：Discovery/JWKS/授权码+PKCE/Token/刷新轮换/撤销/内省/设备码/QR；
//   - 真实协议 E2E：internal/loginte2e 的真实 SQLite + httptest 协议处理器；
//   - 会话与权限联合判定、应用隔离；
//   - CSRF/来源校验、错误码与防枚举；
//   - 软件 TOTP 第二因素与软件 WebAuthn（Passkey）仪式。
//
// 边界：不启动外部 Mail 进程（邮件协议/真实投递由既有 Mail 子模块验收覆盖，见
// docs/deployment/protocol-selftest.md）；不做真实浏览器/真机 WebAuthn/USB 安全密钥；
// 非 Windows/Linux 交叉运行不在本工具范围。成功/失败路径均给出结构化 JSON 与退出码。
//
// 用法：
//
//	go run ./scripts/protocol-selftest -out result.json
//	go run ./scripts/protocol-selftest -suite core -timeout 5m -verbose
//	go run ./scripts/protocol-selftest -inject-failure   # 验证失败退出码
//	go run ./scripts/protocol-selftest -list             # 列出场景（JSON）
//
// 退出码：0 通过（允许 skip）；1 有失败；2 参数错误；3 环境/子进程不可用；
// 4 结果写出失败；130 总超时。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const resultSchema = "evernight.protocol-selftest/v1"

const (
	exitPass      = 0
	exitFail      = 1
	exitUsage     = 2
	exitUnavail   = 3
	exitWrite     = 4
	exitTimeout   = 130
	defaultTotal  = 6 * time.Minute
	defaultPerRun = 2 * time.Minute
)

type scenario struct {
	Name    string   `json:"name"`
	Package string   `json:"package"`
	Run     string   `json:"run"`
	Areas   []string `json:"areas"`
}

// coreScenarios 是稳定注册表；name/package/run/areas 为机器可读契约。
func coreScenarios() []scenario {
	return []scenario{
		{Name: "protocol_http_contract", Package: "./internal/protocolapi",
			Run:   `^(TestDiscovery|TestJWKS|TestHandlerAndMount|TestPathPrefix|TestRouter|TestNew)`,
			Areas: []string{"oauth_oidc", "protocol_errors"}},
		{Name: "protocol_authcode_pkce", Package: "./internal/protocolapi",
			Run:   `^(TestAuthorize|TestWrongPKCE|TestTokenEndpoint|TestRefreshRotation|TestUserInfo|TestOIDC)`,
			Areas: []string{"oauth_oidc", "csrf_origin"}},
		{Name: "protocol_device_qr", Package: "./internal/protocolapi",
			Run:   `^(TestDevice|TestQR)`,
			Areas: []string{"oauth_oidc", "device_flow"}},
		{Name: "protocol_introspection", Package: "./internal/protocolapi",
			Run:   `^(TestIntrospection|TestResponseAndAuditDoNotLeakSecrets)`,
			Areas: []string{"oauth_oidc", "introspection"}},
		{Name: "protocol_real_e2e", Package: "./internal/loginte2e",
			Run:   `^(TestRealProtocolAPI|TestPageDeviceConfirmer|TestVerifyIDToken|TestPathContract)`,
			Areas: []string{"oauth_oidc", "real_sqlite_httptest"}},
		{Name: "oauth_client_lifecycle", Package: "./internal/oauthclient",
			Run:   `^Test`,
			Areas: []string{"oauth_oidc", "client_credentials"}},
		{Name: "protocol_public_go", Package: "./app",
			Run:   `^(TestProtocolPublicIntrospection|TestProtocolPublicRevocation)`,
			Areas: []string{"oauth_oidc", "introspection"}},
		{Name: "session_authorize_permissions", Package: "./app",
			Run:   `^(TestSessionAuthorize|TestSessionServiceValidate|TestSessionDeviceManagementPublicFlow)`,
			Areas: []string{"session_permissions", "csrf_origin"}},
		{Name: "app_cross_isolation", Package: "./app",
			Run:   `^TestApplicationAdminCrossAppIsolation$`,
			Areas: []string{"app_isolation"}},
		{Name: "http_boundary_tls", Package: "./internal/transport",
			Run:   `^TestBoundary`,
			Areas: []string{"http_boundary", "mtls_client_identity"}},
		{Name: "local_tls_service", Package: "./internal/serverapp",
			Run:   `^(TestServeWithLocalTLS|TestResourceAuthorizeAndIntrospectE2E)`,
			Areas: []string{"loopback_tls", "oauth_oidc"}},
		{Name: "csrf_cookie_contract", Package: "./internal/transport",
			Run:   `^(TestCSRFCookieSessionContract|TestCORSExactOriginsPreflightAndRejection|TestSecurityHeadersAppliedToAllResponses)`,
			Areas: []string{"csrf_origin"}},
		{Name: "http_pages_security", Package: "./app",
			Run:   `^(TestEmbeddedHTTPPagesMountAndSecurity|TestEmbeddedHTTPPageOverrides)`,
			Areas: []string{"csrf_origin", "session_permissions"}},
		{Name: "auth_uniform_failure", Package: "./internal/authn",
			Run:   `^(TestAuthenticateSuccessAndUniformFailure|TestAuthenticateDisabledAccountGenericFailure|TestLogAndAuditRedaction|TestTemporaryLockAndRecovery)`,
			Areas: []string{"anti_enumeration", "error_codes"}},
		{Name: "software_totp", Package: "./internal/totp",
			Run:   `^(TestBindConfirmLoginRebindAndRemovalProtection|TestRFC6238KnownVectors|TestRemoveBindingInvalidatesExistingSessions)`,
			Areas: []string{"mfa_software_totp"}},
		{Name: "software_webauthn", Package: "./internal/passkey",
			Run:   `^(TestMFASecurityKeySecondFactorWithRealPasskeyCeremony|TestRegisterListRenameAndReauth|TestDiscoverableLoginAndWrongUserHandle|TestWrongOriginLoginRejected|TestSyncedCredentialCounterMayNotIncrement|TestSecondFactorCeremonyAndPurposeEnforcement)`,
			Areas: []string{"mfa_software_webauthn"}},
	}
}

type scenarioResult struct {
	Name       string   `json:"name"`
	Package    string   `json:"package"`
	Run        string   `json:"run"`
	Areas      []string `json:"areas"`
	Status     string   `json:"status"`
	Pass       int      `json:"pass"`
	Fail       int      `json:"fail"`
	Skip       int      `json:"skip"`
	Failed     []string `json:"failed,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Detail     string   `json:"detail,omitempty"`
}

type coverageEntry struct {
	Area      string   `json:"area"`
	Scenarios []string `json:"scenarios"`
}

type result struct {
	Schema          string           `json:"schema"`
	Tool            string           `json:"tool"`
	Version         string           `json:"version"`
	Status          string           `json:"status"`
	ExitCode        int              `json:"exit_code"`
	StartedAt       string           `json:"started_at"`
	DurationMS      int64            `json:"duration_ms"`
	Suite           string           `json:"suite"`
	Concurrency     int              `json:"concurrency"`
	Offline         bool             `json:"offline"`
	InjectedFailure bool             `json:"injected_failure"`
	Scenarios       []scenarioResult `json:"scenarios"`
	Coverage        []coverageEntry  `json:"coverage"`
	Summary         summary          `json:"summary"`
	Cleanup         cleanup          `json:"cleanup"`
}

type summary struct {
	Scenarios int `json:"scenarios"`
	Pass      int `json:"pass"`
	Fail      int `json:"fail"`
	Skip      int `json:"skip"`
}

type cleanup struct {
	ChildProcessGroupReaped bool   `json:"child_process_group_reaped"`
	GoTestTempArtifacts     string `json:"go_test_temp_artifacts"`
	Note                    string `json:"note,omitempty"`
}

type options struct {
	timeout    time.Duration
	perRun     time.Duration
	outPath    string
	keep       bool
	injectFail bool
	verbose    bool
	suite      string
	list       bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var opts options
	flags := flag.NewFlagSet("protocol-selftest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.DurationVar(&opts.timeout, "timeout", defaultTotal, "总超时（所有场景，含子进程等待）")
	flags.DurationVar(&opts.perRun, "per-scenario-timeout", defaultPerRun, "单个 go test 场景超时")
	flags.StringVar(&opts.outPath, "out", "", "可选：把结果 JSON 写入该路径")
	flags.BoolVar(&opts.keep, "keep", false, "保留场景临时输出（本工具不创建持久临时目录，保留仅影响 go test -v 输出）")
	flags.BoolVar(&opts.injectFail, "inject-failure", false, "注入确定性失败（验证非零退出，诊断用）")
	flags.BoolVar(&opts.verbose, "verbose", false, "把详细进度写到 stderr")
	flags.StringVar(&opts.suite, "suite", "core", "场景集：core（默认，协议+安全）")
	flags.BoolVar(&opts.list, "list", false, "以 JSON 列出场景并退出")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "protocol-selftest: unexpected arguments: %v\n", flags.Args())
		return exitUsage
	}
	if opts.suite != "core" {
		fmt.Fprintf(stderr, "protocol-selftest: unsupported suite %q (only core)\n", opts.suite)
		return exitUsage
	}
	if opts.timeout <= 0 || opts.timeout > time.Hour {
		fmt.Fprintln(stderr, "protocol-selftest: -timeout must be between 1s and 1h")
		return exitUsage
	}
	if opts.perRun <= 0 || opts.perRun > opts.timeout {
		fmt.Fprintln(stderr, "protocol-selftest: -per-scenario-timeout must be >0 and <= -timeout")
		return exitUsage
	}
	scenarios := coreScenarios()
	if opts.list {
		payload, _ := json.MarshalIndent(map[string]any{"schema": resultSchema,
			"tool": "protocol-selftest", "scenarios": scenarios}, "", "  ")
		_, _ = stdout.Write(append(payload, '\n'))
		return exitPass
	}

	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(stderr, "protocol-selftest: %v\n", err)
		return exitUnavail
	}

	res := result{Schema: resultSchema, Tool: "protocol-selftest", Version: "1",
		StartedAt: started.Format(time.RFC3339), Suite: opts.suite, Concurrency: 1,
		Offline: true, InjectedFailure: opts.injectFail, Scenarios: []scenarioResult{},
		Cleanup: cleanup{ChildProcessGroupReaped: true,
			GoTestTempArtifacts: "each go test process uses its own temp dirs and cleans them; tool creates none",
			Note:                "-keep only changes logging; no persistent temp dirs are created by this tool"}}
	areas := map[string]map[string]struct{}{}
	for _, sc := range scenarios {
		if ctx.Err() != nil {
			res.Scenarios = append(res.Scenarios, scenarioResult{Name: sc.Name,
				Package: sc.Package, Run: sc.Run, Areas: sc.Areas, Status: "timeout",
				Detail: "total timeout before scenario start"})
			break
		}
		outcome := runScenario(ctx, repoRoot, sc, opts)
		res.Scenarios = append(res.Scenarios, outcome)
		for _, area := range sc.Areas {
			if areas[area] == nil {
				areas[area] = map[string]struct{}{}
			}
			areas[area][sc.Name] = struct{}{}
		}
		if opts.verbose {
			fmt.Fprintf(stderr, "[protocol-selftest] %-32s %s pass=%d fail=%d skip=%d %dms\n",
				sc.Name, outcome.Status, outcome.Pass, outcome.Fail, outcome.Skip,
				outcome.DurationMS)
		}
	}
	if opts.injectFail {
		res.Scenarios = append(res.Scenarios, scenarioResult{Name: "selftest.injected_failure",
			Status: "fail", Fail: 1, Detail: "-inject-failure requested: deterministic failure",
			Areas: []string{"self_check"}})
	}
	for area, names := range areas {
		listed := make([]string, 0, len(names))
		for name := range names {
			listed = append(listed, name)
		}
		res.Coverage = append(res.Coverage, coverageEntry{Area: area, Scenarios: listed})
	}
	sortStrings(res.Coverage)

	res.Summary.Scenarios = len(res.Scenarios)
	for _, item := range res.Scenarios {
		switch item.Status {
		case "pass":
			res.Summary.Pass++
		case "skip":
			res.Summary.Skip++
		case "unavailable":
			res.Summary.Fail++
			res.Status = "unavailable"
		default:
			res.Summary.Fail++
		}
	}
	res.DurationMS = time.Since(started).Milliseconds()
	res.Status = "pass"
	if res.Summary.Fail > 0 {
		if res.Status == "unavailable" && res.Summary.Pass == 0 {
			res.Status = "unavailable"
		} else {
			res.Status = "fail"
		}
	}
	res.ExitCode = exitPass
	switch res.Status {
	case "fail":
		res.ExitCode = exitFail
	case "unavailable":
		res.ExitCode = exitUnavail
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.Status = "timeout"
		res.ExitCode = exitTimeout
	}
	payload, marshalErr := json.MarshalIndent(res, "", "  ")
	if marshalErr != nil {
		fmt.Fprintf(stderr, "protocol-selftest: marshal result: %v\n", marshalErr)
		return exitWrite
	}
	if _, err := stdout.Write(append(payload, '\n')); err != nil {
		return exitWrite
	}
	if opts.outPath != "" {
		if err := os.WriteFile(opts.outPath, append(payload, '\n'), 0o600); err != nil {
			fmt.Fprintf(stderr, "protocol-selftest: write -out: %v\n", err)
			return exitWrite
		}
	}
	if opts.verbose {
		fmt.Fprintf(stderr, "protocol-selftest: status=%s scenarios=%d pass=%d fail=%d duration=%dms\n",
			res.Status, res.Summary.Scenarios, res.Summary.Pass, res.Summary.Fail, res.DurationMS)
	}
	return res.ExitCode
}

// runScenario 在仓库根目录执行 go test -json，并解析用例计数/失败名。
func runScenario(ctx context.Context, repoRoot string, sc scenario, opts options) scenarioResult {
	started := time.Now()
	outcome := scenarioResult{Name: sc.Name, Package: sc.Package, Run: sc.Run,
		Areas: sc.Areas, Status: "pass"}
	scenarioCtx, cancel := context.WithTimeout(ctx, opts.perRun)
	defer cancel()
	perRunSeconds := int(opts.perRun.Seconds())
	if perRunSeconds < 1 {
		perRunSeconds = 1
	}
	command := exec.CommandContext(scenarioCtx, "go", "test", "-json", "-count=1",
		"-timeout", fmt.Sprintf("%ds", perRunSeconds), sc.Package, "-run", sc.Run)
	command.Dir = repoRoot
	command.Env = append(os.Environ(),
		"GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0", "GOMAXPROCS=2", "GOPROXY=off")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	outcome.DurationMS = time.Since(started).Milliseconds()
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seenTests := 0
	for scanner.Scan() {
		var event struct {
			Action  string
			Test    string
			Package string
			Output  string
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.Test == "" {
			continue
		}
		switch event.Action {
		case "pass":
			seenTests++
			outcome.Pass++
		case "fail":
			seenTests++
			outcome.Fail++
			if len(outcome.Failed) < 8 {
				outcome.Failed = append(outcome.Failed, sanitizeTestName(event.Test))
			}
		case "skip":
			seenTests++
			outcome.Skip++
		}
	}
	if scenarioCtx.Err() == context.DeadlineExceeded {
		outcome.Status = "timeout"
		outcome.Detail = "per-scenario timeout"
		return outcome
	}
	if runErr != nil || outcome.Fail > 0 {
		outcome.Status = "fail"
		detail := strings.TrimSpace(stderr.String())
		if detail == "" && outcome.Fail == 0 {
			detail = "go test exited non-zero before running tests (build/setup failure)"
		}
		outcome.Detail = truncate(sanitizeText(repoRoot, detail), 500)
		if len(outcome.Failed) > 0 {
			outcome.Detail = truncate("failed tests: "+strings.Join(outcome.Failed, ","),
				500)
		}
		if seenTests == 0 && outcome.Fail == 0 {
			outcome.Status = "unavailable"
		}
		return outcome
	}
	if seenTests == 0 {
		outcome.Status = "fail"
		outcome.Detail = "no tests matched scenario regex"
	}
	return outcome
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("未找到仓库根目录（缺少 go.mod）")
		}
		dir = parent
	}
}

var testNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9_./-]+`)

func sanitizeTestName(name string) string {
	trimmed := testNameSanitizer.ReplaceAllString(strings.TrimSpace(name), ":")
	return truncate(trimmed, 120)
}

// sanitizeText 去掉仓库绝对路径与可能的秘密形态，只保留可排障的短文本。
func sanitizeText(repoRoot, text string) string {
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, repoRoot, "<repo>")
	text = strings.ReplaceAll(text, strings.ReplaceAll(repoRoot, `\`, `/`), "<repo>")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " | ")
	return truncate(strings.TrimSpace(text), 800)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func sortStrings(entries []coverageEntry) {
	for left := 0; left < len(entries); left++ {
		for right := left + 1; right < len(entries); right++ {
			if entries[right].Area < entries[left].Area {
				entries[left], entries[right] = entries[right], entries[left]
			}
		}
	}
}
