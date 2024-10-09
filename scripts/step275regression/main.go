// Command step275regression 是步骤 275 的“搜索/通知/接口文档集成回归”编排器。
//
// 目的：用一个有界、串行、可复现的入口运行本轮的回归矩阵，并输出机器可读 JSON：
//   - 搜索：用户、应用成员、RBAC（角色/组/权限）、应用、客服工单、报告历史、审计/
//     任务读取、UI 页面、CLI（managecli）与 EvernightMail 子模块搜索；
//   - 通知：人工恢复安全告知、直接管理安全告知、安全告知分页与邮件投递记录终态
//     回查（queued≠succeeded 的既有断言套件），以及本步骤新增的“直接管理告知真实
//     终态”集成测试；
//   - 文档/权限目录/能力矩阵（阶段2）：待 269/270/271 合入后运行，默认标记为
//     deferred，不伪造通过。
//
// 约束：
//   - 每个子命令串行执行（同一时刻只有一个重型任务），各自有界超时；失败记录
//     最小命令与输出尾部（不含秘密），不继续无限重试；
//   - 只读：除指定 -out 文件与自身临时目录外不写仓库；不执行 git 写操作；
//   - 临时目录在结束时删除；输出不含口令、会话秘密、令牌或完整邮箱；
//   - 退出码：0=所有已运行套件通过；1=存在失败；2=前置/参数错误。
//
// 运行（仓库根目录）：
//
//	go run ./scripts/step275regression -out P:/go/tmp/r11-275/report.json
//	go run ./scripts/step275regression -example            # 追加 272 示例 self-test
//	go run ./scripts/step275regression -phase2             # 269/270/271 合入后跑文档/矩阵
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// suite 是一条回归命令。
type suite struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Phase    int      `json:"phase"`
	Dir      string   `json:"dir"`
	Command  string   `json:"command"`
	Args     []string `json:"args"`
	Deferred string   `json:"deferred_reason,omitempty"`
}

// suiteResult 是一条命令的真实执行结果。
type suiteResult struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Phase      int    `json:"phase"`
	Status     string `json:"status"` // PASS/FAIL/DEFERRED/NOT_RUN
	Dir        string `json:"dir"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// report 是机器可读汇总。
type report struct {
	Schema      string         `json:"schema"`
	GeneratedAt string         `json:"generated_at_utc"`
	Head        string         `json:"head,omitempty"`
	GoVersion   string         `json:"go_version"`
	Platform    string         `json:"platform"`
	Phase       string         `json:"phase"`
	Suites      []suiteResult  `json:"suites"`
	Counts      map[string]int `json:"counts"`
	Untested    []string       `json:"untested_boundaries,omitempty"`
	Error       string         `json:"error,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts := struct {
		out            string
		root           string
		timeout        time.Duration
		includeExample bool
		phase2         bool
		verbose        bool
	}{}
	flags := flag.NewFlagSet("step275regression", flag.ContinueOnError)
	flags.StringVar(&opts.out, "out", "step275-regression.json", "机器可读结果 JSON 路径")
	flags.StringVar(&opts.root, "root", "", "仓库根目录（默认自动定位）")
	flags.DurationVar(&opts.timeout, "timeout", 20*time.Minute, "总超时（所有套件合计）")
	flags.BoolVar(&opts.includeExample, "example", false, "追加运行步骤272 示例 self-test")
	flags.BoolVar(&opts.phase2, "phase2", false, "运行阶段2 文档/OpenAPI/能力矩阵检查")
	flags.BoolVar(&opts.verbose, "v", false, "把子命令输出实时转发到 stderr")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	root := opts.root
	if root == "" {
		located, err := locateRoot()
		if err != nil {
			fmt.Fprintln(os.Stderr, "前置失败:", err)
			return 2
		}
		root = located
	}
	tempDir, err := os.MkdirTemp("", "step275-regression-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建临时目录失败:", err)
		return 2
	}
	defer os.RemoveAll(tempDir)
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	head := readHead(root)
	suites := buildSuites(root, tempDir, opts.includeExample, opts.phase2)
	result := &report{
		Schema: "evernight.step275.regression/v1", GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Head: head, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Phase: "phase1", Counts: map[string]int{"pass": 0, "fail": 0, "deferred": 0, "not_run": 0},
	}
	for _, item := range suites {
		entry := suiteResult{ID: item.ID, Category: item.Category, Phase: item.Phase,
			Dir: item.Dir, Command: item.Command}
		if item.Deferred != "" {
			entry.Status = "DEFERRED"
			entry.Detail = item.Deferred
			result.Counts["deferred"]++
			result.Suites = append(result.Suites, entry)
			continue
		}
		if err := ctx.Err(); err != nil {
			entry.Status = "NOT_RUN"
			entry.Detail = "总超时已到，未执行"
			result.Counts["not_run"]++
			result.Suites = append(result.Suites, entry)
			continue
		}
		started := time.Now()
		cmdCtx, cmdCancel := context.WithTimeout(ctx, 5*time.Minute)
		command := exec.CommandContext(cmdCtx, item.Command, item.Args...)
		command.Dir = item.Dir
		command.Env = append(os.Environ(), "GOMAXPROCS=2", "TMP="+tempDir, "TEMP="+tempDir)
		output, runErr := command.CombinedOutput()
		cmdCancel()
		entry.DurationMS = time.Since(started).Milliseconds()
		if runErr == nil {
			entry.Status = "PASS"
			result.Counts["pass"]++
		} else {
			entry.Status = "FAIL"
			entry.ExitCode = exitCode(runErr)
			entry.Detail = tailLines(string(output), 24)
			result.Counts["fail"]++
		}
		if opts.verbose {
			fmt.Fprintln(os.Stderr, "----", item.ID, entry.Status)
		}
		result.Suites = append(result.Suites, entry)
	}
	result.Untested = untestedBoundaries(opts.phase2)
	raw, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, "序列化结果失败:", marshalErr)
		return 2
	}
	raw = append(raw, '\n')
	if writeErr := os.WriteFile(opts.out, raw, 0o644); writeErr != nil {
		fmt.Fprintln(os.Stderr, "写结果文件失败:", writeErr)
		return 2
	}
	fmt.Printf("步骤275 回归: pass=%d fail=%d deferred=%d not_run=%d；结果=%s\n",
		result.Counts["pass"], result.Counts["fail"], result.Counts["deferred"],
		result.Counts["not_run"], opts.out)
	if result.Counts["fail"] > 0 {
		return 1
	}
	return 0
}

// buildSuites 构造阶段1 搜索/通知矩阵与阶段2 文档检查。
func buildSuites(root, tempDir string, includeExample, phase2 bool) []suite {
	mk := func(id, category string, phase int, dir string, command string, args ...string) suite {
		return suite{ID: id, Category: category, Phase: phase, Dir: dir,
			Command: command, Args: args}
	}
	tests := []suite{
		// 搜索：领域层（字面特殊字符/规范化/字段白名单/分页）。
		mk("search.users.domain", "search", 1, root, "go", "test", "./internal/account", "-run", "TestListUsersSearch", "-count=1"),
		mk("search.members.domain", "search", 1, root, "go", "test", "./internal/app", "-run", "TestApplicationMemberSearch|TestApplicationListSearch", "-count=1"),
		mk("search.rbac.domain", "search", 1, root, "go", "test", "./internal/role", "./internal/group", "./internal/permission", "-run", "TestRoleListSearch|TestGroupListSearch|TestPermissionListSearch", "-count=1"),
		mk("search.support.domain", "search", 1, root, "go", "test", "./internal/support", "-run", "TestCaseListSearch", "-count=1"),
		mk("search.reports.cursor", "search", 1, root, "go", "test", "./internal/reports", "-run", "TestHistoryListSearchAndCursorBinding|TestPlanListPageSearch", "-count=1"),
		// 搜索：公开门面 + UI 页面 + CLI 三入口。
		mk("search.public.facade", "search", 1, root, "go", "test", "./app", "-run", "TestAdminListUsersSearch|TestAdminListApplicationMembersSearch|TestAdminDomainListSearch", "-count=1"),
		mk("search.ui.pages", "search", 1, root, "go", "test", "./ui", "-run", "TestAdminUsersListSearchPage|TestAdminApplicationMembersSearchPage|TestAdminRBACListSearchPages|TestAdminGroupsListSearchPage|TestAdminApplicationsListSearchPage|TestSupportCasesListSearchPage|TestReportHistoryListSearchPage|TestSupportCasesSearchPaginationKeepsFilter|TestReportHistorySearchPaginationKeepsFilter|TestListSearchEnhancementAssets", "-count=1"),
		mk("search.cli.managecli", "search", 1, root, "go", "test", "./internal/managecli", "-run", "TestUserListSearchCLI|TestAppMembersSearchCLI|TestDomainListSearchCLI", "-count=1"),
		mk("search.mail.submodule", "search", 1, filepath.Join(root, "EvernightMail"), "go", "test",
			"./internal/index", "./internal/adminapi", "./internal/users", "./internal/web", "-run", "Search", "-count=1"),
		// 通知：人工恢复/直接管理安全告知与投递终态（queued≠succeeded）。
		mk("notify.manual_recovery", "notification", 1, root, "go", "test", "./internal/serverapp",
			"-run", "TestManualRecoveryNotifierReceiptIdempotent|TestManualRecoveryNotifierQueue|TestManualRecoveryNotifierQueueRealMail|TestManualRecoveryNotificationDeliveryLink", "-count=1"),
		mk("notify.direct_management", "notification", 1, root, "go", "test", "./internal/serverapp",
			"-run", "TestDirectManagementNotifier", "-count=1"),
		mk("notify.history_endpoints", "notification", 1, root, "go", "test", "./internal/serverapp",
			"-run", "TestStep266HistoryEndpointsE2E", "-count=1"),
		mk("notify.terminal_state.integration", "notification", 1, root, "go", "test", "./tests",
			"-run", "TestStep275DirectManagementNoticeTerminalState", "-count=1"),
	}
	if includeExample {
		tests = append(tests, suite{ID: "example.272.selftest", Category: "example", Phase: 1,
			Dir: filepath.Join(root, "examples", "password-reset-consumer"), Command: "go",
			Args: []string{"run", ".", "-mail", filepath.Join(root, "EvernightMail", "evernightmail.exe"),
				"-timeout", "5m", "-out", filepath.Join(tempDir, "example-report.json")}})
	}
	// 阶段2：269/270/271 合入后由 -phase2 运行；默认 deferred，不伪造通过。
	phase2Suites := []suite{
		mk("docs.reference_check", "docs", 2, root, "go", "run", "./scripts/reference", "-check"),
		mk("docs.verify", "docs", 2, root, "go", "run", "./scripts/verify-docs"),
		mk("docs.capabilities", "docs", 2, root, "go", "run", "./scripts/capabilities", "-check"),
	}
	if phase2 {
		tests = append(tests, phase2Suites...)
	} else {
		for _, item := range phase2Suites {
			item.Deferred = "阶段2：等待 269/270/271 提交后运行（OpenAPI/能力矩阵/文档一致性）"
			tests = append(tests, item)
		}
	}
	return tests
}

// untestedBoundaries 返回本轮未测边界（阶段2 默认项 + 平台边界）。
func untestedBoundaries(phase2 bool) []string {
	boundaries := []string{
		"非 SQLite 存储未启动实测（只做结构/编译层面检查）",
		"Linux/macOS/arm64 未运行（当前仅 Windows amd64）",
		"真实浏览器视觉/交互与旧响应抛弃未做浏览器自动化；以 UI 资产与页面测试静态证据为准",
		"跨进程真实 login-server + loginctl 的完整 CLI 在线命令矩阵未在本 runner 内重跑（由独立 e2e 脚本覆盖）",
	}
	if !phase2 {
		boundaries = append(boundaries, "OpenAPI/能力矩阵/文档一致性（阶段2，待 269/270/271 合入）")
	}
	return boundaries
}

// tailLines 截取输出尾部若干行，避免把完整日志写入 JSON。
func tailLines(value string, limit int) string {
	lines := strings.Split(strings.TrimRight(value, "\r\n"), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return strings.Join(lines, "\n")
}

// exitCode 提取命令退出码；被信号终止返回 -1。
func exitCode(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// readHead 读取当前 Git HEAD（只读；失败不影响回归结果）。
func readHead(root string) string {
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// locateRoot 从当前目录向上查找含 go.mod 与 examples 的仓库根。
func locateRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			if _, examplesErr := os.Stat(filepath.Join(dir, "examples")); examplesErr == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("未找到仓库根目录")
		}
		dir = parent
	}
}
