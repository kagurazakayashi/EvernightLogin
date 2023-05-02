// Package managecli 实现 loginctl 的常规管理、诊断与设置命令（步骤 84）。
//
// 命令分为三类，帮助与输出中必须能区分：
//   - 本地运维命令（config/diag/migrate/task/user）：可信边界是本机操作系统与
//     数据库文件访问权；不启动监听端口、不连接远程服务。需要操作者的命令必须
//     显式给出 --operator（本地管理员稳定标识），并使用与 cmd/login-backup 相同的
//     “只允许该本地操作者执行列出的权限动作”授权器，不冒充在线认证。
//   - 本人会话命令（session）：操作者出示真实会话秘密文件，由 internal/session
//     的 Validate/ListSessions/RevokeSession 判定；命令从不打印会话秘密。
//   - 在线管理命令（audit/reports/backups/notifications/tasks）：通过 HTTP 调用
//     运行中的 login-server 管理 JSON API（internal/adminapi），使用 --server /
//     --session-file（受保护的管理会话秘密文件）/ --ca-file / --timeout / --json。
//     权限、数据范围、强认证、敏感操作、幂等与审计全部由服务端每次重新判定；CLI
//     只做参数编排、envelope 解包、原始字节流下载与错误/退出码映射，不缓存授权
//     结论、不直连数据库。
//
// 安全约定：
//   - 密码、主密钥、PFX 密码等秘密不得作为命令行参数传入；只接受受保护来源
//     （env:/file: 引用）或受保护文件，`config set` 拒绝秘密字段。
//   - 诊断输出只包含脱敏值：秘密显示 [REDACTED]/[UNSET]，证书只显示元数据，
//     不输出私钥；不可用能力返回明确的稳定错误码，不返回伪成功。
//   - 写操作要么预演（--dry-run）要么需要显式确认词（--confirm）；取消与超时
//     只影响本次进程，不遗留后台进程、监听端口或临时文件。
//   - 所有命令使用稳定退出码，见 ExitOK…ExitInterrupted。
package managecli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

// 稳定退出码。脚本可以依赖这些值区分失败类别；新增值只能追加。
const (
	// ExitOK 表示命令成功完成（幂等无变化也算成功）。
	ExitOK = 0
	// ExitError 表示执行失败（内部错误、存储不可用、任务失败等）。
	ExitError = 1
	// ExitUsage 表示参数/用法错误，未执行任何操作。
	ExitUsage = 2
	// ExitCancelled 表示操作者取消或任务处于已取消状态，未产生请求的变更。
	ExitCancelled = 3
	// ExitUnauthenticated 表示未认证或认证材料无效/过期/被撤销。
	ExitUnauthenticated = 4
	// ExitForbidden 表示已认证但未获准执行（无权限、受限会话、受保护目标）。
	ExitForbidden = 5
	// ExitConflict 表示并发冲突、状态冲突或版本不匹配，需要重新读取后重试。
	ExitConflict = 6
	// ExitTimeout 表示本地等待超时；任务可能仍在运行，不代表已取消或失败。
	ExitTimeout = 7
	// ExitTaskFailed 表示被等待/查询的任务以失败或超时终态结束。
	ExitTaskFailed = 8
	// ExitInterrupted = 128+2，对应 Ctrl+C（SIGINT）。
	ExitInterrupted = 130
)

// Options 是命令的可注入依赖；零值使用系统时钟、配置加载器默认环境读取。
type Options struct {
	// Now 是时钟；nil 使用 time.Now。
	Now func() time.Time
	// LookupEnv 读取环境变量；nil 使用 os.LookupEnv。仅用于测试注入。
	LookupEnv func(string) (string, bool)
}

// Run 执行一条 loginctl 管理命令并返回稳定退出码。
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunWithOptions(args, stdin, stdout, stderr, Options{})
}

// RunWithOptions 与 Run 相同，但允许测试注入时钟与环境。
func RunWithOptions(args []string, stdin io.Reader, stdout, stderr io.Writer,
	options Options) int {
	if stdout == nil || stderr == nil || stdin == nil {
		return ExitUsage
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	allowDefaultDatabase := false
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--allow-default-database" {
			allowDefaultDatabase = true
			continue
		}
		filtered = append(filtered, arg)
	}
	args = filtered
	r := &runner{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr,
		options: options, allowDefaultDatabase: allowDefaultDatabase}
	if len(args) == 0 {
		printUsage(stderr)
		return ExitUsage
	}
	group := args[0]
	rest := args[1:]
	switch group {
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	case "config":
		return r.runConfig(rest)
	case "diag":
		return r.runDiag(rest)
	case "migrate":
		return r.runMigrate(rest)
	case "task":
		return r.runTask(rest)
	case "session":
		return r.runSession(rest)
	case "user":
		return r.runUser(rest)
	case "group", "role", "app", "permission", "notify":
		return r.runDomain(group, rest)
	case "audit", "reports", "backups", "notifications", "tasks":
		return r.runOnline(group, rest)
	case "admin":
		return r.runAdmin(rest)
	default:
		fmt.Fprintf(stderr, "错误：未知的管理命令 %q（用法：loginctl help）\n", group)
		return ExitUsage
	}
}

// printUsage 输出管理命令总览。它只描述本步已实现的能力，未实现域明确说明。
func printUsage(out io.Writer) {
	fmt.Fprintln(out, "loginctl 常规管理命令（本地运维边界；不启动服务、不连接远程接口）")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "常规设置与诊断：")
	fmt.Fprintln(out, "  loginctl config show [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl config get <field> [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl config validate [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl config diff --old <file> --new <file> [--json]")
	fmt.Fprintln(out, "  loginctl config set <field> <value> --file <file> [--dry-run] [--json]")
	fmt.Fprintln(out, "  loginctl config set-secret <field> --source env:NAME|file:PATH --file <file> "+
		"[--dry-run] [--json]")
	fmt.Fprintln(out, "  loginctl diag health|ready|database|certificate|mail|all [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl migrate status [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl migrate apply [--config <file>] --confirm MIGRATE --service-stopped [--json]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "后台任务（只读查询、等待与取消请求；取消请求不等于实际取消）：")
	fmt.Fprintln(out, "  loginctl task list [--config <file>] [--state <s>] [--kind <k>] [--limit N] [--json]")
	fmt.Fprintln(out, "  loginctl task get <job_id> [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl task wait <job_id> [--timeout 60s] [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl task cancel <job_id> --operator <id> --reason <原因> [--config <file>] [--json]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "本人会话（出示真实会话秘密文件；秘密不进入命令行/日志）：")
	fmt.Fprintln(out, "  loginctl session whoami --session-file <f> --keyring-file <f> [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl session list --session-file <f> --keyring-file <f> [--page N] [--page-size N] [--json]")
	fmt.Fprintln(out, "  loginctl session revoke <session_id> --session-file <f> --keyring-file <f> [--json]")
	fmt.Fprintln(out, "  loginctl session admin-revoke (--user <id> | --session-id <id>) --reason <原因> --confirm ADMIN-REVOKE <在线公共参数>")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "本地用户管理（需要 --operator 本地管理员标识；写操作需要 --confirm）：")
	fmt.Fprintln(out, "  loginctl user list --operator <id> [--config <file>] [--status <s>] [--limit N] [--json]")
	fmt.Fprintln(out, "  loginctl user get <user_id> --operator <id> [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl user disable <user_id> --operator <id> --expected-version N --reason <原因> \\")
	fmt.Fprintln(out, "      --confirm DISABLE [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl user enable <user_id> --operator <id> --expected-version N --reason <原因> \\")
	fmt.Fprintln(out, "      --confirm ENABLE [--config <file>] [--json]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "组/角色/权限/应用（只读 + 受控建组）与通知状态：")
	fmt.Fprintln(out, "  loginctl group list|get|members|create ...")
	fmt.Fprintln(out, "  loginctl role list|get|permissions ...")
	fmt.Fprintln(out, "  loginctl app list|get|members ...")
	fmt.Fprintln(out, "  loginctl permission list [--json]")
	fmt.Fprintln(out, "  loginctl notify status|test ...")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "在线管理（需要运行中的 login-server 与受保护管理会话秘密文件）：")
	fmt.Fprintln(out, "  loginctl audit events list|detail ...")
	fmt.Fprintln(out, "  loginctl audit exports list|create|cancel|download ...")
	fmt.Fprintln(out, "  loginctl audit cleanup preview|submit|cancel ...")
	fmt.Fprintln(out, "  loginctl audit errors search ...")
	fmt.Fprintln(out, "  loginctl reports history list|detail ...")
	fmt.Fprintln(out, "  loginctl reports download-token <report_id> --format <f> --confirm ISSUE-DOWNLOAD ...")
	fmt.Fprintln(out, "  loginctl reports cancel|retry|cleanup ...")
	fmt.Fprintln(out, "  loginctl backups artifacts list|detail|download-token ...")
	fmt.Fprintln(out, "  loginctl backups schedules list|get|create|edit|enable|disable|delete ...")
	fmt.Fprintln(out, "  loginctl backups retention get|set ...")
	fmt.Fprintln(out, "  loginctl backups cleanup preview|submit ...")
	fmt.Fprintln(out, "  loginctl admin users|user|groups|group|roles|role|permissions|applications|application|support-cases|support-case [...]")
	fmt.Fprintln(out, "  loginctl notifications status|test ...")
	fmt.Fprintln(out, "  loginctl tasks get <task_id> ...")
	fmt.Fprintln(out, "  公共参数：--server <url>（默认 http://127.0.0.1:8080） --api-path </admin/v1> \\")
	fmt.Fprintln(out, "    --session-file <受保护文件> [--ca-file <PEM>] [--timeout 30s] [--json]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "安全默认：未显式给出 --config 且数据库路径为默认 database/login.db 时，")
	fmt.Fprintln(out, "  访问数据库的命令会拒绝执行；确需使用请显式加 --allow-default-database。")
	fmt.Fprintln(out, "退出码：0 成功；1 执行失败；2 用法错误；3 已取消；4 未认证；5 无权限；")
	fmt.Fprintln(out, "        6 冲突；7 等待超时（任务可能仍在运行）；8 任务失败/超时；130 被中断。")
}

// runner 是一次命令执行的上下文与输出入口。
type runner struct {
	ctx       context.Context
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	options   Options
	command   string
	usageText string
	json      bool
	// allowDefaultDatabase 是操作者显式确认允许使用默认数据库路径。
	allowDefaultDatabase bool
}

// jsonEnvelope 是 --json 的稳定输出结构。成功与失败都输出同一外壳，便于脚本解析。
// RequestID 只在在线命令成功时出现（来自管理 API，用于关联排障，不是凭证）。
type jsonEnvelope struct {
	OK        bool       `json:"ok"`
	Command   string     `json:"command,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
	Data      any        `json:"data,omitempty"`
	Error     *jsonError `json:"error,omitempty"`
}

// jsonError 是失败输出；Details 只包含已脱敏的结构化信息。
type jsonError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// succeed 输出成功结果并返回 0。
func (r *runner) succeed(data any) int {
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: true, Command: r.command, Data: data})
		return ExitOK
	}
	return ExitOK
}

// succeedWithText 在非 JSON 模式下输出人读文本；JSON 模式输出 data。
func (r *runner) succeedWithText(data any, format string, args ...any) int {
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: true, Command: r.command, Data: data})
		return ExitOK
	}
	fmt.Fprintf(r.stdout, format, args...)
	return ExitOK
}

// fail 输出结构化失败并返回指定退出码；非 JSON 模式只向 stderr 写中文错误。
func (r *runner) fail(code string, exit int, message string, details any) int {
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: false, Command: r.command,
			Error: &jsonError{Code: code, Message: message, Details: details}})
	}
	fmt.Fprintf(r.stderr, "错误：[%s] %s\n", code, message)
	return exit
}

// usage 输出用法错误。
func (r *runner) usage(format string, args ...any) int {
	return r.fail("USAGE_INVALID", ExitUsage, fmt.Sprintf(format, args...), nil)
}

// writeEnvelope 把 JSON 外壳写到 stdout；编码失败只写 stderr（不改变退出码语义，
// 但调用方应把编码失败视为内部错误）。
func (r *runner) writeEnvelope(envelope jsonEnvelope) {
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		fmt.Fprintln(r.stderr, "错误：[INTERNAL_ERROR] 结果序列化失败")
		return
	}
	fmt.Fprintln(r.stdout, string(encoded))
}

// errHelp 表示请求帮助。
var errHelp = errors.New("获取帮助")

// flagDef 描述一个命令参数。布尔参数不接受值。
type flagDef struct {
	name  string
	value bool // 是否接受值
}

// parseFlags 解析命令参数。它允许参数出现在位置参数前后（与常见 CLI 习惯一致），
// 支持 --name=value、--name value、--help/-h 与 -- 终止符；未知/重复/缺值参数返回
// 用法错误。返回的 map 中布尔开关的值为 "1"。
func parseFlags(args []string, defs []flagDef) (map[string]string, []string, error) {
	known := make(map[string]bool, len(defs)+1)
	for _, def := range defs {
		known[def.name] = def.value
	}
	values := make(map[string]string)
	var positional []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			positional = append(positional, args[index+1:]...)
			break
		}
		if arg == "-h" || arg == "--help" {
			return nil, nil, errHelp
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			positional = append(positional, arg)
			continue
		}
		name, inline, hasInline := strings.Cut(arg[2:], "=")
		wantsValue, ok := known[name]
		if !ok {
			return nil, nil, fmt.Errorf("未知参数 --%s", name)
		}
		if _, duplicated := values[name]; duplicated {
			return nil, nil, fmt.Errorf("参数 --%s 重复", name)
		}
		if !wantsValue {
			if hasInline {
				return nil, nil, fmt.Errorf("参数 --%s 不接受值", name)
			}
			values[name] = "1"
			continue
		}
		if hasInline {
			values[name] = inline
			continue
		}
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return nil, nil, fmt.Errorf("参数 --%s 缺少值", name)
		}
		values[name] = args[index+1]
		index++
	}
	return values, positional, nil
}

// boolFlag 报告参数是否被设置。
func boolFlag(values map[string]string, name string) bool {
	return values[name] == "1"
}

// stringFlag 返回参数值（未设置为空串）。
func stringFlag(values map[string]string, name string) string {
	return strings.TrimSpace(values[name])
}

// parseIntFlag 解析整数参数；未设置返回默认值。
func parseIntFlag(values map[string]string, name string, defaultValue int) (int, error) {
	raw := stringFlag(values, name)
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("参数 --%s 必须是整数", name)
	}
	return parsed, nil
}

// parseLimit 解析分页上限并施加边界，避免 CLI 触发无界查询。
func parseLimit(values map[string]string, defaultValue, maxValue int) (int, error) {
	limit, err := parseIntFlag(values, "limit", defaultValue)
	if err != nil {
		return 0, err
	}
	if limit < 1 || limit > maxValue {
		return 0, fmt.Errorf("--limit 必须在 1～%d 之间", maxValue)
	}
	return limit, nil
}

// flagError 把参数解析错误映射为用法错误；帮助请求输出当前组帮助。
func (r *runner) flagError(err error) int {
	return r.flagErrorWith(r.usageText, err)
}

// flagErrorWith 使用指定帮助文本处理参数解析错误。
func (r *runner) flagErrorWith(usageText string, err error) int {
	if errors.Is(err, errHelp) {
		return r.helpText("", usageText)
	}
	return r.usage("%v", err)
}
