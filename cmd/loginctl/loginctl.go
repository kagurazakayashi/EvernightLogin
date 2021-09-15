// 本文件实现 loginctl 本地管理命令的可测试驱动（步骤 48 只含
// root-recover）。Run 接收显式 stdin/stdout/stderr 与可选交互器工厂，便于测试注入
// 假交互；生产 main 传入 os.Stdin/os.Stdout/os.Stderr 与默认终端交互实现。
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/rootrecovery"
	"golang.org/x/term"
)

// 稳定退出码：0 成功；1 执行失败；2 参数/用法错误；3 操作者取消（未做任何修改）。
const (
	ExitOK        = 0
	ExitError     = 1
	ExitUsage     = 2
	ExitCancelled = 3
)

// PrompterFactory 为测试注入交互器；nil 使用终端实现。
type PrompterFactory func(stdin io.Reader, stdout io.Writer) rootrecovery.Prompter

// Run 执行 loginctl 命令并返回稳定退出码。它不访问网络、不发送邮件、不启动后台
// 进程；错误输出只包含安全文本，不包含密码或认证器材料。
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, factory PrompterFactory) int {
	if stdin == nil || stdout == nil || stderr == nil {
		return ExitUsage
	}
	if len(args) == 0 {
		printUsage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "root-recover":
		return runRootRecover(args[1:], stdin, stdout, stderr, factory)
	case "restore-preflight":
		return runRestorePreflight(args[1:], stdout, stderr)
	case "restore-apply":
		return runRestoreApply(args[1:], stdout, stderr)
	case "restore-init-state":
		return runRestoreInitState(args[1:], stdout, stderr)
	case "maintenance-enter":
		return runMaintenanceEnter(args[1:], stdout, stderr)
	case "maintenance-exit":
		return runMaintenanceExit(args[1:], stdout, stderr)
	case "restore-merge-audit":
		return runRestoreMergeAudit(args[1:], stdout, stderr)
	case "restore-disposition":
		return runRestoreDisposition(args[1:], stdout, stderr)
	case "restore-review":
		return runRestoreReview(args[1:], stdout, stderr)
	case "restore-reenable":
		return runRestoreReenable(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	case "version", "--version":
		info := login.CurrentBuildInfo()
		fmt.Fprintf(stdout, "loginctl %s\n", info.String())
		return ExitOK
	default:
		fmt.Fprintf(stderr, "未知命令 %q\n\n", args[0])
		printUsage(stderr)
		return ExitUsage
	}
}

func runRootRecover(args []string, stdin io.Reader, stdout, stderr io.Writer,
	factory PrompterFactory) int {
	flags := flag.NewFlagSet("loginctl root-recover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	database := flags.String("database", "", "目标 SQLite 数据库文件路径（必填）")
	reason := flags.String("reason", "", "本地应急恢复原因（必填，最多 500 字符）")
	resetPassword := flags.Bool("reset-password", false, "重置 root 正式密码（交互式隐藏输入）")
	resetMFA := flags.Bool("reset-mfa", false, "重置 root 两步验证因素（邮件/TOTP/待处理挑战）")
	revokePasskeys := flags.Bool("revoke-login-passkeys", false,
		"同时撤销 root 的主登录 Passkey（默认保留，需二次确认）")
	serviceStopped := flags.Bool("service-stopped", false,
		"确认 login 服务已停止（与 --maintenance 至少一个为 true）")
	maintenance := flags.Bool("maintenance", false,
		"确认实例处于维护状态（与 --service-stopped 至少一个为 true）")
	requestID := flags.String("request-id", "", "可选请求编号，用于关联审计与恢复记录")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：loginctl root-recover --database <path> --reason <原因> \\")
		fmt.Fprintln(stderr, "        (--service-stopped | --maintenance) [--reset-password] [--reset-mfa] \\")
		fmt.Fprintln(stderr, "        [--revoke-login-passkeys] [--request-id <id>]")
	}
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "错误：存在多余参数")
		return ExitUsage
	}
	if strings.TrimSpace(*database) == "" || strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "错误：--database 与 --reason 必填")
		return ExitUsage
	}
	if !*serviceStopped && !*maintenance {
		fmt.Fprintln(stderr, "错误：必须确认服务已停止或处于维护状态（--service-stopped 或 --maintenance）")
		return ExitUsage
	}
	if !*resetPassword && !*resetMFA {
		fmt.Fprintln(stderr, "错误：至少选择 --reset-password 或 --reset-mfa 之一")
		return ExitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	operator := rootrecovery.LocalOperator()
	// 默认交互器强制 stdin 与 stdout 均为终端：管道/重定向/自动化脚本不能在无人
	// 确认的情况下跑完恢复（固定确认词不应成为脚本化旁路）。测试通过注入工厂绕过。
	var prompter rootrecovery.Prompter
	if factory != nil {
		prompter = factory(stdin, stdout)
	} else {
		defaultPrompter, err := newDefaultPrompter(stdin, stdout)
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return ExitUsage
		}
		prompter = defaultPrompter
	}
	service, err := rootrecovery.New(rootrecovery.Options{
		DatabasePath: *database,
		Operator:     operator,
		Prompter:     prompter,
		Logger:       logger,
	})
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitError
	}
	result, err := service.Recover(contextTODO(), rootrecovery.Request{
		Reason:              *reason,
		ResetPassword:       *resetPassword,
		ResetMFA:            *resetMFA,
		RevokeLoginPasskeys: *revokePasskeys,
		ServiceStopped:      *serviceStopped || *maintenance,
		RequestID:           *requestID,
	})
	if err != nil {
		if errors.Is(err, rootrecovery.ErrConfirmationDeclined) {
			fmt.Fprintln(stdout, "已取消：未对数据库做任何修改。")
			return ExitCancelled
		}
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return ExitError
	}
	fmt.Fprintln(stdout, "root 应急恢复已完成。")
	fmt.Fprintf(stdout, "  恢复记录 ID：%s\n", result.EventID)
	fmt.Fprintf(stdout, "  root 用户：%s\n", result.RootUserID)
	fmt.Fprintf(stdout, "  新安全版本：%d\n", result.SecurityVersionAfter)
	fmt.Fprintf(stdout, "  已撤销会话：%d，已禁用因素：%d，已作废恢复代码组：%d，已撤销 Passkey：%d\n",
		result.SessionsRevoked, result.FactorsDisabled,
		result.RecoveryCodeGroupsRevoked, result.PasskeysRevoked)
	fmt.Fprintln(stdout, "  root 已进入 setup_verified：必须重新配置强认证后才能再次使用。")
	fmt.Fprintln(stdout, "  请重启服务，并通过受控初始化流程完成强因素绑定；待补发安全告知已写入 outbox。")
	return ExitOK
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "loginctl - login 身份服务本地管理命令")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "用法：")
	fmt.Fprintln(out, "  loginctl root-recover --database <path> --reason <原因> \\")
	fmt.Fprintln(out, "      (--service-stopped | --maintenance) [--reset-password] [--reset-mfa] \\")
	fmt.Fprintln(out, "      [--revoke-login-passkeys] [--request-id <id>]")
	fmt.Fprintln(out, "  loginctl restore-preflight --database <path> --state-dir <dir> \\")
	fmt.Fprintln(out, "      --key-file <path> --backup <file> --backup-output <dir> \\")
	fmt.Fprintln(out, "      --operator <id> [--avatars <dir>] [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl restore-apply --database <path> --state-dir <dir> \\")
	fmt.Fprintln(out, "      --key-file <path> --backup <file> --backup-output <dir> \\")
	fmt.Fprintln(out, "      --operator <id> --reason <原因> --confirm RESTORE \\")
	fmt.Fprintln(out, "      [--avatars <dir>] [--config <file>] [--json]")
	fmt.Fprintln(out, "  loginctl restore-init-state --database <path> --state-dir <dir> \\")
	fmt.Fprintln(out, "      --key-file <path> --backup-output <dir> --operator <id> --reason <原因> --confirm RESTORE")
	fmt.Fprintln(out, "  loginctl maintenance-enter --database <path> --state-dir <dir> \\")
	fmt.Fprintln(out, "      --operator <id> --reason <原因>")
	fmt.Fprintln(out, "  loginctl maintenance-exit --database <path> --state-dir <dir> \\")
	fmt.Fprintln(out, "      --operator <id> --reason <原因> [--force]")
	fmt.Fprintln(out, "  loginctl restore-merge-audit --database <path> --state-dir <dir> --operator <id>")
	fmt.Fprintln(out, "  loginctl restore-disposition --database <path> --state-dir <dir> --operator <id> [--json]")
	fmt.Fprintln(out, "  loginctl restore-review --database <path> --state-dir <dir> --operator <id> [--restore-id <id>]")
	fmt.Fprintln(out, "  loginctl restore-reenable --database <path> --state-dir <dir> --operator <id> \\")
	fmt.Fprintln(out, "      --reason <原因> [--kind schedule,webhook] [--restore-id <id>]")
	fmt.Fprintln(out, "  loginctl help | version")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "安全要求：")
	fmt.Fprintln(out, "  - 只允许在本地服务器、服务已停止或维护状态下运行；恢复期间独占数据库目录锁。")
	fmt.Fprintln(out, "  - 新密码通过隐藏输入取得，不接受命令行参数或环境变量。")
	fmt.Fprintln(out, "  - 主登录 Passkey 默认保留；只有显式 --revoke-login-passkeys 并二次确认才撤销。")
	fmt.Fprintln(out, "  - 取消确认不会对数据库做任何修改。")
	fmt.Fprintln(out, "  - 备份恢复仅允许本地应急管理员：先 restore-preflight 预演，再 restore-apply 执行；")
	fmt.Fprintln(out, "    恢复在维护状态与库外排他锁下进行，失败默认保持维护，需显式 maintenance-exit。")
}

// ===== 终端交互实现 =====

type terminalPrompter struct {
	in     io.Reader
	out    io.Writer
	reader *bufio.Reader
}

// newDefaultPrompter 校验默认交互器的终端前提：stdin 与 stdout 都必须是 TTY。
// 非 TTY（管道、重定向、CI）直接拒绝，且在打开数据库/加锁之前返回。
func newDefaultPrompter(in io.Reader, out io.Writer) (rootrecovery.Prompter, error) {
	if err := requireTerminal(in, out); err != nil {
		return nil, err
	}
	return &terminalPrompter{in: in, out: out, reader: bufio.NewReader(in)}, nil
}

// requireTerminal 检查输入/输出都是交互终端；失败返回给操作者的明确拒绝原因。
func requireTerminal(in io.Reader, out io.Writer) error {
	inFile, inOK := in.(*os.File)
	outFile, outOK := out.(*os.File)
	if !inOK || !outOK || !term.IsTerminal(int(inFile.Fd())) ||
		!term.IsTerminal(int(outFile.Fd())) {
		return fmt.Errorf("默认交互器要求 stdin 与 stdout 均为终端（TTY）；" +
			"请勿通过管道/重定向执行，自动化必须使用受控注入接口")
	}
	return nil
}

func (p *terminalPrompter) ConfirmRecovery(scope rootrecovery.ScopeSummary) (bool, error) {
	fmt.Fprintln(p.out, "=== root 本地应急恢复确认 ===")
	fmt.Fprintf(p.out, "数据库：%s\n", scope.DatabasePath)
	fmt.Fprintf(p.out, "操作者：%s（机器：%s）\n", scope.Operator.ID, scope.Operator.Machine)
	fmt.Fprintf(p.out, "root 账户：%s，当前初始化状态：%s\n", scope.RootUsername, scope.CurrentState)
	fmt.Fprintf(p.out, "恢复范围：重置密码=%t，重置 MFA=%t，撤销主登录 Passkey=%t\n",
		scope.ResetPassword, scope.ResetMFA, scope.RevokeLoginPasskeys)
	fmt.Fprintln(p.out, "此操作会递增安全版本、撤销 root 全部会话并作废恢复代码；")
	fmt.Fprintln(p.out, "完成后 root 进入必须重新配置强认证的受限状态。")
	fmt.Fprintln(p.out, "请在服务已停止/维护状态下继续；建议先备份数据库。")
	return p.confirmToken("RECOVER", "输入 RECOVER 确认执行，其他输入取消：")
}

func (p *terminalPrompter) ReadNewPassword() ([]byte, error) {
	file, ok := p.in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, fmt.Errorf("隐藏密码输入需要交互终端")
	}
	fmt.Fprint(p.out, "请输入新的 root 密码（输入不回显）：")
	password, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(p.out)
	if err != nil {
		return nil, err
	}
	return password, nil
}

func (p *terminalPrompter) ConfirmPasskeyRevocation() (bool, error) {
	fmt.Fprintln(p.out, "警告：即将撤销 root 的所有主登录 Passkey（不可递延恢复）。")
	fmt.Fprintln(p.out, "若仍能使用 Passkey 完成受限初始化，请取消并保留（不传 --revoke-login-passkeys）。")
	return p.confirmToken("REVOKE-PASSKEYS", "输入 REVOKE-PASSKEYS 确认撤销，其他输入取消：")
}

func (p *terminalPrompter) confirmToken(token, prompt string) (bool, error) {
	// 防御性：即使调用方绕过 newDefaultPrompter，非 TTY 也拒绝确认。
	if err := requireTerminal(p.in, p.out); err != nil {
		return false, err
	}
	fmt.Fprint(p.out, prompt)
	line, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.TrimSpace(line) == token, nil
}

var _ rootrecovery.Prompter = (*terminalPrompter)(nil)

// contextTODO 返回命令作用域上下文（本地短生命周期 CLI 不做额外取消）。
func contextTODO() context.Context { return context.Background() }
