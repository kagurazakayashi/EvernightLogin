// Command login-server 是 login 身份服务的独立进程入口。
//
// 命令只负责解析参数、建立信号上下文并调用 internal/serverapp 完成装配；
// 业务装配、数据库、密钥、审计、页面、监听与优雅关闭都在 serverapp 中显式
// 完成，导入本命令不会启动任何后台任务。
//
// 当前版本提供的真实能力：
//   - serve：严格校验配置 -> 打开/校验 SQLite 与迁移 -> 装配真实服务与内置
//     账户入口页 -> 监听（默认 127.0.0.1）-> 有界优雅关闭。
//   - init：本地受控首次安全初始化（创建 root、兑换一次性凭证、设置正式密码）。
//
// 仍未实现：OAuth2/OIDC/设备码/扫码协议 JSON 端点、管理 JSON API、其余管理
// 页面后端与真实邮件/Webhook 投递。文档与报告按实际能力描述，不夸大可用范围。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/spf13/cobra"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 执行命令并返回进程退出码：0 成功，1 失败。所有诊断写 stderr。
func run(args []string, stdout, stderr io.Writer) int {
	command := newRootCommand(login.CurrentBuildInfo())
	command.SetArgs(args)
	command.SetOut(stdout)
	command.SetErr(stderr)
	if err := command.Execute(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return 1
	}
	return 0
}

// newRootCommand 构造 login-server 命令树。
func newRootCommand(build login.BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "login-server",
		Short: "login 独立身份服务（HTTP 服务 + 本地首次初始化）",
		Long: "login 独立身份服务的装配入口。\n\n" +
			"serve  校验配置、打开并校验数据库迁移、装配真实服务与内置页面后监听 HTTP。\n" +
			"init   本地受控首次初始化：创建唯一 root、兑换一次性配置凭证并设置正式密码。\n\n" +
			"未实现：OAuth2/OIDC/设备码/扫码协议端点、管理 JSON API 与真实邮件/Webhook 投递。",
		Version:       build.String(),
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("请使用 serve 或 init 子命令；--help 查看完整帮助")
		},
	}
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.AddCommand(newServeCommand(), newInitCommand())
	return root
}

// executeWithSignal 建立 SIGINT/SIGTERM 可取消上下文；Windows 与 Unix 都通过
// os/signal 的 syscall.SIGTERM 表示服务停止请求（Windows 由控制台事件映射）。
func executeWithSignal(ctx context.Context, fn func(context.Context) error) error {
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return fn(signalCtx)
}

// newServeCommand 构造 serve 子命令。
func newServeCommand() *cobra.Command {
	var options serverapp.ServeOptions
	var migrateValue string
	command := &cobra.Command{
		Use:   "serve",
		Short: "启动独立 HTTP 身份服务",
		Long: "严格加载并校验 YAML 配置，打开 SQLite 并检查迁移，" +
			"装配真实服务与内置账户入口页后监听 HTTP。\n\n" +
			"未迁移的数据库默认拒绝启动；显式 --migrate=apply 才执行迁移。\n" +
			"收到 SIGINT/SIGTERM 后在 server.shutdown_timeout_seconds 内有界关闭。",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if options.ConfigPath == "" {
				return errors.New("缺少必需的 --config 配置文件路径")
			}
			switch migrateValue {
			case "":
				options.Migrate = false
			case "apply":
				options.Migrate = true
			default:
				return fmt.Errorf("--migrate 只支持空值、--migrate 或 --migrate=apply，实际为 %q", migrateValue)
			}
			return executeWithSignal(context.Background(), func(ctx context.Context) error {
				return serverapp.RunServe(ctx, options)
			})
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.ConfigPath, "config", "", "YAML 配置文件路径（必需）")
	flags.StringVar(&options.DatabasePath, "database", "",
		"覆盖配置中的 SQLite 数据库文件路径")
	flags.StringVar(&options.MasterKeyFile, "master-key-file", "",
		"主密钥环文件路径（配置未设置 secrets.master_key 时必需，必须为受保护文件）")
	flags.StringVar(&options.AccessLogPath, "access-log", "",
		"W3C 访问日志文件路径（默认写 stderr；不自动轮转）")
	flags.StringVar(&options.MaintenanceStateDir, "maintenance-state-dir", "",
		"库外维护状态目录（默认：数据库目录同级的 <数据目录名>-maintenance）")
	flags.BoolVar(&options.InitMaintenanceState, "init-maintenance-state", false,
		"显式允许在已有数据库上创建缺失的库外维护状态（默认 fail-closed）")
	flags.BoolVar(&options.AllowUninitialized, "allow-uninitialized", false,
		"仅开发/测试：允许数据库尚未完成首次初始化时启动（默认拒绝）")
	flags.BoolVar(&options.AllowLegacyWithoutSensitive, "allow-legacy-without-sensitive", false,
		"过渡开关：允许会话管理访问仅走旧强认证闸门（未装配敏感策略，默认 fail-closed）")
	flags.StringVar(&migrateValue, "migrate", "",
		"执行数据库迁移后再启动：--migrate 或 --migrate=apply")
	flags.Lookup("migrate").NoOptDefVal = "apply"
	return command
}

// newInitCommand 构造 init 子命令。
func newInitCommand() *cobra.Command {
	var options serverapp.InitOptions
	command := &cobra.Command{
		Use:   "init",
		Short: "本地受控首次安全初始化（创建唯一 root）",
		Long: "在本地受控环境创建数据库与迁移、生成/加载主密钥环、创建唯一 root，" +
			"兑换一次性配置凭证并设置 root 正式密码。\n\n" +
			"密码只在交互式终端（不回显、二次确认）或受保护 stdin/文件中读取，" +
			"不接受命令行明文密码或密钥参数。重复初始化会被拒绝；" +
			"初始化后 root 仍要求强认证绑定，命令不签发任何会话。",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if options.ConfigPath == "" {
				return errors.New("缺少必需的 --config 配置文件路径")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			return serverapp.RunInit(ctx, options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.ConfigPath, "config", "", "YAML 配置文件路径（必需）")
	flags.StringVar(&options.DatabasePath, "database", "",
		"覆盖配置中的 SQLite 数据库文件路径")
	flags.StringVar(&options.MasterKeyFile, "master-key-file", "",
		"主密钥环文件路径；配置未设置 secrets.master_key 时必需（不存在则生成受保护文件）")
	flags.StringVar(&options.OperatorID, "operator", "",
		"本地受控操作者标识（默认由操作系统本地管理员身份推导）")
	flags.StringVar(&options.PasswordFile, "password-file", "",
		"受保护密码文件路径（仅所有者可读写；不提供命令行明文密码）")
	flags.StringVar(&options.MaintenanceStateDir, "maintenance-state-dir", "",
		"库外维护状态目录（默认与 serve 相同）")
	return command
}
