// Command login-server 是 login 身份服务的独立进程入口。
//
// 命令只负责解析参数、建立信号上下文并调用 internal/serverapp 完成装配；
// 业务装配、数据库、密钥、审计、页面、监听与优雅关闭都在 serverapp 中显式
// 完成，导入本命令不会启动任何后台任务。
//
// 当前版本提供的真实能力：
//   - serve：严格校验配置 -> 单实例数据库锁 -> 打开/校验 SQLite 与迁移 ->
//     装配真实服务与内置页面（14 个页面选项，默认注册 12 个、条件注册 2 个）->
//     启动后台任务执行器/调度器（邮件投递被本地禁用、Webhook 投递使用真实出站
//     策略）-> 监听（默认 127.0.0.1）-> 有界优雅关闭；文件访问日志按大小/数量
//     受控轮转。OAuth2/OIDC 协议端点（Discovery/JWKS/授权/令牌/UserInfo/撤销等）
//     与管理 JSON API（审计/报告/计划/备份/任务/错误码等路由）已装配，默认关闭，
//     分别由 --enable-protocol / --enable-admin-api（或 protocol.enabled 配置）
//     显式启用。
//   - init：本地受控首次安全初始化（创建 root、兑换一次性凭证、设置正式密码）。
//
// 已实现但默认关闭：设备码与扫码登录（步骤 192/193 已验收其已实现边界，需显式配置
// 协议/扫码开关）、令牌状态查询（introspection，145/160 验收边界；mTLS/故障等未实测）；真实邮件外发未配置
// （本地禁用）；发布包不等同于已完成真机互操作验证的完整对外身份服务。
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
			"serve  校验配置、打开并校验数据库迁移、装配真实服务与内置页面后监听 HTTP；\n" +
			"       OAuth2/OIDC 协议端点与管理 JSON API 已装配但默认关闭，\n" +
			"       由 --enable-protocol / --enable-admin-api 显式启用。\n" +
			"init   本地受控首次初始化：创建唯一 root、兑换一次性配置凭证并设置正式密码。\n\n" +
			"已实现但默认关闭：设备码与扫码登录（192/193 验收其已实现边界，需显式配置）、" +
			"令牌状态查询（introspection，145/160 验收边界；mTLS/故障等未实测）；真实邮件外发未配置。",
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
		"W3C 访问日志文件路径（默认写 stderr；文件日志默认受控轮转）")
	flags.Int64Var(&options.AccessLogMaxBytes, "access-log-max-bytes", 0,
		"访问日志单文件字节上限（0 使用默认 64 MiB，允许 1 MiB～1 GiB）")
	flags.IntVar(&options.AccessLogMaxFiles, "access-log-max-files", 0,
		"访问日志保留的历史文件数量（0 使用默认 5，允许 1～100，不含当前文件）")
	flags.StringVar(&options.MaintenanceStateDir, "maintenance-state-dir", "",
		"库外维护状态目录（默认：数据库目录同级的 <数据目录名>-maintenance）")
	flags.BoolVar(&options.InitMaintenanceState, "init-maintenance-state", false,
		"显式允许在已有数据库上创建缺失的库外维护状态（默认 fail-closed）")
	flags.BoolVar(&options.AllowUninitialized, "allow-uninitialized", false,
		"仅开发/测试：允许数据库尚未完成首次初始化时启动（默认拒绝）")
	flags.BoolVar(&options.AllowLegacyWithoutSensitive, "allow-legacy-without-sensitive", false,
		"过渡开关：允许会话管理访问仅走旧强认证闸门（未装配敏感策略，默认 fail-closed）")
	flags.BoolVar(&options.EnableProtocol, "enable-protocol", false,
		"启用 OAuth 2.0 / OpenID Connect 协议端点（需配置 protocol.issuer；默认关闭，未启用时 404）")
	flags.BoolVar(&options.EnableAdminAPI, "enable-admin-api", false,
		"启用管理 JSON API（复用管理会话/CSRF 契约；默认关闭，未启用时 404）")
	flags.StringVar(&options.AdminAPIPrefix, "admin-api-prefix", "",
		"管理 API 站内前缀（默认 /admin/v1，不允许覆盖页面命名空间）")
	flags.BoolVar(&options.EnableManagedAPI, "enable-managed-api", false,
		"启用业务应用托管管理 API（用户 Bearer/应用客户端认证；默认关闭，未启用时 404）")
	flags.StringVar(&options.ManagedAPIPrefix, "managed-api-prefix", "",
		"业务托管 API 站内前缀（默认 /api/managed/v1）")
	flags.BoolVar(&options.EnableAppSupport, "enable-app-support", false,
		"启用应用受限客服 API（需 OAuth 协议端点；默认关闭）")
	flags.StringVar(&options.AppSupportPrefix, "app-support-prefix", "",
		"应用客服 API 站内前缀（默认 /api/app/v1/support）")
	flags.StringVar(&options.AppSupportAudience, "app-support-audience", "",
		"应用客服资源 OAuth audience（默认 urn:evernight:app-support）")
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
