// Command loginte2e 是对运行中的 login 服务做协议端点与管理 JSON API 端到端
// 验收/回归/排障的测试客户端（仅测试用途，不得用于生产入口）。
//
// 用法：
//
//	loginte2e <suite> [全局参数]
//	loginte2e --list-suites
//
// 套件：discovery jwks authcode token device qr adminapi all
//
// 退出码（稳定）：0 通过（允许 skip）；1 有失败用例；2 参数/配置/受保护文件错误；
// 3 目标不可达或全部用例因前置条件被跳过。
//
// 安全：默认严格 TLS 校验，不使用 InsecureSkipVerify；自签环境用 --ca-file 信任
// 指定 CA。会话/客户端秘密只从受保护文件读取，不写入日志、报告或命令行。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/loginte2e"
)

// version 是工具版本（与 CLI 参数解析一起打印；不影响被测服务）。
const version = "1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 是可测试的命令入口：返回稳定退出码，不调用 os.Exit。
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("loginte2e", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		server            = flags.String("server", loginte2e.DefaultServer, "被测服务基础地址（可含部署路径前缀）")
		caFile            = flags.String("ca-file", "", "在系统根证书之外追加信任的 CA 文件（PEM）；不跳过证书校验")
		timeout           = flags.Duration("timeout", loginte2e.DefaultTimeout, "单个 HTTP 请求超时")
		pollTimeout       = flags.Duration("poll-timeout", loginte2e.DefaultPollTimeout, "设备码/扫码轮询总等待上限")
		jsonOutput        = flags.Bool("json", false, "以 JSON 输出报告")
		sessionCookieFile = flags.String("session-cookie-file", "",
			"受保护的浏览器会话 Cookie/会话秘密文件（模拟已登录用户；仅测试用）")
		adminSessionFile = flags.String("admin-session-file", "",
			"受保护的管理会话秘密文件（管理 API 套件用）")
		adminBasePath = flags.String("admin-base-path", "/admin/v1", "管理 API 站内前缀")
		issuer        = flags.String("issuer", "", "期望的 issuer（空则信任 Discovery 返回值）")
		clientID      = flags.String("client-id", "", "被测客户端应用 ID")
		clientSecret  = flags.String("client-secret-file", "", "受保护的保密客户端密钥文件（可选）")
		redirectURI   = flags.String("redirect-uri", "", "客户端登记的回调地址")
		scope         = flags.String("scope", loginte2e.DefaultScope, "授权请求 scope（空格/逗号分隔）")
		deviceConfirm = flags.String("device-confirm-url", "",
			"宿主设备确认页地址（可选，支持 {code} 占位符；协议包本身不提供确认页端点）")
		resourceClientID = flags.String("resource-client-id", "",
			"受信资源服务 confidential 客户端 ID（tokenauthz/introspect 套件）")
		resourceSecretFile = flags.String("resource-client-secret-file", "",
			"受保护的资源服务客户端密钥文件")
		audience = flags.String("audience", "",
			"预期资源 audience（tokenauthz/introspect 套件，也用于授权 resource 参数）")
		listSuites = flags.Bool("list-suites", false, "列出可用套件")
		showHelp   = flags.Bool("help", false, "显示帮助")
	)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法: loginte2e <suite> [全局参数]")
		fmt.Fprintln(stderr, "套件: "+strings.Join(loginte2e.KnownSuites(), " "))
		fmt.Fprintln(stderr, "仅测试用途：默认严格 TLS 校验，不提供跳过校验开关；秘密只从受保护文件读取。")
		fmt.Fprintln(stderr, "参数:")
		flags.PrintDefaults()
	}
	// Go 的 flag 包只解析位置参数之前的开关；这里允许 `loginte2e discovery --server ...`
	// 这种更自然的顺序：先把开关与位置参数分开，再解析开关。
	positional, splitErr := splitArguments(flags, args)
	if splitErr != nil {
		fmt.Fprintln(stderr, "错误:", splitErr)
		return loginte2e.ExitUsage
	}
	if err := flags.Parse(positional.flags); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.Usage()
			return loginte2e.ExitPass
		}
		return loginte2e.ExitUsage
	}
	if *showHelp {
		flags.Usage()
		return loginte2e.ExitPass
	}
	if *listSuites {
		for _, suite := range loginte2e.KnownSuites() {
			fmt.Fprintln(stdout, suite)
		}
		return loginte2e.ExitPass
	}
	suiteargs := positional.positional
	if len(suiteargs) != 1 {
		fmt.Fprintln(stderr, "错误: 必须且只能指定一个套件（用 --list-suites 查看）")
		flags.Usage()
		return loginte2e.ExitUsage
	}
	suite := strings.ToLower(strings.TrimSpace(suiteargs[0]))
	if !loginte2e.IsKnownSuite(suite) {
		fmt.Fprintf(stderr, "错误: 未知套件 %q（可用: %s）\n", suiteargs[0],
			strings.Join(loginte2e.KnownSuites(), ", "))
		return loginte2e.ExitUsage
	}

	config := loginte2e.Config{
		Server: *server, CAFile: *caFile, Timeout: *timeout, PollTimeout: *pollTimeout,
		ExpectedIssuer: *issuer, ClientID: *clientID, RedirectURI: *redirectURI,
		Scopes: splitScope(*scope), AdminBasePath: *adminBasePath,
		DeviceConfirmURL: *deviceConfirm,
		ResourceClientID: *resourceClientID,
		Audience:         *audience,
	}
	if *audience != "" {
		config.Resources = []string{*audience}
	}
	if *resourceSecretFile != "" {
		value, readErr := loginte2e.LoadClientSecretFile(*resourceSecretFile)
		if readErr != nil {
			fmt.Fprintln(stderr, "错误: 读取资源服务密钥文件失败:", readErr)
			return loginte2e.ExitUsage
		}
		config.ResourceClientSecret = value
	}
	if *clientSecret != "" {
		value, err := loginte2e.LoadClientSecretFile(*clientSecret)
		if err != nil {
			fmt.Fprintln(stderr, "错误: 读取客户端密钥文件失败:", err)
			return loginte2e.ExitUsage
		}
		config.ClientSecret = value
	}
	if *sessionCookieFile != "" {
		value, err := loginte2e.LoadSessionSecretFile(*sessionCookieFile, "")
		if err != nil {
			fmt.Fprintln(stderr, "错误: 读取会话 Cookie 文件失败:", err)
			return loginte2e.ExitUsage
		}
		config.SessionSecret = value
	}
	if *adminSessionFile != "" {
		value, err := loginte2e.LoadAdminSessionSecretFile(*adminSessionFile)
		if err != nil {
			fmt.Fprintln(stderr, "错误: 读取管理会话文件失败:", err)
			return loginte2e.ExitUsage
		}
		config.AdminSessionSecret = value
	}

	client, err := loginte2e.New(config)
	if err != nil {
		fmt.Fprintln(stderr, "错误:", err)
		return exitCodeForError(err)
	}
	if strings.HasPrefix(strings.ToLower(config.Server), "http://") {
		fmt.Fprintln(stderr, "警告: 使用本机回环明文 HTTP，仅限测试；真实部署请使用 https。")
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout(suite, *timeout, *pollTimeout))
	defer cancel()
	report, runErr := client.Run(ctx, suite)
	if report != nil {
		if *jsonOutput {
			printJSON(stdout, report, runErr)
		} else {
			printHuman(stdout, report)
		}
	}
	if runErr != nil {
		fmt.Fprintln(stderr, "测试无法继续:", runErr)
		code := exitCodeForError(runErr)
		if code == loginte2e.ExitUnavailable {
			return code
		}
		return code
	}
	fmt.Fprintln(stderr, "提示: 本工具仅用于测试/验收；会话秘密与令牌不写入输出。")
	return report.ExitCode()
}

// splitArguments 把命令行拆成“开关参数”和“位置参数”，允许开关出现在套件名
// 前后（Go 标准 flag 包默认只解析位置参数之前的开关）。
type argumentSplit struct {
	flags      []string
	positional []string
}

// splitArguments 按 FlagSet 的开关定义识别哪些开关需要取值，保留参数原样顺序。
func splitArguments(flags *flag.FlagSet, args []string) (argumentSplit, error) {
	needsValue := map[string]bool{}
	flags.VisitAll(func(item *flag.Flag) {
		if boolean, ok := item.Value.(interface{ IsBoolFlag() bool }); ok &&
			boolean.IsBoolFlag() {
			needsValue[item.Name] = false
			return
		}
		needsValue[item.Name] = true
	})
	var split argumentSplit
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			split.positional = append(split.positional, args[index+1:]...)
			break
		}
		if len(argument) > 1 && argument[0] == '-' {
			split.flags = append(split.flags, argument)
			name := strings.TrimLeft(argument, "-")
			if cut := strings.Index(name, "="); cut >= 0 {
				continue
			}
			if needsValue[name] {
				index++
				if index < len(args) {
					split.flags = append(split.flags, args[index])
				}
			}
			continue
		}
		split.positional = append(split.positional, argument)
	}
	return split, nil
}

// splitScope 把逗号/空格分隔的 scope 规范化为切片。
func splitScope(raw string) []string {
	normalized := strings.ReplaceAll(raw, ",", " ")
	return strings.Fields(normalized)
}

// totalTimeout 给整个运行一个外部上限：单套件按请求数与轮询预算估算，all 放大。
func totalTimeout(suite string, timeout, pollTimeout time.Duration) time.Duration {
	base := timeout * 60
	if pollTimeout > base {
		base = pollTimeout * 3
	}
	if suite == loginte2e.SuiteAll {
		base *= 3
	}
	if base < 2*time.Minute {
		base = 2 * time.Minute
	}
	return base
}

// exitCodeForError 把错误映射为稳定退出码。
func exitCodeForError(err error) int {
	switch {
	case errors.Is(err, loginte2e.ErrConfigInvalid):
		return loginte2e.ExitUsage
	case errors.Is(err, loginte2e.ErrUnavailable):
		return loginte2e.ExitUnavailable
	default:
		return loginte2e.ExitFail
	}
}

// printJSON 输出 JSON 报告；运行错误只以 error 字段出现（不回显秘密）。
func printJSON(writer io.Writer, report *loginte2e.Report, runErr error) {
	payload := struct {
		*loginte2e.Report
		Error string `json:"error,omitempty"`
	}{Report: report}
	if runErr != nil {
		payload.Error = runErr.Error()
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&payload); err != nil {
		fmt.Fprintln(os.Stderr, "错误: 输出 JSON 报告失败:", err)
	}
}

// printHuman 输出人类可读报告（每行一条用例，详情已脱敏）。
func printHuman(writer io.Writer, report *loginte2e.Report) {
	fmt.Fprintf(writer, "loginte2e v%s | 目标 %s | 套件 %s | 开始 %s\n",
		version, report.Server, report.Suite, report.StartedAt)
	for _, result := range report.Results {
		label := "[PASS]"
		switch result.Status {
		case loginte2e.StatusFail:
			label = "[FAIL]"
		case loginte2e.StatusSkip:
			label = "[SKIP]"
		}
		line := fmt.Sprintf("%s %s/%s", label, result.Suite, result.Case)
		if result.Detail != "" {
			line += " — " + result.Detail
		}
		fmt.Fprintln(writer, line)
	}
	fmt.Fprintf(writer, "汇总: 通过 %d，失败 %d，跳过 %d，耗时 %dms\n",
		report.Summary.Pass, report.Summary.Fail, report.Summary.Skip, report.DurationMS)
}
