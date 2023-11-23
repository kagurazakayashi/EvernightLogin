// Command embedded-minimal 是 EvernightLogin 的最小可运行嵌入示例（真实外部 Go Module）。
//
// 本目录有自己的 go.mod，并通过 replace 指向仓库根；源码只导入公开包
// github.com/kagurazakayashi/EvernightLogin（包名 login）与 .../app。Go 的 internal
// 规则禁止本模块之外导入仓库的 internal/ 包，因此本示例能够编译并运行，本身就证明
// 公开装配 API 没有泄漏内部类型、也不需要复制内部实现。
//
// 两种显式运行方式（默认什么也不做，只打印用法）：
//
//	go run . -self-test -json
//	    有界自检（无人值守）：临时目录 + 真实临时 SQLite + 127.0.0.1 动态回环端口，
//	    覆盖打开实例（StateNew）→ 受控本地初始化管理员 → 公开注册合成用户 →
//	    登录失败/成功 → 会话校验与撤销 → HTTP/UI 挂载与页面（CSRF/未认证拒绝）→
//	    宿主受保护业务路由（用公开 Sessions.Validate 校验会话）→ 显式 Start/Ready/
//	    幂等 Close → 删除临时数据目录。stdout 只输出一行 JSON 结果；退出码
//	    0=全部通过，1=存在失败。
//
//	go run . -demo
//	    显式启动演示：把已装配的 HTTP/UI 挂到宿主自己的 http.Server（默认 127.0.0.1
//	    动态端口），打印访问地址与临时演示账户的凭据文件位置；Ctrl+C（或 -duration
//	    到期）后有序关闭 HTTP 服务、运行时并删除临时数据目录。演示模式不会常驻，
//	    也不会把本地管理员（LocalAdmin）暴露给任何 HTTP 请求。
//
// 资源所有权（与 docs/embedding/host_integration.md 的硬约束一致）：
//   - 示例自己创建、自己删除临时数据目录（重复运行不污染旧数据）；
//   - app.Runtime.Close 只关闭运行时自己打开的 SQLite/主密钥/后台任务，不关闭宿主
//     拥有的对象；HTTP 监听器与 http.Server 归示例所有，由示例显式 Shutdown；
//   - 示例不提供、也不调用任何“跳过认证/伪造会话”的入口：受保护路由一律经公开
//     Sessions.Validate 判定，管理员由受控本地初始化流程建立（不经 HTTP）。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// selfTestResultSchema 是自检 JSON 结果的格式版本（脚本按它解析）。
const selfTestResultSchema = "evernight.embedded-minimal.selftest/v1"

// usageText 是默认模式打印的用法说明（不执行任何业务动作）。
const usageText = `EvernightLogin 最小嵌入示例（真实外部 Go Module，只导入公开包）

用法（默认不执行任何动作）：
  go run . -self-test -json          有界自检：输出单行 JSON 结果，退出码 0/1
  go run . -self-test                有界自检：输出人类可读摘要
  go run . -demo                     显式启动演示（默认 127.0.0.1 动态端口）
  go run . -demo -duration 30s       演示最多运行 30 秒后自动清理退出
  go run . -demo -keep-data          退出时保留临时 SQLite 数据目录（便于排查）

一键自检（测试入口统一负责临时目录/总超时/子进程退出/清理，并输出 JSON）：
  pwsh -NoProfile -File scripts/shorttest.ps1 -Scenario embedded-minimal-selftest

说明：自检与演示都使用真实临时 SQLite 与真实动态回环端口；示例不访问外网，
结束时删除自己的临时数据目录。`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run 解析参数并分派模式；返回进程退出码。
func run(args []string) int {
	flags := flag.NewFlagSet("embedded-minimal", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	selfTest := flags.Bool("self-test", false, "运行有界自检并输出结构化结果")
	jsonOutput := flags.Bool("json", false, "自检模式 stdout 只输出单行 JSON 结果")
	demo := flags.Bool("demo", false, "显式启动演示（挂载 HTTP/UI 与宿主路由）")
	duration := flags.Duration("duration", 0, "演示模式最长运行时间；0 表示直到 Ctrl+C")
	timeout := flags.Duration("timeout", 90*time.Second, "自检模式内部总超时（上下期限）")
	keepData := flags.Bool("keep-data", false, "演示模式退出时保留临时数据目录")
	flags.Usage = func() { fmt.Fprint(flags.Output(), usageText+"\n") }
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case *selfTest && *demo:
		fmt.Fprintln(os.Stderr, "参数错误：-self-test 与 -demo 不能同时使用")
		return 2
	case *selfTest:
		if *keepData {
			fmt.Fprintln(os.Stderr, "参数错误：-keep-data 只用于演示模式；自检必须自清理")
			return 2
		}
		return runSelfTestCommand(*jsonOutput, *timeout)
	case *demo:
		return runDemoCommand(*duration, *keepData)
	default:
		flags.Usage()
		return 0
	}
}

// runSelfTestCommand 执行一次有界自检并输出结果（JSON 或人类摘要）。
func runSelfTestCommand(jsonOutput bool, timeout time.Duration) int {
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	report := executeSelfTest(ctx)
	report.DurationMS = time.Since(startedAt).Milliseconds()
	if jsonOutput {
		if err := writeSelfTestJSON(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, "输出自检 JSON 失败:", err)
			return 1
		}
	} else {
		printSelfTestSummary(os.Stdout, report)
	}
	if report.Status == "PASS" {
		return 0
	}
	return 1
}

// runDemoCommand 显式启动演示，直到 Ctrl+C 或 -duration 到期后清理退出。
func runDemoCommand(duration time.Duration, keepData bool) int {
	host, err := openHost(context.Background(), "demo", true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "演示启动失败:", err)
		return 1
	}
	// 演示保留数据目录选项由清理阶段使用。
	host.keepData = keepData
	cleanup := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return host.shutdown(shutdownCtx)
	}
	// 显式启动：Open 本身不启动任何后台任务。
	if startErr := host.start(context.Background()); startErr != nil {
		_ = cleanup()
		fmt.Fprintln(os.Stderr, "演示启动运行时失败:", startErr)
		return 1
	}
	// 演示至少运行 1 秒，避免 -duration 过小导致资源还没来得及关闭就退出。
	runDuration := duration
	if runDuration != 0 && runDuration < time.Second {
		runDuration = time.Second
	}
	waitCtx, stop := demoWaitContext(runDuration)
	defer stop()
	fmt.Println("EvernightLogin 最小嵌入示例已启动（演示模式，仅本机回环监听）：")
	fmt.Println("  登录页：        ", host.url(httpPrefix+"/login"))
	fmt.Println("  注册页：        ", host.url(httpPrefix+"/register"))
	fmt.Println("  宿主健康检查：  ", host.url("/healthz"))
	fmt.Println("  宿主受保护路由：", host.url("/api/whoami"), "（需要宿主会话 Cookie；未认证时应 401）")
	fmt.Println("  临时数据目录：  ", host.dataDir, "（退出时删除，-keep-data 可保留）")
	fmt.Println("  演示账户：      ", host.user.Username, "；密码见", host.credentialsPath,
		"（随临时目录删除）")
	fmt.Println("  说明：本地管理员只由受控初始化流程建立，不通过任何 HTTP 参数提供；按 Ctrl+C 结束。")
	<-waitCtx.Done()
	if waitCtx.Err() == context.DeadlineExceeded {
		fmt.Println("演示时间到，开始清理。")
	} else {
		fmt.Println("收到中断信号，开始清理。")
	}
	if err := cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, "演示清理失败:", err)
		return 1
	}
	if keepData {
		fmt.Println("演示已停止；按 -keep-data 保留了临时数据目录:", host.dataDir)
	} else {
		fmt.Println("演示已停止：HTTP 服务已关闭、运行时已释放、临时数据目录已删除。")
	}
	return 0
}
