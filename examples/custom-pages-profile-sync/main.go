// Command custom-pages-profile-sync 是第二个自包含嵌入示例：宿主自定义页面（登录/
// 注册/邮箱验证/找回/重置/资料）与 Evernight 内置页面并存挂载，并按稳定 UserID
// 同步业务侧资料投影。
//
// 本目录有自己的 go.mod，只导入公开包 github.com/kagurazakayashi/EvernightLogin
// 与 .../app；不导入仓库 internal/，也不依赖真实外部邮件服务器或前端工具链。
//
// 两种显式运行方式（默认什么也不做，只打印用法）：
//
//	go run . -self-test -json
//	    有界自检（无人值守）：临时目录 + 真实临时 SQLite + 127.0.0.1 动态回环端口 +
//	    进程内本地邮件捕获器；覆盖宿主页面并存挂载、匿名 CSRF 拒绝、注册→邮箱验证
//	    邮件→登录、资料读取/白名单更新、受控改名（错误密码拒绝 + 成功后按稳定
//	    UserID 同步业务投影）、找回密码邮件→重置密码→旧会话失效、跨用户修改拒绝、
//	    MFA 受限会话不建立宿主会话、关闭清理。stdout 只输出一行 JSON；退出码
//	    0=全部通过，1=存在失败。
//
//	go run . -demo
//	    显式启动演示：打印宿主页面与 Evernight 内置页面地址、本地邮件捕获器地址与
//	    临时数据目录；注册/找回产生的邮件可在仅演示模式注册的本地信报页查看。
//	    Ctrl+C（或 -duration 到期）后关闭 HTTP 服务、运行时与邮件捕获器，并删除
//	    临时数据目录。
//
// 资源所有权：示例创建并删除自己的临时数据目录；Evernight 运行时只关闭它自己
// 打开的 SQLite/主密钥/后台任务；宿主 HTTP 服务、宿主会话存储与本地邮件捕获器由
// 示例自己关闭。会话秘密只保存在宿主内存，不写入浏览器 Cookie、日志或文件。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// selfTestResultSchema 是自检 JSON 结果格式版本（短测试场景按它解析）。
const selfTestResultSchema = "evernight.custom-pages-profile-sync.selftest/v1"

// usageText 是默认模式打印的用法说明（不执行任何业务动作）。
const usageText = `EvernightLogin 宿主自定义页面与资料同步示例（真实外部 Go Module，只导入公开包）

用法（默认不执行任何动作）：
  go run . -self-test -json          有界自检：输出单行 JSON 结果，退出码 0/1
  go run . -self-test                有界自检：输出人类可读摘要
  go run . -demo                     显式启动演示（默认 127.0.0.1 动态端口）
  go run . -demo -duration 60s       演示最多运行 60 秒后自动清理退出
  go run . -demo -keep-data          退出时保留临时 SQLite 数据目录（便于排查）

一键自检（统一短测试入口负责临时目录/总超时/子进程退出/清理，并输出 JSON）：
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/shorttest.ps1 ` +
	`-Scenario custom-pages-profile-sync-selftest

说明：自检自动启动进程内本地邮件捕获器，走真实注册验证邮件、找回密码邮件与
密码重置流程；示例不访问外网，结束时删除自己的临时数据目录。`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run 解析参数并分派模式；返回进程退出码。
func run(args []string) int {
	flags := flag.NewFlagSet("custom-pages-profile-sync", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	selfTest := flags.Bool("self-test", false, "运行有界自检并输出结构化结果")
	jsonOutput := flags.Bool("json", false, "自检模式 stdout 只输出单行 JSON 结果")
	demo := flags.Bool("demo", false, "显式启动演示（宿主页面 + Evernight 页面并存）")
	duration := flags.Duration("duration", 0, "演示模式最长运行时间；0 表示直到 Ctrl+C")
	timeout := flags.Duration("timeout", 120*time.Second, "自检模式内部总超时（上下文期限）")
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
	report := executeSelfTest(context.Background(), timeout)
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
	host, err := openHost(context.Background(), true, keepData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "演示启动失败:", err)
		return 1
	}
	cleanup := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return host.shutdown(shutdownCtx)
	}
	if startErr := host.start(context.Background()); startErr != nil {
		_ = cleanup()
		fmt.Fprintln(os.Stderr, "演示启动运行时失败:", startErr)
		return 1
	}
	runDuration := duration
	if runDuration != 0 && runDuration < time.Second {
		runDuration = time.Second
	}
	waitCtx, stop := demoWaitContext(runDuration)
	defer stop()
	fmt.Println("EvernightLogin 宿主自定义页面与资料同步示例已启动（演示模式，仅本机回环监听）：")
	fmt.Println("  业务首页：          ", host.url("/"))
	fmt.Println("  宿主自定义登录页：  ", host.url(httpPrefix+"/login"), "（公开 Auth().Login）")
	fmt.Println("  宿主自定义注册页：  ", host.url(httpPrefix+"/register"), "（公开 Registration().RegisterAccount）")
	fmt.Println("  宿主自定义找回页：  ", host.url(httpPrefix+"/login/forgot-password"))
	fmt.Println("  宿主资料同步页：    ", host.url("/profile"), "（公开 Profile().GetProfile/UpdateProfile/ChangeUsername）")
	fmt.Println("  本地演示信报：      ", host.url("/dev/mailbox"), "（仅演示模式；注册/找回邮件在此查看）")
	fmt.Println("  Evernight 内置页面：", host.url(httpPrefix+"/home"), "、", host.url(httpPrefix+"/403"),
		"（与宿主页面并存，路由不冲突）")
	fmt.Println("  本地邮件捕获器：    ", host.sink.Addr(), "（进程内，明文回环，不访问外网）")
	fmt.Println("  临时数据目录：      ", host.dataDir, "（退出时删除，-keep-data 可保留）")
	fmt.Println("  说明：会话秘密只保存在宿主内存；页面不写日志/不写 localStorage；按 Ctrl+C 结束。")
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
		fmt.Println("演示已停止：HTTP 服务、运行时与本地邮件捕获器已关闭，临时数据目录已删除。")
	}
	return 0
}

// demoWaitContext 返回演示模式的结束信号：Ctrl+C/SIGTERM 或 duration 到期。
func demoWaitContext(duration time.Duration) (context.Context, context.CancelFunc) {
	signalCtx, stopSignal := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	if duration <= 0 {
		return signalCtx, stopSignal
	}
	timerCtx, cancelTimer := context.WithTimeout(signalCtx, duration)
	return timerCtx, func() {
		cancelTimer()
		stopSignal()
	}
}
