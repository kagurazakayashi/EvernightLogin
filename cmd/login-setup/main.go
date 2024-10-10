// login-setup 是 EvernightLogin 的本地维护控制台入口（第12轮 277–302）。
//
// 定位：类 BIOS 的全屏 CUI，可由本机终端或已建立的 SSH 终端使用；不监听端口、
// 不新增匿名 HTTP 管理服务。启动不依赖完整生产 Runtime：无配置、坏配置、无数据库、
// 数据库不可达、结构待迁移、root 缺失都会显示状态并允许退出/后续修复。
//
// 当前（步骤277）提供：主框架、实例配置路径选择、只读状态检测、帮助与退出；
// TTY 使用全屏模式，非 TTY/管道自动降级为简化文本命令模式。
// 配置编辑/原子保存/数据库初始化/维护画面由后续 278–302 步骤接入。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/kagurazakayashi/EvernightLogin/internal/setupconsole"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "login.yaml 配置路径（默认尝试当前目录 login.yaml）")
	flag.Parse()
	if configPath == "" {
		if _, err := os.Stat("login.yaml"); err == nil {
			configPath = "login.yaml"
		}
	}
	ctx := context.Background()
	stdinFD := int(os.Stdin.Fd())
	stdoutFD := int(os.Stdout.Fd())
	if term.IsTerminal(stdinFD) && term.IsTerminal(stdoutFD) {
		terminal := setupconsole.NewANSITerminal(os.Stdin, os.Stdout)
		app := setupconsole.NewApp(terminal, configPath, nil)
		if err := app.Run(ctx); err != nil {
			// 错误只写诊断信息，不含秘密/路径内容之外的内部细节。
			fmt.Fprintln(os.Stderr, "控制台异常退出：", err)
			os.Exit(1)
		}
		return
	}
	result := setupconsole.RunPlain(ctx, os.Stdin, os.Stdout, configPath)
	os.Exit(result.ExitCode)
}
