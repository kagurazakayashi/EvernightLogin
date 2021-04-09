// Command login-server 是 login 身份服务的独立进程入口。
//
// 本阶段只装配版本与帮助命令，不启动 HTTP 服务、不连接数据库，也不创建
// 后台协程。服务装配和启动逻辑在后续步骤实现。
package main

import (
	"os"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr, login.CurrentBuildInfo()))
}
