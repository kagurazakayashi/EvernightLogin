// Package cli 装配 login-server 的命令行入口。
//
// 本阶段只提供版本与帮助命令；配置加载、HTTP 监听、OAuth/OIDC 和管理接口
// 尚未实现。不带参数运行会返回明确错误，不能用固定成功返回值伪装服务可用。
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/spf13/cobra"
)

// programName 是对外显示的命令名，也是帮助和版本输出的前缀。
const programName = "login-server"

// ErrNotImplemented 表示命令入口已建立，但独立服务尚未实现。
var ErrNotImplemented = errors.New("login-server 服务功能尚未实现")

// New 构造 login-server 命令。build 用于生成 --version 输出；调用方负责
// 设置输出目的地，便于测试和嵌入其他进程。
func New(build login.BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:           programName,
		Short:         "login 身份服务（当前仅提供版本与帮助）",
		Long:          "login 身份服务的独立进程入口。\n\n当前只完成项目初始化，尚未实现配置加载、HTTP 监听、OAuth/OIDC 或管理接口。\n不带参数运行会明确失败，不会假装服务已启动。",
		Version:       build.String(),
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("%w；当前步骤只提供 --version 和 --help", ErrNotImplemented)
		},
	}
	cmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	return cmd
}

// Execute 运行命令并返回进程退出码。0 表示版本或帮助成功；1 表示失败。
// 错误写入 stderr，帮助和版本写入 stdout，便于脚本区分成功与失败。
func Execute(args []string, stdout, stderr io.Writer, build login.BuildInfo) int {
	cmd := New(build)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return 1
	}
	return 0
}
