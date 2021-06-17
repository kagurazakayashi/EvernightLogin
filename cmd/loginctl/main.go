// Command loginctl 是 login 身份服务的本地管理命令入口（步骤 48 只实现
// root-recover 应急恢复命令，不实现完整 CLI）。
//
// root-recover 只允许在本地服务器上、服务停止或维护状态下运行，用于恢复被锁死的
// root：重置密码与/或两步验证因素，默认保留主登录 Passkey（需显式选择才撤销），
// 重置后 root 进入必须重新配置强认证的受限状态。命令不连接网络、不发送邮件、不启动
// 后台服务；新密码通过隐藏输入取得，绝不出现在命令行参数或日志中。
package main

import "os"

func main() {
	os.Exit(Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil))
}
