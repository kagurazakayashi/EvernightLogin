// Command login-backup 是 login 备份的本地手动触发与离线校验工具（步骤 80）。
//
// 它只在本机运行：create 子命令直接打开本地 SQLite 数据库、读取受保护主密钥环，
// 用 SQLite 在线备份 API 生成加密热备份；verify/info 子命令只读备份文件，不需要
// 启动身份服务器、不连接网络、不执行备份内脚本。创建备份以本地操作者身份写入
// 安全审计（审计落在同一数据库的 audit_events 表），因此需要操作系统层面的数据库
// 与密钥文件访问权限；它不是远程认证通道，也不是恢复工具。
//
// 稳定退出码：0 成功；1 执行失败；2 参数/用法错误；3 备份校验失败（损坏或版本不
// 支持）；4 解密失败（密钥错误或认证失败）。
package main

import "os"

func main() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}
