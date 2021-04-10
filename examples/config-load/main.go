// Command config-load 演示独立调用 login 配置加载器。
//
// 它读取 YAML、叠加 LOGIN_ 环境变量与可选显式覆盖，打印脱敏后的有效配置，
// 并在配置非法时返回非零退出码。示例不监听端口、不打开数据库、不写文件。
//
// 运行方式（在当前目录的上一级模块根目录执行）：
//
//	go run ./examples/config-load -config examples/config-load/login.example.yaml
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kagurazakayashi/EvernightLogin"
)

func main() {
	configPath := flag.String("config", "login.example.yaml", "YAML 配置文件路径")
	flag.Parse()

	cfg, err := login.Load(login.LoadOptions{
		YAMLFile: *configPath,
		// 宿主需要固定某个值时，可以传显式选项；显式 false/0 也会被保留：
		// Overrides: &login.Overrides{Database: login.DatabaseOverrides{WAL: login.Ptr(false)}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置检查失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Println("配置有效（以下为脱敏诊断；秘密只显示脱敏状态）：")
	fmt.Print(cfg.Diagnostic())
}
