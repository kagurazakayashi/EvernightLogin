// 无人值守短测试入口自检场景：故意超过入口总超时，用于验证
// scripts/shorttest.ps1 能强制结束子进程、清理临时目录并输出结构化 TIMEOUT 结果。
//
// 本程序不是产品能力测试，不接触产品代码与数据；正常路径下会睡眠到被入口杀掉，
// 因此不会产生 stdout JSON（入口应报告 TIMEOUT 而不是把缺失结果当成成功）。
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	seconds := flag.Int("seconds", 60, "睡眠秒数（必须大于入口超时，用于触发超时路径）")
	resultPath := flag.String("result", "", "可选：结果文件路径（自检场景通常不会走到这里）")
	flag.Parse()
	startedAt := time.Now()
	fmt.Fprintf(os.Stderr, "harness-timeout: 睡眠 %d 秒（预期被统一入口超时终止）\n", *seconds)
	time.Sleep(time.Duration(*seconds) * time.Second)
	// 只有入口超时配置错误时才会执行到这里；输出结构化结果让入口判定 FAIL。
	message := fmt.Sprintf(`{"schema":"evernight.shorttest.scenario-result/v1",`+
		`"scenario":"harness-timeout","status":"FAIL","error":"未被入口超时终止",`+
		`"duration_ms":%d}`, time.Since(startedAt).Milliseconds())
	fmt.Println(message)
	if *resultPath != "" {
		_ = os.WriteFile(*resultPath, []byte(message+"\n"), 0o644)
	}
	// 走到这里说明入口超时配置错误；必须以非零退出码显式传播失败。
	os.Exit(1)
}
