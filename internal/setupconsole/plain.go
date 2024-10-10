package setupconsole

// 简化文本模式（步骤277 + WS5 G1 修复）：非 TTY/管道下不使用全屏控制序列，
// 用逐行命令提供与全屏画面相同的状态检测/配置诊断/路径选择/帮助/退出能力。
//
// 所有动态文本在输出前统一经 plainText 清洗：去除 ANSI/控制字符并压成单行，
// 避免用户输入、文件名或错误文本操纵终端。

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// PlainResult 是简化模式退出原因/当前配置路径。
type PlainResult struct {
	ConfigPath string
	ExitCode   int
}

// plainText 把动态文本清洗为单行纯文本。
func plainText(text string) string {
	clean := sanitizeDisplay(text)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

// RunPlain 运行简化文本模式；EOF 等价于退出。
func RunPlain(ctx context.Context, in io.Reader, out io.Writer, configPath string) PlainResult {
	result := PlainResult{ConfigPath: strings.TrimSpace(configPath)}
	if ctx == nil {
		ctx = context.Background()
	}
	if in == nil || out == nil {
		return PlainResult{ConfigPath: result.ConfigPath, ExitCode: 1}
	}
	reader := bufio.NewReader(in)
	fmt.Fprintln(out, "EvernightLogin 本地维护控制台（简化文本模式）")
	fmt.Fprintln(out, "无需启动主服务；输入 help 查看命令。")
	if result.ConfigPath == "" {
		fmt.Fprintln(out, "提示：可用 path <login.yaml> 指定实例配置路径。")
	}
	for {
		fmt.Fprint(out, "login-setup> ")
		line, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			fmt.Fprintln(out)
			return result
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			if err != nil {
				return result
			}
			continue
		}
		command := strings.ToLower(fields[0])
		switch command {
		case "help", "h", "?":
			fmt.Fprintln(out, "命令：status 检查实例状态；validate 查看配置诊断；")
			fmt.Fprintln(out, "      path <配置文件> 指定配置路径；help 显示帮助；quit/exit 退出。")
			fmt.Fprintln(out, "检测/诊断只读，不修改配置或数据库。")
		case "path":
			if len(fields) < 2 {
				fmt.Fprintln(out, "用法：path <login.yaml 路径>")
				break
			}
			result.ConfigPath = strings.Join(fields[1:], " ")
			fmt.Fprintln(out, "配置路径已设置为："+plainText(result.ConfigPath))
		case "status", "s":
			detection := Detect(ctx, DetectOptions{ConfigPath: result.ConfigPath})
			printDetectionPlain(out, detection)
		case "validate", "config", "diag":
			report := LoadConfigReport(result.ConfigPath)
			printConfigReportPlain(out, report)
		case "quit", "exit", "q":
			return result
		default:
			fmt.Fprintln(out, "未知命令；输入 help 查看命令。")
		}
		if err != nil {
			return result
		}
	}
}

// printConfigReportPlain 输出与全屏画面相同的配置诊断模型（278）。
func printConfigReportPlain(out io.Writer, report ConfigReport) {
	fmt.Fprintf(out, "配置：%s\n", plainText(displayOr(report.Path, "（未选择）")))
	fmt.Fprintf(out, "摘要：%s\n", plainText(report.Summary))
	if report.Exists {
		fmt.Fprintf(out, "文件大小：%d 字节\n", report.Size)
	}
	if len(report.Issues) == 0 {
		fmt.Fprintln(out, "未发现配置问题。")
		return
	}
	for _, issue := range report.Issues {
		location := ""
		if issue.Line > 0 {
			location = fmt.Sprintf("第 %d 行 ", issue.Line)
		}
		field := ""
		if issue.Field != "" {
			field = "[" + plainText(issue.Field) + "] "
		}
		fmt.Fprintf(out, "  ! %s%s%s：%s\n", location, field, plainText(issue.Kind),
			plainText(issue.Detail))
		if issue.Suggestion != "" {
			fmt.Fprintf(out, "    建议：%s\n", plainText(issue.Suggestion))
		}
	}
}

// printDetectionPlain 以纯文本输出检测结果与诊断。
func printDetectionPlain(out io.Writer, detection Detection) {
	fmt.Fprintf(out, "状态：%s\n", plainText(detection.Kind.Label()))
	fmt.Fprintf(out, "摘要：%s\n", plainText(detection.Summary))
	if detection.ConfigPath != "" {
		fmt.Fprintf(out, "配置文件：%s\n", plainText(detection.ConfigPath))
	}
	if detection.DatabasePath != "" {
		fmt.Fprintf(out, "数据库：%s\n", plainText(detection.DatabasePath))
	}
	if detection.Kind == StateMigrationPending {
		fmt.Fprintf(out, "迁移：已应用 %d / 共 %d\n", detection.AppliedCount,
			detection.LatestCount)
	}
	for _, detail := range detection.Details {
		fmt.Fprintf(out, "  · %s\n", plainText(detail))
	}
	for _, issue := range detection.Issues {
		fmt.Fprintf(out, "  ! %s %s\n", plainText(issue.Kind), plainText(issue.Detail))
		if issue.Suggestion != "" {
			fmt.Fprintf(out, "    建议：%s\n", plainText(issue.Suggestion))
		}
	}
}
