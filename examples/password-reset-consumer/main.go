// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 第 10 轮步骤 211：新公开找回接口的外部消费回归。
//
// 本程序是**真正独立的 Go Module**（自带 go.mod，replace 指向父仓库），只导入公开包
// `github.com/kagurazakayashi/EvernightLogin` 与 `/app`，不导入任何 internal 包：
//
//  1. 启动真实 EvernightMail 子进程作为本地收信端（临时 YAML/回环端口/临时数据）；
//  2. 用 `app.Open` 打开临时 SQLite + 真实邮件运行时 + 嵌入式 HTTP 页面；
//  3. 通过公开页面完成合成账户注册与邮箱验证，通过公开 Go 门面完成登录、TOTP 绑定、
//     找回申请、邮件链接提取、预检查（不消费）、设置新密码、旧会话失效、MFA 保留与
//     新密码 + TOTP 重新登录；
//  4. 覆盖邮件关闭、未知账户、待审核账户、邮件投递失败等拒绝/配置路径；防枚举响应
//     与管理诊断（只读 SQLite 审计行）分离；
//  5. 覆盖步骤 204/205/206 的公开门面行为（预检查不消费、弱密码失败不烧链接、旧链接
//     在改密后失效）。
//
// 安全与资源：只使用临时目录、随机回环端口、合成账户与合成密码；秘密不打印、不写
// 报告；结束时有界终止 Mail/HTTP 与运行时并删除临时目录；不访问公网、不发送真实邮件。
//
// 运行（在仓库根目录）：
//
//	go run ./examples/password-reset-consumer -mail EvernightMail\evernightmail.exe
//	EVERNIGHTMAIL_BIN=... go run ./examples/password-reset-consumer
//
// 退出码：0=无 FAIL（NOT_TESTED 会列入报告）；1=存在 FAIL；2=参数/前置错误。
// `-strict` 时 NOT_TESTED 也视为非零退出，便于后续步骤作为门禁使用。

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// cliOptions 是命令行参数。
type cliOptions struct {
	mailBin string
	workDir string
	keep    bool
	strict  bool
	verbose bool
	timeout time.Duration
	outPath string
}

func run(args []string) int {
	opts := cliOptions{}
	flags := flag.NewFlagSet("password-reset-consumer", flag.ContinueOnError)
	flags.StringVar(&opts.mailBin, "mail", "",
		"EvernightMail 二进制路径（默认 EVERNIGHTMAIL_BIN → EvernightMail/evernightmail.exe）")
	flags.StringVar(&opts.workDir, "workdir", "", "临时工作目录（默认系统 TEMP 下唯一目录）")
	flags.BoolVar(&opts.keep, "keep", false, "保留临时目录用于排查（默认结束时删除）")
	flags.BoolVar(&opts.strict, "strict", false, "NOT_TESTED 也视为失败")
	flags.BoolVar(&opts.verbose, "v", false, "输出逐步进度到 stderr")
	flags.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "总超时（含 Mail 启动与清理）")
	flags.StringVar(&opts.outPath, "out", "", "可选：把结构化结果 JSON 写入该路径")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	mailBin, err := resolveMailBinary(opts.mailBin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "前置失败:", err)
		return 2
	}
	workRoot := opts.workDir
	if workRoot == "" {
		dir, tempErr := os.MkdirTemp("", "password-reset-consumer-")
		if tempErr != nil {
			fmt.Fprintln(os.Stderr, "创建临时目录失败:", tempErr)
			return 2
		}
		workRoot = dir
	} else if mkErr := os.MkdirAll(workRoot, 0o750); mkErr != nil {
		fmt.Fprintln(os.Stderr, "创建工作目录失败:", mkErr)
		return 2
	}
	if !opts.keep {
		defer func() {
			if removeErr := os.RemoveAll(workRoot); removeErr != nil {
				fmt.Fprintln(os.Stderr, "清理临时目录失败:", removeErr)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	report := runScenario(ctx, scenarioOptions{
		MailBin: mailBin, WorkRoot: workRoot, Verbose: opts.verbose,
	})
	if opts.outPath != "" {
		if raw, marshalErr := json.MarshalIndent(report, "", "  "); marshalErr == nil {
			raw = append(raw, '\n')
			if writeErr := os.WriteFile(opts.outPath, raw, 0o644); writeErr != nil {
				fmt.Fprintln(os.Stderr, "写结果文件失败:", writeErr)
			}
		}
	}
	raw, _ := json.Marshal(report)
	fmt.Println(string(raw))
	fmt.Fprintf(os.Stderr, "结果: %s（pass=%d fail=%d not_tested=%d）；工作目录=%s\n",
		report.Status, report.Counts.Pass, report.Counts.Fail, report.Counts.NotTested, workRoot)
	if report.Counts.Fail > 0 {
		return 1
	}
	if opts.strict && report.Counts.NotTested > 0 {
		return 1
	}
	return 0
}

// resolveMailBinary 按显式参数 → EVERNIGHTMAIL_BIN → 子模块构建/既有二进制顺序定位
// EvernightMail；都不可用时返回可执行的明确错误（不静默跳过真实邮件环节）。
func resolveMailBinary(explicit string) (string, error) {
	candidates := make([]string, 0, 4)
	if strings.TrimSpace(explicit) != "" {
		candidates = append(candidates, strings.TrimSpace(explicit))
	}
	if env := strings.TrimSpace(os.Getenv("EVERNIGHTMAIL_BIN")); env != "" {
		candidates = append(candidates, env)
	}
	repoRoot, rootErr := locateRepositoryRoot()
	if rootErr == nil {
		candidates = append(candidates,
			filepath.Join(repoRoot, "EvernightMail", "evernightmail.exe"),
			filepath.Join(repoRoot, "EvernightMail", "evernightmail"))
	}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, statErr := os.Stat(absolute); statErr == nil && info.Mode().IsRegular() {
			return absolute, nil
		}
	}
	if repoRoot, rootErr := locateRepositoryRoot(); rootErr == nil {
		// 末选：在 EvernightMail 子模块源码存在时由调用方自行构建（耗时操作），这里
		// 只给出精确命令，不隐式启动长时间构建，避免把环境问题变成不可控超时。
		return "", fmt.Errorf("未找到 EvernightMail 二进制；请先构建：cd %s && "+
			"go build -trimpath -o evernightmail.exe ./cmd/evernightmail，或设置 -mail/EVERNIGHTMAIL_BIN",
			filepath.Join(repoRoot, "EvernightMail"))
	}
	return "", fmt.Errorf("未找到 EvernightMail 二进制，且无法定位父仓库根目录（请设置 -mail/EVERNIGHTMAIL_BIN）")
}

// locateRepositoryRoot 从当前工作目录向上查找含 go.mod 与 examples 目录的父仓库根。
func locateRepositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			if _, examplesErr := os.Stat(filepath.Join(dir, "examples")); examplesErr == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("未找到父仓库根目录")
		}
		dir = parent
	}
}

// scenarioOptions 是回归场景参数。
type scenarioOptions struct {
	MailBin  string
	WorkRoot string
	Verbose  bool
}

// nowUTCString 返回带毫秒的 UTC 时间串（报告元数据）。
func nowUTCString() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// checkResult 是一条场景检查结果。
type checkResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // PASS / FAIL / NOT_TESTED
	Detail string `json:"detail,omitempty"`
}

// scenarioCounts 汇总检查状态。
type scenarioCounts struct {
	Pass      int `json:"pass"`
	Fail      int `json:"fail"`
	NotTested int `json:"not_tested"`
}

// scenarioReport 是本程序的结构化结果。
type scenarioReport struct {
	Schema       string          `json:"schema"`
	Status       string          `json:"status"`
	StartedAtUTC string          `json:"started_at_utc"`
	DurationMs   int64           `json:"duration_ms"`
	GoVersion    string          `json:"go_version"`
	Platform     string          `json:"platform"`
	LogicalCPUs  int             `json:"logical_cpus"`
	Checks       []checkResult   `json:"checks"`
	Counts       scenarioCounts  `json:"counts"`
	AuditSummary []auditEvidence `json:"audit_diagnostics,omitempty"`
	Error        string          `json:"error,omitempty"`
}
