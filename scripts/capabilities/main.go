// Command capabilities 是第 10 轮步骤 203 建立的机器可读能力清单生成器。
//
// 它只读扫描仓库源码（公开 Go 接口、管理 API 路由、协议端点、页面命名路由、
// CLI 子命令、内置权限、分页字段、测试函数），再与
// scripts/capabilities/catalog.json 中的能力声明交叉核对，输出：
//
//	docs/acceptance/capability-matrix.json  机器可读能力清单
//	docs/acceptance/capability-matrix.md   同一份数据的人类可读摘要
//
// 状态不是手写的：每个声明面都必须能在源码盘点结果中解析到；解析不到的项
// 会进入 missing/未覆盖列表，`-strict` 时以非零退出码使能力清单可作门禁。
//
// 用法（在仓库根目录）：
//
//	go run ./scripts/capabilities                 # 生成 JSON/Markdown
//	go run ./scripts/capabilities -strict         # 有 missing/未核实缺口时退出码 3
//	go run ./scripts/capabilities -dump-inventory <path>  # 额外导出原始盘点
//	go run ./scripts/capabilities -out-json <path> -out-md <path>
//
// 资源与安全：只读、无网络、无后台任务；读取 git 状态仅用只读命令。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// options 是命令行参数。
type options struct {
	Root        string
	Catalog     string
	OutJSON     string
	OutMarkdown string
	DumpPath    string
	Strict      bool
}

// run 执行生成并返回进程退出码：0 成功、2 参数/读取失败、3 -strict 门禁失败。
func run(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	flags.SetOutput(stderr)
	opts := options{}
	flags.StringVar(&opts.Root, "root", ".", "仓库根目录")
	flags.StringVar(&opts.Catalog, "catalog", "scripts/capabilities/catalog.json",
		"能力声明 JSON 路径（相对仓库根）")
	flags.StringVar(&opts.OutJSON, "out-json", "docs/acceptance/capability-matrix.json",
		"机器可读能力清单输出路径（相对仓库根）")
	flags.StringVar(&opts.OutMarkdown, "out-md", "docs/acceptance/capability-matrix.md",
		"人类可读能力清单输出路径（相对仓库根）")
	flags.StringVar(&opts.DumpPath, "dump-inventory", "",
		"可选：额外导出原始盘点 JSON 的路径（相对仓库根）")
	flags.BoolVar(&opts.Strict, "strict", false,
		"存在 missing 能力、未覆盖生产面或未核实缺口时返回非零")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法: go run ./scripts/capabilities [选项]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		fmt.Fprintln(stderr, "错误：解析仓库根目录失败:", err)
		return 2
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "错误：仓库根目录不存在: %s\n", root)
		return 2
	}
	catalogPath := resolvePath(root, opts.Catalog)
	catalog, err := loadCatalog(catalogPath)
	if err != nil {
		fmt.Fprintln(stderr, "错误：", err)
		return 2
	}
	fmt.Fprintf(stdout, "扫描仓库: %s\n", root)
	inventory, warnings, err := scanRepo(root)
	if err != nil {
		fmt.Fprintln(stderr, "错误：源码盘点失败:", err)
		return 2
	}
	results := validateCapabilities(root, catalog, inventory)
	sortCapabilityResults(results)
	generatedAt := time.Now()
	report := buildReport(root, opts.Catalog, catalog, inventory, results, warnings, generatedAt)

	if err := writeJSON(resolvePath(root, opts.OutJSON), report); err != nil {
		fmt.Fprintln(stderr, "错误：写出机器可读清单失败:", err)
		return 2
	}
	if err := writeMarkdown(resolvePath(root, opts.OutMarkdown), report); err != nil {
		fmt.Fprintln(stderr, "错误：写出人类可读清单失败:", err)
		return 2
	}
	if opts.DumpPath != "" {
		if err := writeJSON(resolvePath(root, opts.DumpPath), report); err != nil {
			fmt.Fprintln(stderr, "错误：写出原始盘点失败:", err)
			return 2
		}
	}

	fmt.Fprintf(stdout, "能力数: %d\n", report.Summary.Total)
	for _, status := range []string{"implemented", "implemented_untested", "missing", "unimplemented"} {
		fmt.Fprintf(stdout, "  %-22s %d\n", status, report.Summary.ByStatus[status])
	}
	fmt.Fprintf(stdout, "未覆盖生产面: %d\n", report.Coverage.UnmappedCount())
	fmt.Fprintf(stdout, "分页候选列表: %d（有界 %d）\n",
		len(report.PaginationAudit.GrowableLists), report.PaginationAudit.BoundedLists)
	fmt.Fprintf(stdout, "分页未覆盖: %d；分页参数不一致: %d\n",
		len(report.PaginationAudit.UncoveredLists),
		len(report.PaginationAudit.ContractMismatches))
	fmt.Fprintf(stdout, "输出: %s\n", opts.OutJSON)
	fmt.Fprintf(stdout, "      %s\n", opts.OutMarkdown)
	for _, warning := range report.Warnings {
		fmt.Fprintln(stderr, "警告:", warning)
	}

	if opts.Strict {
		blocking := report.Summary.Missing > 0 || report.Coverage.UnmappedCount() > 0
		if blocking {
			fmt.Fprintln(stderr, "严格模式：存在 missing 能力或未被能力声明覆盖的生产面，退出码 3")
			return 3
		}
		for _, result := range report.Capabilities {
			if len(result.UnverifiedGaps) > 0 {
				fmt.Fprintf(stderr, "严格模式：能力 %s 存在未核实缺口证据，退出码 3\n", result.ID)
				return 3
			}
		}
		if len(report.PaginationAudit.UncoveredLists) > 0 {
			fmt.Fprintln(stderr, "严格模式：存在未覆盖/无界的可增长列表，退出码 3")
			for _, item := range report.PaginationAudit.UncoveredLists {
				fmt.Fprintln(stderr, "  -", item)
			}
			return 3
		}
		if len(report.PaginationAudit.ContractMismatches) > 0 {
			fmt.Fprintln(stderr, "严格模式：跨入口分页参数不一致，退出码 3")
			for _, item := range report.PaginationAudit.ContractMismatches {
				fmt.Fprintln(stderr, "  -", item)
			}
			return 3
		}
	}
	return 0
}

// resolvePath 把相对路径按仓库根目录解析为绝对路径。
func resolvePath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, filepath.FromSlash(path))
}

// writeFile 以 UTF-8 写出文件并在需要时创建父目录。
func writeFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// readGitState 只读读取当前提交、分支与工作树脏状态；git 不可用时返回空值。
func readGitState(root string) (head, branch string, dirty bool) {
	head = strings.TrimSpace(gitOutput(root, "rev-parse", "HEAD"))
	branch = strings.TrimSpace(gitOutput(root, "rev-parse", "--abbrev-ref", "HEAD"))
	status := gitOutput(root, "status", "--porcelain")
	dirty = strings.TrimSpace(status) != ""
	return head, branch, dirty
}

// gitOutput 只读执行 git 命令；失败时返回空字符串（不影响能力清单生成）。
func gitOutput(root string, args ...string) string {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	command := exec.Command(gitPath, append([]string{"-C", root}, args...)...)
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return ""
		}
		return ""
	}
	return string(output)
}

// 保留运行时信息供报告使用（避免编译器剔除 import）。
var _ = runtime.NumCPU
