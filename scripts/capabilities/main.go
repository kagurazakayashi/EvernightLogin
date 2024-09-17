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
//	go run ./scripts/capabilities -check          # 只读校验现有矩阵是否与源码一致（不写文件）
//
// 资源与安全：只读、无网络、无后台任务；读取 git 状态仅用只读命令。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	// Check 只读校验：重新生成并与现有文件逐字节比较，不写文件；不一致退出码 4。
	// 便于审计/CI 在不改动 tracked 文件的前提下确认矩阵是否与源码/声明一致。
	Check bool
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
		"存在 missing 能力、未覆盖生产面、未核实缺口/环境/子模块证据时返回非零")
	flags.BoolVar(&opts.Check, "check", false,
		"只读校验：不写文件，重新生成矩阵并与现有输出逐字节比较；不一致返回非零")
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

	checkOnly := opts.Check
	fmt.Fprintf(stdout, "能力数: %d\n", report.Summary.Total)
	for _, status := range []string{"implemented", "implemented_untested", "partial",
		"missing", "unimplemented"} {
		fmt.Fprintf(stdout, "  %-22s %d\n", status, report.Summary.ByStatus[status])
	}
	fmt.Fprintf(stdout, "正向/拒绝证据: %d/%d\n", report.Summary.PositiveEvidenceTotal,
		report.Summary.RejectionEvidenceTotal)
	fmt.Fprintf(stdout, "环境未测能力: %d；子模块/远端阻塞能力: %d\n",
		report.Summary.EnvironmentUntested, report.Summary.SubmoduleBlocked)
	fmt.Fprintf(stdout, "未覆盖生产面: %d\n", report.Coverage.UnmappedCount())
	fmt.Fprintf(stdout, "分页候选列表: %d（有界 %d）\n",
		len(report.PaginationAudit.GrowableLists), report.PaginationAudit.BoundedLists)
	fmt.Fprintf(stdout, "分页未覆盖: %d；分页参数不一致: %d\n",
		len(report.PaginationAudit.UncoveredLists),
		len(report.PaginationAudit.ContractMismatches))
	for _, warning := range report.Warnings {
		fmt.Fprintln(stderr, "警告:", warning)
	}

	// 步骤 267 审计 N-267-1：先校验后写。strict 失败时绝不写 tracked 产物，
	// 避免把失败结果覆盖成“绿表”（同类问题见 N-249-2：早期失败仍写默认清单）。
	if opts.Strict {
		if message := strictBlocker(report); message != "" {
			fmt.Fprintln(stderr, "严格模式：", message, "，退出码 3")
			return 3
		}
	}
	if checkOnly {
		mismatches, err := compareOutputs(root, opts, report)
		if err != nil {
			fmt.Fprintln(stderr, "错误：读取既有矩阵失败:", err)
			return 2
		}
		if len(mismatches) > 0 {
			for _, mismatch := range mismatches {
				fmt.Fprintln(stderr, "矩阵校验失败:", mismatch)
			}
			fmt.Fprintln(stderr, "矩阵与源码/声明不一致（或来源基线不同），退出码 4")
			return 4
		}
		fmt.Fprintf(stdout, "校验模式（不写文件）: %s / %s\n", opts.OutJSON, opts.OutMarkdown)
		fmt.Fprintln(stdout, "矩阵校验通过：现有 JSON/Markdown 与源码+声明一致")
		return 0
	}
	// 只有全部校验通过后才写出 tracked 产物。
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
	fmt.Fprintf(stdout, "输出: %s\n", opts.OutJSON)
	fmt.Fprintf(stdout, "      %s\n", opts.OutMarkdown)
	return 0
}

// strictBlocker 汇总 strict 门禁的阻断原因；空字符串表示通过。
// 该检查必须在写任何产物之前调用（步骤 267 N-267-1）。
func strictBlocker(report matrixReport) string {
	if report.Summary.Missing > 0 || report.Coverage.UnmappedCount() > 0 {
		return "存在 missing 能力或未被能力声明覆盖的生产面"
	}
	for _, result := range report.Capabilities {
		if len(result.UnverifiedGaps) > 0 || len(result.UnverifiedEnvironment) > 0 ||
			len(result.UnverifiedSubmodule) > 0 {
			return "能力 " + result.ID + " 存在未核实缺口/环境/子模块证据"
		}
	}
	if len(report.PaginationAudit.UncoveredLists) > 0 {
		return "存在未覆盖/无界的可增长列表（见 --help 或扫描报告）"
	}
	if len(report.PaginationAudit.ContractMismatches) > 0 {
		return "跨入口分页参数不一致（见扫描报告）"
	}
	return ""
}

// compareOutputs 只读比较现有矩阵与“本次重新生成”的语义内容：
//   - JSON 以解析后的结构比较，忽略易变基线（生成时间、Git HEAD/分支/脏状态）；
//   - Markdown 逐行比较，忽略生成时间/Git HEAD/逻辑处理器等易变行；
//   - 能力声明面、证据、覆盖与分页审计等语义内容必须一致，否则退出码 4。
//
// 这样矩阵可以在提交前生成，而 -check 不会因为 HEAD 前移或换机 CPU 数不同假失败；
// 真正的声明/源码漂移仍会被发现。
func compareOutputs(root string, opts options, report matrixReport) ([]string, error) {
	var mismatches []string
	expectedJSON, err := renderJSON(report)
	if err != nil {
		return nil, err
	}
	actualJSON, err := os.ReadFile(resolvePath(root, opts.OutJSON))
	if err != nil {
		mismatches = append(mismatches, opts.OutJSON+" 缺失或不可读")
	} else {
		var want, got any
		if err := json.Unmarshal(expectedJSON, &want); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(actualJSON, &got); err != nil {
			mismatches = append(mismatches, opts.OutJSON+" 不是合法 JSON")
		} else {
			deleteVolatileMetadata(want)
			deleteVolatileMetadata(got)
			if !reflect.DeepEqual(want, got) {
				mismatches = append(mismatches,
					opts.OutJSON+" 语义与本次生成不一致（需重新生成或基线不同）")
			}
		}
	}
	actualMarkdown, err := os.ReadFile(resolvePath(root, opts.OutMarkdown))
	if err != nil {
		mismatches = append(mismatches, opts.OutMarkdown+" 缺失或不可读")
	} else if !bytes.Equal(normalizeMarkdown(renderMarkdown(report)),
		normalizeMarkdown(actualMarkdown)) {
		mismatches = append(mismatches,
			opts.OutMarkdown+" 与本次生成不一致（需重新生成或基线不同）")
	}
	return mismatches, nil
}

// deleteVolatileMetadata 删除必然随运行/宿主/提交位置变化的基线字段；能力声明面、
// 证据、覆盖与分页审计等语义字段仍参与比较。
func deleteVolatileMetadata(value any) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	meta, ok := object["metadata"].(map[string]any)
	if !ok {
		return
	}
	// 易变基线字段：运行时间、Git 位置/脏状态、机器并发预算、工作树文件数（脏树与
	// 干净树不同，N-267-2）、仓库根/生成器名/声明路径（换机/换调用方式不同）。
	for _, field := range []string{"generated_at", "git_head", "git_branch", "git_dirty",
		"logical_cpus", "concurrency_budget", "files_scanned", "repo_root", "generator",
		"catalog_path"} {
		delete(meta, field)
	}
}

// normalizeMarkdown 去掉生成时间行后再比较，避免每次运行的时间戳造成假失败。
func normalizeMarkdown(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "| 生成时间（UTC） |") ||
			strings.Contains(line, "| Git HEAD / 分支 |") ||
			strings.Contains(line, "| 逻辑处理器 / 并发预算 |") ||
			strings.Contains(line, "| 仓库 |") ||
			strings.Contains(line, "| 能力声明 |") ||
			strings.Contains(line, "| 扫描文件数 |") {
			continue
		}
		filtered = append(filtered, line)
	}
	return []byte(strings.Join(filtered, "\n"))
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
