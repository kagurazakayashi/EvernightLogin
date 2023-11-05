// 本文件把盘点与核对结果渲染为两种机器/人可读产物：
//   - capability-matrix.json：机器可读能力清单（能力 → 分层证据 → 状态 → 未覆盖项）；
//   - capability-matrix.md：人类可读摘要（同一份数据生成，不手写）。
package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

// matrixSchema 是能力清单 JSON 的格式版本。
const matrixSchema = "evernight.capability-matrix/v1"

// metadata 记录生成时的基线与环境事实，便于审计引用。
type metadata struct {
	GeneratedAt       string   `json:"generated_at"`
	Generator         string   `json:"generator"`
	RepoRoot          string   `json:"repo_root"`
	GitHead           string   `json:"git_head"`
	GitBranch         string   `json:"git_branch"`
	GitDirty          bool     `json:"git_dirty"`
	GoVersion         string   `json:"go_version"`
	Platform          string   `json:"platform"`
	Arch              string   `json:"arch"`
	LogicalCPUs       int      `json:"logical_cpus"`
	ConcurrencyBudget int      `json:"concurrency_budget"`
	CatalogPath       string   `json:"catalog_path"`
	ScanScope         []string `json:"scan_scope"`
	FilesScanned      int      `json:"files_scanned"`
}

// summary 是状态汇总。
type summary struct {
	Total               int            `json:"total"`
	Implemented         int            `json:"implemented"`
	ImplementedUntested int            `json:"implemented_untested"`
	Missing             int            `json:"missing"`
	Unimplemented       int            `json:"unimplemented"`
	ByStatus            map[string]int `json:"by_status"`
	MatchedTestsTotal   int            `json:"matched_tests_total"`
}

// inventories 是盘点到的生产面原始清单（机器可直接消费）。
type inventories struct {
	AppTypes          map[string]*appSymbol `json:"app_types"`
	AppFuncs          []string              `json:"app_funcs"`
	AppVars           []string              `json:"app_vars"`
	RootTypes         []string              `json:"root_types"`
	RootFuncs         []string              `json:"root_funcs"`
	AdminRoutes       []routeEntry          `json:"admin_routes"`
	ProtocolPaths     []protocolPath        `json:"protocol_paths"`
	ProtocolEndpoints []protocolEndpoint    `json:"protocol_endpoint_table"`
	Pages             []pageRoute           `json:"pages"`
	CLI               []cliCommand          `json:"cli"`
	Permissions       []permissionDef       `json:"permissions"`
	Roles             []string              `json:"preset_roles"`
	Groups            []string              `json:"preset_groups"`
	TestsByPackage    map[string][]string   `json:"tests_by_package"`
}

// matrixReport 是 capability-matrix.json 的顶层结构。
type matrixReport struct {
	Schema          string             `json:"schema"`
	Description     string             `json:"description"`
	Metadata        metadata           `json:"metadata"`
	Summary         summary            `json:"summary"`
	Capabilities    []capabilityResult `json:"capabilities"`
	Coverage        coverageReport     `json:"coverage"`
	PaginationAudit paginationAudit    `json:"pagination_audit"`
	Inventories     inventories        `json:"inventories"`
	Warnings        []string           `json:"warnings,omitempty"`
}

// buildSummary 汇总能力状态。
func buildSummary(results []capabilityResult) summary {
	summary := summary{ByStatus: map[string]int{}}
	for _, result := range results {
		summary.Total++
		summary.ByStatus[result.Status]++
		summary.MatchedTestsTotal += len(result.MatchedTests)
		switch result.Status {
		case "implemented":
			summary.Implemented++
		case "implemented_untested":
			summary.ImplementedUntested++
		case "missing":
			summary.Missing++
		case "unimplemented":
			summary.Unimplemented++
		}
	}
	return summary
}

// buildReport 组装完整清单。
func buildReport(root, catalogPath string, catalog *catalogFile, inv *inventory,
	results []capabilityResult, warnings []string, generatedAt time.Time) matrixReport {
	head, branch, dirty := readGitState(root)
	budget := runtime.NumCPU() / 2
	if budget < 1 {
		budget = 1
	}
	return matrixReport{
		Schema:      matrixSchema,
		Description: "EvernightLogin 本轮机器可读能力清单：由 scripts/capabilities 扫描源码生成，状态由声明面是否真实解析决定，禁止手写全绿。",
		Metadata: metadata{
			GeneratedAt:       generatedAt.UTC().Format(time.RFC3339),
			Generator:         "go run ./scripts/capabilities",
			RepoRoot:          ".",
			GitHead:           head,
			GitBranch:         branch,
			GitDirty:          dirty,
			GoVersion:         runtime.Version(),
			Platform:          runtime.GOOS,
			Arch:              runtime.GOARCH,
			LogicalCPUs:       runtime.NumCPU(),
			ConcurrencyBudget: budget,
			CatalogPath:       catalogPath,
			ScanScope: []string{
				"根包 package login(非测试)",
				"app/",
				"cmd/",
				"internal/",
				"测试函数（根、app、internal、cmd 的 *_test.go）",
			},
			FilesScanned: inv.FilesScanned,
		},
		Summary:         buildSummary(results),
		Capabilities:    results,
		Coverage:        computeCoverage(catalog, inv),
		PaginationAudit: buildPaginationAudit(root, catalog, inv),
		Inventories: inventories{
			AppTypes:          inv.AppTypes,
			AppFuncs:          inv.AppFuncs,
			AppVars:           inv.AppVars,
			RootTypes:         inv.RootTypes,
			RootFuncs:         inv.RootFuncs,
			AdminRoutes:       inv.AdminRoutes,
			ProtocolPaths:     inv.ProtocolPaths,
			ProtocolEndpoints: inv.ProtocolEnds,
			Pages:             inv.Pages,
			CLI:               inv.CLI,
			Permissions:       inv.Permissions,
			Roles:             inv.Roles,
			Groups:            inv.Groups,
			TestsByPackage:    inv.TestsByPackage,
		},
		Warnings: warnings,
	}
}

// writeJSON 写出带缩进的机器可读清单。
func writeJSON(path string, report matrixReport) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFile(path, raw)
}

// writeMarkdown 由同一份数据生成人类可读清单。
func writeMarkdown(path string, report matrixReport) error {
	var builder strings.Builder
	builder.WriteString("# EvernightLogin 机器可读能力清单\n\n")
	builder.WriteString("> 本文件由 `go run ./scripts/capabilities` 从源码与能力声明自动生成，")
	builder.WriteString("**不要手工编辑**。状态由「声明面是否在源码中真实解析到」决定，")
	builder.WriteString("不是文档声称。\n\n")
	builder.WriteString("## 生成基线\n\n")
	builder.WriteString("| 项 | 值 |\n|---|---|\n")
	fmt.Fprintf(&builder, "| 生成时间（UTC） | %s |\n", report.Metadata.GeneratedAt)
	fmt.Fprintf(&builder, "| 仓库 | %s |\n", report.Metadata.RepoRoot)
	fmt.Fprintf(&builder, "| Git HEAD / 分支 | `%s` / `%s`%s |\n",
		report.Metadata.GitHead, report.Metadata.GitBranch, dirtyText(report.Metadata.GitDirty))
	fmt.Fprintf(&builder, "| 工具链 / 平台 | %s / %s/%s |\n",
		report.Metadata.GoVersion, report.Metadata.Platform, report.Metadata.Arch)
	fmt.Fprintf(&builder, "| 逻辑处理器 / 并发预算 | %d / %d |\n",
		report.Metadata.LogicalCPUs, report.Metadata.ConcurrencyBudget)
	fmt.Fprintf(&builder, "| 能力声明 | `%s` |\n", report.Metadata.CatalogPath)
	fmt.Fprintf(&builder, "| 扫描文件数 | %d |\n\n", report.Metadata.FilesScanned)
	builder.WriteString("复跑命令（根目录，Windows PowerShell 示例）：\n\n")
	builder.WriteString("```powershell\n$env:GOTOOLCHAIN='local'\n$env:GOMAXPROCS='2'\n")
	builder.WriteString("go run ./scripts/capabilities -strict\n```\n\n")

	builder.WriteString("## 状态汇总\n\n")
	builder.WriteString("| 状态 | 数量 | 含义 |\n|---|---|---|\n")
	statusMeaning := map[string]string{
		"implemented":          "声明面全部在源码中解析到，且有定向测试证据",
		"implemented_untested": "声明面全部解析到，但缺少可核验的定向测试证据（未测，不是已完成）",
		"missing":              "至少一个声明面/测试/缺口证据未解析到（未实现或文档超前）",
		"unimplemented":        "已知未实现能力，缺口证据已核验（不得当作可用能力）",
	}
	for _, status := range []string{"implemented", "implemented_untested", "missing", "unimplemented"} {
		fmt.Fprintf(&builder, "| `%s` | %d | %s |\n",
			status, report.Summary.ByStatus[status], statusMeaning[status])
	}
	fmt.Fprintf(&builder, "| 合计 | %d | 定向测试证据 %d 条 |\n\n",
		report.Summary.Total, report.Summary.MatchedTestsTotal)

	builder.WriteString("## 能力矩阵\n\n")
	builder.WriteString("列值为「已解析/声明总数」；`-` 表示该层未声明。\n\n")
	builder.WriteString("| 能力 | 领域 | 状态 | 内部服务 | 公开 Go | 根包 | 管理 API | 协议 | CLI | 页面 | 权限 | 分页 | 定向测试 |\n")
	builder.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, result := range report.Capabilities {
		pagination := "-"
		if result.Pagination != nil {
			pagination = result.Pagination.Mode
		}
		fmt.Fprintf(&builder, "| `%s` %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			result.ID, result.Title, result.Domain, result.Status,
			layerCounts(result, "internal_service"), layerCounts(result, "app_api"),
			layerCounts(result, "root_api"), layerCounts(result, "admin_route"),
			layerCounts(result, "protocol_path"), layerCounts(result, "cli"),
			layerCounts(result, "page"), layerCounts(result, "permission"),
			pagination, testCountText(len(result.MatchedTests)))
	}

	builder.WriteString("\n### 声明面明细（逐项 found/total）\n\n")
	for _, result := range report.Capabilities {
		var parts []string
		for _, surface := range result.Surfaces {
			if surface.Total == 0 {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %d/%d", surface.Kind, surface.Found, surface.Total))
		}
		tests := "无"
		if len(result.MatchedTests) > 0 {
			tests = fmt.Sprintf("%d", len(result.MatchedTests))
		}
		parts = append(parts, "matched_tests "+tests)
		fmt.Fprintf(&builder, "- `%s`: %s\n", result.ID, strings.Join(parts, ", "))
	}
	builder.WriteString("\n")

	builder.WriteString("\n### 未关闭项（missing / unimplemented）\n\n")
	anyOpen := false
	for _, result := range report.Capabilities {
		if result.Status != "missing" && result.Status != "unimplemented" {
			continue
		}
		anyOpen = true
		fmt.Fprintf(&builder, "- **%s**（%s）：%s\n", result.ID, result.Status, result.Title)
		for _, item := range result.Missing {
			fmt.Fprintf(&builder, "  - 未解析声明: `%s`\n", item)
		}
		for _, item := range result.UnverifiedGaps {
			fmt.Fprintf(&builder, "  - 未核实缺口证据: %s\n", item)
		}
		for _, gap := range result.Gaps {
			fmt.Fprintf(&builder, "  - 已知限制: %s\n", gap.Summary)
		}
	}
	if !anyOpen {
		builder.WriteString("- 无\n")
	}

	builder.WriteString("\n## 反向覆盖（盘点到的生产面是否被能力声明覆盖）\n\n")
	coverage := report.Coverage
	builder.WriteString("| 生产面 | 盘点总数 | 未被声明覆盖 |\n|---|---|---|\n")
	coverageRows := []struct {
		name  string
		total int
		list  []string
	}{
		{"app 公开类型", coverage.AppTypesTotal, coverage.UnmappedAppTypes},
		{"管理 API 路由", coverage.AdminRoutesTotal, coverage.UnmappedAdminRoutes},
		{"协议端点点位", coverage.ProtocolPathsTotal, coverage.UnmappedProtocolPaths},
		{"页面命名路由", coverage.PagesTotal, coverage.UnmappedPages},
		{"CLI 子命令", coverage.CLITotal, coverage.UnmappedCLI},
		{"内置权限键", coverage.PermissionsTotal, coverage.UnmappedPermissions},
	}
	for _, row := range coverageRows {
		fmt.Fprintf(&builder, "| %s | %d | %d |\n", row.name, row.total, len(row.list))
	}
	builder.WriteString("\n")
	appendList := func(title string, values []string) {
		if len(values) == 0 {
			return
		}
		fmt.Fprintf(&builder, "### 未被能力声明覆盖的%s\n\n", title)
		for _, value := range values {
			fmt.Fprintf(&builder, "- `%s`\n", value)
		}
		builder.WriteString("\n")
	}
	appendList("app 公开类型", coverage.UnmappedAppTypes)
	appendList("管理 API 路由", coverage.UnmappedAdminRoutes)
	appendList("协议端点点位", coverage.UnmappedProtocolPaths)
	appendList("页面命名路由", coverage.UnmappedPages)
	appendList("CLI 子命令", coverage.UnmappedCLI)
	appendList("内置权限键", coverage.UnmappedPermissions)

	builder.WriteString("## 分页审计\n\n")
	builder.WriteString("自动盘点 app 公开可增长列表的请求/结果边界，并核对各入口分页参数。")
	builder.WriteString("`offset`/`cursor` 能力必须有“请求边界 + 结果继续”成对证据；")
	builder.WriteString("`fixed`/`none` 与 `continuation=gap` 例外必须写明理由。\n\n")
	audit := report.PaginationAudit
	builder.WriteString("### 跨入口分页参数\n\n")
	builder.WriteString("| 入口 | 默认页大小 | 最大页大小 | offset 上限 | 备注 |\n|---|---|---|---|---|\n")
	fmt.Fprintf(&builder, "| app 公开契约 | %d | %d | %d | 权威值 |\n",
		audit.Contract.AppDefaultLimit, audit.Contract.AppMaxLimit, audit.Contract.AppMaxOffset)
	fmt.Fprintf(&builder, "| internal/session | %d | %d | - | 领域列表 |\n",
		audit.Contract.SessionDefaultLimit, audit.Contract.SessionMaxLimit)
	fmt.Fprintf(&builder, "| internal/authz | %d | %d | - | 授权列表 |\n",
		audit.Contract.AuthzDefaultLimit, audit.Contract.AuthzMaxLimit)
	fmt.Fprintf(&builder, "| loginctl 列表 | %d | %d | %d | CLI 帮助/参数 |\n",
		audit.Contract.CLIDefaultLimit, audit.Contract.CLIMaxLimit, audit.Contract.CLIOffsetCap)
	fmt.Fprintf(&builder, "| 管理页面列表 | %d（固定） | - | %d | 页面固定每页，无 limit 参数 |\n\n",
		audit.Contract.PageFixedLimit, audit.Contract.PageOffsetCap)
	builder.WriteString("### 可增长列表盘点\n\n")
	builder.WriteString("| 类型 | 类别 | 有界 | 能力 | 声明模式 | 继续字段 |\n|---|---|---|---|---|---|\n")
	for _, list := range audit.GrowableLists {
		bounded := "否"
		if list.Bounded {
			bounded = "是"
		}
		capability := list.Capability
		if capability == "" {
			capability = "-"
		}
		continuation := strings.Join(list.ContinuationFields, ",")
		if continuation == "" {
			continuation = "-"
		}
		fmt.Fprintf(&builder, "| `%s` | %s | %s | %s | %s | %s |\n",
			list.Name, list.Kind, bounded, capability, list.ClaimMode, continuation)
	}
	builder.WriteString("\n")
	appendPaginationList := func(title string, values []string) {
		if len(values) == 0 {
			return
		}
		fmt.Fprintf(&builder, "### %s\n\n", title)
		for _, value := range values {
			fmt.Fprintf(&builder, "- %s\n", value)
		}
		builder.WriteString("\n")
	}
	appendPaginationList("分页例外（fixed/none 或 continuation=gap，需理由）", audit.Exceptions)
	appendPaginationList("未覆盖/无界可增长列表（-strict 失败）", audit.UncoveredLists)
	appendPaginationList("跨入口分页参数不一致（-strict 失败）", audit.ContractMismatches)
	builder.WriteString("## 扫描口径与限制\n\n")
	builder.WriteString("- 扫描范围见 JSON `metadata.scan_scope`；跳过 `.ai/`、`docs/`、`scripts/`、")
	builder.WriteString("`web/`、`migrations/`、`dist/`、`data/`，以及 `EvernightMail/`、`go-build-all/`、")
	builder.WriteString("`examples/` 等嵌套 Module。\n")
	builder.WriteString("- 页面路由从 `UIRoute` 复合字面量盘点；动态生成或宿主替换的路由不在静态清单内。\n")
	builder.WriteString("- 协议端点表来自 `internal/protocolapi/doc.go` 的端点文档表；")
	builder.WriteString("点位常量来自 `protocolapi.go`。文档表与代码漂移会体现为声明无法解析。\n")
	builder.WriteString("- 测试证据按「包路径 + 测试函数名前缀」解析，仅证明存在定向测试函数，")
	builder.WriteString("不证明该测试当前通过；通过性需另行执行 `go test`（领域短测试可登记到统一入口")
	builder.WriteString(" `scripts/shorttest.ps1`，见 `docs/acceptance/shorttest.md`）。\n")
	if len(report.Warnings) > 0 {
		builder.WriteString("\n## 扫描警告\n\n")
		for _, warning := range report.Warnings {
			fmt.Fprintf(&builder, "- %s\n", warning)
		}
	}
	builder.WriteString("\n## 原始清单\n\n")
	builder.WriteString("机器可读原始盘点（app 公开面、管理路由、协议点位、页面路由、CLI、权限、测试）")
	builder.WriteString("见同目录 `capability-matrix.json` 的 `inventories` 字段。\n")
	return writeFile(path, []byte(builder.String()))
}

// layerCounts 汇总某类声明面的 found/total。
func layerCounts(result capabilityResult, kind string) string {
	for _, surface := range result.Surfaces {
		if surface.Kind == kind {
			if surface.Total == 0 {
				return "-"
			}
			if surface.Found == surface.Total {
				return fmt.Sprintf("%d", surface.Total)
			}
			return fmt.Sprintf("%d/%d", surface.Found, surface.Total)
		}
	}
	return "-"
}

// testCountText 渲染测试数量。
func testCountText(count int) string {
	if count == 0 {
		return "无"
	}
	return fmt.Sprintf("%d", count)
}

// dirtyText 渲染工作树状态。
func dirtyText(dirty bool) string {
	if dirty {
		return "（工作树含未提交修改）"
	}
	return "（工作树干净）"
}

// statusOrder 用于稳定排序输出。
func statusOrder(status string) int {
	switch status {
	case "missing":
		return 0
	case "unimplemented":
		return 1
	case "implemented_untested":
		return 2
	default:
		return 3
	}
}

// sortCapabilityResults 按状态严重度与 id 稳定排序，便于审计先看问题项。
func sortCapabilityResults(results []capabilityResult) {
	sort.SliceStable(results, func(i, j int) bool {
		left, right := statusOrder(results[i].Status), statusOrder(results[j].Status)
		if left != right {
			return left < right
		}
		return results[i].ID < results[j].ID
	})
}
