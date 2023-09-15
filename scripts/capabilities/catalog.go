// 本文件定义机器可读能力声明（catalog）与交叉核对逻辑。
//
// 能力声明不是"全绿表"：每个声明面（公开 Go 符号、管理 API 路由、协议端点、
// CLI 子命令、页面命名路由、权限键、分页字段、测试函数）都必须能在源码盘点的
// 真实结果中解析到。解析不到即标记 missing，不允许人工把状态写成 implemented。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// catalogSchema 是本仓库能力声明的机器可读格式版本。
const catalogSchema = "evernight.capability-catalog/v1"

// catalogFile 是 scripts/capabilities/catalog.json 的顶层结构。
type catalogFile struct {
	Schema       string       `json:"schema"`
	Description  string       `json:"description"`
	Capabilities []capability `json:"capabilities"`
}

// paginationClaim 描述一个能力的分页契约及可核验证据。
//
// mode 取值：offset（Limit/Offset/HasMore）、cursor（游标）、
// fixed（固定少量枚举，允许不分页，必须写 reason）、none（单项能力，不分页）。
type paginationClaim struct {
	Mode     string   `json:"mode"`
	Reason   string   `json:"reason,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// testClaim 是一个定向测试证据：包路径 + 测试函数名前缀。
type testClaim struct {
	Package string   `json:"package"`
	Run     string   `json:"run"`
	Files   []string `json:"files,omitempty"`
}

// gapClaim 是已知未实现/受限能力的可核验证据（文件 + 必须出现的标记文本）。
type gapClaim struct {
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
}

// capability 是一项能力声明，cross-layer 记录内部服务、公开 Go 接口、HTTP、
// CLI、页面、权限、分页与定向测试路径。
type capability struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Domain           string   `json:"domain"`
	Expect           string   `json:"expect,omitempty"` // 空=已实现；unimplemented=已知未实现
	InternalServices []string `json:"internal_services,omitempty"`
	AppAPI           []string `json:"app_api,omitempty"`
	RootAPI          []string `json:"root_api,omitempty"`
	AdminRoutes      []string `json:"admin_routes,omitempty"`
	ProtocolPaths    []string `json:"protocol_paths,omitempty"`
	CLI              []string `json:"cli,omitempty"`
	Pages            []string `json:"pages,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
	// UnimplementedPermissions 是"目录中存在但代码标记 Implemented=false"的权限键；
	// 扫描器要求这些键真实存在且标记仍为 false，防止把未实现权限当可用能力。
	UnimplementedPermissions []string         `json:"unimplemented_permissions,omitempty"`
	Pagination               *paginationClaim `json:"pagination,omitempty"`
	Tests                    []testClaim      `json:"tests,omitempty"`
	Gaps                     []gapClaim       `json:"gaps,omitempty"`
	Notes                    string           `json:"notes,omitempty"`
}

// surfaceResult 记录一类声明面的核对情况。
type surfaceResult struct {
	Kind    string   `json:"kind"`
	Total   int      `json:"total"`
	Found   int      `json:"found"`
	Missing []string `json:"missing,omitempty"`
}

// capabilityResult 是一项能力的核对结果。
type capabilityResult struct {
	capability
	Status         string          `json:"status"`
	Surfaces       []surfaceResult `json:"surfaces"`
	MatchedTests   []string        `json:"matched_tests,omitempty"`
	Missing        []string        `json:"missing,omitempty"`
	GapEvidence    []gapEvidence   `json:"gap_evidence,omitempty"`
	UnverifiedGaps []string        `json:"unverified_gaps,omitempty"`
}

// gapEvidence 是一条缺口证据的核对结果。
type gapEvidence struct {
	Summary string `json:"summary"`
	File    string `json:"file"`
	Token   string `json:"token"`
	Found   bool   `json:"found"`
}

// loadCatalog 读取并做基础格式校验。
func loadCatalog(path string) (*catalogFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取能力声明失败: %w", err)
	}
	var catalog catalogFile
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, fmt.Errorf("解析能力声明失败: %w", err)
	}
	if catalog.Schema != catalogSchema {
		return nil, fmt.Errorf("能力声明 schema=%q，期望 %q", catalog.Schema, catalogSchema)
	}
	if len(catalog.Capabilities) == 0 {
		return nil, fmt.Errorf("能力声明为空")
	}
	seen := map[string]bool{}
	for index, capability := range catalog.Capabilities {
		if strings.TrimSpace(capability.ID) == "" {
			return nil, fmt.Errorf("第 %d 项能力缺少 id", index+1)
		}
		if seen[capability.ID] {
			return nil, fmt.Errorf("能力 id 重复: %s", capability.ID)
		}
		seen[capability.ID] = true
		if strings.TrimSpace(capability.Title) == "" {
			return nil, fmt.Errorf("能力 %s 缺少 title", capability.ID)
		}
		if capability.Expect != "" && capability.Expect != "unimplemented" {
			return nil, fmt.Errorf("能力 %s 的 expect=%q 非法（只允许空或 unimplemented）",
				capability.ID, capability.Expect)
		}
	}
	return &catalog, nil
}

// checkTokenEvidence 校验 "文件:标记文本" 形式的证据：文件存在且包含该文本。
func checkTokenEvidence(root, ref string) (file, token string, found bool) {
	index := strings.Index(ref, ":")
	if index <= 0 || index == len(ref)-1 {
		return ref, "", false
	}
	file = ref[:index]
	token = ref[index+1:]
	path := filepath.Join(root, filepath.FromSlash(file))
	raw, err := os.ReadFile(path)
	if err != nil {
		return file, token, false
	}
	return file, token, strings.Contains(string(raw), token)
}

// wildcardMatch 支持结尾单个 "*" 的前缀匹配；其他情况要求完全相等。
func wildcardMatch(pattern, value string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

// resolveAppAPI 核对一条 app 包公开符号声明。
// 语法：Type、Type.Member（接口方法/结构字段/接收者方法）、Func。
func resolveAppAPI(inv *inventory, ref string) bool {
	parts := strings.SplitN(ref, ".", 2)
	symbol, ok := inv.AppTypes[parts[0]]
	if ok {
		if len(parts) == 1 {
			return true
		}
		member := parts[1]
		for _, name := range symbol.Methods {
			if name == member {
				return true
			}
		}
		for _, name := range symbol.Fields {
			if name == member {
				return true
			}
		}
		return false
	}
	if len(parts) == 1 {
		for _, name := range inv.AppFuncs {
			if name == ref {
				return true
			}
		}
	}
	return false
}

// validateCapabilities 把能力声明与源码盘点交叉核对，返回逐项结果。
func validateCapabilities(root string, catalog *catalogFile, inv *inventory) []capabilityResult {
	results := make([]capabilityResult, 0, len(catalog.Capabilities))
	for _, capability := range catalog.Capabilities {
		results = append(results, validateCapability(root, capability, inv))
	}
	return results
}

// validateCapability 核对单条能力声明。
func validateCapability(root string, capability capability, inv *inventory) capabilityResult {
	result := capabilityResult{capability: capability, Status: "implemented"}
	var missing []string
	addSurface := func(kind string, total int, missingRefs []string) {
		result.Surfaces = append(result.Surfaces, surfaceResult{
			Kind: kind, Total: total, Found: total - len(missingRefs), Missing: missingRefs,
		})
		missing = append(missing, missingRefs...)
	}

	// 1) 内部服务目录必须真实存在且含生产 Go 源码。
	var missingServices []string
	for _, service := range capability.InternalServices {
		dir := filepath.Join(root, filepath.FromSlash(service))
		if !hasProductionGo(dir) {
			missingServices = append(missingServices, service)
		}
	}
	addSurface("internal_service", len(capability.InternalServices), missingServices)

	// 2) app 包公开 Go 符号。
	var missingApp []string
	for _, ref := range capability.AppAPI {
		if !resolveAppAPI(inv, ref) {
			missingApp = append(missingApp, ref)
		}
	}
	addSurface("app_api", len(capability.AppAPI), missingApp)

	// 3) 根包公开符号。
	var missingRoot []string
	for _, ref := range capability.RootAPI {
		if !containsString(inv.RootTypes, ref) && !containsString(inv.RootFuncs, ref) {
			missingRoot = append(missingRoot, ref)
		}
	}
	addSurface("root_api", len(capability.RootAPI), missingRoot)

	// 4) 管理 API 路由（支持结尾 "*" 前缀通配）。
	var missingRoutes []string
	for _, ref := range capability.AdminRoutes {
		found := false
		for _, route := range inv.AdminRoutes {
			if wildcardMatch(ref, route.bindPath()) {
				found = true
				break
			}
		}
		if !found {
			missingRoutes = append(missingRoutes, ref)
		}
	}
	addSurface("admin_route", len(capability.AdminRoutes), missingRoutes)

	// 5) 协议端点点位常量。
	var missingProtocol []string
	if len(capability.ProtocolPaths) > 0 {
		names := make([]string, 0, len(inv.ProtocolPaths))
		for _, path := range inv.ProtocolPaths {
			names = append(names, path.Name)
		}
		for _, ref := range capability.ProtocolPaths {
			if !containsString(names, ref) {
				missingProtocol = append(missingProtocol, ref)
			}
		}
	}
	addSurface("protocol_path", len(capability.ProtocolPaths), missingProtocol)

	// 6) CLI 子命令（binary:command，命令支持结尾 "*"）。
	var missingCLI []string
	for _, ref := range capability.CLI {
		parts := strings.SplitN(ref, ":", 2)
		if len(parts) != 2 {
			missingCLI = append(missingCLI, ref)
			continue
		}
		found := false
		for _, command := range inv.CLI {
			if command.Binary == parts[0] && wildcardMatch(parts[1], command.Name) {
				found = true
				break
			}
		}
		if !found {
			missingCLI = append(missingCLI, ref)
		}
	}
	addSurface("cli", len(capability.CLI), missingCLI)

	// 7) 页面命名路由（name:xxx、path:/xxx 或裸 name，均支持结尾 "*"）。
	var missingPages []string
	for _, ref := range capability.Pages {
		kind := "name"
		value := ref
		switch {
		case strings.HasPrefix(ref, "name:"):
			value = strings.TrimPrefix(ref, "name:")
		case strings.HasPrefix(ref, "path:"):
			kind = "path"
			value = strings.TrimPrefix(ref, "path:")
		}
		found := false
		for _, page := range inv.Pages {
			candidate := page.Name
			if kind == "path" {
				candidate = page.Path
			}
			if wildcardMatch(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			missingPages = append(missingPages, ref)
		}
	}
	addSurface("page", len(capability.Pages), missingPages)

	// 8) 内置权限键：普通权限必须存在；未实现权限必须存在且代码标记仍为 false。
	var missingPermissions []string
	for _, key := range capability.Permissions {
		if !permissionExists(inv, key) {
			missingPermissions = append(missingPermissions, key)
		}
	}
	addSurface("permission", len(capability.Permissions), missingPermissions)
	var unimplementedProblems []string
	for _, key := range capability.UnimplementedPermissions {
		found, implemented := permissionImplemented(inv, key)
		if !found {
			unimplementedProblems = append(unimplementedProblems, key+" (权限目录中不存在)")
		} else if implemented {
			unimplementedProblems = append(unimplementedProblems, key+" (代码已标记 Implemented=true，缺口声明过期)")
		}
	}
	addSurface("unimplemented_permission", len(capability.UnimplementedPermissions), unimplementedProblems)

	// 9) 分页契约：mode 必须已定义；offset/cursor 必须有字段证据；
	// fixed/none 必须写明理由（固定枚举不分页需有理由，见 AGENTS.md §4）。
	var paginationProblem string
	if capability.Pagination != nil {
		claim := capability.Pagination
		switch claim.Mode {
		case "offset", "cursor":
			if len(claim.Evidence) == 0 {
				paginationProblem = "分页模式 " + claim.Mode + " 缺少字段证据"
			}
			for _, ref := range claim.Evidence {
				// 分页证据支持两种形式：
				//   Type.Field           app 包公开结构的分页字段；
				//   internal/...go:token 内部服务实现中的分页标记（limit/has_more 等）。
				if strings.Contains(ref, ":") {
					if _, _, found := checkTokenEvidence(root, ref); !found {
						paginationProblem = "分页证据不存在: " + ref
						break
					}
					continue
				}
				parts := strings.SplitN(ref, ".", 2)
				symbol, ok := inv.AppTypes[parts[0]]
				if !ok || len(parts) != 2 || !containsString(symbol.Fields, parts[1]) {
					paginationProblem = "分页证据不存在: " + ref
					break
				}
			}
		case "fixed", "none":
			if strings.TrimSpace(claim.Reason) == "" {
				paginationProblem = "固定/不分页能力必须写明理由"
			}
		default:
			paginationProblem = "未知分页模式: " + claim.Mode
		}
		if paginationProblem != "" {
			missing = append(missing, "pagination: "+paginationProblem)
		}
	}

	// 10) 定向测试：包路径 + 测试函数前缀必须真实存在。
	var matchedTests []string
	var missingTests []string
	for _, claim := range capability.Tests {
		pkg := normalizePackagePath(claim.Package)
		names, ok := inv.TestsByPackage[pkg]
		if !ok {
			missingTests = append(missingTests, claim.Package+" (包不存在)")
			continue
		}
		matched := false
		for _, name := range names {
			if strings.HasPrefix(name, claim.Run) {
				matched = true
				matchedTests = append(matchedTests, pkg+":"+name)
			}
		}
		if !matched {
			missingTests = append(missingTests, claim.Package+" -run "+claim.Run)
		}
		for _, file := range claim.Files {
			path := filepath.Join(root, filepath.FromSlash(file))
			if _, err := os.Stat(path); err != nil {
				missingTests = append(missingTests, "缺少测试文件 "+file)
			}
		}
	}
	addSurface("test", len(capability.Tests), missingTests)
	result.MatchedTests = matchedTests

	// 11) 缺口证据：文件必须存在且包含标记文本。
	for _, gap := range capability.Gaps {
		for _, ref := range gap.Evidence {
			file, token, found := checkTokenEvidence(root, ref)
			result.GapEvidence = append(result.GapEvidence, gapEvidence{
				Summary: gap.Summary, File: file, Token: token, Found: found,
			})
			if !found {
				result.UnverifiedGaps = append(result.UnverifiedGaps,
					"缺口证据未核实: "+ref)
			}
		}
	}

	result.Missing = missing
	switch {
	case capability.Expect == "unimplemented":
		if len(result.UnverifiedGaps) > 0 {
			result.Status = "missing"
		} else {
			result.Status = "unimplemented"
		}
	case len(missing) > 0 || len(result.UnverifiedGaps) > 0:
		result.Status = "missing"
	case len(matchedTests) == 0:
		result.Status = "implemented_untested"
	default:
		result.Status = "implemented"
	}
	return result
}

// hasProductionGo 报告目录是否存在非测试 Go 源码。
func hasProductionGo(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			return true
		}
	}
	return false
}

// normalizePackagePath 规范化 go test 包路径（"." 表示根包）。
func normalizePackagePath(pkg string) string {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" || pkg == "." || pkg == "./" {
		return "."
	}
	pkg = strings.TrimPrefix(pkg, "./")
	return "./" + pkg
}

// containsString 报告切片中是否存在目标字符串。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// permissionExists 报告权限目录中是否存在该键。
func permissionExists(inv *inventory, key string) bool {
	_, found := permissionImplemented(inv, key)
	return found
}

// permissionImplemented 返回权限键是否存在及其代码标记的 Implemented 值。
func permissionImplemented(inv *inventory, key string) (found, implemented bool) {
	for _, permission := range inv.Permissions {
		if permission.Key == key {
			return true, permission.Implemented
		}
	}
	return false, false
}

// computeCoverage 反向核对：盘点到的生产面是否被至少一项能力声明覆盖。
// 未覆盖项是可疑的"文档未声称/能力清单遗漏"，必须显式暴露而不是隐藏。
func computeCoverage(catalog *catalogFile, inv *inventory) coverageReport {
	appClaimed := map[string]bool{}
	routeClaimed := make([]bool, len(inv.AdminRoutes))
	protocolClaimed := map[string]bool{}
	pageClaimed := make([]bool, len(inv.Pages))
	cliClaimed := make([]bool, len(inv.CLI))
	permissionClaimed := map[string]bool{}
	for _, capability := range catalog.Capabilities {
		// 未实现能力声明的"未实现权限"同样视为已覆盖：它们是登记在案的缺口，
		// 不应再被当作"文档未声称的遗漏"。
		for _, key := range capability.UnimplementedPermissions {
			permissionClaimed[key] = true
		}
		if capability.Expect == "unimplemented" {
			continue
		}
		for _, ref := range capability.AppAPI {
			parts := strings.SplitN(ref, ".", 2)
			appClaimed[parts[0]] = true
		}
		for _, ref := range capability.AdminRoutes {
			for index, route := range inv.AdminRoutes {
				if wildcardMatch(ref, route.bindPath()) {
					routeClaimed[index] = true
				}
			}
		}
		for _, ref := range capability.ProtocolPaths {
			protocolClaimed[ref] = true
		}
		for _, ref := range capability.Pages {
			kind := "name"
			value := ref
			switch {
			case strings.HasPrefix(ref, "name:"):
				value = strings.TrimPrefix(ref, "name:")
			case strings.HasPrefix(ref, "path:"):
				kind = "path"
				value = strings.TrimPrefix(ref, "path:")
			}
			for index, page := range inv.Pages {
				candidate := page.Name
				if kind == "path" {
					candidate = page.Path
				}
				if wildcardMatch(value, candidate) {
					pageClaimed[index] = true
				}
			}
		}
		for _, ref := range capability.CLI {
			parts := strings.SplitN(ref, ":", 2)
			if len(parts) != 2 {
				continue
			}
			for index, command := range inv.CLI {
				if command.Binary == parts[0] && wildcardMatch(parts[1], command.Name) {
					cliClaimed[index] = true
				}
			}
		}
		for _, key := range capability.Permissions {
			permissionClaimed[key] = true
		}
		for _, key := range capability.UnimplementedPermissions {
			permissionClaimed[key] = true
		}
	}

	report := coverageReport{}
	appTypes := make([]string, 0, len(inv.AppTypes))
	for name := range inv.AppTypes {
		appTypes = append(appTypes, name)
	}
	sort.Strings(appTypes)
	for _, name := range appTypes {
		symbol := inv.AppTypes[name]
		// 只对结构/接口/公开接收者类型做反向覆盖；纯别名不强行要求。
		if symbol.Kind == "alias" {
			continue
		}
		if !appClaimed[name] {
			report.UnmappedAppTypes = append(report.UnmappedAppTypes, name)
		}
	}
	for index, route := range inv.AdminRoutes {
		if !routeClaimed[index] {
			report.UnmappedAdminRoutes = append(report.UnmappedAdminRoutes, route.bindPath())
		}
	}
	for _, path := range inv.ProtocolPaths {
		if !protocolClaimed[path.Name] {
			report.UnmappedProtocolPaths = append(report.UnmappedProtocolPaths, path.Name)
		}
	}
	for index, page := range inv.Pages {
		if !pageClaimed[index] {
			report.UnmappedPages = append(report.UnmappedPages,
				page.Method+" "+page.Path+" ("+page.Name+")")
		}
	}
	for index, command := range inv.CLI {
		if !cliClaimed[index] {
			report.UnmappedCLI = append(report.UnmappedCLI, command.Binary+":"+command.Name)
		}
	}
	for _, permission := range inv.Permissions {
		if !permissionClaimed[permission.Key] {
			report.UnmappedPermissions = append(report.UnmappedPermissions, permission.Key)
		}
	}
	report.AppTypesTotal = len(appTypes)
	report.AdminRoutesTotal = len(inv.AdminRoutes)
	report.ProtocolPathsTotal = len(inv.ProtocolPaths)
	report.PagesTotal = len(inv.Pages)
	report.CLITotal = len(inv.CLI)
	report.PermissionsTotal = len(inv.Permissions)
	return report
}

// coverageReport 是反向覆盖核对结果。
type coverageReport struct {
	AppTypesTotal         int      `json:"app_types_total"`
	AdminRoutesTotal      int      `json:"admin_routes_total"`
	ProtocolPathsTotal    int      `json:"protocol_paths_total"`
	PagesTotal            int      `json:"pages_total"`
	CLITotal              int      `json:"cli_commands_total"`
	PermissionsTotal      int      `json:"permissions_total"`
	UnmappedAppTypes      []string `json:"unmapped_app_types,omitempty"`
	UnmappedAdminRoutes   []string `json:"unmapped_admin_routes,omitempty"`
	UnmappedProtocolPaths []string `json:"unmapped_protocol_paths,omitempty"`
	UnmappedPages         []string `json:"unmapped_pages,omitempty"`
	UnmappedCLI           []string `json:"unmapped_cli,omitempty"`
	UnmappedPermissions   []string `json:"unmapped_permissions,omitempty"`
}

// UnmappedCount 汇总未覆盖项数量。
func (r coverageReport) UnmappedCount() int {
	return len(r.UnmappedAppTypes) + len(r.UnmappedAdminRoutes) +
		len(r.UnmappedProtocolPaths) + len(r.UnmappedPages) +
		len(r.UnmappedCLI) + len(r.UnmappedPermissions)
}
