package apidoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 本文件读取 scripts/capabilities/catalog.json（能力声明）与
// docs/acceptance/capability-matrix.json（只读交叉核对），并把能力 id 反向标注到
// 路由、页面、权限、CLI 等参考条目上，供人类与 AI 从任一方向跳转。

// catalogFile 是 capabilities/catalog.json 的顶层结构（只读子集）。
type catalogFile struct {
	Schema       string              `json:"schema"`
	Description  string              `json:"description"`
	Capabilities []catalogCapability `json:"capabilities"`
}

// catalogPagination 是能力的分页声明（参考索引只保留 mode）。
type catalogPagination struct {
	Mode string `json:"mode"`
}

// catalogCapability 是一份能力声明的只读视图。
type catalogCapability struct {
	ID                       string             `json:"id"`
	Title                    string             `json:"title"`
	Domain                   string             `json:"domain"`
	Expect                   string             `json:"expect,omitempty"`
	Notes                    string             `json:"notes,omitempty"`
	AppAPI                   []string           `json:"app_api,omitempty"`
	RootAPI                  []string           `json:"root_api,omitempty"`
	AdminRoutes              []string           `json:"admin_routes,omitempty"`
	ProtocolPaths            []string           `json:"protocol_paths,omitempty"`
	CLI                      []string           `json:"cli,omitempty"`
	Pages                    []string           `json:"pages,omitempty"`
	Permissions              []string           `json:"permissions,omitempty"`
	UnimplementedPermissions []string           `json:"unimplemented_permissions,omitempty"`
	Pagination               *catalogPagination `json:"pagination,omitempty"`
}

// loadCapabilityCatalog 读取能力声明；缺失或格式错误时返回可读错误（fail-closed）。
func loadCapabilityCatalog(root string) ([]CapabilityRef, error) {
	path := filepath.Join(root, filepath.FromSlash(pathCapabilityCatalog))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取能力声明 %s 失败：%w", pathCapabilityCatalog, err)
	}
	var file catalogFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("解析能力声明 %s 失败：%w", pathCapabilityCatalog, err)
	}
	if len(file.Capabilities) == 0 {
		return nil, fmt.Errorf("能力声明 %s 没有任何能力", pathCapabilityCatalog)
	}
	refs := make([]CapabilityRef, 0, len(file.Capabilities))
	seen := map[string]bool{}
	for _, capability := range file.Capabilities {
		if capability.ID == "" {
			return nil, fmt.Errorf("能力声明 %s 存在缺少 id 的条目", pathCapabilityCatalog)
		}
		if seen[capability.ID] {
			return nil, fmt.Errorf("能力声明 %s 存在重复 id %q", pathCapabilityCatalog, capability.ID)
		}
		seen[capability.ID] = true
		ref := CapabilityRef{
			ID: capability.ID, Title: capability.Title, Domain: capability.Domain,
			Notes: capability.Notes, Expect: capability.Expect,
			AppAPI: capability.AppAPI, RootAPI: capability.RootAPI,
			AdminRoutes: capability.AdminRoutes, ProtocolPaths: capability.ProtocolPaths,
			CLI: capability.CLI, Pages: capability.Pages, Permissions: capability.Permissions,
			UnimplementedPermissions: capability.UnimplementedPermissions,
		}
		if capability.Pagination != nil {
			ref.PaginationMode = capability.Pagination.Mode
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs, nil
}

// capabilityMatchKey 把能力声明中的一条管理路由声明（"GET users*"）拆成方法与模式。
func capabilityMatchKey(claim string) (method, pattern string) {
	claim = strings.TrimSpace(claim)
	index := strings.Index(claim, " ")
	if index <= 0 {
		return strings.ToUpper(claim), ""
	}
	return strings.ToUpper(claim[:index]), strings.TrimSpace(claim[index+1:])
}

// wildcardMatch 支持结尾单个 "*" 的前缀匹配；其他情况要求完全相等（与
// scripts/capabilities 的声明核对语义一致）。
func wildcardMatch(pattern, value string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

// adminRouteMatches 判断一条能力路由声明是否覆盖某条实际管理路由。
func adminRouteMatches(claim string, route AdminRoute) bool {
	method, pattern := capabilityMatchKey(claim)
	if pattern == "" || method != route.Method {
		return false
	}
	return wildcardMatch(pattern, route.Pattern)
}

// pageMatches 判断页面声明（"name:support.*" 或 "path:/admin/*"）是否覆盖页面。
func pageMatches(claim string, page PageRoute) bool {
	claim = strings.TrimSpace(claim)
	switch {
	case strings.HasPrefix(claim, "name:"):
		return wildcardMatch(strings.TrimPrefix(claim, "name:"), page.Name)
	case strings.HasPrefix(claim, "path:"):
		return wildcardMatch(strings.TrimPrefix(claim, "path:"), page.Path)
	case strings.HasPrefix(claim, "method:"):
		return wildcardMatch(strings.TrimPrefix(claim, "method:"), page.Method)
	default:
		return wildcardMatch(claim, page.Name)
	}
}

// cliMatches 判断 CLI 声明（"loginctl:root-recover"）是否覆盖某子命令。
func cliMatches(claim string, binary CLIBinary, subcommand CLISubcommand) bool {
	claim = strings.TrimSpace(claim)
	index := strings.Index(claim, ":")
	if index <= 0 {
		return false
	}
	binaryClaim := strings.TrimSpace(claim[:index])
	subClaim := strings.TrimSpace(claim[index+1:])
	return wildcardMatch(binaryClaim, binary.Name) && wildcardMatch(subClaim, subcommand.Name)
}

// annotateCapabilities 把能力 id 反向标注到路由、页面、权限、角色与 CLI 条目，
// 并返回“声明无法解析”的问题清单（供 -check fail-closed 使用）。
func annotateCapabilities(model *Model) ([]string, []string) {
	issues := make([]string, 0)
	warnings := make([]string, 0)
	appendCap := func(target *[]string, id string) {
		for _, existing := range *target {
			if existing == id {
				return
			}
		}
		*target = append(*target, id)
		sort.Strings(*target)
	}
	appSymbols := buildAppSymbolIndex(model.GoAPI)
	rootSymbols := buildRootSymbolIndex(model.GoAPI)
	for _, capability := range model.Capabilities {
		for _, claim := range capability.AdminRoutes {
			matched := false
			for index := range model.AdminRoutes {
				if adminRouteMatches(claim, model.AdminRoutes[index]) {
					appendCap(&model.AdminRoutes[index].Capabilities, capability.ID)
					matched = true
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的管理路由声明 %q 未匹配任何实际路由", capability.ID, claim))
			}
		}
		for _, claim := range capability.Pages {
			matched := false
			for index := range model.Pages {
				if pageMatches(claim, model.Pages[index]) {
					appendCap(&model.Pages[index].Capabilities, capability.ID)
					matched = true
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的页面声明 %q 未匹配任何页面路由", capability.ID, claim))
			}
		}
		for _, claim := range capability.CLI {
			matched := false
			for binaryIndex := range model.CLIBinaries {
				for subIndex := range model.CLIBinaries[binaryIndex].Subcommands {
					if cliMatches(claim, model.CLIBinaries[binaryIndex], model.CLIBinaries[binaryIndex].Subcommands[subIndex]) {
						matched = true
					}
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的 CLI 声明 %q 未匹配任何子命令", capability.ID, claim))
			}
		}
		for _, claim := range capability.ProtocolPaths {
			matched := false
			for _, path := range model.ProtocolPaths {
				if wildcardMatch(claim, path.Name) {
					matched = true
					break
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的协议路径声明 %q 未匹配任何导出路径常量", capability.ID, claim))
			}
		}
		for _, claim := range capability.AppAPI {
			if !resolveAppClaim(claim, appSymbols) {
				issues = append(issues, fmt.Sprintf("能力 %s 的 app API 声明 %q 未在公开 app 包中找到", capability.ID, claim))
			}
		}
		for _, claim := range capability.RootAPI {
			if !rootSymbols[claim] {
				issues = append(issues, fmt.Sprintf("能力 %s 的根包 API 声明 %q 未在根包公开符号中找到", capability.ID, claim))
			}
		}
		for _, key := range capability.Permissions {
			matched := false
			for index := range model.Permissions {
				if model.Permissions[index].Key == key {
					appendCap(&model.Permissions[index].Capabilities, capability.ID)
					matched = true
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的权限声明 %q 未在预设权限目录中找到", capability.ID, key))
			}
		}
		for _, key := range capability.UnimplementedPermissions {
			matched := false
			for _, permission := range model.Permissions {
				if permission.Key == key {
					matched = true
					if permission.Implemented {
						warnings = append(warnings, fmt.Sprintf("能力 %s 声明权限 %q 未实现，但预设目录已标记为已实现（能力声明可能滞后；请由能力盘点步骤核对）", capability.ID, key))
					}
					break
				}
			}
			if !matched {
				issues = append(issues, fmt.Sprintf("能力 %s 的未实现权限声明 %q 未在预设权限目录中找到", capability.ID, key))
			}
		}
		// 角色通过默认权限与能力关联。
		permissionSet := map[string]bool{}
		for _, key := range capability.Permissions {
			permissionSet[key] = true
		}
		for index := range model.Roles {
			if roleReferencesAny(model.Roles[index], permissionSet) {
				appendCap(&model.Roles[index].Capabilities, capability.ID)
			}
		}
		for index := range model.ApplicationRoles {
			if roleReferencesAny(model.ApplicationRoles[index], permissionSet) {
				appendCap(&model.ApplicationRoles[index].Capabilities, capability.ID)
			}
		}
	}
	return issues, warnings
}

// roleReferencesAny 判断角色默认权限是否覆盖给定权限集合。
func roleReferencesAny(role RoleEntry, permissions map[string]bool) bool {
	for _, key := range role.DefaultPermissions {
		if permissions[key] {
			return true
		}
	}
	return false
}

// buildAppSymbolIndex 建立 app 包公开符号解析索引：类型、函数、类型成员。
func buildAppSymbolIndex(goAPI *GoAPI) map[string]bool {
	symbols := map[string]bool{}
	if goAPI == nil {
		return symbols
	}
	for _, function := range goAPI.AppFuncs {
		symbols[function.Name] = true
	}
	for _, value := range goAPI.AppVars {
		symbols[value.Name] = true
	}
	for _, typ := range goAPI.AppTypes {
		symbols[typ.Name] = true
		for _, member := range typ.Members {
			symbols[typ.Name+"."+member] = true
		}
	}
	for _, iface := range goAPI.Interfaces {
		symbols[iface.Name] = true
		for _, method := range iface.Methods {
			symbols[iface.Name+"."+method.Name] = true
		}
	}
	for _, method := range goAPI.RuntimeMethods {
		symbols["Runtime."+method.Name] = true
	}
	return symbols
}

// resolveAppClaim 解析一条 app API 声明：Type、Type.Member 或函数名。
func resolveAppClaim(claim string, symbols map[string]bool) bool {
	if symbols[claim] {
		return true
	}
	return false
}

// buildRootSymbolIndex 建立根包公开符号索引（类型、函数、常量、变量）。
func buildRootSymbolIndex(goAPI *GoAPI) map[string]bool {
	symbols := map[string]bool{}
	if goAPI == nil {
		return symbols
	}
	for _, summary := range goAPI.RootFiles {
		for _, name := range summary.Types {
			symbols[name] = true
		}
		for _, name := range summary.Funcs {
			symbols[name] = true
		}
		for _, name := range summary.Consts {
			symbols[name] = true
		}
		for _, name := range summary.Vars {
			symbols[name] = true
		}
	}
	return symbols
}

// matrixInventory 是能力矩阵中与参考文档交叉核对的只读盘点数字。
type matrixInventory struct {
	Inventories struct {
		AdminRoutes       []json.RawMessage `json:"admin_routes"`
		Pages             []json.RawMessage `json:"pages"`
		ProtocolPaths     []json.RawMessage `json:"protocol_paths"`
		CLI               []json.RawMessage `json:"cli"`
		Permissions       []json.RawMessage `json:"permissions"`
		RootTypes         []json.RawMessage `json:"root_types"`
		ProtocolEndpoints []json.RawMessage `json:"protocol_endpoint_table"`
		AppFuncs          []json.RawMessage `json:"app_funcs"`
	} `json:"inventories"`
	Summary struct {
		Total int `json:"total"`
	} `json:"summary"`
}

// loadCrossCheck 只读读取能力矩阵并比较盘点数量；不重新生成矩阵。
func loadCrossCheck(root string, model *Model) CrossCheck {
	cross := CrossCheck{}
	path := filepath.Join(root, filepath.FromSlash(pathCapabilityMatrix))
	raw, err := os.ReadFile(path)
	if err != nil {
		model.Warnings = append(model.Warnings,
			fmt.Sprintf("未读取能力矩阵 %s（只读交叉核对跳过）：%v", pathCapabilityMatrix, err))
		return cross
	}
	var matrix matrixInventory
	if err := json.Unmarshal(raw, &matrix); err != nil {
		model.Warnings = append(model.Warnings,
			fmt.Sprintf("解析能力矩阵 %s 失败（只读交叉核对跳过）：%v", pathCapabilityMatrix, err))
		return cross
	}
	cross.MatrixCapabilities = matrix.Summary.Total
	cross.MatrixAdminRoutes = len(matrix.Inventories.AdminRoutes)
	cross.MatrixPages = len(matrix.Inventories.Pages)
	cross.MatrixProtocol = len(matrix.Inventories.ProtocolPaths)
	cross.MatrixProtocolEndpoints = len(matrix.Inventories.ProtocolEndpoints)
	cross.MatrixCLI = len(matrix.Inventories.CLI)
	cross.MatrixPermissions = len(matrix.Inventories.Permissions)
	cross.MatrixRootTypes = len(matrix.Inventories.RootTypes)
	cross.MatrixAppFuncs = len(matrix.Inventories.AppFuncs)

	compare := func(kind string, matrixValue, scannedValue int) {
		if matrixValue != scannedValue {
			cross.Mismatches = append(cross.Mismatches, fmt.Sprintf(
				"%s：能力矩阵盘点=%d，reference 扫描=%d（矩阵可能过期或扫描口径不同，需人工核对；不自动改写矩阵）",
				kind, matrixValue, scannedValue))
		}
	}
	compare("管理路由", cross.MatrixAdminRoutes, len(model.AdminRoutes))
	compare("页面路由", cross.MatrixPages, len(model.Pages))
	compare("协议路径", cross.MatrixProtocol, len(model.ProtocolPaths))
	compare("协议端点表", cross.MatrixProtocolEndpoints, len(model.ProtocolEndpoints))
	compare("CLI 子命令", cross.MatrixCLI, countCLISubcommands(model.CLIBinaries))
	compare("权限键", cross.MatrixPermissions, len(model.Permissions))
	compare("app 函数（含导出方法）", cross.MatrixAppFuncs, len(model.GoAPI.AppFuncs)+model.GoAPI.ExportedMethodCount)
	if len(cross.Mismatches) > 0 {
		sort.Strings(cross.Mismatches)
	}
	return cross
}

// countCLISubcommands 统计全部 CLI 子命令数量。
func countCLISubcommands(binaries []CLIBinary) int {
	total := 0
	for _, binary := range binaries {
		total += len(binary.Subcommands)
	}
	return total
}
