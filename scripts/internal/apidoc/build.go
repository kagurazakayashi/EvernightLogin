package apidoc

import (
	"fmt"
	"sort"
	"strings"
)

// 本文件把各数据源组装为一次完整生成模型，并登记 Phase A 尚未展开的领域清单。
// Generate 只读源码与代码注册表，不写文件；写文件与校验分别由 Write 与 Check 完成。

// Generate 生成一次完整参考模型。
func Generate(root string) (*Model, error) {
	model := &Model{Root: root}
	var err error
	if model.Errors, err = loadErrors(); err != nil {
		return nil, err
	}
	permissionCatalog, err := loadPermissionCatalog()
	if err != nil {
		return nil, err
	}
	model.Permissions = permissionCatalog.Permissions
	model.Roles = permissionCatalog.SystemRoles
	model.ApplicationRoles = permissionCatalog.ApplicationRoles
	model.Groups = permissionCatalog.SystemGroups
	model.ApplicationGroups = permissionCatalog.ApplicationGroups
	model.CatalogVersion = permissionCatalog.Version
	model.ConfigFields = loadConfigFields()

	if model.Capabilities, err = loadCapabilityCatalog(root); err != nil {
		return nil, err
	}
	if model.GoAPI, err = scanGoAPI(root); err != nil {
		return nil, err
	}
	if model.AdminRoutes, err = scanAdminRoutes(root); err != nil {
		return nil, err
	}
	if model.ProtocolPaths, model.ProtocolEndpoints, err = scanProtocol(root); err != nil {
		return nil, err
	}
	if model.Pages, err = scanPages(root); err != nil {
		return nil, err
	}
	if model.CLIBinaries, err = scanCLI(root); err != nil {
		return nil, err
	}
	if model.Snippets, err = loadSnippets(root); err != nil {
		return nil, err
	}
	claimIssues, claimWarnings := annotateCapabilities(model)
	model.ClaimIssues = claimIssues
	model.Warnings = append(model.Warnings, claimWarnings...)
	model.CrossCheck = loadCrossCheck(root, model)
	model.PendingSections = pendingSections(model)
	return model, nil
}

// pendingSections 返回 Phase A 尚未展开为方法级参考的领域（Phase B 补齐）。
// 领域划分是 Phase B 的计划锚点；计数来自当前公开接口方法盘点。
func pendingSections(model *Model) []PendingSection {
	type domain struct {
		id      string
		reason  string
		matches func(name string) bool
	}
	domains := []domain{
		{"auth-session-mfa", "认证、会话、安全与 MFA 领域的方法级参考待 Phase B", containsAny("Auth", "Session", "Security", "Access", "MFA", "PasswordReset")},
		{"users-account", "账户、资料、密码、注册、邀请、批量与有效期领域的方法级参考待 Phase B", containsAny("User", "Profile", "Password", "Registration", "EmailChange", "Invitation", "Validity")},
		{"rbac-applications", "RBAC、应用、OAuth 客户端与委派领域的方法级参考待 Phase B", containsAny("RBAC", "Application", "OAuth", "Delegation", "Role", "Group", "Permission")},
		{"audit-reports", "审计与报告领域的方法级参考待 Phase B", containsAny("Audit", "Report")},
		{"backup-restore", "备份、恢复与任务领域的方法级参考待 Phase B", containsAny("Backup", "Restore", "Recovery", "Job", "Plan")},
		{"ops-diagnostics", "运维、诊断、设置、客服与协议管理领域的方法级参考待 Phase B", containsAny("Diagnostic", "Settings", "Support", "ManualRecovery", "Protocol", "Bootstrap")},
	}
	remaining := map[string]bool{}
	for _, iface := range model.GoAPI.Interfaces {
		remaining[iface.Name] = true
	}
	var sections []PendingSection
	for _, domain := range domains {
		symbols := 0
		for name := range remaining {
			if domain.matches(name) {
				symbols++
				delete(remaining, name)
			}
		}
		sections = append(sections, PendingSection{ID: domain.id, Reason: domain.reason, Symbols: symbols})
	}
	if len(remaining) > 0 {
		names := make([]string, 0, len(remaining))
		for name := range remaining {
			names = append(names, name)
		}
		sort.Strings(names)
		sections = append(sections, PendingSection{
			ID: "misc-interfaces", Reason: "未归类接口（Phase B 复核领域映射）：" + joinNames(names), Symbols: len(remaining),
		})
	}
	return sections
}

// containsAny 返回一个“名称包含任一关键字”的匹配函数。
func containsAny(keywords ...string) func(string) bool {
	return func(name string) bool {
		for _, keyword := range keywords {
			if len(keyword) > 0 && strings.Contains(name, keyword) {
				return true
			}
		}
		return false
	}
}

// joinNames 用顿号连接名称列表。
func joinNames(names []string) string {
	result := ""
	for index, name := range names {
		if index > 0 {
			result += "、"
		}
		result += name
	}
	return result
}

// 生成结果安全下限：低于以下数量通常意味着 214/215 等结构重构后扫描目录/候选路径
// 过期。继续生成会产出“空参考”并误导调用方，因此 -write/-check 直接失败并提示更新
// sources.go；阈值按当前盘点留有余量（页面 245、管理路由 118、协议 17、CLI 40、
// Runtime 51、接口 39）。
const (
	minPageRoutes        = 200
	minAdminRoutes       = 50
	minProtocolPaths     = 10
	minCLISubcommands    = 20
	minRuntimeMethods    = 20
	minServiceInterfaces = 20
)

// validateCounts 校验关键盘点数量不低于安全下限，返回可操作的失败信息。
func validateCounts(model *Model) []string {
	var issues []string
	check := func(name string, got, minimum int, hint string) {
		if got < minimum {
			issues = append(issues, fmt.Sprintf(
				"生成结果异常：%s仅 %d 条（安全下限 %d）：%s", name, got, minimum, hint))
		}
	}
	check("页面命名路由", len(model.Pages), minPageRoutes,
		"检查 sources.go 的 pageScanDirs（214 后页面实现位于公开包 ui/）")
	check("管理 JSON API 路由", len(model.AdminRoutes), minAdminRoutes,
		"检查 adminHandlerCandidates 与管理路由源码目录是否移动")
	check("协议路径常量", len(model.ProtocolPaths), minProtocolPaths,
		"检查 protocolPathCandidates 是否仍指向协议包")
	check("CLI 子命令", countCLISubcommands(model.CLIBinaries), minCLISubcommands,
		"检查 cmdRootDir 与 manageCLIDir 的命令注册方式是否变化")
	check("Runtime 公开方法", len(model.GoAPI.RuntimeMethods), minRuntimeMethods,
		"检查 goAPIDirs 与 app 公开门面文件（215 后按领域分文件）")
	check("app 服务接口", len(model.GoAPI.Interfaces), minServiceInterfaces,
		"检查 goAPIDirs 与 app 公开类型组织是否变化")
	return issues
}
