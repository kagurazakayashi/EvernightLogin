package apidoc

import (
	"fmt"
	"sort"
)

// 本文件渲染 Go API 框架、能力映射与 AI 入口。Phase A 的 Go API 参考以“生命周期 +
// 接口/符号总览 + 稳定领域”为范围，方法级领域参考在 Phase B 补齐。

// renderGoAPI 渲染 go-api.md。
func (m *Model) renderGoAPI(used map[string]bool) []byte {
	runtimeRows := make([][]string, 0, len(m.GoAPI.RuntimeMethods))
	for _, method := range m.GoAPI.RuntimeMethods {
		runtimeRows = append(runtimeRows, []string{
			"`" + method.Name + "`", "`" + method.Signature + "`", method.Doc, sourceLink(method.Source),
		})
	}
	interfaceRows := make([][]string, 0, len(m.GoAPI.Interfaces))
	for _, iface := range m.GoAPI.Interfaces {
		names := make([]string, 0, len(iface.Methods))
		for _, method := range iface.Methods {
			names = append(names, method.Name)
		}
		interfaceRows = append(interfaceRows, []string{
			"`" + iface.Name + "`", fmt.Sprintf("%d", len(iface.Methods)),
			joinCode(names), iface.Doc, sourceLink(iface.Source),
		})
	}
	appFuncRows := make([][]string, 0, len(m.GoAPI.AppFuncs))
	for _, function := range m.GoAPI.AppFuncs {
		appFuncRows = append(appFuncRows, []string{
			"`" + function.Name + "`", "`" + function.Signature + "`", function.Doc, sourceLink(function.Source),
		})
	}
	kindCounts := map[string]int{}
	sourceCounts := map[string]int{}
	for _, typ := range m.GoAPI.AppTypes {
		kindCounts[typ.Kind]++
		sourceCounts[typ.Source]++
	}
	kindRows := make([][]string, 0, len(kindCounts))
	for _, kind := range []string{"interface", "struct", "alias"} {
		if kindCounts[kind] > 0 {
			kindRows = append(kindRows, []string{kind, fmt.Sprintf("%d", kindCounts[kind])})
		}
	}
	sourceKeys := make([]string, 0, len(sourceCounts))
	for source := range sourceCounts {
		sourceKeys = append(sourceKeys, source)
	}
	sort.Strings(sourceKeys)
	sourceRows := make([][]string, 0, len(sourceKeys))
	for _, source := range sourceKeys {
		sourceRows = append(sourceRows, []string{sourceLink(source), fmt.Sprintf("%d", sourceCounts[source])})
	}
	rootFuncRows := make([][]string, 0, len(m.GoAPI.RootFuncs))
	for _, function := range m.GoAPI.RootFuncs {
		rootFuncRows = append(rootFuncRows, []string{
			"`" + function.Name + "`", "`" + function.Signature + "`", function.Doc, sourceLink(function.Source),
		})
	}
	rootFileRows := make([][]string, 0, len(m.GoAPI.RootFiles))
	for _, summary := range m.GoAPI.RootFiles {
		rootFileRows = append(rootFileRows, []string{
			sourceLink(summary.File), fmt.Sprintf("%d", len(summary.Types)),
			fmt.Sprintf("%d", len(summary.Funcs)), fmt.Sprintf("%d", len(summary.Consts)+len(summary.Vars)),
		})
	}
	pendingRows := make([][]string, 0, len(m.PendingSections))
	for _, section := range m.PendingSections {
		pendingRows = append(pendingRows, []string{section.ID, section.Reason, fmt.Sprintf("%d", section.Symbols)})
	}
	return joinBlocks(
		"# 公开 Go API 参考（Phase A：框架 + 稳定领域）\n\n"+
			"> 由 AST 扫描 `app/` 与根包公开符号生成。**Phase A 只交付框架与稳定领域**："+
			"每个服务接口的方法级参考（调用身份/应用范围/分页/取消/幂等/任务终态/错误/最小例）"+
			"待 214/215（页面与 app 类型重组）及 226–235 公开门面稳定后由 Phase B 补齐。"+
			"当前精确签名以 GoDoc 与源码为准。",
		"## 1. 公开范围与生命周期契约\n\n"+
			bulletList([]string{
				"**可导入包**：宿主只能导入模块根包（包名 `login`）与 `app` 包，以及 `config`、`errs`、`httpapi` 等公开叶子包；Go internal 规则禁止模块外导入 `internal/`。",
				"**构造不启动**：`app.Open` 只构造运行时，不监听端口、不启动后台任务；后台任务必须由宿主显式 `Start`；`Close` 幂等，只关闭运行时自建资源，不关闭宿主注入的数据库/日志/通知器。",
				"**监听器归宿主**：运行时通过 `Handler`/`Mount`/`HTTPMounts` 暴露 HTTP；宿主自己的 `http.Server` 生命周期与优雅关闭由宿主负责。",
				"**调用身份**：`LocalAdmin` 仅代表持有宿主进程控制权的可信本地代码（不能由 HTTP 参数获得）；管理门面需要真实管理会话/CSRF；普通业务使用完整会话或受限会话，受限会话不得当登录成功。",
				"**错误与请求编号**：公开门面返回稳定错误码与 `request_id`；错误表见 [errors.md](errors.md)，HTTP 信封见 [http-api.md](http-api.md)。",
				"**分页/取消/幂等**：可增长列表在数据源处分页（默认/最大/排序白名单/稳定次序/HasMore 或游标）；长任务返回受理与任务 ID，受理不等于完成；敏感写操作需再次认证，重试不得绕过。",
				"**安全默认**：认证/授权/审计依赖失败时 fail-closed；来源地址必须来自可信边界；邮件测试只连本地捕获器；真实平台/客户端未实测的边界不写成已支持。",
			}),
		"## 2. Runtime 公开方法（"+fmt.Sprintf("%d", len(m.GoAPI.RuntimeMethods))+" 个）\n\n"+
			markdownTable([]string{"方法", "签名（不含接收者）", "说明", "源码"}, runtimeRows),
		"## 3. 公开服务接口总览（"+fmt.Sprintf("%d 个接口 / %d 个方法", len(m.GoAPI.Interfaces), countInterfaceMethods(m.GoAPI))+"）\n\n"+
			markdownTable([]string{"接口", "方法数", "方法名", "说明", "源码"}, interfaceRows),
		"## 4. app 包公开函数（"+fmt.Sprintf("%d", len(m.GoAPI.AppFuncs))+" 个）\n\n"+
			markdownTable([]string{"函数", "签名", "说明", "源码"}, appFuncRows),
		"### 4.1 app 包公开变量/常量（"+fmt.Sprintf("%d", len(m.GoAPI.AppVars))+" 个）\n\n"+
			appValueTable(m.GoAPI.AppVars),
		"## 5. app 包公开类型（"+fmt.Sprintf("%d", len(m.GoAPI.AppTypes))+" 个）\n\n"+
			markdownTable([]string{"类别", "数量"}, kindRows)+
			"\n按源码文件分布（完整类型名与字段请用 `go doc ./app` 或 GoDoc 查询；Phase B 将按领域展开关键类型字段与边界）：\n\n"+
			markdownTable([]string{"源码文件", "导出类型数"}, sourceRows),
		"## 6. 根包公开函数（"+fmt.Sprintf("%d", len(m.GoAPI.RootFuncs))+" 个；另含公开类型 "+fmt.Sprintf("%d", m.GoAPI.RootTypeCount)+" 个）\n\n"+
			markdownTable([]string{"函数", "签名", "说明", "源码"}, rootFuncRows),
		"### 6.1 根包公开符号按源文件分布（"+fmt.Sprintf("%d", len(m.GoAPI.RootFiles))+" 个文件）\n\n"+
			markdownTable([]string{"源文件", "类型", "函数", "常量/变量"}, rootFileRows),
		"## 7. Phase B 待补领域\n\n"+
			markdownTable([]string{"领域", "待补内容", "涉及接口数"}, pendingRows),
		"## 8. 最小可编译示例\n\n"+
			"Phase A 的最小可编译示例只依赖公开叶子包（避免随根包/UI 重构反复失配）：错误码用法见 [errors.md](errors.md) 第 3 节，配置字段用法见 [configuration.md](configuration.md) 第 3 节。运行时门面（`app.Open` → `Start` → `Mount` → `Close`）的完整可运行示例见 [examples/embedded-minimal](../../examples/embedded-minimal/)；Phase B 会把方法级调用例内嵌到本页。",
		"## 9. 相关文档\n\n"+
			bulletList([]string{
				"公开 API 稳定范围、破坏性变更策略与生命周期细节：[../embedding/host_integration.md](../embedding/host_integration.md)",
				"嵌入模式入口与示例：[../embedding/README.md](../embedding/README.md)",
				"GoDoc/OpenAPI 现状与错误约定：[../guide/api-status.md](../guide/api-status.md)",
				"公开错误码：[errors.md](errors.md)；权限目录：[permissions.md](permissions.md)；配置：[configuration.md](configuration.md)。",
			}),
	)
}

// appValueTable 渲染 app 包公开变量/常量表。
func appValueTable(values []GoValue) string {
	if len(values) == 0 {
		return "无。\n"
	}
	rows := make([][]string, 0, len(values))
	for _, value := range values {
		rows = append(rows, []string{"`" + value.Name + "`", value.Kind, value.Doc, sourceLink(value.Source)})
	}
	return markdownTable([]string{"名称", "类别", "说明", "源码"}, rows)
}

// renderCapabilityMap 渲染 capability-map.md。
func (m *Model) renderCapabilityMap(used map[string]bool) []byte {
	rows := make([][]string, 0, len(m.Capabilities))
	for _, capability := range m.Capabilities {
		appAPI := capability.AppAPI
		if len(appAPI) > 6 {
			appAPI = appAPI[:6]
		}
		rows = append(rows, []string{
			"`" + capability.ID + "`", capability.Domain, capability.Title,
			capability.PaginationMode,
			fmt.Sprintf("%d", len(capability.Permissions)),
			fmt.Sprintf("%d", len(capability.AdminRoutes)),
			fmt.Sprintf("%d", len(capability.Pages)),
			fmt.Sprintf("%d", len(capability.CLI)),
			joinCode(appAPI),
		})
	}
	crossRows := [][]string{
		{"能力总数", fmt.Sprintf("%d", m.CrossCheck.MatrixCapabilities), fmt.Sprintf("%d", len(m.Capabilities))},
		{"管理路由", fmt.Sprintf("%d", m.CrossCheck.MatrixAdminRoutes), fmt.Sprintf("%d", len(m.AdminRoutes))},
		{"页面路由", fmt.Sprintf("%d", m.CrossCheck.MatrixPages), fmt.Sprintf("%d", len(m.Pages))},
		{"协议路径", fmt.Sprintf("%d", m.CrossCheck.MatrixProtocol), fmt.Sprintf("%d", len(m.ProtocolPaths))},
		{"CLI 子命令", fmt.Sprintf("%d", m.CrossCheck.MatrixCLI), fmt.Sprintf("%d", countCLISubcommands(m.CLIBinaries))},
		{"权限键", fmt.Sprintf("%d", m.CrossCheck.MatrixPermissions), fmt.Sprintf("%d", len(m.Permissions))},
	}
	warnings := "无。"
	if len(m.CrossCheck.Mismatches) > 0 || len(m.Warnings) > 0 {
		lines := append([]string{}, m.Warnings...)
		lines = append(lines, m.CrossCheck.Mismatches...)
		warnings = bulletList(lines)
	}
	return joinBlocks(
		"# 能力映射（catalog.json → 参考文档/机器 JSON）\n\n"+
			"> 能力声明来自 `scripts/capabilities/catalog.json`（机器可读能力映射的唯一来源），"+
			"**实现状态不在这里重复**：请以 [能力矩阵](../acceptance/capability-matrix.md) 为准。"+
			"本页提供“能力 → 公开面（Go/HTTP/页面/CLI/权限）→ 参考位置”的导航索引。",
		"## 1. 能力参考索引（"+fmt.Sprintf("%d", len(m.Capabilities))+" 项）\n\n"+
			markdownTable([]string{"能力 id", "领域", "标题", "分页", "权限数", "管理路由声明", "页面声明", "CLI 声明", "主要公开 Go API"}, rows),
		"## 2. 与能力矩阵只读交叉核对\n\n"+
			markdownTable([]string{"对象", "能力矩阵盘点", "reference 扫描"}, crossRows)+"\n"+warnings+"\n",
		"## 3. 使用方式\n\n"+
			bulletList([]string{
				"已知能力 id：在上表定位领域与公开面，再到 [go-api.md](go-api.md)、[http-api.md](http-api.md)、[permissions.md](permissions.md)、[cli.md](cli.md) 对应条目。",
				"判断是否已实现/已测试：读 [能力矩阵](../acceptance/capability-matrix.md) 与 [需求矩阵](../acceptance/requirements-matrix-login.md)；README/本页不承诺状态。",
				"机器消费：catalog.json 是声明源，本目录 4 个 JSON 是公开面清单；两者不一致时 `scripts/reference -check` 会报“能力声明无法解析”。",
				"新增能力：先在 catalog.json 登记交叉层公开面，再实现代码并运行 `-write`；不允许只改文档宣称支持。",
			}),
		"## 4. 相关机器文件\n\n"+
			bulletList([]string{
				"声明源：[scripts/capabilities/catalog.json](../../scripts/capabilities/catalog.json)",
				"状态矩阵：[docs/acceptance/capability-matrix.json](../acceptance/capability-matrix.json)",
				"[http-routes.json](" + fileHTTPRoutesJSON + ") / [" + fileCLIJSON + "](" + fileCLIJSON + ") / [" + filePermissionsJSON + "](" + filePermissionsJSON + ")",
			}),
	)
}

// renderAIIndex 渲染 ai-index.md。
func (m *Model) renderAIIndex(used map[string]bool) []byte {
	jsonRows := [][]string{
		{fileErrorsJSON, "error-codes", fmt.Sprintf("%d 个错误码", len(m.Errors))},
		{filePermissionsJSON, "permission-keys", fmt.Sprintf("%d 权限 / %d 系统角色 / %d 用户组", len(m.Permissions), len(m.Roles), len(m.Groups))},
		{fileHTTPRoutesJSON, "http-routes", fmt.Sprintf("%d 管理路由 / %d 协议路径 / %d 页面", len(m.AdminRoutes), len(m.ProtocolPaths), len(m.Pages))},
		{fileCLIJSON, "cli-commands", fmt.Sprintf("%d 程序 / %d 子命令", len(m.CLIBinaries), countCLISubcommands(m.CLIBinaries))},
	}
	taskRows := [][]string{
		{"找某个错误码含义/处理", "[errors.md](errors.md) 或 [" + fileErrorsJSON + "](" + fileErrorsJSON + ")", "错误码表 + 排障指南"},
		{"查权限键/谁能做什么", "[permissions.md](permissions.md) 或 [" + filePermissionsJSON + "](" + filePermissionsJSON + ")", "权限目录生成"},
		{"查配置字段/环境变量/是否秘密", "[configuration.md](configuration.md)", "语义以 guide 为准"},
		{"找 HTTP 管理路由/协议路径/页面路由", "[http-api.md](http-api.md) 或 [" + fileHTTPRoutesJSON + "](" + fileHTTPRoutesJSON + ")", "AST 扫描注册"},
		{"查 CLI 命令/flag/退出码", "[cli.md](cli.md) 或 [" + fileCLIJSON + "](" + fileCLIJSON + ")", "双风格 CLI 扫描"},
		{"查公开 Go 接口/方法是否存在", "[go-api.md](go-api.md) + `go doc ./app` / GoDoc", "Phase A 框架，Phase B 方法级"},
		{"找最小可编译示例", "本页第 4 节 + 对应文档示例块", "源码 examples/reference-snippets"},
		{"能力 id → 领域/公开面", "[capability-map.md](capability-map.md)", "catalog.json 映射"},
		{"判断是否已实现/已测试", "[../acceptance/capability-matrix.md](../acceptance/capability-matrix.md)", "状态看矩阵，不看本页"},
		{"部署/运维操作", "[../deployment/README.md](../deployment/README.md) 与 [../guide/README.md](../guide/README.md)", "任务导向文档"},
	}
	snippetRows := make([][]string, 0, len(m.Snippets))
	for _, snippet := range m.Snippets {
		snippetRows = append(snippetRows, []string{"`" + snippet.Symbol + "`", sourceLink(pathSnippetFile)})
	}
	return joinBlocks(
		"# AI 入口（机器可读优先）\n\n"+
			"> 面向 AI 与自动化调用者：先读本页，再按任务直接读对应机器 JSON 或稳定 Markdown。"+
			"本目录全部由 `scripts/reference` 从代码生成，**不要手工编辑**；引用接口时以 JSON/源码为准，"+
			"不要把本文当“功能已实现”的证明（状态见能力矩阵）。",
		"## 1. 使用约定\n\n"+
			bulletList([]string{
				"机器优先：需要枚举/匹配/生成调用时读 4 个机器 JSON；需要解释/边界/示例时读 Markdown。",
				"引用事实时带上错误码/权限键/路由/命令的稳定标识，不要引用会随重构变化的文件路径作为契约。",
				"未知符号先运行 `go run ./scripts/reference -check` 与 `go doc ./app`；`-check` 失败表示文档与代码漂移，先修生成物。",
				"不要把本目录之外的开发协作材料（`.ai/`、`AGENTS.md`、`MEMORY.md`）当作产品契约；产品交付文档只在 `docs/`。",
				"涉及秘密/令牌/恢复码时只引用字段名与错误码，不生成或回显真实值。",
				"能力是否已实现/已验收：读 [能力矩阵](../acceptance/capability-matrix.md)；本页不重复状态。",
			}),
		"## 2. 机器 JSON（程序/AI 直接消费）\n\n"+
			markdownTable([]string{"文件", "schema 后缀", "内容"}, jsonRows),
		"## 3. 任务 → 入口\n\n"+
			markdownTable([]string{"任务", "入口", "说明"}, taskRows),
		"## 4. 最小可编译示例（源码内嵌，逐字一致）\n\n"+
			markdownTable([]string{"示例函数", "源码"}, snippetRows)+
			"\n示例分别内嵌于 [errors.md](errors.md)、[configuration.md](configuration.md)、[go-api.md](go-api.md)；"+
			"`go build ./examples/reference-snippets` 做真实编译校验。\n",
		"## 5. 覆盖范围与阶段\n\n"+
			bulletList([]string{
				fmt.Sprintf("错误码 %d、权限键 %d、配置字段 %d、管理路由 %d、协议路径 %d、页面命名路由 %d、CLI 子命令 %d、能力 %d。",
					len(m.Errors), len(m.Permissions), len(m.ConfigFields), len(m.AdminRoutes), len(m.ProtocolPaths),
					len(m.Pages), countCLISubcommands(m.CLIBinaries), len(m.Capabilities)),
				"Go API：Phase A 提供 Runtime 生命周期/访问器与接口总览；方法级参考（身份/范围/分页/幂等/错误/示例）Phase B 补齐。",
				"OpenAPI 仍是最小契约，不构造成完整业务 schema；业务路由以 http-routes.json 为准。",
			}),
		"## 6. 生成与校验命令\n\n"+
			codeBlock("powershell", "go run ./scripts/reference -write\n"+
				"go run ./scripts/reference -check\n"+
				"go run ./scripts/verify-docs\n"+
				"go build ./examples/reference-snippets"),
	)
}
