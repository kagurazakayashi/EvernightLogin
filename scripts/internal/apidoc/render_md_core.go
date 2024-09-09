package apidoc

import (
	"fmt"
	"strings"
)

// 本文件渲染参考索引、错误码、权限、配置与变更记录。所有正文由生成器拥有，
// 不允许手工编辑；需要修改措辞时改这里的渲染代码并重新 -write。

// renderIndex 渲染 docs/reference/README.md（参考目录总索引）。
func (m *Model) renderIndex(used map[string]bool) []byte {
	fileRows := [][]string{
		{fileErrors, fmt.Sprintf("公开错误码表（%d 个注册码 + 公开说明 + 防泄露边界）", len(m.Errors))},
		{filePermissions, "内置权限目录（权限键/角色/用户组 + 谁能在什么范围做什么）"},
		{fileConfiguration, "配置字段元数据（字段/环境变量/生效分类/秘密标记；语义以 guide 为准）"},
		{fileHTTPAPI, "HTTP 契约：管理 JSON API 路由、协议路径、页面命名路由"},
		{fileCLI, "CLI 参考：三个程序的命令树、flag 与稳定退出码"},
		{fileGoAPI, "公开 Go API 参考：运行时生命周期与服务接口总览（Phase A 框架，Phase B 方法级补齐）"},
		{fileCapability, fmt.Sprintf("能力映射：catalog.json 的 %d 项能力 → 参考文档与机器 JSON 锚点", len(m.Capabilities))},
		{fileAIIndex, "AI 入口：按任务找文档/机器 JSON/示例与校验命令"},
		{fileChangeLog, "公开接口变更记录（Phase B 迁入完整历史）"},
	}
	jsonRows := [][]string{
		{fileErrorsJSON, "错误码：码/分类/HTTP/公开含义/原因/建议/重试"},
		{filePermissionsJSON, "权限键 + 预设角色 + 用户组 + 应用模板"},
		{fileHTTPRoutesJSON, "管理路由 + 协议路径/端点 + 页面命名路由"},
		{fileHTTPOpenAPIJSON, "OpenAPI 3：JSON API + 页面/表单操作（字段/响应/状态转移）"},
		{fileCLIJSON, "CLI 命令树 + flag + 退出码"},
	}
	countRows := [][]string{
		{"公开错误码", fmt.Sprintf("%d", len(m.Errors))},
		{"内置权限键", fmt.Sprintf("%d（预设角色 %d、系统用户组 %d、应用角色模板 %d、应用用户组模板 %d）",
			len(m.Permissions), len(m.Roles), len(m.Groups), len(m.ApplicationRoles), len(m.ApplicationGroups))},
		{"配置字段", fmt.Sprintf("%d", len(m.ConfigFields))},
		{"管理 JSON API 路由", fmt.Sprintf("%d", len(m.AdminRoutes))},
		{"协议路径 / 端点表", fmt.Sprintf("%d / %d", len(m.ProtocolPaths), len(m.ProtocolEndpoints))},
		{"内置页面命名路由", fmt.Sprintf("%d", len(m.Pages))},
		{"页面/表单 OpenAPI 操作", fmt.Sprintf("%d（未登记契约的页面路由 %d）", pageOperationCount(m), pageUnregisteredCount(m))},
		{"CLI", fmt.Sprintf("%d 个程序 / %d 个子命令 / %d 个 flag",
			len(m.CLIBinaries), countCLISubcommands(m.CLIBinaries), countCLIFlags(m.CLIBinaries))},
		{"公开 Go API（app）", fmt.Sprintf("Runtime 方法 %d、服务接口 %d（方法 %d）、公开函数 %d、公开类型 %d",
			len(m.GoAPI.RuntimeMethods), len(m.GoAPI.Interfaces), countInterfaceMethods(m.GoAPI),
			len(m.GoAPI.AppFuncs), len(m.GoAPI.AppTypes))},
		{"公开 Go API（根包）", fmt.Sprintf("类型 %d、函数 %d", m.GoAPI.RootTypeCount, m.GoAPI.RootFuncCount)},
		{"能力声明", fmt.Sprintf("%d", len(m.Capabilities))},
	}
	crossRows := [][]string{
		{"管理路由", fmt.Sprintf("%d", m.CrossCheck.MatrixAdminRoutes), fmt.Sprintf("%d", len(m.AdminRoutes))},
		{"页面路由", fmt.Sprintf("%d", m.CrossCheck.MatrixPages), fmt.Sprintf("%d", len(m.Pages))},
		{"协议路径", fmt.Sprintf("%d", m.CrossCheck.MatrixProtocol), fmt.Sprintf("%d", len(m.ProtocolPaths))},
		{"CLI 子命令", fmt.Sprintf("%d", m.CrossCheck.MatrixCLI), fmt.Sprintf("%d", countCLISubcommands(m.CLIBinaries))},
		{"权限键", fmt.Sprintf("%d", m.CrossCheck.MatrixPermissions), fmt.Sprintf("%d", len(m.Permissions))},
		{"app 函数（含导出方法）", fmt.Sprintf("%d", m.CrossCheck.MatrixAppFuncs), fmt.Sprintf("%d", len(m.GoAPI.AppFuncs)+m.GoAPI.ExportedMethodCount)},
		{"根包公开类型", fmt.Sprintf("%d", m.CrossCheck.MatrixRootTypes), fmt.Sprintf("%d", m.GoAPI.RootTypeCount)},
	}
	pendingRows := make([][]string, 0, len(m.PendingSections))
	for _, section := range m.PendingSections {
		pendingRows = append(pendingRows, []string{section.ID, section.Reason, fmt.Sprintf("%d", section.Symbols)})
	}

	warnings := "无。"
	if len(m.CrossCheck.Mismatches) > 0 || len(m.Warnings) > 0 {
		lines := append([]string{}, m.Warnings...)
		lines = append(lines, m.CrossCheck.Mismatches...)
		warnings = bulletList(lines)
	}

	return joinBlocks(
		"# 接口参考（人类与 AI 共用）\n\n"+
			"> 本目录由 `go run ./scripts/reference -write` 生成，**不要手工编辑**。"+
			"修改生成逻辑请改 `scripts/internal/apidoc/` 后重新生成；`-check` 与 "+
			"[verify-docs](../guide/README.md) 会逐字节核对，文档与代码漂移会让校验失败。\n\n"+
			"这里是人类与 AI 共用的**单一接口参考入口**：Go API、HTTP、CLI、权限、错误码、配置与"+
			"能力映射都以代码为唯一事实来源生成，不维护第二套手写全集。",
		"## 1. 现在先读什么\n\n"+
			bulletList([]string{
				"**先判断“能不能用 / 已实现到什么程度”**：读 [能力矩阵](../acceptance/capability-matrix.md)（状态）与本页“覆盖范围”。",
				"**嵌入 Go 程序**：读 [go-api.md](go-api.md)（运行时生命周期与公开接口总览）→ [errors.md](errors.md) → [配置 guide](../guide/configuration.md)。",
				"**独立部署/运维**：读 [HTTP 契约](http-api.md)、[CLI](cli.md)、[部署文档](../deployment/README.md)。",
				"**业务接入**：读 [HTTP 契约](http-api.md) 与 [业务接入契约](../deployment/integration.md)。",
				"**排障**：读 [错误码](errors.md) 与 [排障指南](../guide/troubleshooting.md)。",
				"**AI/自动化**：直接读 [ai-index.md](ai-index.md) 与 5 个机器 JSON。",
			}),
		"## 2. 文件索引\n\n### 2.1 Markdown（稳定锚点，人类与 AI 均可读）\n\n"+
			markdownTable([]string{"文件", "内容"}, fileRows),
		"### 2.2 机器可读 JSON（由本工具生成，供程序/AI 直接消费）\n\n"+
			markdownTable([]string{"文件", "内容"}, jsonRows),
		"## 3. 覆盖范围（本次生成盘点）\n\n"+
			markdownTable([]string{"对象", "数量"}, countRows),
		"## 4. 与能力矩阵的只读交叉核对\n\n"+
			"本工具**不重新生成**能力矩阵，只读取 [capability-matrix.json](../acceptance/capability-matrix.json) "+
			"的盘点数量做交叉核对；不一致只作为告警（矩阵由能力盘点步骤维护，口径可能不同）。\n\n"+
			markdownTable([]string{"对象", "能力矩阵盘点", "reference 扫描"}, crossRows)+
			"\n"+warnings+"\n",
		"## 5. 生成与校验\n\n"+
			codeBlock("powershell", "go run ./scripts/reference -write     # 重新生成 docs/reference\n"+
				"go run ./scripts/reference -check     # 校验生成物与源码一致（只读）\n"+
				"go run ./scripts/verify-docs          # 文档总校验（含 reference 检查）\n"+
				"go build ./examples/reference-snippets # 最小示例真实编译")+
			"\n生成物约定：确定性排序、LF 行尾、无时间戳、无本机路径；`-write` 原子写入，`-check` 只读。",
		"## 6. 阶段范围与 Phase B 待补\n\n"+
			"Phase A（步骤 245A）先交付机器 JSON 与稳定领域参考。公开 Go API 的**方法级**参考"+
			"（每个方法调用身份/应用范围/分页/取消/幂等/任务终态/错误/最小例）等 "+
			"214/215（目录与 app 类型重组）及 226–235 公开门面稳定后再补齐，避免文档随重构反复改写。\n\n"+
			markdownTable([]string{"Phase B 领域", "待补内容", "涉及接口数"}, pendingRows),
		"## 7. 维护约定\n\n"+
			bulletList([]string{
				"新增/修改公开错误码、权限键、HTTP 路由、页面路由、协议路径、CLI 命令或公开 Go 符号后，运行 `-write` 并提交生成物；`-check` 会阻止漂移。",
				"能力声明（catalog.json）中的声明若无法映射到实际符号，`-check` 会失败：先修声明或补实现，再生成文档。",
				"214/215 重构会移动页面实现与 app 类型文件；届时只需更新 `scripts/internal/apidoc/sources.go` 的源码路径或扫描目录，再重新生成。",
				"文档中的最小示例来自 [examples/reference-snippets](../../examples/reference-snippets/snippets.go)，由 `go build` 真实编译；新增示例必须被文档引用。",
				"OpenAPI 现含两部分：JSON API（健康/文档端点）与页面/表单操作（账户/资料/会话/注册登录/MFA/三种恢复流程）；管理 JSON API 的请求/响应模式由后续管理组步骤统一定义，在此之前以本目录机器 JSON 与源码为准（见 [http-api.md](http-api.md)）。",
			}),
	)
}

// renderErrors 渲染 errors.md。
func (m *Model) renderErrors(used map[string]bool) []byte {
	rows := make([][]string, 0, len(m.Errors))
	for _, entry := range m.Errors {
		rows = append(rows, []string{
			"`" + entry.Code + "`", fmt.Sprintf("%d", entry.HTTPStatus), entry.Category,
			entry.DefaultMessage, entry.Cause, entry.Advice, entry.Retry,
		})
	}
	return joinBlocks(
		"# 公开错误码参考（"+fmt.Sprintf("%d", len(m.Errors))+" 个注册码）\n\n"+
			"> 由 `errs.RegisteredErrorCodes()` + `errs.LookupErrorCodeGuidance()` 生成；"+
			"任务导向排障见 [../guide/troubleshooting.md](../guide/troubleshooting.md)，"+
			"历史错误码手册见 [../requirements/login_错误码与排障手册.md](../requirements/login_错误码与排障手册.md)。\n\n"+
			"错误码是**协议/业务拒绝**的稳定机器标识；公开响应同时带 `request_id`，用于把用户"+
			"报错与管理端审计/日志关联。错误文本是公开脱敏文本，不包含内部堆栈、SQL、文件路径或秘密。",
		"## 1. 注册错误码表\n\n"+
			markdownTable([]string{"错误码", "HTTP", "分类", "公开含义", "可能原因", "处理建议", "重试"}, rows),
		"## 2. 错误响应与调用边界\n\n"+
			bulletList([]string{
				"HTTP/协议/Go 门面共用同一套错误码与 `request_id` 关联；错误响应信封与 CSRF/会话约定见 [http-api.md](http-api.md)。",
				"**防枚举**：登录、注册、找回等公开入口不区分“账户不存在/凭证错误/已禁用”等内部原因；不要依据错误差异探测账户状态。",
				"**找回令牌预检查统一失败语义（步骤 204）**：`PasswordReset().ValidateToken` / `ValidateTokenWithSource` 是非消费预检查，领域判断的所有失败统一为 `CHALLENGE_INVALID`；调用前校验保持各自稳定码（非法请求编号/来源 → `REQ_INVALID`，限流 → `RATE_LIMITED`，服务未装配 → `CONFIG_INVALID`）。最终 `Complete` 会重新验证完整状态。",
				"**已授权查询的“未找到”是 app 级公开契约（步骤 207）**：`app.NotFoundCode`、`app.ErrNotFound`、`app.NotFoundError`、`app.IsNotFound(err)`；权限检查先于查询，未授权不会因“未找到”泄露存在性；该码**不加入**根包 48 码注册表，HTTP 层建议映射 404。",
				"**fail-closed**：认证/授权/审计依赖失败时默认拒绝，不用重试绕过；`AUTHZ_UNAVAILABLE`、`DB_UNAVAILABLE`、`AUDIT_WRITE_FAILED` 表示依赖故障而不是操作结果。",
				"日志/审计/支持工单只记录错误码与 `request_id`，不记录完整 Token、密码、恢复码或找回链接。",
			}),
		"## 3. 最小可编译示例\n\n"+m.snippetBlock(used, "ExampleLookupError"),
		"## 4. 机器可读\n\n"+
			"- ["+fileErrorsJSON+"]("+fileErrorsJSON+")：码/分类/HTTP/公开含义/原因/建议/重试的完整机器表。\n"+
			"- 生成源：`errs.RegisteredErrorCodes()`（顺序与手册一致）与 `errs.LookupErrorCodeGuidance()`。",
	)
}

// renderPermissions 渲染 permissions.md。
func (m *Model) renderPermissions(used map[string]bool) []byte {
	permissionRows := make([][]string, 0, len(m.Permissions))
	for _, entry := range m.Permissions {
		permissionRows = append(permissionRows, []string{
			"`" + entry.Key + "`", entry.Name, entry.Summary, entry.Scope, entry.Limits,
			boolMark(entry.RequiresReauth), boolMark(entry.RootOnly),
			joinCode(entry.DefaultRoles), boolMark(entry.Implemented), joinPipes(entry.Capabilities),
		})
	}
	roleRows := roleTableRows(m.Roles)
	applicationRoleRows := roleTableRows(m.ApplicationRoles)
	groupRows := groupTableRows(m.Groups)
	applicationGroupRows := groupTableRows(m.ApplicationGroups)
	return joinBlocks(
		"# 内置权限、角色与用户组参考\n\n"+
			"> 由 `internal/preset.DefaultCatalog()` 生成（目录版本 `"+m.CatalogVersion+"`）；"+
			"授权/委派规则与页面操作见 [../guide/applications-and-permissions.md](../guide/applications-and-permissions.md)"+
			" 与 [../guide/roles-and-scopes.md](../guide/roles-and-scopes.md)。\n\n"+
			"这份参考回答“**谁能对哪些数据做什么**”：系统权限面向整个身份服务，应用权限默认只在该"+
			"应用范围内生效；权限键创建后不可修改，内置权限不可删除、只能按规则停用。",
		"## 1. 使用规则\n\n"+
			bulletList([]string{
				"**系统 vs 应用**：系统权限（如 `users.*`、`audit.*`）作用于整个身份服务；应用独有权限只在该应用范围内判定，同名不等于同权限。",
				"**root 特殊**：`root_only` 权限只允许 root 特殊通道使用，普通角色不能组合；root 不能作为普通角色分配产生。",
				"**默认拒绝**：没有显式授予即拒绝；功能权限本身不替代业务资源归属检查（`RESOURCE_FORBIDDEN` 表示范围不足，而非缺少功能权限）。",
				"**再次认证**：标记“需要再次认证”的操作要求近期强认证或一次性批准，未满足时 fail-closed（`REAUTH_REQUIRED`/`MFA_REQUIRED`）。",
				"**实现标记**：`Implemented=false` 表示该权限仅登记目录说明、对应操作尚无可执行路径，不能当作开关或已实现能力使用。",
				"**委派**：应用委派不能获得系统资格或控制 root；委派范围只减不增。",
			}),
		"## 2. 权限键表（"+fmt.Sprintf("%d", len(m.Permissions))+" 个）\n\n"+
			markdownTable([]string{"权限键", "名称", "能做什么", "影响范围", "不能做什么", "再认证", "root only", "默认角色", "已实现", "关联能力"}, permissionRows),
		"## 3. 系统预设角色（"+fmt.Sprintf("%d", len(m.Roles))+" 个）\n\n"+
			markdownTable([]string{"角色键", "名称", "说明", "限制", "内置", "默认权限", "默认用户组", "关联能力"}, roleRows),
		"## 4. 应用创建时的角色模板（"+fmt.Sprintf("%d", len(m.ApplicationRoles))+" 个）\n\n"+
			markdownTable([]string{"角色键", "名称", "说明", "限制", "内置", "默认权限", "默认用户组", "关联能力"}, applicationRoleRows),
		"## 5. 系统默认用户组（"+fmt.Sprintf("%d", len(m.Groups))+" 个）\n\n"+
			markdownTable([]string{"用户组键", "名称", "说明"}, groupRows),
		"## 6. 应用创建时的用户组模板（"+fmt.Sprintf("%d", len(m.ApplicationGroups))+" 个）\n\n"+
			markdownTable([]string{"用户组键", "名称", "说明"}, applicationGroupRows),
		"## 7. 机器可读\n\n"+
			"- ["+filePermissionsJSON+"]("+filePermissionsJSON+")：权限/角色/用户组完整机器表（含默认权限与能力关联）。\n"+
			"- 生成源：`internal/preset.DefaultCatalog()`（版本化只读目录；不创建账户、不自动赋权）。",
	)
}

// renderConfiguration 渲染 configuration.md。
func (m *Model) renderConfiguration(used map[string]bool) []byte {
	rows := make([][]string, 0, len(m.ConfigFields))
	for _, field := range m.ConfigFields {
		rows = append(rows, []string{
			"`" + field.Field + "`", "`" + field.Env + "`", classLabel(field.Class), boolMark(field.Secret),
		})
	}
	return joinBlocks(
		"# 配置字段机器参考（"+fmt.Sprintf("%d", len(m.ConfigFields))+" 个字段）\n\n"+
			"> **语义权威不在本页**：字段含义、默认值、校验规则、覆盖优先级与迁移说明见 "+
			"[../guide/configuration.md](../guide/configuration.md)（由 `verify-docs` 逐字段核对）。"+
			"本页只提供机器元数据（字段/环境变量/生效分类/秘密标记），由 `config.Fields()` 生成。\n\n"+
			"配置来源优先级：**内置默认 < YAML < 环境变量 < 显式代码覆盖**；未知字段、重复键、类型错误、越界或危险组合会拒绝启动。",
		"## 1. 生效分类\n\n"+
			bulletList([]string{
				"**重启生效**：修改后必须重启进程；热重载不会改变当前有效值。",
				"**重载生效**：宿主触发重新加载后生效；仍需服务端校验与失败回退（失败保留最后有效状态）。",
				"**秘密字段**：诊断/日志只显示“已配置/未配置”等脱敏状态；秘密只通过 `{env: NAME}` 或 `{file: 路径}` 引用，不写明文 YAML。",
				"环境变量命名为 `LOGIN_` + 点分路径大写并用下划线连接（如 `LOGIN_DATABASE_PATH`）。",
			}),
		"## 2. 字段表（"+fmt.Sprintf("%d", len(m.ConfigFields))+" 个）\n\n"+
			markdownTable([]string{"字段", "环境变量", "生效分类", "秘密"}, rows),
		"## 3. 最小可编译示例\n\n"+m.snippetBlock(used, "ExampleConfigLookup"),
		"## 4. 相关入口\n\n"+
			"- 完整语义与默认值：[../guide/configuration.md](../guide/configuration.md)\n"+
			"- 配置校验 CLI：[../guide/root-cli.md](../guide/root-cli.md)（`loginctl config validate`）\n"+
			"- 配置管理与版本冲突（管理员）：[../guide/configuration.md](../guide/configuration.md) 与设置权限说明。",
	)
}

// renderChangeLog 渲染 change-log.md。
func (m *Model) renderChangeLog(used map[string]bool) []byte {
	return joinBlocks(
		"# 公开接口变更记录\n\n"+
			"> 本文记录**公开契约**（公开 Go API、HTTP 路由/错误、CLI、权限键、配置字段）的兼容性"+
			"变更。破坏性变更策略见 [../embedding/host_integration.md](../embedding/host_integration.md) 第 2 节。\n\n"+
			"完整历史变更记录仍保留在嵌入指南的“变更记录”小节；Phase B（245B，等 214/215/226–235 稳定）"+
			"会把历史条目迁入本文件并停用旧小节，避免两处维护。在那之前以嵌入指南为准。",
		"## 1. 记录规则\n\n"+
			bulletList([]string{
				"兼容性变更（新增可选字段/新方法/新错误码）与**破坏性变更**分开标注；破坏性变更必须给出迁移方式与替代接口。",
				"错误码、权限键、HTTP 路由、CLI 命令与配置字段是稳定机器契约；新增属兼容，删除/改名/改变含义属破坏性变更。",
				"数据迁移与公开契约变更分别记录；数据库迁移只向前、不清库，见 [../database/存储模型与迁移设计.md](../database/存储模型与迁移设计.md)。",
			}),
		"## 2. 本轮记录（步骤 245A：接口参考首版）\n\n"+
			bulletList([]string{
				"新增人类与 AI 共用的 `docs/reference/`：由代码生成的 4 个机器 JSON（错误码/权限/HTTP 路由/CLI）与稳定领域 Markdown（错误码/权限/配置/HTTP/CLI/能力映射/Go API 框架/AI 入口）。",
				"`scripts/verify-docs` 接入 `-reference=auto|off|require`：`docs/reference` 存在时逐字节校验生成物；新增公开符号未登记映射、能力声明无法解析时 fail-closed。",
				"新增 `examples/reference-snippets` 最小可编译示例，并被参考文档内嵌；文档内嵌代码与源码逐字一致由 `-check` 保证。",
				"尚未包含**方法级** Go API 参考：Phase B 在 214/215 与 226–235 稳定后补齐，当前 [go-api.md](go-api.md) 提供生命周期/接口总览与稳定领域框架。",
				"步骤 268 起 OpenAPI 增加**页面/表单操作段**（账户/资料/会话/注册登录/MFA/三种恢复流程，95 条），新增生成物 [http-openapi.json](http-openapi.json)；页面与 JSON API 用 `x-login-route-kind` 分开标识，秘密字段 writeOnly、示例为合成值，契约与 AST 扫描路由不一致时 `-check` 失败。",
			}),
		"## 3. 相关文档\n\n"+
			"- 公开 API 稳定范围与破坏性变更策略：[../embedding/host_integration.md](../embedding/host_integration.md)\n"+
			"- 版本与验收记录：[../acceptance/README.md](../acceptance/README.md)\n"+
			"- 能力状态（是否已实现）：[../acceptance/capability-matrix.md](../acceptance/capability-matrix.md)",
	)
}

// roleTableRows 把角色条目转换为表格行。
func roleTableRows(roles []RoleEntry) [][]string {
	rows := make([][]string, 0, len(roles))
	for _, role := range roles {
		rows = append(rows, []string{
			"`" + role.Key + "`", role.Name, role.Summary, role.Limits,
			boolMark(role.Builtin), joinCode(role.DefaultPermissions),
			"`" + role.DefaultGroupKey + "`", joinPipes(role.Capabilities),
		})
	}
	return rows
}

// groupTableRows 把用户组条目转换为表格行。
func groupTableRows(groups []GroupEntry) [][]string {
	rows := make([][]string, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, []string{"`" + group.Key + "`", group.Name, group.Description})
	}
	return rows
}

// boolMark 把布尔值渲染为中文标记。
func boolMark(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

// trimTrailing 去掉字符串末尾空白（辅助函数，保持模板整洁）。
func trimTrailing(text string) string {
	return strings.TrimRight(text, " \t\n")
}
