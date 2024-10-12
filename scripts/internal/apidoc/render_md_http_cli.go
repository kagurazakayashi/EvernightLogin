package apidoc

import (
	"fmt"
	"strings"
)

// 本文件渲染 HTTP 与 CLI 参考。路由/命令由 AST 扫描实际注册得到，不手写第二份
// 端点清单；鉴权与错误语义在少数安全关键处由人工边界说明承担。

// renderHTTPAPI 渲染 http-api.md。
func (m *Model) renderHTTPAPI(used map[string]bool) []byte {
	adminRows := make([][]string, 0, len(m.AdminRoutes))
	for _, route := range m.AdminRoutes {
		adminRows = append(adminRows, []string{
			route.Method, "`" + route.Pattern + "`", joinPipes(route.Capabilities), sourceLink(route.Source),
		})
	}
	pathRows := make([][]string, 0, len(m.ProtocolPaths))
	for _, path := range m.ProtocolPaths {
		pathRows = append(pathRows, []string{path.Name, "`" + path.Path + "`"})
	}
	contractRows := make([][]string, 0, protocolContractCount(m))
	fieldRows := make([][]string, 0, protocolContractCount(m))
	for _, contract := range protocolContractList(m) {
		errorsText := joinPipes(contract.StandardErrors)
		if len(contract.ProjectErrorCodes) > 0 {
			errorsText = "项目信封：" + joinPipes(contract.ProjectErrorCodes)
		}
		contractRows = append(contractRows, []string{
			contract.Method, "`" + contract.Path + "`", contract.EnabledWhen,
			contract.TransportKind + " / " + successStatusText(contract.SuccessStatuses),
			contract.ClientAuth, contract.SessionAuth, errorsText, contract.DiscoveryDeclared,
		})
		fieldRows = append(fieldRows, []string{
			contract.Method + " `" + contract.Path + "`",
			protocolFieldText(contract.RequestFields), protocolFieldText(contract.ResponseFields),
			strings.Join(contract.Notes, "；"),
		})
	}
	exceptionRows := make([][]string, 0, len(protocolExceptionTable()))
	if m.ProtocolContract != nil {
		exceptionRows = exceptionRows[:0]
		for _, exception := range m.ProtocolContract.Exceptions {
			exceptionRows = append(exceptionRows, []string{
				"`" + exception.Code + "`", exception.Kind,
				joinPipes(exception.Endpoints), exception.Reason,
			})
		}
	}
	pageRows := make([][]string, 0, len(m.Pages))
	for _, page := range m.Pages {
		pageRows = append(pageRows, []string{
			"`" + page.Name + "`", page.Method, "`" + page.Path + "`",
			page.Access, joinPipes(page.Capabilities), sourceLink(page.Source),
		})
	}
	return joinBlocks(
		"# HTTP 契约参考（管理 API / 协议路径 / 页面命名路由 / 页面表单 OpenAPI）\n\n"+
			"> 路由清单由 AST 扫描实际注册生成（`handler.go` 的 `add(...)`、领域 "+
			"`DomainRoute{Method, Pattern}`、协议路径常量与 `UIRoute` 页面命名路由），"+
			"不是手写端点表。鉴权/CSRF/开关与托管边界见 [../deployment/managed-api.md](../deployment/managed-api.md)、"+
			"[../deployment/app-support-api.md](../deployment/app-support-api.md) 与 "+
			"[../deployment/standalone-service.md](../deployment/standalone-service.md)。",
		"## 1. 基础约定\n\n"+
			bulletList([]string{
				"所有路径带 `server.path_prefix`（默认空）；管理 API 默认前缀 `/admin/v1`，托管 API `/api/managed/v1`，应用客服 API `/api/app/v1/support`。",
				"**默认关闭**：OAuth/OIDC 协议端点、管理 JSON API、托管 API、应用客服 API 都需显式启用；未启用时对应路径 404，维护模式一律 503。",
				"错误响应使用与 Go 门面一致的错误码 + `request_id`；**错误信封与重试语义见 [errors.md](errors.md)**，排障流程见 [../guide/troubleshooting.md](../guide/troubleshooting.md)。",
				"管理 API 复用真实管理会话并校验 CSRF（Cookie 会话写请求要求 CSRF 令牌）；页面路由与 API 路由不共享鉴权旁路。",
				"请求身份必须来自可信边界（Cookie/Authorization/宿主服务端存储）；请求参数不能自称管理员、root、应用或用户。",
				"`Host`、可信代理、TLS/mTLS 与公开基址使用同一套配置规则（`server.public_base_url`、`server.trusted_proxies`、`server.tls_terminating_proxy`）。",
			}),
		"## 2. 管理 JSON API 路由（"+fmt.Sprintf("%d", len(m.AdminRoutes))+" 条，相对管理前缀）\n\n"+
			markdownTable([]string{"方法", "路径模式", "关联能力", "定义位置"}, adminRows),
		"## 3. OAuth 2.0 / OIDC 协议端点契约（默认关闭；关闭时命名空间 404）\n\n"+
			"协议端点使用标准协议响应（RFC 6749/6750/7009/7662/8628），**不是**统一业务错误信封；"+
			"自定义扫码端点例外使用项目信封。授权端点属浏览器重定向流程，其余端点返回 JSON。\n\n"+
			"### 3.1 协议路径常量（"+fmt.Sprintf("%d", len(m.ProtocolPaths))+" 个）\n\n"+
			markdownTable([]string{"常量名", "路径"}, pathRows),
		"### 3.2 端点 HTTP 契约（"+fmt.Sprintf("%d", protocolContractCount(m))+" 个；与 doc.go 端点表双向一致）\n\n"+
			markdownTable([]string{"方法", "路径", "注册条件", "传输 / 成功状态", "客户端认证", "会话/浏览器", "协议错误", "Discovery 声明"}, contractRows),
		"### 3.3 请求/响应字段与安全说明\n\n"+
			markdownTable([]string{"端点", "请求字段", "响应字段（秘密字段标注）", "说明"}, fieldRows),
		"### 3.4 协议例外登记（显式登记，不能整体豁免）\n\n"+
			markdownTable([]string{"例外", "类别", "涉及端点", "理由"}, exceptionRows),
		"## 4. 内置页面命名路由（"+fmt.Sprintf("%d", len(m.Pages))+" 个冻结命名路由）\n\n"+
			"页面路由是 `ui.v1` 命名契约：名字/路径/访问级别稳定，DOM 与模板不承诺稳定；"+
			"宿主可用 `PageOverrides` 替换展示，但不改变服务端认证/授权/CSRF。214 起页面实现"+
			"位于公开包 `ui/`，根包保留 `UIRoute`/`BuiltinUIRoutes` 等兼容别名；下表“定义位置”"+
			"即实际定义文件。表中包含仅在 `EnableComponentPreview` 时注册的组件预览路由"+
			"（默认不注册），不要把它们当作默认页面。",
		markdownTable([]string{"命名路由", "方法", "路径", "访问级别", "关联能力", "定义位置"}, pageRows),
		"## 5. 页面/表单操作契约（OpenAPI 页面段，"+
			fmt.Sprintf("%d", pageOperationCount(m))+" 条）\n\n"+
			"账户/资料/会话/注册登录/MFA/三种恢复流程（邮件找回、恢复代码重绑、客服人工恢复）的页面路由"+
			"已在机器可读 OpenAPI 中定义请求字段、响应、状态转移与限流说明；页面与 JSON API 用 "+
			"`x-login-route-kind` 分开标识；页面处理器产生的错误以 HTML 错误页呈现，但传输层前置拒绝"+
			"（路径规范化/CSRF/限流/并发/超时/内部 panic）在进入页面处理器之前返回 application/json 统一错误信封。"+
			"\n\n"+bulletList([]string{
			"**同源生成**：方法与路径来自 `ui/` 中 `UIRoute` 字面量的 AST 扫描；字段/响应/状态转移契约在 `internal/transport/pagecontracts_*.go`；二者不一致时 `scripts/reference -check` 直接失败。",
			"**运行期文档**：`{prefix}/openapi.json` 由实际注册的页面路由生成（宿主未挂载的模块不会出现），`docs/reference/http-openapi.json` 是全部模块的离线投影。",
			"**传输语义**：写操作为 `application/x-www-form-urlencoded`（头像上传为 `multipart/form-data`），要求 CSRF 隐藏令牌与精确同源；成功通常 303 跳转流程下一步。页面处理器产生的错误以 HTML 错误页返回（HTTP 状态码 + 页面错误摘要）；传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/内部 panic）返回 `application/json` 统一业务错误信封（Error schema），不声明未实现的额外错误码头。",
			"**秘密与示例**：密码/令牌/恢复码/WebAuthn 断言等字段标记 `writeOnly`，示例全部是明确合成值，不包含可用凭据。",
			"**范围**：管理/审计/报告/备份/OAuth 等页面路由尚未登记本步契约，完整路由清单见 §4 与 [http-routes.json](http-routes.json)。",
			"**启用条件**：对应 `ui.Page*` 模块由宿主装配；OAuth 2.0 / OIDC 协议端点由 `protocol.enabled`（默认 false）显式启用，关闭时保留前缀直接 404，不属于本表。",
		})+"\n"+markdownTable(
			[]string{"命名路由", "方法", "路径", "访问级别", "页面模块", "请求字段", "响应状态", "状态转移（摘要）"},
			m.PageOpenAPI.pageOperationTableRows()),
		"## 6. OpenAPI 与 Discovery 边界（不造假完整契约）\n\n"+
			bulletList([]string{
				"OpenAPI 由三部分组成：运行期最小 JSON API（`/healthz`、`/openapi.json`，错误用统一信封）；页面/表单操作（本页 §5）；**协议端点离线 OpenAPI**（[protocol-openapi.json](protocol-openapi.json)，本页 §3 的同源生成物，不影响运行期 `/openapi.json`）。管理 JSON API 的请求/响应模式由管理组契约（[http-openapi-admin.json](http-openapi-admin.json)）定义，§2 路由清单用于交叉核对。",
				"OAuth 2.0 / OIDC 协议端点默认关闭（`protocol.enabled=false`），关闭时协议命名空间返回普通 404；启用后使用标准协议响应（RFC 6749/6750/7009/7662/8628），**不被统一业务错误信封包装**；自定义扫码端点按 §3.4 例外使用项目信封。",
				"协议契约与 OpenAPI 段由 `scripts/internal/apidoc/protocol_contract.go` 的同一份表生成：端点/方法/字段/错误/开关与 `internal/protocolapi/doc.go` 端点表及 `routes.go` 条件注册双向核对，不一致或例外未登记时 `scripts/reference -check` 直接失败。",
				"OIDC Discovery 只声明真实启用的能力（含 `EnableIntrospection`/`EnableDeviceFlow` 条件端点）；扫码扩展与本包设备取消扩展不伪装成标准 Discovery 字段。真实第三方 OIDC 客户端、设备码/扫码真机互操作等未完成验收的边界见 [../guide/login-and-oauth.md](../guide/login-and-oauth.md)。",
				"管理/托管/客服 API 的授权、对象/字段白名单与审计约束见对应部署文档；不要把管理 API 暴露给业务应用。",
				"新增/删除路由必须同步更新能力声明（catalog.json）、页面契约与协议契约；未映射的公开符号、能力声明或契约/路由不一致会让 `scripts/reference -check` 失败。",
			}),
		"## 7. 机器可读\n\n"+
			"- ["+fileHTTPRoutesJSON+"]("+fileHTTPRoutesJSON+")：方法/路径/来源/能力关联的完整机器表（含协议端点 HTTP 契约与例外登记）。\n"+
			"- ["+fileHTTPOpenAPIJSON+"]("+fileHTTPOpenAPIJSON+")：页面/表单 OpenAPI 3 文档（秘密字段 writeOnly、示例为合成值）。\n"+
			"- ["+fileProtocolOpenAPIJSON+"]("+fileProtocolOpenAPIJSON+")：协议端点 OpenAPI 3 文档（OAuth/OIDC/设备码/扫码；标准错误与项目信封分别建模）。\n"+
			"- 页面 `Access` 列来自 `UIRoute` 字面量；执行时仍由服务端重新判定，台账仅用于契约对照。",
	)
}

// successStatusText 汇总成功状态码。
func successStatusText(statuses []int) string {
	if len(statuses) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%d", status))
	}
	return strings.Join(parts, "/")
}

// protocolFieldText 渲染协议字段列表：名称、位置、必填与秘密标注。
func protocolFieldText(fields []ProtocolField) string {
	if len(fields) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		text := "`" + field.Name + "`（" + field.In
		if field.Required {
			text += "，必填"
		}
		if field.Secret {
			text += "，秘密"
		}
		text += "）"
		parts = append(parts, text)
	}
	return strings.Join(parts, "、")
}

// pageOperationCount 返回已登记页面操作数量（模型缺失时返回 0）。
func pageOperationCount(model *Model) int {
	if model.PageOpenAPI == nil {
		return 0
	}
	return len(model.PageOpenAPI.Operations)
}

// pageUnregisteredCount 返回未登记契约的页面路由数量（模型缺失时返回 0）。
func pageUnregisteredCount(model *Model) int {
	if model.PageOpenAPI == nil {
		return 0
	}
	return model.PageOpenAPI.Unregistered
}

// renderCLI 渲染 cli.md。
func (m *Model) renderCLI(used map[string]bool) []byte {
	blocks := []string{
		"# CLI 参考（login-server / loginctl / login-backup / login-setup）\n\n" +
			"> 命令树、flag 与退出码由 AST 扫描 `cmd/` 与 `internal/managecli/` 实际注册生成；" +
			"任务导向说明见 [../guide/root-cli.md](../guide/root-cli.md)、" +
			"[../guide/backup-and-restore.md](../guide/backup-and-restore.md) 与 " +
			"[../deployment/standalone-service.md](../deployment/standalone-service.md)。",
		"## 1. 通用约定\n\n" +
			bulletList([]string{
				"CLI 只负责装配与命令执行；不绕过领域授权、敏感策略或审计。本地应急命令要求停服/维护 + 排他锁。",
				"危险写动作要求显式确认参数（如 `--confirm ...`）或近期再次认证证明；确认框/参数存在不等于放行，服务端会重新判定。",
				"`--json` 输出为机器可读结果，可能包含 `request_id` 与稳定错误码；不要把输出中的秘密/令牌写日志或工单。",
				"退出码 0 表示成功；非 0 的稳定含义见各程序“退出码”表（`login-server` 为 0/1；`loginctl`、`login-backup` 有细分稳定码）。脚本应依据退出码与 `--json` 结果判断，而不是解析人类文本。",
				"未知子命令/参数一律拒绝并给出用法，不静默忽略。",
			}),
	}
	for _, binary := range m.CLIBinaries {
		commandRows := make([][]string, 0, len(binary.Subcommands))
		for _, command := range binary.Subcommands {
			flagCount := fmt.Sprintf("%d", len(command.Flags))
			commandRows = append(commandRows, []string{"`" + command.Name + "`", flagCount, sourceLink(command.Source)})
		}
		block := "## 程序：" + binary.Name + "（" + fmt.Sprintf("%d", len(binary.Subcommands)) + " 个子命令）\n\n" +
			markdownTable([]string{"子命令", "flag 数", "定义位置"}, commandRows)
		for _, command := range binary.Subcommands {
			if len(command.Flags) == 0 {
				continue
			}
			flagRows := make([][]string, 0, len(command.Flags))
			for _, flag := range command.Flags {
				flagRows = append(flagRows, []string{
					"`--" + flag.Name + "`", flag.Type, "`" + flag.Default + "`", flag.Usage,
				})
			}
			block += "\n### `" + binary.Name + " " + command.Name + "` 的 flag\n\n" +
				markdownTable([]string{"flag", "类型", "默认值", "说明"}, flagRows)
		}
		if len(binary.ExitCodes) > 0 {
			exitRows := make([][]string, 0, len(binary.ExitCodes))
			for _, code := range binary.ExitCodes {
				exitRows = append(exitRows, []string{code.Name, fmt.Sprintf("%d", code.Value), code.Doc})
			}
			block += "\n### `" + binary.Name + "` 稳定退出码\n\n" +
				markdownTable([]string{"常量", "值", "含义"}, exitRows)
		}
		blocks = append(blocks, block)
	}
	blocks = append(blocks,
		"## 嵌套子命令说明\n\n"+
			bulletList([]string{
				"`loginctl` 的部分命令是命令组：`loginctl config <子命令>`、`loginctl diag <子命令>`、`loginctl user list`、`loginctl audit events list` 等；上面只展开顶层命令与其 flag，二级动作以 [../guide/root-cli.md](../guide/root-cli.md) 与 `loginctl help` 为准。",
				"`login-server` 使用 cobra 命令树（`serve`、`init`），全局 `--version/--help` 由框架提供。",
				"`login-setup` 的顶层子命令来自其显式命令表，flag 含全局 `--config`/`--master-key-file`/`--json` 与各命令附加项；需要 PTY 的是全屏 CUI，非交互命令不需要。`login-backup` 的每个子命令都有独立 flag（见上表）；离线查看/导出不连接生产库。",
				"Phase B 可继续补齐命令组二级动作与每命令的鉴权/审计边界；本页当前覆盖顶层命令、flag 与退出码。",
			}),
		"## 机器可读\n\n"+
			"- ["+fileCLIJSON+"]("+fileCLIJSON+")：程序/子命令/flag/退出码完整机器表。\n"+
			"- 生成源：`cmd/`（cobra 与 `flag.NewFlagSet`）与 `internal/managecli/`（`args[0]` 分派）。",
	)
	return joinBlocks(blocks...)
}
