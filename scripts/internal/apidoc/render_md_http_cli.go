package apidoc

import (
	"fmt"
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
	endpointRows := make([][]string, 0, len(m.ProtocolEndpoints))
	for _, endpoint := range m.ProtocolEndpoints {
		endpointRows = append(endpointRows, []string{endpoint.Method, "`" + endpoint.Path + "`"})
	}
	pageRows := make([][]string, 0, len(m.Pages))
	for _, page := range m.Pages {
		pageRows = append(pageRows, []string{
			"`" + page.Name + "`", page.Method, "`" + page.Path + "`",
			page.Access, joinPipes(page.Capabilities), sourceLink(page.Source),
		})
	}
	return joinBlocks(
		"# HTTP 契约参考（管理 API / 协议路径 / 页面命名路由）\n\n"+
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
		"## 3. OAuth 2.0 / OIDC 协议路径常量（"+fmt.Sprintf("%d", len(m.ProtocolPaths))+" 个）\n\n"+
			markdownTable([]string{"常量名", "路径"}, pathRows),
		"### 3.1 协议包文档声明的端点（"+fmt.Sprintf("%d", len(m.ProtocolEndpoints))+" 个）\n\n"+
			markdownTable([]string{"方法", "路径"}, endpointRows),
		"## 4. 内置页面命名路由（"+fmt.Sprintf("%d", len(m.Pages))+" 个冻结命名路由）\n\n"+
			"页面路由是 `ui.v1` 命名契约：名字/路径/访问级别稳定，DOM 与模板不承诺稳定；"+
			"宿主可用 `PageOverrides` 替换展示，但不改变服务端认证/授权/CSRF。",
		markdownTable([]string{"命名路由", "方法", "路径", "访问级别", "关联能力", "定义位置"}, pageRows),
		"## 5. OpenAPI 与 Discovery 边界（不造假完整契约）\n\n"+
			bulletList([]string{
				"OpenAPI 当前只包含最小健康检查/错误契约（`/healthz`、`/openapi.json`），**不是**完整业务 API 文档；业务接口以本页路由清单、机器 JSON 与源码公开契约为准。",
				"OIDC Discovery 只声明真实启用的能力；默认关闭时相关路径 404。真实第三方 OIDC 客户端、设备码/扫码真机互操作等未完成验收的边界见 [../guide/login-and-oauth.md](../guide/login-and-oauth.md)。",
				"管理/托管/客服 API 的授权、对象/字段白名单与审计约束见对应部署文档；不要把管理 API 暴露给业务应用。",
				"新增/删除路由必须同步更新能力声明（catalog.json）；未映射的公开符号或能力声明会让 `scripts/reference -check` 失败。",
			}),
		"## 6. 机器可读\n\n"+
			"- ["+fileHTTPRoutesJSON+"]("+fileHTTPRoutesJSON+")：方法/路径/来源/能力关联的完整机器表。\n"+
			"- 页面 `Access` 列来自 `UIRoute` 字面量；执行时仍由服务端重新判定，台账仅用于契约对照。",
	)
}

// renderCLI 渲染 cli.md。
func (m *Model) renderCLI(used map[string]bool) []byte {
	blocks := []string{
		"# CLI 参考（login-server / loginctl / login-backup）\n\n" +
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
				"`login-backup` 的每个子命令都有独立 flag（见上表）；离线查看/导出不连接生产库。",
				"Phase B 可继续补齐命令组二级动作与每命令的鉴权/审计边界；本页当前覆盖顶层命令、flag 与退出码。",
			}),
		"## 机器可读\n\n"+
			"- ["+fileCLIJSON+"]("+fileCLIJSON+")：程序/子命令/flag/退出码完整机器表。\n"+
			"- 生成源：`cmd/`（cobra 与 `flag.NewFlagSet`）与 `internal/managecli/`（`args[0]` 分派）。",
	)
	return joinBlocks(blocks...)
}
