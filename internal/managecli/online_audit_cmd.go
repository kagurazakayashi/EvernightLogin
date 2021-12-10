// 本文件实现 `loginctl audit` 在线命令：审计事件查询/详情、导出任务列表/创建/
// 取消/下载、审计清理预估/提交/取消，以及由事件查询组合的“错误检索”。
//
// 服务端契约（internal/adminapi）：所有读取重新授权并裁剪数据范围；导出、清理
// 由领域服务按敏感策略再次认证并写真实审计；写操作要求 confirm、取消/清理要求
// reason、清理提交要求与预估一致的 digest。CLI 只做参数编排与如实展示，不缓存
// 授权结论、不把“已提交/已接受取消”写成“已完成/已取消”。
package managecli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

// auditCommandUsage 是 audit 组帮助。
const auditCommandUsage = `用法：
  loginctl audit events list [--scope-id system] [--limit 20] [--offset 0] [--order newest|oldest] \
[--from RFC3339] [--to RFC3339] [--app-id <id>] [--system-only] [--actor-type <t>] \
[--actor-id <id>] [--action <a>] [--outcome success|failure|denied] [--error-code <c>] \
[--request-id <id>] [--task-id <id>] [--target-type <t>] [--target-id <id>] <在线公共参数>
  loginctl audit events detail <event_id> [--scope-id system] [--occurred-at-hint RFC3339] \
<在线公共参数>
  loginctl audit exports list [--scope-id system] [--state <s>] [--limit N] [--offset N] <在线公共参数>
  loginctl audit exports create --format csv|json --confirm CREATE-EXPORT [--max-rows N] \
[--order newest|oldest] [--scope-id system] [审计筛选参数] <在线公共参数>
  loginctl audit exports cancel <export_id> --reason <原因> --confirm CANCEL-EXPORT <在线公共参数>
  loginctl audit exports download <export_id> --out <path|-> [--overwrite] <在线公共参数>
  loginctl audit cleanup preview --cutoff RFC3339 [--scope-id system] [--batch-size N] \
[--max-records N] <在线公共参数>
  loginctl audit cleanup submit --cutoff RFC3339 --digest <预估摘要> --reason <原因> \
--confirm PURGE [--scope-id system] [--batch-size N] [--max-records N] <在线公共参数>
  loginctl audit cleanup cancel <run_id> --reason <原因> --confirm CANCEL-PURGE <在线公共参数>
  loginctl audit errors search [--outcome failure|denied|both] [其它筛选参数] <在线公共参数>

在线公共参数：
  --server <url>        管理 API 基础地址，默认 http://127.0.0.1:<配置端口或 8080>
  --api-path <path>     管理 API 挂载路径，默认 /admin/v1
  --session-file <file> 管理会话秘密的受保护文件（必须；秘密不进入命令行/日志）
  --ca-file <pem>       可选 TLS 附加 CA；默认严格校验证书，不提供跳过开关
  --timeout <30s>       单个 JSON 请求期限（1s～5m）。
  --json                输出 {ok,command,request_id,data|error}；data 为服务端原始 data

安全说明：
  - 需要已运行并装配审计服务的 login-server，以及已完成强认证的管理会话。
  - 下载端点返回原始字节流；--out 默认不覆盖已有文件，确需覆盖请显式 --overwrite。
  - 取消请求被接受不等于已取消；请用列表/详情确认真实状态。`

// auditFilterFlags 返回审计筛选参数定义。
func auditFilterFlags() []flagDef {
	return []flagDef{
		{name: "from", value: true}, {name: "to", value: true},
		{name: "app-id", value: true}, {name: "system-only"},
		{name: "actor-type", value: true}, {name: "actor-id", value: true},
		{name: "action", value: true}, {name: "outcome", value: true},
		{name: "error-code", value: true}, {name: "request-id", value: true},
		{name: "task-id", value: true}, {name: "target-type", value: true},
		{name: "target-id", value: true},
	}
}

// auditFilterQuery 把筛选参数写入查询串。
func auditFilterQuery(values map[string]string, query url.Values) {
	setQuery(values, query, "from", "from")
	setQuery(values, query, "to", "to")
	setQuery(values, query, "app-id", "app_id")
	setQueryBool(values, query, "system-only", "system_only")
	setQuery(values, query, "actor-type", "actor_type")
	setQuery(values, query, "actor-id", "actor_id")
	setQuery(values, query, "action", "action")
	setQuery(values, query, "outcome", "outcome")
	setQuery(values, query, "error-code", "error_code")
	setQuery(values, query, "request-id", "request_id")
	setQuery(values, query, "task-id", "task_id")
	setQuery(values, query, "target-type", "target_type")
	setQuery(values, query, "target-id", "target_id")
}

// auditFilterBody 把筛选参数写入导出创建请求体。
func auditFilterBody(values map[string]string) map[string]any {
	filter := map[string]any{}
	for flag, key := range map[string]string{
		"from": "from", "to": "to", "app-id": "app_id",
		"actor-type": "actor_type", "actor-id": "actor_id", "action": "action",
		"outcome": "outcome", "error-code": "error_code",
		"request-id": "request_id", "task-id": "task_id",
		"target-type": "target_type", "target-id": "target_id",
	} {
		if value := stringFlag(values, flag); value != "" {
			filter[key] = value
		}
	}
	if boolFlag(values, "system-only") {
		filter["system_only"] = true
	}
	return filter
}

// auditOrder 把 CLI 排序别名转换为 adminapi 稳定排序值。
func auditOrder(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return "", nil
	case "newest", "desc", "occurred_desc":
		return "occurred_desc", nil
	case "oldest", "asc", "occurred_asc":
		return "occurred_asc", nil
	default:
		return "", fmt.Errorf("--order 只接受 newest 或 oldest")
	}
}

// auditEventListFlags 是事件列表参数。
func auditEventListFlags() []flagDef {
	defs := onlineFlagDefs(auditFilterFlags()...)
	return append(defs, flagDef{name: "scope-id", value: true},
		flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true},
		flagDef{name: "order", value: true})
}

// runAudit 分派 audit 子命令。
func (r *runner) runAudit(args []string) int {
	r.usageText = auditCommandUsage
	if len(args) == 0 {
		return r.helpText("audit", auditCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "audit " + subcommand
	switch subcommand {
	case "events":
		return r.runAuditEvents(rest)
	case "exports":
		return r.runAuditExports(rest)
	case "cleanup":
		return r.runAuditCleanup(rest)
	case "errors":
		return r.runAuditErrors(rest)
	case "help", "-h", "--help":
		return r.helpText("audit", auditCommandUsage)
	default:
		return r.usage("未知的 audit 子命令 %q（可用：events/exports/cleanup/errors）", subcommand)
	}
}

// runAuditEvents 分派 audit events 子命令。
func (r *runner) runAuditEvents(args []string) int {
	if len(args) == 0 {
		return r.helpText("audit events", auditCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		return r.runAuditEventsList(rest)
	case "detail":
		return r.runAuditEventDetail(rest)
	case "help", "-h", "--help":
		return r.helpText("audit events", auditCommandUsage)
	default:
		return r.usage("未知的 audit events 子命令 %q（可用：list/detail）", subcommand)
	}
}

// runAuditEventsList 查询审计事件列表。
func (r *runner) runAuditEventsList(args []string) int {
	values, positional, err := parseFlags(args, auditEventListFlags())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit events list 不接受位置参数")
	}
	order, err := auditOrder(stringFlag(values, "order"))
	if err != nil {
		return r.usage("%v", err)
	}
	query := queryValues()
	if err := addPageQuery(values, query); err != nil {
		return r.usage("%v", err)
	}
	query.Set("scope_id", onlineScopeID(values))
	if order != "" {
		query.Set("order", order)
	}
	auditFilterQuery(values, query)
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/audit/events", query, nil)
		if failure != nil {
			return r.onlineFailure("查询审计事件", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runAuditEventDetail 查询单条审计事件详情。
func (r *runner) runAuditEventDetail(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "scope-id", value: true},
		flagDef{name: "occurred-at-hint", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl audit events detail <event_id> [--scope-id system] " +
			"[--occurred-at-hint RFC3339] <在线公共参数>")
	}
	eventID := strings.TrimSpace(positional[0])
	if eventID == "" {
		return r.usage("事件编号不能为空")
	}
	query := queryValues()
	query.Set("scope_id", onlineScopeID(values))
	setQuery(values, query, "occurred-at-hint", "occurred_at_hint")
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/audit/events/"+urlPathEscape(eventID), query, nil)
		if failure != nil {
			return r.onlineFailure("读取审计事件详情", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runAuditExports 分派 audit exports 子命令。
func (r *runner) runAuditExports(args []string) int {
	if len(args) == 0 {
		return r.helpText("audit exports", auditCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		return r.runAuditExportsList(rest)
	case "create":
		return r.runAuditExportsCreate(rest)
	case "cancel":
		return r.runAuditExportsCancel(rest)
	case "download":
		return r.runAuditExportsDownload(rest)
	case "help", "-h", "--help":
		return r.helpText("audit exports", auditCommandUsage)
	default:
		return r.usage("未知的 audit exports 子命令 %q（可用：list/create/cancel/download）",
			subcommand)
	}
}

// runAuditExportsList 列出审计导出任务。
func (r *runner) runAuditExportsList(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "scope-id", value: true},
		flagDef{name: "state", value: true}, flagDef{name: "limit", value: true},
		flagDef{name: "offset", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit exports list 不接受位置参数")
	}
	query := queryValues()
	if err := addPageQuery(values, query); err != nil {
		return r.usage("%v", err)
	}
	query.Set("scope_id", onlineScopeID(values))
	setQuery(values, query, "state", "state")
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/audit/exports", query, nil)
		if failure != nil {
			return r.onlineFailure("列出审计导出任务", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runAuditExportsCreate 创建审计导出任务。
func (r *runner) runAuditExportsCreate(args []string) int {
	defs := onlineFlagDefs(auditFilterFlags()...)
	defs = append(defs, flagDef{name: "scope-id", value: true},
		flagDef{name: "format", value: true}, flagDef{name: "max-rows", value: true},
		flagDef{name: "order", value: true}, flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit exports create 不接受位置参数")
	}
	if exit := r.requireConfirmWord(values, "CREATE-EXPORT"); exit != ExitOK {
		return exit
	}
	format := strings.ToLower(stringFlag(values, "format"))
	if format != "csv" && format != "json" {
		return r.usage("--format 必填且只接受 csv 或 json")
	}
	order, err := auditOrder(stringFlag(values, "order"))
	if err != nil {
		return r.usage("%v", err)
	}
	maxRows, err := parseIntFlag(values, "max-rows", 0)
	if err != nil || maxRows < 0 {
		return r.usage("--max-rows 必须是非负整数")
	}
	body := map[string]any{"confirm": true, "scope_id": onlineScopeID(values),
		"format": format, "filter": auditFilterBody(values)}
	if maxRows > 0 {
		body["max_rows"] = maxRows
	}
	if order != "" {
		body["order"] = order
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/audit/exports", nil, body)
		if failure != nil {
			return r.onlineFailure("创建审计导出", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runAuditExportsCancel 请求取消审计导出任务。
func (r *runner) runAuditExportsCancel(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl audit exports cancel <export_id> --reason <原因> " +
			"--confirm CANCEL-EXPORT <在线公共参数>")
	}
	if exit := r.requireConfirmWord(values, "CANCEL-EXPORT"); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "取消原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	body := map[string]any{"confirm": true, "reason": reason}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST",
			"/audit/exports/"+urlPathEscape(positional[0])+"/cancel", nil, body)
		if failure != nil {
			return r.onlineFailure("请求取消审计导出", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			fmt.Fprintln(out, "取消请求已提交；请求被接受不等于导出已取消，请用 "+
				"audit exports list/detail 确认真实状态。")
		})
	})
}

// runAuditExportsDownload 下载审计导出产物（原始字节流）。
func (r *runner) runAuditExportsDownload(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "out", value: true}, flagDef{name: "overwrite"})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl audit exports download <export_id> --out <path|-> " +
			"[--overwrite] <在线公共参数>")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		info, failure := target.download(r.ctx, "GET",
			"/audit/exports/"+urlPathEscape(positional[0])+"/download", nil, nil,
			stringFlag(values, "out"), boolFlag(values, "overwrite"))
		if failure != nil {
			return r.onlineFailure("下载审计导出", failure)
		}
		return r.succeedDownload(info, "审计导出")
	})
}

// runAuditCleanup 分派 audit cleanup 子命令。
func (r *runner) runAuditCleanup(args []string) int {
	if len(args) == 0 {
		return r.helpText("audit cleanup", auditCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "preview":
		return r.runAuditCleanupPreview(rest)
	case "submit":
		return r.runAuditCleanupSubmit(rest)
	case "cancel":
		return r.runAuditCleanupCancel(rest)
	case "help", "-h", "--help":
		return r.helpText("audit cleanup", auditCommandUsage)
	default:
		return r.usage("未知的 audit cleanup 子命令 %q（可用：preview/submit/cancel）",
			subcommand)
	}
}

// auditCleanupFlags 返回清理预估/提交的公共参数。
func auditCleanupFlags(extra ...flagDef) []flagDef {
	defs := onlineFlagDefs(flagDef{name: "scope-id", value: true},
		flagDef{name: "cutoff", value: true}, flagDef{name: "batch-size", value: true},
		flagDef{name: "max-records", value: true})
	return append(defs, extra...)
}

// auditCleanupBody 构造清理请求体（预估与提交共用参数）。
func (r *runner) auditCleanupBody(values map[string]string) (map[string]any, int) {
	cutoff := stringFlag(values, "cutoff")
	if cutoff == "" {
		return nil, r.usage("--cutoff 必填（RFC3339 时间，删除该时间之前的审计）")
	}
	if _, err := time.Parse(time.RFC3339, cutoff); err != nil {
		return nil, r.usage("--cutoff 必须是 RFC3339 时间（例如 2026-01-01T00:00:00Z）")
	}
	batchSize, err := parseIntFlag(values, "batch-size", 0)
	if err != nil || batchSize < 0 {
		return nil, r.usage("--batch-size 必须是非负整数")
	}
	maxRecords, err := parseIntFlag(values, "max-records", 0)
	if err != nil || maxRecords < 0 {
		return nil, r.usage("--max-records 必须是非负整数")
	}
	body := map[string]any{"scope_id": onlineScopeID(values), "cutoff": cutoff}
	if batchSize > 0 {
		body["batch_size"] = batchSize
	}
	if maxRecords > 0 {
		body["max_records"] = maxRecords
	}
	return body, ExitOK
}

// runAuditCleanupPreview 输出审计清理预估（只读，含绑定参数的 digest）。
func (r *runner) runAuditCleanupPreview(args []string) int {
	values, positional, err := parseFlags(args, auditCleanupFlags())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit cleanup preview 不接受位置参数")
	}
	body, exit := r.auditCleanupBody(values)
	if exit != ExitOK {
		return exit
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/audit/purge/preview", nil, body)
		if failure != nil {
			return r.onlineFailure("审计清理预估", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			preview := onlineDataObject(reply, "purge_preview")
			fmt.Fprintf(out, "预估删除：%d 条（至少标记=%v）；返回 digest=%s\n",
				objectInt64(preview, "estimated_count"),
				preview["at_least"], objectString(preview, "digest"))
			fmt.Fprintln(out, "提交执行必须用同一 --cutoff/--batch-size/--max-records 与 --digest；"+
				"预估不是删除授权。")
		})
	})
}

// runAuditCleanupSubmit 提交审计清理任务（root + 敏感策略 + 确认 + 原因 + digest）。
func (r *runner) runAuditCleanupSubmit(args []string) int {
	values, positional, err := parseFlags(args, auditCleanupFlags(
		flagDef{name: "reason", value: true}, flagDef{name: "digest", value: true},
		flagDef{name: "confirm", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit cleanup submit 不接受位置参数")
	}
	if exit := r.requireConfirmWord(values, "PURGE"); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "清理原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	digest, exit := r.requiredFlag(values, "digest", "清理预估摘要")
	if exit != ExitOK {
		return exit
	}
	body, exit := r.auditCleanupBody(values)
	if exit != ExitOK {
		return exit
	}
	body["confirm"] = true
	body["reason"] = reason
	body["digest"] = digest
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/audit/purge", nil, body)
		if failure != nil {
			return r.onlineFailure("提交审计清理", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			run := onlineDataObject(reply, "purge_run")
			fmt.Fprintf(out, "清理任务已提交：id=%s state=%s task_id=%s\n",
				objectString(run, "id"), objectString(run, "state"),
				objectString(run, "task_id"))
			fmt.Fprintln(out, "“已提交”不等于“已清理”；请用任务详情/清理列表确认终态。")
		})
	})
}

// runAuditCleanupCancel 请求取消审计清理运行。
func (r *runner) runAuditCleanupCancel(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl audit cleanup cancel <run_id> --reason <原因> " +
			"--confirm CANCEL-PURGE <在线公共参数>")
	}
	if exit := r.requireConfirmWord(values, "CANCEL-PURGE"); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "取消原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	body := map[string]any{"confirm": true, "reason": reason}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST",
			"/audit/purge/"+urlPathEscape(positional[0])+"/cancel", nil, body)
		if failure != nil {
			return r.onlineFailure("请求取消审计清理", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			fmt.Fprintln(out, "取消请求已提交；请求被接受不等于清理已停止。")
		})
	})
}

// runAuditErrors 分派 audit errors 子命令（由事件查询组合错误检索）。
func (r *runner) runAuditErrors(args []string) int {
	if len(args) == 0 {
		return r.helpText("audit errors", auditCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	if subcommand != "search" {
		if subcommand == "help" || subcommand == "-h" || subcommand == "--help" {
			return r.helpText("audit errors", auditCommandUsage)
		}
		return r.usage("未知的 audit errors 子命令 %q（可用：search）", subcommand)
	}
	values, positional, err := parseFlags(rest, auditErrorSearchFlags())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("audit errors search 不接受位置参数")
	}
	outcome := strings.ToLower(stringFlag(values, "outcome"))
	switch outcome {
	case "":
		outcome = "both"
	case "both", "failure", "denied":
	default:
		return r.usage("--outcome 只接受 failure、denied 或 both")
	}
	limit, err := parseIntFlag(values, "limit", 20)
	if err != nil || limit < 1 || limit > 100 {
		return r.usage("--limit 必须在 1～100 之间")
	}
	baseQuery := func() url.Values {
		query := queryValues()
		query.Set("scope_id", onlineScopeID(values))
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("order", "occurred_desc")
		auditFilterQuery(values, query)
		return query
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		if outcome != "both" {
			query := baseQuery()
			query.Set("outcome", outcome)
			reply, failure := target.doJSON(r.ctx, "GET", "/audit/events", query, nil)
			if failure != nil {
				return r.onlineFailure("检索审计错误", failure)
			}
			if reply.data != nil {
				reply.data["outcome_filter"] = outcome
			}
			return r.succeedOnline(reply, nil)
		}
		merged := make([]any, 0, limit*2)
		hasMore := false
		lastRequestID := ""
		for _, single := range []string{"failure", "denied"} {
			query := baseQuery()
			query.Set("outcome", single)
			reply, failure := target.doJSON(r.ctx, "GET", "/audit/events", query, nil)
			if failure != nil {
				return r.onlineFailure("检索审计错误", failure)
			}
			lastRequestID = reply.requestID
			if more, _ := reply.data["has_more"].(bool); more {
				hasMore = true
			}
			merged = append(merged, onlineDataList(reply, "events")...)
		}
		sort.SliceStable(merged, func(left, right int) bool {
			leftAt := eventOccurredAt(merged[left])
			rightAt := eventOccurredAt(merged[right])
			return leftAt.After(rightAt)
		})
		if len(merged) > limit {
			merged = merged[:limit]
			hasMore = true
		}
		payload := map[string]any{"events": merged, "has_more": hasMore,
			"limit": limit, "outcome_filter": "failure+denied",
			"note": "由 audit/events 组合 outcome=failure 与 outcome=denied 两次查询并按发生时间合并；" +
				"不是独立的错误日志端点"}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return r.fail("INTERNAL_ERROR", ExitError, "结果序列化失败", nil)
		}
		return r.succeedOnline(&onlineReply{requestID: lastRequestID,
			status: 200, raw: raw, data: payload}, nil)
	})
}

// auditErrorSearchFlags 返回错误检索参数（在事件筛选基础上增加 limit）。
func auditErrorSearchFlags() []flagDef {
	defs := onlineFlagDefs(auditFilterFlags()...)
	return append(defs, flagDef{name: "limit", value: true})
}

// eventOccurredAt 解析审计事件的 occurred_at 时间；解析失败按零值处理。
func eventOccurredAt(raw any) time.Time {
	object, ok := raw.(map[string]any)
	if !ok {
		return time.Time{}
	}
	text, _ := object["occurred_at"].(string)
	moment, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}
	}
	return moment
}
