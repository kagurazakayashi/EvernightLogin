package managecli

// 步骤 233：本地受信边界下的脱敏运行时诊断与关联错误查询。
//
// 本入口是 LocalAdmin 显式本地进程信任边界（与既有 `loginctl diag` 相同），只读
// 本地配置/数据库并输出脱敏白名单字段；服务端 diagnostics.read 权限执行路径在
// 公开 Go 门面、管理 API 与管理页面。两条路径共用 internal/diag 同一收集实现，
// 不在 CLI 复制第二套脱敏/查询逻辑。

import (
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/diag"
	"path/filepath"
	"strings"
)

// diagRuntimeFlags 是运行时诊断参数。
func diagRuntimeFlags() []flagDef {
	return []flagDef{{name: "config", value: true}, {name: "json"},
		{name: "scope", value: true}}
}

// diagErrorsFlags 是关联错误查询参数。
func diagErrorsFlags() []flagDef {
	return append(diagRuntimeFlags(),
		flagDef{name: "request-id", value: true}, flagDef{name: "limit", value: true})
}

// runDiagRuntime 输出本地只读运行时诊断快照。
func (r *runner) runDiagRuntime(args []string) int {
	values, positional, err := parseFlags(args, diagRuntimeFlags())
	if err != nil {
		return r.flagErrorWith(diagCommandUsage, err)
	}
	if len(positional) != 0 {
		return r.usage("diag runtime 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	scope, exit := r.diagScope(values)
	if exit != ExitOK {
		return exit
	}
	store, code := r.tryDatabaseReadOnly(config)
	if code != "" {
		return r.fail(code, ExitError, "数据库不可读，无法收集运行诊断", nil)
	}
	defer func() { _ = store.Close() }()
	collector := diag.New(diag.Options{Config: config, DB: store.DB(),
		ConfigPath: diagConfigPath(values), Build: r.options.Build,
		Now: r.options.Now})
	report, snapshotErr := collector.Snapshot(r.ctx, scope)
	if snapshotErr != nil {
		return r.fail("DIAG_UNAVAILABLE", ExitError, "运行诊断收集失败", nil)
	}
	exitCode := ExitOK
	if report.Status != diag.StatusOK {
		exitCode = ExitError
	}
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: exitCode == ExitOK, Command: r.command,
			Data: report})
		return exitCode
	}
	fmt.Fprintf(r.stdout, "状态：%s\n", report.Status)
	fmt.Fprintf(r.stdout, "版本：%s（commit %s，%s，%s）\n", report.Version.Version,
		report.Version.Commit, report.Version.BuildTime, report.Version.GoVersion)
	fmt.Fprintf(r.stdout, "运行状态：%s；作用范围：%s\n", report.State, report.Scope.ID)
	fmt.Fprintf(r.stdout, "存储：%s（%d ms）\n", report.Storage.Status,
		report.Storage.LatencyMS)
	fmt.Fprintf(r.stdout, "队列：%s\n", report.Queues.Status)
	for _, item := range report.Queues.Jobs {
		fmt.Fprintf(r.stdout, "  任务 %s = %d\n", item.State, item.Count)
	}
	for _, item := range report.Queues.MailDeliveries {
		fmt.Fprintf(r.stdout, "  邮件 %s = %d\n", item.State, item.Count)
	}
	fmt.Fprintf(r.stdout, "配置待重启：%s\n", report.Config.PendingRestartStatus)
	for _, field := range report.Config.PendingRestart {
		fmt.Fprintf(r.stdout, "  %s（%s）\n", field.Field, field.Class)
	}
	return exitCode
}

// runDiagErrors 输出与请求编号关联的错误事件（白名单字段、有界条数）。
func (r *runner) runDiagErrors(args []string) int {
	values, positional, err := parseFlags(args, diagErrorsFlags())
	if err != nil {
		return r.flagErrorWith(diagCommandUsage, err)
	}
	if len(positional) != 0 {
		return r.usage("diag errors 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	requestID := strings.TrimSpace(stringFlag(values, "request-id"))
	if requestID == "" {
		return r.usage("diag errors 需要 --request-id <req_...>")
	}
	if err := errs.ValidateRequestID(requestID); err != nil {
		return r.usage("--request-id 格式无效")
	}
	limit, err := parseIntFlag(values, "limit", 0)
	if err != nil || limit < 0 || limit > diag.MaxErrorLimit {
		return r.usage("--limit 必须在 1～%d 之间（0 表示默认 20）", diag.MaxErrorLimit)
	}
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	scope, exit := r.diagScope(values)
	if exit != ExitOK {
		return exit
	}
	store, code := r.tryDatabaseReadOnly(config)
	if code != "" {
		return r.fail(code, ExitError, "数据库不可读，无法查询关联错误", nil)
	}
	defer func() { _ = store.Close() }()
	collector := diag.New(diag.Options{Config: config, DB: store.DB(),
		ConfigPath: diagConfigPath(values), Now: r.options.Now})
	list, queryErr := collector.RelatedErrors(r.ctx, scope, requestID, limit)
	if queryErr != nil {
		return r.fail("DIAG_UNAVAILABLE", ExitError, "关联错误查询失败", nil)
	}
	exitCode := ExitOK
	if list.Status != diag.StatusOK {
		exitCode = ExitError
	}
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: exitCode == ExitOK, Command: r.command,
			Data: list})
		return exitCode
	}
	fmt.Fprintf(r.stdout, "查询状态：%s；请求编号：%s\n", list.Status, list.RequestID)
	if len(list.Entries) == 0 {
		fmt.Fprintln(r.stdout, "没有关联错误事件。")
		return exitCode
	}
	for _, entry := range list.Entries {
		fmt.Fprintf(r.stdout, "%s  %s  %s  %s\n",
			entry.OccurredAt.Format("2006-01-02T15:04:05Z07:00"), entry.Action,
			entry.Outcome, entry.ErrorCode)
	}
	if list.Truncated {
		fmt.Fprintln(r.stdout, "（达到条数上限，仅显示最近事件）")
	}
	return exitCode
}

// diagScope 解析 --scope（默认 system；应用范围使用 app_ 稳定 ID）。
func (r *runner) diagScope(values map[string]string) (diag.Scope, int) {
	raw := strings.TrimSpace(stringFlag(values, "scope"))
	if raw == "" || raw == "system" {
		scope, err := diag.NormalizeScope(diag.Scope{})
		if err != nil {
			return diag.Scope{}, r.usage("--scope 无效")
		}
		return scope, ExitOK
	}
	scope, err := diag.NormalizeScope(diag.Scope{Kind: "application", ID: raw})
	if err != nil {
		return diag.Scope{}, r.usage("--scope 必须是 system 或合法应用 ID")
	}
	return scope, ExitOK
}

// diagConfigPath 返回用于待重启比较的绝对配置路径；未提供时为空（不推断默认路径）。
func diagConfigPath(values map[string]string) string {
	raw := strings.TrimSpace(stringFlag(values, "config"))
	if raw == "" {
		return ""
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return ""
	}
	return absolute
}
