// 本文件实现 `loginctl reports` 在线命令：历史报告列表/详情、一次性下载令牌
// 签发与兑换下载、取消/重试、报告产物清理预览/执行。
//
// 安全约定：
//   - 下载令牌只返回一次且绑定调用者；CLI 在签发后立即用同一管理会话兑换下载，
//     令牌原文既不写入输出、也不进入日志或文件名。
//   - 报告读取、下载、重试与清理都由服务端按“当前”权限、数据范围与敏感策略
//     重新判定；撤权后旧报告不再可读，CLI 不缓存结果代替授权。
//   - 清理只删除受控报告产物，不删除原始安全审计；清理结果如实展示成功/失败计数。
package managecli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// reportsCommandUsage 是 reports 组帮助。
const reportsCommandUsage = `用法：
  loginctl reports history list [--limit 20] [--plan-id <id>] [--state <s>] \
[--search <关键字>] [--search-fields name] \
[--before-created-at RFC3339] [--before-id <id>] [--cursor <next_cursor>] <在线公共参数>
  loginctl reports plans list [--limit 20] [--offset 0] [--search <关键字>] \
[--search-fields name] <在线公共参数>
  loginctl reports history detail <report_id> <在线公共参数>
  loginctl reports download-token <report_id> --format html|csv|json|pdf|markdown \
--confirm ISSUE-DOWNLOAD [--out <path|->] [--overwrite] <在线公共参数>
  loginctl reports cancel <report_id> --reason <原因> --confirm CANCEL-REPORT <在线公共参数>
  loginctl reports retry <report_id> --reason <原因> --confirm RETRY-REPORT <在线公共参数>
  loginctl reports cleanup preview <在线公共参数>
  loginctl reports cleanup exec --reason <原因> --confirm CLEANUP [--max-targets N] <在线公共参数>

安全说明：
  - download-token 签发一次性短时令牌后立即兑换下载；令牌原文不写入输出。
  - 下载默认不覆盖已有文件，确需覆盖请显式 --overwrite；--out - 直接输出原始字节。
  - “已提交/已接受取消”不等于“已完成/已取消”，请用详情确认真实状态。
  - cleanup 只删除到期报告产物，不删除原始安全审计。`

// runReports 分派 reports 子命令。
func (r *runner) runReports(args []string) int {
	r.usageText = reportsCommandUsage
	if len(args) == 0 {
		return r.helpText("reports", reportsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "reports " + subcommand
	switch subcommand {
	case "history":
		return r.runReportsHistory(rest)
	case "plans":
		return r.runReportsPlans(rest)
	case "download-token":
		return r.runReportsDownloadToken(rest)
	case "cancel":
		return r.runReportsCancel(rest)
	case "retry":
		return r.runReportsRetry(rest)
	case "cleanup":
		return r.runReportsCleanup(rest)
	case "help", "-h", "--help":
		return r.helpText("reports", reportsCommandUsage)
	default:
		return r.usage("未知的 reports 子命令 %q（可用：history/download-token/cancel/retry/cleanup）",
			subcommand)
	}
}

// runReportsHistory 分派 reports history 子命令。
func (r *runner) runReportsHistory(args []string) int {
	if len(args) == 0 {
		return r.helpText("reports history", reportsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		return r.runReportsHistoryList(rest)
	case "detail":
		return r.runReportsDetail(rest)
	case "help", "-h", "--help":
		return r.helpText("reports history", reportsCommandUsage)
	default:
		return r.usage("未知的 reports history 子命令 %q（可用：list/detail）", subcommand)
	}
}

// runReportsHistoryList 列出当前调用者可见的历史报告。
func (r *runner) runReportsHistoryList(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "limit", value: true},
		flagDef{name: "plan-id", value: true}, flagDef{name: "state", value: true},
		flagDef{name: "search", value: true}, flagDef{name: "search-fields", value: true},
		flagDef{name: "before-created-at", value: true}, flagDef{name: "before-id", value: true},
		flagDef{name: "cursor", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("reports history list 不接受位置参数")
	}
	limit, err := parseIntFlag(values, "limit", 20)
	if err != nil || limit < 1 || limit > 100 {
		return r.usage("--limit 必须在 1～100 之间")
	}
	query := queryValues()
	query.Set("limit", fmt.Sprintf("%d", limit))
	setQuery(values, query, "plan-id", "plan_id")
	setQuery(values, query, "state", "state")
	setQuery(values, query, "search", "search")
	setQuery(values, query, "search-fields", "search_fields")
	setQuery(values, query, "before-created-at", "before_created_at")
	setQuery(values, query, "before-id", "before_id")
	setQuery(values, query, "cursor", "cursor")
	if strings.TrimSpace(values["cursor"]) != "" &&
		(strings.TrimSpace(values["before-created-at"]) != "" ||
			strings.TrimSpace(values["before-id"]) != "") {
		return r.usage("--cursor 不能与 --before-created-at/--before-id 同时使用")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/reports", query, nil)
		if failure != nil {
			return r.onlineFailure("列出历史报告", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			fmt.Fprintf(out, "历史报告：%d 条", len(onlineDataList(reply, "reports")))
			if onlineDataBool(reply, "has_more") {
				if cursor, _ := reply.data["next_cursor"].(string); cursor != "" {
					fmt.Fprintf(out, "（还有更多，请用 --cursor %s 翻页）", cursor)
				} else {
					fmt.Fprintf(out, "（还有更多，请用 --before-created-at/--before-id 翻页）")
				}
			}
			fmt.Fprintln(out)
			printOnlineData(out, reply.data)
		})
	})
}

// runReportsPlans 分派 reports plans 子命令。
func (r *runner) runReportsPlans(args []string) int {
	if len(args) == 0 {
		return r.helpText("reports plans", reportsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		return r.runReportsPlansList(rest)
	case "help", "-h", "--help":
		return r.helpText("reports plans", reportsCommandUsage)
	default:
		return r.usage("未知的 reports plans 子命令 %q（可用：list）", subcommand)
	}
}

// runReportsPlansList 分页列出报告计划。
func (r *runner) runReportsPlansList(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "limit", value: true},
		flagDef{name: "offset", value: true}, flagDef{name: "search", value: true},
		flagDef{name: "search-fields", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("reports plans list 不接受位置参数")
	}
	query := queryValues()
	if err := addPageQuery(values, query); err != nil {
		return r.usage("%v", err)
	}
	setQuery(values, query, "search", "search")
	setQuery(values, query, "search-fields", "search_fields")
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/report-plans", query, nil)
		if failure != nil {
			return r.onlineFailure("列出报告计划", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runReportsDetail 读取单条历史报告详情。
func (r *runner) runReportsDetail(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl reports history detail <report_id> <在线公共参数>")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET",
			"/reports/"+urlPathEscape(positional[0]), nil, nil)
		if failure != nil {
			return r.onlineFailure("读取报告详情", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// reportFormats 是允许请求的报告格式（与 reports.Format 一致）。
var reportFormats = map[string]bool{"html": true, "csv": true, "json": true,
	"pdf": true, "markdown": true}

// runReportsDownloadToken 签发一次性下载令牌并立即兑换下载。
func (r *runner) runReportsDownloadToken(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "format", value: true},
		flagDef{name: "confirm", value: true}, flagDef{name: "out", value: true},
		flagDef{name: "overwrite"})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl reports download-token <report_id> --format <f> " +
			"--confirm ISSUE-DOWNLOAD [--out <path|->] [--overwrite] <在线公共参数>")
	}
	if exit := r.requireConfirmWord(values, "ISSUE-DOWNLOAD"); exit != ExitOK {
		return exit
	}
	reportID := strings.TrimSpace(positional[0])
	format := strings.ToLower(stringFlag(values, "format"))
	if !reportFormats[format] {
		return r.usage("--format 必填且只接受 html、csv、json、pdf、markdown")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		ticketReply, failure := target.doJSON(r.ctx, "POST",
			"/reports/"+urlPathEscape(reportID)+"/download-tickets", nil,
			map[string]any{"confirm": true, "format": format})
		if failure != nil {
			return r.onlineFailure("签发报告下载令牌", failure)
		}
		ticket := onlineDataObject(ticketReply, "ticket")
		token := objectString(ticket, "token")
		if token == "" {
			return r.fail("SERVER_RESPONSE_INVALID", ExitError,
				"管理 API 未返回下载令牌", nil)
		}
		info, failure := target.download(r.ctx, "POST", "/reports/download-tickets/redeem",
			nil, map[string]any{"token": token}, stringFlag(values, "out"),
			boolFlag(values, "overwrite"))
		if failure != nil {
			return r.onlineFailure("兑换报告下载令牌", failure)
		}
		return r.succeedTokenDownload(ticket, info, "报告下载")
	})
}

// runReportsCancel 取消报告生成。
func (r *runner) runReportsCancel(args []string) int {
	return r.reportWriteWithReason(args, "cancel", "CANCEL-REPORT")
}

// runReportsRetry 重试报告生成（产生新报告记录，原记录保留）。
func (r *runner) runReportsRetry(args []string) int {
	return r.reportWriteWithReason(args, "retry", "RETRY-REPORT")
}

// reportWriteWithReason 实现报告取消/重试的共同参数与确认语义。
func (r *runner) reportWriteWithReason(args []string, action, confirmWord string) int {
	defs := onlineFlagDefs(flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl reports %s <report_id> --reason <原因> "+
			"--confirm %s <在线公共参数>", action, confirmWord)
	}
	if exit := r.requireConfirmWord(values, confirmWord); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	body := map[string]any{"confirm": true, "reason": reason}
	label := "取消报告"
	if action == "retry" {
		label = "重试报告"
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST",
			"/reports/"+urlPathEscape(positional[0])+"/"+action, nil, body)
		if failure != nil {
			return r.onlineFailure(label, failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runReportsCleanup 分派 reports cleanup 子命令。
func (r *runner) runReportsCleanup(args []string) int {
	if len(args) == 0 {
		return r.helpText("reports cleanup", reportsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "preview":
		values, positional, err := parseFlags(rest, onlineFlagDefs())
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("reports cleanup preview 不接受位置参数")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/reports/cleanup-preview", nil, nil)
			if failure != nil {
				return r.onlineFailure("报告清理预览", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				preview := onlineDataObject(reply, "cleanup_preview")
				fmt.Fprintf(out, "到期报告产物：%d 个，共 %d 字节；"+
					"预览不是删除授权。\n", objectInt64(preview, "target_count"),
					objectInt64(preview, "total_bytes"))
				printOnlineData(out, reply.data)
			})
		})
	case "exec":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "reason", value: true}, flagDef{name: "confirm", value: true},
			flagDef{name: "max-targets", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("reports cleanup exec 不接受位置参数")
		}
		if exit := r.requireConfirmWord(values, "CLEANUP"); exit != ExitOK {
			return exit
		}
		reason, exit := r.requiredFlag(values, "reason", "清理原因")
		if exit != ExitOK {
			return exit
		}
		if len([]byte(reason)) > 256 {
			return r.usage("--reason 不能超过 256 字节")
		}
		body := map[string]any{"confirm": true, "reason": reason}
		maxTargets, err := parseIntFlag(values, "max-targets", 0)
		if err != nil || maxTargets < 0 {
			return r.usage("--max-targets 必须是非负整数")
		}
		if maxTargets > 0 {
			body["max_targets"] = maxTargets
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "POST", "/reports/cleanup", nil, body)
			if failure != nil {
				return r.onlineFailure("执行报告清理", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				result := onlineDataObject(reply, "cleanup_result")
				fmt.Fprintf(out, "清理完成：请求 %d，成功 %d，失败 %d，"+
					"删除文件 %d，释放 %d 字节；原始安全审计未被删除。\n",
					objectInt64(result, "requested_count"),
					objectInt64(result, "cleaned_count"),
					objectInt64(result, "failed_count"),
					objectInt64(result, "deleted_files"),
					objectInt64(result, "freed_bytes"))
			})
		})
	case "help", "-h", "--help":
		return r.helpText("reports cleanup", reportsCommandUsage)
	default:
		return r.usage("未知的 reports cleanup 子命令 %q（可用：preview/exec）", subcommand)
	}
}

// succeedTokenDownload 输出“令牌签发 + 兑换下载”的组合结果（不含令牌原文）。
func (r *runner) succeedTokenDownload(ticket map[string]any, info *downloadInfo,
	label string) int {
	if r.json {
		payload := map[string]any{
			"ticket": map[string]any{
				"report_id":    objectString(ticket, "report_id"),
				"backup_id":    objectString(ticket, "backup_id"),
				"format":       objectString(ticket, "format"),
				"issued_at":    objectString(ticket, "issued_at"),
				"expires_at":   objectString(ticket, "expires_at"),
				"ttl_seconds":  ticket["ttl_seconds"],
				"token_issued": true,
			},
			"download": info,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return r.fail("INTERNAL_ERROR", ExitError, "结果序列化失败", nil)
		}
		requestID := info.RequestID
		if requestID == "" {
			requestID = objectString(ticket, "request_id")
		}
		r.writeEnvelope(jsonEnvelope{OK: true, Command: r.command,
			RequestID: requestID, Data: json.RawMessage(encoded)})
		return ExitOK
	}
	if info.Path == "" {
		fmt.Fprintf(r.stderr, "%s已写入标准输出（%d 字节；sha256=%s）\n", label,
			info.Bytes, info.SHA256)
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "%s已保存：%s\n", label, info.Path)
	fmt.Fprintf(r.stdout, "  大小：%d 字节；sha256：%s；令牌已单次消费（有效期至 %s）\n",
		info.Bytes, info.SHA256, firstNonEmpty(objectString(ticket, "expires_at"), "-"))
	return ExitOK
}
