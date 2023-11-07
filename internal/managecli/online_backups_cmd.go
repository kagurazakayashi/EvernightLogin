// 本文件实现 `loginctl backups` 在线命令：备份产物列表/详情/一次性下载令牌兑换
// 下载、备份计划列表/详情/创建/编辑/启停/删除、保留策略读取/设置、清理预览/提交。
//
// 边界与安全约定：
//   - 备份产物与计划的读取、创建、取消、下载、保留策略与清理都由服务端按当前
//     权限、系统范围与敏感策略（再次认证 + 确认）重新判定；CLI 不本地放行。
//   - 下载令牌只返回一次且绑定调用者；CLI 签发后立即兑换下载，令牌原文不输出。
//   - 保留策略写入携带 --expected-version，版本冲突如实返回退出码 6，需重新读取。
//   - 清理“已提交”不等于“已清理”；真实结果以任务/产物状态为准。
package managecli

import (
	"fmt"
	"io"
	"strings"
)

// backupsCommandUsage 是 backups 组帮助。
const backupsCommandUsage = `用法：
  loginctl backups artifacts list [--origin manual|schedule] [--verification <s>] \
[--cleanup <s>] [--schedule-id <id>] [--job-id <id>] [--limit N] [--offset N] <在线公共参数>
  loginctl backups artifacts detail <backup_id> <在线公共参数>
  loginctl backups artifacts download-token <backup_id> --confirm ISSUE-DOWNLOAD \
[--out <path|->] [--overwrite] <在线公共参数>
  loginctl backups schedules list [--limit N] [--offset N] <在线公共参数>
  loginctl backups schedules get <schedule_id> <在线公共参数>
  loginctl backups schedules create --name <名称> --schedule-type daily|weekly|... \
--expression <表达式> --time-zone <IANA> --missed-policy skip|run_once|... --confirm CREATE \
[--max-catch-up N] [--timeout-seconds N] [--max-attempts N] [--retention-version N] \
[--notify-failures] [--notify-success] [--disabled] <在线公共参数>
  loginctl backups schedules edit <schedule_id> <同上计划参数> --confirm EDIT <在线公共参数>
  loginctl backups schedules enable <schedule_id> --reason <原因> --confirm ENABLE <在线公共参数>
  loginctl backups schedules disable <schedule_id> --reason <原因> --confirm DISABLE <在线公共参数>
  loginctl backups schedules delete <schedule_id> --reason <原因> --confirm DELETE <在线公共参数>
  loginctl backups retention get <在线公共参数>
  loginctl backups retention set --max-count N --max-age-days N --max-total-bytes N \
--expected-version N --reason <原因> --confirm SET-RETENTION <在线公共参数>
  loginctl backups cleanup preview <在线公共参数>
  loginctl backups cleanup submit --confirm CLEANUP [--request-id <id>] <在线公共参数>

安全说明：
  - 备份创建/取消/下载/保留策略写入/清理是敏感操作：服务端仍会要求强认证与审计。
  - download-token 签发一次性短时令牌后立即兑换下载；令牌原文不写入输出。
  - 计划写入是整份替换；请先用 schedules get 读取当前值再修改。
  - 默认不覆盖已有下载文件，确需覆盖请显式 --overwrite。`

// runBackups 分派 backups 子命令。
func (r *runner) runBackups(args []string) int {
	r.usageText = backupsCommandUsage
	if len(args) == 0 {
		return r.helpText("backups", backupsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "backups " + subcommand
	switch subcommand {
	case "artifacts":
		return r.runBackupArtifacts(rest)
	case "schedules":
		return r.runBackupSchedules(rest)
	case "retention":
		return r.runBackupRetention(rest)
	case "cleanup":
		return r.runBackupCleanup(rest)
	case "help", "-h", "--help":
		return r.helpText("backups", backupsCommandUsage)
	default:
		return r.usage("未知的 backups 子命令 %q（可用：artifacts/schedules/retention/cleanup）",
			subcommand)
	}
}

// runBackupArtifacts 分派 backups artifacts 子命令。
func (r *runner) runBackupArtifacts(args []string) int {
	if len(args) == 0 {
		return r.helpText("backups artifacts", backupsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		return r.runBackupArtifactsList(rest)
	case "detail":
		return r.runBackupArtifactDetail(rest)
	case "download-token":
		return r.runBackupArtifactDownload(rest)
	case "help", "-h", "--help":
		return r.helpText("backups artifacts", backupsCommandUsage)
	default:
		return r.usage("未知的 backups artifacts 子命令 %q（可用：list/detail/download-token）",
			subcommand)
	}
}

// runBackupArtifactsList 列出备份产物。
func (r *runner) runBackupArtifactsList(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "origin", value: true},
		flagDef{name: "verification", value: true}, flagDef{name: "cleanup", value: true},
		flagDef{name: "schedule-id", value: true}, flagDef{name: "job-id", value: true},
		flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("backups artifacts list 不接受位置参数")
	}
	query := queryValues()
	if err := addPageQuery(values, query); err != nil {
		return r.usage("%v", err)
	}
	setQuery(values, query, "origin", "origin")
	setQuery(values, query, "verification", "verification")
	setQuery(values, query, "cleanup", "cleanup")
	setQuery(values, query, "schedule-id", "schedule_id")
	setQuery(values, query, "job-id", "job_id")
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/backups", query, nil)
		if failure != nil {
			return r.onlineFailure("列出备份产物", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupArtifactDetail 读取单个备份产物详情。
func (r *runner) runBackupArtifactDetail(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl backups artifacts detail <backup_id> <在线公共参数>")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET",
			"/backups/"+urlPathEscape(positional[0]), nil, nil)
		if failure != nil {
			return r.onlineFailure("读取备份产物详情", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupArtifactDownload 签发一次性下载令牌并立即兑换下载。
func (r *runner) runBackupArtifactDownload(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "confirm", value: true},
		flagDef{name: "out", value: true}, flagDef{name: "overwrite"})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl backups artifacts download-token <backup_id> " +
			"--confirm ISSUE-DOWNLOAD [--out <path|->] [--overwrite] <在线公共参数>")
	}
	if exit := r.requireConfirmWord(values, "ISSUE-DOWNLOAD"); exit != ExitOK {
		return exit
	}
	backupID := strings.TrimSpace(positional[0])
	return r.withOnline(values, func(target *onlineTarget) int {
		ticketReply, failure := target.doJSON(r.ctx, "POST",
			"/backups/"+urlPathEscape(backupID)+"/download-tickets", nil,
			map[string]any{"confirm": true})
		if failure != nil {
			return r.onlineFailure("签发备份下载令牌", failure)
		}
		ticket := onlineDataObject(ticketReply, "ticket")
		token := objectString(ticket, "token")
		if token == "" {
			return r.fail("SERVER_RESPONSE_INVALID", ExitError,
				"管理 API 未返回下载令牌", nil)
		}
		info, failure := target.download(r.ctx, "POST", "/backups/download-tickets/redeem",
			nil, map[string]any{"token": token}, stringFlag(values, "out"),
			boolFlag(values, "overwrite"))
		if failure != nil {
			return r.onlineFailure("兑换备份下载令牌", failure)
		}
		return r.succeedTokenDownload(ticket, info, "备份下载")
	})
}

// runBackupSchedules 分派 backups schedules 子命令。
func (r *runner) runBackupSchedules(args []string) int {
	if len(args) == 0 {
		return r.helpText("backups schedules", backupsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "list":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("backups schedules list 不接受位置参数")
		}
		query := queryValues()
		if err := addPageQuery(values, query); err != nil {
			return r.usage("%v", err)
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/backups/schedules", query, nil)
			if failure != nil {
				return r.onlineFailure("列出备份计划", failure)
			}
			return r.succeedOnline(reply, nil)
		})
	case "get":
		values, positional, err := parseFlags(rest, onlineFlagDefs())
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 1 {
			return r.usage("用法：loginctl backups schedules get <schedule_id> <在线公共参数>")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET",
				"/backups/schedules/"+urlPathEscape(positional[0]), nil, nil)
			if failure != nil {
				return r.onlineFailure("读取备份计划", failure)
			}
			return r.succeedOnline(reply, nil)
		})
	case "create":
		return r.runBackupScheduleWrite(rest, "CREATE", "POST", true)
	case "edit":
		return r.runBackupScheduleWrite(rest, "EDIT", "PUT", false)
	case "enable", "disable":
		return r.runBackupScheduleSetEnabled(rest, subcommand == "enable")
	case "delete":
		return r.runBackupScheduleDelete(rest)
	case "help", "-h", "--help":
		return r.helpText("backups schedules", backupsCommandUsage)
	default:
		return r.usage("未知的 backups schedules 子命令 %q"+
			"（可用：list/get/create/edit/enable/disable/delete）", subcommand)
	}
}

// backupScheduleFlags 返回备份计划写入参数定义。
func backupScheduleFlags() []flagDef {
	defs := onlineFlagDefs(flagDef{name: "name", value: true},
		flagDef{name: "schedule-type", value: true}, flagDef{name: "expression", value: true},
		flagDef{name: "time-zone", value: true}, flagDef{name: "missed-policy", value: true},
		flagDef{name: "max-catch-up", value: true}, flagDef{name: "timeout-seconds", value: true},
		flagDef{name: "max-attempts", value: true}, flagDef{name: "retention-version", value: true},
		flagDef{name: "notify-failures"}, flagDef{name: "notify-success"},
		flagDef{name: "disabled"}, flagDef{name: "confirm", value: true})
	return defs
}

// backupScheduleBody 构造备份计划创建/编辑请求体（服务端白名单字段）。
func (r *runner) backupScheduleBody(values map[string]string,
	enabled bool) (map[string]any, int) {
	required := []struct {
		flag  string
		label string
	}{
		{"name", "计划名称"}, {"schedule-type", "计划类型"},
		{"expression", "计划表达式"}, {"time-zone", "时区"},
		{"missed-policy", "错过执行策略"},
	}
	body := map[string]any{"confirm": true, "enabled": enabled,
		"notify_failures": boolFlag(values, "notify-failures"),
		"notify_success":  boolFlag(values, "notify-success")}
	for _, item := range required {
		value := stringFlag(values, item.flag)
		if value == "" {
			return nil, r.usage("%s必填（--%s）", item.label, item.flag)
		}
		body[strings.ReplaceAll(item.flag, "-", "_")] = value
	}
	for flag, key := range map[string]string{
		"max-catch-up": "max_catch_up", "timeout-seconds": "timeout_seconds",
		"max-attempts": "max_attempts", "retention-version": "retention_version",
	} {
		parsed, err := parseIntFlag(values, flag, 0)
		if err != nil || parsed < 0 {
			return nil, r.usage("--%s 必须是非负整数", flag)
		}
		if parsed > 0 {
			body[key] = parsed
		}
	}
	return body, ExitOK
}

// runBackupScheduleWrite 创建或整份替换备份计划。
func (r *runner) runBackupScheduleWrite(args []string, confirmWord,
	method string, allowPositional bool) int {
	values, positional, err := parseFlags(args, backupScheduleFlags())
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if exit := r.requireConfirmWord(values, confirmWord); exit != ExitOK {
		return exit
	}
	var scheduleID string
	if allowPositional {
		if len(positional) != 0 {
			return r.usage("backups schedules create 不接受位置参数")
		}
	} else {
		if len(positional) != 1 {
			return r.usage("用法：loginctl backups schedules edit <schedule_id> <计划参数> " +
				"--confirm EDIT <在线公共参数>")
		}
		scheduleID = strings.TrimSpace(positional[0])
		if scheduleID == "" {
			return r.usage("计划编号不能为空")
		}
	}
	body, exit := r.backupScheduleBody(values, !boolFlag(values, "disabled"))
	if exit != ExitOK {
		return exit
	}
	relative := "/backups/schedules"
	if scheduleID != "" {
		relative += "/" + urlPathEscape(scheduleID)
	}
	label := "创建备份计划"
	if method == "PUT" {
		label = "编辑备份计划"
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, method, relative, nil, body)
		if failure != nil {
			return r.onlineFailure(label, failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupScheduleSetEnabled 启用/停用备份计划。
func (r *runner) runBackupScheduleSetEnabled(args []string, enable bool) int {
	defs := onlineFlagDefs(flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	action, confirmWord, label := "disable", "DISABLE", "停用备份计划"
	if enable {
		action, confirmWord, label = "enable", "ENABLE", "启用备份计划"
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl backups schedules %s <schedule_id> --reason <原因> "+
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
	body := map[string]any{"confirm": true, "enabled": enable, "reason": reason}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST",
			"/backups/schedules/"+urlPathEscape(positional[0])+"/enabled", nil, body)
		if failure != nil {
			return r.onlineFailure(label, failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupScheduleDelete 删除备份计划。
func (r *runner) runBackupScheduleDelete(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("用法：loginctl backups schedules delete <schedule_id> --reason <原因> " +
			"--confirm DELETE <在线公共参数>")
	}
	if exit := r.requireConfirmWord(values, "DELETE"); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "删除原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	body := map[string]any{"confirm": true, "reason": reason}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "DELETE",
			"/backups/schedules/"+urlPathEscape(positional[0]), nil, body)
		if failure != nil {
			return r.onlineFailure("删除备份计划", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupRetention 分派 backups retention 子命令。
func (r *runner) runBackupRetention(args []string) int {
	if len(args) == 0 {
		return r.helpText("backups retention", backupsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	switch subcommand {
	case "get":
		values, positional, err := parseFlags(rest, onlineFlagDefs())
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("backups retention get 不接受位置参数")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/backups/retention", nil, nil)
			if failure != nil {
				return r.onlineFailure("读取备份保留策略", failure)
			}
			return r.succeedOnline(reply, nil)
		})
	case "set":
		return r.runBackupRetentionSet(rest)
	case "help", "-h", "--help":
		return r.helpText("backups retention", backupsCommandUsage)
	default:
		return r.usage("未知的 backups retention 子命令 %q（可用：get/set）", subcommand)
	}
}

// runBackupRetentionSet 写入备份保留策略（版本并发 + 确认 + 原因 + 敏感策略）。
func (r *runner) runBackupRetentionSet(args []string) int {
	defs := onlineFlagDefs(flagDef{name: "max-count", value: true},
		flagDef{name: "max-age-days", value: true}, flagDef{name: "max-total-bytes", value: true},
		flagDef{name: "expected-version", value: true}, flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true})
	values, positional, err := parseFlags(args, defs)
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("backups retention set 不接受位置参数")
	}
	if exit := r.requireConfirmWord(values, "SET-RETENTION"); exit != ExitOK {
		return exit
	}
	reason, exit := r.requiredFlag(values, "reason", "设置原因")
	if exit != ExitOK {
		return exit
	}
	if len([]byte(reason)) > 256 {
		return r.usage("--reason 不能超过 256 字节")
	}
	maxCount, err := parseIntFlag(values, "max-count", 0)
	if err != nil || maxCount < 0 {
		return r.usage("--max-count 必须是非负整数（0 表示不启用该项）")
	}
	maxAgeDays, err := parseIntFlag(values, "max-age-days", 0)
	if err != nil || maxAgeDays < 0 {
		return r.usage("--max-age-days 必须是非负整数（0 表示不启用该项）")
	}
	maxTotalBytes, err := parseIntFlag(values, "max-total-bytes", 0)
	if err != nil || maxTotalBytes < 0 {
		return r.usage("--max-total-bytes 必须是非负整数（0 表示不启用该项）")
	}
	expectedVersion, err := parseIntFlag(values, "expected-version", -1)
	if err != nil || expectedVersion < 0 {
		return r.usage("--expected-version 必填且必须是非负整数（来自 retention get）")
	}
	if maxCount == 0 && maxAgeDays == 0 && maxTotalBytes == 0 {
		return r.usage("保留策略三项不能同时为 0（至少启用一项）")
	}
	body := map[string]any{"confirm": true, "max_count": maxCount,
		"max_age_days": maxAgeDays, "max_total_bytes": maxTotalBytes,
		"expected_version": expectedVersion, "reason": reason}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "PUT", "/backups/retention", nil, body)
		if failure != nil {
			return r.onlineFailure("设置备份保留策略", failure)
		}
		return r.succeedOnline(reply, nil)
	})
}

// runBackupCleanup 分派 backups cleanup 子命令。
func (r *runner) runBackupCleanup(args []string) int {
	if len(args) == 0 {
		return r.helpText("backups cleanup", backupsCommandUsage)
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
			return r.usage("backups cleanup preview 不接受位置参数")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET",
				"/backups/cleanup-preview", nil, nil)
			if failure != nil {
				return r.onlineFailure("备份清理预览", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				preview := onlineDataObject(reply, "cleanup_preview")
				fmt.Fprintf(out, "清理候选：%d 个，%d 字节；受保护 %d 个；"+
					"预览不是删除授权。\n",
					len(onlineDataList(reply, "cleanup_preview")),
					objectInt64(preview, "target_bytes"),
					len(objectList(preview, "protected")))
				printOnlineData(out, reply.data)
			})
		})
	case "submit":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "confirm", value: true},
			flagDef{name: "request-id", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("backups cleanup submit 不接受位置参数")
		}
		if exit := r.requireConfirmWord(values, "CLEANUP"); exit != ExitOK {
			return exit
		}
		body := map[string]any{"confirm": true}
		if requestID := stringFlag(values, "request-id"); requestID != "" {
			body["request_id"] = requestID
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "POST", "/backups/cleanup", nil, body)
			if failure != nil {
				return r.onlineFailure("提交备份清理", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				job := onlineDataObject(reply, "job")
				fmt.Fprintf(out, "清理任务已提交：job_id=%s state=%s existing=%v\n",
					objectString(job, "job_id"), objectString(job, "state"),
					job["existing"])
				fmt.Fprintln(out, "“已提交”不等于“已清理”；清理会在执行时重新计算候选与保护状态。")
			})
		})
	case "help", "-h", "--help":
		return r.helpText("backups cleanup", backupsCommandUsage)
	default:
		return r.usage("未知的 backups cleanup 子命令 %q（可用：preview/submit）", subcommand)
	}
}
