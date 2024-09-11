// 本文件实现 `loginctl notifications` 与 `loginctl tasks` 在线命令，以及在线命令
// 组的总分派。
//
// 边界说明：
//   - notifications status 只返回服务端脱敏的配置/启用状态；test 只在宿主明确
//     声明本地捕获模式时执行，服务端会要求确认、敏感策略（强认证）与真实审计，
//     任一缺失都返回稳定能力码，CLI 如实映射为失败（绝不伪成功、绝不真实外发）。
//   - tasks get 读取服务端任务详情，权限与数据范围由服务端 TaskAuthorizer 每次
//     重新判定；CLI 不做本地授权，也不输出任务载荷。
package managecli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// onlineHistoryMaxLimit 是与服务端 adminapi.MaxPageLimit 对齐的在线列表单页上限。
// CLI 本地校验不能比服务端宽松：否则 101..200 会通过本地校验后被服务端以 400
// 拒绝（步骤 266 质量审计 N-266-1）。上限变化时必须与服务端常量同步核对。
const onlineHistoryMaxLimit = 100

// historyListLimit 解析在线列表 --limit（默认 20，范围 1..onlineHistoryMaxLimit）。
func historyListLimit(values map[string]string) (int, error) {
	limit, err := parseIntFlag(values, "limit", 20)
	if err != nil {
		return 0, err
	}
	if limit < 1 || limit > onlineHistoryMaxLimit {
		return 0, fmt.Errorf("--limit 必须在 1～%d 之间", onlineHistoryMaxLimit)
	}
	return limit, nil
}

// notificationsCommandUsage 是 notifications 组帮助。
const notificationsCommandUsage = `用法：
  loginctl notifications status <在线公共参数>
  loginctl notifications history [--user-id <usr_id>] [--limit 1..100] [--cursor <上一页 next_cursor>] [--json] <在线公共参数>
  loginctl notifications test --confirm TEST-NOTIFICATION <在线公共参数>

安全说明：
  - status 只返回脱敏的启停状态、投递模式与渠道键，不包含 SMTP 主机/账号/密钥。
  - test 只在宿主装配“本地捕获”通知器时执行；任何真实投递模式都会被服务端拒绝
    （NOTIFICATION_TEST_DISABLED），CLI 保留原始错误码并返回退出码 1。
  - 该命令不会真实外发邮件或 Webhook。`

// runNotifications 分派 notifications 子命令。
func (r *runner) runNotifications(args []string) int {
	r.usageText = notificationsCommandUsage
	if len(args) == 0 {
		return r.helpText("notifications", notificationsCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "notifications " + subcommand
	switch subcommand {
	case "status":
		values, positional, err := parseFlags(rest, onlineFlagDefs())
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("notifications status 不接受位置参数")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/notifications", nil, nil)
			if failure != nil {
				return r.onlineFailure("读取通知状态", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				status := onlineDataObject(reply, "notifications")
				fmt.Fprintf(out, "已启用=%v 本地捕获=%v 投递模式=%s 渠道=%v\n",
					status["enabled"], status["local_capture"],
					objectString(status, "delivery_mode"), objectList(status, "channels"))
				if note := objectString(status, "note"); note != "" {
					fmt.Fprintf(out, "说明：%s\n", note)
				}
				fmt.Fprintln(out, "本命令只读；不包含 SMTP 账号、密钥或收件地址。")
			})
		})
	case "history":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "user-id", value: true}, flagDef{name: "cursor", value: true},
			flagDef{name: "limit", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("notifications history 不接受位置参数")
		}
		query := queryValues()
		setQuery(values, query, "user-id", "user_id")
		setQuery(values, query, "cursor", "cursor")
		limit, limitErr := historyListLimit(values)
		if limitErr != nil {
			return r.usage("%v", limitErr)
		}
		query.Set("limit", strconv.Itoa(limit))
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/notifications/history", query, nil)
			if failure != nil {
				return r.onlineFailure("读取安全告知历史", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				list := onlineDataList(reply, "notifications")
				fmt.Fprintf(out, "安全告知：%d 条（has_more=%v）\n", len(list),
					onlineDataBool(reply, "has_more"))
				for _, item := range list {
					record, _ := item.(map[string]any)
					fmt.Fprintf(out, "  - %s %s state=%s recipient=%s created=%s\n",
						objectString(record, "id"), objectString(record, "operation_id"),
						objectString(record, "state"), objectString(record, "recipient_masked"),
						objectString(record, "created_at"))
				}
				if cursor := objectString(reply.data, "next_cursor"); cursor != "" {
					fmt.Fprintf(out, "下一页：--cursor %s\n", cursor)
				}
				fmt.Fprintln(out, "说明：queued 只代表已受理；succeeded 只代表发送后端接受，不代表已读或最终送达。")
			})
		})
	case "test":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "confirm", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("notifications test 不接受位置参数")
		}
		if exit := r.requireConfirmWord(values, "TEST-NOTIFICATION"); exit != ExitOK {
			return exit
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "POST", "/notifications/test", nil,
				map[string]any{"confirm": true})
			if failure != nil {
				return r.onlineFailure("执行通知测试（本地捕获）", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				capture := onlineDataObject(reply, "capture")
				fmt.Fprintf(out, "本地捕获测试完成：capture_id=%s 渠道=%s 接收者=%s\n",
					objectString(capture, "capture_id"), objectString(capture, "channel"),
					objectString(capture, "recipient_masked"))
				fmt.Fprintln(out, "该结果只代表本地捕获器收到消息，不代表任何真实通道可达，"+
					"也未真实外发。")
			})
		})
	case "help", "-h", "--help":
		return r.helpText("notifications", notificationsCommandUsage)
	default:
		return r.usage("未知的 notifications 子命令 %q（可用：status/test）", subcommand)
	}
}

// tasksCommandUsage 是 tasks 组帮助。
const tasksCommandUsage = `用法：
  loginctl tasks get <task_id> <在线公共参数>

说明：
  - 读取服务端真实任务状态与尝试历史；权限与数据范围由服务端每次重新判定。
  - 任务载荷被服务端显式剔除，不返回业务数据或秘密。
  - 本地任务索引/等待仍使用 ` + "`loginctl task list/get/wait/cancel`" + `（本地运维边界）。`

// runTasks 分派 tasks 子命令。
func (r *runner) runTasks(args []string) int {
	r.usageText = tasksCommandUsage
	if len(args) == 0 {
		return r.helpText("tasks", tasksCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "tasks " + subcommand
	switch subcommand {
	case "get":
		values, positional, err := parseFlags(rest, onlineFlagDefs())
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 1 {
			return r.usage("用法：loginctl tasks get <task_id> <在线公共参数>")
		}
		taskID := strings.TrimSpace(positional[0])
		if taskID == "" {
			return r.usage("任务编号不能为空")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET",
				"/tasks/"+urlPathEscape(taskID), nil, nil)
			if failure != nil {
				return r.onlineFailure("读取任务详情", failure)
			}
			return r.succeedOnline(reply, nil)
		})
	case "help", "-h", "--help":
		return r.helpText("tasks", tasksCommandUsage)
	default:
		return r.usage("未知的 tasks 子命令 %q（可用：get）", subcommand)
	}
}

// runOnline 分派在线管理命令组。这些命令必须连接运行中的 login-server 管理 API，
// 与本地运维命令（config/diag/migrate/task/user/...）是两套信任边界。
func (r *runner) runOnline(group string, args []string) int {
	switch group {
	case "audit":
		return r.runAudit(args)
	case "reports":
		return r.runReports(args)
	case "backups":
		return r.runBackups(args)
	case "notifications":
		return r.runNotifications(args)
	case "tasks":
		return r.runTasks(args)
	case "deliveries":
		return r.runDeliveries(args)
	default:
		return r.usage("未知的在线管理命令组 %q", group)
	}
}

// deliveriesCommandUsage 是 deliveries 组帮助（步骤 266）。
const deliveriesCommandUsage = `用法：
  loginctl deliveries list [--state <state>] [--limit 1..100] [--cursor <上一页 next_cursor>] [--json] <在线公共参数>

说明：
  - 读取 login-server 的邮件投递记录分页（需要 diagnostics.read 或受信本机进程）。
  - 只返回白名单字段：投递 ID/模板/状态/尝试次数/错误码/脱敏收件人/时间；
    不返回加密载荷、完整收件人或磁盘路径。
  - queued 只代表已受理；succeeded 只代表发送后端接受，不代表已读或最终送达。
  - 取消投递与取消任务不同：投递取消会终止该封邮件发送；任务取消只是请求受理。`

// runDeliveries 分派 deliveries 子命令。
func (r *runner) runDeliveries(args []string) int {
	r.usageText = deliveriesCommandUsage
	if len(args) == 0 {
		return r.helpText("deliveries", deliveriesCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "deliveries " + subcommand
	switch subcommand {
	case "list":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "state", value: true}, flagDef{name: "cursor", value: true},
			flagDef{name: "limit", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		r.json = boolFlag(values, "json")
		if len(positional) != 0 {
			return r.usage("deliveries list 不接受位置参数")
		}
		query := queryValues()
		setQuery(values, query, "state", "state")
		setQuery(values, query, "cursor", "cursor")
		limit, limitErr := historyListLimit(values)
		if limitErr != nil {
			return r.usage("%v", limitErr)
		}
		query.Set("limit", strconv.Itoa(limit))
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/deliveries", query, nil)
			if failure != nil {
				return r.onlineFailure("读取邮件投递记录", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				list := onlineDataList(reply, "deliveries")
				fmt.Fprintf(out, "投递记录：%d 条（has_more=%v）\n", len(list),
					onlineDataBool(reply, "has_more"))
				for _, item := range list {
					record, _ := item.(map[string]any)
					fmt.Fprintf(out, "  - %s kind=%s state=%s attempts=%d/%d recipient=%s code=%s\n",
						objectString(record, "delivery_id"), objectString(record, "kind"),
						objectString(record, "state"), objectInt64(record, "attempts"),
						objectInt64(record, "max_attempts"),
						objectString(record, "recipient_masked"),
						objectString(record, "last_error_code"))
				}
				if cursor := objectString(reply.data, "next_cursor"); cursor != "" {
					fmt.Fprintf(out, "下一页：--cursor %s\n", cursor)
				}
				fmt.Fprintln(out, "说明：不返回加密载荷/完整收件人；取消投递与取消任务语义不同。")
			})
		})
	case "help", "-h", "--help":
		return r.helpText("deliveries", deliveriesCommandUsage)
	default:
		return r.usage("未知的 deliveries 子命令 %q（可用：list）", subcommand)
	}
}
