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
	"strings"
)

// notificationsCommandUsage 是 notifications 组帮助。
const notificationsCommandUsage = `用法：
  loginctl notifications status <在线公共参数>
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
	default:
		return r.usage("未知的在线管理命令组 %q", group)
	}
}
