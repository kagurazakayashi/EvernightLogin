// 本文件实现步骤 156 的 `loginctl admin` 在线只读管理命令：通过同一管理 JSON API
// （internal/adminapi）读取用户/组/角色/权限/应用/客服工单。认证、CSRF、权限、
// 数据范围与领域授权全部由服务端重新判定；CLI 只做路径/查询参数编排与展示，
// 不做本地授权、不直连数据库、不伪造成成功。
package managecli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const adminCommandUsage = `用法：
  loginctl admin users [--limit 20] [--offset 0] [--status <s>] <在线公共参数>
  loginctl admin user <user_id> <在线公共参数>
  loginctl admin groups [--scope-id system] [--limit 20] [--offset 0] <在线公共参数>
  loginctl admin group <group_id> <在线公共参数>
  loginctl admin roles [--scope-id system] [--limit 20] [--offset 0] <在线公共参数>
  loginctl admin role <role_id> <在线公共参数>
  loginctl admin permissions [--scope-id system] [--limit 20] [--offset 0] <在线公共参数>
  loginctl admin applications [--limit 20] [--offset 0] <在线公共参数>
  loginctl admin application <application_id> [members|managed-policy] <在线公共参数>
  loginctl admin support-cases [--status <s>] [--search <关键字>] [--search-fields id,reason] [--limit 20] [--offset 0] <在线公共参数>
  loginctl admin rename-user <user_id> --new-username <新用户名> --reason <原因> \
      [--expected-row-version <n>] [--proof-file <受保护证明文件>] <在线公共参数>
  loginctl admin reset-password <user_id> --reason <原因> --confirm RESET-PASSWORD \
      [--new-password-file <受保护文件>] [--proof-file <受保护证明文件>] <在线公共参数>
  loginctl admin support-case <case_id> <在线公共参数>
  loginctl admin write <path> --body '<JSON对象>' [--method POST|PUT|DELETE] \
      --confirm ADMIN-WRITE <在线公共参数>
    （写路径见服务端已挂载路由；服务端仍强制强认证/CSRF/领域授权/审计）

在线公共参数与 audit/reports 等命令相同（--server/--api-path/--session-file/--ca-file/
--timeout/--json）。命令只调用已挂载的管理 API 路由；未装配的领域返回 404 而不是
空成功。输出默认只展示脱敏字段（用户不含密码/邮箱明文；客服工单不含完整邮箱/秘密）。`

// runAdmin 分派 admin 只读命令。
func (r *runner) runAdmin(args []string) int {
	r.usageText = adminCommandUsage
	if len(args) == 0 {
		return r.helpText("admin", adminCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "admin " + subcommand
	if subcommand == "write" {
		return r.runAdminWrite(rest)
	}
	if subcommand == "rename-user" {
		return r.runAdminRenameUser(rest)
	}
	if subcommand == "reset-password" {
		return r.runAdminResetPassword(rest)
	}
	extra := []flagDef{{name: "limit", value: true}, {name: "offset", value: true},
		{name: "status", value: true}, {name: "scope-id", value: true},
		{name: "search", value: true}, {name: "search-fields", value: true}}
	values, positional, err := parseFlags(rest, onlineFlagDefs(extra...))
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	path := ""
	switch subcommand {
	case "users":
		path = "/users"
	case "user":
		if len(positional) != 1 {
			return r.usage("admin user 需要且只需要 <user_id>")
		}
		path = "/users/" + url.PathEscape(positional[0])
	case "groups":
		path = "/groups"
	case "group":
		if len(positional) != 1 {
			return r.usage("admin group 需要且只需要 <group_id>")
		}
		path = "/groups/" + url.PathEscape(positional[0])
	case "roles":
		path = "/roles"
	case "role":
		if len(positional) != 1 {
			return r.usage("admin role 需要且只需要 <role_id>")
		}
		path = "/roles/" + url.PathEscape(positional[0])
	case "permissions":
		path = "/permissions"
	case "applications":
		path = "/applications"
	case "application":
		if len(positional) < 1 || len(positional) > 2 {
			return r.usage("admin application 需要 <application_id> [members]")
		}
		path = "/applications/" + url.PathEscape(positional[0])
		if len(positional) == 2 {
			switch positional[1] {
			case "members":
				path += "/members"
			case "managed-policy", "policy":
				path += "/managed-policy"
			default:
				return r.usage("admin application 的第二个参数只允许 members|managed-policy")
			}
		}
	case "support-cases":
		path = "/support/cases"
	case "support-case":
		if len(positional) != 1 {
			return r.usage("admin support-case 需要且只需要 <case_id>")
		}
		path = "/support/cases/" + url.PathEscape(positional[0])
	default:
		return r.usage("未知的 admin 子命令 %q", subcommand)
	}
	query := url.Values{}
	for _, key := range []string{"limit", "offset", "status", "search"} {
		if value := strings.TrimSpace(values[key]); value != "" {
			query.Set(key, value)
		}
	}
	if value := strings.TrimSpace(values["search-fields"]); value != "" {
		query.Set("search_fields", value)
	}
	if value := strings.TrimSpace(values["scope-id"]); value != "" {
		query.Set("scope_id", value)
	}
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", path, nil, nil)
		if failure != nil {
			return r.onlineFailure("读取管理数据", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			writeAdminView(out, reply.data)
		})
	})
}

// writeAdminView 以可读文本展示管理只读结果；--json 时由调用方输出原始 envelope。
func writeAdminView(out io.Writer, data map[string]any) {
	if items, ok := data["items"].([]any); ok {
		for index, item := range items {
			object, _ := item.(map[string]any)
			fmt.Fprintf(out, "[%d] ", index+1)
			first := true
			for _, key := range []string{"id", "username", "nickname", "key", "name", "status",
				"scope_id", "masked_username", "target_masked_username"} {
				if value, exists := object[key]; exists {
					if !first {
						fmt.Fprint(out, "  ")
					}
					fmt.Fprintf(out, "%s=%v", key, value)
					first = false
				}
			}
			fmt.Fprintln(out)
		}
		if data["has_more"] == true {
			fmt.Fprintln(out, "还有更多结果；请使用 --offset 继续读取。")
		}
		return
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	for _, key := range keys {
		fmt.Fprintf(out, "%s=%v\n", key, data[key])
	}
}

// runAdminWrite 是 `loginctl admin write`：通过同一管理 API 提交白名单 JSON 写
// 请求。显式确认词只用于 CLI 交互；服务端仍强制管理会话强认证、CSRF、领域授权/
// 敏感策略与审计，并把真实结果/错误码返回。JSON 中 confirm 由本命令在确认后注入。
func (r *runner) runAdminWrite(args []string) int {
	r.usageText = adminCommandUsage
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "body", value: true}, flagDef{name: "confirm", value: true},
		flagDef{name: "method", value: true}, flagDef{name: "approval-file", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	r.json = boolFlag(values, "json")
	if len(positional) != 1 {
		return r.usage("admin write 需要且只需要 <path>")
	}
	if exit := r.requireConfirmWord(values, "ADMIN-WRITE"); exit != ExitOK {
		return exit
	}
	raw := strings.TrimSpace(values["body"])
	if raw == "" || !strings.HasPrefix(raw, "{") || !strings.HasSuffix(raw, "}") {
		return r.usage("admin write 需要 --body '<JSON 对象>'")
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return r.usage("--body 不是合法 JSON 对象")
	}
	fields["confirm"] = true
	method := strings.ToUpper(strings.TrimSpace(values["method"]))
	switch method {
	case "":
		method = "POST"
	case "POST", "PUT", "DELETE", "PATCH":
	default:
		return r.usage("--method 只允许 POST/PUT/DELETE/PATCH")
	}
	path := "/" + strings.TrimPrefix(positional[0], "/")
	// 可选：一次性 CLI 确认证明（由 loginctl confirm verify/status 写入受保护文件）。
	// 只从受保护文件读取，不进入命令行/JSON 输出；服务端重新校验绑定与一次性消费。
	confirmToken := ""
	if approvalFile := strings.TrimSpace(values["approval-file"]); approvalFile != "" {
		loaded, loadErr := readProtectedSecret(approvalFile, "CLI 确认证明文件")
		if loadErr != nil {
			return r.fail("APPROVAL_FILE_INVALID", ExitUnauthenticated,
				"CLI 确认证明文件无效："+loadErr.Error(), nil)
		}
		confirmToken = loaded
	}
	headers := map[string]string{}
	if confirmToken != "" {
		headers["X-Login-Confirmation"] = confirmToken
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSONHeaders(r.ctx, method, path, nil, fields, headers)
		if failure != nil {
			return r.onlineFailure("执行管理写操作", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			writeAdminView(out, reply.data)
		})
	})
}
