// 本文件实现 `loginctl session admin-revoke` 在线命令（步骤 151）：通过管理
// JSON API 让已获授权的管理员在明确作用范围内强制下线目标用户/会话。
//
// 边界：CLI 不做本地授权；会话秘密只从受保护文件读取并以 Bearer 发送。服务端
// 重新校验管理会话强认证、敏感策略、sessions.revoke 权限、作用范围、root/受保护
// 目标与审计，CLI 只做参数编排与如实展示（0 撤销按幂等成功显示，不伪造更多）。
package managecli

import (
	"fmt"
	"io"
)

const sessionAdminRevokeUsage = `用法：
  loginctl session admin-revoke (--user <user_id> | --session-id <session_id>) \
[--scope-app <app_id>] --reason <原因> --confirm ADMIN-REVOKE <在线公共参数>

在线公共参数：
  --server <url>        管理 API 基础地址，默认 http://127.0.0.1:<配置端口或 8080>
  --api-path <path>     管理 API 挂载路径，默认 /admin/v1
  --session-file <file> 管理会话秘密的受保护文件（必须；秘密不进入命令行/日志）
  --ca-file <pem>       可选 TLS 附加 CA；默认严格校验证书，不提供跳过开关
  --timeout <30s>       单个 JSON 请求期限（1s～5m）。
  --json                输出 {ok,command,request_id,data|error}

安全说明：
  - 必须使用已完成强认证（且未过期）的管理会话；服务端会对敏感操作重新校验。
  - --scope-app 为空表示系统范围；非空时仅撤销绑定该应用的会话，其他应用/全局
    合法会话按服务端既定策略保留。
  - root 与受保护账户不能通过本命令强制下线；越权/过期强认证会返回稳定错误码。
  - 目标不存在、已失效或超出作用范围时返回 revoked=0（幂等成功），不代表发生了撤销。`

func (r *runner) runSessionAdminRevoke(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "user", value: true},
		flagDef{name: "session-id", value: true},
		flagDef{name: "scope-app", value: true},
		flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true},
		flagDef{name: "json"},
	))
	if err != nil {
		return r.flagError(err)
	}
	r.usageText = sessionAdminRevokeUsage
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("session admin-revoke 不接受位置参数")
	}
	if exit := r.requireConfirmWord(values, "ADMIN-REVOKE"); exit != ExitOK {
		return exit
	}
	user := values["user"]
	sessionID := values["session-id"]
	if (user == "") == (sessionID == "") {
		return r.usage("必须且只能指定 --user 或 --session-id 之一")
	}
	reason := values["reason"]
	if reason == "" {
		return r.usage("必须提供 --reason 说明强制下线理由")
	}
	body := map[string]any{
		"confirm":           true,
		"scope_app_id":      values["scope-app"],
		"target_user_id":    user,
		"target_session_id": sessionID,
		"reason":            reason,
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/sessions/revoke", nil, body)
		if failure != nil {
			return r.onlineFailure("管理员强制下线", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			revoked := objectInt64(reply.data, "revoked")
			fmt.Fprintf(out, "已撤销会话数=%d\n", revoked)
			if revoked == 0 {
				fmt.Fprintln(out, "目标不存在、已失效或超出作用范围；按幂等成功处理，"+
					"不代表发生了撤销。")
			}
			fmt.Fprintln(out, "权限、作用范围、root 保护与审计均由服务端重新判定。")
		})
	})
}
