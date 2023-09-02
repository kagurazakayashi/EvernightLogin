// 本文件实现 `loginctl session admin-list` 与 `loginctl session admin-revoke` 在线
// 命令（步骤 151/187）：通过管理 JSON API 让已获授权的管理员查询/强制下线目标
// 用户会话。
//
// 边界：CLI 不做本地授权；会话秘密只从受保护文件读取并以 Bearer 发送。服务端
// 重新校验管理会话强认证、敏感策略、sessions.revoke 权限、作用范围、root/受保护
// 目标与审计，CLI 只做参数编排与如实展示（0 撤销按幂等成功显示，不伪造更多）。
// 敏感撤销在 REAUTH_REQUIRED 时按 186 契约完成一次性再次认证（密码/TOTP），证明
// 只在内存中使用，不进入命令行、日志或 --json 输出。
package managecli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// cliConfirmationHeader 与 186 契约一致的一次性确认证明请求头。
const cliConfirmationHeader = "X-Login-Confirmation"

const sessionAdminRevokeUsage = `用法：
  loginctl session admin-list --user <user_id> [--scope-app <app_id>] \
      [--page 1] [--page-size 20] <在线公共参数>
  loginctl session admin-revoke (--user <user_id> | --session-id <session_id>) \
      [--scope-app <app_id>] --reason <原因> --confirm ADMIN-REVOKE \
      [--approval-file <一次性确认证明文件>] <在线公共参数>

在线公共参数：
  --server <url>        管理 API 基础地址，默认 http://127.0.0.1:<配置端口或 8080>
  --api-path <path>     管理 API 挂载路径，默认 /admin/v1
  --session-file <file> 管理会话秘密的受保护文件（必须；秘密不进入命令行/日志）
  --ca-file <pem>       可选 TLS 附加 CA；默认严格校验证书，不提供跳过开关
  --timeout <30s>       单个 JSON 请求期限（1s～5m）。
  --json                输出 {ok,command,request_id,data|error}

安全说明：
  - 必须使用已完成强认证（且未过期）的管理会话；服务端会对敏感操作重新校验。
  - admin-list 只查询目标用户在当前作用范围内的活动会话；目标不存在、没有活动
    会话或超出范围时统一显示空列表，不泄露目标是否存在。
  - --scope-app 为空表示系统范围；非空时仅撤销/查询绑定该应用的会话，其他应用/
    全局合法会话按服务端既定策略保留。
  - root 与受保护账户不能通过本命令强制下线；越权/过期强认证会返回稳定错误码。
  - 撤销收到 REAUTH_REQUIRED 时按 186 契约进行一次性再次认证（密码/TOTP），证明
    只保存在内存中；也可先用 loginctl confirm 取得证明并传 --approval-file。
  - 目标不存在、已失效或超出作用范围时返回 revoked=0（幂等成功），不代表发生了撤销。
  - 本操作只撤销身份会话，不撤销 OAuth 授权/刷新令牌族/第三方系统会话。`

// runSessionAdminList 查询目标用户在当前作用范围内的活动会话。
func (r *runner) runSessionAdminList(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "user", value: true},
		flagDef{name: "scope-app", value: true},
		flagDef{name: "page", value: true},
		flagDef{name: "page-size", value: true},
		flagDef{name: "json"},
	))
	if err != nil {
		return r.flagError(err)
	}
	r.usageText = sessionAdminRevokeUsage
	r.json = boolFlag(values, "json")
	if len(positional) != 0 {
		return r.usage("session admin-list 不接受位置参数")
	}
	user := strings.TrimSpace(values["user"])
	if user == "" {
		return r.usage("session admin-list 必须提供 --user <user_id>")
	}
	query := url.Values{}
	query.Set("target_user_id", user)
	for _, key := range []string{"scope-app", "page", "page-size"} {
		if value := strings.TrimSpace(values[key]); value != "" {
			query.Set(strings.ReplaceAll(key, "-", "_"), value)
		}
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET", "/sessions", query, nil)
		if failure != nil {
			return r.onlineFailure("查询管理员会话", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			writeSessionAdminList(out, reply.data)
		})
	})
}

// writeSessionAdminList 输出会话公开摘要；不含秘密/CSRF/验证摘要。
func writeSessionAdminList(out io.Writer, data map[string]any) {
	sessions, _ := data["sessions"].([]any)
	total := objectInt64(data, "total")
	fmt.Fprintf(out, "目标用户=%s 作用范围=%s 活动会话总数=%d\n",
		objectString(data, "target_user_id"), scopeLabel(objectString(data, "scope_app_id")), total)
	if len(sessions) == 0 {
		fmt.Fprintln(out, "没有可列出的活动会话（目标不存在、已失效或超出作用范围时结果相同）。")
		return
	}
	for index, raw := range sessions {
		object, _ := raw.(map[string]any)
		fmt.Fprintf(out, "[%d] id=%s app=%s kind=%s current=%v created=%s last_seen=%s\n",
			index+1, objectString(object, "id"), scopeLabel(objectString(object, "app_id")),
			objectString(object, "kind"), object["current"] == true,
			objectString(object, "created_at"), objectString(object, "last_seen_at"))
	}
	if data["has_more"] == true {
		fmt.Fprintln(out, "还有更多结果；请使用 --page 继续读取。")
	}
	fmt.Fprintln(out, "会话 ID 可用于 admin-revoke --session-id；本输出不含会话秘密。")
}

// scopeLabel 把空作用范围显示为系统范围，便于人读。
func scopeLabel(appID string) string {
	if appID == "" {
		return "system"
	}
	return appID
}

// runSessionAdminRevoke 执行管理员强制下线；必要时按 186 契约完成一次性再次认证。
func (r *runner) runSessionAdminRevoke(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "user", value: true},
		flagDef{name: "session-id", value: true},
		flagDef{name: "scope-app", value: true},
		flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true},
		flagDef{name: "approval-file", value: true},
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
	user := strings.TrimSpace(values["user"])
	sessionID := strings.TrimSpace(values["session-id"])
	if (user == "") == (sessionID == "") {
		return r.usage("必须且只能指定 --user 或 --session-id 之一")
	}
	reason := strings.TrimSpace(values["reason"])
	if reason == "" {
		return r.usage("必须提供 --reason 说明强制下线理由")
	}
	scopeAppID := strings.TrimSpace(values["scope-app"])
	body := map[string]any{
		"confirm":           true,
		"scope_app_id":      scopeAppID,
		"target_user_id":    user,
		"target_session_id": sessionID,
		"reason":            reason,
	}
	// 可选的预取证明：只从受保护文件读取，不进入命令行/JSON 输出。
	approvalToken := ""
	if approvalFile := strings.TrimSpace(values["approval-file"]); approvalFile != "" {
		loaded, loadErr := readProtectedSecret(approvalFile, "CLI 确认证明文件")
		if loadErr != nil {
			return r.fail("APPROVAL_FILE_INVALID", ExitUnauthenticated,
				"CLI 确认证明文件无效："+loadErr.Error(), nil)
		}
		approvalToken = loaded
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		revoke := func(token string) (*onlineReply, *onlineError) {
			if token == "" {
				return target.doJSON(r.ctx, "POST", "/sessions/revoke", nil, body)
			}
			return target.doJSONHeaders(r.ctx, "POST", "/sessions/revoke", nil, body,
				map[string]string{cliConfirmationHeader: token})
		}
		reply, failure := revoke(approvalToken)
		reauthUsed := false
		if failure != nil && approvalToken == "" &&
			(failure.code == "REAUTH_REQUIRED" || failure.code == "MFA_REQUIRED") {
			token, exit := r.beginSessionRevokeConfirmation(target, body, scopeAppID, user, sessionID)
			if exit != ExitOK {
				return exit
			}
			reauthUsed = true
			reply, failure = revoke(token)
		}
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
			if reauthUsed {
				fmt.Fprintln(out, "已按 186 契约完成一次性再次认证；证明只使用一次且未输出。")
			}
			fmt.Fprintln(out, "权限、作用范围、root 保护与审计均由服务端重新判定。")
			fmt.Fprintln(out, "本操作只撤销身份会话，不撤销 OAuth 授权/刷新令牌族/第三方会话。")
		})
	})
}

// beginSessionRevokeConfirmation 在服务端要求再次认证时，按 186 契约创建并完成
// 一次性确认，返回仅可内存使用的证明。绑定内容与真正要执行的写请求完全一致
// （method/path/body/操作/目标/参数），证明不落盘、不打印。
func (r *runner) beginSessionRevokeConfirmation(target *onlineTarget, body map[string]any,
	scopeAppID, targetUserID, targetSessionID string) (string, int) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", r.fail("REQ_INVALID", ExitError, "请求体序列化失败", nil)
	}
	targetType, targetID := "user", targetUserID
	if targetSessionID != "" {
		targetType, targetID = "session", targetSessionID
	}
	beginReply, failure := target.doJSON(r.ctx, "POST", "/reauth/begin", nil, map[string]any{
		"scope_id":     "system",
		"operation_id": session.OperationSessionRevokeOther,
		"target_type":  targetType,
		"target_id":    targetID,
		"params":       session.AdminRevokeParams(scopeAppID, targetUserID, targetSessionID),
		"method":       "POST",
		"path":         "/sessions/revoke",
		"body":         string(encoded),
	})
	if failure != nil {
		return "", r.onlineFailure("开始再次认证确认", failure)
	}
	confirmationID := objectString(beginReply.data, "confirmation_id")
	if confirmationID == "" || onlineDataBool(beginReply, "required") == false &&
		confirmationID == "" {
		// 无确认编号：无法在不伪造证明的情况下继续，按失败处理并给出稳定错误。
		return "", r.fail("CONFIRM_UNAVAILABLE", ExitForbidden,
			"服务端未返回可用的再次认证确认；未执行撤销", nil)
	}
	password, exit := r.readSecret("再次认证密码（输入不回显）: ")
	if exit != ExitOK || password == "" {
		if exit == ExitOK {
			return "", r.fail("REAUTH_CANCELLED", ExitUnauthenticated,
				"未输入再次认证凭据；未执行撤销", nil)
		}
		return "", exit
	}
	verifyBody := map[string]any{"confirmation_id": confirmationID,
		"password": password, "totp_code": ""}
	verifyReply, failure := target.doJSON(r.ctx, "POST", "/reauth/verify", nil, verifyBody)
	if failure != nil && failure.code == "MFA_REQUIRED" {
		code, exitCode := r.readSecret("第二因素动态码（输入不回显）: ")
		if exitCode != ExitOK {
			return "", exitCode
		}
		verifyBody["totp_code"] = code
		verifyReply, failure = target.doJSON(r.ctx, "POST", "/reauth/verify", nil, verifyBody)
	}
	if failure != nil {
		return "", r.onlineFailure("完成再次认证", failure)
	}
	token := objectString(verifyReply.data, "confirmation_token")
	if token == "" {
		return "", r.fail("CONFIRM_TOKEN_MISSING", ExitError,
			"服务端未返回一次性确认证明；未执行撤销", nil)
	}
	return token, ExitOK
}
