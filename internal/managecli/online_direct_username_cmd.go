package managecli

// 步骤 258：管理员直接修改他人用户名的在线命令。
//
// 流程与安全约定：
//   - 一次两步验证：begin 绑定目标/新用户名 → 密码（必要时 TOTP）确认为一次性证明 →
//     同一命令内立即用该证明提交改名，不经每层重复弹验证；
//   - 密码/TOTP 只从 stdin 读取（终端不回显；管道/测试输入按行读取），不进入命令行
//     参数、环境变量、进程列表或日志；--json 输出不含密码与一次性证明；
//   - 也可用 --proof-file 读取受保护文件中的外部证明（例如 Passkey/安全密钥流程已
//     完成的证明），此时跳过 begin/verify，仍由服务端核对绑定；
//   - 操作者身份只由服务端管理会话决定；CLI 不做本地授权、不伪造成功；
//   - 稳定错误码与退出码由 onlineFailure 统一映射（REAUTH_REQUIRED/CONFLICT/
//     REQ_INVALID/ACCESS_DENIED 等）。

import (
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// adminRenameCommandUsage 是 admin rename-user 帮助。
const adminRenameCommandUsage = `用法：
  loginctl admin rename-user <user_id> --new-username <新用户名> --reason <原因> \
      --confirm RENAME-USER [--expected-row-version <n>] \
      [--proof-file <受保护证明文件>] <在线公共参数>

说明：
  - 需要真实管理会话与 users.username.change.other 独立权限；目标不能是 root 或本人。
  - 默认交互读取管理密码（必要时再读 TOTP 动态码）完成一次两步验证；自动化可用
    管道输入（例如 printf '密码\n验证码\n' | loginctl admin rename-user ...）。
  - --proof-file 用于已通过外部两步验证取得的一次性证明；证明只能使用一次。
  - 省略 --expected-row-version 时先读取目标当前行版本；并发冲突返回 CONFLICT。
  - --json 输出只含脱敏结果（用户 ID/用户名/行版本），不含密码与证明。`

// runAdminRenameUser 执行一次完整的“两步验证 + 直接改名”。
func (r *runner) runAdminRenameUser(args []string) int {
	r.usageText = adminRenameCommandUsage
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "new-username", value: true}, flagDef{name: "reason", value: true},
		flagDef{name: "expected-row-version", value: true},
		flagDef{name: "proof-file", value: true}, flagDef{name: "confirm", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("admin rename-user 需要且只需要 <user_id>")
	}
	r.json = boolFlag(values, "json")
	targetUserID := strings.TrimSpace(positional[0])
	newUsername := strings.TrimSpace(values["new-username"])
	reason := strings.TrimSpace(values["reason"])
	if targetUserID == "" || newUsername == "" || reason == "" {
		return r.usage("admin rename-user 需要 <user_id>、--new-username 与 --reason")
	}
	expectedRowVersion := int64(0)
	if rawVersion := strings.TrimSpace(values["expected-row-version"]); rawVersion != "" {
		parsedVersion, parseErr := strconv.ParseInt(rawVersion, 10, 64)
		if parseErr != nil || parsedVersion < 0 {
			return r.usage("--expected-row-version 必须是非负整数")
		}
		expectedRowVersion = parsedVersion
	}
	if strings.TrimSpace(values["confirm"]) != "RENAME-USER" {
		return r.usage("直接改名需要显式 --confirm RENAME-USER")
	}
	proofFile := strings.TrimSpace(values["proof-file"])
	return r.withOnline(values, func(target *onlineTarget) int {
		proofToken := ""
		if proofFile != "" {
			token, readErr := readProtectedSecret(proofFile, "直接管理操作证明")
			if readErr != nil {
				return r.fail("PROOF_FILE_READ_FAILED", ExitError,
					"读取受保护证明文件失败："+readErr.Error(), nil)
			}
			proofToken = strings.TrimSpace(token)
			if proofToken == "" {
				return r.fail("PROOF_TOKEN_MISSING", ExitError, "证明文件为空", nil)
			}
		}
		if proofToken == "" {
			beginReply, failure := target.doJSON(r.ctx, "POST",
				"/users/"+url.PathEscape(targetUserID)+"/username-verification", nil,
				map[string]any{"new_username": newUsername, "confirm": true})
			if failure != nil {
				return r.onlineFailure("发起直接改名两步验证", failure)
			}
			challengeID := objectString(beginReply.data, "challenge_id")
			if challengeID == "" {
				return r.fail("CHALLENGE_MISSING", ExitError, "服务端未返回两步验证挑战编号", nil)
			}
			// 若服务端未装配真实两步因素，仍由证明门面 fail-closed；不在此伪造成功。
			password, exit := r.readSecret("管理密码（输入不回显）: ")
			if exit != ExitOK || password == "" {
				return exit
			}
			confirmBody := map[string]any{"challenge_id": challengeID,
				"password": password, "totp_code": "", "confirm": true}
			confirmReply, failure := target.doJSON(r.ctx, "POST",
				"/users/"+url.PathEscape(targetUserID)+"/username-verification/confirm",
				nil, confirmBody)
			if failure != nil && failure.code == "MFA_REQUIRED" {
				code, codeExit := r.readSecret("第二因素动态码（输入不回显）: ")
				if codeExit != ExitOK {
					return codeExit
				}
				confirmBody["totp_code"] = code
				confirmReply, failure = target.doJSON(r.ctx, "POST",
					"/users/"+url.PathEscape(targetUserID)+"/username-verification/confirm",
					nil, confirmBody)
			}
			if failure != nil {
				return r.onlineFailure("完成直接改名两步验证", failure)
			}
			proofToken = objectString(confirmReply.data, "proof_token")
			if proofToken == "" {
				return r.fail("PROOF_TOKEN_MISSING", ExitError, "服务端未返回一次性操作证明", nil)
			}
		}
		if expectedRowVersion == 0 {
			userReply, failure := target.doJSON(r.ctx, "GET",
				"/users/"+url.PathEscape(targetUserID), nil, nil)
			if failure != nil {
				return r.onlineFailure("读取目标用户版本", failure)
			}
			user, _ := userReply.data["user"].(map[string]any)
			if value, ok := user["row_version"].(float64); ok && value > 0 {
				expectedRowVersion = int64(value)
			}
			if expectedRowVersion < 1 {
				return r.fail("ROW_VERSION_MISSING", ExitError, "目标用户缺少可用行版本", nil)
			}
		}
		reply, failure := target.doJSON(r.ctx, "POST",
			"/users/"+url.PathEscape(targetUserID)+"/username", nil,
			map[string]any{"new_username": newUsername,
				"expected_row_version": expectedRowVersion, "reason": reason,
				"proof_token": proofToken, "confirm": true})
		if failure != nil {
			return r.onlineFailure("提交直接改名", failure)
		}
		user, _ := reply.data["user"].(map[string]any)
		result := map[string]any{"user": user}
		if r.json {
			return r.succeed(result)
		}
		fmt.Fprintf(r.stdout, "已修改用户名：%v（用户 ID %v，行版本 %v）\n",
			user["username"], user["id"], user["row_version"])
		io.WriteString(r.stdout, "稳定用户 ID、角色、应用成员与历史关联保持不变。\n")
		return ExitOK
	})
}
