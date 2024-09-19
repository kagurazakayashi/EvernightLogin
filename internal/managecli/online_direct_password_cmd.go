package managecli

// 步骤 259：管理员直接重置他人密码的在线命令。
//
// 安全约定：
//   - 操作者明确输入新口令；口令只从 stdin 隐藏输入（交互）或受保护文件
//     （--new-password-file，自动化），**不作为命令行明文参数/环境变量**；
//   - 管理密码/TOTP 同样只从 stdin 读取；不进入进程列表/日志/--json 输出；
//   - 一次两步验证：begin 绑定目标+新口令密封意图 → confirm 取得一次性证明 →
//     同一命令内立即提交重置，不经每层重复弹验证；
//   - 服务端仍重新授权、校验密码策略/历史、目标状态与证明绑定；CLI 不做本地授权、
//     不伪造成功；稳定错误码与退出码由 onlineFailure 统一映射；
//   - 结果只输出脱敏事实（must_change、会话撤销、旧找回失效），不返回密码/哈希/证明。

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

// adminResetPasswordUsage 是 admin reset-password 帮助。
const adminResetPasswordUsage = `用法：
  loginctl admin reset-password <user_id> --reason <原因> --confirm RESET-PASSWORD \
      [--new-password-file <受保护文件>] [--proof-file <受保护证明文件>] <在线公共参数>

说明：
  - 需要真实管理会话与 users.password.reset.other 独立权限；目标不能是 root 或本人，
    且目标必须已有密码凭证（无密码账户拒绝，不把重置权限扩成添加密码）。
  - 默认交互输入管理密码（必要时再读 TOTP 动态码）与新口令两次；自动化可用管道
    stdin（例如 printf '管理密码\n动态码\n新口令\n新口令\n' | ...）或用
    --new-password-file 提供新口令的受保护文件（0600、绝对路径）。
  - --proof-file 用于已通过外部两步验证取得的一次性证明；证明绑定目标与新口令，
    只能使用一次。
  - 成功后服务端使目标旧会话/找回链接失效，但保留 MFA/Passkey，并要求目标下次登录
    改密（must_change）；--json 只输出脱敏结果，不含密码/证明。`

// runAdminResetPassword 执行一次完整的“两步验证 + 直接重置密码”。
func (r *runner) runAdminResetPassword(args []string) int {
	r.usageText = adminResetPasswordUsage
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "reason", value: true},
		flagDef{name: "confirm", value: true},
		flagDef{name: "new-password-file", value: true},
		flagDef{name: "proof-file", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("admin reset-password 需要且只需要 <user_id>")
	}
	r.json = boolFlag(values, "json")
	targetUserID := strings.TrimSpace(positional[0])
	reason := strings.TrimSpace(values["reason"])
	if targetUserID == "" || reason == "" {
		return r.usage("admin reset-password 需要 <user_id> 与 --reason")
	}
	if strings.TrimSpace(values["confirm"]) != "RESET-PASSWORD" {
		return r.usage("直接重置密码需要显式 --confirm RESET-PASSWORD")
	}
	newPassword, exit := r.readNewPassword(values["new-password-file"])
	if exit != ExitOK {
		return exit
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
				"/users/"+url.PathEscape(targetUserID)+"/password-verification", nil,
				map[string]any{"new_password": newPassword, "confirm": true})
			if failure != nil {
				return r.onlineFailure("发起直接重置密码两步验证", failure)
			}
			challengeID := objectString(beginReply.data, "challenge_id")
			if challengeID == "" {
				return r.fail("CHALLENGE_MISSING", ExitError, "服务端未返回两步验证挑战编号", nil)
			}
			password, exit := r.readSecret("管理密码（输入不回显）: ")
			if exit != ExitOK || password == "" {
				return exit
			}
			confirmBody := map[string]any{"challenge_id": challengeID,
				"password": password, "totp_code": "", "confirm": true}
			confirmReply, failure := target.doJSON(r.ctx, "POST",
				"/users/"+url.PathEscape(targetUserID)+"/password-verification/confirm",
				nil, confirmBody)
			if failure != nil && failure.code == "MFA_REQUIRED" {
				code, codeExit := r.readSecret("第二因素动态码（输入不回显）: ")
				if codeExit != ExitOK {
					return codeExit
				}
				confirmBody["totp_code"] = code
				confirmReply, failure = target.doJSON(r.ctx, "POST",
					"/users/"+url.PathEscape(targetUserID)+
						"/password-verification/confirm", nil, confirmBody)
			}
			if failure != nil {
				return r.onlineFailure("完成直接重置密码两步验证", failure)
			}
			proofToken = objectString(confirmReply.data, "proof_token")
			if proofToken == "" {
				return r.fail("PROOF_TOKEN_MISSING", ExitError, "服务端未返回一次性操作证明", nil)
			}
		}
		reply, failure := target.doJSON(r.ctx, "POST",
			"/users/"+url.PathEscape(targetUserID)+"/password", nil,
			map[string]any{"new_password": newPassword, "reason": reason,
				"proof_token": proofToken, "confirm": true})
		if failure != nil {
			return r.onlineFailure("提交直接重置密码", failure)
		}
		if r.json {
			return r.succeed(reply.data)
		}
		fmt.Fprintf(r.stdout, "已直接重置密码（用户 ID %v，安全版本 %v）。\n",
			reply.data["user_id"], reply.data["security_version"])
		io.WriteString(r.stdout, "目标旧会话与旧找回链接已失效；MFA/Passkey 保留；"+
			"下次登录必须修改密码（must_change）。\n")
		return ExitOK
	})
}

// readNewPassword 读取操作者输入的新口令：受保护文件或交互两次输入（不回显）。
// 空口令、两次不一致或文件不可读都返回用法/读取错误；口令不进入任何输出。
func (r *runner) readNewPassword(passwordFile string) (string, int) {
	if strings.TrimSpace(passwordFile) != "" {
		password, err := readProtectedSecret(passwordFile, "新口令")
		if err != nil {
			return "", r.fail("NEW_PASSWORD_FILE_READ_FAILED", ExitError,
				"读取新口令文件失败："+err.Error(), nil)
		}
		if password == "" {
			return "", r.usage("新口令文件为空")
		}
		return password, ExitOK
	}
	first, exit := r.readSecret("新口令（输入不回显）: ")
	if exit != ExitOK {
		return "", exit
	}
	if first == "" {
		return "", r.usage("新口令不能为空")
	}
	second, exit := r.readSecret("再次输入新口令确认: ")
	if exit != ExitOK {
		return "", exit
	}
	if first != second {
		return "", r.usage("两次输入的新口令不一致")
	}
	return first, ExitOK
}
