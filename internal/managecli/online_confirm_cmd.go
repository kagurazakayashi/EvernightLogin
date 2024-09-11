// 本文件实现步骤 186 的 CLI 敏感操作再认证/确认命令：
//
//	loginctl confirm begin  ...   创建绑定操作/目标/参数与即将执行的写请求的挑战
//	loginctl confirm verify ...  密码（+TOTP）完成真实再次认证，证明写入受保护文件
//	loginctl confirm status ...  查询状态；WebAuthn 完成后取回证明（可 --wait 轮询）
//	loginctl confirm cancel ...  取消未完成的确认（不产生任何可执行能力）
//
// 安全约定：
//   - 密码/TOTP 只从 stdin 交互读取，不进入命令行参数、环境变量、进程列表或日志；
//   - 一次性确认证明只写入 --approval-out 指定的受保护文件（0600、非符号链接），
//     或由后续敏感命令通过 --approval-file 读取；--json 输出明确不包含证明；
//   - 服务端每步重新校验管理会话，普通/受限会话不能冒充管理会话；
//   - 证明绑定操作/目标/参数摘要/主体/会话/过期时间与即将执行的 HTTP 请求，由
//     服务端在消费时再次校验；CLI 不做本地授权、不伪造成成功。
package managecli

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"golang.org/x/term"
)

const confirmCommandUsage = `用法：
  loginctl confirm begin --operation <id> --method <METHOD> --path <相对路径> \
      [--scope-id system] [--target-type <t>] [--target-id <id>] \
      [--params '<JSON对象>'] [--body '<JSON请求体>'] <在线公共参数>
  loginctl confirm verify --confirmation-id <cfm_id> --approval-out <受保护文件> <在线公共参数>
  loginctl confirm status --confirmation-id <cfm_id> [--wait 120s] \
      [--approval-out <受保护文件>] <在线公共参数>
  loginctl confirm cancel --confirmation-id <cfm_id> <在线公共参数>

说明：
  - begin 绑定“操作 + 目标 + 参数摘要 + 主体/会话 + 即将执行的写请求（method/路径/
    请求体）”；每次写请求只能使用一次对应证明。
  - verify 交互式读取密码（必要时的 TOTP 动态码）；WebAuthn 账户请用 begin 输出的
    browser_url 在浏览器完成确认，再用 status 取回证明。
  - 证明文件只保存一次性确认证明，不含管理会话秘密；权限、CSRF、敏感策略与审计
    仍由服务端每次请求重新执行。
  - 在线公共参数：--server/--api-path/--session-file/--ca-file/--timeout/--json。`

// runConfirm 分派 confirm 子命令。
func (r *runner) runConfirm(args []string) int {
	r.usageText = confirmCommandUsage
	if len(args) == 0 {
		return r.helpText("confirm", confirmCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "confirm " + subcommand
	switch subcommand {
	case "begin":
		return r.runConfirmBegin(rest)
	case "verify":
		return r.runConfirmVerify(rest)
	case "status":
		return r.runConfirmStatus(rest)
	case "cancel":
		return r.runConfirmCancel(rest)
	default:
		return r.usage("未知的 confirm 子命令 %q", subcommand)
	}
}

// confirmParams 解析 --params 的 JSON 对象（键值都必须是字符串）。
func confirmParams(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(trimmed), &object); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(object))
	for key, value := range object {
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("参数值必须是字符串")
		}
		result[key] = text
	}
	return result, nil
}

// runConfirmBegin 创建绑定挑战。
func (r *runner) runConfirmBegin(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "operation", value: true}, flagDef{name: "scope-id", value: true},
		flagDef{name: "target-type", value: true}, flagDef{name: "target-id", value: true},
		flagDef{name: "params", value: true}, flagDef{name: "method", value: true},
		flagDef{name: "path", value: true}, flagDef{name: "body", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("confirm begin 不接受位置参数")
	}
	operation := strings.TrimSpace(values["operation"])
	method := strings.ToUpper(strings.TrimSpace(values["method"]))
	path := strings.TrimSpace(values["path"])
	if operation == "" || method == "" || path == "" {
		return r.usage("confirm begin 需要 --operation、--method 与 --path")
	}
	params, err := confirmParams(values["params"])
	if err != nil {
		return r.usage("--params 必须是字符串键值 JSON 对象")
	}
	scope := strings.TrimSpace(values["scope-id"])
	if scope == "" {
		scope = "system"
	}
	body := values["body"]
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/reauth/begin", nil,
			map[string]any{"scope_id": scope, "operation_id": operation,
				"target_type": strings.TrimSpace(values["target-type"]),
				"target_id":   strings.TrimSpace(values["target-id"]),
				"params":      params, "method": method, "path": path, "body": body})
		if failure != nil {
			return r.onlineFailure("开始再次认证确认", failure)
		}
		required := onlineDataBool(reply, "required")
		if !required {
			return r.succeedOnline(reply, func(out io.Writer) {
				io.WriteString(out, "当前策略不要求额外再次认证；可直接执行该操作。\n")
			})
		}
		if !r.json {
			writeConfirmBeginView(r.stdout, reply, target)
			return ExitOK
		}
		return r.succeedOnline(reply, nil)
	})
}

// writeConfirmBeginView 输出人读的确认信息；不包含任何证明/令牌。
func writeConfirmBeginView(out io.Writer, reply *onlineReply, target *onlineTarget) {
	data := reply.data
	browser := objectString(data, "browser_path")
	if browser != "" {
		browser = strings.TrimRight(target.baseURL, "/") + target.apiPath + browser
	}
	methods := make([]string, 0, 4)
	if raw, ok := data["methods"].([]any); ok {
		for _, item := range raw {
			if text, ok := item.(string); ok {
				methods = append(methods, text)
			}
		}
	}
	io.WriteString(out, "确认编号: "+objectString(data, "confirmation_id")+"\n")
	io.WriteString(out, "挑战编号: "+objectString(data, "challenge_id")+"\n")
	io.WriteString(out, "要求强度: "+objectString(data, "required_strength")+"\n")
	io.WriteString(out, "可用方式: "+strings.Join(methods, ", ")+"\n")
	io.WriteString(out, "过期时间: "+objectString(data, "expires_at")+"\n")
	if browser != "" {
		io.WriteString(out, "WebAuthn 受控跳转: "+browser+"\n")
	}
}

// confirmVerifyResult 是 verify 的脱敏输出：不含一次性证明。
type confirmVerifyResult struct {
	ConfirmationID string `json:"confirmation_id"`
	Method         string `json:"method,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	ApprovalFile   string `json:"approval_file"`
}

// runConfirmVerify 交互式完成密码/TOTP 再次认证，并把证明写入受保护文件。
func (r *runner) runConfirmVerify(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "confirmation-id", value: true},
		flagDef{name: "approval-out", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("confirm verify 不接受位置参数")
	}
	confirmationID := strings.TrimSpace(values["confirmation-id"])
	outFile := strings.TrimSpace(values["approval-out"])
	if confirmationID == "" || outFile == "" {
		return r.usage("confirm verify 需要 --confirmation-id 与 --approval-out")
	}
	password, exit := r.readSecret("再次认证密码（输入不回显）: ")
	if exit != ExitOK || password == "" {
		return exit
	}
	totpCode := ""
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/reauth/verify", nil,
			map[string]any{"confirmation_id": confirmationID, "password": password,
				"totp_code": totpCode})
		if failure != nil && failure.code == "MFA_REQUIRED" {
			code, exitCode := r.readSecret("第二因素动态码（输入不回显）: ")
			if exitCode != ExitOK {
				return exitCode
			}
			reply, failure = target.doJSON(r.ctx, "POST", "/reauth/verify", nil,
				map[string]any{"confirmation_id": confirmationID, "password": password,
					"totp_code": code})
		}
		if failure != nil {
			return r.onlineFailure("完成再次认证", failure)
		}
		token := objectString(reply.data, "confirmation_token")
		if token == "" {
			return r.fail("CONFIRM_TOKEN_MISSING", ExitError, "服务端未返回确认证明", nil)
		}
		if err := writeProtectedSecret(outFile, token); err != nil {
			return r.fail("APPROVAL_FILE_WRITE_FAILED", ExitError,
				"写入确认证明文件失败："+err.Error(), nil)
		}
		result := confirmVerifyResult{ConfirmationID: confirmationID,
			Method:       objectString(reply.data, "method"),
			ExpiresAt:    objectString(reply.data, "expires_at"),
			ApprovalFile: outFile}
		if r.json {
			return r.succeed(result)
		}
		io.WriteString(r.stdout, "再次认证完成；确认证明已写入受保护文件 "+outFile+"\n")
		io.WriteString(r.stdout, "该证明只能使用一次，且只能用于确认时绑定的同一写请求。\n")
		return ExitOK
	})
}

// runConfirmStatus 查询状态；WebAuthn 完成后取回证明（可等待轮询）。
func (r *runner) runConfirmStatus(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "confirmation-id", value: true},
		flagDef{name: "approval-out", value: true},
		flagDef{name: "wait", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("confirm status 不接受位置参数")
	}
	confirmationID := strings.TrimSpace(values["confirmation-id"])
	if confirmationID == "" {
		return r.usage("confirm status 需要 --confirmation-id")
	}
	waitTimeout := 0
	if raw := strings.TrimSpace(values["wait"]); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 0 || parsed > 10*time.Minute {
			return r.usage("--wait 必须是 0～10m 的时长")
		}
		waitTimeout = int(parsed / time.Second)
	}
	outFile := strings.TrimSpace(values["approval-out"])
	deadline := time.Now().Add(time.Duration(waitTimeout) * time.Second)
	for {
		exit := r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/reauth/status",
				url.Values{"confirmation_id": {confirmationID}}, nil)
			if failure != nil {
				return r.onlineFailure("查询确认状态", failure)
			}
			data := reply.data
			state := objectString(data, "state")
			result := confirmStatusResult{ConfirmationID: confirmationID, State: state,
				ExpiresAt: objectString(data, "expires_at")}
			token := objectString(data, "confirmation_token")
			if token != "" {
				if outFile == "" {
					return r.fail("APPROVAL_OUT_REQUIRED", ExitUsage,
						"确认已完成；请用 --approval-out 指定受保护文件接收一次性证明", nil)
				}
				if err := writeProtectedSecret(outFile, token); err != nil {
					return r.fail("APPROVAL_FILE_WRITE_FAILED", ExitError,
						"写入确认证明文件失败："+err.Error(), nil)
				}
				result.ApprovalFile = outFile
				if r.json {
					return r.succeed(result)
				}
				io.WriteString(r.stdout, "确认完成；一次性证明已写入受保护文件 "+outFile+"\n")
				return ExitOK
			}
			switch state {
			case "pending":
				if waitTimeout > 0 && time.Now().Before(deadline) {
					time.Sleep(2 * time.Second)
					return ExitRetry
				}
				if r.json {
					return r.succeed(result)
				}
				io.WriteString(r.stdout, "确认仍在等待完成（pending）。\n")
				return ExitOK
			case "verified":
				return r.fail("APPROVAL_OUT_REQUIRED", ExitUsage,
					"确认已验证；请用 --approval-out 指定受保护文件接收一次性证明", nil)
			case "cancelled", "consumed":
				return r.fail("CONFIRM_NOT_EXECUTABLE", ExitError,
					"确认记录当前状态为 "+state+"，不能用于执行", nil)
			default:
				if r.json {
					return r.succeed(result)
				}
				io.WriteString(r.stdout, "确认状态: "+state+"\n")
				return ExitOK
			}
		})
		if exit != ExitRetry {
			return exit
		}
		if time.Now().After(deadline) {
			return r.fail("CONFIRM_WAIT_TIMEOUT", ExitTimeout,
				"等待确认完成超时（确认可能仍在等待浏览器完成）", nil)
		}
	}
}

// confirmStatusResult 是 status 的脱敏输出：永不含一次性证明。
type confirmStatusResult struct {
	ConfirmationID string `json:"confirmation_id"`
	State          string `json:"state"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	ApprovalFile   string `json:"approval_file,omitempty"`
}

// runConfirmCancel 取消未完成的确认。
func (r *runner) runConfirmCancel(args []string) int {
	values, positional, err := parseFlags(args, onlineFlagDefs(
		flagDef{name: "confirmation-id", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("confirm cancel 不接受位置参数")
	}
	confirmationID := strings.TrimSpace(values["confirmation-id"])
	if confirmationID == "" {
		return r.usage("confirm cancel 需要 --confirmation-id")
	}
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "POST", "/reauth/cancel", nil,
			map[string]any{"confirmation_id": confirmationID})
		if failure != nil {
			return r.onlineFailure("取消再次认证确认", failure)
		}
		return r.succeedOnline(reply, func(out io.Writer) {
			io.WriteString(out, "确认已取消；未产生任何可执行能力。\n")
		})
	})
}

// readSecret 从 stdin 读取秘密：终端输入不回显；管道/测试输入按行读取。
func (r *runner) readSecret(prompt string) (string, int) {
	if r.stderr != nil {
		io.WriteString(r.stderr, prompt)
	}
	if file, ok := r.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		raw, err := term.ReadPassword(int(file.Fd()))
		io.WriteString(r.stderr, "\n")
		if err != nil {
			return "", r.fail("SECRET_INPUT_FAILED", ExitError, "读取秘密输入失败", nil)
		}
		return string(raw), ExitOK
	}
	if r.secretInput == nil {
		r.secretInput = bufio.NewReader(r.stdin)
	}
	line, err := r.secretInput.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", r.fail("SECRET_INPUT_FAILED", ExitError, "读取秘密输入失败", nil)
	}
	return strings.TrimRight(line, "\r\n"), ExitOK
}

// writeProtectedSecret 以 0600 独占创建受保护证明文件；已存在或路径不安全时拒绝。
func writeProtectedSecret(path, secret string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || !strings.HasPrefix(trimmed, string(os.PathSeparator)) && !isWindowsAbs(trimmed) {
		return errors.New("必须使用绝对路径")
	}
	if fileInfo, err := os.Lstat(trimmed); err == nil {
		if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return errors.New("目标已存在且不是普通文件")
		}
		return errors.New("目标文件已存在（拒绝覆盖既有确认证明）")
	}
	file, err := os.OpenFile(trimmed, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("无法以受保护权限创建文件")
	}
	if _, err := io.WriteString(file, strings.TrimSpace(secret)+"\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(trimmed)
		return errors.New("写入确认证明失败")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(trimmed)
		return errors.New("同步确认证明失败")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(trimmed)
		return errors.New("关闭确认证明文件失败")
	}
	// 与 --session-file 相同的平台文件保护检查：Windows ACL / Unix 0600。
	if err := secrets.ProtectFile(trimmed); err != nil {
		_ = os.Remove(trimmed)
		return errors.New("无法收紧确认证明文件权限")
	}
	return nil
}

// isWindowsAbs 识别 Windows 绝对路径（测试与跨平台构建）。
func isWindowsAbs(path string) bool {
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') ||
		(path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/')
}

// ExitRetry 是 status --wait 的内部重试哨兵（不暴露给调用者）。
const ExitRetry = -1
