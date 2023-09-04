package managecli

// 步骤 188：客服工单与人工恢复在线 CLI。认证/CSRF/权限/范围/目标保护/敏感策略与
// 审计全部由服务端领域服务重新判定；CLI 只做参数编排与如实展示。
// 敏感动作在 REAUTH_REQUIRED 时按 186 契约完成一次性再次认证并重试同一请求；
// 证明只在内存使用，不进入 argv/日志/JSON。

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

const supportCommandUsage = `用法：
  loginctl support case create --target <user_id> --reason <原因>
  loginctl support case send-reset <case_id>
  loginctl support recovery list [--mode initiated|pending_approval|executable|history] \
      [--operation password_reset|mfa_reset] [--limit 20] [--offset 0]
  loginctl support recovery get <request_id>
  loginctl support recovery request --target <user_id> --operation password_reset|mfa_reset \
      --basis verified_email --reference <核验记录> --evidence <证据摘要> --reason <原因> \
      [--delivery verified_email] [--support-case <case_id>]
  loginctl support recovery approve <request_id> [--note <备注>]
  loginctl support recovery reject <request_id> --reason <原因>
  loginctl support recovery cancel <request_id> --reason <原因>
  loginctl support recovery execute <request_id>
  <在线公共参数：--server/--api-path/--session-file/--ca-file/--timeout/--json>

安全说明：
  - 角色/权限/数据范围由服务端判定；执行人不得是发起者或审批人（三权分离）。
  - 撤销/审批/执行等敏感动作收到 REAUTH_REQUIRED 时按 186 契约再次认证（密码/TOTP）；
    证明不输出、不落盘、不进入命令行。
  - 客服不接触新密码、恢复令牌或验证码；受助用户从既有已验证邮箱接收入口。
  - 列表只显示最小必要字段（脱敏目标），完整目标仅在参与详情读取时展示。`

// runSupport 分派 support 子命令。
func (r *runner) runSupport(args []string) int {
	r.usageText = supportCommandUsage
	if len(args) == 0 {
		return r.helpText("support", supportCommandUsage)
	}
	switch args[0] {
	case "case":
		return r.runSupportCase(args[1:])
	case "recovery":
		return r.runSupportRecovery(args[1:])
	case "help", "-h", "--help":
		return r.helpText("support", supportCommandUsage)
	default:
		return r.usage("未知的 support 子命令 %q", args[0])
	}
}

// runSupportCase 处理 case create/send-reset。
func (r *runner) runSupportCase(args []string) int {
	if len(args) == 0 {
		return r.usage("support case 需要 create 或 send-reset")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "target", value: true}, flagDef{name: "reason", value: true}, flagDef{name: "json"}, flagDef{name: "approval-file", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 0 {
			return r.usage("support case create 不接受位置参数")
		}
		target := strings.TrimSpace(values["target"])
		reason := strings.TrimSpace(values["reason"])
		if target == "" || reason == "" {
			return r.usage("support case create 需要 --target 与 --reason")
		}
		requestID := newLocalRequestID()
		body := map[string]any{"confirm": true, "target_user_id": target,
			"reason": reason, "request_id": requestID}
		params := support.ParamsCaseCreate(target, reason, requestID)
		return r.supportWrite(values, "support.case.create", "user", target, params,
			"POST", "/support/cases", body)
	case "send-reset":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "reason", value: true}, flagDef{name: "json"}, flagDef{name: "approval-file", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 1 {
			return r.usage("support case send-reset 需要且只需要 <case_id>")
		}
		requestID := newLocalRequestID()
		body := map[string]any{"confirm": true, "reason": "客服发送找回",
			"request_id": requestID}
		params := support.ParamsResetSend(positional[0], "", requestID)
		return r.supportWrite(values, "support.reset.send", "support_case", positional[0], params,
			"POST", "/support/cases/"+url.PathEscape(positional[0])+"/send-reset", body)
	default:
		return r.usage("未知的 support case 子命令 %q", sub)
	}
}

// runSupportRecovery 处理人工恢复链。
func (r *runner) runSupportRecovery(args []string) int {
	if len(args) == 0 {
		return r.usage("support recovery 需要 list/get/request/approve/reject/cancel/execute")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "mode", value: true}, flagDef{name: "operation", value: true},
			flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true},
			flagDef{name: "json"}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 0 {
			return r.usage("support recovery list 不接受位置参数")
		}
		query := url.Values{}
		for _, key := range []string{"mode", "operation", "limit", "offset"} {
			if value := strings.TrimSpace(values[key]); value != "" {
				query.Set(key, value)
			}
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET", "/support/recovery/requests", query, nil)
			if failure != nil {
				return r.onlineFailure("查询人工恢复待办", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				writeSupportRecoveryList(out, reply.data)
			})
		})
	case "get":
		values, positional, err := parseFlags(rest, onlineFlagDefs(flagDef{name: "json"}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 1 {
			return r.usage("support recovery get 需要且只需要 <request_id>")
		}
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "GET",
				"/support/recovery/requests/"+url.PathEscape(positional[0]), nil, nil)
			if failure != nil {
				return r.onlineFailure("读取人工恢复申请", failure)
			}
			if r.json {
				return r.succeedOnline(reply, nil)
			}
			return r.succeedOnline(reply, func(out io.Writer) {
				writeSupportRecoveryDetail(out, reply.data)
			})
		})
	case "request":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "target", value: true}, flagDef{name: "operation", value: true},
			flagDef{name: "basis", value: true}, flagDef{name: "reference", value: true},
			flagDef{name: "evidence", value: true}, flagDef{name: "reason", value: true},
			flagDef{name: "delivery", value: true}, flagDef{name: "support-case", value: true},
			flagDef{name: "json"}, flagDef{name: "approval-file", value: true}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 0 {
			return r.usage("support recovery request 不接受位置参数")
		}
		target := strings.TrimSpace(values["target"])
		operation := strings.TrimSpace(values["operation"])
		basis := strings.TrimSpace(values["basis"])
		reference := strings.TrimSpace(values["reference"])
		evidence := strings.TrimSpace(values["evidence"])
		reason := strings.TrimSpace(values["reason"])
		delivery := strings.TrimSpace(values["delivery"])
		if delivery == "" {
			delivery = "verified_email"
		}
		if target == "" || operation == "" || basis == "" || reference == "" ||
			evidence == "" || reason == "" {
			return r.usage("support recovery request 需要 --target/--operation/--basis/--reference/--evidence/--reason")
		}
		requestID := newLocalRequestID()
		body := map[string]any{"confirm": true, "target_user_id": target,
			"operation": operation, "verification_basis": basis,
			"verification_reference": reference, "evidence_summary": evidence,
			"reason": reason, "delivery": delivery,
			"support_case_id": strings.TrimSpace(values["support-case"]),
			"request_id":      requestID}
		params := manualrecovery.ParamsRequest(target, manualrecovery.OperationType(operation),
			manualrecovery.VerificationBasis(basis), reference, evidence, delivery,
			strings.TrimSpace(values["support-case"]))
		return r.supportWrite(values, "support.recovery.request", "user", target, params,
			"POST", "/support/recovery/requests", body)
	case "approve", "reject", "execute":
		return r.runSupportRecoveryDecision(sub, rest)
	case "cancel":
		values, positional, err := parseFlags(rest, onlineFlagDefs(
			flagDef{name: "reason", value: true}, flagDef{name: "json"}))
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 1 {
			return r.usage("support recovery cancel 需要且只需要 <request_id>")
		}
		body := map[string]any{"confirm": true, "reason": strings.TrimSpace(values["reason"]),
			"request_id": newLocalRequestID()}
		r.json = boolFlag(values, "json")
		return r.withOnline(values, func(target *onlineTarget) int {
			reply, failure := target.doJSON(r.ctx, "POST",
				"/support/recovery/"+url.PathEscape(positional[0])+"/cancel", nil, body)
			if failure != nil {
				return r.onlineFailure("取消人工恢复申请", failure)
			}
			return r.succeedOnline(reply, func(out io.Writer) { writeSupportResult(out, reply.data) })
		})
	default:
		return r.usage("未知的 support recovery 子命令 %q", sub)
	}
}

// runSupportRecoveryDecision 实现 approve/reject/execute：先读取受控详情取得
// content_digest/approval_id，再按 186 契约完成敏感写。
func (r *runner) runSupportRecoveryDecision(sub string, args []string) int {
	extra := []flagDef{{name: "json"}, {name: "approval-file", value: true}}
	if sub == "approve" {
		extra = append(extra, flagDef{name: "note", value: true})
	}
	if sub == "reject" {
		extra = append(extra, flagDef{name: "reason", value: true})
	}
	values, positional, err := parseFlags(args, onlineFlagDefs(extra...))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("support recovery %s 需要且只需要 <request_id>", sub)
	}
	requestID := positional[0]
	var detail map[string]any
	return r.withOnline(values, func(target *onlineTarget) int {
		reply, failure := target.doJSON(r.ctx, "GET",
			"/support/recovery/requests/"+url.PathEscape(requestID), nil, nil)
		if failure != nil {
			return r.onlineFailure("读取人工恢复申请详情", failure)
		}
		if data, ok := reply.data["data"].(map[string]any); ok {
			detail = data
		} else {
			detail = reply.data
		}
		targetUserID := objectString(detail, "target_user_id")
		operation := objectString(detail, "operation")
		contentDigest := objectString(detail, "content_digest")
		approvalID := objectString(detail, "approval_id")
		if targetUserID == "" || operation == "" {
			return r.fail("DETAIL_INVALID", ExitError, "服务端详情缺少必要字段", nil)
		}
		var body map[string]any
		var params map[string]string
		path := "/support/recovery/requests/" + url.PathEscape(requestID)
		switch sub {
		case "approve":
			body = map[string]any{"confirm": true, "note": strings.TrimSpace(values["note"]),
				"request_id": newLocalRequestID()}
			params = manualrecovery.ParamsApproveRaw(requestID, targetUserID, operation, contentDigest, "approve")
			path += "/approve"
		case "reject":
			body = map[string]any{"confirm": true, "reason": strings.TrimSpace(values["reason"]),
				"request_id": newLocalRequestID()}
			params = manualrecovery.ParamsApproveRaw(requestID, targetUserID, operation, "", "reject")
			path += "/reject"
		case "execute":
			if approvalID == "" || contentDigest == "" {
				return r.fail("APPROVAL_UNAVAILABLE", ExitForbidden,
					"申请尚未批准或缺少批准绑定信息；不能执行", nil)
			}
			body = map[string]any{"confirm": true, "request_id": newLocalRequestID()}
			params = manualrecovery.ParamsExecuteRaw(requestID, approvalID, targetUserID, operation, contentDigest)
			path += "/execute"
		}
		return r.supportWriteOnTarget(values, target, "support.recovery."+mapDecisionOp(sub),
			"manual_recovery_request", requestID, params, "POST", path, body)
	})
}

// mapDecisionOp 把 CLI 子命令映射为 policy 操作名中的动词部分。
func mapDecisionOp(sub string) string {
	switch sub {
	case "approve", "reject":
		return "approve"
	default:
		return "execute"
	}
}

// supportWrite 通过 withOnline 建立连接并调用 supportWriteOnTarget。
func (r *runner) supportWrite(values map[string]string, operationID, targetType, targetID string,
	params map[string]string, method, path string, body map[string]any) int {
	r.json = boolFlag(values, "json")
	return r.withOnline(values, func(target *onlineTarget) int {
		return r.supportWriteOnTarget(values, target, operationID, targetType, targetID, params,
			method, path, body)
	})
}

// supportWriteOnTarget 执行敏感写；REAUTH_REQUIRED 时按 186 契约再次认证后重试。
func (r *runner) supportWriteOnTarget(values map[string]string, target *onlineTarget,
	operationID, targetType, targetID string, params map[string]string,
	method, path string, body map[string]any) int {
	headers := map[string]string{}
	if approvalFile := strings.TrimSpace(values["approval-file"]); approvalFile != "" {
		loaded, loadErr := readProtectedSecret(approvalFile, "CLI 确认证明文件")
		if loadErr != nil {
			return r.fail("APPROVAL_FILE_INVALID", ExitUnauthenticated,
				"CLI 确认证明文件无效："+loadErr.Error(), nil)
		}
		headers[cliConfirmationHeader] = loaded
	}
	do := func() (*onlineReply, *onlineError) {
		if len(headers) == 0 {
			return target.doJSON(r.ctx, method, path, nil, body)
		}
		return target.doJSONHeaders(r.ctx, method, path, nil, body, headers)
	}
	reply, failure := do()
	reauthUsed := false
	if failure != nil && (failure.code == "REAUTH_REQUIRED" || failure.code == "MFA_REQUIRED") {
		token, exit := r.beginSupportConfirmation(target, operationID, targetType, targetID,
			params, method, path, body)
		if exit != ExitOK {
			return exit
		}
		headers[cliConfirmationHeader] = token
		reauthUsed = true
		reply, failure = do()
	}
	if failure != nil {
		return r.onlineFailure("执行客服/人工恢复操作", failure)
	}
	return r.succeedOnline(reply, func(out io.Writer) {
		if reauthUsed {
			fmt.Fprintln(out, "已按 186 契约完成一次性再次认证；证明未输出。")
		}
		writeSupportResult(out, reply.data)
	})
}

// beginSupportConfirmation 按 186 契约创建并完成一次性确认，返回内存证明。
func (r *runner) beginSupportConfirmation(target *onlineTarget, operationID, targetType, targetID string,
	params map[string]string, method, path string, body map[string]any) (string, int) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", r.fail("REQ_INVALID", ExitError, "请求体序列化失败", nil)
	}
	beginReply, failure := target.doJSON(r.ctx, "POST", "/reauth/begin", nil, map[string]any{
		"scope_id": "system", "operation_id": operationID, "target_type": targetType,
		"target_id": targetID, "params": params, "method": method, "path": path,
		"body": string(encoded),
	})
	if failure != nil {
		return "", r.onlineFailure("开始再次认证确认", failure)
	}
	confirmationID := objectString(beginReply.data, "confirmation_id")
	if confirmationID == "" {
		return "", r.fail("CONFIRM_UNAVAILABLE", ExitForbidden, "服务端未返回确认编号", nil)
	}
	password, exit := r.readSecret("再次认证密码（输入不回显）: ")
	if exit != ExitOK || password == "" {
		return "", r.fail("REAUTH_CANCELLED", ExitUnauthenticated, "未完成再次认证", nil)
	}
	verifyBody := map[string]any{"confirmation_id": confirmationID, "password": password, "totp_code": ""}
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
		return "", r.fail("CONFIRM_TOKEN_MISSING", ExitError, "服务端未返回一次性证明", nil)
	}
	return token, ExitOK
}

// newLocalRequestID 生成仅供本次 CLI 请求使用的稳定 request_id（不含秘密）。
func newLocalRequestID() string {
	return "req_cli_" + randomHexToken(12)
}

// randomHexToken 由 186 同源 crypto/rand 生成十六进制令牌；失败时返回零串。
func randomHexToken(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return strings.Repeat("0", bytesLen*2)
	}
	return fmt.Sprintf("%x", buf)
}

// writeSupportRecoveryList 以可读文本展示待办列表（不含秘密）。
func writeSupportRecoveryList(out io.Writer, data map[string]any) {
	items, _ := data["items"].([]any)
	fmt.Fprintf(out, "count=%d has_more=%v\n", len(items), data["has_more"] == true)
	for index, raw := range items {
		item, _ := raw.(map[string]any)
		fmt.Fprintf(out, "[%d] request=%s operation=%s status=%s target=%s relation=%s created=%s\n",
			index+1, objectString(item, "request_id"), objectString(item, "operation"),
			objectString(item, "status"), objectString(item, "target_masked"),
			objectString(item, "my_relation"), objectString(item, "created_at"))
	}
}

// writeSupportRecoveryDetail 展示申请详情；不含秘密/链接/验证码。
func writeSupportRecoveryDetail(out io.Writer, data map[string]any) {
	for _, key := range []string{"id", "target_user_id", "initiator_user_id", "operation",
		"status", "delivery", "approval_id", "content_digest", "content_consistent",
		"has_approval", "expires_at"} {
		fmt.Fprintf(out, "%s=%v\n", key, data[key])
	}
}

// writeSupportResult 输出敏感写结果；不输出证明/秘密/验证码。
func writeSupportResult(out io.Writer, data map[string]any) {
	keys := []string{"id", "status", "sessions_revoked", "factors_reset", "sent",
		"manual_review", "approver_user_id"}
	for _, key := range keys {
		if value, ok := data[key]; ok {
			fmt.Fprintf(out, "%s=%v\n", key, value)
		}
	}
}
