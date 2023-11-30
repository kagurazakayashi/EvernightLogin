package managecli

// 步骤 234：本地受信边界下的账户有效期读写命令。
//
// 与既有 loginctl user 命令相同，本地运维者可读数据库即可管理；写操作仍需显式
// --operator、--expected-version、--confirm，并复用账户领域服务的 root 保护、
// UTC 半开区间、乐观并发与关键审计。到期/续期只影响可用性，不改手动状态。

import (
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// userValidityUsage 是 user validity 帮助。
const userValidityUsage = `用法：
  loginctl user validity get <user_id> --operator <id> [--config <file>] [--json]
  loginctl user validity set <user_id> --operator <id> --expected-version N \
--confirm SET-VALIDITY [--from <RFC3339>] [--until <RFC3339>] [--config <file>] [--json]

说明：
  - 有效期是 UTC 半开区间 [from, until)；省略某端表示该端不限制（永久有效）。
  - 到期只影响可用性，不修改 status；续期不会启用被手动禁用的账户；root 拒绝。
  - 写操作必须带 --expected-version（来自 validity get 的 row_version）与确认词。`

// userValidityOutput 是账户有效期脱敏投影。
type userValidityOutput struct {
	UserID     string  `json:"user_id"`
	Status     string  `json:"status"`
	IsRoot     bool    `json:"is_root"`
	ValidFrom  *string `json:"valid_from"`
	ValidUntil *string `json:"valid_until"`
	RowVersion int64   `json:"row_version"`
	Available  bool    `json:"available"`
	Reason     string  `json:"reason"`
	CheckedAt  string  `json:"checked_at"`
}

// newUserValidityOutput 投影有效期视图。
func newUserValidityOutput(validity account.UserValidity) userValidityOutput {
	output := userValidityOutput{UserID: validity.UserID,
		Status: string(validity.Status), IsRoot: validity.IsRoot,
		RowVersion: validity.RowVersion, Available: validity.Available,
		Reason: string(validity.Reason), CheckedAt: formatTime(validity.CheckedAt)}
	if validity.ValidFrom != nil {
		value := formatTime(*validity.ValidFrom)
		output.ValidFrom = &value
	}
	if validity.ValidUntil != nil {
		value := formatTime(*validity.ValidUntil)
		output.ValidUntil = &value
	}
	return output
}

// runUserValidity 分派 user validity get/set。
func (r *runner) runUserValidity(args []string) int {
	r.usageText = userValidityUsage
	if len(args) == 0 {
		return r.helpText("user validity", userValidityUsage)
	}
	action, rest := args[0], args[1:]
	r.command = "user validity " + action
	switch action {
	case "get":
		return r.runUserValidityGet(rest)
	case "set":
		return r.runUserValiditySet(rest)
	case "help", "-h", "--help":
		return r.helpText("user validity", userValidityUsage)
	default:
		return r.usage("未知的 user validity 子命令 %q（可用：get/set）", action)
	}
}

// runUserValidityGet 读取账户有效期与当前可用性。
func (r *runner) runUserValidityGet(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl user validity get <user_id> --operator <id>")
	}
	r.json = boolFlag(values, "json")
	operator := stringFlag(values, "operator")
	if operator == "" {
		return r.usage("user validity get 必须提供 --operator")
	}
	userID := strings.TrimSpace(positional[0])
	if !account.ValidUserID(userID) {
		return r.usage("用户 ID 格式无效")
	}
	caller, exit := r.userCaller(operator)
	if exit != ExitOK {
		return exit
	}
	bundle, exit := r.openAccountService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer bundle.close()
	validity, err := bundle.service.GetUserValidity(r.ctx, caller, userID)
	if err != nil {
		return r.userFailure("读取账户有效期", err)
	}
	output := newUserValidityOutput(validity)
	return r.succeedWithText(output, "用户：%s\n状态：%s\nroot：%t\n"+
		"有效起：%s\n有效止：%s\nrow_version：%d\n当前可用：%t（%s，检查于 %s）\n",
		output.UserID, output.Status, output.IsRoot, optionalText(output.ValidFrom),
		optionalText(output.ValidUntil), output.RowVersion, output.Available,
		output.Reason, output.CheckedAt)
}

// runUserValiditySet 设置账户有效期（显式确认 + 乐观并发）。
func (r *runner) runUserValiditySet(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
		{name: "expected-version", value: true}, {name: "confirm", value: true},
		{name: "from", value: true}, {name: "until", value: true},
		{name: "request-id", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl user validity set <user_id> ...")
	}
	r.json = boolFlag(values, "json")
	operator := stringFlag(values, "operator")
	if operator == "" {
		return r.usage("user validity set 必须提供 --operator")
	}
	if stringFlag(values, "confirm") != "SET-VALIDITY" {
		return r.usage("user validity set 必须提供 --confirm SET-VALIDITY")
	}
	userID := strings.TrimSpace(positional[0])
	if !account.ValidUserID(userID) {
		return r.usage("用户 ID 格式无效")
	}
	expected, err := parseIntFlag(values, "expected-version", 0)
	if err != nil || expected <= 0 {
		return r.usage("--expected-version 必须是正整数（来自 validity get）")
	}
	validFrom, err := parseValidityFlag(stringFlag(values, "from"), "--from")
	if err != nil {
		return r.usage("%v", err)
	}
	validUntil, err := parseValidityFlag(stringFlag(values, "until"), "--until")
	if err != nil {
		return r.usage("%v", err)
	}
	caller, exit := r.userCaller(operator)
	if exit != ExitOK {
		return exit
	}
	if requestID := strings.TrimSpace(stringFlag(values, "request-id")); requestID != "" {
		if caller, err = caller.WithRequestID(requestID); err != nil {
			return r.usage("--request-id 格式无效")
		}
	}
	bundle, exit := r.openAccountService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer bundle.close()
	result, err := bundle.service.SetValidity(r.ctx, caller,
		account.ValidityCommandRequest{UserID: userID, ValidFrom: validFrom,
			ValidUntil: validUntil, ExpectedRowVersion: int64(expected)})
	if err != nil {
		return r.userFailure("设置账户有效期", err)
	}
	validity, err := bundle.service.GetUserValidity(r.ctx, caller, userID)
	if err != nil {
		return r.userFailure("读取账户有效期", err)
	}
	output := newUserValidityOutput(validity)
	data := map[string]any{"validity": output, "changed": result.Changed,
		"previous_valid_from":  validityText(result.PreviousValidFrom),
		"previous_valid_until": validityText(result.PreviousValidUntil)}
	return r.succeedWithText(data, "用户：%s\n是否变更：%t\n有效起：%s\n有效止：%s\n"+
		"row_version：%d\n当前可用：%t（%s）\n", output.UserID, result.Changed,
		optionalText(output.ValidFrom), optionalText(output.ValidUntil),
		output.RowVersion, output.Available, output.Reason)
}

// parseValidityFlag 解析可选 RFC3339 时间；空串表示该端不限制（nil）。
func parseValidityFlag(raw, flagName string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%s 必须是 RFC3339 时间（如 2026-11-26T00:00:00Z）", flagName)
	}
	utc := parsed.UTC().Truncate(time.Millisecond)
	return &utc, nil
}

// optionalText 把可选时间字符串渲染为“不限制”。
func optionalText(value *string) string {
	if value == nil {
		return "不限制"
	}
	return *value
}

// validityText 把可选时间渲染为 JSON 友好的字符串或 nil。
func validityText(value *time.Time) *string {
	if value == nil {
		return nil
	}
	text := formatTime(*value)
	return &text
}
