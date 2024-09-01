// 本文件实现 `loginctl user` 命令：本地管理员对账户的只读查询与启停。
//
// 信任边界与授权：
//   - 这是本地运维命令（与 cmd/login-backup 相同的边界）：能读数据库文件的本地
//     管理员即可管理；--operator 是写入审计与授权器比对的本地管理员稳定标识。
//   - 命令不实现自己的权限放行规则：所有读写都调用既有 internal/account 服务，
//     account.Authorizer 只允许“该本地操作者”执行本步明确列出的账户动作，其余
//     （创建、删除、资料修改）一律拒绝，避免 CLI 扩大管理面。
//   - root 等受保护账户由服务层拒绝变更；CLI 不额外放行。
//   - 写操作要求 --expected-version（来自先前的只读查询）与显式 --confirm 确认词，
//     并发/版本冲突返回退出码 6，不隐式重试或覆盖。
package managecli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// userCommandUsage 是 user 组帮助。
const userCommandUsage = `用法：
  loginctl user list --operator <id> [--config <file>] [--status <s>] [--sort <f>] \
[--search <关键字>] [--search-fields username,nickname] [--desc] [--limit N] [--offset N] [--json]
  loginctl user get <user_id> --operator <id> [--config <file>] [--json]
  loginctl user disable <user_id> --operator <id> --expected-version N --confirm DISABLE \
[--config <file>] [--json]
  loginctl user enable <user_id> --operator <id> --expected-version N --confirm ENABLE \
[--config <file>] [--json]
  loginctl user validity get <user_id> --operator <id> [--config <file>] [--json]
  loginctl user validity set <user_id> --operator <id> --expected-version N --confirm SET-VALIDITY \
[--from <RFC3339>] [--until <RFC3339>] [--config <file>] [--json]

说明：
  - --operator 是本地管理员稳定标识；授权器只允许该标识执行本命令列出的动作。
  - --search 是可选的字面子串搜索（默认匹配用户名与昵称，最多 64 个字符）；
    --search-fields 可限定 username/nickname；搜索不参与登录或唯一身份判定。
  - 写操作必须带 --expected-version（来自 user get/list 的 row_version）与确认词；
    版本不匹配返回退出码 6，请重新读取后再决定。
  - root 等受保护账户由账户服务拒绝变更；本命令不提供创建/删除/资料修改。`

// userListDefaultLimit 是用户列表默认与上限。
const (
	userListDefaultLimit = 20
	userListMaxLimit     = 100
)

// localAccountAuthorizer 是本地 CLI 的账户授权器：只允许显式指定的本地操作者
// 执行本步开放的动作。它不调用远程认证、不读取前端自报权限，也不扩大管理面。
type localAccountAuthorizer struct {
	operatorID string
}

// Authorize 实现 account.Authorizer。
func (a localAccountAuthorizer) Authorize(_ context.Context, caller account.Caller,
	action account.Action) error {
	actor := caller.Actor()
	if actor.Type != audit.ActorLocalAdmin || actor.ID != a.operatorID {
		return account.ErrAccessDenied
	}
	switch action {
	case account.ActionGetUser, account.ActionListUsers,
		account.ActionDisableUser, account.ActionEnableUser,
		account.ActionGetValidity, account.ActionSetValidity:
		return nil
	default:
		return account.ErrAccessDenied
	}
}

// userOutput 是账户的公开投影；不含秘密（账户本就没有可输出的认证秘密）。
type userOutput struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	Nickname        string `json:"nickname"`
	Status          string `json:"status"`
	RowVersion      int64  `json:"row_version"`
	SecurityVersion int64  `json:"security_version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// newUserOutput 投影账户。
func newUserOutput(user account.User) userOutput {
	return userOutput{ID: user.ID, Username: user.Username, Nickname: user.Nickname,
		Status: string(user.Status), RowVersion: user.RowVersion,
		SecurityVersion: user.SecurityVersion,
		CreatedAt:       formatTime(user.CreatedAt), UpdatedAt: formatTime(user.UpdatedAt)}
}

// runUser 分派 user 子命令。
func (r *runner) runUser(args []string) int {
	r.usageText = userCommandUsage
	if len(args) == 0 {
		return r.helpText("user", userCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "user " + subcommand
	switch subcommand {
	case "list":
		return r.runUserList(rest)
	case "get":
		return r.runUserGet(rest)
	case "disable":
		return r.runUserState(rest, false)
	case "enable":
		return r.runUserState(rest, true)
	case "validity":
		return r.runUserValidity(rest)
	case "help", "-h", "--help":
		return r.helpText("user", userCommandUsage)
	default:
		return r.usage("未知的 user 子命令 %q（可用：list/get/disable/enable/validity）", subcommand)
	}
}

// accountServiceBundle 是账户命令构造的服务与底层连接。
type accountServiceBundle struct {
	service *account.Service
	raw     *storagesqlite.Store
}

// close 释放数据库连接。
func (b *accountServiceBundle) close() {
	if b != nil && b.raw != nil {
		_ = b.raw.Close()
	}
}

// openAccountService 打开数据库并构造真实账户服务（本地操作者授权器）。
func (r *runner) openAccountService(values map[string]string,
	operator string) (*accountServiceBundle, int) {
	if _, err := account.LocalBootstrapCaller(operator); err != nil {
		return nil, r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return nil, exit
	}
	raw, exit := r.openDatabase(config)
	if exit != ExitOK {
		return nil, exit
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		_ = raw.Close()
		return nil, r.fail("AUDIT_STORE_UNAVAILABLE", ExitError, "无法构造审计存储", nil)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: r.options.Now})
	if err != nil {
		_ = raw.Close()
		return nil, r.fail("AUDIT_STORE_UNAVAILABLE", ExitError, "无法构造审计写入器", nil)
	}
	accountStore, err := accountsqlite.New(raw)
	if err != nil {
		_ = raw.Close()
		return nil, r.fail("ACCOUNT_STORE_UNAVAILABLE", ExitError, "无法构造账户存储", nil)
	}
	service, err := account.New(account.Options{Store: accountStore, Audit: recorder,
		Authorizer: localAccountAuthorizer{operatorID: operator}, Now: r.options.Now})
	if err != nil {
		_ = raw.Close()
		return nil, r.fail("ACCOUNT_STORE_UNAVAILABLE", ExitError, "无法构造账户服务", nil)
	}
	return &accountServiceBundle{service: service, raw: raw}, ExitOK
}

// userCaller 把本地操作者标识构造为可信调用者。
func (r *runner) userCaller(operator string) (account.Caller, int) {
	caller, err := account.LocalBootstrapCaller(operator)
	if err != nil {
		return account.Caller{}, r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	return caller, ExitOK
}

// runUserList 分页列出账户。
func (r *runner) runUserList(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
		{name: "status", value: true}, {name: "sort", value: true}, {name: "desc"},
		{name: "limit", value: true}, {name: "offset", value: true},
		{name: "search", value: true}, {name: "search-fields", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("user list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	operator := stringFlag(values, "operator")
	if operator == "" {
		return r.usage("user list 必须提供 --operator")
	}
	limit, err := parseLimit(values, userListDefaultLimit, userListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	status := account.Status(stringFlag(values, "status"))
	if status != "" && !status.Valid() {
		return r.usage("--status 不是已定义的账户状态")
	}
	sortField := account.SortField(stringFlag(values, "sort"))
	if sortField != "" && !sortField.Valid() {
		return r.usage("--sort 只支持 created_at/updated_at/username/id")
	}
	if sortField == "" {
		sortField = account.SortCreatedAt
	}
	searchText := strings.TrimSpace(stringFlag(values, "search"))
	var searchFields []account.UserSearchField
	for _, part := range strings.Split(stringFlag(values, "search-fields"), ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		searchFields = append(searchFields, account.UserSearchField(value))
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
	result, err := bundle.service.ListUsers(r.ctx, caller, account.ListRequest{
		Limit: limit, Offset: offset, Status: status, Sort: sortField,
		Descending: boolFlag(values, "desc"),
		Search:     searchText, SearchFields: searchFields})
	if err != nil {
		return r.userFailure("列出用户", err)
	}
	items := make([]userOutput, 0, len(result.Users))
	for _, user := range result.Users {
		items = append(items, newUserOutput(user))
	}
	output := map[string]any{"users": items, "has_more": result.HasMore,
		"limit": limit, "offset": offset, "search": searchText}
	if r.json {
		return r.succeed(output)
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "没有匹配的用户。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  %s  row_version=%d\n", item.ID, item.Username,
			item.Status, item.RowVersion)
	}
	if result.HasMore {
		fmt.Fprintln(r.stdout, "（还有更多结果，请使用 --offset）")
	}
	return ExitOK
}

// runUserGet 读取单个账户。
func (r *runner) runUserGet(args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl user get <user_id> --operator <id> [--config <file>] [--json]")
	}
	r.json = boolFlag(values, "json")
	operator := stringFlag(values, "operator")
	if operator == "" {
		return r.usage("user get 必须提供 --operator")
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
	user, err := bundle.service.GetUser(r.ctx, caller, userID)
	if err != nil {
		return r.userFailure("读取用户", err)
	}
	output := newUserOutput(user)
	return r.succeedWithText(output, "用户：%s\n用户名：%s\n昵称：%s\n状态：%s\n"+
		"row_version：%d\n安全版本：%d\n创建：%s；更新：%s\n",
		output.ID, output.Username, output.Nickname, output.Status,
		output.RowVersion, output.SecurityVersion, output.CreatedAt, output.UpdatedAt)
}

// runUserState 执行禁用或启用；enable 为 true 表示启用。
func (r *runner) runUserState(args []string, enable bool) int {
	action, confirmToken := "disable", "DISABLE"
	if enable {
		action, confirmToken = "enable", "ENABLE"
	}
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"}, {name: "operator", value: true},
		{name: "expected-version", value: true}, {name: "confirm", value: true},
	})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl user %s <user_id> --operator <id> "+
			"--expected-version N --confirm %s [--config <file>] [--json]",
			action, confirmToken)
	}
	r.json = boolFlag(values, "json")
	operator := stringFlag(values, "operator")
	if operator == "" {
		return r.usage("user %s 必须提供 --operator", action)
	}
	if stringFlag(values, "confirm") != confirmToken {
		return r.usage("该写操作必须显式确认：--confirm %s", confirmToken)
	}
	expectedVersion, err := parseIntFlag(values, "expected-version", -1)
	if err != nil || expectedVersion < 1 {
		return r.usage("必须提供正整数 --expected-version（来自 user get/list 的 row_version）")
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
	request := account.StateCommandRequest{UserID: userID,
		ExpectedRowVersion: int64(expectedVersion)}
	var result account.StateChangeResult
	if enable {
		result, err = bundle.service.EnableUser(r.ctx, caller, request)
	} else {
		result, err = bundle.service.DisableUser(r.ctx, caller, request)
	}
	if err != nil {
		return r.userFailure(action+"用户", err)
	}
	output := map[string]any{"user": newUserOutput(result.User),
		"previous_status": string(result.PreviousStatus), "changed": result.Changed}
	if r.json {
		return r.succeed(output)
	}
	if result.Changed {
		fmt.Fprintf(r.stdout, "已%s用户 %s：%s -> %s（row_version=%d）。\n",
			action, result.User.ID, result.PreviousStatus, result.User.Status,
			result.User.RowVersion)
	} else {
		fmt.Fprintf(r.stdout, "未产生变更：用户 %s 已是 %s。\n", result.User.ID,
			result.User.Status)
	}
	return ExitOK
}

// userFailure 把账户领域错误映射为稳定错误码/退出码。
func (r *runner) userFailure(operation string, err error) int {
	code := string(account.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	exitCode := ExitError
	switch {
	case errors.Is(err, account.ErrUserNotFound):
		code = "USER_NOT_FOUND"
		exitCode = ExitError
	case errors.Is(err, account.ErrInvalidRequest), errors.Is(err, account.ErrValidityInvalid):
		exitCode = ExitUsage
	case errors.Is(err, account.ErrAccessDenied), errors.Is(err, account.ErrProtectedUser):
		exitCode = ExitForbidden
	case errors.Is(err, account.ErrInvalidTransition), errors.Is(err, account.ErrStateConflict):
		exitCode = ExitConflict
	}
	return r.fail(code, exitCode, operation+"失败："+err.Error(), nil)
}
