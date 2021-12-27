// 本文件实现组、角色、应用与通知的本地管理只读命令（步骤 84 第二轮）。
//
// 信任边界与授权：
//   - 与 user/session/task 相同的本地运维边界：--operator 是本地管理员稳定标识，
//     能读数据库文件的本机管理员即可管理；不冒充在线认证。
//   - 不实现自己的权限放行规则：读写都调用既有 internal/group、internal/role、
//     internal/app 服务，并复用各包既有的 StaticAuthorizer（LocalAdminIDs 只含该
//     显式操作者）；本包只暴露少量读命令与受控建组，未开放的写动作直接拒绝。
//   - 委派转授检查注入 fail-closed 的 delegation.GuardFuncs（回调为空即拒绝）：
//     本步只开放不需要委派转授的读取与建组；角色分配、应用启停等需要委派/敏感
//     策略的动作不开放，CLI 明确返回 MANAGEMENT_WRITE_NOT_EXPOSED 而不是绕过。
//   - 所有读取由领域服务写真实读审计（服务内既有行为），输出不含秘密。
package managecli

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// domainCommandUsage 是组/角色/应用/通知命令帮助。
const domainCommandUsage = `用法：
  loginctl group list --operator <id> [--scope system|<app_id>] [--limit N] [--offset N] [--json]
  loginctl group get <group_id> --operator <id> [--json]
  loginctl group members <group_id> --operator <id> [--limit N] [--json]
  loginctl group create --operator <id> --scope <system|<app_id>> --key <key> --name <名称> \
--confirm CREATE [--json]
  loginctl role list --operator <id> [--scope system|<app_id>] [--limit N] [--json]
  loginctl role get <role_id> --operator <id> [--json]
  loginctl role permissions <role_id> --operator <id> [--json]
  loginctl app list --operator <id> [--status active|disabled|pending] [--limit N] [--json]
  loginctl app get <application_id> --operator <id> [--json]
  loginctl app members <application_id> --operator <id> [--limit N] [--json]
  loginctl permission list [--scope system|application] [--json]（只读预设目录）
  loginctl notify status [--json] / loginctl notify test（禁止真实外发，明确拒绝）

说明：
  - 全部为本地运维边界；读取由既有领域服务授权并写审计。
  - 角色分配、角色改权限、应用启停/成员变更等需要委派转授与敏感策略的动作
    本步不开放，返回 MANAGEMENT_WRITE_NOT_EXPOSED（退出码 5），不使用放宽替身。
  - 通知测试发送禁止真实外发；宿主未注入 mailer 时配置状态为不可用。`

// managementWriteNotExposed 返回“写动作未在 CLI 开放”的稳定拒绝。
func (r *runner) managementWriteNotExposed(domain, action, reason string) int {
	return r.fail("MANAGEMENT_WRITE_NOT_EXPOSED", ExitForbidden,
		fmt.Sprintf("%s 的 %s 未在 CLI 开放：%s", domain, action, reason), nil)
}

// domainBase 是一次域命令共享的底层资源与审计写入器。
type domainBase struct {
	raw      *storagesqlite.Store
	recorder *audit.Recorder
}

func (b *domainBase) close() {
	if b != nil && b.raw != nil {
		_ = b.raw.Close()
	}
}

// openDomainBase 打开数据库与审计写入器。
func (r *runner) openDomainBase(values map[string]string) (*domainBase, int) {
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
	return &domainBase{raw: raw, recorder: recorder}, ExitOK
}

// openGroupService 构造真实用户组服务（本地操作者授权，委派检查 fail-closed）。
func (r *runner) openGroupService(values map[string]string,
	operator string) (*domainBase, *group.Service, int) {
	if _, err := group.LocalBootstrapCaller(operator); err != nil {
		return nil, nil, r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	base, exit := r.openDomainBase(values)
	if exit != ExitOK {
		return nil, nil, exit
	}
	store, err := groupsqlite.New(base.raw)
	if err != nil {
		base.close()
		return nil, nil, r.fail("GROUP_STORE_UNAVAILABLE", ExitError, "无法构造用户组存储", nil)
	}
	authorizer, err := group.NewStaticAuthorizer(group.AuthorizerOptions{
		LocalAdminIDs: []string{operator}})
	if err != nil {
		base.close()
		return nil, nil, r.fail("GROUP_STORE_UNAVAILABLE", ExitError, "无法构造用户组授权器", nil)
	}
	service, err := group.New(group.Options{Store: store, Audit: base.recorder,
		Authorizer: authorizer, Transfers: delegation.GuardFuncs{},
		AllowLegacyWithoutSensitive: true, Now: r.options.Now})
	if err != nil {
		base.close()
		return nil, nil, r.fail("GROUP_STORE_UNAVAILABLE", ExitError, "无法构造用户组服务", nil)
	}
	return base, service, ExitOK
}

// openRoleService 构造真实角色服务（本地操作者授权，委派检查 fail-closed）。
func (r *runner) openRoleService(values map[string]string,
	operator string) (*domainBase, *role.Service, int) {
	if _, err := role.LocalBootstrapCaller(operator); err != nil {
		return nil, nil, r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	base, exit := r.openDomainBase(values)
	if exit != ExitOK {
		return nil, nil, exit
	}
	store, err := rolesqlite.New(base.raw)
	if err != nil {
		base.close()
		return nil, nil, r.fail("ROLE_STORE_UNAVAILABLE", ExitError, "无法构造角色存储", nil)
	}
	authorizer, err := role.NewStaticAuthorizer(role.AuthorizerOptions{
		LocalAdminIDs: []string{operator}})
	if err != nil {
		base.close()
		return nil, nil, r.fail("ROLE_STORE_UNAVAILABLE", ExitError, "无法构造角色授权器", nil)
	}
	service, err := role.New(role.Options{Store: store, Audit: base.recorder,
		Authorizer: authorizer, Transfers: delegation.GuardFuncs{},
		AllowLegacyWithoutSensitive: true, Now: r.options.Now})
	if err != nil {
		base.close()
		return nil, nil, r.fail("ROLE_STORE_UNAVAILABLE", ExitError, "无法构造角色服务", nil)
	}
	return base, service, ExitOK
}

// openAppService 构造真实应用服务（本地操作者授权，委派检查 fail-closed）。
func (r *runner) openAppService(values map[string]string,
	operator string) (*domainBase, *app.Service, int) {
	if _, err := app.LocalBootstrapCaller(operator); err != nil {
		return nil, nil, r.usage("--operator 本地管理员标识无效（只允许可见 ASCII 稳定标识）")
	}
	base, exit := r.openDomainBase(values)
	if exit != ExitOK {
		return nil, nil, exit
	}
	store, err := appsqlite.New(base.raw)
	if err != nil {
		base.close()
		return nil, nil, r.fail("APP_STORE_UNAVAILABLE", ExitError, "无法构造应用存储", nil)
	}
	authorizer, err := app.NewStaticAuthorizer(app.AuthorizerOptions{
		LocalAdminIDs: []string{operator}})
	if err != nil {
		base.close()
		return nil, nil, r.fail("APP_STORE_UNAVAILABLE", ExitError, "无法构造应用授权器", nil)
	}
	service, err := app.New(app.Options{Store: store, Audit: base.recorder,
		Authorizer: authorizer, Transfers: delegation.GuardFuncs{},
		Now: r.options.Now})
	if err != nil {
		base.close()
		return nil, nil, r.fail("APP_STORE_UNAVAILABLE", ExitError, "无法构造应用服务", nil)
	}
	return base, service, ExitOK
}

// 域命令的公共分页上限。
const (
	domainListDefaultLimit = 20
	domainListMaxLimit     = 100
)

// groupOutput 是用户组的公开投影。
type groupOutput struct {
	ID            string `json:"id"`
	ScopeID       string `json:"scope_id"`
	ScopeKind     string `json:"scope_kind"`
	ApplicationID string `json:"application_id,omitempty"`
	GroupKey      string `json:"group_key"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

func newGroupOutput(item group.Group) groupOutput {
	return groupOutput{ID: item.ID, ScopeID: item.ScopeID, ScopeKind: string(item.ScopeKind),
		ApplicationID: item.ApplicationID, GroupKey: item.GroupKey, Name: item.Name,
		Description: item.Description, CreatedAt: formatTime(item.CreatedAt),
		UpdatedAt: formatTime(item.UpdatedAt)}
}

// roleOutput 是角色的公开投影。
type roleOutput struct {
	ID            string `json:"id"`
	ScopeID       string `json:"scope_id"`
	ScopeKind     string `json:"scope_kind"`
	ApplicationID string `json:"application_id,omitempty"`
	Key           string `json:"key"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Limits        string `json:"limits,omitempty"`
	IsBuiltin     bool   `json:"is_builtin"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

func newRoleOutput(item role.Role) roleOutput {
	return roleOutput{ID: item.ID, ScopeID: item.ScopeID, ScopeKind: string(item.ScopeKind),
		ApplicationID: item.ApplicationID, Key: item.Key, Name: item.Name,
		Description: item.Description, Limits: item.Limits, IsBuiltin: item.IsBuiltin,
		Enabled: item.Enabled, CreatedAt: formatTime(item.CreatedAt),
		UpdatedAt: formatTime(item.UpdatedAt)}
}

// appOutput 是应用的公开投影。
type appOutput struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	ClientType  string `json:"client_type"`
	ScopeID     string `json:"scope_id"`
	RowVersion  int64  `json:"row_version"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

func newAppOutput(item app.Application) appOutput {
	return appOutput{ID: item.ID, Name: item.Name, Description: item.Description,
		Status: string(item.Status), ClientType: string(item.ClientType),
		ScopeID: item.ScopeID, RowVersion: item.RowVersion,
		CreatedAt: formatTime(item.CreatedAt), UpdatedAt: formatTime(item.UpdatedAt)}
}

// runDomain 分派 group/role/app/permission/notify。
func (r *runner) runDomain(groupName string, args []string) int {
	r.usageText = domainCommandUsage
	if len(args) == 0 {
		return r.helpText(groupName, domainCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = groupName + " " + subcommand
	// 组级帮助与在线命令组保持一致：`<组> help|--help|-h` 显示组帮助并退出 0，
	// 不带子命令时同样显示组帮助。
	switch subcommand {
	case "help", "-h", "--help":
		return r.helpText(groupName, domainCommandUsage)
	}
	// 明确拒绝路径在解析具体参数前返回，这里先识别 --json 以便输出机器可读外壳。
	for _, arg := range rest {
		if arg == "--json" {
			r.json = true
		}
	}
	switch groupName {
	case "group":
		return r.runGroup(subcommand, rest)
	case "role":
		return r.runRole(subcommand, rest)
	case "app":
		return r.runApp(subcommand, rest)
	case "permission":
		return r.runPermission(subcommand, rest)
	case "notify":
		return r.runNotify(subcommand, rest)
	default:
		return r.usage("未知命令组 %q", groupName)
	}
}

// domainFlags 返回域命令的公共参数。
func domainFlags(extra ...flagDef) []flagDef {
	definitions := []flagDef{{name: "config", value: true}, {name: "json"},
		{name: "operator", value: true}}
	return append(definitions, extra...)
}

// requireOperator 读取并校验必须的 --operator。
func (r *runner) requireOperator(values map[string]string) (string, int) {
	operator := stringFlag(values, "operator")
	if operator == "" {
		return "", r.usage("必须提供 --operator 本地管理员标识")
	}
	return operator, ExitOK
}

// group list/get/members/create。
func (r *runner) runGroup(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.runGroupList(args)
	case "get":
		return r.runGroupGet(args)
	case "members":
		return r.runGroupMembers(args)
	case "create":
		return r.runGroupCreate(args)
	case "update", "delete", "add-member", "remove-member":
		return r.managementWriteNotExposed("用户组", subcommand,
			"组资料/成员变更需要委派转授与敏感策略装配，CLI 不提供放宽替身")
	default:
		return r.usage("未知的 group 子命令 %q（可用：list/get/members/create）", subcommand)
	}
}

func (r *runner) runGroupList(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "scope", value: true}, flagDef{name: "limit", value: true},
		flagDef{name: "offset", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("group list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	limit, err := parseLimit(values, domainListDefaultLimit, domainListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	scope := stringFlag(values, "scope")
	if scope == "" {
		scope = "system"
	}
	base, service, exit := r.openGroupService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := group.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	result, err := service.ListGroups(r.ctx, caller, group.ListRequest{ScopeID: scope,
		Limit: limit, Offset: offset})
	if err != nil {
		return r.domainFailure("列出用户组", group.CodeOf(err), err)
	}
	items := make([]groupOutput, 0, len(result.Groups))
	for _, item := range result.Groups {
		items = append(items, newGroupOutput(item))
	}
	output := map[string]any{"scope_id": scope, "groups": items,
		"has_more": result.HasMore, "limit": limit, "offset": offset}
	if r.json {
		return r.succeed(output)
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "没有匹配的用户组。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  %s  scope=%s\n", item.ID, item.GroupKey,
			item.Name, item.ScopeID)
	}
	if result.HasMore {
		fmt.Fprintln(r.stdout, "（还有更多结果，请使用 --offset）")
	}
	return ExitOK
}

func (r *runner) runGroupGet(args []string) int {
	values, positional, err := parseFlags(args, domainFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl group get <group_id> --operator <id> [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	base, service, exit := r.openGroupService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := group.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	item, err := service.GetGroup(r.ctx, caller, strings.TrimSpace(positional[0]))
	if err != nil {
		return r.domainFailure("读取用户组", group.CodeOf(err), err)
	}
	output := newGroupOutput(item)
	return r.succeedWithText(output, "用户组：%s\n机器键：%s\n名称：%s\n范围：%s（%s）\n",
		output.ID, output.GroupKey, output.Name, output.ScopeID, output.ScopeKind)
}

func (r *runner) runGroupMembers(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl group members <group_id> --operator <id> [--limit N] [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	limit, err := parseLimit(values, domainListDefaultLimit, domainListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	base, service, exit := r.openGroupService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := group.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	result, err := service.ListMembers(r.ctx, caller, group.MemberListRequest{
		GroupID: strings.TrimSpace(positional[0]), Limit: limit, Offset: offset})
	if err != nil {
		return r.domainFailure("读取组成员", group.CodeOf(err), err)
	}
	members := make([]map[string]any, 0, len(result.Members))
	for _, item := range result.Members {
		members = append(members, map[string]any{"group_id": item.GroupID,
			"user_id": item.UserID, "created_at": formatTime(item.CreatedAt)})
	}
	output := map[string]any{"members": members, "has_more": result.HasMore}
	if r.json {
		return r.succeed(output)
	}
	if len(members) == 0 {
		fmt.Fprintln(r.stdout, "没有组成员。")
		return ExitOK
	}
	for _, item := range members {
		fmt.Fprintf(r.stdout, "%v  %v\n", item["user_id"], item["created_at"])
	}
	return ExitOK
}

func (r *runner) runGroupCreate(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "scope", value: true}, flagDef{name: "key", value: true},
		flagDef{name: "name", value: true}, flagDef{name: "description", value: true},
		flagDef{name: "confirm", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("group create 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	if stringFlag(values, "confirm") != "CREATE" {
		return r.usage("创建用户组必须显式确认：--confirm CREATE")
	}
	scope := stringFlag(values, "scope")
	key := stringFlag(values, "key")
	name := stringFlag(values, "name")
	if scope == "" || key == "" || name == "" {
		return r.usage("--scope、--key、--name 必填")
	}
	base, service, exit := r.openGroupService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := group.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	created, err := service.CreateGroup(r.ctx, caller, group.CreateRequest{
		ScopeID: scope, GroupKey: key, Name: name,
		Description: stringFlag(values, "description")})
	if err != nil {
		return r.domainFailure("创建用户组", group.CodeOf(err), err)
	}
	output := newGroupOutput(created)
	return r.succeedWithText(output, "已创建用户组 %s（%s，范围 %s）。\n",
		output.ID, output.GroupKey, output.ScopeID)
}

// role list/get/permissions。
func (r *runner) runRole(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.runRoleList(args)
	case "get":
		return r.runRoleGet(args)
	case "permissions":
		return r.runRolePermissions(args)
	case "create", "update", "enable", "disable", "assign", "revoke", "delete":
		return r.managementWriteNotExposed("角色", subcommand,
			"角色变更/分配需要委派转授检查与敏感策略装配，CLI 不提供放宽替身")
	default:
		return r.usage("未知的 role 子命令 %q（可用：list/get/permissions）", subcommand)
	}
}

func (r *runner) runRoleList(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "scope", value: true}, flagDef{name: "limit", value: true},
		flagDef{name: "offset", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("role list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	limit, err := parseLimit(values, domainListDefaultLimit, domainListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	scope := stringFlag(values, "scope")
	if scope == "" {
		scope = "system"
	}
	base, service, exit := r.openRoleService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := role.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	result, err := service.ListRoles(r.ctx, caller, role.ListRequest{ScopeID: scope,
		Limit: limit, Offset: offset})
	if err != nil {
		return r.domainFailure("列出角色", role.CodeOf(err), err)
	}
	items := make([]roleOutput, 0, len(result.Roles))
	for _, item := range result.Roles {
		items = append(items, newRoleOutput(item))
	}
	output := map[string]any{"scope_id": scope, "roles": items,
		"has_more": result.HasMore, "limit": limit, "offset": offset}
	if r.json {
		return r.succeed(output)
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "没有匹配的角色。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  %s  enabled=%t  scope=%s\n", item.ID, item.Key,
			item.Name, item.Enabled, item.ScopeID)
	}
	return ExitOK
}

func (r *runner) runRoleGet(args []string) int {
	values, positional, err := parseFlags(args, domainFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl role get <role_id> --operator <id> [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	base, service, exit := r.openRoleService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := role.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	item, err := service.GetRole(r.ctx, caller, strings.TrimSpace(positional[0]))
	if err != nil {
		return r.domainFailure("读取角色", role.CodeOf(err), err)
	}
	output := newRoleOutput(item)
	return r.succeedWithText(output, "角色：%s\n标识：%s\n名称：%s\n启用：%t\n范围：%s\n",
		output.ID, output.Key, output.Name, output.Enabled, output.ScopeID)
}

func (r *runner) runRolePermissions(args []string) int {
	values, positional, err := parseFlags(args, domainFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl role permissions <role_id> --operator <id> [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	base, service, exit := r.openRoleService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := role.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	permissions, err := service.ListRolePermissions(r.ctx, caller,
		strings.TrimSpace(positional[0]))
	if err != nil {
		return r.domainFailure("读取角色权限", role.CodeOf(err), err)
	}
	items := make([]map[string]any, 0, len(permissions))
	for _, item := range permissions {
		items = append(items, map[string]any{"permission_id": item.PermissionID,
			"key": item.Key, "name": item.Name, "scope_id": item.ScopeID,
			"enabled": item.Enabled, "root_only": item.RootOnly})
	}
	if r.json {
		return r.succeed(map[string]any{"permissions": items})
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "该角色未组合任何权限。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%v  %v  enabled=%v root_only=%v\n", item["key"],
			item["name"], item["enabled"], item["root_only"])
	}
	return ExitOK
}

// app list/get/members。
func (r *runner) runApp(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.runAppList(args)
	case "get":
		return r.runAppGet(args)
	case "members":
		return r.runAppMembers(args)
	case "create", "update", "enable", "disable", "add-member", "remove-member",
		"credentials":
		return r.managementWriteNotExposed("应用", subcommand,
			"应用变更/成员/凭证需要委派转授、敏感策略与 OAuth 凭证装配，CLI 不提供放宽替身")
	default:
		return r.usage("未知的 app 子命令 %q（可用：list/get/members）", subcommand)
	}
}

func (r *runner) runAppList(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "status", value: true}, flagDef{name: "limit", value: true},
		flagDef{name: "offset", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("app list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	limit, err := parseLimit(values, domainListDefaultLimit, domainListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	status := app.Status(stringFlag(values, "status"))
	if status != "" && !status.Valid() {
		return r.usage("--status 不是已定义的应用状态")
	}
	base, service, exit := r.openAppService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := app.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	result, err := service.ListApplications(r.ctx, caller, app.ListRequest{
		Limit: limit, Offset: offset, Status: status})
	if err != nil {
		return r.domainFailure("列出应用", app.CodeOf(err), err)
	}
	items := make([]appOutput, 0, len(result.Applications))
	for _, item := range result.Applications {
		items = append(items, newAppOutput(item))
	}
	output := map[string]any{"applications": items, "has_more": result.HasMore,
		"limit": limit, "offset": offset}
	if r.json {
		return r.succeed(output)
	}
	if len(items) == 0 {
		fmt.Fprintln(r.stdout, "没有匹配的应用。")
		return ExitOK
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  %s  client_type=%s\n", item.ID, item.Name,
			item.Status, item.ClientType)
	}
	return ExitOK
}

func (r *runner) runAppGet(args []string) int {
	values, positional, err := parseFlags(args, domainFlags())
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl app get <application_id> --operator <id> [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	base, service, exit := r.openAppService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := app.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	item, err := service.GetApplication(r.ctx, caller, strings.TrimSpace(positional[0]))
	if err != nil {
		return r.domainFailure("读取应用", app.CodeOf(err), err)
	}
	output := newAppOutput(item)
	return r.succeedWithText(output, "应用：%s\n名称：%s\n状态：%s\n客户端类型：%s\n",
		output.ID, output.Name, output.Status, output.ClientType)
}

func (r *runner) runAppMembers(args []string) int {
	values, positional, err := parseFlags(args, domainFlags(
		flagDef{name: "limit", value: true}, flagDef{name: "offset", value: true}))
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 1 {
		return r.usage("用法：loginctl app members <application_id> --operator <id> " +
			"[--limit N] [--json]")
	}
	r.json = boolFlag(values, "json")
	operator, exit := r.requireOperator(values)
	if exit != ExitOK {
		return exit
	}
	limit, err := parseLimit(values, domainListDefaultLimit, domainListMaxLimit)
	if err != nil {
		return r.usage("%v", err)
	}
	offset, err := parseIntFlag(values, "offset", 0)
	if err != nil || offset < 0 || offset > 1_000_000 {
		return r.usage("--offset 必须在 0～1000000 之间")
	}
	base, service, exit := r.openAppService(values, operator)
	if exit != ExitOK {
		return exit
	}
	defer base.close()
	caller, err := app.LocalBootstrapCaller(operator)
	if err != nil {
		return r.usage("--operator 本地管理员标识无效")
	}
	result, err := service.ListApplicationMembers(r.ctx, caller, app.MemberListRequest{
		ApplicationID: strings.TrimSpace(positional[0]), Limit: limit, Offset: offset})
	if err != nil {
		return r.domainFailure("读取应用成员", app.CodeOf(err), err)
	}
	members := make([]map[string]any, 0, len(result.Members))
	for _, item := range result.Members {
		members = append(members, map[string]any{"application_id": item.ApplicationID,
			"user_id": item.UserID, "status": string(item.Status),
			"row_version": item.RowVersion, "created_at": formatTime(item.CreatedAt)})
	}
	if r.json {
		return r.succeed(map[string]any{"members": members, "has_more": result.HasMore})
	}
	if len(members) == 0 {
		fmt.Fprintln(r.stdout, "没有应用成员。")
		return ExitOK
	}
	for _, item := range members {
		fmt.Fprintf(r.stdout, "%v  %v  row_version=%v\n", item["user_id"], item["status"],
			item["row_version"])
	}
	return ExitOK
}

// permission list：只读预设权限目录（不访问数据库）。
func (r *runner) runPermission(subcommand string, args []string) int {
	if subcommand != "list" {
		if subcommand == "create" || subcommand == "update" || subcommand == "enable" ||
			subcommand == "disable" || subcommand == "delete" {
			return r.managementWriteNotExposed("权限", subcommand,
				"权限目录变更需要委派转授与敏感策略装配，CLI 不提供放宽替身")
		}
		return r.usage("未知的 permission 子命令 %q（可用：list）", subcommand)
	}
	values, positional, err := parseFlags(args, []flagDef{{name: "json"}})
	if err != nil {
		return r.flagError(err)
	}
	if len(positional) != 0 {
		return r.usage("permission list 不接受位置参数")
	}
	r.json = boolFlag(values, "json")
	catalog := preset.DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		return r.fail("INTERNAL_ERROR", ExitError, "内置权限目录无效", nil)
	}
	type permissionOutput struct {
		Key            string `json:"key"`
		Name           string `json:"name,omitempty"`
		RootOnly       bool   `json:"root_only"`
		RequiresReauth bool   `json:"requires_reauth"`
		Implemented    bool   `json:"implemented"`
	}
	items := make([]permissionOutput, 0, len(catalog.Permissions))
	for _, item := range catalog.Permissions {
		items = append(items, permissionOutput{Key: item.Key, Name: item.Name,
			RootOnly: item.RootOnly, RequiresReauth: item.RequiresReauth,
			Implemented: item.Implemented})
	}
	if r.json {
		return r.succeed(map[string]any{"permissions": items, "count": len(items)})
	}
	for _, item := range items {
		fmt.Fprintf(r.stdout, "%s  %s  root_only=%t reauth=%t implemented=%t\n",
			item.Key, item.Name, item.RootOnly, item.RequiresReauth, item.Implemented)
	}
	return ExitOK
}

// notify status/test：通知与邮件配置状态（不真实外发）。
func (r *runner) runNotify(subcommand string, args []string) int {
	switch subcommand {
	case "status":
		values, positional, err := parseFlags(args, []flagDef{
			{name: "config", value: true}, {name: "json"}})
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 0 {
			return r.usage("notify status 不接受位置参数")
		}
		r.json = boolFlag(values, "json")
		config, exit := r.loadEffectiveConfig(values)
		if exit != ExitOK {
			return exit
		}
		_ = config
		output := map[string]any{
			"status": "unavailable",
			"code":   "NOTIFICATION_UNAVAILABLE",
			"detail": "根配置没有 SMTP/mailer 配置项，宿主装配 mailer 前无法投递；" +
				"CLI 不发送真实邮件",
			"test_send_allowed": false,
		}
		if r.json {
			r.writeEnvelope(jsonEnvelope{OK: false, Command: r.command,
				Data: output, Error: &jsonError{Code: "NOTIFICATION_UNAVAILABLE",
					Message: "通知通道未装配，不能投递"}})
			return ExitError
		}
		fmt.Fprintln(r.stdout, "通知通道：不可用（宿主未装配 mailer/SMTP 配置；CLI 不发送真实邮件）。")
		return ExitError
	case "test":
		values, positional, err := parseFlags(args, []flagDef{
			{name: "config", value: true}, {name: "json"}, {name: "to", value: true}})
		if err != nil {
			return r.flagError(err)
		}
		if len(positional) != 0 {
			return r.usage("notify test 不接受位置参数")
		}
		r.json = boolFlag(values, "json")
		return r.fail("NOTIFICATION_TEST_DISABLED", ExitForbidden,
			"禁止真实外发测试通知；请由宿主装配受控本地捕获器后验证", nil)
	case "help", "-h", "--help":
		return r.helpText("notify", domainCommandUsage)
	default:
		return r.usage("未知的 notify 子命令 %q（可用：status/test）", subcommand)
	}
}

// domainFailure 把领域服务错误映射为稳定错误码与退出码。
func (r *runner) domainFailure(operation string, code any, err error) int {
	codeText := fmt.Sprint(code)
	exitCode := ExitError
	switch codeText {
	case "ACCESS_DENIED":
		exitCode = ExitForbidden
	case "CONFLICT":
		exitCode = ExitConflict
	case "REQ_INVALID":
		exitCode = ExitUsage
	}
	return r.fail(codeText, exitCode, operation+"失败："+err.Error(), nil)
}
