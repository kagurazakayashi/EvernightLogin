package serverapp

// 生产授权适配层：把页面/领域服务的管理动作接到真实 internal/authz 权限判定。
//
// 安全不变量：
//   - 默认拒绝：无法确定调用者身份、权限键未知、权限引擎错误、作用范围非法时一律拒绝。
//   - root 由 bootstrap 初始化记录显式识别（唯一 root），不走普通权限引擎（authz 引擎
//     明确对 root 返回 ErrRootProtected）；root 仍必须通过管理会话强认证门禁才能到达
//     这里。
//   - 普通用户必须通过 authz.Service.Check 在目标作用范围内持有对应权限键；查不到
//     角色/权限数据一律拒绝，不缓存、不从前端自报身份推导。
//   - 委派转授检查（delegation.Guard）本阶段只允许受信系统/本地管理员与 root；普通
//     管理员的细粒度转授策略（可转授清单、自我提权、目标白名单）尚未装配，明确拒绝而
//     不是放行（见报告缺口）。
//   - 查询授权器只允许系统/本地管理员或用户查询自己；管理员查询他人有效权限需要的
//     应用管理员数据范围策略尚待装配，缺失时 fail-closed。

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// errAuthorizerNotConfigured 表示授权适配层缺少真实权限引擎；任何判定都拒绝。
var errAuthorizerNotConfigured = errors.New("授权适配层未装配权限引擎，拒绝执行")

// hostRootChecker 通过 bootstrap 初始化记录识别唯一 root。
type hostRootChecker struct {
	store *bootstrapsqlite.Store
}

// newHostRootChecker 构造 root 识别器；存储为空时返回错误（不允许“无 root”语义）。
func newHostRootChecker(store *bootstrapsqlite.Store) (*hostRootChecker, error) {
	if store == nil {
		return nil, fmt.Errorf("root 识别器缺少首次初始化存储")
	}
	return &hostRootChecker{store: store}, nil
}

// isRoot 报告给定用户 ID 是否为当前初始化记录中的唯一 root。
func (r *hostRootChecker) isRoot(ctx context.Context, userID string) (bool, error) {
	if r == nil || r.store == nil {
		return false, errAuthorizerNotConfigured
	}
	if !account.ValidUserID(userID) {
		return false, fmt.Errorf("用户 ID 格式无效")
	}
	record, found, err := r.store.GetRootAccount(ctx)
	if err != nil {
		return false, fmt.Errorf("读取 root 初始化记录失败: %w", err)
	}
	if !found || record.UserID != userID {
		return false, nil
	}
	if record.Status != account.StatusActive {
		return false, fmt.Errorf("root 账户状态不是 active")
	}
	return true, nil
}

// isRootCaller 检查 caller.Actor() 是否 root 或受信系统/本地主体。
func (r *hostRootChecker) trustedActor(ctx context.Context, actor audit.Actor) (bool, error) {
	switch actor.Type {
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return true, nil
	case audit.ActorUser:
		return r.isRoot(ctx, actor.ID)
	default:
		return false, fmt.Errorf("匿名主体不允许管理操作")
	}
}

// hostSensitiveRunner 是敏感操作执行器的 fail-closed 实现：当前阶段 reauth/policy
// 链路由后续装配接管；未装配时导出/清理/凭证轮换等敏感动作一律拒绝并返回明确错误。
// 它与 tasks.go 中的同名实现共享语义（邮件/Webhook 使用同一策略）。
var _ = failClosedSensitiveRunner{}

// permissionChecker 是权限判定的公共实现。
type permissionChecker struct {
	access  *authz.Service
	roots   *hostRootChecker
	enabled bool
}

// newPermissionChecker 构造权限判定器；缺少权限引擎时 enabled=false，所有判定拒绝。
func newPermissionChecker(access *authz.Service, roots *hostRootChecker) *permissionChecker {
	return &permissionChecker{access: access, roots: roots,
		enabled: access != nil && roots != nil}
}

// check 判定 userID 是否在 scopeID 内持有 permissionKey。
func (p *permissionChecker) check(ctx context.Context, userID, permissionKey, scopeID string) error {
	if p == nil || !p.enabled {
		return errAuthorizerNotConfigured
	}
	if !account.ValidUserID(userID) {
		return fmt.Errorf("用户 ID 格式无效")
	}
	key := strings.TrimSpace(permissionKey)
	if key == "" {
		return fmt.Errorf("缺少权限键")
	}
	root, err := p.roots.isRoot(ctx, userID)
	if err != nil {
		return err
	}
	if root {
		return nil
	}
	scope, err := normalizeAuthzScope(scopeID)
	if err != nil {
		return err
	}
	caller, err := authz.UserCaller(userID)
	if err != nil {
		return fmt.Errorf("构造授权调用者失败: %w", err)
	}
	result, err := p.access.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: userID, ScopeID: scope, Permissions: []string{key},
		Mode: authz.ModeAll,
	})
	if err != nil {
		return fmt.Errorf("权限判定失败: %w", err)
	}
	if !result.Allowed {
		return fmt.Errorf("缺少权限 %s（范围 %s）", key, scope)
	}
	return nil
}

// evaluate 返回“是否允许”而不把权限不足当作依赖错误；依赖失败仍返回 error。
// 供 auditops/stats 等 ScopeGrant 风格授权器区分“明确拒绝”和“无法判定”。
func (p *permissionChecker) evaluate(ctx context.Context,
	userID, permissionKey, scopeID string) (bool, error) {
	if p == nil || !p.enabled {
		return false, errAuthorizerNotConfigured
	}
	if !account.ValidUserID(userID) {
		return false, fmt.Errorf("用户 ID 格式无效")
	}
	key := strings.TrimSpace(permissionKey)
	if key == "" {
		return false, fmt.Errorf("缺少权限键")
	}
	root, err := p.roots.isRoot(ctx, userID)
	if err != nil {
		return false, err
	}
	if root {
		return true, nil
	}
	scope, err := normalizeAuthzScope(scopeID)
	if err != nil {
		return false, err
	}
	caller, err := authz.UserCaller(userID)
	if err != nil {
		return false, fmt.Errorf("构造授权调用者失败: %w", err)
	}
	result, err := p.access.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: userID, ScopeID: scope, Permissions: []string{key},
		Mode: authz.ModeAll,
	})
	if err != nil {
		return false, fmt.Errorf("权限判定失败: %w", err)
	}
	return result.Allowed, nil
}

// manageableScopes 返回可管理范围；root/受信主体返回 all=true，普通用户只返回
// 其在 system 范围确有的读取权限，其他应用范围无法枚举时 fail-closed 拒绝。
func (p *permissionChecker) manageableScopes(ctx context.Context,
	actor audit.Actor, readPermission string) (bool, []string, error) {
	if p == nil || !p.enabled {
		return false, nil, errAuthorizerNotConfigured
	}
	trusted, err := p.roots.trustedActor(ctx, actor)
	if err != nil {
		return false, nil, err
	}
	if trusted {
		return true, nil, nil
	}
	if err := p.check(ctx, actor.ID, readPermission, "system"); err != nil {
		return false, nil, err
	}
	return false, []string{"system"}, nil
}

// normalizeAuthzScope 规范化作用范围：空值表示系统范围。
func normalizeAuthzScope(scopeID string) (string, error) {
	trimmed := strings.TrimSpace(scopeID)
	if trimmed == "" {
		return "system", nil
	}
	if _, err := authz.ParseScope(trimmed); err != nil {
		return "", err
	}
	return trimmed, nil
}

// selfQueryAuthorizer 实现 authz.Authorizer：系统/本地管理员可查询任意主体；普通
// 用户只能查询自己。管理员查询他人有效权限需要的应用管理员/数据范围策略尚未装配，
// 此时明确拒绝（fail-closed），不猜测范围。
type selfQueryAuthorizer struct{}

// AuthorizeQuery 实现 authz.Authorizer。
func (selfQueryAuthorizer) AuthorizeQuery(_ context.Context, caller authz.Caller,
	subjectUserID string, _ authz.Scope) error {
	actor := caller.Actor()
	switch actor.Type {
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	case audit.ActorUser:
		if subjectUserID == actor.ID {
			return nil
		}
		return fmt.Errorf("普通管理员查询他人有效权限的数据范围策略未装配：拒绝")
	default:
		return fmt.Errorf("匿名主体不允许查询权限")
	}
}

// pageActionPermissions 把页面适配器的管理动作名映射到 preset 权限目录键。
//
// 页面适配器已在代码注释中约定动作名；未登记的动作一律拒绝，避免拼写错误导致
// “看起来检查了”实际放行的安全漏洞。
var pageActionPermissions = map[string]string{
	"users.read":             "users.read",
	"users.create":           "users.create",
	"users.update":           "users.update",
	"users.delete":           "users.delete",
	"users.review":           "users.update",
	"users.import":           "users.create",
	"users.export":           "users.export",
	"groups.read":            "groups.read",
	"groups.update":          "groups.manage",
	"roles.read":             "roles.read",
	"roles.manage":           "roles.manage",
	"roles.assign":           "roles.assign",
	"permissions.read":       "permissions.read",
	"permissions.manage":     "permissions.manage",
	"applications.read":      "applications.read",
	"applications.create":    "applications.create",
	"applications.update":    "applications.update",
	"applications.members":   "applications.members.manage",
	"applications.secret":    "applications.credentials.manage",
	"support.read":           "support.cases.read",
	"support.update":         "support.cases.update",
	"recovery.approve":       "recovery.approve",
	"audit.read":             "audit.read",
	"audit.export":           "audit.export",
	"audit.purge":            "audit.purge",
	"stats.read":             "reports.read",
	"reports.read":           "reports.read",
	"reports.manage":         "reports.schedule.manage",
	"backups.read":           "backups.read",
	"backups.manage":         "backups.create",
	"security.policy":        "security.policy.manage",
	"security.policy.manage": "security.policy.manage",
}

// authorizePageAction 是 uiadminadapter 各页面 Options.Authorize 的实现。
func (p *permissionChecker) authorizePageAction(ctx context.Context,
	adminUserID, action string) error {
	key, ok := pageActionPermissions[strings.TrimSpace(action)]
	if !ok {
		return fmt.Errorf("未登记的页面管理动作 %q：拒绝", action)
	}
	return p.check(ctx, adminUserID, key, "system")
}

// pageManageableScopes 是 RBAC 页面适配器的范围展示钩子：root/受信主体可管理
// 全部范围（当前只有 system 域装配），普通用户返回其真实可读的系统范围；失败即
// 拒绝，不展示未授权应用范围。
func (p *permissionChecker) pageManageableScopes(ctx context.Context,
	adminUserID string) ([]string, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: adminUserID}
	all, scopes, err := p.manageableScopes(ctx, actor, "roles.read")
	if err != nil {
		return nil, err
	}
	if all {
		return []string{"system"}, nil
	}
	return scopes, nil
}

// authorizePageActionScoped 与 authorizePageAction 相同，但按应用范围判定；
// 供应用管理页的页面层管理动作复核使用。
func (p *permissionChecker) authorizePageActionScoped(ctx context.Context,
	adminUserID, action, scopeID string) error {
	key, ok := pageActionPermissions[strings.TrimSpace(action)]
	if !ok {
		return fmt.Errorf("未登记的页面管理动作 %q：拒绝", action)
	}
	return p.check(ctx, adminUserID, key, scopeID)
}

// oauthclientAuthorizer 实现 oauthclient.Authorizer。
type oauthclientAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeClient 实现 oauthclient.Authorizer。
func (a oauthclientAuthorizer) AuthorizeClient(ctx context.Context, caller oauthclient.Caller,
	applicationID string, action oauthclient.Action) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key := ""
	switch action {
	case oauthclient.ActionRead:
		key = "applications.read"
	case oauthclient.ActionUpdateSettings:
		key = "applications.update"
	case oauthclient.ActionManageCredentials:
		key = "applications.credentials.manage"
	default:
		return fmt.Errorf("未登记的客户端动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, applicationID)
}

// accountAuthorizer 实现 account.Authorizer。
type accountAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 account.Authorizer。
func (a accountAuthorizer) Authorize(ctx context.Context, caller account.Caller,
	action account.Action) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key, ok := accountActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的账户动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, "system")
}

// accountActionPermission 把账户服务动作映射到权限键。
func accountActionPermission(action account.Action) (string, bool) {
	switch action {
	case account.ActionCreateUser:
		return "users.create", true
	case account.ActionGetUser, account.ActionListUsers:
		return "users.read", true
	case account.ActionDisableUser, account.ActionEnableUser:
		return "users.disable", true
	case account.ActionRequestDeletion, account.ActionPreviewDeletion,
		account.ActionCompleteDeletion:
		return "users.delete", true
	default:
		return "", false
	}
}

// profileAuthorizer 实现 profile.Authorizer。root 账户资料只允许本人或 root 读写；
// 其他用户按资料读写权限判定。
type profileAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeProfile 实现 profile.Authorizer。
func (a profileAuthorizer) AuthorizeProfile(ctx context.Context,
	caller profile.Caller, target profile.UserProfile, write bool) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	if actor.Type == audit.ActorUser && target.IsRoot {
		// root 资料禁止普通管理员读写，避免通过资料接口探测/篡改 root。
		return fmt.Errorf("root 账户资料不允许普通管理操作")
	}
	key := "users.read"
	if write {
		key = "users.update"
	}
	// 本人维护资料走 self.* 权限；管理员代改走 users.* 权限。
	if actor.Type == audit.ActorUser && target.UserID == actor.ID {
		key = "self.profile.read"
		if write {
			key = "self.profile.update"
		}
	}
	return a.checker.check(ctx, actor.ID, key, "system")
}

// roleAuthorizer 实现 role.Authorizer。
type roleAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 role.Authorizer。
func (a roleAuthorizer) Authorize(ctx context.Context, caller role.Caller,
	action role.Action, scopeID string) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key, ok := roleActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的角色动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, scopeID)
}

// ManageableScopes 实现 role.Authorizer。
func (a roleAuthorizer) ManageableScopes(ctx context.Context,
	caller role.Caller) (bool, []string, error) {
	return a.checker.manageableScopes(ctx, caller.Actor(), "roles.read")
}

// roleActionPermission 把角色服务动作映射到权限键。
func roleActionPermission(action role.Action) (string, bool) {
	switch action {
	case role.ActionGetRole, role.ActionListRoles, role.ActionListRolePermissions,
		role.ActionListRoleAssignments:
		return "roles.read", true
	case role.ActionCreateRole, role.ActionUpdateRole, role.ActionDeleteRole,
		role.ActionEnableRole, role.ActionDisableRole, role.ActionAddRolePermission,
		role.ActionRemoveRolePermission:
		return "roles.manage", true
	case role.ActionAssignUserRole, role.ActionRevokeUserRole,
		role.ActionAssignGroupRole, role.ActionRevokeGroupRole:
		return "roles.assign", true
	default:
		return "", false
	}
}

// permissionAuthorizer 实现 permission.Authorizer。
type permissionAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 permission.Authorizer。
func (a permissionAuthorizer) Authorize(ctx context.Context, caller permission.Caller,
	action permission.Action, scopeID string) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key, ok := permissionActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的权限目录动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, scopeID)
}

// ManageableScopes 实现 permission.Authorizer。
func (a permissionAuthorizer) ManageableScopes(ctx context.Context,
	caller permission.Caller) (bool, []string, error) {
	return a.checker.manageableScopes(ctx, caller.Actor(), "permissions.read")
}

// permissionActionPermission 把权限目录服务动作映射到权限键。
func permissionActionPermission(action permission.Action) (string, bool) {
	switch action {
	case permission.ActionGetPermission, permission.ActionListPermissions:
		return "permissions.read", true
	case permission.ActionCreatePermission, permission.ActionUpdatePermission,
		permission.ActionDeletePermission:
		return "permissions.manage", true
	case permission.ActionEnablePermission, permission.ActionDisablePermission:
		return "permissions.state.update", true
	default:
		return "", false
	}
}

// groupAuthorizer 实现 group.Authorizer。
type groupAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 group.Authorizer。
func (a groupAuthorizer) Authorize(ctx context.Context, caller group.Caller,
	action group.Action, scopeID string) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key, ok := groupActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的用户组动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, scopeID)
}

// ManageableScopes 实现 group.Authorizer。
func (a groupAuthorizer) ManageableScopes(ctx context.Context,
	caller group.Caller) (bool, []string, error) {
	return a.checker.manageableScopes(ctx, caller.Actor(), "groups.read")
}

// groupActionPermission 把用户组服务动作映射到权限键。
func groupActionPermission(action group.Action) (string, bool) {
	switch action {
	case group.ActionGetGroup, group.ActionListGroups, group.ActionListMembers:
		return "groups.read", true
	case group.ActionCreateGroup, group.ActionUpdateGroup, group.ActionDeleteGroup,
		group.ActionAddMembers, group.ActionRemoveMembers:
		return "groups.manage", true
	default:
		return "", false
	}
}

// appAuthorizer 实现 app.Authorizer（当前仅用于未来应用页装配；保留真实判定）。
type appAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 app.Authorizer。
func (a appAuthorizer) Authorize(ctx context.Context, caller app.Caller,
	action app.Action, applicationID string) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key, ok := appActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的应用动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, applicationID)
}

// ApplicationScope 实现 app.Authorizer：root/受信主体可管理全部应用；普通用户需要
// 逐应用授权，应用列表无法安全枚举时 fail-closed 返回错误。
func (a appAuthorizer) ApplicationScope(ctx context.Context,
	caller app.Caller) (bool, []string, error) {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return false, nil, err
	}
	if trusted {
		return true, nil, nil
	}
	return false, nil, fmt.Errorf("普通用户的应用管理范围策略未装配：拒绝")
}

// appActionPermission 把应用服务动作映射到权限键。
func appActionPermission(action app.Action) (string, bool) {
	switch action {
	case app.ActionGetApplication, app.ActionListApplications:
		return "applications.read", true
	case app.ActionCreateApplication:
		return "applications.create", true
	case app.ActionUpdateApplication, app.ActionEnableApplication,
		app.ActionDisableApplication:
		return "applications.update", true
	case app.ActionAddApplicationMember, app.ActionGetApplicationMember,
		app.ActionListApplicationMembers, app.ActionUpdateApplicationMemberProfile,
		app.ActionEnableApplicationMember, app.ActionDisableApplicationMember,
		app.ActionRemoveApplicationMember:
		return "applications.members.manage", true
	default:
		return "", false
	}
}

// onboardingManagementAuthorizer 实现 onboarding.ManagementAuthorizer：注册审核
// 要求管理访问权限（users.update）。非管理员拒绝。
type onboardingManagementAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeManagement 实现 onboarding.ManagementAuthorizer。
func (a onboardingManagementAuthorizer) AuthorizeManagement(ctx context.Context,
	caller onboarding.Caller) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	if actor.Type != audit.ActorUser {
		return fmt.Errorf("注册审核只允许受信管理主体")
	}
	return a.checker.check(ctx, actor.ID, "users.update", "system")
}

// rootOnlyDelegationGuard 是 delegation.Guard 的本阶段实现：受信系统/本地管理员与
// root 允许；普通管理员的细粒度转授策略（可转授清单、自我提权、目标白名单）尚未
// 装配，一律拒绝并返回明确错误。绝不使用全放行替身。
type rootOnlyDelegationGuard struct {
	roots *hostRootChecker
}

// allow 判定 actor 是否允许执行转授类操作。
func (g rootOnlyDelegationGuard) allow(ctx context.Context, actor audit.Actor) error {
	if g.roots == nil {
		return errAuthorizerNotConfigured
	}
	allowed, err := g.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if allowed {
		return nil
	}
	return fmt.Errorf("普通管理员的转授权限策略未装配：拒绝转授/提权操作")
}

// CheckPermissionAccess 实现 delegation.Guard。
func (g rootOnlyDelegationGuard) CheckPermissionAccess(ctx context.Context,
	_ audit.Tx, actor audit.Actor, _ string, _ []delegation.PermissionRef,
	_ []delegation.Target) error {
	return g.allow(ctx, actor)
}

// CheckAssignment 实现 delegation.Guard。
func (g rootOnlyDelegationGuard) CheckAssignment(ctx context.Context,
	_ audit.Tx, actor audit.Actor, _ string, _ []delegation.PermissionRef,
	_ delegation.Target) error {
	return g.allow(ctx, actor)
}

// CheckPermissionActivation 实现 delegation.Guard。
func (g rootOnlyDelegationGuard) CheckPermissionActivation(ctx context.Context,
	_ audit.Tx, actor audit.Actor, _ string, _ []delegation.PermissionRef,
	_ []delegation.Target) error {
	return g.allow(ctx, actor)
}

// CheckScopeRestoration 实现 delegation.Guard。
func (g rootOnlyDelegationGuard) CheckScopeRestoration(ctx context.Context,
	_ audit.Tx, actor audit.Actor, _ string) error {
	return g.allow(ctx, actor)
}

// 编译期契约确认。
var (
	_ authz.Authorizer                = selfQueryAuthorizer{}
	_ account.Authorizer              = accountAuthorizer{}
	_ profile.Authorizer              = profileAuthorizer{}
	_ role.Authorizer                 = roleAuthorizer{}
	_ permission.Authorizer           = permissionAuthorizer{}
	_ group.Authorizer                = groupAuthorizer{}
	_ app.Authorizer                  = appAuthorizer{}
	_ oauthclient.Authorizer          = oauthclientAuthorizer{}
	_ onboarding.ManagementAuthorizer = onboardingManagementAuthorizer{}
	_ delegation.Guard                = rootOnlyDelegationGuard{}
	_ bootstrap.RootAccount           = bootstrap.RootAccount{}
)
