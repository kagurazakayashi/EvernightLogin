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
//   - 委派转授检查（delegation.Guard）由 productionDelegationGuard 包装真实
//     delegation.Service：root/受信本地管理员/system 先放行，其余主体必须持有有效
//     Grant 且目标/权限/范围通过引擎检查（禁止自我提权、组间接提权、跨应用与停用后
//     恢复）；包装器绝不对未知主体全放行。
//   - 查询授权器只允许系统/本地管理员或用户查询自己；管理员查询他人有效权限需要的
//     应用管理员数据范围策略尚待装配，缺失时 fail-closed。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
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
	// appScopes 是可选的应用范围候选枚举能力（步骤 184）：只缩小候选范围，
	// 最终权限仍由 access.Check 逐应用判定。为 nil 时应用管理员范围无法枚举，
	// 所有应用范围判定 fail-closed。
	appScopes app.ScopeCandidateLister
}

// newPermissionChecker 构造权限判定器；缺少权限引擎时 enabled=false，所有判定拒绝。
func newPermissionChecker(access *authz.Service, roots *hostRootChecker) *permissionChecker {
	return &permissionChecker{access: access, roots: roots,
		enabled: access != nil && roots != nil}
}

// SetApplicationScopeLister 注入应用范围候选枚举能力（步骤 184）。必须在校验开始
// 前由装配层调用；nil 时保持 fail-closed（不猜测范围）。该能力只列候选应用 ID，
// 不能替代权限引擎判定。
func (p *permissionChecker) SetApplicationScopeLister(lister app.ScopeCandidateLister) {
	if p == nil {
		return
	}
	p.appScopes = lister
}

// Check 实现 session.PermissionChecker：委托真实 authz 引擎；root 在管理强制
// 下线场景按“受保护超级管理员”语义允许检查自身权限（目标 root 保护仍由会话
// 服务在读取目标后拒绝），其余调用一律走真实权限判定，不伪造放行。
func (p *permissionChecker) Check(ctx context.Context, caller authz.Caller,
	request authz.CheckRequest) (authz.CheckResult, error) {
	if p == nil || p.access == nil {
		return authz.CheckResult{Allowed: false}, errAuthorizerNotConfigured
	}
	if caller.Actor().Type == audit.ActorUser {
		if root, err := p.roots.isRoot(ctx, caller.Actor().ID); err == nil && root {
			return authz.CheckResult{SubjectUserID: caller.Actor().ID, Allowed: true}, nil
		}
	}
	return p.access.Check(ctx, caller, request)
}

// EffectivePermissions 实现 session.PermissionChecker：委托真实 authz 引擎。
func (p *permissionChecker) EffectivePermissions(ctx context.Context, caller authz.Caller,
	subjectUserID, scopeID string, options authz.ListOptions) (authz.EffectiveResult, error) {
	if p == nil || p.access == nil {
		return authz.EffectiveResult{}, errAuthorizerNotConfigured
	}
	return p.access.EffectivePermissions(ctx, caller, subjectUserID, scopeID, options)
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

// manageableScopes 返回可管理范围；root/受信主体返回 all=true，普通用户返回其
// 真实持有读取权限的范围（步骤 184：system 或已获应用范围，逐应用由权限引擎判定）。
// 无法枚举应用范围或没有任何可读范围时 fail-closed 拒绝，不返回空列表成功。
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
	// 系统范围读取权限优先（例如系统管理员/系统角色）。
	if err := p.check(ctx, actor.ID, readPermission, "system"); err == nil {
		return false, []string{"system"}, nil
	}
	scopes, err := p.manageableApplicationScopes(ctx, actor.ID, readPermission)
	if err != nil {
		return false, nil, err
	}
	if len(scopes) == 0 {
		return false, nil, fmt.Errorf("没有可读取范围的应用管理权限：拒绝")
	}
	return false, scopes, nil
}

// manageableApplicationScopes 返回用户通过应用范围角色真实持有 permissionKey 的
// 应用 ID 列表（步骤 184）。
//
// 流程：先用应用存储的可选候选枚举缩小范围（只读 user_roles/group_roles + 启用角色），
// 再逐应用调用权限引擎 Check（应用状态、成员关系、权限启用与 root_only 过滤都在引擎
// 内）。任一候选依赖失败即整体失败，绝不把候选列表直接当成已授权。
func (p *permissionChecker) manageableApplicationScopes(ctx context.Context,
	userID, permissionKey string) ([]string, error) {
	if p == nil || !p.enabled {
		return nil, errAuthorizerNotConfigured
	}
	if p.appScopes == nil {
		return nil, fmt.Errorf("应用范围候选枚举未装配：拒绝枚举应用管理范围")
	}
	if !account.ValidUserID(userID) {
		return nil, fmt.Errorf("用户 ID 格式无效")
	}
	key := strings.TrimSpace(permissionKey)
	if key == "" {
		return nil, fmt.Errorf("缺少权限键")
	}
	candidates, err := p.appScopes.ListUserApplicationScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("枚举应用管理候选范围失败: %w", err)
	}
	managed := make([]string, 0, len(candidates))
	for _, applicationID := range candidates {
		if strings.TrimSpace(applicationID) == "" {
			continue
		}
		if checkErr := p.check(ctx, userID, key, applicationID); checkErr == nil {
			managed = append(managed, applicationID)
		}
	}
	sort.Strings(managed)
	return managed, nil
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
	"users.read":           "users.read",
	"users.create":         "users.create",
	"users.update":         "users.update",
	"users.delete":         "users.delete",
	"users.review":         "users.update",
	"users.import":         "users.create",
	"users.export":         "users.export",
	"groups.read":          "groups.read",
	"groups.update":        "groups.manage",
	"roles.read":           "roles.read",
	"roles.manage":         "roles.manage",
	"roles.assign":         "roles.assign",
	"permissions.read":     "permissions.read",
	"permissions.manage":   "permissions.manage",
	"applications.read":    "applications.read",
	"applications.create":  "applications.create",
	"applications.update":  "applications.update",
	"applications.members": "applications.members.manage",
	"applications.secret":  "applications.credentials.manage",
	// 页面适配器直接使用完整权限键名（凭证管理）；与 applications.secret 同义，
	// 保留别名避免不同调用点因拼写差异被误判为“未登记动作”而一律拒绝。
	"applications.credentials.manage": "applications.credentials.manage",
	"support.read":                    "support.cases.read",
	"support.update":                  "support.cases.update",
	"recovery.approve":                "recovery.approve",
	"audit.read":                      "audit.read",
	"audit.export":                    "audit.export",
	"audit.purge":                     "audit.purge",
	"stats.read":                      "reports.read",
	"reports.read":                    "reports.read",
	"reports.manage":                  "reports.schedule.manage",
	"backups.read":                    "backups.read",
	"backups.manage":                  "backups.create",
	"security.policy":                 "security.policy.manage",
	"security.policy.manage":          "security.policy.manage",
}

// appScopablePagePermissions 是允许以“任一应用范围持有”判定的页面动作权限键
// （步骤 184）。这些权限的应用范围由领域服务在目标应用上再次判定；不能让应用
// 管理员以系统范围权限进入。未列出的权限（账户/审计/备份等）仍要求系统范围。
var appScopablePagePermissions = map[string]bool{
	"applications.read":               true,
	"applications.update":             true,
	"applications.members.manage":     true,
	"applications.credentials.manage": true,
	"roles.read":                      true,
	"roles.manage":                    true,
	"roles.assign":                    true,
	"permissions.read":                true,
	"permissions.manage":              true,
	"groups.read":                     true,
	"groups.manage":                   true,
}

// authorizePageAction 是 uiadminadapter 各页面 Options.Authorize 的实现。
//
// 判定顺序（默认拒绝）：root/受信主体 → 系统范围权限 → （仅限应用可作用域权限）
// 任一应用范围持有该权限。列表类读取随后仍由领域服务按 ApplicationScope 过滤；
// 应用写入仍由领域服务以目标应用范围重新判定；“任一应用持有”不等于可写未授权应用。
func (p *permissionChecker) authorizePageAction(ctx context.Context,
	adminUserID, action string) error {
	key, ok := pageActionPermissions[strings.TrimSpace(action)]
	if !ok {
		return fmt.Errorf("未登记的页面管理动作 %q：拒绝", action)
	}
	if err := p.check(ctx, adminUserID, key, "system"); err == nil {
		return nil
	}
	if !appScopablePagePermissions[key] {
		return fmt.Errorf("缺少系统范围权限 %s：拒绝", key)
	}
	scopes, err := p.manageableApplicationScopes(ctx, adminUserID, key)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		return fmt.Errorf("缺少权限 %s（系统或应用范围）：拒绝", key)
	}
	return nil
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

// appAuthorizer 实现 app.Authorizer（步骤 184 接入真实应用范围判定）。
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
	// 列表动作不针对单一应用：范围由 ApplicationScope 过滤；这里不能用空范围
	// 退化为 system 权限，否则持有应用范围读取权限的合法管理员会被阻断（R06）。
	if action == app.ActionListApplications && strings.TrimSpace(applicationID) == "" {
		return nil
	}
	key, ok := appActionPermission(action)
	if !ok {
		return fmt.Errorf("未登记的应用动作 %q：拒绝", action)
	}
	if strings.TrimSpace(applicationID) == "" {
		return fmt.Errorf("应用动作 %q 缺少目标应用：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, applicationID)
}

// ApplicationScope 实现 app.Authorizer：root/受信主体可管理全部应用；普通用户返回
// 其真实持有 applications.read 的应用范围（步骤 184：候选枚举 + 权限引擎逐应用判定）。
// 无法枚举或没有任何可读应用时返回错误，绝不返回空成功或范围外应用。
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
	applicationIDs, err := a.checker.manageableApplicationScopes(ctx, actor.ID, "applications.read")
	if err != nil {
		return false, nil, err
	}
	if len(applicationIDs) == 0 {
		return false, nil, fmt.Errorf("普通用户没有可读取的应用管理范围：拒绝")
	}
	return false, applicationIDs, nil
}

// appActionPermission 把应用服务动作映射到权限键。
func appActionPermission(action app.Action) (string, bool) {
	switch action {
	case app.ActionGetApplication, app.ActionListApplications:
		return "applications.read", true
	case app.ActionCreateApplication:
		return "applications.create", true
	case app.ActionUpdateApplication, app.ActionEnableApplication,
		app.ActionDisableApplication, app.ActionPreviewApplicationDeletion,
		app.ActionDeleteApplication, app.ActionPurgeApplication:
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

// rootOnlyDelegationGuard 是步骤 149 之前的旧 fail-closed 实现：受信系统/本地管理员
// 与 root 允许，普通管理员一律拒绝。它保留作回滚/对照，不再注入生产装配；生产使用
// productionDelegationGuard + 真实 delegation.Service。
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

// productionDelegationGuard 是步骤 149 的生产委派检查：root、受信本地管理员与
// system 主体先按既有 root 识别器放行；其余主体必须交给真实 delegation.Service
// 按“可转授资格 + 当前持有 + 自我提权 + 目标白名单 + 数据范围”检查。
//
// 不能直接用 delegation.Service 替换旧 rootOnlyDelegationGuard：root 在管理 API
// 中是 ActorUser，裸引擎会因缺少 Grant 拒绝 root。本包装只对受信主体放行，绝不
// 对未知主体放行，也不重复写审计（领域服务在审计事务内记录）。
type productionDelegationGuard struct {
	roots  *hostRootChecker
	engine *delegation.Service
}

// newDelegationService 用真实 SQLite 委派存储与审计构造委派引擎；Store/Audit 缺失
// 时明确失败，不能降级为全放行。
func newDelegationService(deps Deps) (*delegation.Service, error) {
	if deps.Store == nil {
		return nil, fmt.Errorf("构造委派服务缺少存储依赖")
	}
	if deps.Audit == nil {
		return nil, fmt.Errorf("构造委派服务缺少审计依赖")
	}
	store, err := delegationsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造委派存储失败: %w", err)
	}
	service, err := delegation.New(delegation.Options{
		Store: store, Audit: deps.Audit, Now: deps.Now, Logger: deps.Logger})
	if err != nil {
		return nil, fmt.Errorf("构造委派服务失败: %w", err)
	}
	return service, nil
}

// allow 判定是否为受信 root/本地/system 主体；未知主体交给真实引擎检查。
func (g productionDelegationGuard) allow(ctx context.Context, actor audit.Actor) (bool, error) {
	if g.roots == nil {
		return false, errAuthorizerNotConfigured
	}
	return g.roots.trustedActor(ctx, actor)
}

// engineOrError 返回真实引擎；未装配时 fail-closed。
func (g productionDelegationGuard) engineOrError() (*delegation.Service, error) {
	if g.engine == nil {
		return nil, errAuthorizerNotConfigured
	}
	return g.engine, nil
}

// CheckPermissionAccess 实现 delegation.Guard。
func (g productionDelegationGuard) CheckPermissionAccess(ctx context.Context,
	tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	targets []delegation.Target) error {
	trusted, err := g.allow(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	engine, err := g.engineOrError()
	if err != nil {
		return err
	}
	return engine.CheckPermissionAccess(ctx, tx, actor, scopeID, permissions, targets)
}

// CheckAssignment 实现 delegation.Guard。
func (g productionDelegationGuard) CheckAssignment(ctx context.Context,
	tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	target delegation.Target) error {
	trusted, err := g.allow(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	engine, err := g.engineOrError()
	if err != nil {
		return err
	}
	return engine.CheckAssignment(ctx, tx, actor, scopeID, permissions, target)
}

// CheckPermissionActivation 实现 delegation.Guard。
func (g productionDelegationGuard) CheckPermissionActivation(ctx context.Context,
	tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef,
	targets []delegation.Target) error {
	trusted, err := g.allow(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	engine, err := g.engineOrError()
	if err != nil {
		return err
	}
	return engine.CheckPermissionActivation(ctx, tx, actor, scopeID, permissions, targets)
}

// CheckScopeRestoration 实现 delegation.Guard。
func (g productionDelegationGuard) CheckScopeRestoration(ctx context.Context,
	tx audit.Tx, actor audit.Actor, scopeID string) error {
	trusted, err := g.allow(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	engine, err := g.engineOrError()
	if err != nil {
		return err
	}
	return engine.CheckScopeRestoration(ctx, tx, actor, scopeID)
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
	_ delegation.Guard                = productionDelegationGuard{}
	_ bootstrap.RootAccount           = bootstrap.RootAccount{}
)
