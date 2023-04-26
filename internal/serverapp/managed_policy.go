package serverapp

// 步骤 146：业务托管管理 API 的受信策略配置装配。
//
// 边界：
//   - managedapi.Service 只接受受信策略通道读取/写入；页面写策略还要经过管理会话
//     强认证事实与一次性 app/version/policy-digest 批准（见 managedPolicyApprovals）。
//   - 策略写仍由 managedapi.SetPolicy 完成，包含行版本条件更新、同事务审计与应用
//     状态校验；本文件不复制策略校验逻辑。
//   - 页面写策略只允许 root/受信本地管理员；应用管理员不能修改自己的委托策略。
//   - 为托管业务 API 构造专用的 account/app/role/group/permission 服务实例：这些实例
//     使用 managedapi.NewDelegatedAuthorizers，没有 WithGrant 上下文时一律拒绝；页面/
//     CLI 继续使用原有服务实例，二者共享同一 SQLite 存储与审计。

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	managedapisqlite "github.com/kagurazakayashi/EvernightLogin/internal/managedapi/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
)

// managedPolicyReaderID 是页面读取策略的受信系统通道标识。
const managedPolicyReaderID = "login-server-page"

// managedPolicyAuthorizer 是策略配置的受信授权器：
//   - 系统页面只读通道可 Get/List；
//   - 策略写只允许 root/受信本地管理员用户主体（页面强认证与一次性批准另行校验）；
//   - 应用管理员、普通用户、匿名一律拒绝。
type managedPolicyAuthorizer struct {
	roots *hostRootChecker
}

// AuthorizePolicy 实现 managedapi.PolicyAuthorizer。
func (a managedPolicyAuthorizer) AuthorizePolicy(ctx context.Context,
	actor audit.Actor, _ string) error {
	if actor.Type == audit.ActorSystem && actor.ID == managedPolicyReaderID {
		return nil
	}
	if actor.Type == audit.ActorUser && a.roots != nil {
		trusted, err := a.roots.trustedActor(ctx, actor)
		if err == nil && trusted {
			return nil
		}
	}
	return managedapi.ErrAccessDenied
}

// managedPolicyApproval 是一次页面策略写的一次性批准（短时、单次、绑定内容）。
type managedPolicyApproval struct {
	userID    string
	appID     string
	version   int64
	digest    string
	expiresAt time.Time
}

// managedPolicyApprovals 同时实现：
//   - 页面层 Register：在真实管理强认证通过后登记一次策略写批准；
//   - managedapi.Options.Reauth（reauth.OperationRunner）：SetPolicy 内部调用时只
//     消费匹配同一 request_id/app/version/digest/actor 的批准，不再二次挑战。
//
// 批准 30 秒过期、单次消费；目标、版本、策略摘要或操作者任一变化均拒绝。
type managedPolicyApprovals struct {
	mu      sync.Mutex
	entries map[string]managedPolicyApproval
	now     func() time.Time
}

// newManagedPolicyApprovals 构造一次性批准登记器。
func newManagedPolicyApprovals(now func() time.Time) *managedPolicyApprovals {
	if now == nil {
		now = time.Now
	}
	return &managedPolicyApprovals{entries: map[string]managedPolicyApproval{}, now: now}
}

// Register 登记页面已通过强认证绑定的一次策略写。
func (g *managedPolicyApprovals) Register(userID string, binding login.UIAppPolicyActionBinding) error {
	if g == nil {
		return managedapi.ErrAccessDenied
	}
	if err := account.ValidateRequestID(binding.RequestID); err != nil {
		return managedapi.ErrInvalidRequest
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(binding.ApplicationID) == "" ||
		strings.TrimSpace(binding.PolicyDigest) == "" || binding.ExpectedRowVersion < 0 {
		return managedapi.ErrInvalidRequest
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for key, entry := range g.entries {
		if !now.Before(entry.expiresAt) {
			delete(g.entries, key)
		}
	}
	g.entries[binding.RequestID] = managedPolicyApproval{
		userID: userID, appID: binding.ApplicationID, version: binding.ExpectedRowVersion,
		digest: binding.PolicyDigest, expiresAt: now.Add(30 * time.Second),
	}
	return nil
}

// Authorize 实现 reauth.OperationRunner：只消费页面登记的一次性批准。
func (g *managedPolicyApprovals) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	if g == nil {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	key := request.RequestID
	g.mu.Lock()
	entry, ok := g.entries[key]
	if ok {
		delete(g.entries, key)
	}
	g.mu.Unlock()
	if !ok || !g.now().Before(entry.expiresAt) {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	actor := caller.Actor()
	if actor.Type != audit.ActorUser || actor.ID != entry.userID {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	if request.TargetType != "application" || request.TargetID != entry.appID ||
		request.Params["reauth_binding"] != entry.digest ||
		request.Params["expected_row_version"] != strconv.FormatInt(entry.version, 10) {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	return reauth.Result{
		OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description,
		UserID: actor.ID, Method: "approval", RequestID: request.RequestID,
	}, nil
}

// NotifyOutcome 实现 reauth.OperationRunner；策略写审计由 managedapi 事务完成。
func (g *managedPolicyApprovals) NotifyOutcome(context.Context, reauth.Result,
	reauth.Outcome) error {
	return nil
}

// ManagedPolicyReauth 在 SecurityGate 上执行页面策略写的真实强认证校验：
// 只允许 root、管理强认证事实仍在短期窗口内，然后以 managed_api.policy.manage
// 操作和 app/version/policy-digest 参数调用真实 reauth 服务。
func (g *SecurityGate) ManagedPolicyReauth(ctx context.Context, userID string,
	binding login.UIAppPolicyActionBinding) error {
	if g == nil || g.Reauth == nil || g.Policy == nil {
		return reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) || strings.TrimSpace(binding.ApplicationID) == "" ||
		strings.TrimSpace(binding.PolicyDigest) == "" || binding.ExpectedRowVersion < 0 {
		return reauth.ErrAccessDenied
	}
	root, err := g.reauthCallerIsRoot(ctx, userID)
	if err != nil || !root {
		return reauth.ErrAccessDenied
	}
	fact, ok := g.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return reauth.ErrReauthRequired
	}
	caller, callerErr := reauth.UserCaller(userID)
	if callerErr != nil {
		return reauth.ErrAccessDenied
	}
	params := map[string]string{
		"application_id":       binding.ApplicationID,
		"expected_row_version": strconv.FormatInt(binding.ExpectedRowVersion, 10),
		"reauth_binding":       binding.PolicyDigest,
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: "managed_api.policy.manage",
		TargetType: "application", TargetID: binding.ApplicationID,
		Params: params, Description: "修改应用托管管理 API 委托策略",
		RequestID: binding.RequestID,
	}
	signals := reauth.Signals{
		VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true,
	}
	if _, authorizeErr := g.Reauth.Authorize(reauth.WithSignals(ctx, signals), caller, request); authorizeErr != nil {
		return reauth.ErrReauthRequired
	}
	return nil
}

// buildManagedAPI 构造受信策略服务、专用 delegated 域服务与一次性批准器。
func buildManagedAPI(deps Deps, core *Services, managed *ManagedServices,
	guard delegation.Guard, gate *SecurityGate) (*managedapi.Service,
	*managedPolicyApprovals, audit.Actor, error) {
	if managed == nil || core == nil || core.Sessions == nil || managed.OAuthClient == nil ||
		managed.Authz == nil || managed.Delegation == nil || gate == nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("托管管理 API 缺少策略服务必需依赖")
	}
	delegatedAccount, delegatedApp, delegatedRole, delegatedGroup, delegatedPermission :=
		managedapi.NewDelegatedAuthorizers(deps.Audit)

	accountStore, err := accountsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管账户存储失败: %w", err)
	}
	managedAccount, err := account.New(account.Options{
		Store: accountStore, Audit: deps.Audit, Authorizer: delegatedAccount,
		Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管账户服务失败: %w", err)
	}
	appStore, err := appsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管应用存储失败: %w", err)
	}
	managedApp, err := app.New(app.Options{
		Store: appStore, Audit: deps.Audit, Authorizer: delegatedApp,
		Transfers: guard, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管应用服务失败: %w", err)
	}
	roleStore, err := rolesqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管角色存储失败: %w", err)
	}
	managedRole, err := role.New(role.Options{
		Store: roleStore, Audit: deps.Audit, Authorizer: delegatedRole,
		Transfers: guard, Sensitive: gate.Reauth,
		Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管角色服务失败: %w", err)
	}
	groupStore, err := groupsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管用户组存储失败: %w", err)
	}
	managedGroup, err := group.New(group.Options{
		Store: groupStore, Audit: deps.Audit, Authorizer: delegatedGroup,
		Transfers: guard, Sensitive: gate.Reauth,
		Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管用户组服务失败: %w", err)
	}
	permissionStore, err := permissionsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管权限存储失败: %w", err)
	}
	managedPermission, err := permission.New(permission.Options{
		Store: permissionStore, Audit: deps.Audit, Authorizer: delegatedPermission,
		Transfers: guard, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管权限服务失败: %w", err)
	}
	policyStore, err := managedapisqlite.New(deps.Store)
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管策略存储失败: %w", err)
	}
	approvals := newManagedPolicyApprovals(deps.Now)
	service, err := managedapi.New(managedapi.Options{
		Store: policyStore, Audit: deps.Audit, Authz: managed.Authz,
		Sessions: core.Sessions, Clients: managed.OAuthClient,
		Account: managedAccount, App: managedApp,
		Role: managedRole, Group: managedGroup, Permission: managedPermission,
		PolicyAuthorizer: managedPolicyAuthorizer{roots: managed.Roots},
		Reauth:           approvals,
		Now:              deps.Now,
		Random:           rand.Reader,
		Logger:           deps.Logger,
	})
	if err != nil {
		return nil, nil, audit.Actor{}, fmt.Errorf("构造托管管理 API 服务失败: %w", err)
	}
	reader := audit.Actor{Type: audit.ActorSystem, ID: managedPolicyReaderID}
	return service, approvals, reader, nil
}
