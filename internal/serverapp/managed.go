package serverapp

// 管理域服务装配：为管理页面与（后续）管理 API 提供真实领域服务与生产授权适配。
//
// 本文件只装配已具备真实依赖的域：账户/资料/用户组/入驻审核/用户批量/角色/权限/
// 权限引擎/委派。未装配的域（MFA/Passkey/恢复/客服/审计/统计/报告/备份/OAuth 协议）
// 不构造、不注册页面，绝不用测试替身冒充生产。
//
// 所有安全裁决都在真实服务 + permissionChecker 内完成；本文件不缓存授权、不放行
// 未知动作、不读取前端自报身份。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
	userbatchsqlite "github.com/kagurazakayashi/EvernightLogin/internal/userbatch/sqlite"
)

// ManagedServices 是管理页可用的真实领域服务与授权适配层。
type ManagedServices struct {
	Roots      *hostRootChecker
	Checker    *permissionChecker
	Account    *account.Service
	Profile    *profile.Service
	Group      *group.Service
	Onboarding *onboarding.Service
	Batch      *userbatch.Service
	Role       *role.Service
	Permission *permission.Service
	Authz      *authz.Service
	Delegation *delegation.Service
	// 观测域：审计读取/导出/清理与统计（真实服务 + 生产授权适配器）。
	AuditOps *auditops.Service
	Stats    *stats.Service
	// 报告域：报告服务/计划服务/任务调度 relay（relay 在执行器创建后 Attach）。
	Reports         *reports.Service
	Plans           *reports.PlanService
	ReportScheduler *planSchedulerRelay
	// 备份域：备份服务/备份管理服务（计划触发任务由调度 relay 进入管理索引）。
	Backup      *backup.Service
	BackupAdmin *backupadmin.Service
	// 应用域：应用资料/成员与 OAuth 客户端安全接入。
	App         *app.Service
	OAuthClient *oauthclient.Service
}

// TaskHandlers 返回管理域提供的真实任务处理器（用户批量导入/导出）。
func (m *ManagedServices) TaskHandlers() map[string]task.Handler {
	if m == nil || m.Batch == nil {
		return nil
	}
	handlers := map[string]task.Handler{
		userbatch.TaskKindUserBatchImport: m.Batch.Handler,
		userbatch.TaskKindUserBatchExport: m.Batch.Handler,
	}
	if m.AuditOps != nil {
		handlers[auditops.TaskKindAuditExport] = m.AuditOps.ExportHandler
		handlers[auditops.TaskKindAuditPurge] = m.AuditOps.PurgeHandler
	}
	if m.Reports != nil {
		handlers[reports.TaskKindReportGenerate] = m.Reports.GenerateHandler
	}
	if m.Plans != nil && m.Reports != nil {
		handlers[reports.TaskKindPlannedReportGenerate] = m.Reports.GenerateScheduledHandler
	}
	if m.BackupAdmin != nil {
		for kind, handler := range m.BackupAdmin.TaskHandlers() {
			handlers[kind] = handler
		}
	}
	return handlers
}

// AttachScheduler 把任务调度器绑定到延迟 relay（宿主在任务运行时 Complete 后调用）。
func (m *ManagedServices) AttachScheduler(scheduler *task.Scheduler) {
	if m != nil && m.ReportScheduler != nil {
		m.ReportScheduler.Attach(scheduler)
	}
}

// BuildManagedServices 装配管理域服务。
//
// runtime 必须已由 NewTaskRuntime 构造（提供入队/取消 relay 与任务存储）；未构造
// 时返回错误而不是跳过真实依赖。所有子服务构造失败即整体失败（fail-closed）。
func BuildManagedServices(deps Deps, core *Services, runtime *TaskRuntime,
	gate *SecurityGate) (*ManagedServices, error) {
	if deps.Store == nil || deps.Audit == nil || deps.Logger == nil {
		return nil, fmt.Errorf("管理域装配缺少存储、审计或日志依赖")
	}
	if gate == nil || gate.Reauth == nil {
		return nil, fmt.Errorf("管理域装配缺少敏感操作闸门（不允许跳过 reauth/policy）")
	}
	if core == nil || core.Credential == nil {
		return nil, fmt.Errorf("管理域装配缺少核心服务（一次性凭证）")
	}
	if runtime == nil || runtime.Enqueuer() == nil {
		return nil, fmt.Errorf("管理域装配缺少任务运行时入队器")
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	roots, err := newHostRootChecker(core.BootstrapStore)
	if err != nil {
		return nil, err
	}
	authzStore, err := authzsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造权限引擎存储失败: %w", err)
	}
	access, err := authz.New(authz.Options{
		Store: authzStore, Authorizer: selfQueryAuthorizer{}, Logger: deps.Logger})
	if err != nil {
		return nil, fmt.Errorf("构造权限引擎失败: %w", err)
	}
	checker := newPermissionChecker(access, roots)
	guard := rootOnlyDelegationGuard{roots: roots}
	// 敏感操作（导出/清理/凭证轮换/策略修改等）统一经真实 reauth/policy 判定。
	sensitive := gate.Reauth
	recentAuth := recentAuthVerifier{maxAge: 10 * time.Minute, now: now}

	accountStore, err := accountsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造账户存储失败: %w", err)
	}
	accountService, err := account.New(account.Options{
		Store: accountStore, Audit: deps.Audit, Authorizer: accountAuthorizer{checker: checker},
		Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造账户服务失败: %w", err)
	}
	profileStore, err := profilesqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造资料存储失败: %w", err)
	}
	profileService, err := profile.New(profile.Options{
		Store: profileStore, Audit: deps.Audit,
		Authorizer:     profileAuthorizer{checker: checker},
		ReauthVerifier: profileReauthVerifier{recentAuth},
		Sensitive:      sensitive, Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造资料服务失败: %w", err)
	}
	groupStore, err := groupsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造用户组存储失败: %w", err)
	}
	groupService, err := group.New(group.Options{
		Store: groupStore, Audit: deps.Audit, Authorizer: groupAuthorizer{checker: checker},
		Transfers: guard, Sensitive: sensitive, Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造用户组服务失败: %w", err)
	}
	onboardingStore, err := onboardingsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造入驻存储失败: %w", err)
	}
	onboardingService, err := onboarding.New(onboarding.Options{
		Store: onboardingStore, Audit: deps.Audit, Guard: guard,
		Credentials:    core.Credential,
		ManagementAuth: onboardingManagementAuthorizer{checker: checker},
		PasswordPolicy: authn.DefaultPasswordPolicy(), HashParams: authn.DefaultParams(),
		Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造入驻服务失败: %w", err)
	}
	roleStore, err := rolesqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造角色存储失败: %w", err)
	}
	roleService, err := role.New(role.Options{
		Store: roleStore, Audit: deps.Audit, Authorizer: roleAuthorizer{checker: checker},
		Transfers: guard, Sensitive: sensitive, Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造角色服务失败: %w", err)
	}
	permissionStore, err := permissionsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造权限目录存储失败: %w", err)
	}
	permissionService, err := permission.New(permission.Options{
		Store: permissionStore, Audit: deps.Audit,
		Authorizer: permissionAuthorizer{checker: checker},
		Transfers:  guard, Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造权限目录服务失败: %w", err)
	}
	exportDir, err := ensureExportDir(deps.Config.Database.Path)
	if err != nil {
		return nil, err
	}
	batchStore, err := userbatchsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造批量任务存储失败: %w", err)
	}
	batchService, err := userbatch.New(userbatch.Options{
		Store: batchStore, Audit: deps.Audit,
		Authorizer: batchAuthorizer{checker: checker},
		Sensitive:  sensitive, Accounts: accountService,
		DataScope: exportScopeAuthorizer{checker: checker},
		Enqueuer:  runtime.Enqueuer(), Canceller: runtime.Enqueuer(),
		OutputDir: exportDir, Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造用户批量服务失败: %w", err)
	}
	delegationStore, err := delegationsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造委派存储失败: %w", err)
	}
	delegationService, err := delegation.New(delegation.Options{
		Store: delegationStore, Audit: deps.Audit, Now: now, Logger: deps.Logger})
	if err != nil {
		return nil, fmt.Errorf("构造委派服务失败: %w", err)
	}
	managed := &ManagedServices{
		Roots: roots, Checker: checker, Account: accountService, Profile: profileService,
		Group: groupService, Onboarding: onboardingService, Batch: batchService,
		Role: roleService, Permission: permissionService, Authz: access,
		Delegation: delegationService,
	}
	auditService, err := buildAuditOps(deps, managed, runtime, gate)
	if err != nil {
		return nil, err
	}
	statsService, err := buildStats(deps, managed)
	if err != nil {
		return nil, err
	}
	managed.AuditOps = auditService
	managed.Stats = statsService
	reportService, planService, planRelay, reportErr := buildReports(deps, managed, runtime, gate)
	if reportErr != nil {
		return nil, reportErr
	}
	managed.Reports = reportService
	managed.Plans = planService
	managed.ReportScheduler = planRelay
	backupService, backupAdmin, backupErr := buildBackups(deps, managed, runtime, gate)
	if backupErr != nil {
		return nil, backupErr
	}
	managed.Backup = backupService
	managed.BackupAdmin = backupAdmin
	appService, oauthService, appErr := buildApplicationServices(deps, managed, guard, gate)
	if appErr != nil {
		return nil, appErr
	}
	managed.App = appService
	managed.OAuthClient = oauthService
	return managed, nil
}

// buildApplicationServices 构造应用资料与 OAuth 客户端服务。
func buildApplicationServices(deps Deps, managed *ManagedServices,
	guard delegation.Guard, gate *SecurityGate) (*app.Service, *oauthclient.Service, error) {
	appStore, err := appsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, fmt.Errorf("构造应用存储失败: %w", err)
	}
	appService, err := app.New(app.Options{
		Store: appStore, Audit: deps.Audit, Authorizer: appAuthorizer{checker: managed.Checker},
		Transfers: guard, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("构造应用服务失败: %w", err)
	}
	oauthStore, err := oauthclientsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, fmt.Errorf("构造 OAuth 客户端存储失败: %w", err)
	}
	oauthService, err := oauthclient.New(oauthclient.Options{
		Store: oauthStore, Audit: deps.Audit,
		Authorizer: oauthclientAuthorizer{checker: managed.Checker},
		// 客户端签名密钥/回调变更属敏感操作：经真实 reauth/policy 判定。
		Sensitive: gate.Reauth,
		Now:       deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("构造 OAuth 客户端服务失败: %w", err)
	}
	return appService, oauthService, nil
}

// ensureExportDir 创建批量导出受控目录（0700；不跟随符号链接由服务构造器校验）。
func ensureExportDir(databasePath string) (string, error) {
	if databasePath == "" {
		return "", fmt.Errorf("批量导出目录缺少数据库路径")
	}
	directory := filepath.Join(filepath.Dir(databasePath), "exports")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("创建批量导出目录失败: %w", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("解析批量导出目录失败: %w", err)
	}
	return absolute, nil
}

// batchAuthorizer 实现 userbatch.Authorizer。
type batchAuthorizer struct {
	checker *permissionChecker
}

// Authorize 实现 userbatch.Authorizer。
func (a batchAuthorizer) Authorize(ctx context.Context, caller account.Caller,
	action userbatch.Action, scopeID string) error {
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
	case userbatch.ActionImport:
		key = "users.create"
	case userbatch.ActionExport:
		key = "users.export"
	case userbatch.ActionQuery:
		key = "users.read"
	case userbatch.ActionCancel, userbatch.ActionRetry:
		key = "users.export"
	default:
		return fmt.Errorf("未登记的批量任务动作 %q：拒绝", action)
	}
	return a.checker.check(ctx, actor.ID, key, scopeID)
}

// exportScopeAuthorizer 实现 userbatch.UserScopeAuthorizer：root/受信主体可导出
// 全部；普通用户必须持有导出权限（系统范围），但逐用户数据范围映射尚未装配，
// 因此只能按“范围全有或全无”处理——无权限时拒绝，有权限时放行范围内所有用户。
// 这不是按部门/应用的细粒度数据范围；报告已将其列为待装配缺口。
type exportScopeAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeUser 实现 userbatch.UserScopeAuthorizer。
func (a exportScopeAuthorizer) AuthorizeUser(ctx context.Context,
	caller account.Caller, permissionKey, userID string) (bool, error) {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return false, err
	}
	if trusted {
		return true, nil
	}
	if err := a.checker.check(ctx, actor.ID, permissionKey, "system"); err != nil {
		return false, nil
	}
	return true, nil
}
