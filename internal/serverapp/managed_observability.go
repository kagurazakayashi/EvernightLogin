package serverapp

// 审计/统计页面后端装配：真实 internal/auditops + internal/stats 服务 + 生产授权
// 适配器 + 后台任务处理器。
//
// 边界：
//   - 查询/导出/清理的授权与数据范围由 auditops/stats 内部与宿主 ScopeGrant 授权器
//     判定；未授权一律拒绝。
//   - 导出/清理等敏感操作仍需 reauth/policy 链（尚未装配），SensitiveRunner 使用
//     fail-closed 实现：敏感动作明确拒绝，不伪造成功；只读查询不受影响。
//   - 导出目录固定在数据目录下的受控子目录（0700），不允许指向符号链接。
//   - 数据范围当前按“系统范围全员可见（授予权限者）”处理；按部门/应用资源的细粒度
//     数据范围映射未装配，报告已列为缺口。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	backupadminsqlite "github.com/kagurazakayashi/EvernightLogin/internal/backupadmin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	reportssqlite "github.com/kagurazakayashi/EvernightLogin/internal/reports/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	statssqlite "github.com/kagurazakayashi/EvernightLogin/internal/stats/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// buildAuditOps 构造审计读取/导出/清理服务与导出目录。
func buildAuditOps(deps Deps, managed *ManagedServices,
	runtime *TaskRuntime, gate *SecurityGate) (*auditops.Service, error) {
	store, err := auditopssqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造审计查询存储失败: %w", err)
	}
	outputDir, err := ensureControlledDir(deps.Config.Database.Path, "audit-exports")
	if err != nil {
		return nil, err
	}
	service, err := auditops.New(auditops.Options{
		Store: store, Audit: deps.Audit,
		Authorizer: auditScopeAuthorizer{checker: managed.Checker},
		Root:       auditRootChecker{roots: managed.Roots},
		Sensitive:  gate.Reauth,
		Enqueuer:   runtime.Enqueuer(), Canceller: runtime.Enqueuer(),
		Tasks:     runtime.taskStore(),
		OutputDir: outputDir, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造审计查询服务失败: %w", err)
	}
	return service, nil
}

// buildStats 构造统计服务（真实 SQLite 事实存储 + 授权/root 适配器）。
func buildStats(deps Deps, managed *ManagedServices) (*stats.Service, error) {
	store, err := statssqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造统计存储失败: %w", err)
	}
	service, err := stats.New(stats.Options{
		Store:      store,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Root:       statsRootChecker{roots: managed.Roots},
		Audit:      deps.Audit, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造统计服务失败: %w", err)
	}
	return service, nil
}

// ensureControlledDir 在数据库同目录下创建受控子目录（0700），返回绝对路径。
func ensureControlledDir(databasePath, name string) (string, error) {
	if databasePath == "" {
		return "", fmt.Errorf("受控目录缺少数据库路径")
	}
	directory := filepath.Join(filepath.Dir(databasePath), name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("创建受控目录 %s 失败: %w", name, err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("解析受控目录失败: %w", err)
	}
	return absolute, nil
}

// auditScopeAuthorizer 实现 auditops.Authorizer。
type auditScopeAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeScope 实现 auditops.Authorizer。root/受信主体数据范围不限；普通用户
// 需在作用范围持有对应权限键，数据范围按“作用范围全覆盖”处理（细粒度资源范围
// 映射未装配，报告已列缺口）。
func (a auditScopeAuthorizer) AuthorizeScope(ctx context.Context,
	caller account.Caller, permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return auditops.ScopeGrant{}, err
	}
	if trusted {
		return auditops.ScopeGrant{Allowed: true, AllData: true}, nil
	}
	allowed, evalErr := a.checker.evaluate(ctx, actor.ID, permissionKey, scopeID)
	if evalErr != nil {
		return auditops.ScopeGrant{}, evalErr
	}
	if !allowed {
		return auditops.ScopeGrant{Allowed: false}, nil
	}
	return auditops.ScopeGrant{Allowed: true, AllData: true}, nil
}

// auditRootChecker 实现 auditops.RootChecker。
type auditRootChecker struct {
	roots *hostRootChecker
}

// IsRoot 实现 auditops.RootChecker。
func (c auditRootChecker) IsRoot(ctx context.Context,
	caller account.Caller) (bool, error) {
	actor := caller.Actor()
	trusted, err := c.roots.trustedActor(ctx, actor)
	if err != nil {
		return false, err
	}
	if trusted {
		return true, nil
	}
	return false, nil
}

// statsScopeAuthorizer 实现 stats.Authorizer。
type statsScopeAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeScope 实现 stats.Authorizer。
func (a statsScopeAuthorizer) AuthorizeScope(ctx context.Context,
	caller account.Caller, permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return stats.ScopeGrant{}, err
	}
	if trusted {
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	}
	allowed, evalErr := a.checker.evaluate(ctx, actor.ID, permissionKey, scopeID)
	if evalErr != nil {
		return stats.ScopeGrant{}, evalErr
	}
	if !allowed {
		return stats.ScopeGrant{Allowed: false}, nil
	}
	// 数据范围按作用范围全覆盖处理（细粒度资源范围映射未装配，报告已列缺口）。
	return stats.ScopeGrant{Allowed: true, AllData: true}, nil
}

// statsRootChecker 实现 stats.RootChecker。
type statsRootChecker struct {
	roots *hostRootChecker
}

// IsRoot 实现 stats.RootChecker。
func (c statsRootChecker) IsRoot(ctx context.Context,
	caller account.Caller) (bool, error) {
	actor := caller.Actor()
	trusted, err := c.roots.trustedActor(ctx, actor)
	if err != nil {
		return false, err
	}
	if trusted {
		return true, nil
	}
	return false, nil
}

// planSchedulerRelay 把报告计划服务与任务调度器的构造顺序解耦：计划服务在
// 执行器/调度器创建前构造（因为调度器需要报告处理器），但真正的计划读写发生在
// 服务启动之后，此时 relay 已绑定真实调度器；未绑定前所有计划操作 fail-closed。
type planSchedulerRelay struct {
	scheduler *task.Scheduler
}

// Attach 绑定真实调度器（由宿主在任务运行时 Complete 之后调用）。
func (r *planSchedulerRelay) Attach(scheduler *task.Scheduler) { r.scheduler = scheduler }

func (r *planSchedulerRelay) require() (*task.Scheduler, error) {
	if r == nil || r.scheduler == nil {
		return nil, fmt.Errorf("任务调度器尚未启动，报告计划暂不可用")
	}
	return r.scheduler, nil
}

// Create 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) Create(ctx context.Context,
	request task.NewScheduleRequest) (task.Schedule, error) {
	scheduler, err := r.require()
	if err != nil {
		return task.Schedule{}, err
	}
	return scheduler.Create(ctx, request)
}

// Get 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) Get(ctx context.Context, id string) (task.Schedule, error) {
	scheduler, err := r.require()
	if err != nil {
		return task.Schedule{}, err
	}
	return scheduler.Get(ctx, id)
}

// List 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) List(ctx context.Context) ([]task.Schedule, error) {
	scheduler, err := r.require()
	if err != nil {
		return nil, err
	}
	return scheduler.List(ctx)
}

// Pause 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) Pause(ctx context.Context,
	command task.ScheduleStateCommand) (task.Schedule, error) {
	scheduler, err := r.require()
	if err != nil {
		return task.Schedule{}, err
	}
	return scheduler.Pause(ctx, command)
}

// Resume 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) Resume(ctx context.Context,
	command task.ScheduleStateCommand) (task.Schedule, error) {
	scheduler, err := r.require()
	if err != nil {
		return task.Schedule{}, err
	}
	return scheduler.Resume(ctx, command)
}

// Delete 实现 reports.PlanScheduler。
func (r *planSchedulerRelay) Delete(ctx context.Context,
	command task.ScheduleDeleteCommand) error {
	scheduler, err := r.require()
	if err != nil {
		return err
	}
	return scheduler.Delete(ctx, command)
}

// taskJobReader 把 reports.TaskReader 延迟适配到任务执行器（构造时为 nil）。
type taskJobReader struct {
	runtime *TaskRuntime
}

// Get 实现 reports.TaskReader。
func (r taskJobReader) Get(ctx context.Context, id string) (task.Job, error) {
	if r.runtime == nil || r.runtime.Executor() == nil {
		return task.Job{}, fmt.Errorf("任务执行器尚未启动")
	}
	return r.runtime.Executor().Get(ctx, id)
}

// buildReports 构造报告服务与计划服务（真实历史持久化、受控产物目录、任务入队）。
func buildReports(deps Deps, managed *ManagedServices,
	runtime *TaskRuntime, gate *SecurityGate) (*reports.Service, *reports.PlanService, *planSchedulerRelay, error) {
	store, err := reportssqlite.New(deps.Store)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造报告存储失败: %w", err)
	}
	history, err := reportssqlite.NewHistoryRecorder(store)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造报告历史记录器失败: %w", err)
	}
	projections, err := reportssqlite.NewPlanProjectionStore(store)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造报告计划投影存储失败: %w", err)
	}
	outputDir, err := ensureControlledDir(deps.Config.Database.Path, "reports")
	if err != nil {
		return nil, nil, nil, err
	}
	relay := &planSchedulerRelay{}
	service, err := reports.New(reports.Options{
		Source:     managed.Stats,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Root:       statsRootChecker{roots: managed.Roots},
		Sensitive:  gate.Reauth,
		Audit:      deps.Audit, Enqueuer: runtime.Enqueuer(), Canceller: runtime.Enqueuer(),
		Tasks:   taskJobReader{runtime: runtime},
		History: history,
		// PDF 字体未部署：能力显式不可用，请求 PDF 会被拒绝而不是伪造文件。
		OutputDir: outputDir, Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造报告服务失败: %w", err)
	}
	plans, err := reports.NewPlanService(reports.PlanOptions{
		Schedules:  relay,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Root:       statsRootChecker{roots: managed.Roots},
		Audit:      deps.Audit, Projections: projections,
		PDFAvailable: func() bool { return false },
		Now:          deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造报告计划服务失败: %w", err)
	}
	return service, plans, relay, nil
}

// buildBackups 构造备份服务与备份管理服务（真实 SQLite 一致性快照 + 受控产物
// 目录 + 任务调度 relay）。
func buildBackups(deps Deps, managed *ManagedServices,
	runtime *TaskRuntime, gate *SecurityGate) (*backup.Service, *backupadmin.Service, error) {
	snapshotter, err := backup.NewSQLiteSnapshotter(deps.Store)
	if err != nil {
		return nil, nil, fmt.Errorf("构造数据库快照器失败: %w", err)
	}
	outputDir, err := ensureControlledDir(deps.Config.Database.Path, "backups")
	if err != nil {
		return nil, nil, err
	}
	keyringProvider := secrets.ProviderFunc(func(context.Context) ([]byte, error) {
		return deps.Keyring.Document()
	})
	backupService, err := backup.New(backup.Options{
		Snapshotter: snapshotter, Keyring: keyringProvider,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Audit:      deps.Audit,
		OutputDir:  outputDir, AppVersion: login.CurrentBuildInfo().Version,
		Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("构造备份服务失败: %w", err)
	}
	store, err := backupadminsqlite.New(deps.Store)
	if err != nil {
		return nil, nil, fmt.Errorf("构造备份管理存储失败: %w", err)
	}
	// 调度器成功入队回调必须指向同一 relay：否则计划触发任务不会进入管理索引。
	relay := &backupadmin.EnqueueRelay{}
	runtime.SetSchedulerEnqueueHook(relay.Handle)
	adminService, err := backupadmin.New(backupadmin.Options{
		Backup: backupService, Store: store,
		Scheduler: runtime.Scheduler(),
		Enqueuer:  runtime.Enqueuer(), Canceller: runtime.Enqueuer(),
		TaskReader: taskJobReader{runtime: runtime},
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Root:       statsRootChecker{roots: managed.Roots},
		Sensitive:  gate.Reauth,
		Audit:      deps.Audit, SchedulerRelay: relay,
		Keyring:   keyringProvider,
		OutputDir: outputDir, AppVersion: login.CurrentBuildInfo().Version,
		DefaultRetention: backupadmin.RetentionPolicy{
			Version: 1, MaxAgeDays: 30, MaxCount: 20,
		},
		Now: deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("构造备份管理服务失败: %w", err)
	}
	return backupService, adminService, nil
}

// timeNow 是内部装配使用的默认时钟（避免每处重复 nil 判断）。
func timeNow() time.Time { return time.Now() }
