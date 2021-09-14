package sqlite_test

// 步骤 81 备份管理端到端测试：真实 SQLite 迁移 + 真实 internal/task 任务存储/调度器/
// 执行器 + 真实备份生命周期仓储。备份引擎（internal/backup.Service）与授权/再次认证/
// 通知使用明确标注的受控测试替身（避免在单测里制造真实磁盘/密钥/外发），但调度、
// 任务状态机、持久化、保护规则与页面适配器链路都是真实实现。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	backupstore "github.com/kagurazakayashi/EvernightLogin/internal/backupadmin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

const testUserID = "usr_00000000000000000000000000000081"

var testNow = time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)

// fakeAuthorizer 是按权限键控的授权替身。
type fakeAuthorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

func (a *fakeAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grants[permissionKey+"|"+scopeID], nil
}

func (a *fakeAuthorizer) allow(permission string) {
	a.mu.Lock()
	a.grants[permission+"|"+backupadmin.ScopeSystem] = stats.ScopeGrant{Allowed: true, AllData: true}
	a.mu.Unlock()
}

func (a *fakeAuthorizer) deny(permission string) {
	a.mu.Lock()
	delete(a.grants, permission+"|"+backupadmin.ScopeSystem)
	a.mu.Unlock()
}

func (a *fakeAuthorizer) check(_ context.Context, permission string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if grant := a.grants[permission+"|"+backupadmin.ScopeSystem]; grant.Allowed {
		return nil
	}
	return errors.New("权限不足")
}

// fakeSensitive 是再次认证替身；可注入拒绝以验证 fail-closed。
type fakeSensitive struct {
	mu       sync.Mutex
	denied   bool
	requests []reauth.Request
}

func (s *fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, request)
	if s.denied {
		return reauth.Result{}, errors.New("强认证不足")
	}
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (s *fakeSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// fakeAudit 记录审计事件（不访问真实审计库；另由真实 task 存储覆盖任务审计）。
type fakeAudit struct {
	mu     sync.Mutex
	fail   bool
	events []audit.Event
}

func (a *fakeAudit) Record(_ context.Context, event audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

func (a *fakeAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return a.Record(ctx, event)
}

// fakeNotifier 记录通知并支持注入投递失败。
type fakeNotifier struct {
	mu       sync.Mutex
	fail     bool
	messages []backupadmin.BackupNotification
}

func (n *fakeNotifier) NotifyBackup(_ context.Context, message backupadmin.BackupNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.messages = append(n.messages, message)
	if n.fail {
		return errors.New("通知投递失败")
	}
	return nil
}

func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.messages)
}

// fakeCreator 是备份引擎替身：写出一个与 Result 摘要一致的受控文件，不访问真实数据库
// 或密钥。失败注入用于验证失败通知与“失败新备份不删最后可用备份”。
type fakeCreator struct {
	mu      sync.Mutex
	dir     string
	counter int
	fail    error
	content []byte
}

func (c *fakeCreator) Create(ctx context.Context, _ backup.CreateRequest) (backup.Result, error) {
	if err := ctx.Err(); err != nil {
		return backup.Result{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return backup.Result{}, c.fail
	}
	c.counter++
	content := []byte(fmt.Sprintf("fake-encrypted-backup-payload-%d", c.counter))
	backupID := fmt.Sprintf("bkp_%032d", c.counter)
	createdAt := testNow
	fileName := "login-backup_" + createdAt.UTC().Format("20060102T150405Z") + "_" + backupID + ".elnbak"
	path := filepath.Join(c.dir, fileName)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return backup.Result{}, err
	}
	sum := sha256.Sum256(content)
	return backup.Result{
		BackupID: backupID, FileName: fileName, Path: path,
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(content)),
		PayloadBytes: int64(len(content)), CreatedAt: createdAt,
		Database: backup.DatabaseMeta{Engine: "sqlite", SchemaVersion: "0043",
			SizeBytes: 4096, SHA256: strings.Repeat("b", 64)},
		Content: backup.ContentMeta{
			Database:    true,
			Attachments: backup.ContentStatus{Status: "not_configured"},
			Config:      backup.ContentStatus{Status: "not_configured"},
		},
		ManifestSHA256: strings.Repeat("a", 64), Attempts: 1, Duration: time.Second,
	}, nil
}

// env 是测试装配。
type env struct {
	t         *testing.T
	ctx       context.Context
	now       time.Time
	raw       *storagesqlite.Store
	taskStore *tasksqlite.Store
	scheduler *task.Scheduler
	executor  *task.Executor
	store     *backupstore.Store
	admin     *backupadmin.Service
	relay     *backupadmin.EnqueueRelay
	authz     *fakeAuthorizer
	sensitive *fakeSensitive
	audit     *fakeAudit
	notifier  *fakeNotifier
	creator   *fakeCreator
	dir       string
	caller    account.Caller
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{t: t, ctx: ctx, now: testNow}
	e.dir = t.TempDir()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(e.dir, "step81.db")))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	e.raw = raw
	migrationSet, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	e.taskStore = taskStore
	store, err := backupstore.New(raw)
	if err != nil {
		t.Fatalf("构造备份仓储失败: %v", err)
	}
	e.store = store
	caller, err := account.UserCaller(testUserID)
	if err != nil {
		t.Fatalf("构造调用者失败: %v", err)
	}
	e.caller = caller
	e.authz = &fakeAuthorizer{grants: map[string]stats.ScopeGrant{}}
	for _, permission := range []string{backupadmin.PermissionRead, backupadmin.PermissionCreate,
		backupadmin.PermissionCancel, backupadmin.PermissionDownload,
		backupadmin.PermissionRetention, backupadmin.PermissionCleanup} {
		e.authz.allow(permission)
	}
	e.sensitive = &fakeSensitive{}
	e.audit = &fakeAudit{}
	e.notifier = &fakeNotifier{}
	outputDir := filepath.Join(e.dir, "backups")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("创建输出目录失败: %v", err)
	}
	e.creator = &fakeCreator{dir: outputDir}
	e.relay = &backupadmin.EnqueueRelay{}
	permissionCheck := func(permission string) task.PermissionCheck {
		return func(_ context.Context, _ task.PermissionRequest) error {
			return e.authz.check(context.Background(), permission)
		}
	}
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "step81-scheduler",
		PermissionCheck: permissionCheck(backupadmin.PermissionCreate),
		OnJobEnqueued:   e.relay.Handle,
		TickInterval:    200 * time.Millisecond, CatchUpGrace: time.Minute,
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	e.scheduler = scheduler
	var admin *backupadmin.Service
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			backupadmin.KindBackupCreate: func(handlerCtx context.Context, job task.Job) error {
				return admin.TaskHandlers()[backupadmin.KindBackupCreate](handlerCtx, job)
			},
			backupadmin.KindBackupCleanup: func(handlerCtx context.Context, job task.Job) error {
				return admin.TaskHandlers()[backupadmin.KindBackupCleanup](handlerCtx, job)
			},
		},
		ExecutorID: "step81-executor", MaxConcurrent: 1,
		PollInterval: 20 * time.Millisecond, ShutdownTimeout: 3 * time.Second,
		PermissionCheck: permissionCheck(backupadmin.PermissionCreate),
		Now:             func() time.Time { return e.now },
		RetryPolicy:     task.RetryPolicy{BaseDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	e.executor = executor
	admin, err = backupadmin.New(backupadmin.Options{
		Backup: e.creator, Store: store, Scheduler: scheduler,
		SchedulerRelay: e.relay, Enqueuer: executor, Canceller: executor,
		TaskReader: executor, Authorizer: e.authz, Sensitive: e.sensitive,
		Audit: e.audit, Notifier: e.notifier, OutputDir: outputDir,
		DefaultRetention: backupadmin.RetentionPolicy{
			Version: 1, MaxCount: 10, MaxAgeDays: 30, MaxTotalBytes: 1 << 30,
		},
		DefaultNotifyTarget: "owner_mail", DefaultNotifyFailures: true,
		DefaultNotifySuccess: true,
		DownloadTTL:          time.Minute, MaxPageDownloadBytes: 1 << 20,
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("构造备份管理服务失败: %v", err)
	}
	e.admin = admin
	return e
}

// startExecutor 启动执行器并在测试结束前停止。
func (e *env) startExecutor() {
	e.t.Helper()
	if err := e.executor.Start(e.ctx); err != nil {
		e.t.Fatalf("启动执行器失败: %v", err)
	}
	e.t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.executor.Stop(stopCtx); err != nil {
			e.t.Logf("停止执行器: %v", err)
		}
	})
}

// waitFor 有界等待条件成立。
func (e *env) waitFor(description string, condition func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("等待超时: %s", description)
}

// artifacts 返回当前全部产物。
func (e *env) artifacts() []backupadmin.ArtifactView {
	e.t.Helper()
	views, _, err := e.admin.ListArtifacts(e.ctx, e.caller, backupadmin.ArtifactFilter{Limit: 100})
	if err != nil {
		e.t.Fatalf("列产物失败: %v", err)
	}
	return views
}

// runHandler 直接执行指定任务的处理器（不经执行器，便于确定性断言）。
func (e *env) runHandler(job task.Job) error {
	e.t.Helper()
	return e.admin.TaskHandlers()[job.Kind](e.ctx, job)
}

// job 读取任务真实状态。
func (e *env) job(id string) task.Job {
	e.t.Helper()
	job, err := e.executor.Get(e.ctx, id)
	if err != nil {
		e.t.Fatalf("读取任务 %s 失败: %v", id, err)
	}
	return job
}

// TestScheduleTimezoneTriggerDedupAndPermissionRevoke 验证计划时区/下次执行、
// 停机补跑（latest）、触发去重、执行身份失权后拒绝触发（未创建任务）。
func TestScheduleTimezoneTriggerDedupAndPermissionRevoke(t *testing.T) {
	e := newEnv(t)
	e.startExecutor()
	view, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
		Caller: e.caller, Name: "每日备份", ScheduleType: task.ScheduleTypeDaily,
		Expression: "02:30", TimeZone: "Asia/Shanghai", MissedPolicy: task.MissedLatest,
		MaxCatchUp: 10, TimeoutSeconds: 3600, MaxAttempts: 1,
		RetentionVersion: 1, NotifyFailures: true, NotifySuccess: true,
		NotifyTarget: "owner_mail", Enabled: true, RequestID: "req-schedule",
	})
	if err != nil {
		t.Fatalf("创建备份计划失败: %v", err)
	}
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("加载时区失败: %v", err)
	}
	if view.NextRunUnknown {
		t.Fatal("下次执行不应未知")
	}
	local := view.NextRun.In(shanghai)
	if local.Hour() != 2 || local.Minute() != 30 {
		t.Fatalf("下次执行本地时间 = %s，期望 02:30 Asia/Shanghai", local.Format(time.RFC3339))
	}
	// 停机 3 天后只补跑最近一次。
	e.now = e.now.Add(72 * time.Hour)
	if err := e.scheduler.Tick(e.ctx); err != nil {
		t.Fatalf("调度 Tick 失败: %v", err)
	}
	e.waitFor("计划触发任务生成", func() bool { return len(e.artifacts()) >= 1 })
	if count := len(e.artifacts()); count != 1 {
		t.Fatalf("补跑产物数 = %d，期望 1（latest 策略）", count)
	}
	// 同一触发时刻重复 Tick 不重复创建。
	entries, err := e.store.ListJobs(e.ctx, backupadmin.JobFilter{Kind: backupadmin.KindBackupCreate, Limit: 10})
	if err != nil {
		t.Fatalf("列任务失败: %v", err)
	}
	before := len(entries)
	if err := e.scheduler.Tick(e.ctx); err != nil {
		t.Fatalf("重复调度 Tick 失败: %v", err)
	}
	entries, err = e.store.ListJobs(e.ctx, backupadmin.JobFilter{Kind: backupadmin.KindBackupCreate, Limit: 10})
	if err != nil {
		t.Fatalf("列任务失败: %v", err)
	}
	if len(entries) != before {
		t.Fatalf("重复 Tick 后任务数 = %d，期望 %d（触发去重）", len(entries), before)
	}
	// 执行身份失权：触发被拒绝且不创建任务。
	e.authz.deny(backupadmin.PermissionCreate)
	e.now = e.now.Add(24 * time.Hour)
	if err := e.scheduler.Tick(e.ctx); err != nil {
		t.Fatalf("失权后 Tick 失败: %v", err)
	}
	entries, err = e.store.ListJobs(e.ctx, backupadmin.JobFilter{Kind: backupadmin.KindBackupCreate, Limit: 10})
	if err != nil {
		t.Fatalf("列任务失败: %v", err)
	}
	if len(entries) != before {
		t.Fatalf("失权触发后任务数 = %d，期望 %d（未创建任务）", len(entries), before)
	}
}

// TestManualBackupDownloadCancelAndNotification 验证手动备份幂等、产物登记、
// 一次性下载令牌、独立下载权限撤销、取消请求接受不等于已取消、通知投递失败不改写产物。
func TestManualBackupDownloadCancelAndNotification(t *testing.T) {
	e := newEnv(t)
	// 执行器不启动：任务保持 queued，便于验证幂等与取消语义。
	first, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-1")
	if err != nil {
		t.Fatalf("提交手动备份失败: %v", err)
	}
	second, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-2")
	if err != nil {
		t.Fatalf("重复提交手动备份失败: %v", err)
	}
	if !second.Existing || second.JobID != first.JobID {
		t.Fatalf("重复提交应返回已存在任务，得到 %+v", second)
	}
	// 取消请求：queued 任务直接 cancelled，但返回结果必须如实表达“请求已接受”。
	cancelView, err := e.admin.CancelJob(e.ctx, e.caller, first.JobID, "维护窗口", "req-3")
	if err != nil {
		t.Fatalf("请求取消失败: %v", err)
	}
	if !cancelView.Accepted || cancelView.State != string(task.StateCancelled) {
		t.Fatalf("取消结果 = %+v，期望已接受并真实取消", cancelView)
	}
	// 成功路径：直接执行处理器（模拟执行器领取任务）。
	jobRef, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-4")
	if err != nil {
		t.Fatalf("提交手动备份失败: %v", err)
	}
	job := e.job(jobRef.JobID)
	if err := e.runHandler(job); err != nil {
		t.Fatalf("备份处理器失败: %v", err)
	}
	views := e.artifacts()
	if len(views) != 1 || views[0].Verification != string(backupadmin.VerificationVerified) {
		t.Fatalf("产物登记不正确: %+v", views)
	}
	if !views[0].IsLastUsable || !views[0].Downloadable {
		t.Fatalf("唯一产物应为最后可用且可下载: %+v", views[0])
	}
	// 下载：一次性令牌只能兑换一次，内容摘要一致。
	ticket, err := e.admin.IssueDownloadTicket(e.ctx, e.caller, views[0].BackupID, "req-dl")
	if err != nil {
		t.Fatalf("签发下载令牌失败: %v", err)
	}
	file, err := e.admin.RedeemDownloadTicket(e.ctx, e.caller, ticket.Token, "req-dl2")
	if err != nil {
		t.Fatalf("兑换下载令牌失败: %v", err)
	}
	sum := sha256.Sum256(file.Data)
	if hex.EncodeToString(sum[:]) != file.SHA256 || int64(len(file.Data)) != file.Size {
		t.Fatalf("下载内容与实际产物不一致")
	}
	if _, err := e.admin.RedeemDownloadTicket(e.ctx, e.caller, ticket.Token, "req-dl3"); err == nil {
		t.Fatal("下载令牌不应可重复兑换")
	}
	// 撤销独立下载权限后，旧令牌与再次签发都必须拒绝。
	e.authz.deny(backupadmin.PermissionDownload)
	if _, err := e.admin.IssueDownloadTicket(e.ctx, e.caller, views[0].BackupID, "req-dl4"); !errors.Is(err, backupadmin.ErrAccessDenied) {
		t.Fatalf("下载越权期望 ErrAccessDenied，得到 %v", err)
	}
	e.authz.allow(backupadmin.PermissionDownload)
	// 再次认证拒绝时下载必须失败（不提供假准备过程）。
	e.sensitive.denied = true
	if _, err := e.admin.IssueDownloadTicket(e.ctx, e.caller, views[0].BackupID, "req-dl5"); !errors.Is(err, backupadmin.ErrAccessDenied) {
		t.Fatalf("再次认证拒绝时期望 ErrAccessDenied，得到 %v", err)
	}
	e.sensitive.denied = false
	// 通知失败不改变产物事实。
	e.notifier.mu.Lock()
	e.notifier.fail = true
	e.notifier.mu.Unlock()
	jobRef2, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-5")
	if err != nil {
		t.Fatalf("提交第二个手动备份失败: %v", err)
	}
	if err := e.runHandler(e.job(jobRef2.JobID)); err != nil {
		t.Fatalf("第二个备份处理器失败: %v", err)
	}
	views = e.artifacts()
	if len(views) != 2 {
		t.Fatalf("通知失败后产物数 = %d，期望 2（通知失败不改写备份）", len(views))
	}
	jobState, found, err := e.store.JobState(e.ctx, jobRef2.JobID)
	if err != nil || !found {
		t.Fatalf("读取任务状态失败: %v", err)
	}
	if jobState.NotificationStat != backupadmin.NotificationStateFailed {
		t.Fatalf("通知状态 = %q，期望 failed", jobState.NotificationStat)
	}
}

// seedArtifact 直接写入一条产物与真实受控文件（用于保留策略边界测试）。
func (e *env) seedArtifact(t *testing.T, suffix string, published time.Time,
	size int, verification backupadmin.VerificationState) backupadmin.Artifact {
	t.Helper()
	content := []byte(strings.Repeat("x", size))
	backupID := "bkp_" + suffix + strings.Repeat("0", 28-len(suffix))
	fileName := "login-backup_" + published.UTC().Format("20060102T150405Z") + "_" + backupID + ".elnbak"
	if err := os.WriteFile(filepath.Join(e.creator.dir, fileName), content, 0o600); err != nil {
		t.Fatalf("写入测试产物失败: %v", err)
	}
	sum := sha256.Sum256(content)
	artifact := backupadmin.Artifact{
		BackupID: backupID, Origin: backupadmin.OriginManual, FileName: fileName,
		SizeBytes: int64(size), PayloadBytes: int64(size),
		FileSHA256: hex.EncodeToString(sum[:]), ManifestSHA256: strings.Repeat("c", 64),
		FormatVersion: 1, SchemaVersion: "0043", ContentDatabase: true,
		ContentAttach: backupadmin.ContentNotConfigured,
		ContentConfig: backupadmin.ContentNotConfigured,
		Verification:  verification, Cleanup: backupadmin.CleanupRetained,
		CreatedAt: published, PublishedAt: published, RetentionVersion: 1,
	}
	if verification == backupadmin.VerificationVerified {
		artifact.VerifiedAt = published
	}
	if err := e.store.InsertArtifact(e.ctx, artifact); err != nil {
		t.Fatalf("写入测试产物元数据失败: %v", err)
	}
	return artifact
}

// TestRetentionProtectionBoundariesAndCleanup 验证数量/天数/容量边界、最后可用保护、
// 失败新备份不使旧可用备份失去保护，以及清理执行时重新保护。
func TestRetentionProtectionBoundariesAndCleanup(t *testing.T) {
	e := newEnv(t)
	// A 最早、C 中间、B 最新（全部校验通过）。
	seedA := e.seedArtifact(t, "a", e.now.Add(-40*24*time.Hour), 100, backupadmin.VerificationVerified)
	e.seedArtifact(t, "c", e.now.Add(-5*24*time.Hour), 100, backupadmin.VerificationVerified)
	seedB := e.seedArtifact(t, "b", e.now.Add(-1*24*time.Hour), 100, backupadmin.VerificationVerified)
	// 失败/未校验的新备份（更新时间更晚）不得成为最后可用备份。
	unknown := e.seedArtifact(t, "d", e.now.Add(-time.Hour), 100, backupadmin.VerificationUnknown)
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 2, ExpectedVersion: 0, Reason: "收紧数量上限",
		RequestID: "req-retention",
	}); err != nil {
		t.Fatalf("保存保留策略失败: %v", err)
	}
	preview, err := e.admin.CleanupPreview(e.ctx, e.caller)
	if err != nil {
		t.Fatalf("清理预览失败: %v", err)
	}
	if len(preview.Targets) != 1 || preview.Targets[0].BackupID != seedA.BackupID {
		t.Fatalf("数量上限候选 = %+v，期望仅最早 A", preview.Targets)
	}
	protected := make(map[string]string, len(preview.Protected))
	for _, item := range preview.Protected {
		protected[item.BackupID] = item.Reason
	}
	if protected[seedB.BackupID] == "" || !strings.Contains(protected[seedB.BackupID], "最后一份可用") {
		t.Fatalf("最新可用备份未受保护: %+v", preview.Protected)
	}
	if protected[unknown.BackupID] == "" || !strings.Contains(protected[unknown.BackupID], "未知") {
		t.Fatalf("未校验产物未按未知保护: %+v", preview.Protected)
	}
	// 容量上限边界：总容量 400 字节、上限 150 → 需释放 250；A(100)+C(100) 仍不足，
	// 受保护的 B/D 不被删除，预览如实标注。
	preview, err = e.admin.CleanupPreview(e.ctx, e.caller)
	if err != nil {
		t.Fatalf("清理预览失败: %v", err)
	}
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxTotalBytes: 150, ExpectedVersion: preview.Policy.Version,
		Reason: "收紧容量上限", RequestID: "req-capacity",
	}); err != nil {
		t.Fatalf("保存容量策略失败: %v", err)
	}
	preview, err = e.admin.CleanupPreview(e.ctx, e.caller)
	if err != nil {
		t.Fatalf("容量预览失败: %v", err)
	}
	if len(preview.Targets) != 2 {
		t.Fatalf("容量候选数 = %d，期望 2（A、C）", len(preview.Targets))
	}
	if !strings.Contains(preview.Note, "保护规则") {
		t.Fatalf("容量超限时预览缺少保护说明: %q", preview.Note)
	}
	// 执行清理：A、C 删除，B（最后可用）与 D（未知）保留。
	ref, err := e.admin.EnqueueCleanup(e.ctx, e.caller, "req-cleanup")
	if err != nil {
		t.Fatalf("提交清理任务失败: %v", err)
	}
	if err := e.runHandler(e.job(ref.JobID)); err != nil {
		t.Fatalf("清理处理器失败: %v", err)
	}
	refreshed := e.artifacts()
	states := make(map[string]backupadmin.ArtifactView, len(refreshed))
	for _, view := range refreshed {
		states[view.BackupID] = view
	}
	if states[seedA.BackupID].Cleanup != string(backupadmin.CleanupCleaned) {
		t.Fatalf("A 应已清理: %+v", states[seedA.BackupID])
	}
	if states[seedB.BackupID].Cleanup != string(backupadmin.CleanupRetained) {
		t.Fatalf("最后可用备份 B 不应被清理: %+v", states[seedB.BackupID])
	}
	if states[unknown.BackupID].Cleanup != string(backupadmin.CleanupRetained) {
		t.Fatalf("未知状态产物不应被清理: %+v", states[unknown.BackupID])
	}
	// 执行时再保护：B 成为唯一可用备份后再预览已无 A，不得按旧预览强删。
	preview, err = e.admin.CleanupPreview(e.ctx, e.caller)
	if err != nil {
		t.Fatalf("清理预览失败: %v", err)
	}
	if len(preview.Targets) != 0 {
		t.Fatalf("清理后仍存在候选 = %+v，期望 0", preview.Targets)
	}
	// 天数边界：仅保留 B 时启用 1 天上限（B 已 1 天整，边界按严格早于）。
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxAgeDays: 1, MaxTotalBytes: 1 << 30,
		ExpectedVersion: preview.Policy.Version, Reason: "按天保留", RequestID: "req-age",
	}); err != nil {
		t.Fatalf("保存天数策略失败: %v", err)
	}
	agePreview, err := e.admin.CleanupPreview(e.ctx, e.caller)
	if err != nil {
		t.Fatalf("天数预览失败: %v", err)
	}
	if len(agePreview.Targets) != 0 {
		t.Fatalf("最后可用备份不得因天数被清理: %+v", agePreview.Targets)
	}
}

// TestPermissionRevocationOnAttemptAndReconcile 验证任务尝试前失权拒绝执行，以及孤儿
// 成品对账登记为“可用性未知”且不可下载、受清理保护。
func TestPermissionRevocationOnAttemptAndReconcile(t *testing.T) {
	e := newEnv(t)
	ref, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-perm")
	if err != nil {
		t.Fatalf("提交备份失败: %v", err)
	}
	e.authz.deny(backupadmin.PermissionCreate)
	err = e.runHandler(e.job(ref.JobID))
	if !task.IsNonRetryable(err) {
		t.Fatalf("失权后处理器错误应不可重试，得到 %v", err)
	}
	if len(e.artifacts()) != 0 {
		t.Fatal("失权后不应产生备份产物")
	}
	e.authz.allow(backupadmin.PermissionCreate)
	// 构造一个真实存在的完整命名文件，但不登记（模拟发布成功审计前被强杀）。
	orphanID := "bkp_" + strings.Repeat("9", 32)
	orphanName := "login-backup_20261118T000000Z_" + orphanID + ".elnbak"
	orphanPath := filepath.Join(e.creator.dir, orphanName)
	if err := os.WriteFile(orphanPath, []byte("orphan-backup-bytes"), 0o600); err != nil {
		t.Fatalf("写入孤儿成品失败: %v", err)
	}
	// 用受控 Inspect 替身返回真实结构摘要（生产使用 backup.InspectFile）。
	e.admin = mustRebuildWithInspect(t, e, func(_ context.Context, path string) (backup.VerifyReport, error) {
		return backup.VerifyReport{
			StructuralValid: true, FormatVersion: 1, BackupID: orphanID,
			CreatedAt: testNow.Add(-24 * time.Hour), Host: "test-host",
			Database:       backup.DatabaseMeta{Engine: "sqlite", SchemaVersion: "0043"},
			Content:        backup.ContentMeta{Database: true, Attachments: backup.ContentStatus{Status: "not_configured"}, Config: backup.ContentStatus{Status: "not_configured"}},
			ManifestSHA256: strings.Repeat("d", 64), FileSHA256: strings.Repeat("e", 64),
			FileSize: 18, Encryption: backup.EncryptionSummary{PayloadCipherBytes: 18},
		}, nil
	})
	result, err := e.admin.Reconcile(e.ctx)
	if err != nil {
		t.Fatalf("对账失败: %v", err)
	}
	if result.Orphans != 1 || result.MissingFiles != 0 {
		t.Fatalf("对账结果 = %+v，期望 1 个孤儿", result)
	}
	views := e.artifacts()
	if len(views) != 1 || views[0].Verification != string(backupadmin.VerificationUnknown) {
		t.Fatalf("孤儿产物登记 = %+v，期望 unknown", views)
	}
	if views[0].Downloadable {
		t.Fatal("可用性未知的孤儿产物不得可下载")
	}
	if !strings.Contains(views[0].ProtectionReason, "未知") {
		t.Fatalf("孤儿产物应受保护: %q", views[0].ProtectionReason)
	}
	// 重复对账不应重复登记。
	result, err = e.admin.Reconcile(e.ctx)
	if err != nil || result.Orphans != 0 {
		t.Fatalf("重复对账结果 = %+v err=%v，期望 0 个新孤儿", result, err)
	}
}

// mustRebuildWithInspect 用受控孤儿检查器重建服务（其余依赖不变）。
func mustRebuildWithInspect(t *testing.T, e *env, inspect func(context.Context, string) (backup.VerifyReport, error)) *backupadmin.Service {
	t.Helper()
	service, err := backupadmin.New(backupadmin.Options{
		Backup: e.creator, Store: e.store, Scheduler: e.scheduler,
		SchedulerRelay: e.relay, Enqueuer: e.executor, Canceller: e.executor,
		TaskReader: e.executor, Authorizer: e.authz, Sensitive: e.sensitive,
		Audit: e.audit, Notifier: e.notifier, OutputDir: e.creator.dir,
		DefaultRetention: backupadmin.RetentionPolicy{
			Version: 1, MaxCount: 10, MaxAgeDays: 30, MaxTotalBytes: 1 << 30},
		DefaultNotifyTarget: "owner_mail", DownloadTTL: time.Minute,
		MaxPageDownloadBytes: 1 << 20, Inspect: inspect,
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("重建服务失败: %v", err)
	}
	return service
}

// TestInvalidScheduleRejected 验证拒绝 Local 时区与非法保留策略。
func TestInvalidScheduleRejected(t *testing.T) {
	e := newEnv(t)
	if _, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
		Caller: e.caller, Name: "本地时区", ScheduleType: task.ScheduleTypeDaily,
		Expression: "02:30", TimeZone: "Local", MissedPolicy: task.MissedSkip,
		MaxCatchUp: 1, Enabled: true,
	}); err == nil {
		t.Fatal("Local 时区应被拒绝")
	}
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, Reason: "无限保留", ExpectedVersion: 0,
	}); !errors.Is(err, backupadmin.ErrRetentionInvalid) {
		t.Fatalf("三项上限全禁用应拒绝，得到 %v", err)
	}
}

// TestUIAdapterIntegration 验证管理页适配器到真实备份服务/仓储的集成（不是 mock）：
// 能力位、历史列表、保留策略、任务详情的映射均来自真实 SQLite 与领域服务。
func TestUIAdapterIntegration(t *testing.T) {
	e := newEnv(t)
	e.seedArtifact(t, "a", e.now.Add(-time.Hour), 64, backupadmin.VerificationVerified)
	adapter, err := uiadminadapter.NewBackups(uiadminadapter.BackupsOptions{Admin: e.admin})
	if err != nil {
		t.Fatalf("构造备份页适配器失败: %v", err)
	}
	caps, err := adapter.Capabilities(e.ctx, testUserID)
	if err != nil || !caps.Read || !caps.Download || !caps.Cleanup {
		t.Fatalf("能力位 = %+v err=%v", caps, err)
	}
	artifacts, hasMore, err := adapter.ListArtifacts(e.ctx, testUserID,
		login.UIBackupArtifactQuery{Limit: 20})
	if err != nil || hasMore || len(artifacts) != 1 {
		t.Fatalf("历史列表 = %d hasMore=%v err=%v", len(artifacts), hasMore, err)
	}
	if !artifacts[0].IsLastUsable || artifacts[0].VerifiedAt.IsZero() {
		t.Fatalf("适配器丢失最后可用/校验状态: %+v", artifacts[0])
	}
	retention, err := adapter.Retention(e.ctx, testUserID)
	if err != nil || retention.MaxCount != 10 {
		t.Fatalf("保留策略 = %+v err=%v", retention, err)
	}
	preview, err := adapter.CleanupPreview(e.ctx, testUserID)
	if err != nil {
		t.Fatalf("清理预览失败: %v", err)
	}
	if preview.TotalRetained != 1 || len(preview.Targets) != 0 {
		t.Fatalf("预览 = %+v，唯一可用备份不应成为候选", preview)
	}
}
