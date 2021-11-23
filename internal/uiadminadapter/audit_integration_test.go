package uiadminadapter_test

// 步骤 74 审计页适配器真实服务集成测试：使用真实 SQLite + 真实 internal/audit 写入
// 与 internal/auditops（查询/详情/导出/清理）验证页面契约到领域服务的授权、披露、
// 状态机与范围隔离。边界处（权限引擎、root 判定、再次认证、任务执行）使用测试替身，
// 不把替身当作生产鉴权；真实任务执行器与浏览器页面另列未实测项。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var integrationNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// testUserID 生成格式合法的稳定用户 ID。
func testUserID(index int) string { return fmt.Sprintf("usr_%032x", index) }

// fakeAuthorizer 是权限判定替身：只按 (权限键, 作用范围) 白名单放行。
type fakeAuthorizer struct {
	grants map[string]auditops.ScopeGrant
}

func (f *fakeAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	key := caller.Actor().ID + "|" + permissionKey + "|" + scopeID
	if grant, ok := f.grants[key]; ok {
		return grant, nil
	}
	return auditops.ScopeGrant{Allowed: false}, nil
}

// fakeRoot 是 root 判定替身。
type fakeRoot struct{ roots map[string]bool }

func (f *fakeRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	return f.roots[caller.Actor().ID], nil
}

// fakeSensitive 是敏感操作替身：默认放行，denied 集合模拟再次认证不足。
type fakeSensitive struct{ denied map[string]bool }

func (f *fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	if f.denied[request.OperationID] {
		return reauth.Result{}, errors.New("再次认证不足")
	}
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (f *fakeSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// fakeEnqueuer 是任务入队替身：返回 queued 任务并记录载荷。
type fakeEnqueuer struct {
	next  int
	last  task.EnqueueRequest
	kinds []string
}

func (f *fakeEnqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	f.next++
	f.last = request
	f.kinds = append(f.kinds, request.Kind)
	return task.Job{ID: fmt.Sprintf("job_%032x", f.next), Kind: request.Kind,
		State: task.StateQueued, Payload: request.Payload, RequestID: request.RequestID,
		CreatedAt: integrationNow}, nil
}

// fakeCanceller 是取消替身：按 nextState 返回真实取消/取消已请求。
type fakeCanceller struct {
	nextState task.State
	err       error
	calls     int
}

func (f *fakeCanceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	f.calls++
	if f.err != nil {
		return task.CancelResult{}, f.err
	}
	state := f.nextState
	if state == "" {
		state = task.StateCancelRequested
	}
	return task.CancelResult{Accepted: true, State: state}, nil
}

// fakeTaskStore 是任务只读替身，用于详情关联任务摘要。
type fakeTaskStore struct {
	jobs map[string]task.Job
}

func (f *fakeTaskStore) Get(_ context.Context, id string) (task.Job, bool, error) {
	job, ok := f.jobs[id]
	return job, ok, nil
}

// captureStore 记录 Recorder 实际写入的事件 ID，供详情测试使用。
type captureStore struct {
	audit.Store
	events []audit.Event
}

func (c *captureStore) Append(ctx context.Context, event audit.Event) error {
	c.events = append(c.events, event)
	return c.Store.Append(ctx, event)
}

// integrationEnv 是真实 SQLite + 真实 audit/auditops 的隔离环境。
type integrationEnv struct {
	t          *testing.T
	ctx        context.Context
	audit      *auditsqlite.Store
	store      *auditopssqlite.Store
	service    *auditops.Service
	recorder   *audit.Recorder
	capture    *captureStore
	adapter    *uiadminadapter.AuditAdapter
	authorizer *fakeAuthorizer
	root       *fakeRoot
	sensitive  *fakeSensitive
	enqueuer   *fakeEnqueuer
	canceller  *fakeCanceller
	tasks      *fakeTaskStore
	outputDir  string
}

func newIntegrationEnv(t *testing.T, rootUserIDs ...string) *integrationEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx,
		storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "auditpage.db")))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	opStore, err := auditopssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造 auditops 仓储失败: %v", err)
	}
	env := &integrationEnv{t: t, ctx: ctx, audit: auditStore, store: opStore,
		outputDir: testutil.TempDir(t)}
	env.capture = &captureStore{Store: auditStore}
	recorder, err := audit.New(env.capture, audit.Options{
		Now: func() time.Time { return integrationNow }})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	env.recorder = recorder
	env.authorizer = &fakeAuthorizer{grants: map[string]auditops.ScopeGrant{
		auditops.PermissionRead + "|" + auditops.ScopeSystem:   {Allowed: true, AllData: true},
		auditops.PermissionExport + "|" + auditops.ScopeSystem: {Allowed: true, AllData: true},
	}}
	env.root = &fakeRoot{roots: map[string]bool{}}
	for _, userID := range rootUserIDs {
		env.root.roots[userID] = true
	}
	env.sensitive = &fakeSensitive{denied: map[string]bool{}}
	env.enqueuer = &fakeEnqueuer{}
	env.canceller = &fakeCanceller{}
	env.tasks = &fakeTaskStore{jobs: map[string]task.Job{}}
	service, err := auditops.New(auditops.Options{
		Store: opStore, Audit: recorder, Authorizer: env.authorizer, Root: env.root,
		Sensitive: env.sensitive, Enqueuer: env.enqueuer, Canceller: env.canceller,
		OutputDir: env.outputDir, MaxExportRows: 500, MaxBatchSize: 20,
		MaxPurgeRecords: 100, RetentionDays: 180,
		Now:    func() time.Time { return integrationNow },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造 auditops 服务失败: %v", err)
	}
	env.service = service
	env.adapter, err = uiadminadapter.NewAudit(uiadminadapter.AuditOptions{
		Audit: service, Authorizer: env.authorizer, Recorder: recorder, Tasks: env.tasks,
		IsRoot: func(_ context.Context, userID string) (bool, error) {
			return env.root.roots[userID], nil
		},
		RestrictedDiagnosis: func(_ context.Context, userID string) (bool, error) {
			return env.root.roots[userID], nil
		},
	})
	if err != nil {
		t.Fatalf("构造审计页适配器失败: %v", err)
	}
	return env
}

// allow 为指定用户授予系统作用范围的权限（测试替身，不代表生产授权）。
func (e *integrationEnv) allow(userID, permission string) {
	e.authorizer.grants[userID+"|"+permission+"|"+auditops.ScopeSystem] =
		auditops.ScopeGrant{Allowed: true, AllData: true}
}

// recordUserEvent 通过真实审计写入记录一条用户事件并返回事件 ID。
func (e *integrationEnv) recordUserEvent(actorID, action, outcome string) string {
	e.t.Helper()
	before := len(e.capture.events)
	err := e.recorder.Record(e.ctx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorUser, ID: actorID},
		Action: action, Target: audit.Target{Type: "session", ID: "sess_1"},
		Outcome: audit.Outcome(outcome), RequestID: "req_integration"})
	if err != nil {
		e.t.Fatalf("写入审计事件失败: %v", err)
	}
	if len(e.capture.events) <= before {
		e.t.Fatal("审计 Recorder 未写入事件")
	}
	return e.capture.events[len(e.capture.events)-1].ID
}

// backdateEvent 直接写入一条历史事件（用于保留期/清理测试）。
func (e *integrationEnv) backdateEvent(id string, occurredAt time.Time) {
	e.t.Helper()
	event := audit.Event{ID: id, OccurredAt: occurredAt,
		Actor:  audit.Actor{Type: audit.ActorUser, ID: testUserID(90)},
		Action: "permission.grant", Target: audit.Target{Type: "user", ID: "usr_target"},
		Outcome: audit.OutcomeSuccess}
	normalized, err := audit.NormalizeEvent(event)
	if err != nil {
		e.t.Fatalf("构造历史事件失败: %v", err)
	}
	if err := e.audit.Append(e.ctx, normalized); err != nil {
		e.t.Fatalf("写入历史事件失败: %v", err)
	}
}

func publicErrorCode(err error) string {
	var publicErr *login.UIAuditError
	if errors.As(err, &publicErr) {
		return publicErr.Code
	}
	return ""
}

// TestAuditAdapterQueryAndDetail 验证列表筛选、范围隔离与详情披露状态都来自真实
// auditops 服务（授权、存储范围与保留期由服务判定）。
func TestAuditAdapterQueryAndDetail(t *testing.T) {
	env := newIntegrationEnv(t)
	actor := testUserID(1)
	env.allow(actor, auditops.PermissionRead)
	eventID := env.recordUserEvent(actor, "session.revoke", "success")

	page, err := env.adapter.ListAudit(env.ctx, actor, login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem, Filter: login.UIAuditFilter{RequestID: "req_integration"},
		Order: "occurred_desc", Limit: 20})
	if err != nil {
		t.Fatalf("列表查询失败: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != eventID {
		t.Fatalf("列表结果 = %+v", page.Events)
	}
	detail, err := env.adapter.GetAudit(env.ctx, actor, eventID, time.Time{})
	if err != nil {
		t.Fatalf("详情查询失败: %v", err)
	}
	if detail.Event.ID != eventID || detail.Event.Outcome != "success" {
		t.Fatalf("详情 = %+v", detail)
	}
	// 不存在：披露为查无记录。
	if _, err := env.adapter.GetAudit(env.ctx, actor, fmt.Sprintf("aud_%032x", 999),
		integrationNow); publicErrorCode(err) != "NOT_FOUND" {
		t.Fatalf("不存在详情错误码 = %v", err)
	}
	// 发生时间早于保留边界：披露为已过保留期。
	if _, err := env.adapter.GetAudit(env.ctx, actor, fmt.Sprintf("aud_%032x", 998),
		integrationNow.AddDate(0, 0, -400)); publicErrorCode(err) != "RETENTION_EXPIRED" {
		t.Fatalf("保留期详情错误码 = %v", err)
	}
	// 跨应用筛选：授权范围只含 system 且非 allData 时服务拒绝。
	env.authorizer.grants[testUserID(2)+"|"+auditops.PermissionRead+"|"+auditops.ScopeSystem] =
		auditops.ScopeGrant{Allowed: true, AllData: false, ResourceIDs: []string{"app_allowed"}}
	if _, err := env.adapter.ListAudit(env.ctx, testUserID(2), login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem,
		Filter:  login.UIAuditFilter{AppID: "app_other"}, Limit: 20}); publicErrorCode(err) != "ACCESS_DENIED" {
		t.Fatalf("跨应用筛选错误码 = %v", err)
	}
	// 无 audit.read 授权的用户被拒绝。
	if _, err := env.adapter.ListAudit(env.ctx, testUserID(3), login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem, Limit: 20}); publicErrorCode(err) != "ACCESS_DENIED" {
		t.Fatalf("未授权用户列表错误码 = %v", err)
	}
}

// TestAuditAdapterOwnActivityIsolation 验证普通用户只能读取本人安全活动。
func TestAuditAdapterOwnActivityIsolation(t *testing.T) {
	env := newIntegrationEnv(t)
	self := testUserID(11)
	other := testUserID(12)
	ownID := env.recordUserEvent(self, "password.change", "success")
	otherID := env.recordUserEvent(other, "password.change", "failure")

	page, err := env.adapter.QueryOwnActivity(env.ctx, self, login.UIAuditQuery{Limit: 20})
	if err != nil {
		t.Fatalf("本人活动查询失败: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != ownID {
		t.Fatalf("本人活动混入他人记录: %+v", page.Events)
	}
	// 显式传入他人操作者筛选也不能越权：服务固定为本人。
	page, err = env.adapter.QueryOwnActivity(env.ctx, self, login.UIAuditQuery{
		Filter: login.UIAuditFilter{ActorType: "user", ActorID: other}, Limit: 20})
	if err != nil {
		t.Fatalf("本人活动筛选查询失败: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != ownID {
		t.Fatalf("筛选他人操作者后越权: %+v", page.Events)
	}
	// 读取他人事件统一按不存在处理（不泄露存在性）。
	if _, err := env.adapter.GetOwnActivity(env.ctx, self, otherID, time.Time{}); publicErrorCode(err) != "NOT_FOUND" {
		t.Fatalf("读取他人事件错误码 = %v", err)
	}
	if _, err := env.adapter.GetOwnActivity(env.ctx, self, ownID, time.Time{}); err != nil {
		t.Fatalf("读取本人事件失败: %v", err)
	}
}

// TestAuditAdapterExportLifecycle 验证导出创建、列表、详情、未完成下载拒绝与取消
// 状态机（取消请求被接受 ≠ 实际取消；queued 被取消进入真实取消终态）。
func TestAuditAdapterExportLifecycle(t *testing.T) {
	env := newIntegrationEnv(t)
	actor := testUserID(21)
	env.allow(actor, auditops.PermissionExport)
	env.recordUserEvent(actor, "session.revoke", "success")

	export, err := env.adapter.CreateExport(env.ctx, actor, login.UIAuditExportRequest{
		ScopeID: auditops.ScopeSystem, Filter: login.UIAuditFilter{Outcome: "success"},
		Order: "occurred_desc", Format: "csv", RequestID: "req_export_it"})
	if err != nil {
		t.Fatalf("创建导出失败: %v", err)
	}
	if export.State != auditops.ExportQueued || export.TaskID == "" {
		t.Fatalf("导出创建结果 = %+v", export)
	}
	if len(env.enqueuer.kinds) != 1 || env.enqueuer.kinds[0] != auditops.TaskKindAuditExport {
		t.Fatalf("导出任务未入队: %+v", env.enqueuer.kinds)
	}
	list, err := env.adapter.ListExports(env.ctx, actor, auditops.ScopeSystem, "", 20, 0)
	if err != nil || len(list.Exports) != 1 || list.Exports[0].ID != export.ID {
		t.Fatalf("导出列表 = %+v err=%v", list, err)
	}
	// 任务尚未成功：下载被拒绝，且不把任务状态改成失败。
	if _, err := env.adapter.DownloadExport(env.ctx, actor, export.ID); publicErrorCode(err) != "CONFLICT" {
		t.Fatalf("未完成导出下载错误码 = %v", err)
	}
	if got, err := env.adapter.GetExport(env.ctx, actor, export.ID); err != nil ||
		got.State != auditops.ExportQueued {
		t.Fatalf("下载失败改变了任务状态: %+v err=%v", got, err)
	}
	// 取消请求已接受但仍在收尾：状态保持 cancel_requested。
	env.canceller.nextState = task.StateCancelRequested
	cancelled, err := env.adapter.CancelExport(env.ctx, actor, export.ID, "owner request",
		"req_cancel_it")
	if err != nil {
		t.Fatalf("取消导出失败: %v", err)
	}
	if cancelled.State != "cancel_requested" {
		t.Fatalf("取消请求状态 = %q，期望 cancel_requested", cancelled.State)
	}
	// 真实取消终态：执行器回报 queued 直接取消时记录收敛为 cancelled。
	env.canceller.nextState = task.StateCancelled
	cancelled, err = env.adapter.CancelExport(env.ctx, actor, export.ID, "owner request",
		"req_cancel_it2")
	if err != nil {
		t.Fatalf("再次取消导出失败: %v", err)
	}
	if cancelled.State != "cancelled" {
		t.Fatalf("实际取消状态 = %q，期望 cancelled", cancelled.State)
	}
}

// TestAuditAdapterPurgeRootOnlyAndPreview 验证 root 门槛、只读预估与真实清理任务
// 提交/取消状态；非 root 一律拒绝。
func TestAuditAdapterPurgeRootOnlyAndPreview(t *testing.T) {
	rootID := testUserID(31)
	env := newIntegrationEnv(t, rootID)
	env.backdateEvent(fmt.Sprintf("aud_%032x", 500), integrationNow.AddDate(0, 0, -400))
	env.backdateEvent(fmt.Sprintf("aud_%032x", 501), integrationNow.AddDate(0, 0, -300))

	cutoff := integrationNow.AddDate(0, 0, -200)
	// 非 root（即便有 audit.read）：预估与提交都拒绝。
	if _, err := env.adapter.PreviewPurge(env.ctx, testUserID(32),
		login.UIPurgeRequest{ScopeID: auditops.ScopeSystem, Cutoff: cutoff,
			BatchSize: 20, MaxRecords: 100}); publicErrorCode(err) != "ACCESS_DENIED" {
		t.Fatalf("非 root 预估错误码 = %v", err)
	}
	// root 只读预估：返回真实预估与保护/产物边界。
	preview, err := env.adapter.PreviewPurge(env.ctx, rootID, login.UIPurgeRequest{
		ScopeID: auditops.ScopeSystem, Cutoff: cutoff, BatchSize: 20, MaxRecords: 100})
	if err != nil {
		t.Fatalf("root 预估失败: %v", err)
	}
	if preview.EstimatedCount < 2 || preview.MaintenanceProtected != true ||
		preview.ArtifactsIncluded {
		t.Fatalf("预估结果 = %+v", preview)
	}
	if preview.Digest == "" {
		t.Fatal("预估缺少提交摘要")
	}
	// 预估不是删除：记录仍在。
	if page, err := env.adapter.ListAudit(env.ctx, rootID, login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem, Limit: 20}); err != nil || len(page.Events) < 2 {
		t.Fatalf("预估删除了记录？events=%d err=%v", len(page.Events), err)
	}
	// 提交清理：只表示已受理，返回 queued 任务。
	run, err := env.adapter.StartPurge(env.ctx, rootID, login.UIPurgeRequest{
		ScopeID: auditops.ScopeSystem, Cutoff: cutoff, BatchSize: 20, MaxRecords: 100},
		preview.Digest, "integration cleanup", "req_purge_it")
	if err != nil {
		t.Fatalf("提交清理失败: %v", err)
	}
	if run.State != auditops.PurgeQueued || run.TaskID == "" {
		t.Fatalf("清理提交结果 = %+v", run)
	}
	if len(env.enqueuer.kinds) == 0 ||
		env.enqueuer.kinds[len(env.enqueuer.kinds)-1] != auditops.TaskKindAuditPurge {
		t.Fatalf("清理任务未入队: %+v", env.enqueuer.kinds)
	}
	// 取消请求：返回 cancel_requested，不伪造已取消。
	env.canceller.nextState = task.StateCancelRequested
	cancelled, err := env.adapter.CancelPurge(env.ctx, rootID, run.ID, "stop", "req_purge_cancel")
	if err != nil {
		t.Fatalf("取消清理失败: %v", err)
	}
	if cancelled.State != "cancel_requested" {
		t.Fatalf("清理取消状态 = %q", cancelled.State)
	}
}

// TestAuditAdapterRestrictedDiagnosisGate 验证受限原因码只在独立诊断权限通过后
// 返回；公开调用者拿不到内部原因。
func TestAuditAdapterRestrictedDiagnosisGate(t *testing.T) {
	rootID := testUserID(41)
	env := newIntegrationEnv(t)
	// 通过真实存储写入带受限原因码的事件。
	event := audit.Event{ID: fmt.Sprintf("aud_%032x", 600), OccurredAt: integrationNow,
		Actor:  audit.Actor{Type: audit.ActorUser, ID: testUserID(42)},
		Action: "permission.grant", Target: audit.Target{Type: "user", ID: "usr_target"},
		Outcome: audit.OutcomeDenied, ErrorCode: "ACCESS_DENIED",
		ReasonCode: "owner_mismatch"}
	normalized, err := audit.NormalizeEvent(event)
	if err != nil {
		t.Fatalf("构造受限事件失败: %v", err)
	}
	if err := env.audit.Append(env.ctx, normalized); err != nil {
		t.Fatalf("写入受限事件失败: %v", err)
	}
	env.allow(testUserID(43), auditops.PermissionRead)
	noDiag, err := env.adapter.GetAudit(env.ctx, testUserID(43), event.ID, time.Time{})
	if err != nil {
		t.Fatalf("公开详情失败: %v", err)
	}
	if noDiag.RestrictedReasonCode != "" || noDiag.Restricted {
		t.Fatalf("无诊断权限仍返回受限原因: %+v", noDiag)
	}
	// 授予 root（同样是独立诊断许可来源）后可见原因码。
	env.root.roots[rootID] = true
	allowed, err := env.adapter.GetAudit(env.ctx, rootID, event.ID, time.Time{})
	if err != nil {
		t.Fatalf("受限诊断详情失败: %v", err)
	}
	if allowed.RestrictedReasonCode != "owner_mismatch" || !allowed.Restricted {
		t.Fatalf("受限原因码未展示: %+v", allowed)
	}
}

// TestAuditAdapterCapabilities 验证清理能力位只对真实 root 打开（呈现辅助）。
func TestAuditAdapterCapabilities(t *testing.T) {
	rootID := testUserID(51)
	env := newIntegrationEnv(t, rootID)
	// 未获 audit.read/audit.export 的合法用户：能力位必须为 false（不能无条件 true）。
	denied, err := env.adapter.Capabilities(env.ctx, testUserID(52))
	if err != nil || denied.Read || denied.Export || denied.Purge {
		t.Fatalf("未授权用户能力位 = %+v err=%v", denied, err)
	}
	// 真实授权后读取/导出能力位打开；清理仍只对 root。
	normalID := testUserID(53)
	env.allow(normalID, auditops.PermissionRead)
	env.allow(normalID, auditops.PermissionExport)
	normal, err := env.adapter.Capabilities(env.ctx, normalID)
	if err != nil || !normal.Read || !normal.Export || normal.Purge {
		t.Fatalf("普通管理员能力位 = %+v err=%v", normal, err)
	}
	rootCaps, err := env.adapter.Capabilities(env.ctx, rootID)
	if err != nil || !rootCaps.Read || !rootCaps.Export || !rootCaps.Purge {
		// 与 internal/auditops 一致：root 旁路普通 audit.read/audit.export 授权，
		// 页面能力位与后端判定统一，避免 root 被页面 403 而服务层本可访问。
		t.Fatalf("root 能力位 = %+v err=%v", rootCaps, err)
	}
	if _, err := env.adapter.Capabilities(env.ctx, "not-a-user"); publicErrorCode(err) != "ACCESS_DENIED" {
		t.Fatalf("非法用户能力位错误码 = %v", err)
	}
	// root 未获普通授权也可经真实 auditops 读取列表与错误码目录（与后端旁路一致）。
	env.recordUserEvent(rootID, "session.revoke", "success")
	if page, err := env.adapter.ListAudit(env.ctx, rootID, login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem, Limit: 20}); err != nil || len(page.Events) == 0 {
		t.Fatalf("root 列表被页面适配器拒绝: %+v err=%v", page, err)
	}
	if search, err := env.adapter.SearchErrors(env.ctx, rootID, login.UIErrorQuery{
		Code: "ACCESS_DENIED"}); err != nil || len(search.Entries) != 1 {
		t.Fatalf("root 错误码目录被拒绝: %+v err=%v", search, err)
	}
}

// TestAuditAdapterErrorCatalogAuthorization 验证错误码检索同样需要真实 audit.read，
// 越权被拒绝，且页面级拒绝可写失败审计。
func TestAuditAdapterErrorCatalogAuthorization(t *testing.T) {
	env := newIntegrationEnv(t)
	reader := testUserID(61)
	env.allow(reader, auditops.PermissionRead)
	allowed, err := env.adapter.SearchErrors(env.ctx, reader, login.UIErrorQuery{
		Code: "ACCESS_DENIED"})
	if err != nil || len(allowed.Entries) != 1 {
		t.Fatalf("授权用户错误码检索 = %+v err=%v", allowed, err)
	}
	denied, err := env.adapter.SearchErrors(env.ctx, testUserID(62), login.UIErrorQuery{})
	if publicErrorCode(err) != "ACCESS_DENIED" || len(denied.Entries) != 0 {
		t.Fatalf("未授权错误码检索 = %+v err=%v", denied, err)
	}
	// 页面级拒绝留痕：写 audit.access.denied（含稳定原因标记，不含用户输入）。
	if err := env.adapter.RecordDenial(env.ctx, reader, "csrf_invalid"); err != nil {
		t.Fatalf("拒绝留痕失败: %v", err)
	}
	found := false
	for _, event := range env.capture.events {
		if event.Action == auditops.ActionAccessDenied &&
			event.Outcome == audit.OutcomeDenied && event.ReasonCode == "csrf_invalid" {
			found = true
		}
	}
	if !found {
		t.Fatal("页面拒绝未写入失败审计")
	}
}

// TestAuditAdapterRelatedTaskSummary 验证详情关联任务摘要由真实任务读取契约提供。
func TestAuditAdapterRelatedTaskSummary(t *testing.T) {
	env := newIntegrationEnv(t)
	actor := testUserID(71)
	env.allow(actor, auditops.PermissionRead)
	taskID := "job_abcdef"
	env.tasks.jobs[taskID] = task.Job{ID: taskID, Kind: "audit.export",
		State: task.StateRunning, Attempt: 2, MaxAttempts: 3,
		ErrorCode: "", FailureReason: "上次尝试超时"}
	eventID := fmt.Sprintf("aud_%032x", 700)
	event := audit.Event{ID: eventID, OccurredAt: integrationNow,
		Actor: audit.Actor{Type: audit.ActorUser, ID: actor}, Action: "session.revoke",
		Target:  audit.Target{Type: "session", ID: "sess_1"},
		Outcome: audit.OutcomeSuccess, TaskID: taskID}
	normalized, err := audit.NormalizeEvent(event)
	if err != nil {
		t.Fatalf("构造关联任务事件失败: %v", err)
	}
	if err := env.audit.Append(env.ctx, normalized); err != nil {
		t.Fatalf("写入关联任务事件失败: %v", err)
	}
	detail, err := env.adapter.GetAudit(env.ctx, actor, eventID, time.Time{})
	if err != nil {
		t.Fatalf("读取详情失败: %v", err)
	}
	if detail.RelatedTask == nil || detail.RelatedTask.ID != taskID ||
		detail.RelatedTask.State != "running" || detail.RelatedTask.Attempt != 2 {
		t.Fatalf("关联任务摘要 = %+v", detail.RelatedTask)
	}
}
