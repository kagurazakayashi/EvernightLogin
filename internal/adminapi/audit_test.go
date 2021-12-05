package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// adminBaseTime 是审计集成测试的固定时钟基准。
var adminBaseTime = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// adminTestUserID 生成合法稳定用户 ID。
func adminTestUserID(index int) string {
	return fmt.Sprintf("usr_%032x", index)
}

// adminAuditEnv 是真实 SQLite + 真实 audit 写入 + 真实 auditops 服务的隔离环境。
type adminAuditEnv struct {
	t         *testing.T
	ctx       context.Context
	raw       *storagesqlite.Store
	audit     *auditsqlite.Store
	service   *auditops.Service
	server    *Server
	session   *stubSession
	outputDir string
	now       func() time.Time

	authorizer *adminFakeAuthorizer
	root       *adminFakeRoot
	sensitive  *adminFakeSensitive
	enqueuer   *adminFakeEnqueuer
	canceller  *adminFakeCanceller
	tasks      *adminFakeTasks
}

// newAdminAuditEnv 构造临时数据库、迁移、真实审计写入与真实 auditops 服务。
func newAdminAuditEnv(t *testing.T) *adminAuditEnv {
	t.Helper()
	ctx := context.Background()
	dir := testutil.TempDir(t)
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(dir, "adminapi.db")))
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
	store, err := auditopssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造 auditops 仓储失败: %v", err)
	}
	outputDir := filepath.Join(dir, "exports")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("创建导出目录失败: %v", err)
	}
	env := &adminAuditEnv{t: t, ctx: ctx, raw: raw, audit: auditStore,
		outputDir: outputDir, now: func() time.Time { return adminBaseTime }}
	env.authorizer = &adminFakeAuthorizer{grants: map[string]auditops.ScopeGrant{}}
	env.root = &adminFakeRoot{roots: map[string]bool{}}
	env.sensitive = &adminFakeSensitive{denied: map[string]bool{}}
	env.enqueuer = &adminFakeEnqueuer{}
	env.canceller = &adminFakeCanceller{}
	env.tasks = &adminFakeTasks{jobs: map[string]task.Job{}}
	recorder, err := audit.New(auditStore, audit.Options{Now: env.now})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	service, err := auditops.New(auditops.Options{
		Store: store, Audit: recorder, Authorizer: env.authorizer, Root: env.root,
		Sensitive: env.sensitive, Enqueuer: env.enqueuer, Canceller: env.canceller,
		Tasks: env.tasks, OutputDir: outputDir,
		MaxExportRows: 500, MaxBatchSize: 20, MaxPurgeRecords: 100, Now: env.now,
	})
	if err != nil {
		t.Fatalf("构造 auditops 服务失败: %v", err)
	}
	env.service = service
	env.session = &stubSession{secret: "management-secret",
		userID: adminTestUserID(4)}
	server, err := New(Options{Session: env.session, ErrorCodes: testCodes(),
		Audit: service, Now: env.now})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	env.server = server
	return env
}

// call 以 Bearer 管理会话调用管理 API。
func (e *adminAuditEnv) call(method, path, body string) apiReply {
	e.t.Helper()
	return callAPI(e.t, e.server, method, path, body, "Bearer management-secret", nil)
}

// caller 返回与 stub 会话一致的可信调用者。
func (e *adminAuditEnv) caller() account.Caller {
	e.t.Helper()
	caller, err := account.UserCaller(adminTestUserID(4))
	if err != nil {
		e.t.Fatalf("构造调用者失败: %v", err)
	}
	return caller
}

// grant 设置授权结果。
func (e *adminAuditEnv) grant(permission, scopeID string, grant auditops.ScopeGrant) {
	e.authorizer.grants[adminTestUserID(4)+"|"+permission+"|"+scopeID] = grant
}

// revoke 撤销授权结果。
func (e *adminAuditEnv) revoke(permission, scopeID string) {
	delete(e.authorizer.grants, adminTestUserID(4)+"|"+permission+"|"+scopeID)
}

// setRoot 切换调用者 root 身份。
func (e *adminAuditEnv) setRoot(isRoot bool) { e.root.roots[adminTestUserID(4)] = isRoot }

// seed 直接写入一条审计事件（真实 audit 规范化与 SQLite）。
func (e *adminAuditEnv) seed(action, appID, actorID string, at time.Time) string {
	e.t.Helper()
	prepared, err := audit.PrepareEvent(audit.Event{
		Actor:  audit.Actor{Type: audit.ActorUser, ID: actorID},
		AppID:  appID,
		Action: action, Target: audit.Target{Type: "user", ID: "target_1"},
		Outcome: audit.OutcomeSuccess}, at)
	if err != nil {
		e.t.Fatalf("准备审计事件失败: %v", err)
	}
	if err := e.audit.Append(e.ctx, prepared); err != nil {
		e.t.Fatalf("写入审计事件失败: %v", err)
	}
	return prepared.ID
}

// countAuditAction 统计指定动作与结果的审计事件数。
func (e *adminAuditEnv) countAuditAction(action, outcome string) int {
	e.t.Helper()
	var count int
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = ? AND outcome = ?`,
		action, outcome).Scan(&count); err != nil {
		e.t.Fatalf("统计审计事件失败: %v", err)
	}
	return count
}

// TestAuditQueryPermissionsAndDataScope 验证管理审计查询：无权限拒绝、数据范围
// 在存储层生效、撤权后立即失效。
func TestAuditQueryPermissionsAndDataScope(t *testing.T) {
	env := newAdminAuditEnv(t)
	env.seed("user.update", "app_1", adminTestUserID(5), adminBaseTime.Add(-3*time.Hour))
	env.seed("user.update", "app_2", adminTestUserID(5), adminBaseTime.Add(-2*time.Hour))
	systemID := env.seed("task.run", "", "system_worker", adminBaseTime.Add(-time.Hour))

	// 无 audit.read：明确拒绝。
	reply := env.call(http.MethodGet, "/admin/v1/audit/events?scope_id=system", "")
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	// 授予全数据范围后可见全部系统范围事件。
	env.grant(auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	data := requireSuccess(t, env.call(http.MethodGet,
		"/admin/v1/audit/events?scope_id=system", ""))
	events, _ := data["events"].([]any)
	if len(events) < 3 {
		t.Fatalf("全范围事件数 = %d，期望至少 3", len(events))
	}

	// 数据范围收窄到 app_1 后只能看到该应用事件。
	env.grant(auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}})
	data = requireSuccess(t, env.call(http.MethodGet,
		"/admin/v1/audit/events?scope_id=system", ""))
	events, _ = data["events"].([]any)
	if len(events) == 0 {
		t.Fatalf("数据范围收缩后未返回 app_1 事件")
	}
	for _, raw := range events {
		event, _ := raw.(map[string]any)
		if appID, _ := event["app_id"].(string); appID != "app_1" {
			t.Fatalf("数据范围收缩后返回了其他应用/系统事件: %v", event)
		}
	}

	// 事件详情同样受权限与保留期状态约束。
	env.grant(auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	detail := requireSuccess(t, env.call(http.MethodGet,
		"/admin/v1/audit/events/"+systemID+"?scope_id=system", ""))
	event, _ := detail["event"].(map[string]any)
	if event["id"] != systemID {
		t.Fatalf("事件详情编号不符: %v", event)
	}
	env.revoke(auditops.PermissionRead, auditops.ScopeSystem)
	reply = env.call(http.MethodGet, "/admin/v1/audit/events/"+systemID+"?scope_id=system", "")
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
}

// TestAuditExportSensitiveReauthAuditAndDownload 验证导出：敏感策略拒绝时
// fail-closed、成功路径写真实审计、产物可下载、撤权后下载被拒绝。
func TestAuditExportSensitiveReauthAuditAndDownload(t *testing.T) {
	env := newAdminAuditEnv(t)
	env.seed("user.update", "app_1", adminTestUserID(5), adminBaseTime.Add(-3*time.Hour))
	env.grant(auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})

	// 缺少显式确认：参数错误，不进入敏感策略与服务调用。
	reply := env.call(http.MethodPost, "/admin/v1/audit/exports",
		`{"format":"csv","scope_id":"system"}`)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")

	// 敏感策略未通过：导出请求必须被拒绝，且不产生成功导出记录。
	env.sensitive.denied[auditops.OperationExport] = true
	reply = env.call(http.MethodPost, "/admin/v1/audit/exports",
		`{"confirm":true,"format":"csv","scope_id":"system"}`)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	// 允许敏感策略后创建导出任务（异步 queued，不等于完成）。
	delete(env.sensitive.denied, auditops.OperationExport)
	if got := env.countAuditAction(auditops.ActionExportRequest, string(audit.OutcomeSuccess)); got != 0 {
		t.Fatalf("被拒绝的导出不应产生成功请求审计，实际 %d", got)
	}
	data := requireSuccess(t, env.call(http.MethodPost, "/admin/v1/audit/exports",
		`{"confirm":true,"format":"csv","scope_id":"system"}`))
	export, _ := data["export"].(map[string]any)
	exportID, _ := export["id"].(string)
	if exportID == "" || export["state"] != auditops.ExportQueued {
		t.Fatalf("导出视图不符: %v", export)
	}
	if got := env.countAuditAction(auditops.ActionExportRequest, string(audit.OutcomeSuccess)); got != 1 {
		t.Fatalf("成功导出应写 1 条 %s 审计，实际 %d",
			auditops.ActionExportRequest, got)
	}

	// 用真实处理器执行导出任务，产物落盘。
	taskID, _ := export["task_id"].(string)
	enqueued := env.enqueuer.last
	job := task.Job{ID: taskID, Kind: enqueued.Kind, Initiator: enqueued.Actor,
		ExecutorID: "worker_1", Payload: enqueued.Payload,
		RequestID: enqueued.RequestID, MaxAttempts: enqueued.MaxAttempts}
	if err := env.service.ExportHandler(env.ctx, job); err != nil {
		t.Fatalf("执行导出任务失败: %v", err)
	}
	detail := requireSuccess(t, env.call(http.MethodGet,
		"/admin/v1/audit/exports/"+exportID, ""))
	finished, _ := detail["export"].(map[string]any)
	if finished["state"] != auditops.ExportSucceeded || finished["file_available"] != true {
		t.Fatalf("导出终态不符: %v", finished)
	}

	// 下载：真实 CSV 字节，不包含宿主路径。
	download := callAPI(t, env.server, http.MethodGet,
		"/admin/v1/audit/exports/"+exportID+"/download", "", "Bearer management-secret", nil)
	if download.status != http.StatusOK {
		t.Fatalf("下载状态 = %d，期望 200，响应=%s", download.status, string(download.body))
	}
	if !strings.Contains(string(download.body), "occurred_at") &&
		!strings.Contains(string(download.body), "action") {
		t.Fatalf("导出文件内容不符: %s", string(download.body))
	}
	if strings.Contains(string(download.body), env.outputDir) {
		t.Fatalf("导出响应泄露了宿主路径")
	}
	if contentType := download.header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("导出 Content-Type = %q", contentType)
	}

	// 撤销导出权限：下载与详情立即被拒绝。
	env.revoke(auditops.PermissionExport, auditops.ScopeSystem)
	reply = callAPI(t, env.server, http.MethodGet,
		"/admin/v1/audit/exports/"+exportID, "", "Bearer management-secret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	reply = callAPI(t, env.server, http.MethodGet,
		"/admin/v1/audit/exports/"+exportID+"/download", "", "Bearer management-secret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
}

// TestAuditRetentionAndPurgeRequireRootReauthConfirm 验证保留策略与清理：root 与
// 敏感策略缺一不可、确认/原因/digest 语义、以及保留策略版本并发。
func TestAuditRetentionAndPurgeRequireRootReauthConfirm(t *testing.T) {
	env := newAdminAuditEnv(t)

	// 非 root 设置保留策略：拒绝。
	reply := env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"confirm":true,"retention_days":30,"reason":"测试","expected_version":0}`)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	env.setRoot(true)
	// root 但敏感策略未通过：拒绝。
	env.sensitive.denied[auditops.OperationPurge] = true
	reply = env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"confirm":true,"retention_days":30,"reason":"测试","expected_version":0}`)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	delete(env.sensitive.denied, auditops.OperationPurge)

	// 缺少确认/原因：参数错误，不调用服务。
	reply = env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"retention_days":30,"reason":"测试","expected_version":0}`)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	reply = env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"confirm":true,"retention_days":30,"expected_version":0}`)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")

	// 成功设置保留策略并写真实审计。
	data := requireSuccess(t, env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"confirm":true,"retention_days":30,"reason":"测试保留期","expected_version":0}`))
	retention, _ := data["retention"].(map[string]any)
	if retention["days"].(float64) != 30 {
		t.Fatalf("保留策略天数不符: %v", retention)
	}
	if got := env.countAuditAction(auditops.ActionRetentionSet, string(audit.OutcomeSuccess)); got != 1 {
		t.Fatalf("设置保留策略应写 1 条审计，实际 %d", got)
	}

	// 版本冲突：期望版本过期返回 409。
	reply = env.call(http.MethodPut, "/admin/v1/audit/retention",
		`{"confirm":true,"retention_days":60,"reason":"测试保留期","expected_version":0}`)
	requireErrorCode(t, reply, http.StatusConflict, "CONFLICT")

	// 清理预估：root 专属只读操作，返回绑定参数的摘要。
	cutoff := adminBaseTime.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	data = requireSuccess(t, env.call(http.MethodPost, "/admin/v1/audit/purge/preview",
		`{"scope_id":"system","cutoff":"`+cutoff+`","batch_size":5,"max_records":10}`))
	preview, _ := data["purge_preview"].(map[string]any)
	digest, _ := preview["digest"].(string)
	if digest == "" {
		t.Fatalf("清理预估缺少 digest: %v", preview)
	}

	// 提交清理缺少确认/digest：参数错误。
	reply = env.call(http.MethodPost, "/admin/v1/audit/purge",
		`{"scope_id":"system","cutoff":"`+cutoff+`","digest":"`+digest+`","reason":"测试清理"}`)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	reply = env.call(http.MethodPost, "/admin/v1/audit/purge",
		`{"confirm":true,"scope_id":"system","cutoff":"`+cutoff+`","reason":"测试清理"}`)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")

	// 错误 digest（参数被篡改）：服务层冲突拒绝。
	reply = env.call(http.MethodPost, "/admin/v1/audit/purge",
		`{"confirm":true,"scope_id":"system","cutoff":"`+cutoff+`","digest":"tampered","reason":"测试清理"}`)
	requireErrorCode(t, reply, http.StatusConflict, "CONFLICT")

	// 正确 digest 提交清理任务（queued 不等于完成）。
	data = requireSuccess(t, env.call(http.MethodPost, "/admin/v1/audit/purge",
		`{"confirm":true,"scope_id":"system","cutoff":"`+cutoff+`","batch_size":5,"max_records":10,"digest":"`+digest+`","reason":"测试清理"}`))
	run, _ := data["purge_run"].(map[string]any)
	if run["state"] != auditops.PurgeQueued || run["task_id"] == "" {
		t.Fatalf("清理任务视图不符: %v", run)
	}
}

// 下面是审计集成测试使用的最小授权/敏感/任务替身：替换的是领域服务的鉴权
// 接缝（与 auditops 自身测试一致），业务逻辑与审计写入仍是真实的。
type adminFakeAuthorizer struct {
	mu     sync.Mutex
	grants map[string]auditops.ScopeGrant
}

func (f *adminFakeAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	grant, found := f.grants[caller.Actor().ID+"|"+permissionKey+"|"+scopeID]
	if !found {
		return auditops.ScopeGrant{}, nil
	}
	return grant, nil
}

type adminFakeRoot struct {
	mu    sync.Mutex
	roots map[string]bool
}

func (f *adminFakeRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roots[caller.Actor().ID], nil
}

type adminFakeSensitive struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (f *adminFakeSensitive) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied[request.OperationID] {
		return reauth.Result{}, fmt.Errorf("%w: 需要再次认证", reauth.ErrReauthRequired)
	}
	return reauth.Result{OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID,
		UserID: caller.Actor().ID, RequestID: request.RequestID}, nil
}

func (f *adminFakeSensitive) NotifyOutcome(_ context.Context, _ reauth.Result,
	_ reauth.Outcome) error {
	return nil
}

type adminFakeEnqueuer struct {
	mu   sync.Mutex
	last task.EnqueueRequest
}

func (f *adminFakeEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = request
	return task.Job{ID: fmt.Sprintf("job_%032x", 1), Kind: request.Kind,
		State: task.StateQueued, Initiator: request.Actor, Payload: request.Payload,
		TimeoutSeconds: request.TimeoutSeconds, MaxAttempts: request.MaxAttempts,
		RequestID: request.RequestID, CreatedAt: adminBaseTime}, nil
}

type adminFakeCanceller struct {
	mu sync.Mutex
}

func (f *adminFakeCanceller) RequestCancel(_ context.Context,
	_ task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelRequested}, nil
}

type adminFakeTasks struct {
	mu   sync.Mutex
	jobs map[string]task.Job
}

func (f *adminFakeTasks) Get(_ context.Context, id string) (task.Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, found := f.jobs[id]
	return job, found, nil
}

// 编译期确认测试替身满足领域接缝。
var (
	_ auditops.Authorizer      = (*adminFakeAuthorizer)(nil)
	_ auditops.RootChecker     = (*adminFakeRoot)(nil)
	_ auditops.SensitiveRunner = (*adminFakeSensitive)(nil)
	_ auditops.Enqueuer        = (*adminFakeEnqueuer)(nil)
	_ auditops.Canceller       = (*adminFakeCanceller)(nil)
	_ auditops.TaskReader      = (*adminFakeTasks)(nil)
	_                          = errors.Is
	_                          = session.DefaultCookieName
)
