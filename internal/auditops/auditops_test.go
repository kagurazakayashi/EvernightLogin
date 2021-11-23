package auditops_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// baseTime 是测试固定时钟；所有测试事件以它为基准相对生成。
var baseTime = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// testUserID 生成格式合法的稳定用户 ID，供 account.Caller 构造。
func testUserID(index int) string {
	return fmt.Sprintf("usr_%032x", index)
}

// testEnv 是使用真实 SQLite + 真实 audit 写入的隔离测试环境。
type testEnv struct {
	t         *testing.T
	ctx       context.Context
	raw       *storagesqlite.Store
	audit     *auditsqlite.Store
	store     *auditopssqlite.Store
	service   *auditops.Service
	recorder  *audit.Recorder
	outputDir string
	now       func() time.Time

	authorizer *fakeAuthorizer
	root       *fakeRoot
	sensitive  *fakeSensitive
	enqueuer   *fakeEnqueuer
	canceller  *fakeCanceller
	tasks      *fakeTasks
}

// newTestEnv 构造临时数据库与完整依赖。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "auditops.db")
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
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
	env := &testEnv{t: t, ctx: ctx, raw: raw, audit: auditStore, store: store,
		outputDir: testutil.TempDir(t), now: func() time.Time { return baseTime }}
	env.authorizer = &fakeAuthorizer{grants: map[string]auditops.ScopeGrant{}}
	env.root = &fakeRoot{roots: map[string]bool{}}
	env.sensitive = &fakeSensitive{denied: map[string]bool{}}
	env.enqueuer = &fakeEnqueuer{now: env.now}
	env.canceller = &fakeCanceller{}
	env.tasks = &fakeTasks{jobs: map[string]task.Job{}}
	recorder, err := audit.New(auditStore, audit.Options{Now: env.now})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	service, err := auditops.New(auditops.Options{
		Store: store, Audit: recorder, Authorizer: env.authorizer, Root: env.root,
		Sensitive: env.sensitive, Enqueuer: env.enqueuer, Canceller: env.canceller,
		Tasks: env.tasks, OutputDir: env.outputDir,
		MaxExportRows: 500, MaxBatchSize: 20, MaxPurgeRecords: 100,
		Now: env.now,
	})
	if err != nil {
		t.Fatalf("构造 auditops 服务失败: %v", err)
	}
	env.recorder = recorder
	env.service = service
	return env
}

// userCaller 构造普通用户调用者。
func userCaller(t *testing.T, id string) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(id)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

// grant 设置授权结果。
func (e *testEnv) grant(userID, permission, scopeID string, grant auditops.ScopeGrant) {
	e.authorizer.grants[userID+"|"+permission+"|"+scopeID] = grant
}

// revoke 撤销授权结果。
func (e *testEnv) revoke(userID, permission, scopeID string) {
	delete(e.authorizer.grants, userID+"|"+permission+"|"+scopeID)
}

// withStore 用替换的存储构造同配置服务（用于故障/取消注入测试）。
func (e *testEnv) withStore(store auditops.Store) *auditops.Service {
	e.t.Helper()
	service, err := auditops.New(auditops.Options{
		Store: store, Audit: e.recorder, Authorizer: e.authorizer, Root: e.root,
		Sensitive: e.sensitive, Enqueuer: e.enqueuer, Canceller: e.canceller,
		Tasks: e.tasks, OutputDir: e.outputDir,
		MaxExportRows: 500, MaxBatchSize: 20, MaxPurgeRecords: 100, Now: e.now,
	})
	if err != nil {
		e.t.Fatalf("构造替换存储服务失败: %v", err)
	}
	return service
}

// setRoot 设置 root 身份。
func (e *testEnv) setRoot(userID string) { e.root.roots[userID] = true }

// allowSensitive 允许敏感操作。
func (e *testEnv) allowSensitive(operationID string) {
	delete(e.sensitive.denied, operationID)
}

// denySensitive 拒绝敏感操作。
func (e *testEnv) denySensitive(operationID string) {
	e.sensitive.denied[operationID] = true
}

// allowPurgeWithRetention 允许清理敏感操作并把保留期设为 days 天，使测试截止时间
// 位于保留期边界之前（手动清理强制要求）。
func (e *testEnv) allowPurgeWithRetention(days int) {
	e.t.Helper()
	e.allowSensitive(auditops.OperationPurge)
	if _, err := e.service.SetRetention(e.ctx, auditops.SetRetentionRequest{
		Caller:        userCaller(e.t, testUserID(4)),
		RetentionDays: days, Reason: "测试保留期", RequestID: "req_retention_setup"}); err != nil {
		e.t.Fatalf("测试设置保留策略失败: %v", err)
	}
}

// seed 直接写入一条审计事件（走真实 audit 规范化与 SQLite）。
func (e *testEnv) seed(event audit.Event, at time.Time) string {
	e.t.Helper()
	prepared, err := audit.PrepareEvent(event, at)
	if err != nil {
		e.t.Fatalf("准备审计事件失败: %v", err)
	}
	if err := e.audit.Append(e.ctx, prepared); err != nil {
		e.t.Fatalf("写入审计事件失败: %v", err)
	}
	return prepared.ID
}

// event 构造测试事件。
func event(action, appID, actorID string, outcome audit.Outcome) audit.Event {
	return audit.Event{
		Actor: audit.Actor{Type: audit.ActorUser, ID: actorID}, AppID: appID,
		Action: action, Target: audit.Target{Type: "user", ID: "target_1"},
		Outcome: outcome,
	}
}

// countEvents 直接查询 audit_events 行数。
func (e *testEnv) countEvents(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果")
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return count
}

// cancellingStore 在第一次清理批次时注入取消，用于验证取消终态。
type cancellingStore struct {
	auditops.Store
	cancel context.CancelFunc
}

func (c *cancellingStore) PurgeBatch(ctx context.Context,
	command auditops.PurgeBatchCommand) (auditops.PurgedBatch, error) {
	c.cancel()
	return c.Store.PurgeBatch(ctx, command)
}

// fakeAuthorizer 是可控的作用范围授权器。
type fakeAuthorizer struct {
	mu     sync.Mutex
	grants map[string]auditops.ScopeGrant
}

func (f *fakeAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	grant, found := f.grants[caller.Actor().ID+"|"+permissionKey+"|"+scopeID]
	if !found {
		return auditops.ScopeGrant{}, nil
	}
	return grant, nil
}

// fakeRoot 是可控 root 判定器。
type fakeRoot struct {
	mu    sync.Mutex
	roots map[string]bool
}

func (f *fakeRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roots[caller.Actor().ID], nil
}

// fakeSensitive 是可控敏感操作校验器。
type fakeSensitive struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (f *fakeSensitive) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied[request.OperationID] {
		return reauth.Result{}, errors.New("reauth required")
	}
	return reauth.Result{OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID,
		UserID: caller.Actor().ID, RequestID: request.RequestID}, nil
}

func (f *fakeSensitive) NotifyOutcome(_ context.Context, _ reauth.Result,
	_ reauth.Outcome) error {
	return nil
}

// fakeEnqueuer 记录入队请求并返回可控任务。
type fakeEnqueuer struct {
	mu      sync.Mutex
	now     func() time.Time
	last    task.EnqueueRequest
	count   int
	failure error
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = request
	f.count++
	if f.failure != nil {
		return task.Job{}, f.failure
	}
	return task.Job{ID: fmt.Sprintf("job_%032x", f.count), Kind: request.Kind,
		State: task.StateQueued, Initiator: request.Actor, Payload: request.Payload,
		TimeoutSeconds: request.TimeoutSeconds, MaxAttempts: request.MaxAttempts,
		RequestID: request.RequestID, CreatedAt: f.now()}, nil
}

// fakeCanceller 记录取消请求。
type fakeCanceller struct {
	mu      sync.Mutex
	last    task.CancelRequest
	failure error
	// state 模拟 RequestCancel 后的真实任务状态；默认取消请求已接受。
	state task.State
}

func (f *fakeCanceller) RequestCancel(_ context.Context,
	request task.CancelRequest) (task.CancelResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = request
	if f.failure != nil {
		return task.CancelResult{}, f.failure
	}
	state := f.state
	if state == "" {
		state = task.StateCancelRequested
	}
	return task.CancelResult{Accepted: true, State: state}, nil
}

// fakeTasks 返回预设任务状态。
type fakeTasks struct {
	mu   sync.Mutex
	jobs map[string]task.Job
}

func (f *fakeTasks) Get(_ context.Context, id string) (task.Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, found := f.jobs[id]
	return job, found, nil
}

// TestQueryDataScopeEnforcedInStore 验证数据范围由授权结果决定，跨范围筛选被拒绝，
// 普通用户只能看本人活动。
func TestQueryDataScopeEnforcedInStore(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	actor := userCaller(t, testUserID(1))
	eventIDApp1 := env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-3*time.Hour))
	env.seed(event("user.update", "app_2", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-2*time.Hour))
	systemID := env.seed(event("task.run", "", "system_worker", audit.OutcomeFailure),
		baseTime.Add(-time.Hour))

	// 只获准 app_1 时，系统范围查询只能看到 app_1 事件。
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}})
	result, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != eventIDApp1 {
		t.Fatalf("数据范围查询结果 = %+v", result.Events)
	}
	// 显式筛选范围外应用直接拒绝，而不是静默返回空。
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem, Filter: auditops.Filter{AppID: "app_2"}}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("范围外应用筛选错误 = %v，期望 ErrAccessDenied", err)
	}
	// 只获准 system 资源时只能看系统级事件。
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{auditops.ScopeSystem}})
	result, err = env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem})
	if err != nil {
		t.Fatalf("系统级事件查询失败: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != systemID {
		t.Fatalf("系统级事件查询结果 = %+v", result.Events)
	}
	// 未获准的调用者默认拒绝。
	actor2 := userCaller(t, testUserID(2))
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor2,
		ScopeID: auditops.ScopeSystem}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("未授权查询错误 = %v，期望 ErrAccessDenied", err)
	}
	// 应用范围只返回该应用事件。
	env.grant(testUserID(1), auditops.PermissionRead, "app_1",
		auditops.ScopeGrant{Allowed: true, AllData: true})
	result, err = env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: "app_1"})
	if err != nil || len(result.Events) != 1 || result.Events[0].AppID != "app_1" {
		t.Fatalf("应用范围查询 = %+v err=%v", result.Events, err)
	}
}

// TestOwnActivityOnlySelf 验证普通用户只能看到本人安全活动。
func TestOwnActivityOnlySelf(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	ownID := env.seed(event("profile.update", "app_1", testUserID(3), audit.OutcomeSuccess),
		baseTime.Add(-2*time.Hour))
	env.seed(event("profile.update", "app_1", testUserID(2), audit.OutcomeSuccess),
		baseTime.Add(-1*time.Hour))
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		baseTime.Add(-30*time.Minute))
	result, err := env.service.QueryOwnActivity(ctx, auditops.OwnQueryRequest{
		Caller: userCaller(t, testUserID(3))})
	if err != nil {
		t.Fatalf("本人活动查询失败: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != ownID {
		t.Fatalf("本人活动结果 = %+v", result.Events)
	}
	// 他人在本人查询中不可见；直接读取他人事件按不存在处理。
	env.seed(event("profile.update", "app_1", testUserID(2), audit.OutcomeSuccess),
		baseTime.Add(-10*time.Minute))
	other := env.seed(event("profile.update", "app_1", testUserID(2), audit.OutcomeDenied),
		baseTime.Add(-9*time.Minute))
	if _, err := env.service.GetOwnEvent(ctx, userCaller(t, testUserID(3)), other,
		time.Time{}); !errors.Is(err, auditops.ErrNotFound) {
		t.Fatalf("读取他人事件错误 = %v，期望 ErrNotFound", err)
	}
}

// TestPaginationStableAndHasMore 验证同一时间戳下分页稳定、无重复/漏项、HasMore。
func TestPaginationStableAndHasMore(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	occurredAt := baseTime.Add(-time.Hour)
	ids := map[string]bool{}
	for index := 0; index < 25; index++ {
		id := env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
			occurredAt)
		ids[id] = true
	}
	seen := map[string]bool{}
	offset := 0
	for page := 0; page < 2; page++ {
		result, err := env.service.Query(ctx, auditops.QueryRequest{
			Caller: userCaller(t, testUserID(1)), ScopeID: auditops.ScopeSystem,
			Limit: 10, Offset: offset})
		if err != nil {
			t.Fatalf("分页查询失败: %v", err)
		}
		if len(result.Events) != 10 {
			t.Fatalf("第 %d 页条数 = %d", page, len(result.Events))
		}
		for _, record := range result.Events {
			if seen[record.ID] {
				t.Fatalf("分页出现重复事件: %s", record.ID)
			}
			seen[record.ID] = true
		}
		if !result.HasMore {
			t.Fatalf("第 %d 页 HasMore = false", page)
		}
		offset += 10
	}
	result, err := env.service.Query(ctx, auditops.QueryRequest{
		Caller: userCaller(t, testUserID(1)), ScopeID: auditops.ScopeSystem,
		Limit: 10, Offset: offset})
	if err != nil {
		t.Fatalf("末页查询失败: %v", err)
	}
	if len(result.Events) != 5 || result.HasMore {
		t.Fatalf("末页 = %d 条 HasMore=%v", len(result.Events), result.HasMore)
	}
	for _, record := range result.Events {
		if seen[record.ID] {
			t.Fatalf("分页出现重复事件: %s", record.ID)
		}
		seen[record.ID] = true
	}
	if len(seen) != 25 {
		t.Fatalf("分页读取唯一事件 = %d，期望 25", len(seen))
	}
	// 默认倒序：同一时间按事件 ID 倒序，稳定次序可重复。
	first, err := env.service.Query(ctx, auditops.QueryRequest{
		Caller: userCaller(t, testUserID(1)), ScopeID: auditops.ScopeSystem, Limit: 10})
	if err != nil {
		t.Fatalf("默认批次查询失败: %v", err)
	}
	second, err := env.service.Query(ctx, auditops.QueryRequest{
		Caller: userCaller(t, testUserID(1)), ScopeID: auditops.ScopeSystem, Limit: 10})
	if err != nil {
		t.Fatalf("重复批次查询失败: %v", err)
	}
	for index := range first.Events {
		if first.Events[index].ID != second.Events[index].ID {
			t.Fatalf("分页次序不稳定: index %d", index)
		}
	}
}

// TestFilterValidationRejectsMalicious 验证恶意/非法筛选被拒绝而不是拼进 SQL。
func TestFilterValidationRejectsMalicious(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	caller := userCaller(t, testUserID(1))
	cases := []struct {
		name   string
		filter auditops.Filter
		limit  int
		offset int
		order  auditops.SortOrder
	}{
		{name: "SQL 注入动作", filter: auditops.Filter{Action: "user.update' OR '1'='1"}},
		{name: "SQL 注入请求编号", filter: auditops.Filter{RequestID: "req'--"}},
		{name: "未知结果", filter: auditops.Filter{Outcome: audit.Outcome("unknown")}},
		{name: "非法错误码", filter: auditops.Filter{ErrorCode: "drop table"}},
		{name: "操作者缺少类型", filter: auditops.Filter{ActorID: testUserID(5)}},
		{name: "非法操作者类型", filter: auditops.Filter{ActorType: audit.ActorKind("root")}},
		{name: "时间倒置", filter: auditops.Filter{From: baseTime,
			To: baseTime.Add(-time.Hour)}},
		{name: "未来结束时间", filter: auditops.Filter{To: baseTime.Add(48 * time.Hour)}},
		{name: "系统与应同时指定", filter: auditops.Filter{SystemOnly: true, AppID: "app_1"}},
		{name: "超长动作", filter: auditops.Filter{Action: strings.Repeat("a", 129)}},
		{name: "控制字符目标", filter: auditops.Filter{TargetID: "a\x01b"}},
		{name: "非法排序", order: auditops.SortOrder("id desc; drop table")},
		{name: "非法分页大小", limit: 101},
		{name: "负分页偏移", offset: -1},
		{name: "超深分页", offset: auditops.MaxOffset + 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := env.service.Query(ctx, auditops.QueryRequest{
				Caller: caller, ScopeID: auditops.ScopeSystem, Filter: testCase.filter,
				Limit: testCase.limit, Offset: testCase.offset, Order: testCase.order})
			if !errors.Is(err, auditops.ErrInvalidRequest) && !errors.Is(err, auditops.ErrAccessDenied) {
				t.Fatalf("非法筛选错误 = %v，期望 ErrInvalidRequest/ErrAccessDenied", err)
			}
		})
	}
	// 合法精确筛选仍可命中（参数化 SQL，不把注入当条件）。
	id := env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	result, err := env.service.Query(ctx, auditops.QueryRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem,
		Filter: auditops.Filter{Action: "user.update", Outcome: audit.OutcomeSuccess}})
	if err != nil || len(result.Events) != 1 || result.Events[0].ID != id {
		t.Fatalf("合法筛选结果 = %+v err=%v", result.Events, err)
	}
}

// TestExportRequiresIndependentPermission 验证导出独立授权、敏感校验与限量。
func TestExportRequiresIndependentPermission(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	// 只有 audit.read 没有 audit.export：导出被拒绝。
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	if _, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem,
		Format: auditops.FormatCSV}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("缺少导出权限错误 = %v，期望 ErrAccessDenied", err)
	}
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	// 敏感操作拒绝：不创建任务。
	env.denySensitive(auditops.OperationExport)
	if _, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem,
		Format: auditops.FormatCSV}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("敏感校验拒绝错误 = %v，期望 ErrAccessDenied", err)
	}
	if env.enqueuer.count != 0 {
		t.Fatalf("敏感校验拒绝后不应入队")
	}
	// 超过单次上限拒绝。
	env.allowSensitive(auditops.OperationExport)
	if _, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem,
		Format: auditops.FormatCSV, MaxRows: 501}); !errors.Is(err, auditops.ErrInvalidRequest) {
		t.Fatalf("超限导出错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestExportAsyncRedactionAndControlledArtifact 验证异步导出、脱敏、受控产物与
// 权限撤销后不可下载。
func TestExportAsyncRedactionAndControlledArtifact(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	// 写入含敏感差异（密码）与受限原因码的事件。
	sensitiveEvent := event("user.password.change", "app_1", testUserID(5), audit.OutcomeSuccess)
	sensitiveEvent.ReasonCode = "internal_timing"
	sensitiveEvent.RequestID = "req_export_1"
	sensitiveEvent.Changes = []audit.FieldChange{
		{Field: "password", Before: "hunter2", After: "hunter3"},
		{Field: "status", Before: "active", After: "active"},
	}
	env.seed(sensitiveEvent, baseTime.Add(-time.Hour))

	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV,
		Filter: auditops.Filter{To: baseTime}, RequestID: "req_export_1"})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	if view.State != auditops.ExportQueued || view.TaskID == "" {
		t.Fatalf("导出任务视图 = %+v", view)
	}
	if !strings.HasPrefix(view.TaskID, "job_") {
		t.Fatalf("导出任务编号 = %q", view.TaskID)
	}
	// 执行异步处理器。
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditExport,
		Initiator: caller.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload, RequestID: "req_export_1"}
	if err := env.service.ExportHandler(ctx, job); err != nil {
		t.Fatalf("导出处理失败: %v", err)
	}
	detail, err := env.service.GetExport(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("读取导出任务失败: %v", err)
	}
	if detail.State != auditops.ExportSucceeded || detail.RowCount != 1 || !detail.FileAvailable {
		t.Fatalf("导出完成视图 = %+v", detail)
	}
	file, err := env.service.OpenExportFile(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("打开受控产物失败: %v", err)
	}
	if filepath.Dir(file.HostPath) != env.outputDir {
		t.Fatalf("产物不在受控目录: %s", file.HostPath)
	}
	content, err := os.ReadFile(file.HostPath)
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != file.SHA256 {
		t.Fatalf("产物摘要不一致")
	}
	text := string(content)
	if strings.Contains(text, "hunter2") || strings.Contains(text, "hunter3") {
		t.Fatalf("导出泄露敏感值")
	}
	if !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("导出未保留脱敏标记: %s", text)
	}
	if strings.Contains(text, "internal_timing") {
		t.Fatalf("导出泄露受限原因码")
	}
	if !strings.Contains(text, "event_id") || !strings.Contains(text, "request_id") {
		t.Fatalf("导出字段白名单缺失: %s", text)
	}
	// 权限撤销后，旧任务不再可下载。
	env.revoke(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem)
	if _, err := env.service.OpenExportFile(ctx, caller, view.ID); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("撤销权限后下载错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestRetentionPolicyAndBoundary 验证 root 保留策略、版本冲突与保留期边界区分。
func TestRetentionPolicyAndBoundary(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	// 非 root 不能设置保留策略。
	if _, err := env.service.SetRetention(ctx, auditops.SetRetentionRequest{
		Caller: userCaller(t, testUserID(5)), RetentionDays: 30, Reason: "测试"}); !errors.Is(err, auditops.ErrRootRequired) {
		t.Fatalf("非 root 设置保留策略错误 = %v，期望 ErrRootRequired", err)
	}
	// root 但敏感策略拒绝。
	env.denySensitive(auditops.OperationPurge)
	if _, err := env.service.SetRetention(ctx, auditops.SetRetentionRequest{
		Caller: rootCaller, RetentionDays: 30, Reason: "调整保留期"}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("敏感校验拒绝错误 = %v，期望 ErrAccessDenied", err)
	}
	env.allowSensitive(auditops.OperationPurge)
	retention, err := env.service.SetRetention(ctx, auditops.SetRetentionRequest{
		Caller: rootCaller, RetentionDays: 30, Reason: "调整保留期"})
	if err != nil {
		t.Fatalf("设置保留策略失败: %v", err)
	}
	if !retention.Configured || retention.Days != 30 || retention.Version != 1 {
		t.Fatalf("保留策略 = %+v", retention)
	}
	// 旧版本页面不能覆盖新策略。
	if _, err := env.service.SetRetention(ctx, auditops.SetRetentionRequest{
		Caller: rootCaller, RetentionDays: 90, Reason: "旧页面",
		ExpectedVersion: 0}); !errors.Is(err, auditops.ErrConflict) {
		t.Fatalf("版本冲突错误 = %v，期望 ErrConflict", err)
	}
	// 保留期边界：过期缺失记录与从未存在区分（调用方提供发生时）。
	staleID := env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-40*24*time.Hour))
	env.grant(testUserID(4), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	detail, err := env.service.GetEvent(ctx, auditops.GetRequest{Caller: rootCaller,
		ScopeID: auditops.ScopeSystem, EventID: staleID})
	if err != nil {
		t.Fatalf("读取过期仍存在记录失败: %v", err)
	}
	if !detail.Stale {
		t.Fatalf("超过保留期的记录未标记 Stale")
	}
	if _, err := env.service.GetEvent(ctx, auditops.GetRequest{Caller: rootCaller,
		ScopeID: auditops.ScopeSystem, EventID: "aud_" + strings.Repeat("0", 32),
		OccurredAtHint: baseTime.Add(-40 * 24 * time.Hour)}); !errors.Is(err, auditops.ErrRetentionExpired) {
		t.Fatalf("过期缺失记录错误 = %v，期望 ErrRetentionExpired", err)
	}
	if _, err := env.service.GetEvent(ctx, auditops.GetRequest{Caller: rootCaller,
		ScopeID: auditops.ScopeSystem, EventID: "aud_" + strings.Repeat("0", 32),
		OccurredAtHint: baseTime.Add(-time.Hour)}); !errors.Is(err, auditops.ErrNotFound) {
		t.Fatalf("保留期内缺失记录错误 = %v，期望 ErrNotFound", err)
	}
}

// purgePreview 生成预览。
func (e *testEnv) purgePreview(caller account.Caller, scopeID string, cutoff time.Time,
	batchSize, maxRecords int) auditops.PurgePreview {
	e.t.Helper()
	preview, err := e.service.PreviewPurge(e.ctx, auditops.PurgePreviewRequest{
		Caller: caller, ScopeID: scopeID, Cutoff: cutoff,
		BatchSize: batchSize, MaxRecords: maxRecords})
	if err != nil {
		e.t.Fatalf("清理预估失败: %v", err)
	}
	return preview
}

// startPurge 提交清理任务并执行一次处理器。
func (e *testEnv) startPurge(caller account.Caller, preview auditops.PurgePreview) auditops.PurgeRunView {
	e.t.Helper()
	view, err := e.service.StartPurge(e.ctx, auditops.StartPurgeRequest{
		Caller: caller, ScopeID: preview.ScopeID, Cutoff: preview.Cutoff,
		BatchSize: preview.BatchSize, MaxRecords: preview.MaxRecords,
		Reason: "测试清理", Digest: preview.Digest, RequestID: "req_purge_1"})
	if err != nil {
		e.t.Fatalf("提交清理任务失败: %v", err)
	}
	return view
}

// runPurge 以给定上下文执行清理处理器。
func (e *testEnv) runPurge(ctx context.Context, view auditops.PurgeRunView,
	caller account.Caller) error {
	e.t.Helper()
	return e.service.PurgeHandler(ctx, task.Job{ID: view.TaskID,
		Kind: auditops.TaskKindAuditPurge, Initiator: caller.Actor(),
		ExecutorID: "worker_1", Payload: e.enqueuer.last.Payload,
		RequestID: "req_purge_1"})
}

// TestPurgeBatchesBoundaryAndProtectedAudit 验证分批、边界、保留期内不清理、
// 受保护清理审计不可删除、清理结果可追踪。
func TestPurgeBatchesBoundaryAndProtectedAudit(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	env.grant(testUserID(4), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	// 12 条系统级过期事件、2 条保留期内系统事件、2 条应用事件（不应被系统范围清理）。
	cutoff := baseTime.Add(-24 * time.Hour)
	for index := 0; index < 12; index++ {
		env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
	}
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		cutoff.Add(-time.Hour))
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 4, 5)
	if preview.EstimatedCount != 5 || !preview.AtLeast {
		t.Fatalf("预估 = %+v，期望至少 5 条", preview)
	}
	if !preview.MaintenanceProtected || preview.ArtifactsIncluded {
		t.Fatalf("预估保护标记错误: %+v", preview)
	}
	view := env.startPurge(rootCaller, preview)
	if view.State != auditops.PurgeQueued || view.TaskID == "" {
		t.Fatalf("清理视图 = %+v", view)
	}
	if err := env.runPurge(ctx, view, rootCaller); err != nil {
		t.Fatalf("执行清理失败: %v", err)
	}
	finished, err := env.service.GetPurgeRun(ctx, rootCaller, view.ID)
	if err != nil {
		t.Fatalf("读取清理结果失败: %v", err)
	}
	if finished.State != auditops.PurgeSucceeded || finished.Cleaned != 5 ||
		finished.Batches != 2 || !finished.LimitReached {
		t.Fatalf("清理结果 = %+v", finished)
	}
	// 保留期内系统事件仍存在；过期系统事件删 5 条后剩 7 条（按 action 过滤，
	// 清理自身写入的审计事件属于系统范围但不计入业务事件）。
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot IS NULL AND action='task.run'`); got != 8 {
		t.Fatalf("系统级业务事件剩余 = %d，期望 8（7 条过期 + 1 条保留期）", got)
	}
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot='app_1'`); got != 1 {
		t.Fatalf("应用事件被系统范围清理误删: %d", got)
	}
	// 清理自身的审计事件仍在，且受保护日志可追踪。
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE action='audit.purge.finish'`); got != 1 {
		t.Fatalf("清理审计事件 = %d，期望 1", got)
	}
	entries, err := env.service.MaintenanceLog(ctx, rootCaller, view.ID)
	if err != nil {
		t.Fatalf("读取受保护清理日志失败: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("受保护清理日志条数 = %d，期望至少 3（请求/批次/结果）", len(entries))
	}
	if entries[0].Action != auditops.ActionPurgeRequest {
		t.Fatalf("首条清理日志 = %+v", entries[0])
	}
	// 受保护日志禁止 UPDATE/DELETE。
	if _, err := env.raw.ExecContext(ctx,
		`DELETE FROM audit_maintenance_log WHERE run_id=?`, view.ID); err == nil {
		t.Fatalf("受保护清理日志被删除：触发器未生效")
	}
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE audit_maintenance_log SET result='tampered' WHERE run_id=?`, view.ID); err == nil {
		t.Fatalf("受保护清理日志被修改：触发器未生效")
	}
}

// TestPurgeRejectsNonRootAndStalePreview 验证非 root 拒绝、预估摘要过期拒绝与
// 取消运行的真实终态。
func TestPurgeRejectsNonRootAndStalePreview(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := baseTime.Add(-24 * time.Hour)
	for index := 0; index < 6; index++ {
		env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
	}
	// 非 root 不能预估/提交。
	if _, err := env.service.PreviewPurge(ctx, auditops.PurgePreviewRequest{
		Caller: userCaller(t, testUserID(5)), ScopeID: auditops.ScopeSystem,
		Cutoff: cutoff}); !errors.Is(err, auditops.ErrRootRequired) {
		t.Fatalf("非 root 预估错误 = %v", err)
	}
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	// 参数变化使旧摘要失效。
	if _, err := env.service.StartPurge(ctx, auditops.StartPurgeRequest{
		Caller: rootCaller, ScopeID: auditops.ScopeSystem, Cutoff: cutoff,
		BatchSize: 3, MaxRecords: 10, Reason: "参数变化", Digest: preview.Digest}); !errors.Is(err, auditops.ErrConflict) {
		t.Fatalf("摘要过期错误 = %v，期望 ErrConflict", err)
	}
	view := env.startPurge(rootCaller, preview)
	// 在第一批执行时注入取消：处理器写入真实取消终态（计数保留）。
	cancelledCtx, cancel := context.WithCancel(ctx)
	wrapped := &cancellingStore{Store: env.store, cancel: cancel}
	service := env.withStore(wrapped)
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditPurge,
		Initiator: rootCaller.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload, RequestID: "req_purge_1"}
	if err := service.PurgeHandler(cancelledCtx, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消清理错误 = %v，期望 context.Canceled", err)
	}
	finished, err := env.service.GetPurgeRun(ctx, rootCaller, view.ID)
	if err != nil {
		t.Fatalf("读取清理结果失败: %v", err)
	}
	if finished.State != auditops.PurgeCancelled {
		t.Fatalf("取消后清理状态 = %s，期望 cancelled", finished.State)
	}
	// 取消请求可追踪（提交取消请求不等于实际取消）。
	another := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	run := env.startPurge(rootCaller, another)
	result, err := env.service.CancelPurge(ctx, rootCaller, run.ID, "不再需要", "req_cancel_1")
	if err != nil || !result.Accepted {
		t.Fatalf("取消请求结果 = %+v err=%v", result, err)
	}
	if env.canceller.last.JobID != run.TaskID {
		t.Fatalf("取消请求任务编号 = %q", env.canceller.last.JobID)
	}
	// 非 root 不能取消。
	if _, err := env.service.CancelPurge(ctx, userCaller(t, testUserID(5)), run.ID,
		"越权", "req_cancel_2"); !errors.Is(err, auditops.ErrRootRequired) {
		t.Fatalf("非 root 取消错误 = %v", err)
	}
}

// TestAppScopePurgeOnlyAffectsApp 验证应用范围清理只影响该应用，系统事件保留。
func TestAppScopePurgeOnlyAffectsApp(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := baseTime.Add(-24 * time.Hour)
	for index := 0; index < 3; index++ {
		env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
		env.seed(event("user.update", "app_2", testUserID(5), audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
	}
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		cutoff.Add(-time.Hour))
	preview := env.purgePreview(rootCaller, "app_1", cutoff, 10, 100)
	if preview.EstimatedCount != 3 || preview.AtLeast {
		t.Fatalf("应用范围预估 = %+v", preview)
	}
	appView, err := env.service.StartPurge(ctx, auditops.StartPurgeRequest{
		Caller: rootCaller, ScopeID: "app_1", Cutoff: cutoff, BatchSize: 10,
		MaxRecords: 100, Reason: "应用范围清理", Digest: preview.Digest,
		RequestID: "req_purge_app"})
	if err != nil {
		t.Fatalf("提交应用范围清理失败: %v", err)
	}
	if err := env.runPurge(ctx, appView, rootCaller); err != nil {
		t.Fatalf("执行应用范围清理失败: %v", err)
	}
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot='app_1' AND action='user.update'`); got != 0 {
		t.Fatalf("应用 app_1 业务事件剩余 = %d，期望 0", got)
	}
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot='app_2' AND action='user.update'`); got != 3 {
		t.Fatalf("应用 app_2 事件 = %d，期望 3", got)
	}
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE app_id_snapshot IS NULL AND action='task.run'`); got != 1 {
		t.Fatalf("系统事件 = %d，期望 1", got)
	}
}

// TestExportSnapshotFilterAndDataScope 验证导出使用创建时筛选快照且数据范围收缩后
// 不再可下载（数据范围快照覆盖检查）。
func TestExportSnapshotFilterAndDataScope(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}})
	env.allowSensitive(auditops.OperationExport)
	env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-3*time.Hour))
	env.seed(event("user.update", "app_2", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-2*time.Hour))
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatJSON,
		Filter: auditops.Filter{To: baseTime}})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditExport,
		Initiator: caller.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload}
	if err := env.service.ExportHandler(ctx, job); err != nil {
		t.Fatalf("导出处理失败: %v", err)
	}
	detail, err := env.service.GetExport(ctx, caller, view.ID)
	if err != nil || detail.RowCount != 1 {
		t.Fatalf("导出范围 = %+v err=%v", detail, err)
	}
	// 数据范围收缩为 app_2 后，快照包含 app_1 不再被覆盖。
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_2"}})
	if _, err := env.service.OpenExportFile(ctx, caller, view.ID); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("数据范围收缩后下载错误 = %v，期望 ErrAccessDenied", err)
	}
	// 列表同样不再展示该任务。
	list, _, err := env.service.ListExports(ctx, auditops.ExportListRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem})
	if err != nil {
		t.Fatalf("导出列表失败: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("范围收缩后仍列出导出任务: %+v", list)
	}
}

// TestExportTaskInitiatorMismatchRejected 验证任务身份与 root 授权来源可追踪：
// 非发起者身份不能执行导出任务。
func TestExportTaskInitiatorMismatchRejected(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	impostor := userCaller(t, testUserID(2))
	err = env.service.ExportHandler(ctx, task.Job{ID: view.TaskID,
		Kind: auditops.TaskKindAuditExport, Initiator: impostor.Actor(),
		ExecutorID: "worker_1", Payload: env.enqueuer.last.Payload})
	if !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("伪造任务身份错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestRetentionDefaultAndValidation 验证未设置保留策略时的内置默认值与非法参数。
func TestRetentionDefaultAndValidation(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	info, err := env.service.Retention(ctx, userCaller(t, testUserID(5)))
	if err != nil {
		t.Fatalf("读取默认保留策略失败: %v", err)
	}
	if info.Days != auditops.DefaultRetentionDays || info.Configured {
		t.Fatalf("默认保留策略 = %+v", info)
	}
	env.allowSensitive(auditops.OperationPurge)
	invalid := []int{0, -1, auditops.MaxRetentionDays + 1}
	for _, days := range invalid {
		if _, err := env.service.SetRetention(ctx, auditops.SetRetentionRequest{
			Caller: rootCaller, RetentionDays: days, Reason: "非法"}); !errors.Is(err, auditops.ErrInvalidRequest) {
			t.Fatalf("非法保留天数 %d 错误 = %v", days, err)
		}
	}
}

// TestGetEventScopeCrossDenied 验证跨范围的详情读取被拒绝且不泄露正文。
func TestGetEventScopeCrossDenied(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}})
	app2ID := env.seed(event("user.update", "app_2", testUserID(5), audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	if _, err := env.service.GetEvent(ctx, auditops.GetRequest{Caller: caller,
		ScopeID: auditops.ScopeSystem, EventID: app2ID}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("跨范围详情错误 = %v，期望 ErrAccessDenied", err)
	}
	// 非法事件 ID 拒绝。
	if _, err := env.service.GetEvent(ctx, auditops.GetRequest{Caller: caller,
		ScopeID: auditops.ScopeSystem, EventID: "not-an-event"}); !errors.Is(err, auditops.ErrInvalidRequest) {
		t.Fatalf("非法事件 ID 错误 = %v", err)
	}
}

// TestPurgeDigestChangesWithData 验证预估后数据变化使提交失效（不能扩大范围）。
func TestPurgeDigestChangesWithData(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := baseTime.Add(-24 * time.Hour)
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		cutoff.Add(-time.Hour))
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	// 预估后新增一条更早的事件，计数变化使摘要失效。
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		cutoff.Add(-2*time.Hour))
	if _, err := env.service.StartPurge(ctx, auditops.StartPurgeRequest{
		Caller: rootCaller, ScopeID: auditops.ScopeSystem, Cutoff: cutoff,
		BatchSize: 2, MaxRecords: 10, Reason: "数据变化", Digest: preview.Digest}); !errors.Is(err, auditops.ErrConflict) {
		t.Fatalf("数据变化后提交错误 = %v，期望 ErrConflict", err)
	}
}

// TestExportLimitTruncated 验证导出行数上限产生真实 truncated 标记而不是假成功。
func TestExportLimitTruncated(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	for index := 0; index < 5; index++ {
		env.seed(event("user.update", "app_1", testUserID(5), audit.OutcomeSuccess),
			baseTime.Add(-time.Duration(index+1)*time.Minute))
	}
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatJSON,
		Filter: auditops.Filter{To: baseTime}, MaxRows: 3})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditExport,
		Initiator: caller.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload}
	if err := env.service.ExportHandler(ctx, job); err != nil {
		t.Fatalf("导出处理失败: %v", err)
	}
	detail, err := env.service.GetExport(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("读取导出任务失败: %v", err)
	}
	if detail.RowCount != 3 || !detail.Truncated {
		t.Fatalf("截断导出视图 = %+v", detail)
	}
	// JSON 导出是合法 JSON 数组自包含内容。
	file, err := env.service.OpenExportFile(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("打开产物失败: %v", err)
	}
	content, err := os.ReadFile(file.HostPath)
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(content, &rows); err != nil {
		t.Fatalf("JSON 导出内容无效: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("JSON 导出行数 = %d", len(rows))
	}
	_ = fmt.Sprintf("%v", rows)
}

// TestListExportsAndTaskSummary 验证导出列表与本包任务状态摘要。
func TestListExportsAndTaskSummary(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	env.tasks.jobs[view.TaskID] = task.Job{ID: view.TaskID,
		Kind: auditops.TaskKindAuditExport, State: task.StateCancelRequested,
		Initiator: caller.Actor(), Attempt: 1, MaxAttempts: 1,
		RequestID: "req_list_1", CreatedAt: baseTime}
	list, hasMore, err := env.service.ListExports(ctx, auditops.ExportListRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem})
	if err != nil {
		t.Fatalf("导出列表失败: %v", err)
	}
	if len(list) != 1 || hasMore {
		t.Fatalf("导出列表 = %+v hasMore=%v", list, hasMore)
	}
	if list[0].Task == nil || list[0].Task.State != string(task.StateCancelRequested) {
		t.Fatalf("导出任务摘要 = %+v", list[0].Task)
	}
}

// fakeAuthzChecker 是 internal/authz Check 的受控替身，用于验证数据范围映射。
type fakeAuthzChecker struct {
	result authz.CheckResult
	err    error
}

func (f *fakeAuthzChecker) Check(_ context.Context, _ authz.Caller,
	_ authz.CheckRequest) (authz.CheckResult, error) {
	return f.result, f.err
}

// TestAuthzAuthorizerMapsDataScope 验证生产授权适配器把数据范围正确映射为
// ScopeGrant，undefined/none/依赖失败默认拒绝。
func TestAuthzAuthorizerMapsDataScope(t *testing.T) {
	caller := userCaller(t, testUserID(1))
	cases := []struct {
		name   string
		result authz.CheckResult
		err    error
		want   auditops.ScopeGrant
	}{
		{name: "数据范围 all", result: authz.CheckResult{Allowed: true,
			Permissions: []authz.PermissionDecision{{Key: auditops.PermissionRead,
				Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeAll}}}},
			want: auditops.ScopeGrant{Allowed: true, AllData: true}},
		{name: "数据范围 resources", result: authz.CheckResult{Allowed: true,
			Permissions: []authz.PermissionDecision{{Key: auditops.PermissionRead,
				Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeResources,
					Resources: []string{"app_1"}}}}},
			want: auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}}},
		{name: "数据范围未声明", result: authz.CheckResult{Allowed: true,
			Permissions: []authz.PermissionDecision{{Key: auditops.PermissionRead,
				Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeUndefined}}}},
			want: auditops.ScopeGrant{Allowed: false}},
		{name: "数据范围 none", result: authz.CheckResult{Allowed: true,
			Permissions: []authz.PermissionDecision{{Key: auditops.PermissionRead,
				Allowed: true, DataScope: authz.DataScope{Mode: authz.DataScopeNone}}}},
			want: auditops.ScopeGrant{Allowed: false}},
		{name: "权限拒绝", result: authz.CheckResult{Allowed: false},
			want: auditops.ScopeGrant{Allowed: false}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			authorizer, err := auditops.NewAuthzAuthorizer(&fakeAuthzChecker{
				result: testCase.result, err: testCase.err})
			if err != nil {
				t.Fatalf("构造授权适配器失败: %v", err)
			}
			grant, err := authorizer.AuthorizeScope(context.Background(), caller,
				auditops.PermissionRead, auditops.ScopeSystem)
			if err != nil {
				t.Fatalf("授权适配器错误: %v", err)
			}
			if grant.Allowed != testCase.want.Allowed || grant.AllData != testCase.want.AllData ||
				strings.Join(grant.ResourceIDs, ",") != strings.Join(testCase.want.ResourceIDs, ",") {
				t.Fatalf("授权结果 = %+v，期望 %+v", grant, testCase.want)
			}
		})
	}
	// 依赖失败默认不授权。
	authorizer, err := auditops.NewAuthzAuthorizer(&fakeAuthzChecker{
		err: errors.New("authz unavailable")})
	if err != nil {
		t.Fatalf("构造授权适配器失败: %v", err)
	}
	if _, err := authorizer.AuthorizeScope(context.Background(), caller,
		auditops.PermissionRead, auditops.ScopeSystem); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("授权依赖失败错误 = %v，期望 ErrAccessDenied", err)
	}
	// 空检查器拒绝构造。
	if _, err := auditops.NewAuthzAuthorizer(nil); !errors.Is(err, auditops.ErrOptionsInvalid) {
		t.Fatalf("空检查器错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestExportCancelOwnership 验证只有任务发起者或 root 能请求取消导出任务，
// 同等范围的其他审计员不能取消他人任务（取消请求仍不等于实际取消）。
func TestExportCancelOwnership(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	owner := userCaller(t, testUserID(1))
	other := userCaller(t, testUserID(2))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.grant(testUserID(2), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: owner, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	if _, err := env.service.CancelExport(ctx, other, view.ID, "他人取消",
		"req_cancel_other"); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("他人取消导出错误 = %v，期望 ErrAccessDenied", err)
	}
	result, err := env.service.CancelExport(ctx, owner, view.ID, "本人取消",
		"req_cancel_owner")
	if err != nil || !result.Accepted {
		t.Fatalf("本人取消导出结果 = %+v err=%v", result, err)
	}
}

// TestSystemOnlyFilterRequiresScope 验证显式请求系统级事件但数据范围不含系统级
// 数据时拒绝，而不是静默返回空列表。
func TestSystemOnlyFilterRequiresScope(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_1"}})
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: caller,
		ScopeID: auditops.ScopeSystem, Filter: auditops.Filter{SystemOnly: true}}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("无系统级范围时 SystemOnly 错误 = %v，期望 ErrAccessDenied", err)
	}
	// 获准 system 资源后可显式查询系统级事件。
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, ResourceIDs: []string{auditops.ScopeSystem}})
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: caller,
		ScopeID: auditops.ScopeSystem, Filter: auditops.Filter{SystemOnly: true}}); err != nil {
		t.Fatalf("获准系统级范围查询失败: %v", err)
	}
}

// TestCodeOfReusesRegisteredCodes 验证领域错误投影到既有注册码（不新增码）。
func TestCodeOfReusesRegisteredCodes(t *testing.T) {
	cases := []struct {
		err  error
		want auditops.ErrorCode
	}{
		{nil, ""},
		{auditops.ErrInvalidRequest, auditops.CodeReqInvalid},
		{auditops.ErrNotFound, auditops.CodeReqInvalid},
		{auditops.ErrRetentionExpired, auditops.CodeReqInvalid},
		{auditops.ErrAccessDenied, auditops.CodeAccessDenied},
		{auditops.ErrRootRequired, auditops.CodeAccessDenied},
		{auditops.ErrConflict, auditops.CodeConflict},
		{auditops.ErrExportPathUnsafe, auditops.CodeExportPathUnsafe},
		{auditops.ErrStoreUnavailable, auditops.CodeDBUnavailable},
		{auditops.ErrAuditUnavailable, auditops.CodeAuditWriteFailed},
	}
	for _, testCase := range cases {
		if got := auditops.CodeOf(testCase.err); got != testCase.want {
			t.Fatalf("CodeOf(%v) = %q，期望 %q", testCase.err, got, testCase.want)
		}
	}
}

// cancellingQueryStore 在导出分页读取时注入取消，模拟任务墙钟到期/取消。
type cancellingQueryStore struct {
	auditops.Store
	cancel context.CancelFunc
}

func (c *cancellingQueryStore) QueryEvents(ctx context.Context,
	query auditops.EventQuery) (auditops.EventPage, error) {
	c.cancel()
	return c.Store.QueryEvents(ctx, query)
}

// TestPurgeCutoffMustBeBeyondRetention 验证 root 不能用保留期内的截止时间一次
// 清掉最近审计（M2）。
func TestPurgeCutoffMustBeBeyondRetention(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowSensitive(auditops.OperationPurge)
	// 默认保留 180 天：截止时间减 30 分钟仍在保留期内，预估与提交都必须拒绝。
	recent := env.now().Add(-30 * time.Minute)
	if _, err := env.service.PreviewPurge(ctx, auditops.PurgePreviewRequest{
		Caller: rootCaller, ScopeID: auditops.ScopeSystem, Cutoff: recent}); !errors.Is(err, auditops.ErrInvalidRequest) {
		t.Fatalf("保留期内预估错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.StartPurge(ctx, auditops.StartPurgeRequest{
		Caller: rootCaller, ScopeID: auditops.ScopeSystem, Cutoff: recent,
		BatchSize: 4, MaxRecords: 10, Reason: "越界", Digest: "digest"}); !errors.Is(err, auditops.ErrInvalidRequest) {
		t.Fatalf("保留期内提交错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestQueuedExportCancelFinalizes 验证排队中取消导出后记录进入真实取消终态（M1）。
func TestQueuedExportCancelFinalizes(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	env.canceller.state = task.StateCancelled
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	if _, err := env.service.CancelExport(ctx, caller, view.ID, "排队取消",
		"req_cancel_queued"); err != nil {
		t.Fatalf("取消排队导出失败: %v", err)
	}
	detail, err := env.service.GetExport(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("读取导出任务失败: %v", err)
	}
	if detail.State != auditops.ExportCancelled {
		t.Fatalf("排队取消后导出状态 = %s，期望 cancelled", detail.State)
	}
	if got := env.countEvents(`SELECT COUNT(*) FROM audit_events WHERE action='audit.export.cancel'`); got != 2 {
		// 1 条取消请求已受理 + 1 条取消已生效（真实终态）。
		t.Fatalf("导出取消审计事件 = %d，期望 2", got)
	}
}

// TestQueuedPurgeCancelFinalizes 验证排队中取消清理后运行记录进入真实取消终态（M1）。
func TestQueuedPurgeCancelFinalizes(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := env.now().Add(-24 * time.Hour)
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		cutoff.Add(-time.Hour))
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	view := env.startPurge(rootCaller, preview)
	env.canceller.state = task.StateCancelled
	if _, err := env.service.CancelPurge(ctx, rootCaller, view.ID, "排队取消",
		"req_cancel_purge_queued"); err != nil {
		t.Fatalf("取消排队清理失败: %v", err)
	}
	finished, err := env.service.GetPurgeRun(ctx, rootCaller, view.ID)
	if err != nil {
		t.Fatalf("读取清理运行失败: %v", err)
	}
	if finished.State != auditops.PurgeCancelled {
		t.Fatalf("排队取消后清理状态 = %s，期望 cancelled", finished.State)
	}
}

// TestRunningExportTimeoutFinalizes 验证运行中导出遇取消/超时时用不受取消影响的
// 上下文写入取消终态，不停在 running（M1）。
func TestRunningExportTimeoutFinalizes(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	env.seed(event("user.update", "app_1", "user_1", audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV,
		Filter: auditops.Filter{To: baseTime}})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditExport,
		Initiator: caller.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload}
	cancelCtx, cancel := context.WithCancel(ctx)
	service := env.withStore(&cancellingQueryStore{Store: env.store, cancel: cancel})
	if err := service.ExportHandler(cancelCtx, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消导出错误 = %v，期望 context.Canceled", err)
	}
	detail, err := env.service.GetExport(ctx, caller, view.ID)
	if err != nil {
		t.Fatalf("读取导出任务失败: %v", err)
	}
	if detail.State != auditops.ExportCancelled {
		t.Fatalf("超时/取消后导出状态 = %s，期望 cancelled（不得停在 running）", detail.State)
	}
}

// TestPurgeRunningFailureFinalizes 验证清理执行前 root 资格丢失时写入真实失败终态（M1）。
func TestPurgeRunningFailureFinalizes(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := env.now().Add(-24 * time.Hour)
	env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
		cutoff.Add(-time.Hour))
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	view := env.startPurge(rootCaller, preview)
	// 执行前 root 资格失效（例如 root 被保护流程收回/账户变化）。
	delete(env.root.roots, testUserID(4))
	_ = env.runPurge(ctx, view, rootCaller)
	// 非 root 后读取运行也需要 root；直接读存储验证真实终态。
	record, found, getErr := env.store.GetPurgeRun(ctx, view.ID)
	if getErr != nil || !found {
		t.Fatalf("读取清理运行失败: %v found=%v", getErr, found)
	}
	if record.State != auditops.PurgeFailed || record.ErrorCode != string(auditops.CodeAccessDenied) {
		t.Fatalf("清理失败终态 = %+v，期望 failed/ACCESS_DENIED", record)
	}
}

// TestProtectedLogRejectsReplace 验证 INSERT OR REPLACE 不能绕过追加表保护（L2）。
func TestProtectedLogRejectsReplace(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := env.now().Add(-24 * time.Hour)
	for index := 0; index < 2; index++ {
		env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
	}
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	view := env.startPurge(rootCaller, preview)
	rows, err := env.raw.QueryContext(ctx,
		`SELECT id FROM audit_maintenance_log WHERE run_id=? LIMIT 1`, view.ID)
	if err != nil {
		t.Fatalf("读取受保护日志失败: %v", err)
	}
	var logID string
	if rows.Next() {
		if err := rows.Scan(&logID); err != nil {
			t.Fatalf("扫描受保护日志失败: %v", err)
		}
	}
	rows.Close()
	if logID == "" {
		t.Fatalf("未找到受保护清理日志")
	}
	if _, err := env.raw.ExecContext(ctx,
		`INSERT OR REPLACE INTO audit_maintenance_log(id,occurred_at_ms,action,actor_type,
actor_id,scope_kind,scope_id,result) VALUES(?,?,?,?,?,?,?,?)`,
		logID, env.now().UnixMilli(), "tampered", "user", testUserID(4),
		"system", "system", "tampered"); err == nil {
		t.Fatalf("INSERT OR REPLACE 绕过受保护日志保护：触发器未生效")
	}
}

// TestExportDownloadVerifiesDigestAndOwner 验证下载前校验 SHA-256（L3）且产物
// 下载绑定发起者/root（L6）。
func TestExportDownloadVerifiesDigestAndOwner(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	owner := userCaller(t, testUserID(1))
	other := userCaller(t, testUserID(2))
	env.grant(testUserID(1), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.grant(testUserID(2), auditops.PermissionExport, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	env.allowSensitive(auditops.OperationExport)
	env.seed(event("user.update", "app_1", "user_1", audit.OutcomeSuccess),
		baseTime.Add(-time.Hour))
	view, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: owner, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV,
		Filter: auditops.Filter{To: baseTime}})
	if err != nil {
		t.Fatalf("创建导出任务失败: %v", err)
	}
	job := task.Job{ID: view.TaskID, Kind: auditops.TaskKindAuditExport,
		Initiator: owner.Actor(), ExecutorID: "worker_1",
		Payload: env.enqueuer.last.Payload}
	if err := env.service.ExportHandler(ctx, job); err != nil {
		t.Fatalf("导出处理失败: %v", err)
	}
	// 同范围其他用户不能下载他人产物。
	if _, err := env.service.OpenExportFile(ctx, other, view.ID); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("同范围他人下载错误 = %v，期望 ErrAccessDenied", err)
	}
	file, err := env.service.OpenExportFile(ctx, owner, view.ID)
	if err != nil {
		t.Fatalf("发起者下载失败: %v", err)
	}
	// 同长度篡改内容后摘要校验必须拒绝。
	content, err := os.ReadFile(file.HostPath)
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if len(content) == 0 {
		t.Fatalf("产物为空")
	}
	content[0] ^= 0xFF
	if err := os.WriteFile(file.HostPath, content, 0o600); err != nil {
		t.Fatalf("篡改产物失败: %v", err)
	}
	if _, err := env.service.OpenExportFile(ctx, owner, view.ID); !errors.Is(err, auditops.ErrExportPathUnsafe) {
		t.Fatalf("篡改产物下载错误 = %v，期望 ErrExportPathUnsafe", err)
	}
}

// TestPurgeCountsAndExecutorAreReal 验证清理扫描/清理计数与真实执行者被持久化（L5）。
func TestPurgeCountsAndExecutorAreReal(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	rootCaller := userCaller(t, testUserID(4))
	env.setRoot(testUserID(4))
	env.allowPurgeWithRetention(1)
	cutoff := env.now().Add(-24 * time.Hour)
	for index := 0; index < 5; index++ {
		env.seed(event("task.run", "", "system_worker", audit.OutcomeSuccess),
			cutoff.Add(-time.Duration(index+1)*time.Hour))
	}
	preview := env.purgePreview(rootCaller, auditops.ScopeSystem, cutoff, 2, 10)
	view := env.startPurge(rootCaller, preview)
	if err := env.runPurge(ctx, view, rootCaller); err != nil {
		t.Fatalf("执行清理失败: %v", err)
	}
	finished, err := env.service.GetPurgeRun(ctx, rootCaller, view.ID)
	if err != nil {
		t.Fatalf("读取清理运行失败: %v", err)
	}
	if finished.ExecutorID != "worker_1" {
		t.Fatalf("清理真实执行者 = %q，期望 worker_1", finished.ExecutorID)
	}
	if finished.Scanned != 5 || finished.Cleaned != 5 || finished.Batches != 3 {
		t.Fatalf("清理计数 = scanned=%d cleaned=%d batches=%d，期望 5/5/3",
			finished.Scanned, finished.Cleaned, finished.Batches)
	}
}

// TestReadDenialsAudited 验证越权查询/导出拒绝写失败审计（L9）。
func TestReadDenialsAudited(t *testing.T) {
	env := newTestEnv(t)
	ctx := env.ctx
	caller := userCaller(t, testUserID(1))
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: caller,
		ScopeID: auditops.ScopeSystem}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("未授权查询错误 = %v", err)
	}
	if _, err := env.service.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: auditops.ScopeSystem, Format: auditops.FormatCSV}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("未授权导出错误 = %v", err)
	}
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: userCaller(t, testUserID(2)),
		ScopeID: auditops.ScopeSystem}); !errors.Is(err, auditops.ErrAccessDenied) {
		t.Fatalf("第二个未授权查询错误 = %v", err)
	}
	if got := env.countEvents(
		`SELECT COUNT(*) FROM audit_events WHERE action='audit.access.denied' AND outcome='denied'`); got < 3 {
		t.Fatalf("读拒绝失败审计条数 = %d，期望至少 3", got)
	}
}
