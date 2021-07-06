package userbatch_test

import (
	"context"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
	userbatchsqlite "github.com/kagurazakayashi/EvernightLogin/internal/userbatch/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// fakeAuthorizer 可按脚本拒绝，验证 fail-closed 与中途撤权。
type fakeAuthorizer struct {
	mu        sync.Mutex
	denyAfter int
	calls     int
}

func (f *fakeAuthorizer) Authorize(_ context.Context, _ account.Caller,
	_ userbatch.Action, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.denyAfter > 0 && f.calls > f.denyAfter {
		return errors.New("revoked")
	}
	return nil
}

type fakeSensitive struct{}

func (fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (fakeSensitive) NotifyOutcome(_ context.Context, _ reauth.Result, _ reauth.Outcome) error {
	return nil
}

// fakeAccounts 是账户服务测试替身：创建返回递增用户；ListUsers 返回预置用户。
type fakeAccounts struct {
	nextID int
	users  []account.User
	deny   bool
}

func (f *fakeAccounts) CreateUser(_ context.Context, _ account.Caller,
	request account.CreateRequest) (account.User, error) {
	if f.deny {
		return account.User{}, account.ErrAccessDenied
	}
	if strings.Contains(request.Username, "taken") {
		return account.User{}, account.ErrUsernameTaken
	}
	f.nextID++
	return account.User{ID: makeUserID(f.nextID), Username: request.Username,
		Nickname: request.Nickname, Biography: request.Biography, Language: request.Language,
		Timezone: request.Timezone, Status: account.StatusActive}, nil
}

func (f *fakeAccounts) ListUsers(_ context.Context, _ account.Caller,
	request account.ListRequest) (account.ListResult, error) {
	if f.deny {
		return account.ListResult{}, account.ErrAccessDenied
	}
	start := request.Offset
	if start > len(f.users) {
		start = len(f.users)
	}
	end := start + request.Limit
	if end > len(f.users) {
		end = len(f.users)
	}
	return account.ListResult{Users: f.users[start:end], HasMore: end < len(f.users)}, nil
}

func makeUserID(index int) string {
	return "usr_" + strings.Repeat("0", 28) + string(rune('0'+index))
}

type fakeDataScope struct{ allowed map[string]bool }

// allowAllScope 允许全部用户（用于只验证其他行为的导出测试）。
type allowAllScope struct{}

func (allowAllScope) AuthorizeUser(_ context.Context, _ account.Caller, _,
	_ string) (bool, error) {
	return true, nil
}

func (f fakeDataScope) AuthorizeUser(_ context.Context, _ account.Caller, _,
	userID string) (bool, error) {
	return f.allowed[userID], nil
}

type fakeEnqueuer struct{ jobs []task.EnqueueRequest }

func (f *fakeEnqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	f.jobs = append(f.jobs, request)
	return task.Job{ID: "job_" + request.Kind, Kind: request.Kind}, nil
}

type fakeCanceller struct{}

func (fakeCanceller) RequestCancel(_ context.Context,
	_ task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelled}, nil
}

type testEnv struct {
	t          *testing.T
	ctx        context.Context
	raw        *storagesqlite.Store
	store      *userbatchsqlite.Store
	audit      *audit.Recorder
	service    *userbatch.Service
	accounts   *fakeAccounts
	authorizer *fakeAuthorizer
	enqueuer   *fakeEnqueuer
	caller     account.Caller
	outputDir  string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithConfig(t, nil)
}

func newTestEnvWithConfig(t *testing.T, mutate func(*userbatch.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "userbatch-test.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	store, err := userbatchsqlite.New(raw)
	if err != nil {
		t.Fatalf("批量存储: %v", err)
	}
	authorizer := &fakeAuthorizer{}
	accounts := &fakeAccounts{}
	enqueuer := &fakeEnqueuer{}
	outputDir := t.TempDir()
	options := userbatch.Options{
		Store: store, Audit: recorder, Authorizer: authorizer, Sensitive: fakeSensitive{},
		Accounts: accounts, DataScope: fakeDataScope{}, Enqueuer: enqueuer,
		Canceller: fakeCanceller{}, OutputDir: outputDir, BatchSize: 2,
		MaxFileBytes: 1 << 20, MaxImportRows: 1000, MaxExportRows: 50,
		Now: func() time.Time { return now },
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := userbatch.New(options)
	if err != nil {
		t.Fatalf("构造服务: %v", err)
	}
	caller, err := account.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("调用者: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, store: store, audit: recorder,
		service: service, accounts: accounts, authorizer: authorizer, enqueuer: enqueuer,
		caller: caller, outputDir: outputDir}
	return env
}

func (e *testEnv) seedUser(id, username, nickname string, isRoot bool) {
	e.t.Helper()
	now := time.Now().UTC().UnixMilli()
	var root int
	if isRoot {
		root = 1
	}
	// 种子用户资料与测试 CSV 一致，便于验证“相同→skipped / 不同→conflict”。
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO users(id,username,
username_normalized,nickname,biography,language,timezone,status,is_root,security_version,
row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?, '', 'zh-CN','Asia/Shanghai', 'active',?,1,1,?,?)`,
		id, username, strings.ToLower(username), nickname, root, now, now); err != nil {
		e.t.Fatalf("种子用户: %v", err)
	}
}

func (e *testEnv) csv(rows ...string) []byte {
	header := "username,nickname,biography,language,timezone"
	return []byte(header + "\n" + strings.Join(rows, "\n") + "\n")
}

func (e *testEnv) startImport(content []byte, key, requestID string) userbatch.StartResult {
	e.t.Helper()
	result, err := e.service.StartImport(e.ctx, userbatch.ImportRequest{
		Caller: e.caller, IdempotencyKey: key, Content: content, RequestID: requestID})
	if err != nil {
		e.t.Fatalf("创建导入任务: %v", err)
	}
	return result
}

func (e *testEnv) runHandler(job userbatch.Job) error {
	e.t.Helper()
	payload, _ := json.Marshal(map[string]string{"job_id": job.ID})
	return e.service.Handler(e.ctx, task.Job{ID: job.TaskID,
		Kind: userbatch.TaskKindUserBatchImport, Payload: payload, Attempt: 1,
		Initiator: audit.Actor{Type: audit.ActorSystem, ID: "test"}})
}

func (e *testEnv) job(t *testing.T, id string) userbatch.Job {
	t.Helper()
	job, err := e.service.GetJob(e.ctx, e.caller, id)
	if err != nil {
		t.Fatalf("读取任务: %v", err)
	}
	return job
}

// ===== 文件校验 =====

func TestImportPrecheckRejectsBadFiles(t *testing.T) {
	env := newTestEnv(t)
	cases := map[string][]byte{
		"空文件":      {},
		"未知列":      []byte("username,email\nuser1,a@b.c\n"),
		"禁止列":      []byte("username,password\nuser1,secret\n"),
		"缺表头":      []byte("user1\n"),
		"非法 UTF-8": append([]byte("username\n"), 0xff, 0xfe, '\n'),
	}
	for name, content := range cases {
		if _, err := env.service.PrecheckImport(env.ctx, env.caller, content); err == nil {
			t.Errorf("%s: 预检查应拒绝", name)
		}
	}
	if _, err := env.service.StartImport(env.ctx, userbatch.ImportRequest{
		Caller: env.caller, IdempotencyKey: "bad-file-1", Content: cases["禁止列"],
		RequestID: "req_bad"}); err == nil {
		t.Fatal("坏文件不应创建任务")
	}
}

// ===== 导入与幂等 =====

func TestImportRowsAndIdempotency(t *testing.T) {
	env := newTestEnv(t)
	env.seedUser("usr_existing_same", "alice", "Alice", false)
	env.seedUser("usr_existing_diff", "bob", "Bob", false)
	env.seedUser("usr_root_target", "rootuser", "Root", true)
	content := env.csv(
		"alice,Alice,,zh-CN,Asia/Shanghai",       // 相同 → skipped
		"bob,Robert,,zh-CN,Asia/Shanghai",        // 不同 → conflict
		"rootuser,Root,,zh-CN,Asia/Shanghai",     // root → denied
		"carol,Carol,,zh-CN,Asia/Shanghai",       // 新建
		"bad username!,Bad,,zh-CN,Asia/Shanghai", // 用户名无效 → failed
	)
	start := env.startImport(content, "import-key-1", "req_import_1")
	if start.Duplicate || len(env.enqueuer.jobs) != 1 {
		t.Fatal("首次导入应创建 1 个任务并入队")
	}
	// 幂等：同键同内容返回既有任务，不重复入队。
	again := env.startImport(content, "import-key-1", "req_import_2")
	if !again.Duplicate || len(env.enqueuer.jobs) != 1 {
		t.Fatal("同键同内容应返回既有任务且不重复入队")
	}
	// 同键不同内容 → CONFLICT。
	if _, err := env.service.StartImport(env.ctx, userbatch.ImportRequest{
		Caller: env.caller, IdempotencyKey: "import-key-1", RequestID: "req_import_3",
		Content: env.csv("dave,Dave,,zh-CN,Asia/Shanghai"),
	}); !errors.Is(err, userbatch.ErrConflict) {
		t.Fatalf("同键不同内容 error = %v，期望冲突", err)
	}
	if err := env.runHandler(start.Job); err != nil {
		t.Fatalf("执行导入: %v", err)
	}
	job := env.job(t, start.Job.ID)
	if job.State != userbatch.JobPartial {
		t.Fatalf("任务状态 = %q，期望 partial", job.State)
	}
	if job.CreatedCount != 1 || job.SkippedCount != 1 || job.ConflictCount != 1 ||
		job.DeniedCount != 1 || job.FailedCount != 1 {
		t.Fatalf("汇总计数异常: %+v", job)
	}
	if env.accounts.nextID != 1 {
		t.Fatalf("创建用户次数 = %d，期望 1（不更新既有用户）", env.accounts.nextID)
	}
	if len(env.accounts.users) != 0 {
		t.Fatal("fakeAccounts 不应返回预置用户")
	}
}

// ===== 取消 / 续跑 =====

func TestImportCancelAndResume(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv("user-1,One,,zh-CN,Asia/Shanghai", "user-2,Two,,zh-CN,Asia/Shanghai",
		"user-3,Three,,zh-CN,Asia/Shanghai")
	start := env.startImport(content, "import-key-cancel", "req_cancel")
	// 预置第 1 行结果模拟上次运行已处理，续跑应跳过。
	if _, err := env.raw.DB().ExecContext(env.ctx, `INSERT INTO user_batch_rows(job_id,row_number,
action,error_code,reason_code,username_normalized,user_id,created_at_ms)
VALUES(?,1,'created','','', 'user-1','usr_seed_1',?)`, start.Job.ID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("预置行: %v", err)
	}
	if err := env.runHandler(start.Job); err != nil {
		t.Fatalf("续跑执行: %v", err)
	}
	job := env.job(t, start.Job.ID)
	if job.CreatedCount != 3 || env.accounts.nextID != 2 {
		t.Fatalf("续跑创建数 = %d/新建 %d，期望 3（含预置行）/2（跳过已处理行）",
			job.CreatedCount, env.accounts.nextID)
	}
	// 取消 queued 任务。
	second := env.startImport(env.csv("user-9,Nine,,zh-CN,Asia/Shanghai"),
		"import-key-cancel2", "req_cancel2")
	if err := env.service.Cancel(env.ctx, env.caller, second.Job.ID, "operator_cancel",
		"req_cancel2"); err != nil {
		t.Fatalf("取消任务: %v", err)
	}
	if got := env.job(t, second.Job.ID); got.State != userbatch.JobCancelled {
		t.Fatalf("取消后状态 = %q，期望 cancelled", got.State)
	}
}

// ===== 中途撤权 =====

func TestImportPermissionRevokedMidRun(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv("u-1,A,,zh-CN,Asia/Shanghai", "u-2,B,,zh-CN,Asia/Shanghai",
		"u-3,C,,zh-CN,Asia/Shanghai", "u-4,D,,zh-CN,Asia/Shanghai", "u-5,E,,zh-CN,Asia/Shanghai")
	start := env.startImport(content, "import-key-revoke", "req_revoke")
	// 首次鉴权通过后拒绝后续批次复验（StartImport 已消耗 1 次调用）。
	env.authorizer.denyAfter = 1
	if err := env.runHandler(start.Job); err == nil {
		t.Fatal("中途撤权应停止任务")
	}
	env.authorizer.denyAfter = 0
	job := env.job(t, start.Job.ID)
	if job.State != userbatch.JobFailed || job.ErrorCode != "ACCESS_DENIED" {
		t.Fatalf("撤权后任务 = %+v，期望 failed/ACCESS_DENIED", job)
	}
}

// ===== 导出 =====

func TestExportFieldsScopeAndFormulaInjection(t *testing.T) {
	env := newTestEnv(t)
	users := []account.User{
		{ID: "usr_a", Username: "=cmd", Nickname: "+1+1", Language: "zh-CN",
			Timezone: "Asia/Shanghai", Status: account.StatusActive},
		{ID: "usr_b", Username: "bob", Nickname: "@x", Language: "zh-CN",
			Timezone: "Asia/Shanghai", Status: account.StatusActive},
	}
	env.accounts.users = users
	// 重新构造带数据范围过滤的服务（只允许 usr_a）。
	service, err := userbatch.New(userbatch.Options{
		Store: env.store, Audit: env.audit,
		Authorizer: env.authorizer, Sensitive: fakeSensitive{}, Accounts: env.accounts,
		DataScope: fakeDataScope{allowed: map[string]bool{"usr_a": true}},
		Enqueuer:  env.enqueuer, Canceller: fakeCanceller{}, OutputDir: env.outputDir,
		MaxExportRows: 50, BatchSize: 2,
	})
	if err != nil {
		t.Fatalf("构造导出服务: %v", err)
	}
	env.service = service
	result, err := service.StartExport(env.ctx, userbatch.ExportRequest{
		Caller: env.caller, IdempotencyKey: "export-key-1", RequestID: "req_export"})
	if err != nil {
		t.Fatalf("创建导出任务: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"job_id": result.Job.ID})
	if err := service.Handler(env.ctx, task.Job{ID: result.Job.TaskID,
		Kind: userbatch.TaskKindUserBatchExport, Payload: payload, Attempt: 1}); err != nil {
		t.Fatalf("执行导出: %v", err)
	}
	job := env.job(t, result.Job.ID)
	if job.State != userbatch.JobSucceeded || job.ExportRows != 1 || job.DeniedCount != 1 {
		t.Fatalf("导出任务 = %+v，期望 succeeded/1 行/1 拒绝范围", job)
	}
	if job.ExportPath == "" || job.ExportSHA256 == "" {
		t.Fatal("导出任务缺少文件路径或摘要")
	}
	content, err := os.ReadFile(job.ExportPath)
	if err != nil {
		t.Fatalf("读取导出文件: %v", err)
	}
	text := string(content)
	// CSV 转义：公式前缀被前置单引号，不能以 = 或 + 开头。
	if strings.Contains(text, ",=cmd,") || strings.Contains(text, "\n=cmd,") {
		t.Fatal("导出未防公式注入（= 开头未转义）")
	}
	if !strings.Contains(text, "'=cmd") {
		t.Fatalf("导出应前置单引号防公式注入: %q", text)
	}
	if strings.Contains(text, "biography") || strings.Contains(text, "email") {
		t.Fatal("默认导出不应包含自由文本/邮箱字段")
	}
}

// ===== 报告 =====

func TestReportCSVAuthorizedAndEscaped(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv("bad username!,Bad,,zh-CN,Asia/Shanghai")
	start := env.startImport(content, "import-key-report", "req_report")
	if err := env.runHandler(start.Job); err != nil {
		t.Fatalf("执行导入: %v", err)
	}
	report, _, err := env.service.ReportCSV(env.ctx, env.caller, start.Job.ID)
	if err != nil {
		t.Fatalf("生成报告: %v", err)
	}
	if !strings.Contains(string(report), "row_number,action,error_code") {
		t.Fatal("报告缺少表头")
	}
	if strings.Contains(string(report), "api_key") || strings.Contains(string(report), "password") {
		t.Fatal("报告不应包含秘密")
	}
	// 其他身份不可读取该任务。
	other, _ := account.UserCaller(makeUserID(9))
	if _, _, err := env.service.ReportCSV(env.ctx, other, start.Job.ID); !errors.Is(err,
		userbatch.ErrAccessDenied) {
		t.Fatalf("跨调用者读取报告 error = %v，期望拒绝", err)
	}
}

// ===== 审计修复用例 =====

// TestConcurrentExportsKeepConfiguredLimit 验证导出 handler 使用任务局部上限，不污染
// 共享 Service 配置（B1）。
func TestConcurrentExportsKeepConfiguredLimit(t *testing.T) {
	env := newTestEnvWithConfig(t, func(options *userbatch.Options) {
		options.DataScope = allowAllScope{}
	})
	users := make([]account.User, 0, 5)
	for index := 1; index <= 5; index++ {
		users = append(users, account.User{ID: makeUserID(index), Username: "user" + string(rune('0'+index))})
	}
	env.accounts.users = users
	start := func(key string, maxRows int) userbatch.StartResult {
		result, err := env.service.StartExport(env.ctx, userbatch.ExportRequest{
			Caller: env.caller, IdempotencyKey: key, MaxRows: maxRows, RequestID: "req_" + key})
		if err != nil {
			t.Fatalf("创建导出任务: %v", err)
		}
		return result
	}
	first := start("export-small-1", 2)
	second := start("export-large-1", 4)
	var wait sync.WaitGroup
	for _, job := range []userbatch.Job{first.Job, second.Job} {
		payload, _ := json.Marshal(map[string]string{"job_id": job.ID})
		wait.Add(1)
		go func(jobID, taskID string) {
			defer wait.Done()
			_ = env.service.Handler(env.ctx, task.Job{ID: taskID,
				Kind: userbatch.TaskKindUserBatchExport, Payload: payload, Attempt: 1})
		}(job.ID, job.TaskID)
	}
	wait.Wait()
	smallJob := env.job(t, first.Job.ID)
	largeJob := env.job(t, second.Job.ID)
	if smallJob.ExportRows > 2 || largeJob.ExportRows > 4 {
		t.Fatalf("任务局部上限未生效: small=%d large=%d", smallJob.ExportRows, largeJob.ExportRows)
	}
	// 共享配置未被缩小：再创建默认上限任务仍按构造配置（50）执行。
	third := start("export-default-1", 0)
	payload, _ := json.Marshal(map[string]string{"job_id": third.Job.ID})
	if err := env.service.Handler(env.ctx, task.Job{ID: third.Job.TaskID,
		Kind: userbatch.TaskKindUserBatchExport, Payload: payload, Attempt: 1}); err != nil {
		t.Fatalf("执行默认导出: %v", err)
	}
	thirdJob := env.job(t, third.Job.ID)
	if thirdJob.ExportRows != 5 || thirdJob.State != userbatch.JobSucceeded {
		t.Fatalf("默认导出异常: %+v", thirdJob)
	}
}

// TestReportPaginationAndTruncationMark 验证 >100 行逐项结果完整与截断标记（B3）。
func TestReportPaginationAndTruncationMark(t *testing.T) {
	// 明细上限放宽到 5000：250 行必须完整。
	env := newTestEnv(t)
	rows := make([]string, 0, 250)
	for index := 1; index <= 250; index++ {
		rows = append(rows, "user-"+strings.Repeat("0", 3)+string(rune('0'+index%10))+"-"+itoa(index)+",N"+itoa(index)+",,zh-CN,Asia/Shanghai")
	}
	_ = rows
	content := env.csv(bulkRows(250)...)
	start := env.startImport(content, "import-many-1", "req_many")
	if err := env.runHandler(start.Job); err != nil {
		t.Fatalf("执行导入: %v", err)
	}
	list, truncated, err := env.service.ListRows(env.ctx, env.caller, start.Job.ID, 0)
	if err != nil {
		t.Fatalf("读取明细: %v", err)
	}
	if len(list) != 250 || truncated {
		t.Fatalf("250 行明细 = %d/truncated=%v，期望 250/false", len(list), truncated)
	}
	report, reportTruncated, err := env.service.ReportCSV(env.ctx, env.caller, start.Job.ID)
	if err != nil {
		t.Fatalf("生成报告: %v", err)
	}
	if reportTruncated || strings.Count(string(report), "\n") < 250 {
		t.Fatalf("250 行报告被截断或缺失（truncated=%v lines=%d）",
			reportTruncated, strings.Count(string(report), "\n"))
	}
	// 明细上限 100：必须显式标记 truncated（报告列 + 返回值）。
	limited := newTestEnvWithConfig(t, func(options *userbatch.Options) {
		options.MaxRowDetails = 100
	})
	limited.accounts.users = env.accounts.users
	content2 := env.csv(bulkRows(150)...)
	start2 := limited.startImport(content2, "import-many-2", "req_many2")
	if err := limited.runHandler(start2.Job); err != nil {
		t.Fatalf("执行限量导入: %v", err)
	}
	list2, truncated2, err := limited.service.ListRows(limited.ctx, limited.caller, start2.Job.ID, 0)
	if err != nil {
		t.Fatalf("读取明细: %v", err)
	}
	if len(list2) != 100 || !truncated2 {
		t.Fatalf("截断明细 = %d/%v，期望 100/true", len(list2), truncated2)
	}
	report2, reportTruncated2, err := limited.service.ReportCSV(limited.ctx, limited.caller, start2.Job.ID)
	if err != nil {
		t.Fatalf("生成限量报告: %v", err)
	}
	if !reportTruncated2 || !strings.Contains(string(report2), "report_truncated") ||
		!strings.Contains(string(report2), ",true") {
		t.Fatalf("报告缺少截断标记: truncated=%v", reportTruncated2)
	}
}

// TestImportPermissionRevokedBeforeFirstRow 验证排队期间撤权时首行前即拒绝（B2）。
func TestImportPermissionRevokedBeforeFirstRow(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv("early-1,A,,zh-CN,Asia/Shanghai", "early-2,B,,zh-CN,Asia/Shanghai")
	start := env.startImport(content, "import-key-early", "req_early")
	// StartImport 已消耗 1 次鉴权；handler 首行前复验将被拒绝。
	env.authorizer.denyAfter = 1
	if err := env.runHandler(start.Job); err == nil {
		t.Fatal("首行前撤权应失败")
	}
	env.authorizer.denyAfter = 0
	job := env.job(t, start.Job.ID)
	if job.State != userbatch.JobFailed || job.ErrorCode != "ACCESS_DENIED" {
		t.Fatalf("首行前撤权任务 = %+v，期望 failed/ACCESS_DENIED", job)
	}
	if env.accounts.nextID != 0 {
		t.Fatalf("撤权后仍创建了 %d 个用户", env.accounts.nextID)
	}
}

// TestExportPermissionRevokedMidRun 验证导出运行中撤权 fail-closed（B2）。
func TestExportPermissionRevokedMidRun(t *testing.T) {
	env := newTestEnvWithConfig(t, func(options *userbatch.Options) {
		options.MaxExportRows = 2
		options.DataScope = allowAllScope{}
	})
	for index := 1; index <= 6; index++ {
		env.accounts.users = append(env.accounts.users, account.User{
			ID: makeUserID(index), Username: "u" + itoa(index)})
	}
	result, err := env.service.StartExport(env.ctx, userbatch.ExportRequest{
		Caller: env.caller, IdempotencyKey: "export-revoke-1", MaxRows: 2,
		RequestID: "req_export_revoke"})
	if err != nil {
		t.Fatalf("创建导出任务: %v", err)
	}
	// 允许 start + 第一页复验，第二页复验拒绝。
	env.authorizer.denyAfter = 2
	payload, _ := json.Marshal(map[string]string{"job_id": result.Job.ID})
	_ = env.service.Handler(env.ctx, task.Job{ID: result.Job.TaskID,
		Kind: userbatch.TaskKindUserBatchExport, Payload: payload, Attempt: 1})
	env.authorizer.denyAfter = 0
	job := env.job(t, result.Job.ID)
	if job.State != userbatch.JobFailed || job.ErrorCode != "ACCESS_DENIED" {
		t.Fatalf("导出中途撤权任务 = %+v，期望 failed/ACCESS_DENIED", job)
	}
}

// TestFailedImportRetrySucceeds 验证 failed 保留输入、授权恢复后可续跑成功（中2）。
func TestFailedImportRetrySucceeds(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv(bulkRows(6)...)
	start := env.startImport(content, "import-retry-1", "req_retry")
	env.authorizer.denyAfter = 1 // StartImport 后 handler 首行前拒绝
	if err := env.runHandler(start.Job); err == nil {
		t.Fatal("撤权应失败")
	}
	env.authorizer.denyAfter = 0
	failed := env.job(t, start.Job.ID)
	if failed.State != userbatch.JobFailed || !failed.InputAvailable {
		t.Fatalf("failed 任务应保留输入: %+v", failed)
	}
	retried, err := env.service.Retry(env.ctx, env.caller, start.Job.ID, "req_retry2")
	if err != nil {
		t.Fatalf("受控重试失败: %v", err)
	}
	if err := env.runHandler(retried); err != nil {
		t.Fatalf("重试执行失败: %v", err)
	}
	done := env.job(t, start.Job.ID)
	if done.State != userbatch.JobSucceeded || done.CreatedCount != 6 {
		t.Fatalf("重试后任务 = %+v，期望 succeeded/6", done)
	}
}

// TestReconcileInterruptedAllowsRetry 验证崩溃遗留 running 对账为 failed 且 Retry 可达。
func TestReconcileInterruptedAllowsRetry(t *testing.T) {
	env := newTestEnv(t)
	content := env.csv("restart-1,A,,zh-CN,Asia/Shanghai")
	start := env.startImport(content, "import-restart-1", "req_restart")
	// 模拟崩溃：任务停在 running、无执行者。
	if _, err := env.store.MarkRunning(env.ctx, start.Job.ID, time.Now().UTC()); err != nil {
		t.Fatalf("标记 running: %v", err)
	}
	reconciled, err := env.service.ReconcileInterrupted(env.ctx, env.caller)
	if err != nil || reconciled != 1 {
		t.Fatalf("对账 = %d/%v，期望 1", reconciled, err)
	}
	job := env.job(t, start.Job.ID)
	if job.State != userbatch.JobFailed || job.ErrorCode != "TASK_TIMEOUT" {
		t.Fatalf("对账后任务 = %+v，期望 failed/TASK_TIMEOUT", job)
	}
	retried, err := env.service.Retry(env.ctx, env.caller, start.Job.ID, "req_restart_retry")
	if err != nil {
		t.Fatalf("对账后 Retry: %v", err)
	}
	if err := env.runHandler(retried); err != nil {
		t.Fatalf("对账后执行: %v", err)
	}
	if done := env.job(t, start.Job.ID); done.State != userbatch.JobSucceeded {
		t.Fatalf("对账后续跑状态 = %q", done.State)
	}
}

func itoa(value int) string { return fmt.Sprint(value) }

// bulkRows 生成 n 行合法导入数据。
func bulkRows(n int) []string {
	rows := make([]string, 0, n)
	for index := 1; index <= n; index++ {
		rows = append(rows, "bulk-"+itoa(index)+",Nick"+itoa(index)+",,zh-CN,Asia/Shanghai")
	}
	return rows
}
