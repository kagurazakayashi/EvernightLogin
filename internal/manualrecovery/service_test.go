package manualrecovery_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	initiator = "usr_00000000000000000000000000000001"
	approver  = "usr_00000000000000000000000000000002"
	executor  = "usr_00000000000000000000000000000003"
	target    = "usr_00000000000000000000000000000011"
	rootUser  = "usr_00000000000000000000000000000012"
	highUser  = "usr_00000000000000000000000000000013"
)

// fakeReauth 模拟已接线的步骤 38/39 敏感策略执行器；denyErr 可注入拒绝。
type fakeReauth struct {
	mu          sync.Mutex
	denyErr     error
	requests    []reauth.Request
	notifyCalls int
}

func (f *fakeReauth) Authorize(_ context.Context, _ reauth.Caller, request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if f.denyErr != nil {
		return reauth.Result{}, f.denyErr
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID}, nil
}

func (f *fakeReauth) NotifyOutcome(_ context.Context, _ reauth.Result, _ reauth.Outcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifyCalls++
	return nil
}

// fakeStaff 按 (账号, 权限) 返回是否具备资格；revoke 记录撤销。
type fakeStaff struct {
	mu      sync.Mutex
	request map[string]bool
	approve map[string]map[manualrecovery.OperationType]bool
	// approvalTargets 限制审批人可审批的目标；nil 表示不限制（兼容既有用例）。
	approvalTargets map[string]map[string]bool
	execute         map[string]bool
	err             error
	calls           int
}

func (f *fakeStaff) AuthorizeRequest(_ context.Context, staffUserID, _ string, _ manualrecovery.OperationType) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	if !f.request[staffUserID] {
		return manualrecovery.ErrAccessDenied
	}
	return nil
}

func (f *fakeStaff) AuthorizeApproval(_ context.Context, approverUserID, targetUserID, scopeID string, operation manualrecovery.OperationType) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	if allowed, restricted := f.approvalTargets[approverUserID]; restricted && !allowed[targetUserID] {
		return manualrecovery.ErrAccessDenied
	}
	if !f.approve[approverUserID][operation] {
		return manualrecovery.ErrAccessDenied
	}
	_ = scopeID
	return nil
}

func (f *fakeStaff) AuthorizeExecution(_ context.Context, executorUserID, _ string, operation manualrecovery.OperationType) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	if !f.execute[executorUserID] {
		return manualrecovery.ErrAccessDenied
	}
	_ = operation
	return nil
}

// fakeTargets 返回目标状态快照；测试可修改以模拟目标变为高权限/停用/版本变化。
type fakeTargets struct {
	mu     sync.Mutex
	states map[string]manualrecovery.TargetState
	err    error
}

func (f *fakeTargets) LoadTarget(_ context.Context, userID string) (manualrecovery.TargetState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return manualrecovery.TargetState{}, f.err
	}
	state, ok := f.states[userID]
	if !ok {
		return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
	}
	return state, nil
}

// fakeExecutor 记录受控执行调用并可注入失败。
type fakeExecutor struct {
	mu         sync.Mutex
	calls      int
	compensate int
	err        error
	outcome    manualrecovery.ExecutionOutcome
	last       manualrecovery.ExecutionCommand
}

func (f *fakeExecutor) Execute(_ context.Context, command manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = command
	if f.err != nil {
		return manualrecovery.ExecutionOutcome{}, f.err
	}
	return f.outcome, nil
}

func (f *fakeExecutor) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compensate++
	return nil
}

// fakeNotifier 记录通知。
type fakeNotifier struct {
	mu       sync.Mutex
	kinds    []manualrecovery.NotificationKind
	failErr  error
	onNotify func(requestID string)
}

func (f *fakeNotifier) Notify(_ context.Context, notification manualrecovery.Notification) error {
	f.mu.Lock()
	hook := f.onNotify
	f.kinds = append(f.kinds, notification.Kind)
	err := f.failErr
	f.mu.Unlock()
	if hook != nil {
		hook(notification.RequestID)
	}
	return err
}

// failingAudit 在指定阶段注入审计事务失败。
type failingAudit struct {
	inner         manualrecovery.AuditRecorder
	mu            sync.Mutex
	successBefore int
	failCritical  int
}

func (f *failingAudit) Record(ctx context.Context, event audit.Event) error {
	return f.inner.Record(ctx, event)
}
func (f *failingAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.inner.RecordFailure(ctx, event)
}
func (f *failingAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error {
	f.mu.Lock()
	if f.successBefore > 0 {
		f.successBefore--
		f.mu.Unlock()
		return f.inner.ExecuteCritical(ctx, request, change)
	}
	if f.failCritical > 0 {
		f.failCritical--
		f.mu.Unlock()
		return fmt.Errorf("%w: 注入审计失败", manualrecovery.ErrAuditUnavailable)
	}
	f.mu.Unlock()
	return f.inner.ExecuteCritical(ctx, request, change)
}

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	raw      *storagesqlite.Store
	store    *manualrecoverysqlite.Store
	service  *manualrecovery.Service
	audit    manualrecovery.AuditRecorder
	auth     *fakeReauth
	staff    *fakeStaff
	targets  *fakeTargets
	executor *fakeExecutor
	notifier *fakeNotifier
	now      time.Time
}

func newTestEnv(t *testing.T, mutate func(*manualrecovery.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "manual-recovery.db")))
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
	env := &testEnv{t: t, ctx: ctx, raw: raw, now: time.Now().UTC().Truncate(time.Millisecond),
		auth: &fakeReauth{},
		staff: &fakeStaff{
			request: map[string]bool{initiator: true},
			approve: map[string]map[manualrecovery.OperationType]bool{
				approver: {manualrecovery.OperationPasswordReset: true, manualrecovery.OperationMFAReset: true},
			},
			execute: map[string]bool{executor: true},
		},
		targets:  &fakeTargets{states: map[string]manualrecovery.TargetState{}},
		executor: &fakeExecutor{outcome: manualrecovery.ExecutionOutcome{Summary: "ok", SessionsRevoked: 3}},
		notifier: &fakeNotifier{},
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	env.audit = recorder
	env.store, err = manualrecoverysqlite.New(raw)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	options := manualrecovery.Options{
		Store: env.store, Audit: recorder, Reauth: env.auth, Staff: env.staff,
		Targets: env.targets, Executor: env.executor, Notifier: env.notifier,
		Policy: manualrecovery.Policy{
			Enabled: true,
			VerificationBases: []manualrecovery.VerificationBasis{
				manualrecovery.BasisInPersonIdentityDocument,
			},
			DeliveryChannels:           []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:                 time.Hour,
			ApprovalTTL:                12 * time.Hour,
			RequestTTL:                 24 * time.Hour,
			RequireIndependentApproval: true,
		},
		Now: func() time.Time { return env.now },
	}
	if mutate != nil {
		mutate(&options)
	}
	env.service, err = manualrecovery.New(options)
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	nowMS := env.now.UnixMilli()
	for _, user := range []string{initiator, approver, executor, target, rootUser, highUser} {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			user, "u-"+user[len(user)-2:], "u-"+user[len(user)-2:], "active", 0, 3, 1, nowMS, nowMS); err != nil {
			t.Fatalf("插入用户 %s: %v", user, err)
		}
	}
	env.targets.states[target] = manualrecovery.TargetState{
		UserID: target, Active: true, SecurityVersion: 3,
		DeliveryFingerprint: "fp:alice@example.test",
	}
	env.targets.states[rootUser] = manualrecovery.TargetState{
		UserID: rootUser, Active: true, IsRoot: true, SecurityVersion: 3,
		DeliveryFingerprint: "fp:root@example.test",
	}
	env.targets.states[highUser] = manualrecovery.TargetState{
		UserID: highUser, Active: true, HighPrivilege: true, SecurityVersion: 3,
		DeliveryFingerprint: "fp:high@example.test",
	}
	return env
}

// caller 构造工作人员调用者。
func (env *testEnv) caller(userID string) manualrecovery.Caller {
	env.t.Helper()
	caller, err := manualrecovery.UserCaller(userID)
	if err != nil {
		env.t.Fatalf("调用者: %v", err)
	}
	return caller
}

// create 创建一条密码恢复申请。
func (env *testEnv) create() manualrecovery.RequestRecord {
	env.t.Helper()
	record, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID:          target,
		Operation:             manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "verify-2026-0001",
		EvidenceSummary:       "线下核验证件原件，核验记录由独立核验人留存",
		Reason:                "用户既有邮箱不可用，需要人工核验恢复",
		Delivery:              manualrecovery.DeliveryVerifiedEmail,
		RequestID:             "req-create-1",
	})
	if err != nil {
		env.t.Fatalf("创建申请: %v", err)
	}
	return record
}

// approve 审批申请。
func (env *testEnv) approve(requestID string) manualrecovery.ApprovalRecord {
	env.t.Helper()
	approval, err := env.service.Approve(env.ctx, env.caller(approver), manualrecovery.ApproveRequest{
		RequestID: requestID, Note: "已复核核验依据", TraceID: "req-approve-1",
	})
	if err != nil {
		env.t.Fatalf("审批申请: %v", err)
	}
	return approval
}

// count 统计计数查询。
func (env *testEnv) count(query string, args ...any) int {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx, query, args...)
	if err != nil {
		env.t.Fatalf("计数查询: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		env.t.Fatalf("计数查询无结果")
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		env.t.Fatalf("扫描计数: %v", err)
	}
	return value
}

// auditActors 返回某动作的真实操作者集合。
func (env *testEnv) auditActors(action string) []string {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx,
		`SELECT COALESCE(actor_id,'') FROM audit_events WHERE action=? ORDER BY occurred_at_ms`, action)
	if err != nil {
		env.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var actors []string
	for rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			env.t.Fatalf("扫描审计: %v", err)
		}
		actors = append(actors, actor)
	}
	return actors
}

// TestDisabledByDefault 验证默认关闭时所有阶段拒绝并留失败审计。
func TestDisabledByDefault(t *testing.T) {
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Policy = manualrecovery.DefaultPolicy()
	})
	if env.service.Enabled() {
		t.Fatal("默认策略不应启用")
	}
	_, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-1", EvidenceSummary: "证据摘要",
		Reason: "原因", Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-1",
	})
	if !errors.Is(err, manualrecovery.ErrDisabled) {
		t.Fatalf("默认关闭应拒绝，得到 %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests`) != 0 {
		t.Fatal("默认关闭时不应创建申请")
	}
	if !strings.Contains(env.auditDump(), "manual_recovery_disabled") {
		t.Fatal("默认关闭拒绝缺少失败审计")
	}
	// 非法策略配置拒绝构造。
	_, err = manualrecovery.New(manualrecovery.Options{
		Store: env.store, Audit: &failingAudit{inner: nil}, Reauth: env.auth,
		Staff: env.staff, Targets: env.targets, Executor: env.executor,
		Policy: manualrecovery.Policy{Enabled: true, RequireIndependentApproval: true},
	})
	if !errors.Is(err, manualrecovery.ErrOptionsInvalid) {
		t.Fatalf("启用但缺少核验依据应拒绝构造，得到 %v", err)
	}
}

// auditDump 拼接审计动作与原因码，供“是否留痕”断言。
func (env *testEnv) auditDump() string {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx,
		`SELECT action,COALESCE(reason_code,''),COALESCE(error_code,'') FROM audit_events`)
	if err != nil {
		env.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var action, reason, code string
		if err := rows.Scan(&action, &reason, &code); err != nil {
			env.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(action + "|" + reason + "|" + code + "\n")
	}
	return builder.String()
}

// TestCreateRejectsWeakVerificationAndProtectedTargets 验证弱核验依据/未知交付渠道/
// root 与高权限目标/停用目标/未授权发起者都被拒绝并留痕。
func TestCreateRejectsWeakVerificationAndProtectedTargets(t *testing.T) {
	env := newTestEnv(t, nil)
	base := manualrecovery.CreateRequest{
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.VerificationBasis("security_question"),
		VerificationReference: "ref-1", EvidenceSummary: "问题答案",
		Reason: "原因", Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-weak",
	}
	if _, err := env.service.Create(env.ctx, env.caller(initiator), base); !errors.Is(err, manualrecovery.ErrInvalidRequest) {
		t.Fatalf("弱核验依据应拒绝，得到 %v", err)
	}
	weak := base
	weak.VerificationBasis = manualrecovery.BasisInPersonIdentityDocument
	weak.Delivery = manualrecovery.DeliveryChannel("phone_oral")
	if _, err := env.service.Create(env.ctx, env.caller(initiator), weak); !errors.Is(err, manualrecovery.ErrInvalidRequest) {
		t.Fatalf("不支持交付方式应拒绝，得到 %v", err)
	}
	if _, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: rootUser, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-1", EvidenceSummary: "证据", Reason: "原因",
		Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-root",
	}); !errors.Is(err, manualrecovery.ErrTargetProtected) {
		t.Fatalf("root 目标应拒绝，得到 %v", err)
	}
	if _, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: highUser, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-1", EvidenceSummary: "证据", Reason: "原因",
		Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-high",
	}); !errors.Is(err, manualrecovery.ErrTargetProtected) {
		t.Fatalf("高权限目标应拒绝，得到 %v", err)
	}
	// 发起者无 recovery.request 范围。
	env.staff.mu.Lock()
	env.staff.request[initiator] = false
	env.staff.mu.Unlock()
	if _, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-1", EvidenceSummary: "证据", Reason: "原因",
		Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-noauth",
	}); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("未授权发起者应拒绝，得到 %v", err)
	}
	dump := env.auditDump()
	for _, reason := range []string{"target_protected", "staff_not_authorized"} {
		if !strings.Contains(dump, reason) {
			t.Errorf("缺少拒绝失败审计 %q", reason)
		}
	}
}

// TestSelfApprovalRejected 验证发起者与目标本人不能自批。
func TestSelfApprovalRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.staff.mu.Lock()
	env.staff.approve[initiator] = map[manualrecovery.OperationType]bool{
		manualrecovery.OperationPasswordReset: true,
	}
	env.staff.mu.Unlock()
	if _, err := env.service.Approve(env.ctx, env.caller(initiator), manualrecovery.ApproveRequest{
		RequestID: record.ID, TraceID: "req-self"}); !errors.Is(err, manualrecovery.ErrSelfApproval) {
		t.Fatalf("发起者自批应拒绝，得到 %v", err)
	}
	env.staff.mu.Lock()
	env.staff.approve[target] = map[manualrecovery.OperationType]bool{
		manualrecovery.OperationPasswordReset: true,
	}
	env.staff.mu.Unlock()
	if _, err := env.service.Approve(env.ctx, env.caller(target), manualrecovery.ApproveRequest{
		RequestID: record.ID, TraceID: "req-target"}); !errors.Is(err, manualrecovery.ErrSelfApproval) {
		t.Fatalf("目标自批应拒绝，得到 %v", err)
	}
	if !strings.Contains(env.auditDump(), "self_approval") {
		t.Fatal("自批拒绝缺少失败审计")
	}
	// 发起者不得执行自己发起的请求中的目标约束之外绕过：审批人独立后，执行需授权。
}

// TestApprovalWaitingPeriodAndExecution 验证批准等待期、执行成功、状态与真实操作者
// 审计；并发之外的核心成功路径。
func TestApprovalWaitingPeriodAndExecution(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	approval := env.approve(record.ID)
	if approval.Status != manualrecovery.ApprovalActive {
		t.Fatalf("批准状态 = %s", approval.Status)
	}
	// 等待期内不能执行。
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-exec-early"}); !errors.Is(err, manualrecovery.ErrApprovalNotYetValid) {
		t.Fatalf("等待期内执行应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("等待期内不应调用执行器")
	}
	// 等待期后执行成功。
	env.now = env.now.Add(time.Hour + time.Minute)
	result, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-exec-1"})
	if err != nil {
		t.Fatalf("执行恢复: %v", err)
	}
	if result.Status != manualrecovery.StatusCompleted || !result.NotificationSent {
		t.Fatalf("执行结果异常: %+v", result)
	}
	if env.executor.calls != 1 || env.executor.last.TargetUserID != target ||
		env.executor.last.Operation != manualrecovery.OperationPasswordReset {
		t.Fatalf("执行器调用异常: %+v", env.executor.last)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='completed'`) != 1 {
		t.Fatal("申请未完成")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='consumed'`) != 1 {
		t.Fatal("批准未被消费")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='succeeded'`) != 1 {
		t.Fatal("执行记录未成功")
	}
	// 真实操作者审计：申请=发起者、批准=审批人、执行=执行人。
	if actors := env.auditActors(manualrecovery.ActionRequested); len(actors) == 0 || actors[0] != initiator {
		t.Errorf("申请审计操作者异常: %v", actors)
	}
	if actors := env.auditActors(manualrecovery.ActionApproved); len(actors) == 0 || actors[0] != approver {
		t.Errorf("批准审计操作者异常: %v", actors)
	}
	if actors := env.auditActors(manualrecovery.ActionExecution); len(actors) == 0 || actors[0] != executor {
		t.Errorf("执行审计操作者异常: %v", actors)
	}
	// 重复执行被拒绝。
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-exec-2"}); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("重复执行应拒绝，得到 %v", err)
	}
}

// TestContentReplacementInvalidatesApproval 验证批准后内容被替换（直接篡改数据库）
// 时执行 fail-closed，执行器不被调用。
func TestContentReplacementInvalidatesApproval(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE manual_recovery_requests SET reason=? WHERE id=?`, "替换后的原因", record.ID); err != nil {
		t.Fatalf("篡改申请内容: %v", err)
	}
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-replaced"}); !errors.Is(err, manualrecovery.ErrContentChanged) {
		t.Fatalf("内容替换应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("内容替换后不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='failed'`) != 1 {
		t.Fatal("内容替换后申请应置失败")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='invalidated'`) != 1 {
		t.Fatal("内容替换后批准应失效")
	}
}

// TestExpiredApprovalRejected 验证批准过期后执行拒绝并使批准失效、申请回到待审批。
func TestExpiredApprovalRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(13 * time.Hour)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-expired"}); !errors.Is(err, manualrecovery.ErrApprovalExpired) {
		t.Fatalf("过期批准应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("过期批准不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='invalidated'`) != 1 {
		t.Fatal("过期批准应失效")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='pending_approval'`) != 1 {
		t.Fatal("过期批准后申请应回到待审批")
	}
}

// TestApproverPermissionRevoked 验证审批人权限撤销后既有批准无效。
func TestApproverPermissionRevoked(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.staff.mu.Lock()
	env.staff.approve[approver] = map[manualrecovery.OperationType]bool{}
	env.staff.mu.Unlock()
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-revoked"}); !errors.Is(err, manualrecovery.ErrApproverUnqualified) {
		t.Fatalf("审批人撤权后应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("审批人撤权后不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='invalidated'`) != 1 {
		t.Fatal("审批人撤权后批准应失效")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='pending_approval'`) != 1 {
		t.Fatal("审批人撤权后申请应回到待审批")
	}
}

// TestTargetBecomesHighPrivilege 验证批准后目标变为高权限时 fail-closed。
func TestTargetBecomesHighPrivilege(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.targets.mu.Lock()
	state := env.targets.states[target]
	state.HighPrivilege = true
	env.targets.states[target] = state
	env.targets.mu.Unlock()
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-high"}); !errors.Is(err, manualrecovery.ErrTargetProtected) {
		t.Fatalf("目标变为高权限应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("目标变为高权限后不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='failed'`) != 1 {
		t.Fatal("目标变为高权限后申请应置失败")
	}
}

// TestConcurrentExecutionSingleWinner 验证双执行竞争只有一个成功、执行器只调用一次。
func TestConcurrentExecutionSingleWinner(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	const workers = 8
	var wait sync.WaitGroup
	results := make([]error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
				RequestID: record.ID, TraceID: fmt.Sprintf("req-concurrent-%d", index)})
			results[index] = err
		}(index)
	}
	wait.Wait()
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("并发执行成功次数 = %d，期望 1（%v）", successes, results)
	}
	if env.executor.calls != 1 {
		t.Fatalf("执行器调用次数 = %d，期望 1", env.executor.calls)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions`) != 1 {
		t.Fatal("并发执行产生多条执行记录")
	}
}

// TestExecutionFailureDoesNotClaimSuccess 验证执行器故障时整体失败、通知失败渠道、
// 不写成功审计、不宣布完成。
func TestExecutionFailureDoesNotClaimSuccess(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.executor.err = errors.New("delivery channel failed")
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-fail"}); !errors.Is(err, manualrecovery.ErrExecutionFailed) {
		t.Fatalf("执行失败应拒绝，得到 %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='failed'`) != 1 {
		t.Fatal("执行失败后申请应置失败")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='invalidated'`) != 1 {
		t.Fatal("执行失败后批准应失效")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='failed'`) != 1 {
		t.Fatal("执行记录应失败")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='manual_recovery.executed'`) != 0 {
		t.Fatal("执行失败不应写成功审计")
	}
	if len(env.notifier.kinds) != 1 || env.notifier.kinds[0] != manualrecovery.NotificationFailed {
		t.Fatalf("执行失败通知异常: %v", env.notifier.kinds)
	}
}

// TestOperationTypeSeparated 验证密码恢复与 MFA 恢复分别审批：MFA 申请审批使用
// recovery.mfa.approve，且跨操作类型的内容篡改被拒绝。
func TestOperationTypeSeparated(t *testing.T) {
	env := newTestEnv(t, nil)
	// MFA 恢复申请：审批人只有密码恢复权限时必须被拒绝。
	env.staff.mu.Lock()
	env.staff.approve[approver] = map[manualrecovery.OperationType]bool{
		manualrecovery.OperationPasswordReset: true,
	}
	env.staff.mu.Unlock()
	mfaRecord, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: target, Operation: manualrecovery.OperationMFAReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-mfa", EvidenceSummary: "线下核验",
		Reason: "两步验证恢复", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-mfa-create",
	})
	if err != nil {
		t.Fatalf("创建 MFA 恢复申请: %v", err)
	}
	if _, err := env.service.Approve(env.ctx, env.caller(approver), manualrecovery.ApproveRequest{
		RequestID: mfaRecord.ID, TraceID: "req-mfa-approve"}); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("只有密码恢复权限不能审批 MFA 恢复，得到 %v", err)
	}
	// 登录审计绑定 operation_type，确认审批按操作类型区分。
	if len(env.auth.requests) < 2 {
		t.Fatalf("敏感策略调用不足: %d", len(env.auth.requests))
	}
	if env.auth.requests[len(env.auth.requests)-1].OperationID != manualrecovery.OperationApprove {
		t.Fatal("审批应使用 support.recovery.approve 操作")
	}
	// 密码恢复申请批准后篡改操作类型为 MFA：内容摘要不一致而拒绝。
	env.staff.mu.Lock()
	env.staff.approve[approver][manualrecovery.OperationMFAReset] = true
	env.staff.mu.Unlock()
	passwordRecord := env.create()
	env.approve(passwordRecord.ID)
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE manual_recovery_requests SET operation_type='mfa_reset' WHERE id=?`, passwordRecord.ID); err != nil {
		t.Fatalf("篡改操作类型: %v", err)
	}
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: passwordRecord.ID, TraceID: "req-op-mismatch"}); !errors.Is(err, manualrecovery.ErrContentChanged) {
		t.Fatalf("跨操作类型执行应拒绝，得到 %v", err)
	}
}

// TestAuditFailureRollsBackCreation 验证审计事务失败时申请不落库（故障回滚）。
func TestAuditFailureRollsBackCreation(t *testing.T) {
	var inject *failingAudit
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		inject = &failingAudit{inner: options.Audit}
		options.Audit = inject
	})
	inject.mu.Lock()
	inject.failCritical = 1
	inject.mu.Unlock()
	_, err := env.service.Create(env.ctx, env.caller(initiator), manualrecovery.CreateRequest{
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
		VerificationReference: "ref-1", EvidenceSummary: "证据", Reason: "原因",
		Delivery: manualrecovery.DeliveryVerifiedEmail, RequestID: "req-audit-fail",
	})
	if !errors.Is(err, manualrecovery.ErrAuditUnavailable) {
		t.Fatalf("审计失败应拒绝创建，得到 %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests`) != 0 {
		t.Fatal("审计失败后申请不应落库")
	}
}

// TestApproverTargetScopeDenied 验证 47-FIX：审批人只能审批其数据范围内的目标，
// 范围外目标在审批时被拒绝并写失败审计。
func TestApproverTargetScopeDenied(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.staff.mu.Lock()
	env.staff.approvalTargets = map[string]map[string]bool{
		approver: {highUser: true},
	}
	env.staff.mu.Unlock()
	if _, err := env.service.Approve(env.ctx, env.caller(approver), manualrecovery.ApproveRequest{
		RequestID: record.ID, TraceID: "req-scope"}); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("范围外目标审批应拒绝，得到 %v", err)
	}
	if !strings.Contains(env.auditDump(), "approver_not_qualified") {
		t.Fatal("范围外审批拒绝缺少失败审计")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals`) != 0 {
		t.Fatal("范围外审批不应产生批准")
	}
}

// TestDeliveryAddressChangeInvalidatesApproval 验证 47-FIX：批准绑定交付地址指纹，
// 批准后目标换绑已验证邮箱（地址变化）则执行 fail-closed。
func TestDeliveryAddressChangeInvalidatesApproval(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.targets.mu.Lock()
	state := env.targets.states[target]
	state.DeliveryFingerprint = "fp:new-address@example.test"
	env.targets.states[target] = state
	env.targets.mu.Unlock()
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-address"}); !errors.Is(err, manualrecovery.ErrContentChanged) {
		t.Fatalf("交付地址变化应拒绝执行，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("交付地址变化后不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='failed'`) != 1 {
		t.Fatal("交付地址变化后申请应置失败")
	}
	if !strings.Contains(env.auditDump(), string(manualrecovery.ActionExecutionFail)) {
		t.Fatal("交付地址变化缺少失败审计")
	}
}

// TestRequestExpiryBlocksExecution 验证 47-FIX：批准晚于申请创建导致批准窗口超出
// 申请生命周期时，申请过期后不得执行，批准一并失效。
func TestRequestExpiryBlocksExecution(t *testing.T) {
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Policy.WaitPeriod = time.Hour
		options.Policy.ApprovalTTL = 2 * time.Hour
		options.Policy.RequestTTL = 3 * time.Hour
	})
	record := env.create()
	// 申请即将到期时才批准：批准窗口（等待 1h + 有效 2h）会超出申请生命周期。
	env.now = env.now.Add(150 * time.Minute)
	env.approve(record.ID)
	env.now = env.now.Add(61 * time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-expired-request"}); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("申请过期后执行应拒绝，得到 %v", err)
	}
	if env.executor.calls != 0 {
		t.Fatal("申请过期后不应执行")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='expired'`) != 1 {
		t.Fatal("申请应置 expired")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='invalidated'`) != 1 {
		t.Fatal("申请过期后批准应失效")
	}
}

// TestEnabledRequiresNotifierAndCoveringRequestTTL 验证 47-FIX 的策略/装配校验：
// 启用必须有通知适配器；申请有效期必须覆盖等待期+批准有效期。
func TestEnabledRequiresNotifierAndCoveringRequestTTL(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := manualrecovery.New(manualrecovery.Options{
		Store: env.store, Audit: &failingAudit{inner: env.audit}, Reauth: env.auth,
		Staff: env.staff, Targets: env.targets, Executor: env.executor,
		Policy: manualrecovery.Policy{
			Enabled: true, RequireIndependentApproval: true,
			VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisInPersonIdentityDocument},
			DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:        time.Hour, ApprovalTTL: 12 * time.Hour, RequestTTL: 24 * time.Hour,
		},
		Now: func() time.Time { return env.now },
	}); !errors.Is(err, manualrecovery.ErrOptionsInvalid) {
		t.Fatalf("启用但缺少通知适配器应拒绝构造，得到 %v", err)
	}
	if _, err := manualrecovery.New(manualrecovery.Options{
		Store: env.store, Audit: env.audit, Reauth: env.auth,
		Staff: env.staff, Targets: env.targets, Executor: env.executor, Notifier: env.notifier,
		Policy: manualrecovery.Policy{
			Enabled: true, RequireIndependentApproval: true,
			VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisInPersonIdentityDocument},
			DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:        time.Hour, ApprovalTTL: 12 * time.Hour, RequestTTL: 2 * time.Hour,
		},
		Now: func() time.Time { return env.now },
	}); !errors.Is(err, manualrecovery.ErrOptionsInvalid) {
		t.Fatalf("申请有效期不覆盖等待期+批准有效期应拒绝构造，得到 %v", err)
	}
}

// TestNotificationOnlyAfterCommit 验证 47-FIX：完成通知在最终审计/状态提交之后发送，
// 通知时可观察到请求已 completed；通知失败只记录状态不回滚。
func TestNotificationOnlyAfterCommit(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	observedCompleted := -1
	env.notifier.mu.Lock()
	env.notifier.onNotify = func(string) {
		observedCompleted = env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='completed'`)
	}
	env.notifier.mu.Unlock()
	env.now = env.now.Add(time.Hour + time.Minute)
	result, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-notify-order"})
	if err != nil {
		t.Fatalf("执行: %v", err)
	}
	if observedCompleted != 1 {
		t.Fatalf("通知时请求完成状态 = %d，期望 1（通知必须在提交后）", observedCompleted)
	}
	if !result.NotificationSent {
		t.Fatal("通知应成功")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE notification_state='sent'`) != 1 {
		t.Fatal("执行通知状态未记录为 sent")
	}
}

// TestFinalizeAuditFailureCompensatesWithoutNotification 验证 47-FIX：最终审计提交失败
// 时执行器补偿、不发送完成通知、不宣称完成。
func TestFinalizeAuditFailureCompensatesWithoutNotification(t *testing.T) {
	var inject *failingAudit
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		inject = &failingAudit{inner: options.Audit}
		options.Audit = inject
	})
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	inject.mu.Lock()
	inject.successBefore = 1 // 执行权 claim 成功
	inject.failCritical = 1  // 最终完成审计失败
	inject.mu.Unlock()
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-final-audit-fail"}); !errors.Is(err, manualrecovery.ErrAuditUnavailable) {
		t.Fatalf("最终审计失败应拒绝，得到 %v", err)
	}
	if env.executor.compensate < 1 {
		t.Fatal("最终审计失败应尽力补偿执行器")
	}
	env.notifier.mu.Lock()
	notifications := len(env.notifier.kinds)
	env.notifier.mu.Unlock()
	if notifications != 0 {
		t.Fatal("最终审计失败不应发送完成通知")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE status='completed'`) != 0 {
		t.Fatal("最终审计失败不应宣称完成")
	}
}

// TestGetRequestHistoricalApprover 验证 47-FIX：批准消费/失效后审批人仍可查看申请
// （历史参与人授权），无关人员拒绝。
func TestGetRequestHistoricalApprover(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-history"}); err != nil {
		t.Fatalf("执行: %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals WHERE status='consumed'`) != 1 {
		t.Fatal("批准应已消费")
	}
	// 历史审批人可查看；执行人（非发起者/审批人）拒绝。
	if _, err := env.service.GetRequest(env.ctx, env.caller(approver), record.ID); err != nil {
		t.Fatalf("历史审批人应可查看申请: %v", err)
	}
	if _, err := env.service.GetRequest(env.ctx, env.caller(executor), record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("无关人员不应查看申请，得到 %v", err)
	}
}
