package support_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	staffOne   = "usr_00000000000000000000000000000001"
	staffTwo   = "usr_00000000000000000000000000000002"
	targetA    = "usr_00000000000000000000000000000011"
	targetB    = "usr_00000000000000000000000000000012"
	rootUser   = "usr_00000000000000000000000000000013"
	seedMillis = int64(1_700_000_000_000)
)

var fixedNow = time.UnixMilli(seedMillis).UTC()

// ===== 测试替身 =====

// fakeAuthorizer 按 工作人员/权限 返回数据范围；未配置时拒绝（fail-closed）。
type fakeAuthorizer struct {
	scopes   map[string]map[string]support.StaffScope
	eligible map[string]bool
	err      error
}

func (f *fakeAuthorizer) AuthorizeStaff(ctx context.Context, staffUserID, permissionKey string) (support.StaffScope, error) {
	if f.err != nil {
		return support.StaffScope{}, f.err
	}
	if byPermission, ok := f.scopes[staffUserID]; ok {
		if scope, ok := byPermission[permissionKey]; ok {
			return scope, nil
		}
	}
	return support.StaffScope{}, support.ErrAccessDenied
}

func (f *fakeAuthorizer) StaffEligible(ctx context.Context, staffUserID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.eligible[staffUserID], nil
}

// fakeProtector 返回受保护目标集合（模拟实际权限识别）。
type fakeProtector struct {
	protected map[string]bool
	err       error
}

func (f *fakeProtector) Protected(ctx context.Context, targetUserID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.protected[targetUserID], nil
}

// stubSensitive 模拟已接线的步骤 38/39 敏感策略执行器。
type stubSensitive struct {
	authorizeCalls int
	notifyCalls    int
	denyErr        error
	lastRequest    reauth.Request
}

func (s *stubSensitive) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	s.authorizeCalls++
	s.lastRequest = request
	if s.denyErr != nil {
		return reauth.Result{}, s.denyErr
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID}, nil
}

func (s *stubSensitive) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	s.notifyCalls++
	return nil
}

// fakeSender 记录受信找回发送调用并可注入错误。
type fakeSender struct {
	calls      int
	lastUserID string
	delivered  bool
	err        error
}

func (f *fakeSender) SendResetForSupport(ctx context.Context, request passwordreset.SupportResetRequest) (passwordreset.SupportResetResult, error) {
	f.calls++
	f.lastUserID = request.TargetUserID
	if f.err != nil {
		return passwordreset.SupportResetResult{}, f.err
	}
	return passwordreset.SupportResetResult{Delivered: f.delivered}, nil
}

// ===== 测试环境 =====

type testEnv struct {
	t      *testing.T
	ctx    context.Context
	raw    *storagesqlite.Store
	store  *supportsqlite.Store
	authz  *fakeAuthorizer
	prot   *fakeProtector
	sens   *stubSensitive
	sender *fakeSender
	svc    *support.Service
}

func newTestEnv(t *testing.T, mutate func(*support.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(t.TempDir()+"/support.db"))
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
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	store, err := supportsqlite.New(raw)
	if err != nil {
		t.Fatalf("求助单存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, store: store,
		authz: &fakeAuthorizer{scopes: map[string]map[string]support.StaffScope{}, eligible: map[string]bool{}},
		prot:  &fakeProtector{protected: map[string]bool{}},
		sens:  &stubSensitive{}, sender: &fakeSender{delivered: true}}
	options := support.Options{
		Store: store, Audit: recorder, Authorizer: env.authz,
		TargetProtector: env.prot, Sensitive: env.sens, ResetSender: env.sender,
		Now: func() time.Time { return fixedNow },
	}
	if mutate != nil {
		mutate(&options)
	}
	svc, err := support.New(options)
	if err != nil {
		t.Fatalf("客服服务: %v", err)
	}
	env.svc = svc
	// 默认：客服一负责 targetA，客服二负责 targetB；均具备 read/update/reset。
	env.grantStaff(staffOne, targetA)
	env.grantStaff(staffTwo, targetB)
	env.seedUser(staffOne, "staff-one", "active", false)
	env.seedUser(staffTwo, "staff-two", "active", false)
	env.seedUser(targetA, "alice", "active", false)
	env.seedUser(targetB, "bob", "active", false)
	env.seedUser(rootUser, "rootuser", "active", true)
	env.seedEmail(targetA, "alice@example.com")
	env.seedEmail(targetB, "bob@example.com")
	env.seedEmail(rootUser, "root@example.com")
	env.seedPassword(targetA)
	env.seedPassword(targetB)
	env.seedPassword(rootUser)
	return env
}

func (e *testEnv) grantStaff(staffID string, userIDs ...string) {
	scope := support.StaffScope{UserIDs: userIDs}
	if e.authz.scopes[staffID] == nil {
		e.authz.scopes[staffID] = map[string]support.StaffScope{}
	}
	for _, permission := range []string{
		support.PermissionCasesRead, support.PermissionCasesCreate,
		support.PermissionCasesUpdate, support.PermissionResetRequest,
	} {
		e.authz.scopes[staffID][permission] = scope
	}
	e.authz.eligible[staffID] = true
}

func (e *testEnv) seedUser(id, username, status string, isRoot bool) {
	e.t.Helper()
	rootInt := 0
	if isRoot {
		rootInt = 1
	}
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai',?,?,1,1,?,?)`,
		id, username, strings.ToLower(username), status, rootInt, seedMillis, seedMillis); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(id, address string) {
	e.t.Helper()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, strings.ToLower(address), id, address, seedMillis, seedMillis, seedMillis); err != nil {
		e.t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) seedPassword(id string) {
	e.t.Helper()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)`, id,
		"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$"+strings.Repeat("a", 43),
		seedMillis, seedMillis, seedMillis); err != nil {
		e.t.Fatalf("密码凭证: %v", err)
	}
}

func (e *testEnv) caller(t *testing.T, userID string) support.Caller {
	t.Helper()
	caller, err := support.UserCaller(userID)
	if err != nil {
		t.Fatalf("调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.raw.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func (e *testEnv) createCase(t *testing.T, staffID, targetID, reason string) support.CaseView {
	t.Helper()
	view, err := e.svc.CreateCase(e.ctx, e.caller(t, staffID), support.CreateCaseRequest{
		TargetUserID: targetID, Reason: reason, RequestID: "req-create"})
	if err != nil {
		t.Fatalf("登记求助单: %v", err)
	}
	return view
}

// ===== 测试用例 =====

// TestCreateCaseScopeMaskingAndAudit 覆盖客服范围、脱敏、处理历史与成功审计：
// 只返回脱敏资料；范围外目标拒绝并写失败审计；受理人不暴露。
func TestCreateCaseScopeMaskingAndAudit(t *testing.T) {
	env := newTestEnv(t, nil)
	view := env.createCase(t, staffOne, targetA, "用户来电求助：忘记密码")
	if !strings.HasPrefix(view.ID, "sup_") {
		t.Errorf("求助单 ID = %q", view.ID)
	}
	if view.TargetMaskedUsername != "al***" || view.TargetMaskedEmail != "a***@example.com" {
		t.Errorf("脱敏视图异常: username=%q email=%q", view.TargetMaskedUsername, view.TargetMaskedEmail)
	}
	if view.Status != support.StatusPendingVerification || view.AssigneeUserID != staffOne ||
		view.CreatedByUserID != staffOne || view.RowVersion != 1 {
		t.Errorf("求助单状态异常: %+v", view)
	}
	if env.count(`SELECT COUNT(*) FROM support_case_events WHERE case_id=?`, view.ID) != 1 {
		t.Error("缺少首条处理历史")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.created' AND outcome='success'`) != 1 {
		t.Error("缺少成功审计")
	}
	// 目标定位同样脱敏。
	targetView, err := env.svc.LookupTarget(env.ctx, env.caller(t, staffOne), targetA, "req-lookup")
	if err != nil {
		t.Fatalf("定位目标: %v", err)
	}
	if targetView.MaskedEmail != "a***@example.com" || !targetView.CanRequestReset {
		t.Errorf("目标视图异常: %+v", targetView)
	}
	// 范围外目标：拒绝并写失败审计。
	if _, err := env.svc.CreateCase(env.ctx, env.caller(t, staffOne), support.CreateCaseRequest{
		TargetUserID: targetB, Reason: "越权", RequestID: "req-out"}); !errors.Is(err, support.ErrAccessDenied) {
		t.Fatalf("范围外目标错误 = %v，期望 ErrAccessDenied", err)
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.denied' AND outcome='denied'`) < 1 {
		t.Error("范围外拒绝缺少失败审计")
	}
	if env.count(`SELECT COUNT(*) FROM support_cases`) != 1 {
		t.Error("拒绝后不应创建求助单")
	}
	// 审计不得包含邮箱明文或原始用户名。
	rows, err := env.raw.DB().QueryContext(env.ctx, `SELECT COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		for _, forbidden := range []string{"alice@example.com", "alice"} {
			if strings.Contains(detail, forbidden) {
				t.Errorf("审计泄露明文 %q: %s", forbidden, detail)
			}
		}
	}
}

// TestGetCaseOtherStaffDenied 覆盖查看他人工单拒绝、本人列表与系统只读视图。
func TestGetCaseOtherStaffDenied(t *testing.T) {
	env := newTestEnv(t, nil)
	view := env.createCase(t, staffOne, targetA, "求助")
	if _, err := env.svc.GetCase(env.ctx, env.caller(t, staffTwo), view.ID); !errors.Is(err, support.ErrAccessDenied) {
		t.Fatalf("查看他人工单错误 = %v，期望 ErrAccessDenied", err)
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.denied' AND outcome='denied' AND target_id=?`, view.ID) < 1 {
		t.Error("查看他人工单被拒缺少失败审计")
	}
	if _, err := env.svc.ListEvents(env.ctx, env.caller(t, staffTwo), view.ID, 0, 10); !errors.Is(err, support.ErrAccessDenied) {
		t.Fatalf("查看他人历史错误 = %v，期望 ErrAccessDenied", err)
	}
	own, err := env.svc.GetCase(env.ctx, env.caller(t, staffOne), view.ID)
	if err != nil || own.ID != view.ID {
		t.Fatalf("查看本人求助单: %v %+v", err, own)
	}
	page, err := env.svc.ListCases(env.ctx, env.caller(t, staffTwo), nil, 0, 10)
	if err != nil || len(page.Cases) != 0 {
		t.Fatalf("他人列表 = %+v，期望为空", page)
	}
	pageOne, err := env.svc.ListCases(env.ctx, env.caller(t, staffOne), nil, 0, 10)
	if err != nil || len(pageOne.Cases) != 1 {
		t.Fatalf("本人列表 = %+v", pageOne)
	}
	history, err := env.svc.ListEvents(env.ctx, env.caller(t, staffOne), view.ID, 0, 10)
	if err != nil || len(history.Events) != 1 || history.Events[0].ActorID != staffOne {
		t.Fatalf("处理历史 = %+v", history)
	}
}

// TestHighPrivilegeTargetRejected 覆盖按实际权限拒绝高权限目标：root 与受保护账户
// 返回 SUPPORT_TARGET_PROTECTED，且不创建求助单。
func TestHighPrivilegeTargetRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	env.grantStaff(staffOne, targetA, targetB, rootUser)
	env.prot.protected[targetB] = true
	for _, target := range []string{rootUser, targetB} {
		_, err := env.svc.CreateCase(env.ctx, env.caller(t, staffOne), support.CreateCaseRequest{
			TargetUserID: target, Reason: "高权限目标", RequestID: "req-protected"})
		if !errors.Is(err, support.ErrTargetProtected) {
			t.Fatalf("高权限目标 %s 错误 = %v，期望 ErrTargetProtected", target, err)
		}
		if code := support.CodeOf(err); code != support.CodeSupportTargetProtected {
			t.Errorf("错误码 = %q，期望 SUPPORT_TARGET_PROTECTED", code)
		}
	}
	if env.count(`SELECT COUNT(*) FROM support_cases`) != 0 {
		t.Error("高权限目标不应创建求助单")
	}
	if _, err := env.svc.LookupTarget(env.ctx, env.caller(t, staffOne), targetB, "req-lookup"); !errors.Is(err, support.ErrTargetProtected) {
		t.Fatalf("定位高权限目标错误 = %v，期望 ErrTargetProtected", err)
	}
}

// TestReassignAndStatusTransitionsAudited 覆盖指派变更、状态流转与历史不可覆盖：
// 指派后原客服失去访问；终态不可再变更；数据库层拒绝改写处理历史。
func TestReassignAndStatusTransitionsAudited(t *testing.T) {
	env := newTestEnv(t, nil)
	view := env.createCase(t, staffOne, targetA, "求助")
	// 新受理客服需要同时具备客服资格与目标数据范围。
	env.grantStaff(staffTwo, targetB, targetA)
	reassigned, err := env.svc.ReassignCase(env.ctx, env.caller(t, staffOne), support.ReassignRequest{
		CaseID: view.ID, NewAssigneeUserID: staffTwo, RequestID: "req-assign"})
	if err != nil {
		t.Fatalf("转派: %v", err)
	}
	if reassigned.AssigneeUserID != staffTwo || reassigned.RowVersion != 2 {
		t.Errorf("转派结果异常: %+v", reassigned)
	}
	if _, err := env.svc.GetCase(env.ctx, env.caller(t, staffOne), view.ID); !errors.Is(err, support.ErrAccessDenied) {
		t.Fatalf("转派后原客服访问错误 = %v，期望 ErrAccessDenied", err)
	}
	// 新客服可以关闭求助单，终态后不能再变更。
	closed, err := env.svc.TransitionCase(env.ctx, env.caller(t, staffTwo), support.TransitionRequest{
		CaseID: view.ID, ToStatus: support.StatusClosed, Note: "已处理", RequestID: "req-close"})
	if err != nil || closed.Status != support.StatusClosed {
		t.Fatalf("关闭求助单: %v %+v", err, closed)
	}
	if _, err := env.svc.TransitionCase(env.ctx, env.caller(t, staffTwo), support.TransitionRequest{
		CaseID: view.ID, ToStatus: support.StatusCancelled, RequestID: "req-cancel"}); !errors.Is(err, support.ErrCaseClosed) {
		t.Fatalf("终态再变更错误 = %v，期望 ErrCaseClosed", err)
	}
	if _, err := env.svc.ReassignCase(env.ctx, env.caller(t, staffTwo), support.ReassignRequest{
		CaseID: view.ID, NewAssigneeUserID: staffOne, RequestID: "req-assign2"}); !errors.Is(err, support.ErrCaseClosed) {
		t.Fatalf("终态转派错误 = %v，期望 ErrCaseClosed", err)
	}
	// 处理历史追加：登记 + 转派 + 关闭 = 3 条，且数据库触发器禁止改写。
	if got := env.count(`SELECT COUNT(*) FROM support_case_events WHERE case_id=?`, view.ID); got != 3 {
		t.Errorf("处理历史条数 = %d，期望 3", got)
	}
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE support_case_events SET detail='覆盖' WHERE case_id=?`, view.ID); err == nil {
		t.Fatal("处理历史不应允许 UPDATE（审计不可覆盖）")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.assigned' AND outcome='success'`) != 1 {
		t.Error("缺少转派成功审计")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.status_changed' AND outcome='success'`) != 1 {
		t.Error("缺少状态变更成功审计")
	}
}

// TestSendResetUsesOriginalVerifiedEmail 覆盖发送动作：复用找回服务、只按目标 ID
// 发起（不能指定地址）、不返回链接、发送成功后才标记 sent，限流错误不回滚状态。
func TestSendResetUsesOriginalVerifiedEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	view := env.createCase(t, staffOne, targetA, "求助")
	result, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: view.ID, RequestID: "req-send"})
	if err != nil {
		t.Fatalf("发起找回: %v", err)
	}
	if !result.Sent || result.ManualReview || result.Status != support.StatusSent {
		t.Errorf("发送结果异常: %+v", result)
	}
	if env.sender.calls != 1 || env.sender.lastUserID != targetA {
		t.Errorf("找回服务调用异常: calls=%d user=%q", env.sender.calls, env.sender.lastUserID)
	}
	updated, err := env.svc.GetCase(env.ctx, env.caller(t, staffOne), view.ID)
	if err != nil || updated.Status != support.StatusSent {
		t.Fatalf("发送后状态: %v %+v", err, updated)
	}
	// 发送动作不应触碰密码：目标密码凭证保持不变。
	var mustChange int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT must_change FROM password_credentials WHERE user_id=?`, targetA).Scan(&mustChange); err != nil {
		t.Fatalf("读取密码凭证: %v", err)
	}
	if mustChange != 0 {
		t.Error("发送找回不应修改密码凭证")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.reset_requested' AND outcome='success'`) != 1 {
		t.Error("缺少发起找回成功审计")
	}
	// 找回服务限流：返回 RATE_LIMITED，状态保持 sent。
	env.sender.err = passwordreset.ErrRateLimited
	if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: view.ID, RequestID: "req-send2"}); !errors.Is(err, support.ErrRateLimited) {
		t.Fatalf("重复发起错误 = %v，期望 ErrRateLimited", err)
	}
	after, err := env.svc.GetCase(env.ctx, env.caller(t, staffOne), view.ID)
	if err != nil || after.Status != support.StatusSent {
		t.Fatalf("限流后状态: %v %+v", err, after)
	}
	if code := support.CodeOf(support.ErrRateLimited); code != support.CodeRateLimited {
		t.Errorf("限流错误码 = %q", code)
	}
}

// TestSendResetManualReviewWithoutChannel 覆盖未具备验证渠道：只转人工核验待处理，
// 不调用找回服务、不宣称已完成。
func TestSendResetManualReviewWithoutChannel(t *testing.T) {
	env := newTestEnv(t, nil)
	const noEmailTarget = "usr_00000000000000000000000000000014"
	env.seedUser(noEmailTarget, "noemail", "active", false)
	env.seedPassword(noEmailTarget)
	env.grantStaff(staffOne, noEmailTarget)
	view := env.createCase(t, staffOne, noEmailTarget, "用户无法收邮件")
	result, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: view.ID, RequestID: "req-manual"})
	if err != nil {
		t.Fatalf("转入人工核验: %v", err)
	}
	if !result.ManualReview || result.Sent || result.Status != support.StatusManualReview {
		t.Errorf("人工核验结果异常: %+v", result)
	}
	if env.sender.calls != 0 {
		t.Error("缺少验证渠道时不应调用找回服务")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.manual_review' AND outcome='success'`) != 1 {
		t.Error("缺少转入人工核验审计")
	}
}

// TestStrongAuthGateAndMissingDependencies 覆盖强认证闸门与依赖缺失 fail-closed：
// 敏感策略拒绝时不产生求助单；构造时缺任一依赖直接拒绝。
func TestStrongAuthGateAndMissingDependencies(t *testing.T) {
	env := newTestEnv(t, nil)
	env.sens.denyErr = reauth.ErrReauthRequired
	_, err := env.svc.CreateCase(env.ctx, env.caller(t, staffOne), support.CreateCaseRequest{
		TargetUserID: targetA, Reason: "求助", RequestID: "req-reauth"})
	if !errors.Is(err, support.ErrReauthRequired) {
		t.Fatalf("强认证拒绝错误 = %v，期望 ErrReauthRequired", err)
	}
	if env.sens.authorizeCalls != 1 || env.sens.lastRequest.OperationID != support.OperationCaseCreate ||
		env.sens.lastRequest.TargetID != targetA {
		t.Errorf("敏感策略绑定异常: calls=%d %+v", env.sens.authorizeCalls, env.sens.lastRequest)
	}
	if env.count(`SELECT COUNT(*) FROM support_cases`) != 0 {
		t.Error("被拒绝时不应创建求助单")
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.denied' AND outcome='denied'`) < 1 {
		t.Error("强认证拒绝缺少失败审计")
	}
	// 缺任一依赖构造失败。
	if _, err := support.New(support.Options{}); !errors.Is(err, support.ErrOptionsInvalid) {
		t.Fatalf("缺依赖构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}
