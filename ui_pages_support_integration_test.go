package login_test

// 步骤 71 真实服务集成测试：客服求助、人工恢复申请/独立审批/执行页面通过
// internal/uiadminadapter 接到真实 support/manualrecovery 服务（隔离 SQLite、
// 本地测试发送器、合成账户），验证不同工作人员账户、跨范围拒绝、自批拒绝、
// 等待期、重复执行、通知失败与权限撤销后的页面行为。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	itStaffA  = "usr_00000000000000000000000000000001"
	itStaffB  = "usr_00000000000000000000000000000002"
	itExec    = "usr_00000000000000000000000000000003"
	itTargetA = "usr_00000000000000000000000000000011"
	itTargetB = "usr_00000000000000000000000000000012"
	itSeedMS  = int64(1_780_000_000_000)
)

// itAuthorizer 是客服服务授权器替身（仅测试；生产由 authz 实现）。
type itAuthorizer struct {
	mu     sync.Mutex
	scopes map[string]map[string]support.StaffScope
}

func (a *itAuthorizer) AuthorizeStaff(_ context.Context, staffUserID, permission string) (support.StaffScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if scope, ok := a.scopes[staffUserID][permission]; ok {
		return scope, nil
	}
	return support.StaffScope{}, support.ErrAccessDenied
}

func (a *itAuthorizer) StaffEligible(_ context.Context, staffUserID string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.scopes[staffUserID]
	return ok, nil
}

// itProtector 高权限目标识别替身。
type itProtector struct{ protected map[string]bool }

func (p itProtector) Protected(_ context.Context, userID string) (bool, error) {
	return p.protected[userID], nil
}

// itSensitive 模拟已接线的敏感策略执行器（测试内始终放行强认证）。
type itSensitive struct{}

func (itSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID}, nil
}

func (itSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error { return nil }

// itSender 是本地测试发送器：记录调用，不真实外发。
type itSender struct {
	mu      sync.Mutex
	calls   int
	last    string
	failErr error
}

func (s *itSender) SendResetForSupport(_ context.Context,
	request passwordreset.SupportResetRequest) (passwordreset.SupportResetResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.last = request.TargetUserID
	if s.failErr != nil {
		return passwordreset.SupportResetResult{}, s.failErr
	}
	return passwordreset.SupportResetResult{Delivered: true}, nil
}

// itStaff 是人工恢复工作人员授权替身。
type itStaff struct {
	mu      sync.Mutex
	request map[string]bool
	approve map[string]map[manualrecovery.OperationType]bool
	execute map[string]bool
}

func (s *itStaff) AuthorizeRequest(_ context.Context, staffUserID, _ string,
	_ manualrecovery.OperationType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.request[staffUserID] {
		return manualrecovery.ErrAccessDenied
	}
	return nil
}

func (s *itStaff) AuthorizeApproval(_ context.Context, approverUserID, _ string, _ string,
	operation manualrecovery.OperationType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.approve[approverUserID][operation] {
		return manualrecovery.ErrAccessDenied
	}
	return nil
}

func (s *itStaff) AuthorizeExecution(_ context.Context, executorUserID, _ string,
	_ manualrecovery.OperationType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.execute[executorUserID] {
		return manualrecovery.ErrAccessDenied
	}
	return nil
}

// itTargets 是人工恢复目标状态替身（真实服务组合时由宿主实现）。
type itTargets struct {
	states map[string]manualrecovery.TargetState
}

func (t itTargets) LoadTarget(_ context.Context, userID string) (manualrecovery.TargetState, error) {
	state, ok := t.states[userID]
	if !ok {
		return manualrecovery.TargetState{}, manualrecovery.ErrTargetUnavailable
	}
	return state, nil
}

// itExecutor 记录受控执行调用。
type itExecutor struct {
	mu      sync.Mutex
	calls   int
	outcome manualrecovery.ExecutionOutcome
}

func (e *itExecutor) Execute(_ context.Context,
	_ manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return e.outcome, nil
}

func (e *itExecutor) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	return nil
}

// itNotifier 记录通知并记录错误；通知失败不回滚已完成恢复。
type itNotifier struct {
	mu      sync.Mutex
	kinds   []manualrecovery.NotificationKind
	failErr error
}

func (n *itNotifier) Notify(_ context.Context, notification manualrecovery.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.kinds = append(n.kinds, notification.Kind)
	return n.failErr
}

// itEnv 是集成测试环境。
type itEnv struct {
	t         *testing.T
	ctx       context.Context
	raw       *storagesqlite.Store
	recorder  *audit.Recorder
	now       time.Time
	cases     *support.Service
	recovery  *manualrecovery.Service
	authz     *itAuthorizer
	staff     *itStaff
	notifier  *itNotifier
	executor  *itExecutor
	sender    *itSender
	protector *itProtector
	targets   map[string]manualrecovery.TargetState
	// allowed 非 nil 时模拟宿主按真实权限键授予页面能力位（action -> 是否允许）。
	allowed map[string]map[string]bool
}

// newITEnv 构造隔离数据库与真实客服/人工恢复服务。
func newITEnv(t *testing.T, policy manualrecovery.Policy) *itEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx,
		storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "support-integration.db")))
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
	env := &itEnv{t: t, ctx: ctx, raw: raw, now: time.UnixMilli(itSeedMS).UTC()}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	env.recorder = recorder
	supportStore, err := supportsqlite.New(raw)
	if err != nil {
		t.Fatalf("求助单存储: %v", err)
	}
	env.authz = &itAuthorizer{scopes: map[string]map[string]support.StaffScope{}}
	env.sender = &itSender{}
	// 客服 A 负责 targetA；客服 B 负责 targetB。
	env.grantSupport(itStaffA, itTargetA)
	env.grantSupport(itStaffB, itTargetB)
	env.protector = &itProtector{protected: map[string]bool{}}
	env.cases, err = support.New(support.Options{Store: supportStore, Audit: recorder,
		Authorizer:      env.authz,
		TargetProtector: env.protector,
		Sensitive:       itSensitive{}, ResetSender: env.sender,
		Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("客服服务: %v", err)
	}
	recoveryStore, err := manualrecoverysqlite.New(raw)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	env.staff = &itStaff{
		request: map[string]bool{itStaffA: true},
		approve: map[string]map[manualrecovery.OperationType]bool{
			itStaffB: {manualrecovery.OperationPasswordReset: true,
				manualrecovery.OperationMFAReset: true},
		},
		execute: map[string]bool{itExec: true},
	}
	env.executor = &itExecutor{outcome: manualrecovery.ExecutionOutcome{
		Summary: "ok", SessionsRevoked: 2, FactorsReset: true, ResetCredentialIssued: true}}
	env.notifier = &itNotifier{}
	env.targets = map[string]manualrecovery.TargetState{
		itTargetA: {UserID: itTargetA, Active: true, SecurityVersion: 3,
			DeliveryFingerprint: "fp:alice"},
	}
	env.recovery, err = manualrecovery.New(manualrecovery.Options{
		Store: recoveryStore, Audit: recorder, Reauth: itSensitive{}, Staff: env.staff,
		Targets:  itTargets{states: env.targets},
		Executor: env.executor, Notifier: env.notifier, Policy: policy,
		Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	// 种子用户与已验证邮箱（隔离合成数据）。
	nowMS := env.now.UnixMilli()
	for _, user := range []string{itStaffA, itStaffB, itExec, itTargetA, itTargetB} {
		if _, err := raw.ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,3,1,?,?)`,
			user, "u"+user[len(user)-2:], "u"+user[len(user)-2:], nowMS, nowMS); err != nil {
			t.Fatalf("用户: %v", err)
		}
		if _, err := raw.ExecContext(ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, "mail-"+user[len(user)-2:]+"@example.test", user,
			"mail-"+user[len(user)-2:]+"@example.test", nowMS, nowMS, nowMS); err != nil {
			t.Fatalf("邮箱: %v", err)
		}
		if _, err := raw.ExecContext(ctx, `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)`, user,
			"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$"+strings.Repeat("a", 43),
			nowMS, nowMS, nowMS); err != nil {
			t.Fatalf("密码凭证: %v", err)
		}
	}
	return env
}

// grantSupport 给客服授予四类客服权限并限定目标范围。
func (e *itEnv) grantSupport(staffID string, targets ...string) {
	scope := support.StaffScope{UserIDs: targets}
	byPermission := map[string]support.StaffScope{}
	for _, permission := range []string{support.PermissionCasesRead, support.PermissionCasesCreate,
		support.PermissionCasesUpdate, support.PermissionResetRequest} {
		byPermission[permission] = scope
	}
	e.authz.scopes[staffID] = byPermission
}

// newUI 用真实服务适配器构造 WebUI（指定当前工作人员会话）。
func (e *itEnv) newUI(staffID string) *login.WebUI {
	e.t.Helper()
	adapter, err := uiadminadapter.NewSupport(uiadminadapter.SupportOptions{
		Cases: e.cases, Recovery: e.recovery,
		Authorize: func(_ context.Context, staffUserID, action string) error {
			if e.allowed != nil {
				if e.allowed[staffUserID][action] {
					return nil
				}
				return errors.New("denied")
			}
			if staffUserID == itStaffA || staffUserID == itStaffB || staffUserID == itExec {
				return nil
			}
			return errors.New("denied")
		},
		Reauth: func(context.Context, string,
			login.UISupportActionBinding) (login.UISupportEvidence, error) {
			return login.UISupportEvidence{VerifiedAt: e.now, Strength: "strong",
				Complete: true, Confirmed: true}, nil
		}})
	if err != nil {
		e.t.Fatalf("客服适配器: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:     appsTestSessions{userID: staffID, management: true},
		PageSupport: &login.UIPageSupportOptions{Backend: adapter}})
	if err != nil {
		e.t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// newAdapterUI 构造指定工作人员会话的页面框架。
func (e *itEnv) newAdapterUI(staffID string) *login.WebUI {
	e.t.Helper()
	return e.newUI(staffID)
}

// enabledRecoveryPolicy 返回测试用已启用制度（1 小时等待期）。
func enabledRecoveryPolicy() manualrecovery.Policy {
	return manualrecovery.Policy{
		Enabled:                    true,
		VerificationBases:          []manualrecovery.VerificationBasis{manualrecovery.BasisInPersonIdentityDocument},
		DeliveryChannels:           []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
		WaitPeriod:                 time.Hour,
		ApprovalTTL:                12 * time.Hour,
		RequestTTL:                 24 * time.Hour,
		RequireIndependentApproval: true,
	}
}

// TestUIPageSupportIntegrationRealServices 覆盖真实服务联调主链路：不同工作人员账户、
// 跨范围拒绝、发送回收、人工恢复自批拒绝、等待期、执行与重复执行、通知失败。
func TestUIPageSupportIntegrationRealServices(t *testing.T) {
	env := newITEnv(t, enabledRecoveryPolicy())
	staffAUI := env.newAdapterUI(itStaffA)
	// 1) 客服 A 登记真实求助单：页面显示脱敏资料，不含完整邮箱。
	created := serveSupportPage(staffAUI, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"create"},
			"target_user_id": {itTargetA}, "reason": {"用户忘记密码，来电求助"},
			"confirm": {"yes"}})
	body := supportBody(created)
	if created.Code != 200 || !strings.Contains(body, "sup_") ||
		!strings.Contains(body, "尚未发送邮件或恢复账户") {
		t.Fatalf("真实登记求助单 = %d", created.Code)
	}
	caseID := extractSupportID(body, "sup_")
	if caseID == "" {
		t.Fatalf("未取得真实求助单 ID")
	}
	// 详情页显示脱敏目标资料，不含完整邮箱。
	caseDetail := serveSupportPage(staffAUI, http.MethodGet,
		"/support/cases/detail?case_id="+caseID, nil)
	detailBody := supportBody(caseDetail)
	if caseDetail.Code != 200 || !strings.Contains(detailBody, "u1***") ||
		!strings.Contains(detailBody, "m***@example.test") ||
		strings.Contains(detailBody, "mail-11@example.test") ||
		!strings.Contains(detailBody, "support.case.created") {
		t.Fatalf("真实求助单详情/脱敏/历史 = %d", caseDetail.Code)
	}
	// 2) 客服 B 读取 A 的工单：无权限。
	staffBUI := env.newAdapterUI(itStaffB)
	crossRead := serveSupportPage(staffBUI, http.MethodGet,
		"/support/cases/detail?case_id="+caseID, nil)
	if crossRead.Code != http.StatusForbidden {
		t.Fatalf("跨工作人员读取应拒绝 = %d", crossRead.Code)
	}
	// 3) 客服 B 定位 A 范围内目标：统一拒绝（防枚举）。
	crossLookup := serveSupportPage(staffBUI, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"lookup"},
			"target_user_id": {itTargetA}})
	if crossLookup.Code != http.StatusForbidden ||
		!strings.Contains(supportBody(crossLookup), "你没有查看或处理该对象的权限") {
		t.Fatalf("超范围目标定位应统一拒绝 = %d", crossLookup.Code)
	}
	// 4) 客服 A 向原验证邮箱发送入口：真实服务调用本地发送器，页面不显示链接。
	send := serveSupportPage(staffAUI, http.MethodPost, "/support/cases/send",
		url.Values{"csrf_token": {"token"}, "case_id": {caseID}, "confirm": {"yes"}})
	if send.Code != 200 || env.sender.calls != 1 ||
		!strings.Contains(supportBody(send), "密码尚未因此改变") ||
		strings.Contains(supportBody(send), "http://") {
		t.Fatalf("真实发送找回 = %d", send.Code)
	}
	// 5) 人工恢复申请：由发起人 A 创建（案件详情页提交真实服务）。
	createRecovery := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"verify-2026-0001"},
			"evidence_summary":       {"线下核验证件原件，记录编号 verify-2026-0001"},
			"reason":                 {"既有邮箱不可用"}, "delivery": {"verified_email"},
			"support_case_id": {caseID}, "confirm": {"yes"}})
	recoveryBody := supportBody(createRecovery)
	if createRecovery.Code != 200 || !strings.Contains(recoveryBody, "mrr_") ||
		strings.Contains(recoveryBody, "线下核验证件原件") {
		t.Fatalf("真实创建人工恢复申请 = %d", createRecovery.Code)
	}
	requestID := extractSupportID(recoveryBody, "mrr_")
	if requestID == "" {
		t.Fatalf("未取得真实申请 ID")
	}
	// 6) 发起人打开审批页：显示不能自批，不渲染批准表单。
	selfApproval := serveSupportPage(staffAUI, http.MethodGet,
		"/support/recovery/approval?request_id="+requestID, nil)
	if selfApproval.Code != 200 ||
		!strings.Contains(supportBody(selfApproval), "不能审批本人发起或本人账户的恢复申请") ||
		strings.Contains(supportBody(selfApproval), `action="/support/recovery/approval"`) {
		t.Fatalf("自批限制 = %d", selfApproval.Code)
	}
	// 7) 发起人提交批准：服务端拒绝（自批）。
	selfSubmit := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/approval",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"note": {"自批尝试"}, "confirm": {"yes"}})
	if selfSubmit.Code != http.StatusForbidden {
		t.Fatalf("自批提交应被服务端拒绝 = %d", selfSubmit.Code)
	}
	// 8) 独立审批人 B 读取真实待审批内容并批准。
	candidateRead := serveSupportPage(staffBUI, http.MethodGet,
		"/support/recovery/approval?request_id="+requestID, nil)
	if candidateRead.Code != 200 ||
		!strings.Contains(supportBody(candidateRead), "密码恢复：作废旧密码") ||
		!strings.Contains(supportBody(candidateRead), "确认不是授权") {
		t.Fatalf("候选审批人读取待审批申请 = %d", candidateRead.Code)
	}
	approved := serveSupportPage(staffBUI, http.MethodPost, "/support/recovery/approval",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"note": {"已按记录编号复核"}, "confirm": {"yes"}})
	if approved.Code != 200 || !strings.Contains(supportBody(approved), "已批准，但尚未执行") {
		t.Fatalf("独立批准 = %d", approved.Code)
	}
	// 9) 等待期未满执行：服务端拒绝，页面不显示成功。
	execUI := env.newAdapterUI(itExec)
	tooEarly := serveSupportPage(execUI, http.MethodPost, "/support/recovery/execute",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID}, "confirm": {"yes"}})
	if tooEarly.Code == 200 && strings.Contains(supportBody(tooEarly), "恢复已执行完成") {
		t.Fatalf("等待期未满不应显示成功 = %d", tooEarly.Code)
	}
	if env.executor.calls != 0 {
		t.Fatalf("等待期未满不应调用执行器")
	}
	// 10) 等待期后执行；通知失败不回滚恢复。
	env.now = env.now.Add(time.Hour + time.Minute)
	env.notifier.failErr = errors.New("本地通知失败")
	executed := serveSupportPage(execUI, http.MethodPost, "/support/recovery/execute",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID}, "confirm": {"yes"}})
	executedBody := supportBody(executed)
	if executed.Code != 200 || env.executor.calls != 1 ||
		!strings.Contains(executedBody, "恢复已执行完成") ||
		!strings.Contains(executedBody, "完成通知发送失败") {
		t.Fatalf("真实执行/通知失败分离 = %d", executed.Code)
	}
	// 11) 重复执行：重新读取确认为已完成，显示幂等提示，不再次调用执行器。
	duplicate := serveSupportPage(execUI, http.MethodPost, "/support/recovery/execute",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID}, "confirm": {"yes"}})
	if duplicate.Code != 200 ||
		!strings.Contains(supportBody(duplicate), "该申请已执行，本次未再次执行") ||
		env.executor.calls != 1 {
		t.Fatalf("重复执行幂等 = %d", duplicate.Code)
	}
}

// extractSupportID 从页面正文提取稳定领域 ID（测试辅助）。
func extractSupportID(body, prefix string) string {
	index := strings.Index(body, prefix)
	if index < 0 {
		return ""
	}
	end := index
	for end < len(body) {
		character := body[end]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' {
			end++
			continue
		}
		break
	}
	return body[index:end]
}

// TestUIPageSupportIntegrationRecoveryDisabled 验证人工恢复默认关闭时页面显示真实原因，
// 且创建请求被服务端拒绝（不渲染可提交的假控件）。
func TestUIPageSupportIntegrationRecoveryDisabled(t *testing.T) {
	env := newITEnv(t, manualrecovery.DefaultPolicy())
	ui := env.newAdapterUI(itStaffA)
	created := serveSupportPage(ui, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"create"},
			"target_user_id": {itTargetA}, "reason": {"忘记密码"}, "confirm": {"yes"}})
	caseID := extractSupportID(supportBody(created), "sup_")
	if caseID == "" {
		t.Fatalf("未取得求助单 ID")
	}
	detail := serveSupportPage(ui, http.MethodGet,
		"/support/cases/detail?case_id="+caseID, nil)
	body := supportBody(detail)
	if detail.Code != 200 ||
		!strings.Contains(body, "人工恢复流程尚未由 root/宿主启用") ||
		strings.Contains(body, `action="/support/recovery/request"`) {
		t.Fatalf("未启用时不应渲染可提交的恢复表单 = %d", detail.Code)
	}
	submit := serveSupportPage(ui, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"ref-1"}, "evidence_summary": {"摘要"},
			"reason": {"原因"}, "delivery": {"verified_email"}, "confirm": {"yes"}})
	if submit.Code == 200 && strings.Contains(supportBody(submit), "已创建人工恢复申请") {
		t.Fatalf("未启用时不得创建申请 = %d", submit.Code)
	}
}

// TestUIPageSupportIntegrationApproverRevoked 验证审批人权限被撤销后不能读取/批准，
// 以及拒绝后的终态展示。
func TestUIPageSupportIntegrationApproverRevoked(t *testing.T) {
	env := newITEnv(t, enabledRecoveryPolicy())
	staffAUI := env.newAdapterUI(itStaffA)
	staffBUI := env.newAdapterUI(itStaffB)
	create := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"mfa_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"ref-2026-2"}, "evidence_summary": {"线下核验证件"},
			"reason": {"两步验证不可用"}, "delivery": {"verified_email"}, "confirm": {"yes"}})
	requestID := extractSupportID(supportBody(create), "mrr_")
	if requestID == "" {
		t.Fatalf("未取得申请 ID: %d", create.Code)
	}
	// 审批人先拒绝一份申请：终态只读。
	rejected := serveSupportPage(staffBUI, http.MethodPost, "/support/recovery/reject",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"reason": {"核验依据不足"}, "confirm": {"yes"}})
	if rejected.Code != 200 || !strings.Contains(supportBody(rejected), "已被独立审批人拒绝") {
		t.Fatalf("拒绝申请 = %d", rejected.Code)
	}
	// 第二份申请：撤销审批资格后读取与批准均被拒绝。
	second := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"ref-2026-3"}, "evidence_summary": {"线下核验证件"},
			"reason": {"密码不可用"}, "delivery": {"verified_email"}, "confirm": {"yes"}})
	secondID := extractSupportID(supportBody(second), "mrr_")
	if secondID == "" {
		t.Fatalf("未取得第二份申请 ID: %d", second.Code)
	}
	env.staff.mu.Lock()
	env.staff.approve[itStaffB] = map[manualrecovery.OperationType]bool{}
	env.staff.mu.Unlock()
	revokedRead := serveSupportPage(staffBUI, http.MethodGet,
		"/support/recovery/approval?request_id="+secondID, nil)
	if revokedRead.Code != http.StatusForbidden {
		t.Fatalf("审批资格撤销后读取应拒绝 = %d", revokedRead.Code)
	}
	revokedApprove := serveSupportPage(staffBUI, http.MethodPost, "/support/recovery/approval",
		url.Values{"csrf_token": {"token"}, "request_id": {secondID},
			"note": {"越权批准"}, "confirm": {"yes"}})
	if revokedApprove.Code != http.StatusForbidden {
		t.Fatalf("审批资格撤销后批准应拒绝 = %d", revokedApprove.Code)
	}
}

// TestUIPageSupportIntegrationFixRound 覆盖审计修复项：高权限目标拒绝、发起者取消成功、
// 执行能力位使用真实权限键（专职执行人可见执行确认页）、审批工作台制度读取失败区分。
func TestUIPageSupportIntegrationFixRound(t *testing.T) {
	env := newITEnv(t, enabledRecoveryPolicy())
	staffAUI := env.newAdapterUI(itStaffA)
	// 高权限目标拒绝普通客服流程（root/实际高权限由服务端识别，页面无继续旁路）。
	env.protector.protected[itTargetA] = true
	blocked := serveSupportPage(staffAUI, http.MethodPost, "/support/cases/create",
		url.Values{"csrf_token": {"token"}, "action": {"create"},
			"target_user_id": {itTargetA}, "reason": {"忘记密码"}, "confirm": {"yes"}})
	blockedBody := supportBody(blocked)
	if blocked.Code != http.StatusForbidden ||
		!strings.Contains(blockedBody, "不能走普通客服恢复流程") ||
		strings.Contains(blockedBody, `action="/support/recovery/request"`) {
		t.Fatalf("高权限目标拒绝 = %d", blocked.Code)
	}
	env.protector.protected[itTargetA] = false
	// 发起者取消：成功后状态为 cancelled，终态再取消被拒绝。
	create := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"ref-fix-1"}, "evidence_summary": {"线下核验证件"},
			"reason": {"密码不可用"}, "delivery": {"verified_email"}, "confirm": {"yes"}})
	requestID := extractSupportID(supportBody(create), "mrr_")
	if requestID == "" {
		t.Fatalf("未取得申请 ID: %d", create.Code)
	}
	cancelDenied := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/cancel",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"reason": {"不再需要"}})
	if cancelDenied.Code != http.StatusBadRequest {
		t.Fatalf("取消缺少确认应拒绝 = %d", cancelDenied.Code)
	}
	cancelled := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/cancel",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"reason": {"不再需要"}, "confirm": {"yes"}})
	if cancelled.Code != 200 || !strings.Contains(supportBody(cancelled), "已由发起人取消") {
		t.Fatalf("发起者取消 = %d", cancelled.Code)
	}
	again := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/cancel",
		url.Values{"csrf_token": {"token"}, "request_id": {requestID},
			"reason": {"重复取消"}, "confirm": {"yes"}})
	if again.Code == 200 {
		t.Fatalf("终态重复取消不应成功 = %d", again.Code)
	}
	// N2：页面能力位使用真实权限键 recovery.approve；专职执行人（仅该键）可见执行确认页。
	env.allowed = map[string]map[string]bool{
		itExec: {manualrecovery.PermissionApprove: true},
	}
	execUI := env.newAdapterUI(itExec)
	second := serveSupportPage(staffAUI, http.MethodPost, "/support/recovery/request",
		url.Values{"csrf_token": {"token"}, "target_user_id": {itTargetA},
			"operation": {"password_reset"}, "verification_basis": {"in_person_identity_document"},
			"verification_reference": {"ref-fix-2"}, "evidence_summary": {"线下核验证件"},
			"reason": {"密码不可用"}, "delivery": {"verified_email"}, "confirm": {"yes"}})
	secondID := extractSupportID(supportBody(second), "mrr_")
	if secondID == "" {
		t.Fatalf("未取得第二份申请 ID: %d", second.Code)
	}
	env.staff.mu.Lock()
	env.staff.approve[itStaffB][manualrecovery.OperationPasswordReset] = true
	env.staff.mu.Unlock()
	env.now = env.now.Add(time.Minute)
	approved := serveSupportPage(env.newAdapterUI(itStaffB), http.MethodPost, "/support/recovery/approval",
		url.Values{"csrf_token": {"token"}, "request_id": {secondID},
			"note": {"已复核"}, "confirm": {"yes"}})
	if approved.Code != 200 {
		t.Fatalf("独立批准 = %d", approved.Code)
	}
	env.now = env.now.Add(time.Hour)
	confirmPage := serveSupportPage(execUI, http.MethodGet,
		"/support/recovery/execute?request_id="+secondID, nil)
	if confirmPage.Code != 200 ||
		!strings.Contains(supportBody(confirmPage), `action="/support/recovery/execute"`) {
		t.Fatalf("专职执行人应可见执行确认页 = %d", confirmPage.Code)
	}
}
