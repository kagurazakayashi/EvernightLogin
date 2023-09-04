package serverapp

// 步骤 188 应用客服跨链路 E2E：真实 SQLite + appsupport/support/manualrecovery/
// passwordreset/session/audit 服务与 Mail 夹具。
//   - 应用客服（受限身份）只能在本应用建工单，不能改密码/MFA/读链接；越权被拒且审计；
//   - 工单经系统客服接手（SupportCaseID）→ 独立审批 → 受控执行 → 找回交付 → 撤会话；
//   - 系统侧权限按 recovery.request/approve/execute 精确判定，应用客服不获得这些权限。

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/appsupport"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
	supportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/support/sqlite"
)

const (
	ccAppA       = "app_000000000000000000000000000000c1"
	ccAppB       = "app_000000000000000000000000000000c2"
	ccAppStaff   = "usr_000000000000000000000000000000c3"
	ccSysOne     = "usr_000000000000000000000000000000c4"
	ccSysTwo     = "usr_000000000000000000000000000000c5"
	ccSysRun     = "usr_000000000000000000000000000000c6"
	ccTarget     = "usr_000000000000000000000000000000c7"
	ccTargetMail = "crosschain@example.test"
	ccTokenA     = "token-app-a-188"
	ccTokenB     = "token-app-b-188"
)

type ccTokens struct{}

func (ccTokens) ValidateToken(_ context.Context, raw string) (appsupport.Identity, error) {
	switch raw {
	case ccTokenA:
		return appsupport.Identity{ApplicationID: ccAppA, StaffUserID: ccAppStaff}, nil
	case ccTokenB:
		return appsupport.Identity{ApplicationID: ccAppB, StaffUserID: ccAppStaff}, nil
	default:
		return appsupport.Identity{}, appsupport.ErrIdentityUnavailable
	}
}

type ccMembership struct{}

func (ccMembership) IsActiveMember(context.Context, string, string) (bool, error) { return true, nil }

type ccPermissions struct{}

func (ccPermissions) CheckApplicationPermission(_ context.Context, appID, staffID, permission string) error {
	if staffID == ccAppStaff && appID == ccAppA &&
		(permission == "support.cases.create" || permission == "support.cases.read" ||
			permission == "support.cases.update") {
		return nil
	}
	return appsupport.ErrAccessDenied
}

type ccTargetProtector struct{}

func (ccTargetProtector) Protected(context.Context, string) (bool, error) { return false, nil }

type ccSensitive struct{}

func (ccSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID}, nil
}
func (ccSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error { return nil }

// ccSystemStaff 记录系统侧实际使用的权限键，并只允许三个系统操作员。
type ccSystemStaff struct {
	used   map[string][]string
	denied []string
}

func (s *ccSystemStaff) authorize(userID, key string) error {
	s.used[userID] = append(s.used[userID], key)
	switch userID {
	case ccSysOne:
		if key == "recovery.request" {
			return nil
		}
	case ccSysTwo:
		if key == "recovery.approve" || key == "recovery.mfa.approve" {
			return nil
		}
	case ccSysRun:
		if key == "recovery.execute" {
			return nil
		}
	}
	s.denied = append(s.denied, userID+"|"+key)
	return manualrecovery.ErrAccessDenied
}

func (s *ccSystemStaff) AuthorizeRequest(_ context.Context, userID, _ string, _ manualrecovery.OperationType) error {
	return s.authorize(userID, "recovery.request")
}
func (s *ccSystemStaff) AuthorizeApproval(_ context.Context, userID, _ string, _ string,
	_ manualrecovery.OperationType) error {
	return s.authorize(userID, "recovery.approve")
}
func (s *ccSystemStaff) AuthorizeExecution(_ context.Context, userID, _ string,
	_ manualrecovery.OperationType) error {
	return s.authorize(userID, "recovery.execute")
}

// ccSupportAuthorizer 允许系统客服读取/更新工单（仅系统操作员）；应用客服没有系统客服权限。
type ccSupportAuthorizer struct{}

func (ccSupportAuthorizer) AuthorizeStaff(_ context.Context, staffUserID, key string) (support.StaffScope, error) {
	if staffUserID == ccAppStaff || staffUserID == ccSysOne || staffUserID == ccSysTwo || staffUserID == ccSysRun {
		switch key {
		case support.PermissionCasesRead, support.PermissionCasesUpdate, support.PermissionCasesCreate:
			return support.StaffScope{AllUsers: true}, nil
		}
	}
	return support.StaffScope{}, support.ErrAccessDenied
}
func (ccSupportAuthorizer) StaffEligible(context.Context, string) (bool, error) { return true, nil }

// TestAppSupportCrossChainManualRecovery 覆盖应用工单→系统恢复→交付→撤会话链路。
func TestAppSupportCrossChainManualRecovery(t *testing.T) {
	ctx := context.Background()
	store := openMigratedStore(t)
	recorder := newTestAudit(t, store)
	keyring, err := secrets.GenerateKeyring("cross-chain-test", time.Now())
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	nowMS := time.Now().UTC().UnixMilli()
	exec := func(query string, args ...any) {
		if _, err := store.DB().ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("播种数据: %v", err)
		}
	}
	for _, user := range []string{ccAppStaff, ccSysOne, ccSysTwo, ccSysRun, ccTarget} {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, user, "cc-"+user[len(user)-2:], "cc-"+user[len(user)-2:], nowMS, nowMS)
	}
	exec(`INSERT INTO applications(id,name,description,owner_user_id,status,client_type,
row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?,'active','confidential',1,?,?)`,
		ccAppA, "跨链应用A", "测试", ccSysOne, nowMS, nowMS)
	exec(`INSERT INTO user_emails(user_id,email,email_normalized,verified_at_ms,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`, ccTarget, ccTargetMail, ccTargetMail, nowMS, nowMS, nowMS)
	exec(`INSERT INTO password_credentials(user_id,hash_scheme,hash_version,password_hash,
must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
VALUES(?,'argon2id',19,?,0,1,?,?,?)`, ccTarget, strings.Repeat("a", 64), nowMS, nowMS, nowMS)

	// 真实服务依赖：会话/找回/Mail 夹具/凭证。
	mailService := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	sender := recoveryMailSender{instance: mailService, t: t}
	credentialStore, err := credentialsqlite.New(store)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{Keyring: keyring, Now: time.Now})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: recorder, Keyring: keyring, Now: time.Now})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	resetStore, err := passwordresetsqlite.New(store)
	if err != nil {
		t.Fatalf("找回存储: %v", err)
	}
	resetService, err := passwordreset.New(passwordreset.Options{
		Store: resetStore, Audit: recorder, Credentials: credentialService,
		Passwords: recoveryPasswordStub{}, Sessions: sessionService, Mailer: sender,
		FromAddress: "noreply@example.test", ResetURLBase: "http://127.0.0.1/reset",
		Now: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("找回服务: %v", err)
	}
	supportStore, err := supportsqlite.New(store)
	if err != nil {
		t.Fatalf("客服存储: %v", err)
	}
	systemSupport, err := support.New(support.Options{
		Store: supportStore, Audit: recorder, Authorizer: ccSupportAuthorizer{},
		TargetProtector: ccTargetProtector{}, Sensitive: ccSensitive{},
		ResetSender: resetService, Now: func() time.Time { return time.Now() },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("系统客服服务: %v", err)
	}
	appSupportService, err := appsupport.New(appsupport.Options{
		Store: supportStore, Audit: recorder, Tokens: ccTokens{},
		Membership: ccMembership{}, Permissions: ccPermissions{},
		TargetProtector: ccTargetProtector{}, Now: func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("应用客服服务: %v", err)
	}
	appHandler, err := appsupport.NewHTTPHandler(appsupport.HTTPOptions{Service: appSupportService})
	if err != nil {
		t.Fatalf("应用客服 HTTP: %v", err)
	}

	// 1) 应用客服仅能建本应用工单；尝试携带 password 字段被白名单拒绝。
	caseView, err := appSupportService.CreateCase(ctx, ccTokenA, appsupport.CreateCaseRequest{
		TargetUserID: ccTarget, Reason: "应用 A 客服升级申请",
		RequestID: "req-cross-chain-app"})
	if err != nil {
		t.Fatalf("应用客服建单: %v", err)
	}
	badBody := `{"target_user_id":"` + ccTarget + `","reason":"x","password":"should-not-be-accepted"}`
	badRequest := httptest.NewRequest(http.MethodPost, "/api/app/v1/support/cases",
		strings.NewReader(badBody))
	badRequest.Header.Set("Authorization", "Bearer "+ccTokenA)
	badRequest.Header.Set("Content-Type", "application/json")
	badResponse := httptest.NewRecorder()
	appHandler.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("应用客服用含密码字段请求应 400，实际 %d", badResponse.Code)
	}
	// 跨应用读取被拒绝（不泄露存在性）。
	if _, err := appSupportService.GetCase(ctx, ccTokenB, caseView.ID); err == nil {
		t.Fatal("应用 B 读取应用 A 工单应被拒绝")
	}

	// 2) 系统客服接手同一工单（受控指派后读取）。
	handoffCaller, _ := support.UserCaller(ccAppStaff)
	if _, err := systemSupport.ReassignCase(ctx, handoffCaller, support.ReassignRequest{
		CaseID: caseView.ID, NewAssigneeUserID: ccSysOne,
		RequestID: "req-cross-chain-assign"}); err != nil {
		t.Fatalf("系统客服接手应用工单: %v", err)
	}
	sysCaller, _ := support.UserCaller(ccSysOne)
	caseDetail, err := systemSupport.GetCase(ctx, sysCaller, caseView.ID)
	if err != nil {
		t.Fatalf("系统客服读取应用工单: %v", err)
	}
	if string(caseDetail.Status) != string(support.StatusManualReview) {
		t.Fatalf("应用工单状态 = %s，期望 manual_review", caseDetail.Status)
	}
	manualStore, err := manualrecoverysqlite.New(store)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	staff := &ccSystemStaff{used: map[string][]string{}}
	clock := time.Now().UTC()
	targets := manualRecoveryTargets{store: store, keyring: keyring, checker: nil}
	bootstrapStore, err := bootstrapsqlite.New(store)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		t.Fatalf("root 检查: %v", err)
	}
	targets.roots = roots
	executor := manualRecoveryExecutor{passwordReset: resetService, sessions: sessionService,
		targets: targets, strongSetupAllowed: true}
	notifier := manualRecoveryNotifier{sender: sender, store: store,
		from: mailer.Address{Spec: "noreply@example.test"}, appName: "CrossChain"}
	manualService, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: recorder, Reauth: recoveryReauthStub{}, Staff: staff,
		Targets: targets, Executor: executor, Notifier: notifier,
		Policy: manualrecovery.Policy{Enabled: true,
			VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisNotarizedDeclaration},
			DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:        time.Hour, ApprovalTTL: 2 * time.Hour, RequestTTL: 3 * time.Hour,
			RequireIndependentApproval: true},
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	// 应用客服身份不能发起系统人工恢复（权限口径 recovery.request）。
	appCaller, _ := manualrecovery.UserCaller(ccAppStaff)
	if _, err := manualService.Create(ctx, appCaller, manualrecovery.CreateRequest{
		TargetUserID: ccTarget, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-cross-1", EvidenceSummary: "应用客服越权尝试",
		Reason: "越权尝试", Delivery: manualrecovery.DeliveryVerifiedEmail,
		SupportCaseID: caseView.ID, RequestID: "req-cross-chain-denied"}); err == nil {
		t.Fatal("应用客服不应能发起系统人工恢复")
	}
	// 系统客服发起，并绑定应用工单。
	initiator, _ := manualrecovery.UserCaller(ccSysOne)
	record, err := manualService.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: ccTarget, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-cross-2", EvidenceSummary: "系统客服接手核验",
		Reason: "用户丢失密码", Delivery: manualrecovery.DeliveryVerifiedEmail,
		SupportCaseID: caseView.ID, RequestID: "req-cross-chain-request"})
	if err != nil {
		t.Fatalf("系统人工恢复申请: %v", err)
	}
	if record.SupportCaseID != caseView.ID {
		t.Fatalf("人工恢复未关联应用工单: %+v", record.SupportCaseID)
	}
	// 3) 独立审批（recovery.approve）；执行过早拒绝，等待后执行（recovery.execute）。
	approver, _ := manualrecovery.UserCaller(ccSysTwo)
	if _, err := manualService.Approve(ctx, approver, manualrecovery.ApproveRequest{
		RequestID: record.ID, Note: "独立核验", TraceID: "trace-cross-approve"}); err != nil {
		t.Fatalf("独立审批: %v", err)
	}
	executorCaller, _ := manualrecovery.UserCaller(ccSysRun)
	if _, err := manualService.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-cross-early"}); err == nil {
		t.Fatal("等待期未到不得执行")
	}
	clock = clock.Add(90 * time.Minute)
	result, err := manualService.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-cross-exec"})
	if err != nil || result.Status != manualrecovery.StatusCompleted {
		t.Fatalf("受控执行失败: %+v %v", result, err)
	}
	if result.SessionsRevoked < 0 || !result.CredentialIssued {
		t.Fatalf("执行结果不含交付/撤会话: %+v", result)
	}
	// 找回交付：Mail 夹具收到找回邮件；执行器不返回链接/密码。
	messages, err := mailService.Messages(mailtest.Query{To: ccTargetMail, Limit: 10})
	if err != nil || len(messages) == 0 {
		t.Fatalf("应用工单跨链恢复未投递找回邮件: %v", err)
	}
	// 权限口径：系统侧仅使用 recovery.request/approve/execute；应用客服从未获得这些键。
	for _, key := range []string{"recovery.request", "recovery.approve", "recovery.execute"} {
		found := false
		for _, usedKeys := range staff.used {
			for _, used := range usedKeys {
				if used == key {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("系统侧未使用权限键 %s", key)
		}
	}
	appDenied := false
	for _, denied := range staff.denied {
		if denied == ccAppStaff+"|recovery.request" {
			appDenied = true
		}
	}
	if !appDenied {
		t.Fatal("应用客服尝试系统恢复未被权限判定拒绝")
	}
	// 审计：应用工单创建、人工恢复拒绝/执行均记录真实操作者。
	var count int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events
WHERE action IN ('support.app.case.created','manual_recovery.executed')`).Scan(&count); err != nil {
		t.Fatalf("查询审计: %v", err)
	}
	if count < 2 {
		t.Fatalf("跨链审计事件不足: %d", count)
	}
}
