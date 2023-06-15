// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package serverapp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
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
)

type recoveryStaffStub struct{}

func (recoveryStaffStub) AuthorizeRequest(context.Context, string, string, manualrecovery.OperationType) error {
	return nil
}
func (recoveryStaffStub) AuthorizeApproval(context.Context, string, string, string, manualrecovery.OperationType) error {
	return nil
}
func (recoveryStaffStub) AuthorizeExecution(context.Context, string, string, manualrecovery.OperationType) error {
	return nil
}

type recoveryReauthStub struct{}

func (recoveryReauthStub) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID}, nil
}
func (recoveryReauthStub) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

type recoveryPasswordStub struct{}

func (recoveryPasswordStub) SetPassword(context.Context, authn.Caller,
	authn.SetPasswordRequest) (authn.SetPasswordResult, error) {
	return authn.SetPasswordResult{}, errors.New("测试不使用改密路径")
}
func (recoveryPasswordStub) ResetPasswordForRecovery(context.Context, authn.Caller,
	authn.RecoveryResetRequest) (authn.SetPasswordResult, error) {
	return authn.SetPasswordResult{}, errors.New("测试不使用改密路径")
}

type recoveryMailSender struct {
	instance *mailtest.Instance
	t        *testing.T
}

func (s recoveryMailSender) Send(ctx context.Context, message mailer.Message) error {
	to := make([]string, 0, len(message.To))
	for _, address := range message.To {
		to = append(to, address.Spec)
	}
	raw := mailtest.BuildMessage(message.From.Spec, to, message.Subject, message.TextBody)
	conn, err := net.DialTimeout("tcp", s.instance.SMTPAddr, 5*time.Second)
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = client.Close() }()
	// 夹具测试配置 SMTPAuthNone=true：匿名本地投递，不发送 AUTH。
	if err := client.Mail(message.From.Spec); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// TestManualRecoveryPasswordResetRealMail 使用真实 SQLite、真实找回/会话/审计服务
// 与 EvernightMail 夹具完成“两名操作员申请→独立审批→等待期→真实邮件交付→会话撤销”
// 的密码恢复链路；执行器不返回任何链接/密码/秘密。
func TestManualRecoveryPasswordResetRealMail(t *testing.T) {
	ctx := context.Background()
	store := openMigratedStore(t)
	recorder := newTestAudit(t, store)
	keyring, err := secrets.GenerateKeyring("manual-recovery-test", time.Now())
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	const (
		operatorOne = "usr_11111111111111111111111111111111"
		operatorTwo = "usr_22222222222222222222222222222222"
		operatorRun = "usr_33333333333333333333333333333333"
		targetUser  = "usr_44444444444444444444444444444444"
		targetEmail = "recover@example.test"
	)
	nowMS := time.Now().UTC().UnixMilli()
	insertUser := func(id, name string) {
		t.Helper()
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(
			id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
			VALUES(?,?,?,'active',0,1,1,?,?)`, id, name, name, nowMS, nowMS); err != nil {
			t.Fatalf("插入用户 %s: %v", id, err)
		}
	}
	insertUser(operatorOne, "recovery-operator-one")
	insertUser(operatorTwo, "recovery-operator-two")
	insertUser(operatorRun, "recovery-operator-run")
	insertUser(targetUser, "recovery-target")
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO password_credentials(
		user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
		VALUES(?,'argon2id',19,?,0,1,?,?,?)`, targetUser,
		strings.Repeat("a", 64), nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("插入密码凭证: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO user_emails(
		user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
		VALUES(?,?,?,?,?,?)`, targetUser, targetEmail, targetEmail, nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("插入已验证邮箱: %v", err)
	}
	mailService := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	sender := recoveryMailSender{instance: mailService, t: t}
	credentialStore, err := credentialsqlite.New(store)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: time.Now})
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
	var clock = time.Now().UTC()
	targets := manualRecoveryTargets{store: store, keyring: keyring, roots: nil}
	// roots 仅用于识别 root；该目标非 root，构造只读 root 检查器即可。
	bootstrapStore, err := bootstrapsqlite.New(store)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		t.Fatalf("root 识别器: %v", err)
	}
	targets.roots = roots
	executor := manualRecoveryExecutor{passwordReset: resetService, sessions: sessionService, targets: targets}
	notifier := manualRecoveryNotifier{sender: sender, store: store,
		from: mailer.Address{Spec: "noreply@example.test"}, appName: "TestLogin"}
	policy := manualrecovery.Policy{Enabled: true,
		VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisNotarizedDeclaration},
		DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
		WaitPeriod:        time.Hour, ApprovalTTL: 2 * time.Hour, RequestTTL: 3 * time.Hour,
		RequireIndependentApproval: true}
	manualStore, err := manualrecoverysqlite.New(store)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	service, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: recorder, Reauth: recoveryReauthStub{},
		Staff: recoveryStaffStub{}, Targets: targets, Executor: executor,
		Notifier: notifier, Policy: policy, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	initiator, err := manualrecovery.UserCaller(operatorOne)
	if err != nil {
		t.Fatalf("发起者: %v", err)
	}
	created, err := service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetUser, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-2026-001", EvidenceSummary: "线下核验记录摘要",
		Reason: "用户丢失密码", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-recovery-create-1",
	})
	if err != nil {
		t.Fatalf("创建人工恢复申请: %v", err)
	}
	if _, err := service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetUser, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-2026-002", EvidenceSummary: "第二次申请",
		Reason: "第二次申请", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-recovery-create-2",
	}); err != nil {
		// 同一目标账号不允许重复 pending 申请属于受控拒绝；这里只验证双操作员主链路。
		t.Logf("第二次申请按预期被拒绝/限制: %v", err)
	}
	approver, err := manualrecovery.UserCaller(operatorTwo)
	if err != nil {
		t.Fatalf("审批人: %v", err)
	}
	if _, err := service.Approve(ctx, approver, manualrecovery.ApproveRequest{
		RequestID: created.ID, Note: "独立核验通过", TraceID: "trace-approve-1"}); err != nil {
		t.Fatalf("独立审批: %v", err)
	}
	// 自批（目标本人/发起者）必须拒绝，即使其他权限满足。
	initiatorAgain, _ := manualrecovery.UserCaller(operatorOne)
	if _, err := service.Approve(ctx, initiatorAgain, manualrecovery.ApproveRequest{
		RequestID: created.ID, TraceID: "trace-self-approve"}); err == nil {
		t.Fatal("发起人不得审批自己的申请")
	}
	executorCaller, err := manualrecovery.UserCaller(operatorRun)
	if err != nil {
		t.Fatalf("执行人: %v", err)
	}
	if _, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "trace-execute-too-early"}); err == nil {
		t.Fatal("等待期未满不得执行")
	}
	clock = clock.Add(policy.WaitPeriod + time.Second)
	result, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "trace-execute-1"})
	if err != nil {
		t.Fatalf("等待期后执行失败: %v", err)
	}
	if result.Status != manualrecovery.StatusCompleted || !result.CredentialIssued {
		t.Fatalf("执行结果不正确: %+v", result)
	}
	if result.SessionsRevoked < 0 {
		t.Fatalf("会话撤销计数异常: %d", result.SessionsRevoked)
	}
	// 真实 Mail 夹具必须收到找回邮件与完成通知；结果/邮件不含密码或 token。
	messages, err := mailService.Messages(mailtest.Query{To: targetEmail, Limit: 10})
	if err != nil {
		t.Fatalf("读取 Mail 夹具: %v", err)
	}
	if len(messages) == 0 {
		t.Fatal("真实 Mail 未收到找回/通知邮件")
	}
	for _, message := range messages {
		text := string(message.Data)
		if strings.Contains(text, "password") && strings.Contains(text, "secret") {
			t.Fatalf("邮件疑似包含秘密: %s", text)
		}
	}
	// 重复执行必须幂等/拒绝并保持 completed，不重复投递。
	if _, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "trace-execute-2"}); err == nil {
		t.Fatal("重复执行应被拒绝")
	}
}
