package onboarding_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var testStart = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

const (
	inviterID = "usr_00000000000000000000000000000001"
	adminID   = "usr_00000000000000000000000000000002"
	appID     = "app_00000000000000000000000000000010"
)

type captureMail struct {
	mu          sync.Mutex
	invitations []onboarding.InvitationEmail
	reviews     []onboarding.ReviewEmail
	fail        bool
}

func (m *captureMail) SendInvitation(_ context.Context, message onboarding.InvitationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("注入发送失败")
	}
	m.invitations = append(m.invitations, message)
	return nil
}

func (m *captureMail) SendReviewDecision(_ context.Context, message onboarding.ReviewEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("注入发送失败")
	}
	m.reviews = append(m.reviews, message)
	return nil
}

func (m *captureMail) lastInvitation(t *testing.T) onboarding.InvitationEmail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.invitations) == 0 {
		t.Fatal("未捕获邀请邮件")
	}
	return m.invitations[len(m.invitations)-1]
}

type fakeGuard struct {
	deny       bool
	denyAccess bool
	calls      int
	target     string
}

func (g *fakeGuard) CheckPermissionAccess(_ context.Context, _ audit.Tx, _ audit.Actor, _ string, _ []delegation.PermissionRef, _ []delegation.Target) error {
	g.calls++
	if g.denyAccess || g.deny {
		return delegation.ErrAccessDenied
	}
	return nil
}

func (g *fakeGuard) CheckAssignment(_ context.Context, _ audit.Tx, _ audit.Actor, _ string,
	_ []delegation.PermissionRef, target delegation.Target) error {
	g.calls++
	g.target = target.ID
	if g.deny {
		return delegation.ErrAccessDenied
	}
	return nil
}

func (g *fakeGuard) CheckPermissionActivation(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
	return nil
}

func (g *fakeGuard) CheckScopeRestoration(context.Context, audit.Tx, audit.Actor, string) error {
	return nil
}

type testEnv struct {
	t           *testing.T
	ctx         context.Context
	storage     *storagesqlite.Store
	store       onboarding.Store
	service     *onboarding.Service
	mail        *captureMail
	audit       *audit.Recorder
	credentials *credential.Service
	guard       *fakeGuard
	now         time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "onboarding-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, mail: &captureMail{}, guard: &fakeGuard{}, now: testStart}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	store, err := onboardingsqlite.New(storage)
	if err != nil {
		t.Fatalf("入驻存储: %v", err)
	}
	env.store = store
	env.audit = recorder
	env.credentials = credentialService
	service, err := onboarding.New(onboarding.Options{
		Store:             store,
		Audit:             recorder,
		Guard:             env.guard,
		Credentials:       credentialService,
		Mailer:            env.mail,
		AcceptanceURLBase: "https://login.example.test/accept",
		SupportURL:        "https://login.example.test/support",
		AppName:           "EvernightLogin",
		InvitationTTL:     time.Hour,
		InviteAuthorizer: onboarding.InviteAuthorizerFunc(func(_ context.Context, caller onboarding.Caller, _ onboarding.CreateRequest) error {
			if caller.IsUser() && caller.Actor().ID == inviterID {
				return nil
			}
			return onboarding.ErrAccessDenied
		}),
		ManagementAuth: onboarding.ManagementAuthorizerFunc(func(_ context.Context, caller onboarding.Caller) error {
			if caller.IsUser() && caller.Actor().ID == adminID {
				return nil
			}
			return onboarding.ErrManagementAuthRequired
		}),
		Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("入驻服务: %v", err)
	}
	env.service = service
	env.seedUser(t, inviterID, "inviter", "active")
	env.seedUser(t, adminID, "admin", "active")
	env.seedEmail(t, inviterID, "inviter@example.test", true)
	env.seedEmail(t, adminID, "admin@example.test", true)
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,'demo','','active','confidential',1,?,?)`, appID, testStart.UnixMilli(), testStart.UnixMilli()); err != nil {
		t.Fatalf("应用: %v", err)
	}
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID); err != nil {
		t.Fatalf("scope: %v", err)
	}
	env.seedRole(t, "role_app_member", appID)
	env.seedRole(t, "role_system_member", "system")
	env.seedRole(t, "role_system_member", "system")
	return env
}

func (e *testEnv) seedUser(t *testing.T, id, username, status string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai',?,0,1,1,?,?)`, id, username, username, status, now, now); err != nil {
		t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(t *testing.T, userID, email string, verified bool) {
	t.Helper()
	now := testStart.UnixMilli()
	var verifiedAt any
	if verified {
		verifiedAt = now
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, email, userID, email, verifiedAt, now, now); err != nil {
		t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) seedRole(t *testing.T, roleID, scopeID string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT OR IGNORE INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?, '', '', '', 0,1,?,?)`, roleID, scopeID, roleID, now, now); err != nil {
		t.Fatalf("角色: %v", err)
	}
}

func (e *testEnv) caller(t *testing.T, userID string) onboarding.Caller {
	t.Helper()
	caller, err := onboarding.UserCaller(userID)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

// TestInviteCreateAcceptNewUser 验证新用户受邀、通知可追踪、重复接受被拒绝。
func TestInviteCreateAcceptNewUser(t *testing.T) {
	env := newTestEnv(t)
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "newcomer@example.test",
		Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
	})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	if !created.TokenSent || created.Invitation.Status != onboarding.InvitationPending {
		t.Fatalf("创建结果: %+v", created)
	}
	_ = created
	mail := env.mail.lastInvitation(t)
	parsed, err := url.Parse(mail.AcceptanceURL)
	if err != nil {
		t.Fatalf("接受入口: %v", err)
	}
	request := onboarding.AcceptRequest{
		InvitationID: parsed.Query().Get("iid"), CredentialID: parsed.Query().Get("cid"),
		Token: parsed.Query().Get("token"),
		NewUser: &onboarding.NewUserRequest{
			Username: "newcomer", Password: "correct-horse-battery-9",
		},
	}
	accepted, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request)
	if err != nil {
		t.Fatalf("接受邀请: %v", err)
	}
	if !accepted.NewUser || accepted.UserID == "" {
		t.Fatalf("接受结果: %+v", accepted)
	}
	var status string
	if err := env.storage.DB().QueryRowContext(env.ctx, `SELECT status FROM users WHERE id=?`, accepted.UserID).Scan(&status); err != nil {
		t.Fatalf("新用户查询: %v", err)
	}
	if status != string(account.StatusActive) {
		t.Errorf("新用户状态 = %q", status)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id='role_system_member'`, accepted.UserID); got != 1 {
		t.Errorf("应分配邀请角色，实际 %d", got)
	}
	// 重复接受：令牌已消费，统一拒绝。
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request); !errors.Is(err, onboarding.ErrInvitationNotFound) {
		t.Fatalf("重复接受错误 = %v", err)
	}
	invitation, err := env.service.GetInvitation(env.ctx, env.caller(t, inviterID), created.Invitation.ID)
	if err != nil {
		t.Fatalf("查询邀请: %v", err)
	}
	if invitation.UsedCount != 1 || invitation.NotifyState != onboarding.NotifySent {
		t.Errorf("邀请状态 = %+v", invitation)
	}
}

// TestEmailInviteIdentityBinding 验证知道邀请 ID 的其他用户不能认领邮箱邀请。
func TestEmailInviteIdentityBinding(t *testing.T) {
	env := newTestEnv(t)
	env.seedUser(t, "usr_00000000000000000000000000000030", "other", "active")
	env.seedEmail(t, "usr_00000000000000000000000000000030", "other@example.test", true)
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "target@example.test",
	})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	_ = created
	mail := env.mail.lastInvitation(t)
	parsed, _ := url.Parse(mail.AcceptanceURL)
	request := onboarding.AcceptRequest{InvitationID: parsed.Query().Get("iid"), CredentialID: parsed.Query().Get("cid"), Token: parsed.Query().Get("token")}
	if _, err := env.service.AcceptInvitation(env.ctx, env.caller(t, "usr_00000000000000000000000000000030"), request); !errors.Is(err, onboarding.ErrInvitationIdentityMismatch) {
		t.Fatalf("错误邮箱用户接受应被拒绝，实际 %v", err)
	}
	// 目标用户（已验证目标邮箱）可用同一令牌接受。
	env.seedUser(t, "usr_00000000000000000000000000000031", "target", "active")
	env.seedEmail(t, "usr_00000000000000000000000000000031", "target@example.test", true)
	accepted, err := env.service.AcceptInvitation(env.ctx, env.caller(t, "usr_00000000000000000000000000000031"), request)
	if err != nil {
		t.Fatalf("目标用户接受失败: %v", err)
	}
	if accepted.UserID != "usr_00000000000000000000000000000031" {
		t.Errorf("接受用户 = %s", accepted.UserID)
	}
	_ = created
}

// TestInviteRejectedWhenCancelledExpiredOrGuardDenied 验证取消/过期/邀请者权限撤销阻止接受。
func TestInviteRejectedWhenCancelledExpiredOrGuardDenied(t *testing.T) {
	env := newTestEnv(t)
	create := func() onboarding.CreateResult {
		created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
			TargetEmail: "late@example.test",
			Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
		})
		if err != nil {
			t.Fatalf("创建邀请: %v", err)
		}
		return created
	}
	parse := func(created onboarding.CreateResult) onboarding.AcceptRequest {
		mail := env.mail.lastInvitation(t)
		parsed, _ := url.Parse(mail.AcceptanceURL)
		return onboarding.AcceptRequest{InvitationID: parsed.Query().Get("iid"), CredentialID: parsed.Query().Get("cid"), Token: parsed.Query().Get("token"), NewUser: &onboarding.NewUserRequest{Username: "lateuser", Password: "correct-horse-battery-9"}}
	}
	// 取消后接受。
	cancelled := create()
	request := parse(cancelled)
	if _, err := env.service.CancelInvitation(env.ctx, env.caller(t, inviterID), onboarding.CancelRequest{
		InvitationID: cancelled.Invitation.ID,
	}); err != nil {
		t.Fatalf("取消邀请: %v", err)
	}
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request); !errors.Is(err, onboarding.ErrInvitationCancelled) {
		t.Fatalf("取消后接受错误 = %v", err)
	}
	// 过期后接受。
	expired := create()
	expiredRequest := parse(expired)
	env.now = env.now.Add(2 * time.Hour)
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, expiredRequest); !errors.Is(err, onboarding.ErrInvitationExpired) && !errors.Is(err, onboarding.ErrInvitationNotFound) {
		t.Fatalf("过期后接受错误 = %v", err)
	}
	env.now = testStart
	// 邀请者权限撤销（委派 Guard 拒绝）。
	denied := create()
	deniedRequest := parse(denied)
	env.guard.deny = true
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, deniedRequest); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("邀请者权限撤销后接受错误 = %v", err)
	}
}

// TestReviewApproveRejectAndConcurrency 验证审核查询/批准/拒绝、自行批准拒绝与并发冲突。
func TestReviewApproveRejectAndConcurrency(t *testing.T) {
	env := newTestEnv(t)
	env.seedUser(t, "usr_00000000000000000000000000000040", "pending1", "pending")
	env.seedUser(t, "usr_00000000000000000000000000000041", "pending2", "pending")
	env.seedEmail(t, "usr_00000000000000000000000000000040", "p1@example.test", true)
	env.seedEmail(t, "usr_00000000000000000000000000000041", "p2@example.test", true)
	adminCaller, err := onboarding.UserCaller(adminID)
	if err != nil {
		t.Fatalf("管理员调用者: %v", err)
	}
	pending, err := env.service.ListPendingReviews(env.ctx, adminCaller, onboarding.ReviewQuery{})
	if err != nil || len(pending.Users) != 2 {
		t.Fatalf("待审核列表: %v %d", err, len(pending.Users))
	}
	// 申请人不能自己批准。
	if _, err := env.service.ApproveRegistration(env.ctx, env.caller(t, "usr_00000000000000000000000000000040"),
		onboarding.ReviewRequest{UserID: "usr_00000000000000000000000000000040"}); !errors.Is(err, onboarding.ErrSelfApproval) {
		t.Fatalf("申请人自行批准应被拒绝，实际 %v", err)
	}
	// 并发批准同一账户：恰好一个成功，另一个状态冲突。
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := env.service.ApproveRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
				UserID: "usr_00000000000000000000000000000040", Reason: "ok",
			})
			results[i] = err
		}(index)
	}
	wg.Wait()
	successes, conflicts := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, onboarding.ErrReviewStateConflict):
			conflicts++
		default:
			t.Fatalf("并发批准错误: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("并发批准 = 成功 %d 冲突 %d", successes, conflicts)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id='usr_00000000000000000000000000000040' AND status='active'`); got != 1 {
		t.Errorf("批准后账户应为 active")
	}
	// 拒绝另一个申请人。
	rejected, err := env.service.RejectRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
		UserID: "usr_00000000000000000000000000000041", Reason: "资料不全",
	})
	if err != nil {
		t.Fatalf("拒绝注册: %v", err)
	}
	if rejected.Review.ReviewStatus != onboarding.ReviewRejected || !rejected.Notified {
		t.Errorf("拒绝结果 = %+v", rejected)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id='usr_00000000000000000000000000000041' AND status='disabled'`); got != 1 {
		t.Errorf("拒绝后账户应为 disabled")
	}
}

// count 查询单值计数。
func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数查询: %v", err)
	}
	return value
}

// TestAppInvitationMembershipAndDisabled 验证应用邀请接受后加入应用成员并分配应用
// 角色；应用停用后邀请不可接受。
func TestAppInvitationMembershipAndDisabled(t *testing.T) {
	env := newTestEnv(t)
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "appmember@example.test",
		AppID:       appID,
		Roles:       []onboarding.Role{{RoleID: "role_app_member", ScopeID: appID}},
	})
	if err != nil {
		t.Fatalf("创建应用邀请: %v", err)
	}
	_ = created
	mail := env.mail.lastInvitation(t)
	parsed, _ := url.Parse(mail.AcceptanceURL)
	request := onboarding.AcceptRequest{
		InvitationID: parsed.Query().Get("iid"),
		CredentialID: parsed.Query().Get("cid"),
		Token:        parsed.Query().Get("token"),
		NewUser:      &onboarding.NewUserRequest{Username: "appmember", Password: "correct-horse-battery-9"},
	}
	accepted, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request)
	if err != nil {
		t.Fatalf("接受应用邀请: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`, appID, accepted.UserID); got != 1 {
		t.Errorf("应加入应用成员，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id='role_app_member'`, accepted.UserID); got != 1 {
		t.Errorf("应分配应用角色，实际 %d", got)
	}
	// 应用停用后另一邀请不可接受。
	second, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "appmember2@example.test", AppID: appID,
		Roles: []onboarding.Role{{RoleID: "role_app_member", ScopeID: appID}},
	})
	if err != nil {
		t.Fatalf("创建第二个邀请: %v", err)
	}
	secondMail := env.mail.lastInvitation(t)
	secondParsed, _ := url.Parse(secondMail.AcceptanceURL)
	secondRequest := onboarding.AcceptRequest{
		InvitationID: secondParsed.Query().Get("iid"),
		CredentialID: secondParsed.Query().Get("cid"),
		Token:        secondParsed.Query().Get("token"),
		NewUser:      &onboarding.NewUserRequest{Username: "appmember2", Password: "correct-horse-battery-9"},
	}
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE applications SET status='disabled' WHERE id=?`, appID); err != nil {
		t.Fatalf("停用应用: %v", err)
	}
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, secondRequest); !errors.Is(err, onboarding.ErrInvitationNotAcceptable) {
		t.Fatalf("应用停用后接受错误 = %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE username_normalized='appmember2'`); got != 0 {
		t.Errorf("失败接受不应创建用户，实际 %d", got)
	}
	_ = created
	_ = second
}

// TestReviewApproveWithMembershipAndSelfApproval 验证批准时在同一事务加入应用成员/
// 角色，且申请人在具备管理身份时仍不能批准自己。
func TestReviewApproveWithMembershipAndSelfApproval(t *testing.T) {
	env := newTestEnv(t)
	applicant := "usr_00000000000000000000000000000050"
	env.seedUser(t, applicant, "selfadmin", "pending")
	env.seedEmail(t, applicant, "selfadmin@example.test", true)
	selfService, err := onboarding.New(onboarding.Options{
		Store: env.store, Audit: env.audit, Guard: env.guard, Credentials: env.credentials,
		Mailer: env.mail, AcceptanceURLBase: "https://login.example.test/accept",
		SupportURL: "https://login.example.test/support", AppName: "EvernightLogin",
		ManagementAuth: onboarding.ManagementAuthorizerFunc(func(_ context.Context, caller onboarding.Caller) error {
			if caller.IsUser() && caller.Actor().ID == applicant {
				return nil
			}
			return onboarding.ErrManagementAuthRequired
		}),
		Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("构造自审服务: %v", err)
	}
	if _, err := selfService.ApproveRegistration(env.ctx, env.caller(t, applicant),
		onboarding.ReviewRequest{UserID: applicant}); !errors.Is(err, onboarding.ErrSelfApproval) {
		t.Fatalf("申请人自批错误 = %v", err)
	}
	// 管理员批准并加入应用成员/角色。
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE registration_reviews SET notify_state='pending' WHERE user_id=?`, applicant); err != nil {
		t.Fatalf("重置通知状态: %v", err)
	}
	adminCaller, _ := onboarding.UserCaller(adminID)
	result, err := env.service.ApproveRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
		UserID: applicant, AppID: appID,
		Roles: []onboarding.Role{{RoleID: "role_app_member", ScopeID: appID}},
	})
	if err != nil {
		t.Fatalf("批准注册: %v", err)
	}
	if result.Review.ReviewStatus != onboarding.ReviewApproved || !result.Notified {
		t.Errorf("批准结果 = %+v", result)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE user_id=? AND app_id=?`, applicant, appID); got != 1 {
		t.Errorf("批准应加入应用成员，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id='role_app_member'`, applicant); got != 1 {
		t.Errorf("批准应分配角色，实际 %d", got)
	}
}

// TestNotificationFailureTraceable 验证通知失败不回滚邀请/审核主事务，且状态与错误码
// 可查询。
func TestNotificationFailureTraceable(t *testing.T) {
	env := newTestEnv(t)
	env.mail.fail = true
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "nomail@example.test",
	})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	if created.TokenSent || created.ErrorCode != string(onboarding.CodeMailDeliveryFailed) {
		t.Fatalf("通知失败结果 = %+v", created)
	}
	invitation, err := env.service.GetInvitation(env.ctx, env.caller(t, inviterID), created.Invitation.ID)
	if err != nil {
		t.Fatalf("查询邀请: %v", err)
	}
	if invitation.NotifyState != onboarding.NotifyFailed || invitation.NotifyError != string(onboarding.CodeMailDeliveryFailed) {
		t.Errorf("通知状态 = %+v", invitation)
	}
	if got := env.count(`SELECT COUNT(*) FROM invitations WHERE id=? AND status='pending'`, created.Invitation.ID); got != 1 {
		t.Errorf("通知失败不应回滚邀请")
	}
}

// TestUserTargetInvitationAndRollback 验证已有用户邀请按用户 ID 绑定接受；并在角色
// 不可分配时验证审核/接受失败整体回滚、不留下部分账户/成员/决定。
func TestUserTargetInvitationAndRollback(t *testing.T) {
	env := newTestEnv(t)
	targetID := "usr_00000000000000000000000000000060"
	env.seedUser(t, targetID, "targetuser", "active")
	env.seedEmail(t, targetID, "targetuser@example.test", true)
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetUserID: targetID,
	})
	if err != nil {
		t.Fatalf("创建用户邀请: %v", err)
	}
	_ = created
	mail := env.mail.lastInvitation(t)
	parsed, _ := url.Parse(mail.AcceptanceURL)
	request := onboarding.AcceptRequest{
		InvitationID: parsed.Query().Get("iid"),
		CredentialID: parsed.Query().Get("cid"),
		Token:        parsed.Query().Get("token"),
	}
	// 其他用户不能接受用户邀请。
	env.seedUser(t, "usr_00000000000000000000000000000061", "otheruser", "active")
	if _, err := env.service.AcceptInvitation(env.ctx, env.caller(t, "usr_00000000000000000000000000000061"), request); !errors.Is(err, onboarding.ErrInvitationIdentityMismatch) {
		t.Fatalf("非目标用户接受用户邀请错误 = %v", err)
	}
	accepted, err := env.service.AcceptInvitation(env.ctx, env.caller(t, targetID), request)
	if err != nil {
		t.Fatalf("目标用户接受邀请: %v", err)
	}
	if accepted.UserID != targetID {
		t.Errorf("接受用户 = %s", accepted.UserID)
	}
	// 审核批准时角色不可分配：整体回滚，账户保持 pending。
	pendingID := "usr_00000000000000000000000000000062"
	env.seedUser(t, pendingID, "pendrollback", "pending")
	adminCaller, _ := onboarding.UserCaller(adminID)
	if _, err := env.service.ApproveRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
		UserID: pendingID, AppID: appID,
		Roles: []onboarding.Role{{RoleID: "role_missing", ScopeID: appID}},
	}); err == nil {
		t.Fatal("不可分配角色的批准应失败")
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND status='pending'`, pendingID); got != 1 {
		t.Errorf("失败批准应回滚账户状态，实际 pending 行 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE user_id=?`, pendingID); got != 0 {
		t.Errorf("失败批准不应加入成员，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM registration_reviews WHERE user_id=?`, pendingID); got != 0 {
		t.Errorf("失败批准不应写审核决定，实际 %d", got)
	}
	// 接受失败（邀请者撤权）不得写接受记录；令牌侧消费是防重放语义，已在文档声明。
	denied, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "rollback@example.test",
		Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
	})
	if err != nil {
		t.Fatalf("创建回滚测试邀请: %v", err)
	}
	deniedMail := env.mail.lastInvitation(t)
	deniedParsed, _ := url.Parse(deniedMail.AcceptanceURL)
	env.guard.deny = true
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, onboarding.AcceptRequest{
		InvitationID: deniedParsed.Query().Get("iid"),
		CredentialID: deniedParsed.Query().Get("cid"),
		Token:        deniedParsed.Query().Get("token"),
		NewUser:      &onboarding.NewUserRequest{Username: "rollbackuser", Password: "correct-horse-battery-9"},
	}); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("撤权后接受错误 = %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE username_normalized='rollbackuser'`); got != 0 {
		t.Errorf("失败接受不应创建用户，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM invitation_acceptances WHERE invitation_id=?`, denied.Invitation.ID); got != 0 {
		t.Errorf("失败接受不应写接受记录，实际 %d", got)
	}
}
