package onboarding_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
)

// seedPermission 插入应用作用域权限定义。
func (e *testEnv) seedPermission(t *testing.T, permissionID, scopeID, key string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms
) VALUES(?,?,?,?, '', '', 0,0,1,?,?)`, permissionID, scopeID, key, key, now, now); err != nil {
		t.Fatalf("权限: %v", err)
	}
}

// seedRolePermission 关联角色与权限。
func (e *testEnv) seedRolePermission(t *testing.T, roleID, scopeID, permissionID string) {
	t.Helper()
	if _, err := e.storage.DB().ExecContext(e.ctx,
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		roleID, permissionID, scopeID); err != nil {
		t.Fatalf("角色权限: %v", err)
	}
}

// seedUserRole 给用户分配角色。
func (e *testEnv) seedUserRole(t *testing.T, userID, roleID, scopeID string) {
	t.Helper()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO user_roles(
user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms
) VALUES(?,?,?,'{}','test',?)`, userID, roleID, scopeID, testStart.UnixMilli()); err != nil {
		t.Fatalf("用户角色: %v", err)
	}
}

// seedMembership 写入应用成员状态。
func (e *testEnv) seedMembership(t *testing.T, appID, userID, status string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'{}',1,?,?)`, appID, userID, status, now, now); err != nil {
		t.Fatalf("成员: %v", err)
	}
}

// realGuard 构造真实 delegation.Service（SQLite + 审计）。
func (e *testEnv) realGuard(t *testing.T) *delegation.Service {
	t.Helper()
	store, err := delegationsqlite.New(e.storage)
	if err != nil {
		t.Fatalf("委派存储: %v", err)
	}
	service, err := delegation.New(delegation.Options{
		Store: store,
		Audit: e.audit,
		Now:   func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("委派服务: %v", err)
	}
	return service
}

// serviceWithGuard 用指定 Guard 构造同依赖的入驻服务。
func (e *testEnv) serviceWithGuard(t *testing.T, guard delegation.Guard) *onboarding.Service {
	t.Helper()
	service, err := onboarding.New(onboarding.Options{
		Store:             e.store,
		Audit:             e.audit,
		Guard:             guard,
		Credentials:       e.credentials,
		Mailer:            e.mail,
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
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("入驻服务: %v", err)
	}
	return service
}

// seedDelegationGrant 为邀请者签发可转授资格。
func (e *testEnv) seedDelegationGrant(t *testing.T, guard *delegation.Service, userID, scopeID, permissionKey string) {
	t.Helper()
	caller, err := delegation.SystemCaller("onboarding-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	if _, err := guard.Grant(e.ctx, caller, delegation.GrantRequest{
		DelegatorUserID: userID,
		ScopeID:         scopeID,
		PermissionKey:   permissionKey,
	}); err != nil {
		t.Fatalf("签发委派资格: %v", err)
	}
}

// TestGuardRejectsReactivatingRetainedPermissions 验证零角色邀请不能借重新启用被禁
// 成员恢复其保留角色权限（真实 delegation.Guard/SQLite）；授予对应资格后合法通过。
func TestGuardRejectsReactivatingRetainedPermissions(t *testing.T) {
	env := newTestEnv(t)
	targetID := "usr_00000000000000000000000000000070"
	env.seedUser(t, targetID, "retained", "active")
	env.seedEmail(t, targetID, "retained@example.test", true)
	env.seedMembership(t, appID, inviterID, "active")
	env.seedPermission(t, "perm_00000000000000000000000000000001", appID, "app.read")
	env.seedPermission(t, "perm_00000000000000000000000000000002", appID, "app.delete")
	env.seedRole(t, "role_inviter", appID)
	env.seedRole(t, "role_retained", appID)
	env.seedRolePermission(t, "role_inviter", appID, "perm_00000000000000000000000000000001")
	env.seedRolePermission(t, "role_retained", appID, "perm_00000000000000000000000000000001")
	env.seedRolePermission(t, "role_retained", appID, "perm_00000000000000000000000000000002")
	env.seedUserRole(t, inviterID, "role_inviter", appID)
	env.seedUserRole(t, targetID, "role_retained", appID)
	env.seedMembership(t, appID, targetID, "disabled")
	guard := env.realGuard(t)
	env.seedDelegationGrant(t, guard, inviterID, appID, "app.read")
	recorder := &recordingGuard{inner: guard}
	service := env.serviceWithGuard(t, recorder)

	create := func() url.Values {
		created, err := service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
			TargetEmail: "retained@example.test",
			AppID:       appID,
		})
		if err != nil {
			t.Fatalf("创建零角色应用邀请: %v", err)
		}
		mail := env.mail.lastInvitation(t)
		parsed, err := url.Parse(mail.AcceptanceURL)
		if err != nil {
			t.Fatalf("邀请链接: %v", err)
		}
		_ = created
		return parsed.Query()
	}
	accept := func(query url.Values) error {
		_, err := service.AcceptInvitation(env.ctx, env.caller(t, targetID), onboarding.AcceptRequest{
			InvitationID: query.Get("iid"),
			CredentialID: query.Get("cid"),
			Token:        query.Get("token"),
		})
		return err
	}
	// 目标保留 app.delete 权限但邀请者没有该权限资格：拒绝恢复成员。
	if err := accept(create()); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("零角色邀请恢复保留权限应被 Guard 拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`, appID, targetID); got != 0 {
		t.Errorf("被拒绝的接受不应重新启用成员，实际 active %d", got)
	}
	// 移除未获资格的权限后，目标既有权限仅为可转授的 app.read：接受合法通过。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`DELETE FROM role_permissions WHERE role_id='role_retained' AND permission_id='perm_00000000000000000000000000000002'`); err != nil {
		t.Fatalf("移除权限: %v", err)
	}
	if err := accept(create()); err != nil {
		t.Fatalf("既有权限均可转授时应接受成功: %v / guard: %v", err, recorder.lastErr)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`, appID, targetID); got != 1 {
		t.Errorf("接受成功后成员应恢复 active，实际 %d", got)
	}
}

// TestExistingUserAlreadyHoldingRoleAccepts 验证已有用户已持有邀请角色时接受仍然
// 成功（角色插入按幂等成功处理，不因影响 0 行失败并消费令牌）。
func TestExistingUserAlreadyHoldingRoleAccepts(t *testing.T) {
	env := newTestEnv(t)
	targetID := "usr_00000000000000000000000000000071"
	env.seedUser(t, targetID, "holder", "active")
	env.seedEmail(t, targetID, "holder@example.test", true)
	env.seedUserRole(t, targetID, "role_system_member", "system")
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "holder@example.test",
		Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
	})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	mail := env.mail.lastInvitation(t)
	parsed, _ := url.Parse(mail.AcceptanceURL)
	accepted, err := env.service.AcceptInvitation(env.ctx, env.caller(t, targetID), onboarding.AcceptRequest{
		InvitationID: parsed.Query().Get("iid"),
		CredentialID: parsed.Query().Get("cid"),
		Token:        parsed.Query().Get("token"),
	})
	if err != nil {
		t.Fatalf("已持有角色的用户接受失败: %v", err)
	}
	if accepted.UserID != targetID {
		t.Errorf("接受用户 = %s", accepted.UserID)
	}
	_ = created
	if got := env.count(`SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id='role_system_member'`, targetID); got != 1 {
		t.Errorf("角色应保持 1 条，实际 %d", got)
	}
}

// TestCreateInvitationGuardDenied 验证创建邀请时按当前发起者检查可委派范围。
func TestCreateInvitationGuardDenied(t *testing.T) {
	env := newTestEnv(t)
	env.guard.denyAccess = true
	if _, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID), onboarding.CreateRequest{
		TargetEmail: "guarded@example.test",
		Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
	}); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("发起者无可委派范围时创建邀请应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM invitations WHERE target_email='guarded@example.test'`); got != 0 {
		t.Errorf("被拒绝的邀请不应落库，实际 %d", got)
	}
}

// TestReviewApprovalGuardAndScopedManagement 验证审核批准也经 Guard；未配置范围管理
// 授权时普通用户不能授予系统作用域角色。
func TestReviewApprovalGuardAndScopedManagement(t *testing.T) {
	env := newTestEnv(t)
	pendingID := "usr_00000000000000000000000000000072"
	env.seedUser(t, pendingID, "pendguard", "pending")
	env.seedEmail(t, pendingID, "pendguard@example.test", true)
	adminCaller, _ := onboarding.UserCaller(adminID)
	env.guard.deny = true
	if _, err := env.service.ApproveRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
		UserID: pendingID, AppID: appID,
		Roles: []onboarding.Role{{RoleID: "role_app_member", ScopeID: appID}},
	}); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("审核者无可委派范围时批准应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND status='pending'`, pendingID); got != 1 {
		t.Errorf("失败批准应回滚账户状态，实际 %d", got)
	}
	env.guard.deny = false
	// 未实现范围管理授权扩展时，普通用户不能授予 system 作用域角色。
	if _, err := env.service.ApproveRegistration(env.ctx, adminCaller, onboarding.ReviewRequest{
		UserID: pendingID,
		Roles:  []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
	}); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("未配置范围授权时授予系统角色应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND status='pending'`, pendingID); got != 1 {
		t.Errorf("越权审批不应改变账户状态，实际 %d", got)
	}
	_ = account.StatusPending
}

// recordingGuard 包装真实 Guard 并保留最近错误，便于断言失败原因（不是替身）。
type recordingGuard struct {
	inner   delegation.Guard
	lastErr error
}

func (r *recordingGuard) CheckPermissionAccess(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef, targets []delegation.Target) error {
	err := r.inner.CheckPermissionAccess(ctx, tx, actor, scopeID, permissions, targets)
	if err != nil {
		r.lastErr = err
	}
	return err
}

func (r *recordingGuard) CheckAssignment(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef, target delegation.Target) error {
	err := r.inner.CheckAssignment(ctx, tx, actor, scopeID, permissions, target)
	if err != nil {
		r.lastErr = err
	}
	return err
}

func (r *recordingGuard) CheckPermissionActivation(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string, permissions []delegation.PermissionRef, targets []delegation.Target) error {
	return r.inner.CheckPermissionActivation(ctx, tx, actor, scopeID, permissions, targets)
}

func (r *recordingGuard) CheckScopeRestoration(ctx context.Context, tx audit.Tx, actor audit.Actor, scopeID string) error {
	return r.inner.CheckScopeRestoration(ctx, tx, actor, scopeID)
}
