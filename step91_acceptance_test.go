package login_test

// 步骤 91 验收用例：Windows + SQLite 隔离环境下的账户、权限与客服流程验收。
// 每个用例使用独立临时 SQLite（真实迁移）与真实领域服务；失败即验收不通过。
// 覆盖：账户生命周期与安全版本/会话失效；注册/邀请/审核；资料与用户名/邮箱变更；
// 多应用隔离、直接与间接授权、成员状态、数据范围边界；自我提权/跨应用越权/root
// 保护；客服人工恢复的求助→审批→执行/拒绝/取消与审计留痕。

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// localAdmin 构造受信本地管理员账户调用者。
func (e *step91Env) localAdmin(t *testing.T) account.Caller {
	t.Helper()
	caller, err := account.LocalBootstrapCaller(step91LocalAdmin)
	if err != nil {
		t.Fatalf("本地管理员 Caller: %v", err)
	}
	return caller
}

// getUser 以受信本地管理员通道读取账户（账户读取不依赖业务权限）。
func (e *step91Env) getUser(t *testing.T, userID string) account.User {
	t.Helper()
	user, err := e.accounts.GetUser(e.ctx, e.localAdmin(t), userID)
	if err != nil {
		t.Fatalf("读取账户 %s: %v", userID, err)
	}
	return user
}

// TestStep91AccountLifecycleAndSessionInvalidation 覆盖账户创建/资料更新/禁用/启用/
// 删除的状态机、security_version 递增与会话失效语义，以及 root 受保护拒绝留痕。
func TestStep91AccountLifecycleAndSessionInvalidation(t *testing.T) {
	env := newStep91Env(t)
	localAdmin := env.localAdmin(t)

	created, err := env.accounts.CreateUser(env.ctx, localAdmin, account.CreateRequest{
		Username: "step91-lifecycle", Nickname: "生命周期账户"})
	if err != nil {
		t.Fatalf("创建账户: %v", err)
	}
	if created.Status != account.StatusActive || created.SecurityVersion != 1 {
		t.Fatalf("新账户状态不符合预期: %+v", created)
	}
	env.assertAudit(t, "user.create", "success")

	// 资料更新：字段白名单（昵称/简介），行版本递增。
	current, err := env.profiles.GetProfile(env.ctx, mustStep91ProfileCaller(t, created.ID), created.ID)
	if err != nil {
		t.Fatalf("读取资料: %v", err)
	}
	nickname := "生命周期账户2"
	biography := "步骤91验收合成资料"
	updated, err := env.profiles.UpdateSelf(env.ctx, mustStep91ProfileCaller(t, created.ID),
		profile.ProfileChange{Nickname: &nickname, Biography: &biography},
		current.RowVersion, "")
	if err != nil {
		t.Fatalf("更新资料: %v", err)
	}
	if updated.Nickname != nickname || updated.Biography != biography ||
		updated.RowVersion != current.RowVersion+1 {
		t.Fatalf("资料更新结果不符合预期: %+v", updated)
	}

	// 受控更名：用户 ID 不变、审计成功、规范化用户名生效。
	renamed, err := env.profiles.ChangeUsername(env.ctx, mustStep91ProfileCaller(t, created.ID),
		profile.ChangeUsernameRequest{TargetUserID: created.ID, NewUsername: "step91-renamed",
			ExpectedRowVersion: updated.RowVersion})
	if err != nil {
		t.Fatalf("受控更名: %v", err)
	}
	if renamed.UserID != created.ID || renamed.UsernameNormalized != "step91-renamed" {
		t.Fatalf("更名后稳定 ID/规范化用户名不符合预期: %+v", renamed)
	}
	env.assertAudit(t, "profile.username_change", "success")
	// 普通用户不能更名他人账户（默认授权口径 fail-closed）。
	if _, err := env.profiles.ChangeUsername(env.ctx, mustStep91ProfileCaller(t, created.ID),
		profile.ChangeUsernameRequest{TargetUserID: env.user1, NewUsername: "step91-steal",
			ExpectedRowVersion: 1}); !errors.Is(err, profile.ErrAccessDenied) {
		t.Fatalf("跨用户更名应被拒绝，实际 %v", err)
	}

	// 会话签发与校验（真实 session 服务）。
	issued, err := env.sessions.Login(env.ctx, session.LoginRequest{
		Result: env.sessionResult(t, created.ID)})
	if err != nil {
		t.Fatalf("签发会话: %v", err)
	}
	if _, err := env.sessions.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("活动账户会话应有效: %v", err)
	}

	// 禁用：security_version 递增，旧会话立即失效。
	currentRowVersion := env.getUser(t, created.ID).RowVersion
	disabled, err := env.accounts.DisableUser(env.ctx, localAdmin,
		account.StateCommandRequest{UserID: created.ID, ExpectedRowVersion: currentRowVersion})
	if err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	if !disabled.Changed || disabled.User.Status != account.StatusDisabled ||
		disabled.User.SecurityVersion != 2 {
		t.Fatalf("禁用结果不符合预期: %+v", disabled)
	}
	env.assertAudit(t, "user.disable", "success")
	if _, err := env.sessions.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("禁用后旧会话应失效，实际 %v", err)
	}

	// 启用不降安全版本，旧会话不会复活。
	enabled, err := env.accounts.EnableUser(env.ctx, localAdmin,
		account.StateCommandRequest{UserID: created.ID,
			ExpectedRowVersion: env.getUser(t, created.ID).RowVersion})
	if err != nil {
		t.Fatalf("启用账户: %v", err)
	}
	if enabled.User.SecurityVersion != 2 || enabled.User.Status != account.StatusActive {
		t.Fatalf("启用后安全版本/状态不符合预期: %+v", enabled)
	}
	if _, err := env.sessions.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("启用后旧会话不应复活，实际 %v", err)
	}
	// 新版本可重新登录。
	reissued, err := env.sessions.Login(env.ctx, session.LoginRequest{
		Result: env.sessionResult(t, created.ID)})
	if err != nil {
		t.Fatalf("重新登录: %v", err)
	}
	if _, err := env.sessions.Validate(env.ctx, reissued.Secret.Reveal()); err != nil {
		t.Fatalf("新会话应有效: %v", err)
	}

	// 删除预览与完成删除：安全版本递增、关联数据清理、审计留痕。
	preview, err := env.accounts.PreviewDeletion(env.ctx, localAdmin, created.ID)
	if err != nil {
		t.Fatalf("删除预览: %v", err)
	}
	if preview.SecurityVersion != 2 {
		t.Fatalf("删除预览安全版本不符合预期: %+v", preview)
	}
	if _, err := env.accounts.RequestDeletion(env.ctx, localAdmin,
		account.StateCommandRequest{UserID: created.ID,
			ExpectedRowVersion: env.getUser(t, created.ID).RowVersion}); err != nil {
		t.Fatalf("请求删除: %v", err)
	}
	if got := env.getUser(t, created.ID); got.Status != account.StatusPendingDelete ||
		got.SecurityVersion != 3 {
		t.Fatalf("请求删除后状态/版本不符合预期: %+v", got)
	}
	deleted, err := env.accounts.CompleteDeletion(env.ctx, localAdmin,
		account.StateCommandRequest{UserID: created.ID,
			ExpectedRowVersion: env.getUser(t, created.ID).RowVersion})
	if err != nil {
		t.Fatalf("完成删除: %v", err)
	}
	if deleted.DeletedAt.IsZero() {
		t.Fatalf("完成删除缺少时间: %+v", deleted)
	}
	if got := env.dbCount(t, `SELECT COUNT(*) FROM users WHERE id=?`, created.ID); got != 0 {
		t.Fatalf("删除后账户仍存在: %d", got)
	}

	// root 受保护：普通管理流程不能禁用 root，失败审计独立留痕。
	if _, err := env.accounts.DisableUser(env.ctx, localAdmin,
		account.StateCommandRequest{UserID: env.root,
			ExpectedRowVersion: env.getUser(t, env.root).RowVersion}); !errors.Is(err, account.ErrProtectedUser) {
		t.Fatalf("禁用 root 应被拒绝，实际 %v", err)
	}
	if got := env.auditCount(t, "user.disable", "failure"); got < 1 {
		t.Fatalf("root 保护拒绝缺少失败审计: %d", got)
	}
	// 普通用户（非管理身份）不能禁用他人账户。
	if _, err := env.accounts.DisableUser(env.ctx, mustStep91AccountUserCaller(t, env.user1),
		account.StateCommandRequest{UserID: env.user2}); !errors.Is(err, account.ErrAccessDenied) {
		t.Fatalf("普通用户禁用他人应被拒绝，实际 %v", err)
	}
}

// TestStep91RegistrationInviteAndReview 覆盖自主注册（待审核）→ 审核批准/拒绝、
// 跨作用域角色授予被拒、邀请创建与接受（新用户）。
func TestStep91RegistrationInviteAndReview(t *testing.T) {
	env := newStep91Env(t)
	adminCaller := mustStep91OnboardingCaller(t, env.adminA)

	registered, err := env.registration.Register(env.ctx, registration.RegisterRequest{
		Username: "step91-register", Password: "Step91-acceptance-passphrase",
		Nickname: "注册待审账户", RequestID: "req-step91-register"})
	if err != nil {
		t.Fatalf("自主注册: %v", err)
	}
	if registered.Status != account.StatusPending {
		t.Fatalf("要求人工审核时应为 pending，实际 %s", registered.Status)
	}

	// 审核授予跨应用角色：角色作用域与应用不一致必须拒绝，且账户保持待审。
	if _, err := env.onboarding.ApproveRegistration(env.ctx, adminCaller,
		onboarding.ReviewRequest{UserID: registered.UserID, AppID: env.appA,
			Roles:     []onboarding.Role{{RoleID: env.roleBReader, ScopeID: env.appB}},
			RequestID: "req-step91-review-bad"}); err == nil {
		t.Fatal("跨应用角色审核应被拒绝")
	}
	if got := env.getUser(t, registered.UserID); got.Status != account.StatusPending {
		t.Fatalf("被拒绝的审核不应改变账户状态: %s", got.Status)
	}

	// 审核批准：分配应用 A 角色 + 应用成员关系，并发送审核结果通知。
	approved, err := env.onboarding.ApproveRegistration(env.ctx, adminCaller,
		onboarding.ReviewRequest{UserID: registered.UserID, AppID: env.appA,
			Roles:     []onboarding.Role{{RoleID: env.roleAReader, ScopeID: env.appA}},
			RequestID: "req-step91-review-ok"})
	if err != nil {
		t.Fatalf("审核批准: %v", err)
	}
	if approved.Review.UserID != registered.UserID || approved.Review.Status != account.StatusActive {
		t.Fatalf("审核结果不符合预期: %+v", approved.Review)
	}
	if got := env.dbCount(t, `SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`,
		env.appA, registered.UserID); got != 1 {
		t.Fatalf("审核批准后应用成员关系不生效: %d", got)
	}
	if got := env.dbCount(t, `SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id=?`,
		registered.UserID, env.roleAReader); got != 1 {
		t.Fatalf("审核批准后角色未分配: %d", got)
	}

	// 匿名申请者不能批准审核（管理强认证通道契约）。
	if _, err := env.onboarding.ApproveRegistration(env.ctx, onboarding.Caller{},
		onboarding.ReviewRequest{UserID: env.target}); err == nil {
		t.Fatal("匿名审核应被拒绝")
	}

	// 邀请：应用 A 管理员创建邀请 → 捕获本地邀请邮件 → 新用户接受。
	invitation, err := env.onboarding.CreateInvitation(env.ctx, adminCaller,
		onboarding.CreateRequest{TargetEmail: "step91-invitee@example.test", AppID: env.appA,
			Roles: []onboarding.Role{{RoleID: env.roleAReader, ScopeID: env.appA}}})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	if !invitation.TokenSent || invitation.Invitation.Status != onboarding.InvitationPending {
		t.Fatalf("邀请结果不符合预期: %+v", invitation)
	}
	link := env.mail.lastInvitationURL(t)
	query := link.Query()
	accepted, err := env.onboarding.AcceptInvitation(env.ctx, onboarding.Caller{},
		onboarding.AcceptRequest{InvitationID: query.Get("iid"), CredentialID: query.Get("cid"),
			Token: query.Get("token"), NewUser: &onboarding.NewUserRequest{
				Username: "step91-invitee", Password: "Q7m-Vr4t-Ln2x-Wh8k"}})
	if err != nil {
		t.Fatalf("接受邀请: %v", err)
	}
	if !accepted.NewUser || accepted.UserID == "" || accepted.AppID != env.appA {
		t.Fatalf("接受邀请结果不符合预期: %+v", accepted)
	}
	if got := env.dbCount(t, `SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`,
		env.appA, accepted.UserID); got != 1 {
		t.Fatalf("接受邀请后成员关系不生效: %d", got)
	}
	// 一次性凭证：重复接受被拒绝。
	if _, err := env.onboarding.AcceptInvitation(env.ctx, onboarding.Caller{},
		onboarding.AcceptRequest{InvitationID: query.Get("iid"), CredentialID: query.Get("cid"),
			Token: query.Get("token")}); err == nil {
		t.Fatal("重复接受邀请应被拒绝")
	}
	// 非授权发起者不能创建邀请（宿主授权钩子 fail-closed）。
	adminBCaller := mustStep91OnboardingCaller(t, env.adminB)
	if _, err := env.onboarding.CreateInvitation(env.ctx, adminBCaller,
		onboarding.CreateRequest{TargetEmail: "step91-denied@example.test"}); !errors.Is(err, onboarding.ErrAccessDenied) {
		t.Fatalf("非授权发起者创建邀请应被拒绝，实际 %v", err)
	}
}

// TestStep91ProfileAndEmailChange 覆盖邮箱变更（申请→验证→切换→旧地址告知）与
// 未验证/错误凭证的拒绝路径。
func TestStep91ProfileAndEmailChange(t *testing.T) {
	env := newStep91Env(t)
	userCaller, err := emailchange.UserCaller(env.user1)
	if err != nil {
		t.Fatalf("邮箱变更 Caller: %v", err)
	}
	first, err := env.emailchange.RequestChange(env.ctx, userCaller, "step91-user1@example.test", "")
	if err != nil {
		t.Fatalf("申请邮箱变更: %v", err)
	}
	if !first.VerificationSent {
		t.Fatalf("邮箱验证入口未发送: %+v", first)
	}
	link := env.mail.lastVerificationURL(t)
	// 错误令牌必须拒绝，且不产生切换。
	if _, err := env.emailchange.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: link.Query().Get("rid"), CredentialID: link.Query().Get("cid"),
		Token: "invalid-token"}); err == nil {
		t.Fatal("错误验证令牌应被拒绝")
	}
	verified, err := env.emailchange.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: link.Query().Get("rid"), CredentialID: link.Query().Get("cid"),
		Token: link.Query().Get("token")})
	if err != nil {
		t.Fatalf("验证新邮箱: %v", err)
	}
	if verified.UserID != env.user1 || verified.Email != "step91-user1@example.test" {
		t.Fatalf("邮箱切换结果不符合预期: %+v", verified)
	}
	env.assertAudit(t, "email.change.request", "success")
	env.assertAudit(t, "email.change.verify", "success")
	// 再次变更：旧（已验证）地址在切换完成后收到安全告知；未验证前地址不切换。
	second, err := env.emailchange.RequestChange(env.ctx, userCaller, "step91-user1b@example.test", "")
	if err != nil {
		t.Fatalf("二次申请邮箱变更: %v", err)
	}
	if !second.VerificationSent {
		t.Fatalf("二次邮箱验证入口未发送: %+v", second)
	}
	if got := env.dbCount(t, `SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email=?`,
		env.user1, "step91-user1b@example.test"); got != 0 {
		t.Fatalf("未验证的新邮箱不应入库: %d", got)
	}
	link2 := env.mail.lastVerificationURL(t)
	if _, err := env.emailchange.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: link2.Query().Get("rid"), CredentialID: link2.Query().Get("cid"),
		Token: link2.Query().Get("token")}); err != nil {
		t.Fatalf("验证第二个新邮箱: %v", err)
	}
	env.mail.mu.Lock()
	noticeCount := len(env.mail.notices)
	env.mail.mu.Unlock()
	if noticeCount < 1 {
		t.Fatal("已验证旧邮箱应收安全告知")
	}
}

// TestStep91PermissionMatrixAcrossApps 覆盖多应用权限隔离、直接/间接授权、
// 成员状态（active/disabled/移除）、角色/权限启停与资源数据范围边界。
func TestStep91PermissionMatrixAcrossApps(t *testing.T) {
	env := newStep91Env(t)
	user1Caller := mustStep91AuthzUserCaller(t, env.user1)
	readCheck := func(caller authz.Caller, userID, scopeID string, keys ...string) authz.CheckResult {
		t.Helper()
		result, err := env.access.Check(env.ctx, caller, authz.CheckRequest{
			SubjectUserID: userID, ScopeID: scopeID, Permissions: keys, Mode: authz.ModeAll})
		if err != nil {
			t.Fatalf("权限检查 %s/%s: %v", userID, scopeID, err)
		}
		return result
	}

	// 间接授权（组成员 → 组角色 → 权限）：应用 A app.read 允许。
	allowed := readCheck(user1Caller, env.user1, env.appA, "app.read")
	if !allowed.Allowed {
		t.Fatalf("组成员间接授权应允许 app.read: %+v", allowed)
	}
	if len(allowed.Permissions) != 1 || len(allowed.Permissions[0].Sources) == 0 {
		t.Fatalf("权限来源应可追踪: %+v", allowed.Permissions)
	}
	// 组成员没有 app.write：拒绝且返回稳定码。
	if denied := readCheck(user1Caller, env.user1, env.appA, "app.write"); denied.Allowed ||
		denied.Code != authz.CodePermissionRequired {
		t.Fatalf("未授权 app.write 应拒绝/PERMISSION_REQUIRED: %+v", denied)
	}
	// 跨应用：用户1非应用 B 成员，同名 app.read 不能跨应用继承。
	if crossApp := readCheck(user1Caller, env.user1, env.appB, "app.read"); crossApp.Allowed ||
		crossApp.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("跨应用访问应要求成员关系: %+v", crossApp)
	}

	// 直接授权（用户2 → 角色 → 权限）：应用 A app.read/app.write 允许；
	// 应用 B 是成员但无角色：同名 app.read 仍拒绝（同名权限不跨应用关联）。
	user2Caller := mustStep91AuthzUserCaller(t, env.user2)
	if direct := readCheck(user2Caller, env.user2, env.appA, "app.read", "app.write"); !direct.Allowed {
		t.Fatalf("直接角色应允许 app.read/app.write: %+v", direct)
	}
	if crossRole := readCheck(user2Caller, env.user2, env.appB, "app.read"); crossRole.Allowed ||
		crossRole.Code != authz.CodePermissionRequired {
		t.Fatalf("应用 B 无角色时同名权限不应生效: %+v", crossRole)
	}

	// 数据范围边界：直接角色数据范围为 resources，仅允许指定资源。
	inScope, err := env.access.CheckResourceAccess(env.ctx, user2Caller, env.user2, env.appA,
		"app.read", "res_step91_allowed")
	if err != nil || !inScope.Allowed {
		t.Fatalf("数据范围内资源应允许: %+v / %v", inScope, err)
	}
	outScope, err := env.access.CheckResourceAccess(env.ctx, user2Caller, env.user2, env.appA,
		"app.read", "res_step91_other")
	if err != nil {
		t.Fatalf("越界资源检查: %v", err)
	}
	if outScope.Allowed || outScope.Code != authz.CodeResourceForbidden {
		t.Fatalf("数据范围外资源应拒绝/RESOURCE_FORBIDDEN: %+v", outScope)
	}

	// 成员状态 disabled：即使持有角色也不能获得应用权限。
	if disabledMember := readCheck(mustStep91AuthzUserCaller(t, env.user3), env.user3, env.appA, "app.read"); disabledMember.Allowed ||
		disabledMember.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("停用成员应不能获得权限: %+v", disabledMember)
	}
	// 无成员关系：直接拒绝。
	if noMember := readCheck(mustStep91AuthzUserCaller(t, env.userNoApp), env.userNoApp, env.appA, "app.read"); noMember.Allowed ||
		noMember.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("无成员关系应拒绝: %+v", noMember)
	}

	// 角色停用：组成员权限立即失效（来源被标记 role_disabled，结果拒绝）。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE roles SET enabled=0 WHERE id=?`, env.roleAReader); err != nil {
		t.Fatalf("停用角色: %v", err)
	}
	disabledRole := readCheck(user1Caller, env.user1, env.appA, "app.read")
	if disabledRole.Allowed || !sourcesContainReason(disabledRole, "role_disabled") {
		t.Fatalf("角色停用后应拒绝并标记 role_disabled: %+v", disabledRole)
	}
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE roles SET enabled=1 WHERE id=?`, env.roleAReader); err != nil {
		t.Fatalf("恢复角色: %v", err)
	}
	// 权限停用：直接角色 app.write 立即失效（来源被标记 permission_disabled）。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE permissions SET enabled=0 WHERE id=?`, env.permAWrite); err != nil {
		t.Fatalf("停用权限: %v", err)
	}
	disabledPermission := readCheck(user2Caller, env.user2, env.appA, "app.write")
	if disabledPermission.Allowed || disabledPermission.Code != authz.CodePermissionDisabled {
		t.Fatalf("权限停用后应拒绝/PERMISSION_DISABLED: %+v", disabledPermission)
	}
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE permissions SET enabled=1 WHERE id=?`, env.permAWrite); err != nil {
		t.Fatalf("恢复权限: %v", err)
	}

	// 普通用户不能查询他人有效权限（数据范围/隐私边界）。
	if _, err := env.access.EffectivePermissions(env.ctx, user1Caller, env.user2, env.appA,
		authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("普通用户查询他人权限应被拒绝，实际 %v", err)
	}
	// root 不通过普通权限引擎推导权限。
	systemCaller, err := authz.SystemCaller("step91-target-guard")
	if err != nil {
		t.Fatalf("系统查询 Caller: %v", err)
	}
	rootCheck := readCheck(systemCaller, env.root, "system", "users.read")
	if rootCheck.Allowed || rootCheck.Code != authz.CodeAccessDenied {
		t.Fatalf("root 不应通过普通权限引擎获得权限: %+v", rootCheck)
	}

	// 成员移除：通过真实用户组服务移除组成员后，间接授权立即失效。
	adminAGroupCaller := mustStep91GroupUserCaller(t, env.adminA)
	if _, err := env.groups.RemoveMembers(env.ctx, adminAGroupCaller,
		group.MemberBatchRequest{GroupID: env.groupA, UserIDs: []string{env.user1}}); err != nil {
		t.Fatalf("移除组成员: %v", err)
	}
	if removed := readCheck(user1Caller, env.user1, env.appA, "app.read"); removed.Allowed {
		t.Fatalf("移除组成员后间接授权应失效: %+v", removed)
	}
	env.assertAudit(t, "group.member.remove", "success")
}

// TestStep91SelfEscalationAndCrossAppDenied 覆盖自我提权、跨应用越权与服务端
// 授权器 fail-closed：应用 A 管理员不能管理应用 B/系统范围，普通用户不能改角色。
func TestStep91SelfEscalationAndCrossAppDenied(t *testing.T) {
	env := newStep91Env(t)
	adminACaller := mustStep91RoleUserCaller(t, env.adminA)
	adminAOnboarding := mustStep91OnboardingCaller(t, env.adminA)

	// 自我提权（直接分配本人未获转授权限的角色）：委派检查拒绝。
	if _, err := env.roles.AssignUserRole(env.ctx, adminACaller, env.roleAWriter, env.adminA); err == nil {
		t.Fatal("给本人分配未获资格的角色应被拒绝")
	}
	// 合法直接授权（已获 app.read 转授资格，目标为他人且是应用成员）。
	if _, err := env.roles.AssignUserRole(env.ctx, adminACaller, env.roleAReader, env.user1); err != nil {
		t.Fatalf("合法直接授权应成功: %v", err)
	}
	env.assertAudit(t, "role.assignment.user.assign", "success")
	// 跨应用越权：应用 A 管理员不能给应用 B 角色授权。
	if _, err := env.roles.AssignUserRole(env.ctx, adminACaller, env.roleBReader, env.adminB); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("跨应用角色授权应被拒绝，实际 %v", err)
	}
	// 系统范围：应用管理员不能创建系统角色。
	if _, err := env.roles.CreateRole(env.ctx, mustStep91RoleUserCaller(t, env.adminA), role.CreateRequest{
		ScopeID: "system", Key: "system_escalation", Name: "越权系统角色"}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员创建系统角色应被拒绝，实际 %v", err)
	}
	// 应用管理员不能创建其他应用的用户组。
	if _, err := env.groups.CreateGroup(env.ctx, mustStep91GroupUserCaller(t, env.adminA),
		group.CreateRequest{ScopeID: env.appB, GroupKey: "app_b_escalation", Name: "越权组"}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("跨应用创建用户组应被拒绝，实际 %v", err)
	}
	// 普通用户不能分配角色（不是管理身份）。
	if _, err := env.roles.AssignUserRole(env.ctx, mustStep91RoleUserCaller(t, env.user1),
		env.roleAWriter, env.user1); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("普通用户分配角色应被拒绝，实际 %v", err)
	}
	// 应用管理员不能把应用 B 角色塞进应用 A 的邀请。
	if _, err := env.onboarding.CreateInvitation(env.ctx, adminAOnboarding,
		onboarding.CreateRequest{TargetEmail: "step91-crossapp@example.test", AppID: env.appA,
			Roles: []onboarding.Role{{RoleID: env.roleBReader, ScopeID: env.appB}}}); err == nil {
		t.Fatal("跨应用角色邀请应被拒绝")
	}
	// 应用管理员不能批准其他应用相关的注册（管理授权只放行应用 A 管理员）。
	if _, err := env.onboarding.ApproveRegistration(env.ctx,
		mustStep91OnboardingCaller(t, env.adminB), onboarding.ReviewRequest{UserID: env.target}); err == nil {
		t.Fatal("应用 B 管理员批准注册应被拒绝")
	}
	// 被停用的账户不能走普通人工恢复（目标不可用，客服流程 fail-closed）。
	if _, err := env.accounts.DisableUser(env.ctx, env.localAdmin(t),
		account.StateCommandRequest{UserID: env.disabledTarget,
			ExpectedRowVersion: env.getUser(t, env.disabledTarget).RowVersion}); err != nil {
		t.Fatalf("停用目标账户: %v", err)
	}
	staffCaller, err := manualrecovery.UserCaller(env.support)
	if err != nil {
		t.Fatalf("客服 Caller: %v", err)
	}
	if _, err := env.recovery.Create(env.ctx, staffCaller,
		manualrecovery.CreateRequest{TargetUserID: env.disabledTarget,
			Operation:             manualrecovery.OperationPasswordReset,
			VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
			VerificationReference: "verify-ref-91-1",
			EvidenceSummary:       "线下核验身份证件原件（合成验收数据）",
			Reason:                "用户遗忘密码（合成验收场景）",
			Delivery:              manualrecovery.DeliveryVerifiedEmail}); !errors.Is(err, manualrecovery.ErrTargetUnavailable) {
		t.Fatalf("停用账户人工恢复应被拒绝，实际 %v", err)
	}
}

// TestStep91SupportRecoveryFlow 覆盖客服人工恢复完整状态机：求助→独立审批→等待期→
// 受控执行、拒绝、取消，以及 root/高权限目标保护、自我审批、越界执行与审计留痕。
func TestStep91SupportRecoveryFlow(t *testing.T) {
	env := newStep91Env(t)
	staffCaller, err := manualrecovery.UserCaller(env.support)
	if err != nil {
		t.Fatalf("客服 Caller: %v", err)
	}
	approverCaller, err := manualrecovery.UserCaller(env.approver)
	if err != nil {
		t.Fatalf("审批人 Caller: %v", err)
	}
	executorCaller, err := manualrecovery.UserCaller(env.executorUser)
	if err != nil {
		t.Fatalf("执行人 Caller: %v", err)
	}
	createRequest := func(targetUserID string) manualrecovery.CreateRequest {
		return manualrecovery.CreateRequest{TargetUserID: targetUserID,
			Operation:             manualrecovery.OperationPasswordReset,
			VerificationBasis:     manualrecovery.BasisInPersonIdentityDocument,
			VerificationReference: "verify-ref-91-2",
			EvidenceSummary:       "线下核验身份证件原件（合成验收数据）",
			Reason:                "用户遗忘密码（合成验收场景）",
			Delivery:              manualrecovery.DeliveryVerifiedEmail}
	}

	// 正路径：求助 → 独立审批 → 等待期未满拒绝执行 → 等待期满执行完成。
	created, err := env.recovery.Create(env.ctx, staffCaller, createRequest(env.target))
	if err != nil {
		t.Fatalf("客服发起求助: %v", err)
	}
	if created.Status != manualrecovery.StatusPendingApproval {
		t.Fatalf("求助初始状态不符合预期: %s", created.Status)
	}
	env.assertAudit(t, manualrecovery.ActionRequested, "success")

	// 本人不能审批自己发起的申请（独立性）。
	if _, err := env.recovery.Approve(env.ctx, staffCaller,
		manualrecovery.ApproveRequest{RequestID: created.ID}); !errors.Is(err, manualrecovery.ErrSelfApproval) {
		t.Fatalf("发起人自批应被拒绝，实际 %v", err)
	}
	approved, err := env.recovery.Approve(env.ctx, approverCaller,
		manualrecovery.ApproveRequest{RequestID: created.ID, Note: "独立审批通过"})
	if err != nil {
		t.Fatalf("独立审批: %v", err)
	}
	if approved.Status != manualrecovery.ApprovalActive {
		t.Fatalf("审批结果不符合预期: %+v", approved)
	}
	env.assertAudit(t, manualrecovery.ActionApproved, "success")
	// 等待期未满：不能提前执行。
	if _, err := env.recovery.Execute(env.ctx, executorCaller,
		manualrecovery.ExecuteRequest{RequestID: created.ID}); !errors.Is(err, manualrecovery.ErrApprovalNotYetValid) {
		t.Fatalf("等待期未满执行应被拒绝，实际 %v", err)
	}
	// 推进时钟到等待期满后：审批人没有执行权限，越界执行拒绝；执行人执行成功。
	env.now = step91AcceptanceTime.Add(time.Hour + time.Minute)
	if _, err := env.recovery.Execute(env.ctx, approverCaller,
		manualrecovery.ExecuteRequest{RequestID: created.ID}); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("审批人越界执行应被拒绝，实际 %v", err)
	}
	executed, err := env.recovery.Execute(env.ctx, executorCaller,
		manualrecovery.ExecuteRequest{RequestID: created.ID})
	if err != nil {
		t.Fatalf("受控执行: %v", err)
	}
	if executed.Status != manualrecovery.StatusCompleted || !executed.CredentialIssued {
		t.Fatalf("执行结果不符合预期: %+v", executed)
	}
	if env.executor.calls != 1 {
		t.Fatalf("执行器调用次数不符合预期: %d", env.executor.calls)
	}
	if env.notifier.countNotifications() < 1 {
		t.Fatal("恢复完成后应向既有渠道发送通知")
	}
	env.assertAudit(t, manualrecovery.ActionExecution, "success")
	// 一次性：重复执行拒绝。
	if _, err := env.recovery.Execute(env.ctx, executorCaller,
		manualrecovery.ExecuteRequest{RequestID: created.ID}); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("重复执行应被拒绝，实际 %v", err)
	}

	// 拒绝路径：第二次求助被独立审批人拒绝（终态），之后不能执行。
	rejectedRequest, err := env.recovery.Create(env.ctx, staffCaller, createRequest(env.target))
	if err != nil {
		t.Fatalf("二次求助: %v", err)
	}
	if err := env.recovery.Reject(env.ctx, approverCaller,
		manualrecovery.RejectRequest{RequestID: rejectedRequest.ID, Reason: "核验依据不足"}); err != nil {
		t.Fatalf("拒绝申请: %v", err)
	}
	env.assertAudit(t, manualrecovery.ActionRejected, "success")
	if _, err := env.recovery.Execute(env.ctx, executorCaller,
		manualrecovery.ExecuteRequest{RequestID: rejectedRequest.ID}); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("已拒绝申请不能再执行，实际 %v", err)
	}

	// 取消路径：发起者取消待审批申请（终态）。
	cancelRequest, err := env.recovery.Create(env.ctx, staffCaller, createRequest(env.target))
	if err != nil {
		t.Fatalf("三次求助: %v", err)
	}
	if err := env.recovery.Cancel(env.ctx, staffCaller, cancelRequest.ID, "", "用户已线下解决"); err != nil {
		t.Fatalf("取消申请: %v", err)
	}
	env.assertAudit(t, manualrecovery.ActionCancelled, "success")
	if _, err := env.recovery.Approve(env.ctx, approverCaller,
		manualrecovery.ApproveRequest{RequestID: cancelRequest.ID}); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("已取消申请不能再审批，实际 %v", err)
	}

	// 目标保护：root 与高权限账户不能走普通客服恢复（SUPPORT_TARGET_PROTECTED）。
	// 重新处于 active 的高权限账户（测试内恢复状态用于目标保护判定）。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE users SET status='active' WHERE id=?`, env.highPriv); err != nil {
		t.Fatalf("恢复高权限账户状态: %v", err)
	}
	for _, target := range []string{env.root, env.highPriv} {
		if _, err := env.recovery.Create(env.ctx, staffCaller, createRequest(target)); !errors.Is(err, manualrecovery.ErrTargetProtected) {
			t.Fatalf("受保护目标 %s 的普通恢复应被拒绝，实际 %v", target, err)
		}
		if code := manualrecovery.CodeOf(manualrecovery.ErrTargetProtected); code != manualrecovery.CodeSupportTargetProtected {
			t.Fatalf("目标保护错误码不符合预期: %s", code)
		}
	}
	// 非工作人员不能发起求助（客服资格不是普通用户权限）。
	normalCaller, err := manualrecovery.UserCaller(env.userNoApp)
	if err != nil {
		t.Fatalf("普通用户 Caller: %v", err)
	}
	if _, err := env.recovery.Create(env.ctx, normalCaller, createRequest(env.target)); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("非工作人员发起求助应被拒绝，实际 %v", err)
	}
	// 拒绝路径必须留痕：无效请求/越权至少产生 manual_recovery.denied 审计。
	if got := env.auditCount(t, manualrecovery.ActionDenied, ""); got < 1 {
		t.Fatalf("人工恢复拒绝缺少审计留痕: %d", got)
	}
	// 审计不得包含明文秘密：检查人工恢复审计 detail_json 不含口令/令牌字样。
	var leakCount int
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'manual_recovery.%'
AND (detail_json LIKE '%"password":%' OR detail_json LIKE '%"token":%'
	OR detail_json LIKE '%"secret":%' OR detail_json LIKE '%"otp":%')`).Scan(&leakCount); err != nil {
		t.Fatalf("检查审计明文: %v", err)
	}
	if leakCount != 0 {
		t.Fatalf("人工恢复审计出现疑似明文秘密字段: %d", leakCount)
	}
}

// sourcesContainReason 报告检查结果中是否有来源被指定原因排除（用于断言角色/权限
// 停用、成员状态等状态限制确实被引擎识别）。
func sourcesContainReason(result authz.CheckResult, reason string) bool {
	for _, permission := range result.Permissions {
		for _, source := range permission.Sources {
			if source.ExcludedReason == reason {
				return true
			}
		}
	}
	return false
}

// --- 可信调用者构造辅助 ---

func mustStep91ProfileCaller(t *testing.T, userID string) profile.Caller {
	t.Helper()
	caller, err := profile.UserCaller(userID)
	if err != nil {
		t.Fatalf("资料用户 Caller: %v", err)
	}
	return caller
}

func mustStep91OnboardingCaller(t *testing.T, userID string) onboarding.Caller {
	t.Helper()
	caller, err := onboarding.UserCaller(userID)
	if err != nil {
		t.Fatalf("入驻用户 Caller: %v", err)
	}
	return caller
}

func mustStep91AccountUserCaller(t *testing.T, userID string) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(userID)
	if err != nil {
		t.Fatalf("账户用户 Caller: %v", err)
	}
	return caller
}

func mustStep91AuthzUserCaller(t *testing.T, userID string) authz.Caller {
	t.Helper()
	caller, err := authz.UserCaller(userID)
	if err != nil {
		t.Fatalf("授权用户 Caller: %v", err)
	}
	return caller
}

func mustStep91RoleUserCaller(t *testing.T, userID string) role.Caller {
	t.Helper()
	caller, err := role.UserCaller(userID)
	if err != nil {
		t.Fatalf("角色用户 Caller: %v", err)
	}
	return caller
}

func mustStep91GroupUserCaller(t *testing.T, userID string) group.Caller {
	t.Helper()
	caller, err := group.UserCaller(userID)
	if err != nil {
		t.Fatalf("用户组用户 Caller: %v", err)
	}
	return caller
}
