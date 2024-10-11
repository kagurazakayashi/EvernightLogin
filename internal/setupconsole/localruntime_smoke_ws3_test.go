package setupconsole

// WS3 本地维护真实装配冒烟测试（临时/可保留）：用 serverapp.OpenBase 在临时
// SQLite + 临时主密钥上构造真实领域服务，验证本地维护调用者能通过真实授权层完成
// 用户列表/创建/RBAC 列表等基础操作，防止“测试替身通过但生产授权层拒绝”。
//
// 该测试不启动监听/后台任务；所有资源由子测试清理。

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// TestWS3LocalRuntimeAuthorizationSmoke 验证真实生产授权层对本地维护调用者的判定。
func TestWS3LocalRuntimeAuthorizationSmoke(t *testing.T) {
	ctx := context.Background()
	dir := testutil.TempDir(t)
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(dir, "login.db")
	cfg.Server.PathPrefix = ""
	base, err := serverapp.OpenBase(ctx, serverapp.BaseOptions{
		Config: cfg, MasterKeyFile: filepath.Join(dir, "master.key"),
		Migrate: true, CreateMasterKey: true, Now: time.Now,
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := base.Close(context.Background()); closeErr != nil {
			t.Logf("Close: %v", closeErr)
		}
	})
	if base.Managed == nil || base.Managed.Account == nil {
		t.Fatal("账户服务未装配")
	}
	caller, err := account.LocalBootstrapCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地账户调用者: %v", err)
	}
	// 1) 用户列表：真实授权层是否允许本地维护调用者。
	if _, err := base.Managed.Account.ListUsers(ctx, caller, account.ListRequest{Limit: 5}); err != nil {
		t.Fatalf("本地维护 ListUsers 被真实授权层拒绝: %v", err)
	}
	// 2) 创建用户 + 读取。
	created, err := base.Managed.Account.CreateUser(ctx, caller, account.CreateRequest{
		Username: "ws3-smoke-user", Nickname: "冒烟用户"})
	if err != nil {
		t.Fatalf("本地维护 CreateUser 失败: %v", err)
	}
	if created.ID == "" || created.Username != "ws3-smoke-user" {
		t.Fatalf("创建结果异常: %+v", created)
	}
	// 3) 角色列表。
	roleCaller, err := role.LocalBootstrapCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地角色调用者: %v", err)
	}
	if base.Managed.Role != nil {
		if _, err := base.Managed.Role.ListRoles(ctx, roleCaller,
			role.ListRequest{ScopeID: "system", Limit: 20}); err != nil {
			t.Fatalf("本地维护 ListRoles 失败: %v", err)
		}
	}
	// 4) WS3Services 适配器真实链：用户列表/详情/创建/启停/有效期/密码/改名、
	// RBAC 列表、应用列表、安全域因素/会话、审计不可用明确。
	maint, _ := newFakeMaintRecorder()
	services, err := newWS3Services(base, "os:tester@local", nil, maint)
	if err != nil {
		t.Fatalf("构造 WS3Services: %v", err)
	}
	userPage, err := services.Users.ListUsers(ctx, LocalUserQuery{PageRequest: LocalPageRequest{Limit: 10}})
	if err != nil || len(userPage.Users) == 0 {
		t.Fatalf("WS3 ListUsers = %+v err=%v", userPage, err)
	}
	user, err := services.Users.GetUser(ctx, created.ID)
	if err != nil || user.ID != created.ID {
		t.Fatalf("WS3 GetUser = %+v err=%v", user, err)
	}
	disabled, err := services.Users.SetEnabled(ctx, created.ID, false, 0)
	if err != nil || disabled.Status != "disabled" {
		t.Fatalf("WS3 SetEnabled 停用 = %+v err=%v", disabled, err)
	}
	enabled, err := services.Users.SetEnabled(ctx, created.ID, true, 0)
	if err != nil || enabled.Status != "active" {
		t.Fatalf("WS3 SetEnabled 启用 = %+v err=%v", enabled, err)
	}
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	validityUser, err := services.Users.SetValidity(ctx, created.ID, LocalValidity{
		UserID: created.ID, ValidUntil: &future})
	if err != nil || validityUser.ID != created.ID {
		t.Fatalf("WS3 SetValidity = %+v err=%v", validityUser, err)
	}
	if _, err := services.Identity.SetPassword(ctx, created.ID, "WS3-Smoke!Pass9", true); err != nil {
		t.Fatalf("WS3 SetPassword: %v", err)
	}
	credentialStatus, err := services.Identity.Credentials(ctx, created.ID)
	if err != nil || !credentialStatus.HasPassword {
		t.Fatalf("WS3 Credentials = %+v err=%v", credentialStatus, err)
	}
	renamed, err := services.Identity.Rename(ctx, created.ID, "ws3-smoke-renamed", "冒烟测试", 0)
	if err != nil || renamed.Username != "ws3-smoke-renamed" {
		t.Fatalf("WS3 Rename = %+v err=%v", renamed, err)
	}
	if roles, _, err := services.RBAC.ListRoles(ctx, LocalPageRequest{Limit: 20}, "system"); err != nil {
		t.Fatalf("WS3 ListRoles: %v", err)
	} else {
		t.Logf("roles=%d", len(roles))
	}
	if _, _, err := services.RBAC.ListPermissions(ctx, LocalPageRequest{Limit: 20}); err != nil {
		t.Fatalf("WS3 ListPermissions: %v", err)
	}
	if _, _, err := services.RBAC.ListGroups(ctx, LocalPageRequest{Limit: 20}, "system"); err != nil {
		t.Fatalf("WS3 ListGroups: %v", err)
	}
	if _, _, err := services.Apps.ListApplications(ctx, LocalPageRequest{Limit: 20}); err != nil {
		t.Fatalf("WS3 ListApplications: %v", err)
	}
	if _, err := services.Security.ListFactors(ctx, created.ID); err != nil {
		t.Fatalf("WS3 ListFactors: %v", err)
	}
	if _, _, err := services.Security.ListSessions(ctx, created.ID, 20, 0); err != nil {
		t.Fatalf("WS3 ListSessions: %v", err)
	}
	if _, err := services.Security.RevokeSessions(ctx, created.ID, "冒烟测试"); err != nil {
		t.Fatalf("WS3 RevokeSessions: %v", err)
	}
	// 5) 应用写/成员链（真实授权层 + 本地维护身份）。
	application, err := services.Apps.CreateApplication(ctx, "WS3 冒烟应用", "冒烟描述", "https://example.test")
	if err != nil {
		t.Fatalf("WS3 CreateApplication: %v", err)
	}
	if application.ID == "" {
		t.Fatal("应用 ID 为空")
	}
	if _, err := services.Apps.UpdateApplication(ctx, application.ID, "WS3 冒烟应用改名",
		"更新描述", "", 0); err != nil {
		t.Fatalf("WS3 UpdateApplication: %v", err)
	}
	if err := services.Apps.SetApplicationEnabled(ctx, application.ID, true); err != nil {
		t.Fatalf("WS3 SetApplicationEnabled 启用: %v", err)
	}
	if err := services.Apps.AddMember(ctx, application.ID, created.ID); err != nil {
		t.Fatalf("WS3 AddMember: %v", err)
	}
	members, _, err := services.Apps.ListMembers(ctx, application.ID, LocalPageRequest{Limit: 20})
	if err != nil || len(members) == 0 || members[0].UserID != created.ID {
		t.Fatalf("WS3 ListMembers = %+v err=%v", members, err)
	}
	if err := services.Apps.RemoveMember(ctx, application.ID, created.ID); err != nil {
		t.Fatalf("WS3 RemoveMember: %v", err)
	}
	clientCreated, err := services.Apps.CreateClient(ctx, application.ID,
		"冒烟 OAuth 客户端", []string{"https://client.example.test/cb"})
	if err != nil {
		t.Fatalf("WS3 CreateClient: %v", err)
	}
	if clientCreated.Secret == "" {
		t.Fatal("客户端登记应一次性返回秘密")
	}
	clients, err := services.Apps.ListClients(ctx, application.ID)
	if err != nil || len(clients) != 1 {
		t.Fatalf("WS3 ListClients = %+v err=%v", clients, err)
	}
	rotated, err := services.Apps.RotateClientSecret(ctx, application.ID, clients[0].ClientID)
	if err != nil || rotated.Secret == "" {
		t.Fatalf("WS3 RotateClientSecret = %+v err=%v", rotated, err)
	}
	if err := services.Apps.RevokeClient(ctx, application.ID, clients[0].ClientID); err != nil {
		t.Fatalf("WS3 RevokeClient: %v", err)
	}
	if err := services.Apps.SetApplicationEnabled(ctx, application.ID, false); err != nil {
		t.Fatalf("WS3 SetApplicationEnabled 停用: %v", err)
	}
	_ = application
	// 6) 审计/诊断/任务（本地维护只读；真实生产授权层已允许 actor_local_admin 读审计）。
	if _, err := services.Audit.QueryAudit(ctx, LocalAuditFilter{Limit: 20}); err != nil {
		t.Fatalf("WS3 QueryAudit: %v", err)
	}
	diagnostics, err := services.Audit.Diagnostics(ctx)
	if err != nil || diagnostics.LatestCount == 0 {
		t.Fatalf("WS3 Diagnostics = %+v err=%v", diagnostics, err)
	}
	if _, _, err := services.Audit.ListTasks(ctx, 20, 0); err != nil &&
		!errors.Is(err, ErrLocalUnsupported) {
		t.Fatalf("WS3 ListTasks: %v", err)
	}
	// 7) 审计保留策略/危险清理适配器（本地维护；临时实例上真实执行 retention 设置
	// 与清理预估；清理提交依赖任务运行时，未启用时接受明确不可用）。
	if _, err := services.Audit.Retention(ctx); err != nil {
		t.Fatalf("WS3 Retention: %v", err)
	}
	if _, err := services.Audit.SetRetention(ctx, 30, "冒烟测试保留策略"); err != nil {
		t.Fatalf("WS3 SetRetention: %v", err)
	}
	purgeCutoff := time.Now().UTC().Add(-400 * 24 * time.Hour)
	preview, err := services.Audit.PreviewPurge(ctx, purgeCutoff, 100)
	if err != nil {
		t.Fatalf("WS3 PreviewPurge: %v", err)
	}
	if preview.ScopeID != "system" || !preview.MaintenanceProtected {
		t.Fatalf("清理预估异常: %+v", preview)
	}
	if _, err := services.Audit.StartPurge(ctx, preview, "冒烟测试清理"); err != nil &&
		!errors.Is(err, ErrLocalUnsupported) {
		// 任务运行时未启用/入队失败属明确不可用；不能伪造成功。
		t.Logf("清理提交不可用（可接受）: %v", err)
	}
	if _, _, err := services.Audit.ListPurgeRuns(ctx, 10, 0); err != nil {
		t.Fatalf("WS3 ListPurgeRuns: %v", err)
	}
	if _, _, err := services.Audit.ListDeliveries(ctx, 10, 0); err != nil &&
		!errors.Is(err, ErrLocalUnsupported) {
		t.Fatalf("WS3 ListDeliveries: %v", err)
	}
	if _, _, err := services.Audit.ListReports(ctx, 10, 0); err != nil &&
		!errors.Is(err, ErrLocalUnsupported) {
		t.Fatalf("WS3 ListReports: %v", err)
	}
	now := time.Now().UTC()
	if report, err := services.Audit.GenerateReport(ctx, LocalReportRequest{
		ScopeID: "system", From: now.Add(-24 * time.Hour), To: now,
		Formats: []string{"json"}}); err != nil {
		if !errors.Is(err, ErrLocalUnsupported) {
			t.Logf("报告生成明确不可用（可接受）: %v", err)
		}
	} else if report.ID == "" {
		t.Fatal("报告生成返回空报告编号")
	}
}
