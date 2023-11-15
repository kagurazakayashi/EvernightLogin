package app

// 步骤 225 P0：应用生命周期/成员公开接口测试。
//   - LocalAdmin 成功链：创建应用→详情→更新资料→成员加入/详情/资料/启停/移除；
//   - 两应用隔离：应用范围管理员只能读自己应用，跨应用拒绝；
//   - 审计失败回滚：SQLite 触发注入，应用资料更新被拒绝且状态不变。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// createTestApplication 通过公开管理门面创建应用并返回详情。
func createTestApplication(t *testing.T, ctx context.Context, runtime *Runtime,
	name, clientType string) AdminApplication {
	t.Helper()
	created, err := runtime.Admin().CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: runtime.LocalAdmin(), Name: name, Description: name + " 说明",
		ClientType: clientType, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 %s 失败: %v", name, err)
	}
	return created
}

// TestApplicationLifecyclePublicFlow 覆盖应用资料与成员管理成功链。
func TestApplicationLifecyclePublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 30, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	applications := runtime.Applications()
	const password = "K8$wR3!nB6@yF1#v"
	member := createLifecycleUser(t, ctx, runtime, "app-member", password)
	application := createTestApplication(t, ctx, runtime, "生命周期应用", "confidential")

	detail, err := applications.GetApplication(ctx, AdminApplicationRequest{
		Caller: local, ApplicationID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if detail.ID != application.ID || detail.Name != "生命周期应用" ||
		detail.ClientType != "confidential" || detail.RowVersion <= 0 {
		t.Fatalf("应用详情异常: %+v", detail)
	}
	updated, err := applications.UpdateApplication(ctx, AdminUpdateApplicationRequest{
		Caller: local, ApplicationID: application.ID, Name: "改名应用",
		Description: "新说明", IconRef: "icons/new.png", Homepage: "https://example.test/app",
		OwnerUserID: member.ID, ContactInfo: "ops@example.test",
		ExpectedRowVersion: detail.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}
	if updated.Name != "改名应用" || updated.IconRef != "icons/new.png" ||
		updated.OwnerUserID != member.ID || updated.RowVersion <= detail.RowVersion {
		t.Fatalf("应用更新结果异常: %+v", updated)
	}
	// 过期版本 → CONFLICT。
	if _, err := applications.UpdateApplication(ctx, AdminUpdateApplicationRequest{
		Caller: local, ApplicationID: application.ID, Name: "并发名",
		ExpectedRowVersion: detail.RowVersion, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("过期版本更新错误 = %v，期望 CONFLICT", err)
	}

	// 新应用默认停用：成员与客户端操作前先启用。
	enabledApp := enableTestApplication(t, ctx, runtime, application.ID, updated.RowVersion)

	// 成员：加入→详情→资料→停用/启用→移除。
	if err := runtime.Admin().AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: application.ID, UserID: member.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("AddApplicationMember: %v", err)
	}
	memberDetail, err := applications.GetApplicationMember(ctx, AdminApplicationMemberRequest{
		Caller: local, ApplicationID: application.ID, UserID: member.ID,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetApplicationMember: %v", err)
	}
	if memberDetail.Status != "active" || memberDetail.RowVersion <= 0 {
		t.Fatalf("成员详情异常: %+v", memberDetail)
	}
	changedMember, err := applications.UpdateApplicationMemberProfile(ctx,
		AdminUpdateApplicationMemberRequest{Caller: local, ApplicationID: application.ID,
			UserID: member.ID, DisplayName: "应用内显示名", Title: "运营",
			Note: "备注", ExpectedRowVersion: memberDetail.RowVersion,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("UpdateApplicationMemberProfile: %v", err)
	}
	if changedMember.DisplayName != "应用内显示名" || changedMember.Title != "运营" {
		t.Fatalf("成员资料更新异常: %+v", changedMember)
	}
	disabled, err := applications.DisableApplicationMember(ctx,
		AdminApplicationMemberChangeRequest{Caller: local, ApplicationID: application.ID,
			UserID: member.ID, ExpectedRowVersion: changedMember.RowVersion,
			RequestID: login.NewRequestID()})
	if err != nil || disabled.Member.Status != "disabled" || !disabled.Changed {
		t.Fatalf("停用成员异常: %+v, %v", disabled, err)
	}
	enabled, err := applications.EnableApplicationMember(ctx,
		AdminApplicationMemberChangeRequest{Caller: local, ApplicationID: application.ID,
			UserID: member.ID, ExpectedRowVersion: disabled.Member.RowVersion,
			RequestID: login.NewRequestID()})
	if err != nil || enabled.Member.Status != "active" {
		t.Fatalf("启用成员异常: %+v, %v", enabled, err)
	}
	if err := applications.RemoveApplicationMember(ctx,
		AdminApplicationMemberChangeRequest{Caller: local, ApplicationID: application.ID,
			UserID: member.ID, ExpectedRowVersion: enabled.Member.RowVersion,
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RemoveApplicationMember: %v", err)
	}
	if _, err := applications.GetApplicationMember(ctx, AdminApplicationMemberRequest{
		Caller: local, ApplicationID: application.ID, UserID: member.ID,
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("移除后成员读取错误 = %v，期望 NOT_FOUND", err)
	}

	// 删除预览/逻辑删除：应用需先停用。
	preview, err := applications.PreviewApplicationDeletion(ctx, AdminApplicationRequest{
		Caller: local, ApplicationID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("PreviewApplicationDeletion: %v", err)
	}
	if preview.ApplicationID != application.ID {
		t.Fatalf("删除预览异常: %+v", preview)
	}
	disabledApp, err := runtime.Admin().SetApplicationEnabled(ctx,
		AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: application.ID,
			Enabled: false, ExpectedRowVersion: enabledApp.RowVersion,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("停用应用: %v", err)
	}
	deleted, err := applications.DeleteApplication(ctx, AdminApplicationDeleteRequest{
		Caller: local, ApplicationID: application.ID,
		ExpectedRowVersion: disabledApp.RowVersion, RequestID: login.NewRequestID()})
	if err != nil || !deleted.Changed || deleted.Application.DeletedAt.IsZero() {
		t.Fatalf("删除应用异常: %+v, %v", deleted, err)
	}
	// 重复删除：已删除状态幂等（Changed=false）或稳定 CONFLICT；不得双删成功。
	if _, err := applications.DeleteApplication(ctx, AdminApplicationDeleteRequest{
		Caller: local, ApplicationID: application.ID,
		ExpectedRowVersion: deleted.Application.RowVersion,
		RequestID:          login.NewRequestID()}); err == nil {
		// 幂等成功也可接受，但必须仍是已删除状态。
		if fresh, getErr := applications.GetApplication(ctx, AdminApplicationRequest{
			Caller: local, ApplicationID: application.ID,
			RequestID: login.NewRequestID()}); getErr != nil || fresh.DeletedAt.IsZero() {
			t.Fatalf("重复删除后应用状态异常: %+v, %v", fresh, getErr)
		}
	}
}

// enableTestApplication 通过公开门面启用应用并返回最新详情（新应用默认停用）。
func enableTestApplication(t *testing.T, ctx context.Context, runtime *Runtime,
	applicationID string, rowVersion int64) AdminApplication {
	t.Helper()
	enabled, err := runtime.Admin().SetApplicationEnabled(ctx,
		AdminSetApplicationEnabledRequest{Caller: runtime.LocalAdmin(),
			ApplicationID: applicationID, Enabled: true, ExpectedRowVersion: rowVersion,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用失败: %v", err)
	}
	return enabled
}

// grantApplicationPermissions 给用户分配应用范围权限（测试运行时不安装预设目录）。
func grantApplicationPermissions(t *testing.T, ctx context.Context, runtime *Runtime,
	applicationID, userID string, keys []string) {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: applicationID, UserID: userID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入应用成员失败: %v", err)
	}
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: applicationID, Key: "step225-app-admin",
		Name: "应用管理员测试角色", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用角色失败: %v", err)
	}
	for _, key := range keys {
		permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: applicationID, Key: key, Name: "测试权限 " + key,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用权限 %s 失败: %v", key, err)
		}
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("组合应用权限失败: %v", err)
		}
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: userID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配应用角色失败: %v", err)
	}
}

// TestApplicationAdminCrossAppIsolation 覆盖应用范围管理员的两应用隔离。
func TestApplicationAdminCrossAppIsolation(t *testing.T) {
	ctx := context.Background()
	runtime, ctx, clock := lifecycleRuntimeWithClock(t)
	local := runtime.LocalAdmin()
	const password = "K8$wR3!nB6@yF1#v"
	appA := createTestApplication(t, ctx, runtime, "隔离应用A", "confidential")
	appB := createTestApplication(t, ctx, runtime, "隔离应用B", "confidential")
	enableTestApplication(t, ctx, runtime, appA.ID, appA.RowVersion)
	appAdminID, _, totpSecret := setupUserWithTOTP(t, runtime, clock, "app-admin-225", password)
	grantApplicationPermissions(t, ctx, runtime, appA.ID, appAdminID,
		[]string{"applications.read", "applications.update"})
	session := loginSessionWithTOTP(t, ctx, runtime, clock, "app-admin-225", password, totpSecret)
	adminCaller := runtime.AdminSession(session)
	applications := runtime.Applications()
	if _, err := applications.GetApplication(ctx, AdminApplicationRequest{
		Caller: adminCaller, ApplicationID: appA.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("应用管理员读取本应用失败: %v", err)
	}
	if _, err := applications.GetApplication(ctx, AdminApplicationRequest{
		Caller: adminCaller, ApplicationID: appB.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("跨应用读取错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := applications.UpdateApplication(ctx, AdminUpdateApplicationRequest{
		Caller: adminCaller, ApplicationID: appB.ID, Name: "越权改名",
		ExpectedRowVersion: 1, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("跨应用更新错误 = %v，期望 ACCESS_DENIED", err)
	}
	_ = local
}

// TestApplicationAuditFailureRollsBack 覆盖应用资料更新的审计失败回滚。
func TestApplicationAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 40, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	applications := runtime.Applications()
	application := createTestApplication(t, ctx, runtime, "审计回滚应用", "confidential")
	fresh, err := applications.GetApplication(ctx, AdminApplicationRequest{
		Caller: local, ApplicationID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	db := runtime.base.Store.DB()
	if _, err := db.Exec(`CREATE TRIGGER step225_audit_failure BEFORE INSERT ON audit_events
WHEN NEW.action='application.update' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计失败触发器: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS step225_audit_failure`) })
	_, err = applications.UpdateApplication(ctx, AdminUpdateApplicationRequest{
		Caller: local, ApplicationID: application.ID, Name: "审计失败改名",
		IconRef: "icons/audit.png", ExpectedRowVersion: fresh.RowVersion,
		RequestID: login.NewRequestID()})
	if !login.IsErrorCode(err, login.CodeAuditWriteFailed) &&
		!login.IsErrorCode(err, login.CodeDBUnavailable) {
		t.Fatalf("审计失败错误 = %v，期望 AUDIT_WRITE_FAILED/DB_UNAVAILABLE", err)
	}
	after, err := applications.GetApplication(ctx, AdminApplicationRequest{
		Caller: local, ApplicationID: application.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("回滚后 GetApplication: %v", err)
	}
	if after.Name != fresh.Name || after.RowVersion != fresh.RowVersion {
		t.Fatalf("审计失败后应用被改变: before=%+v after=%+v", fresh, after)
	}
}
