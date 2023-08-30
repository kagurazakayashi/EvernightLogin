package app_test

// 步骤 190：应用逻辑删除/物理清理的真实临时 SQLite 服务测试。覆盖影响预览、停用
// 前置、行版本、幂等、终态防复活、其他应用/共享账户不受损、审计保留、保留期与
// 受控通道限制、物理清理级联与幂等重试。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// mustExec 直接写入测试关联数据（成员/角色/权限/组/会话/客户端/刷新族/审计）。
func mustExec(t *testing.T, env *testEnv, statement string, args ...any) {
	t.Helper()
	if _, err := env.raw.ExecContext(context.Background(), statement, args...); err != nil {
		t.Fatalf("写入测试数据失败: %v", err)
	}
}

// TestApplicationDeletionLifecycle 覆盖逻辑删除的影响预览、状态机、行版本、幂等、
// 终态防复活、其他应用与共享账户不受损、审计保留与物理清理。
func TestApplicationDeletionLifecycle(t *testing.T) {
	// 保留期取 1ns：测试推进时钟后即可执行物理清理（生产默认 30 天）。
	env := prepareEnvWithRetention(t, time.Nanosecond)
	ctx := context.Background()
	appA := env.createApp(validCreateRequest(app.ClientTypeConfidential))
	appB := env.createApp(validCreateRequest(app.ClientTypeConfidential))
	// A 启用后才有“必须先停用”的拒绝路径。
	enabled, err := env.service.EnableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: appA.RowVersion})
	if err != nil || !enabled.Changed {
		t.Fatalf("启用应用失败: %v", err)
	}
	nowMs := env.clock.Now().UnixMilli()
	expiresMs := env.clock.Now().Add(time.Hour).UnixMilli()
	mustExec(t, env, `INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,1,?,?)`, appA.ID, testOwnerOne, "active", "{}", nowMs, nowMs)
	mustExec(t, env, `INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,0,1,?,?)`, "role_delete_fixture", appA.ID, "delete-fixture",
		"删除测试角色", "测试", "仅测试", nowMs, nowMs)
	mustExec(t, env, `INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,0,0,1,?,?)`, "perm_delete_fixture", appA.ID, "fixture.read",
		"删除测试权限", "测试", "仅测试", nowMs, nowMs)
	mustExec(t, env, `INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?)`, "grp_delete_fixture", appA.ID, "delete-fixture",
		"删除测试用户组", "测试", nowMs, nowMs)
	digest := make([]byte, 32)
	mustExec(t, env, `INSERT INTO sessions(id,user_id,app_id,kind,restricted_reason,required_steps_json,
security_version,secret_digest,csrf_digest,key_id,created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms)
VALUES(?,?,?,'normal','','[]',1,?,?,?,?,?,?,?)`,
		"11111111-1111-1111-1111-111111111111", testOwnerOne, appA.ID, digest, digest,
		"test-key", nowMs, nowMs, expiresMs, expiresMs)
	mustExec(t, env, `INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,row_version,created_at_ms,updated_at_ms)
VALUES(?,'confidential','["authorization_code"]','["https://client.example/cb"]','[]','["openid"]','["https://api.example"]','["client_secret_basic"]',1,1,?,?)`,
		appA.ID, nowMs, nowMs)
	mustExec(t, env, `INSERT INTO refresh_token_families(id,client_id,subject_user_id,authorization_id,scope,
audiences_json,security_version,created_at_ms,absolute_expires_at_ms,idle_timeout_ms,revoked_at_ms,revoke_reason)
VALUES(?,?,?,?,?,?,1,?,?,?,NULL,'')`, "rtf_delete_fixture", appA.ID, testOwnerOne,
		"auth_delete_fixture", "openid", `["https://api.example"]`, nowMs, expiresMs, 60000)
	mustExec(t, env, `INSERT INTO audit_events(id,occurred_at_ms,actor_type,actor_id,app_id_snapshot,
action,target_type,target_id,outcome,detail_json)
VALUES(?,?,'user',?,?,?,?,?,'success','{}')`, "audit_delete_fixture", nowMs,
		testOwnerOne, appA.ID, "application.fixture", "application", appA.ID)
	usersBefore := env.queryInt(`SELECT COUNT(*) FROM users`)

	// 影响预览：真实计数与“已启用不可删除”的阻塞原因。
	impact, err := env.service.PreviewDeletion(ctx, env.system, appA.ID)
	if err != nil {
		t.Fatalf("删除影响预览: %v", err)
	}
	if impact.CanDelete || impact.BlockReason == "" {
		t.Fatalf("启用中的应用不应可直接删除: %+v", impact)
	}
	if impact.MemberCount != 1 || impact.ActiveMemberCount != 1 || impact.RoleCount != 1 ||
		impact.PermissionCount != 1 || impact.GroupCount != 1 || impact.ActiveSessionCount != 1 ||
		impact.OAuthClientCount != 1 || impact.RefreshTokenFamilyCount != 1 ||
		impact.AuditEventCount != 1 {
		t.Fatalf("影响预览计数 = %+v", impact)
	}
	// 启用状态直接逻辑删除 → 非法状态转换（必须先停用）。
	if _, err := env.service.DeleteApplication(ctx, env.system, app.DeletionRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: enabled.Application.RowVersion}); !errors.Is(err, app.ErrInvalidTransition) {
		t.Fatalf("启用应用直接删除错误 = %v，期望 ErrInvalidTransition", err)
	}
	// 停用后再删除；停用不等于删除。
	disabled, err := env.service.DisableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: enabled.Application.RowVersion})
	if err != nil || !disabled.Changed {
		t.Fatalf("停用应用失败: %v", err)
	}
	if disabled.Application.Deleted() {
		t.Fatal("停用不应被当作删除")
	}
	// 行版本冲突：用旧版本删除 → ErrStateConflict。
	if _, err := env.service.DeleteApplication(ctx, env.system, app.DeletionRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: appA.RowVersion}); !errors.Is(err, app.ErrStateConflict) {
		t.Fatalf("旧行版本删除错误 = %v，期望 ErrStateConflict", err)
	}
	result, err := env.service.DeleteApplication(ctx, env.system, app.DeletionRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: disabled.Application.RowVersion})
	if err != nil || !result.Changed || !result.Application.Deleted() {
		t.Fatalf("逻辑删除结果 = %+v err=%v", result, err)
	}
	if result.Application.Status != app.StatusDisabled ||
		result.Application.RowVersion != disabled.Application.RowVersion+1 {
		t.Fatalf("逻辑删除后状态/版本 = %+v", result.Application)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM applications WHERE id=? AND deleted_at_ms IS NOT NULL`,
		appA.ID); value != 1 {
		t.Fatal("数据库未记录逻辑删除时间")
	}
	// 逻辑删除是终态：不能改资料/启停/复活；重复删除幂等成功。
	if _, err := env.service.UpdateApplication(ctx, env.system, appA.ID,
		app.UpdateRequest{Name: "复活尝试", ExpectedRowVersion: result.Application.RowVersion}); !errors.Is(err, app.ErrInvalidTransition) {
		t.Fatalf("已删除应用改资料错误 = %v", err)
	}
	if _, err := env.service.EnableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: result.Application.RowVersion}); !errors.Is(err, app.ErrInvalidTransition) {
		t.Fatalf("已删除应用启用错误 = %v", err)
	}
	again, err := env.service.DeleteApplication(ctx, env.system, app.DeletionRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: result.Application.RowVersion})
	if err != nil || again.Changed {
		t.Fatalf("重复逻辑删除 = %+v err=%v（期望幂等未变更）", again, err)
	}
	// 已删除应用仍可按 ID/包含已删除列表读取（审计/追溯），默认列表不返回。
	if _, err := env.service.GetApplication(ctx, env.system, appA.ID); err != nil {
		t.Fatalf("已删除应用应可读取用于追溯: %v", err)
	}
	defaultList, err := env.service.ListApplications(ctx, env.system, app.ListRequest{Limit: 100})
	if err != nil {
		t.Fatalf("默认列表: %v", err)
	}
	for _, item := range defaultList.Applications {
		if item.ID == appA.ID {
			t.Fatal("默认应用列表不应包含已逻辑删除应用")
		}
	}
	allList, err := env.service.ListApplications(ctx, env.system,
		app.ListRequest{Limit: 100, IncludeDeleted: true})
	if err != nil {
		t.Fatalf("包含已删除列表: %v", err)
	}
	foundDeleted := false
	for _, item := range allList.Applications {
		if item.ID == appA.ID && item.Deleted() {
			foundDeleted = true
		}
	}
	if !foundDeleted {
		t.Fatal("IncludeDeleted 列表缺少已逻辑删除应用")
	}
	// 其他应用与共享账户不受损。
	gotB, err := env.service.GetApplication(ctx, env.system, appB.ID)
	if err != nil || gotB.Deleted() || gotB.Status != app.StatusDisabled {
		t.Fatalf("其他应用受影响 = %+v err=%v", gotB, err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM users`) != usersBefore {
		t.Fatal("删除应用不应删除共享账户")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE id='audit_delete_fixture'`); value != 1 {
		t.Fatal("逻辑删除不应删除安全审计事件")
	}
	// 逻辑删除后按消费者判定口径已不可用（应用不再是 active）。
	if value := env.queryInt(`SELECT COUNT(*) FROM applications WHERE id=? AND status='active'`, appA.ID); value != 0 {
		t.Fatal("逻辑删除后应用仍被判定为 active")
	}
	// 物理清理：受控通道限制（普通用户调用被拒绝）；保留期满足后清理成功。
	if _, err := env.service.PurgeApplication(ctx, env.userCaller(testOwnerOne),
		app.PurgeRequest{ApplicationID: appA.ID}); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("普通用户物理清理错误 = %v，期望 ErrAccessDenied", err)
	}
	env.clock.Advance(time.Millisecond)
	purged, err := env.service.PurgeApplication(ctx, env.system,
		app.PurgeRequest{ApplicationID: appA.ID})
	if err != nil || !purged.Changed {
		t.Fatalf("物理清理 = %+v err=%v", purged, err)
	}
	if _, err := env.service.GetApplication(ctx, env.system, appA.ID); !errors.Is(err, app.ErrApplicationNotFound) {
		t.Fatalf("物理清理后应用应不存在: %v", err)
	}
	// 级联清理应用关联数据，但保留共享账户、审计与其他应用。
	for _, query := range []string{
		`SELECT COUNT(*) FROM scopes WHERE app_id=?`,
		`SELECT COUNT(*) FROM app_memberships WHERE app_id=?`,
		`SELECT COUNT(*) FROM roles WHERE scope_id=?`,
		`SELECT COUNT(*) FROM permissions WHERE scope_id=?`,
		`SELECT COUNT(*) FROM user_groups WHERE scope_id=?`,
		`SELECT COUNT(*) FROM sessions WHERE app_id=?`,
		`SELECT COUNT(*) FROM oauth_clients WHERE client_id=?`,
		`SELECT COUNT(*) FROM refresh_token_families WHERE client_id=?`,
	} {
		if value := env.queryInt(query, appA.ID); value != 0 {
			t.Fatalf("物理清理残留数据 %q = %d", query, value)
		}
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE id='audit_delete_fixture'`); value != 1 {
		t.Fatal("物理清理不应删除安全审计事件")
	}
	if env.queryInt(`SELECT COUNT(*) FROM users`) != usersBefore {
		t.Fatal("物理清理不应删除共享账户")
	}
	if _, err := env.service.GetApplication(ctx, env.system, appB.ID); err != nil {
		t.Fatalf("物理清理其他应用受影响: %v", err)
	}
	// 物理清理重试幂等：目标已不存在按未变更成功（并留审计）。
	retry, err := env.service.PurgeApplication(ctx, env.system,
		app.PurgeRequest{ApplicationID: appA.ID})
	if err != nil || retry.Changed {
		t.Fatalf("物理清理重试 = %+v err=%v（期望幂等未变更）", retry, err)
	}
}

// TestApplicationPurgeRetentionEnforced 验证默认保留期内不允许物理清理，且未逻辑
// 删除的应用不能直接清理。
func TestApplicationPurgeRetentionEnforced(t *testing.T) {
	env := prepareEnv(t) // 默认 30 天保留期
	ctx := context.Background()
	application := env.createApp(validCreateRequest(app.ClientTypePublic))
	if _, err := env.service.PurgeApplication(ctx, env.system,
		app.PurgeRequest{ApplicationID: application.ID}); !errors.Is(err, app.ErrInvalidTransition) {
		t.Fatalf("未删除应用物理清理错误 = %v，期望 ErrInvalidTransition", err)
	}
	disabled, err := env.service.DisableApplication(ctx, env.system, app.StatusRequest{
		ApplicationID: application.ID, ExpectedRowVersion: application.RowVersion})
	if err != nil {
		t.Fatalf("停用应用: %v", err)
	}
	deleted, err := env.service.DeleteApplication(ctx, env.system, app.DeletionRequest{
		ApplicationID: application.ID, ExpectedRowVersion: disabled.Application.RowVersion})
	if err != nil || !deleted.Changed {
		t.Fatalf("逻辑删除: %v", err)
	}
	if _, err := env.service.PurgeApplication(ctx, env.system,
		app.PurgeRequest{ApplicationID: application.ID}); !errors.Is(err, app.ErrInvalidTransition) {
		t.Fatalf("保留期内物理清理错误 = %v，期望 ErrInvalidTransition", err)
	}
	// 保留期过后（时钟推进 31 天）允许清理。
	env.clock.Advance(31 * 24 * time.Hour)
	if _, err := env.service.PurgeApplication(ctx, env.system,
		app.PurgeRequest{ApplicationID: application.ID}); err != nil {
		t.Fatalf("保留期后物理清理: %v", err)
	}
}
