package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// 本文件覆盖步骤 21：应用成员管理与应用内资料隔离。
// 安全重点：应用成员关系按应用隔离、加入既有账户必须受控授权、应用内状态/资料
// 不修改全局账户或其他应用、关键变更与审计一致、并发重复加入/移除不产生半状态。

// enableApp 用系统操作者启用应用，返回启用后的快照。
func (e *testEnv) enableApp(application app.Application) app.Application {
	e.t.Helper()
	result, err := e.service.EnableApplication(context.Background(), e.system, app.StatusRequest{
		ApplicationID:      application.ID,
		ExpectedRowVersion: application.RowVersion,
	})
	if err != nil {
		e.t.Fatalf("启用应用失败: %v", err)
	}
	return result.Application
}

// newActiveApp 创建并启用一个应用。
func (e *testEnv) newActiveApp() app.Application {
	e.t.Helper()
	return e.enableApp(e.createApp(validCreateRequest(app.ClientTypeConfidential)))
}

// addMember 用系统操作者把用户加入应用，返回成员快照。
func (e *testEnv) addMember(applicationID, userID string, profile app.MemberProfile) app.Membership {
	e.t.Helper()
	membership, err := e.service.AddApplicationMember(context.Background(), e.system, app.AddMemberRequest{
		ApplicationID: applicationID,
		UserID:        userID,
		Profile:       profile,
	})
	if err != nil {
		e.t.Fatalf("加入应用成员失败: %v", err)
	}
	return membership
}

// insertUserWithStatus 直接插入指定全局状态的账户，用于成员资格边界测试。
func (e *testEnv) insertUserWithStatus(userID, username, status string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai',?,0,1,1,?,?)`,
		userID, username, username, status, now, now); err != nil {
		e.t.Fatalf("插入测试用户失败: %v", err)
	}
}

// setUserStatus 直接更新全局账户状态，模拟账户停用/待删除。
func (e *testEnv) setUserStatus(userID, status string) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(context.Background(),
		`UPDATE users SET status=? WHERE id=?`, status, userID); err != nil {
		e.t.Fatalf("更新测试用户状态失败: %v", err)
	}
}

// appAdminCaller 显式分配应用管理员并返回用户调用者。
func (e *testEnv) appAdminCaller(applicationID, userID string) app.Caller {
	e.t.Helper()
	if err := e.authorizer.AssignApplicationAdmin(applicationID, userID); err != nil {
		e.t.Fatalf("分配应用管理员失败: %v", err)
	}
	return e.userCaller(userID)
}

// localAdminCaller 返回受限本地管理员调用者（authorizer 已配置 operator-1）。
func (e *testEnv) localAdminCaller() app.Caller {
	e.t.Helper()
	caller, err := app.LocalBootstrapCaller("operator-1")
	if err != nil {
		e.t.Fatalf("构造本地管理员调用者失败: %v", err)
	}
	return caller
}

// memberRowCount 返回指定应用的成员行数。
func (e *testEnv) memberRowCount(applicationID string) int {
	e.t.Helper()
	return e.queryInt(`SELECT COUNT(*) FROM app_memberships WHERE app_id=?`, applicationID)
}

// auditCount 统计指定动作/结果（可选应用与错误码）的审计事件数量。
func (e *testEnv) auditCount(action, outcome, applicationID string) int {
	e.t.Helper()
	if applicationID == "" {
		return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=?`, action, outcome)
	}
	return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=? AND app_id_snapshot=?`,
		action, outcome, applicationID)
}

// getMember 读取成员关系。
func (e *testEnv) getMember(applicationID, userID string) (app.Membership, error) {
	e.t.Helper()
	return e.service.GetApplicationMember(context.Background(), e.system, applicationID, userID)
}

// TestApplicationMemberProfileIsolationAcrossApps 验证同一用户在两个应用中的成员
// 关系与资料互不影响，且不写全局资料。
func TestApplicationMemberProfileIsolationAcrossApps(t *testing.T) {
	env := prepareEnv(t)
	appA := env.newActiveApp()
	appB := env.newActiveApp()
	user := testOwnerOne

	profileA := app.MemberProfile{DisplayName: "应用A成员名", Title: "审批人", Note: "A备注"}
	profileB := app.MemberProfile{DisplayName: "应用B成员名", Title: "运营", Note: "B备注"}
	memberA := env.addMember(appA.ID, user, profileA)
	memberB := env.addMember(appB.ID, user, profileB)

	if memberA.ApplicationID != appA.ID || memberA.Status != app.MembershipActive || memberA.RowVersion != 1 {
		t.Fatalf("应用A成员快照 = %+v", memberA)
	}
	if memberB.ApplicationID != appB.ID || memberB.Profile != profileB {
		t.Fatalf("应用B成员快照 = %+v", memberB)
	}
	if memberA.Profile != profileA || memberB.Profile != profileB {
		t.Fatalf("应用专属资料串写：A=%+v B=%+v", memberA.Profile, memberB.Profile)
	}

	// 在应用A更新资料：只允许写A的 profile_json 与 row_version。
	updatedA, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system,
		app.MemberProfileRequest{
			ApplicationID:      appA.ID,
			UserID:             user,
			Profile:            app.MemberProfile{DisplayName: "A新名字"},
			ExpectedRowVersion: memberA.RowVersion,
		})
	if err != nil {
		t.Fatalf("更新应用A成员资料失败: %v", err)
	}
	if updatedA.RowVersion != 2 || updatedA.Profile.DisplayName != "A新名字" || updatedA.Profile.Title != "" {
		t.Fatalf("应用A更新后快照 = %+v", updatedA)
	}
	reloadedA, err := env.getMember(appA.ID, user)
	if err != nil || reloadedA.Profile.DisplayName != "A新名字" {
		t.Fatalf("重新读取应用A = %+v err=%v", reloadedA, err)
	}
	reloadedB, err := env.getMember(appB.ID, user)
	if err != nil {
		t.Fatalf("读取应用B失败: %v", err)
	}
	if reloadedB.Profile != profileB || reloadedB.RowVersion != memberB.RowVersion {
		t.Fatalf("应用A更新影响了应用B：%+v", reloadedB)
	}

	// 全局账户资料与状态不得被应用成员资料改动。
	if nickname := env.queryString(`SELECT nickname FROM users WHERE id=?`, user); nickname != "" {
		t.Fatalf("全局昵称被成员操作修改：%q", nickname)
	}
	if status := env.queryString(`SELECT status FROM users WHERE id=?`, user); status != "active" {
		t.Fatalf("全局状态被成员操作修改：%q", status)
	}
	if version := env.queryInt(`SELECT row_version FROM users WHERE id=?`, user); version != 1 {
		t.Fatalf("全局行版本被成员操作修改：%d", version)
	}

	// 两个应用的 profile_json 各自独立持久化。
	if value := env.queryString(`SELECT profile_json FROM app_memberships WHERE app_id=? AND user_id=?`, appA.ID, user); !strings.Contains(value, "A新名字") || strings.Contains(value, "应用B成员名") {
		t.Fatalf("应用A profile_json = %q", value)
	}
	if value := env.queryString(`SELECT profile_json FROM app_memberships WHERE app_id=? AND user_id=?`, appB.ID, user); !strings.Contains(value, "应用B成员名") {
		t.Fatalf("应用B profile_json = %q", value)
	}

	// 移除应用A成员关系后，应用B成员关系与全局账户保持。
	if err := env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: reloadedA.RowVersion,
	}); err != nil {
		t.Fatalf("移除应用A成员失败: %v", err)
	}
	if env.memberRowCount(appA.ID) != 0 || env.memberRowCount(appB.ID) != 1 {
		t.Fatalf("移除应用A后成员行数 = A:%d B:%d", env.memberRowCount(appA.ID), env.memberRowCount(appB.ID))
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user); value != "active" {
		t.Fatalf("移除应用成员改变了全局账户状态：%q", value)
	}
}

// TestApplicationMemberAuthorizationByAppScope 验证所有成员操作都按应用分配授权，
// 不能跨应用读写，也不能用请求参数扩大范围。
func TestApplicationMemberAuthorizationByAppScope(t *testing.T) {
	env := prepareEnv(t)
	appA := env.newActiveApp()
	appB := env.newActiveApp()
	memberA := env.addMember(appA.ID, testOwnerOne, app.MemberProfile{})
	_ = env.addMember(appB.ID, testOwnerOne, app.MemberProfile{})
	adminA := env.appAdminCaller(appA.ID, testAppAdmin)

	// 应用A管理员可以完成本应用成员全生命周期操作。
	if _, err := env.service.GetApplicationMember(context.Background(), adminA, appA.ID, memberA.UserID); err != nil {
		t.Fatalf("应用A管理员读取本应用成员失败: %v", err)
	}
	listResult, err := env.service.ListApplicationMembers(context.Background(), adminA, app.MemberListRequest{ApplicationID: appA.ID})
	if err != nil || len(listResult.Members) != 1 || listResult.Members[0].ApplicationID != appA.ID {
		t.Fatalf("应用A管理员列表 = %+v err=%v", listResult, err)
	}
	updated, err := env.service.UpdateApplicationMemberProfile(context.Background(), adminA, app.MemberProfileRequest{
		ApplicationID: appA.ID, UserID: memberA.UserID,
		Profile: app.MemberProfile{DisplayName: "管理员改名"}, ExpectedRowVersion: memberA.RowVersion,
	})
	if err != nil || updated.Profile.DisplayName != "管理员改名" {
		t.Fatalf("应用A管理员更新资料 = %+v err=%v", updated, err)
	}
	disabled, err := env.service.DisableApplicationMember(context.Background(), adminA, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: memberA.UserID, ExpectedRowVersion: updated.RowVersion,
	})
	if err != nil || !disabled.Changed || disabled.Membership.Status != app.MembershipDisabled {
		t.Fatalf("应用A管理员停用成员 = %+v err=%v", disabled, err)
	}
	if _, err := env.service.EnableApplicationMember(context.Background(), adminA, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: memberA.UserID, ExpectedRowVersion: disabled.Membership.RowVersion,
	}); err != nil {
		t.Fatalf("应用A管理员启用成员失败: %v", err)
	}
	if err := env.service.RemoveApplicationMember(context.Background(), adminA, app.RemoveMemberRequest{
		ApplicationID: appA.ID, UserID: memberA.UserID, ExpectedRowVersion: disabled.Membership.RowVersion + 1,
	}); err != nil {
		t.Fatalf("应用A管理员移除成员失败: %v", err)
	}

	// 应用A管理员读取/操作应用B成员全部拒绝，且错误为 ACCESS_DENIED。
	cases := []struct {
		name string
		run  func() error
	}{
		{name: "读取B成员", run: func() error {
			_, err := env.service.GetApplicationMember(context.Background(), adminA, appB.ID, testOwnerOne)
			return err
		}},
		{name: "列表B成员", run: func() error {
			_, err := env.service.ListApplicationMembers(context.Background(), adminA, app.MemberListRequest{ApplicationID: appB.ID})
			return err
		}},
		{name: "加入B成员", run: func() error {
			_, err := env.service.AddApplicationMember(context.Background(), adminA, app.AddMemberRequest{
				ApplicationID: appB.ID, UserID: testOwnerTwo,
			})
			return err
		}},
		{name: "更新B成员资料", run: func() error {
			_, err := env.service.UpdateApplicationMemberProfile(context.Background(), adminA, app.MemberProfileRequest{
				ApplicationID: appB.ID, UserID: testOwnerOne, ExpectedRowVersion: 1,
			})
			return err
		}},
		{name: "停用B成员", run: func() error {
			_, err := env.service.DisableApplicationMember(context.Background(), adminA, app.MemberStatusRequest{
				ApplicationID: appB.ID, UserID: testOwnerOne, ExpectedRowVersion: 1,
			})
			return err
		}},
		{name: "移除B成员", run: func() error {
			return env.service.RemoveApplicationMember(context.Background(), adminA, app.RemoveMemberRequest{
				ApplicationID: appB.ID, UserID: testOwnerOne, ExpectedRowVersion: 1,
			})
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, app.ErrAccessDenied) {
				t.Fatalf("跨应用操作错误 = %v，期望 ErrAccessDenied", err)
			}
		})
	}

	// 未分配任何应用的用户无法读取/加入任何应用。
	unrelated := env.userCaller(testOwnerTwo)
	if _, err := env.service.ListApplicationMembers(context.Background(), unrelated, app.MemberListRequest{ApplicationID: appA.ID}); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("无关用户列表错误 = %v", err)
	}
	if _, err := env.service.AddApplicationMember(context.Background(), unrelated, app.AddMemberRequest{
		ApplicationID: appA.ID, UserID: testOwnerOne,
	}); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("无关用户加入错误 = %v", err)
	}

	// 本地管理员可管理全部应用成员。
	localAdmin := env.localAdminCaller()
	if _, err := env.service.AddApplicationMember(context.Background(), localAdmin, app.AddMemberRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, Profile: app.MemberProfile{Title: "本地管理员加入"},
	}); err != nil {
		t.Fatalf("本地管理员加入成员失败: %v", err)
	}
	if _, err := env.service.ListApplicationMembers(context.Background(), localAdmin, app.MemberListRequest{ApplicationID: appB.ID}); err != nil {
		t.Fatalf("本地管理员列表失败: %v", err)
	}
}

// TestApplicationMemberControlledAssociation 验证加入既有账户必须满足受控条件：
// 应用启用、账户存在且 active、且调用者已获该应用授权；重复加入不覆盖资料。
func TestApplicationMemberControlledAssociation(t *testing.T) {
	env := prepareEnv(t)
	disabledApp := env.createApp(validCreateRequest(app.ClientTypeConfidential))
	env.insertUserWithStatus("usr_00000000000000000000000000000010", "disableduser", "disabled")
	env.insertUserWithStatus("usr_00000000000000000000000000000011", "deleteduser", "pending_delete")

	// 停用应用不能加入成员（即使调用者是系统操作者）。
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: disabledApp.ID, UserID: testOwnerOne,
	}); !errors.Is(err, app.ErrApplicationInactive) {
		t.Fatalf("停用应用加入成员错误 = %v，期望 ErrApplicationInactive", err)
	}
	activeApp := env.enableApp(disabledApp)

	// 不存在的用户。
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: activeApp.ID, UserID: "usr_ffffffffffffffffffffffffffffffff",
	}); !errors.Is(err, app.ErrTargetUserNotFound) {
		t.Fatalf("不存在用户加入错误 = %v", err)
	}
	// 全局禁用/待删除账户不能加入。
	for _, userID := range []string{"usr_00000000000000000000000000000010", "usr_00000000000000000000000000000011"} {
		if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
			ApplicationID: activeApp.ID, UserID: userID,
		}); !errors.Is(err, app.ErrUserNotEligible) {
			t.Fatalf("非 active 用户 %s 加入错误 = %v", userID, err)
		}
	}

	// 受控加入成功；重复加入返回 CONFLICT 且不覆盖首次资料。
	first := env.addMember(activeApp.ID, testOwnerOne, app.MemberProfile{DisplayName: "首次资料"})
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: activeApp.ID, UserID: testOwnerOne,
		Profile: app.MemberProfile{DisplayName: "覆盖尝试"},
	}); !errors.Is(err, app.ErrMemberExists) {
		t.Fatalf("重复加入错误 = %v，期望 ErrMemberExists", err)
	}
	stored, err := env.getMember(activeApp.ID, testOwnerOne)
	if err != nil || stored.Profile.DisplayName != "首次资料" || stored.RowVersion != first.RowVersion {
		t.Fatalf("重复加入覆盖了资料：%+v err=%v", stored, err)
	}
	if rows := env.memberRowCount(activeApp.ID); rows != 1 {
		t.Fatalf("重复加入后成员行数 = %d", rows)
	}

	// 重复加入失败审计使用 CONFLICT。
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.member.add' AND outcome='failure' AND error_code='CONFLICT'`); count != 1 {
		t.Errorf("重复加入失败审计 error_code=CONFLICT 数量 = %d", count)
	}
}

// insertRootUser 直接插入 is_root=1 的 root 账户，用于应用成员 root 保护回归。
func (e *testEnv) insertRootUser(userID, username string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		userID, username, username, now, now); err != nil {
		e.t.Fatalf("插入 root 测试用户失败: %v", err)
	}
}

// TestApplicationMemberRejectsRoot 验证 root 账户不能成为应用成员：root 能力只走
// 受保护本地通道，普通应用管理员不能通过成员关系给 root 建立业务资格。拒绝保持
// 既有 USER_DISABLED 语义、不落成员行，并写一条失败审计。
func TestApplicationMemberRejectsRoot(t *testing.T) {
	env := prepareEnv(t)
	application := env.newActiveApp()
	rootID := "usr_11111111111111111111111111111111"
	env.insertRootUser(rootID, "root")

	_, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: application.ID, UserID: rootID,
	})
	if !errors.Is(err, app.ErrUserNotEligible) {
		t.Fatalf("root 加入应用成员错误 = %v，期望 ErrUserNotEligible", err)
	}
	if code := app.CodeOf(err); code != app.CodeUserDisabled {
		t.Errorf("root 成员拒绝错误码 = %q，期望 USER_DISABLED", code)
	}
	if rows := env.memberRowCount(application.ID); rows != 0 {
		t.Errorf("root 加入后成员行数 = %d，期望 0", rows)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action=? AND outcome='failure' AND error_code='USER_DISABLED' AND reason_code='root_protected'`,
		string(app.ActionAddApplicationMember)); count != 1 {
		t.Errorf("root 成员拒绝失败审计数 = %d，期望 1", count)
	}
	// 重新启用路径同样拒绝 root（若存在遗留成员行也不能恢复为 active）。
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'disabled','{"v":1}',1,?,?)`,
		application.ID, rootID, env.clock.Now().UnixMilli(), env.clock.Now().UnixMilli()); err != nil {
		t.Fatalf("插入遗留 root 成员行失败: %v", err)
	}
	if _, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: application.ID, UserID: rootID, ExpectedRowVersion: 1,
	}); !errors.Is(err, app.ErrUserNotEligible) {
		t.Fatalf("root 成员重新启用错误 = %v，期望 ErrUserNotEligible", err)
	}
	if rows := env.queryInt(`SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=? AND status='active'`,
		application.ID, rootID); rows != 0 {
		t.Errorf("root 成员被重新启用，活跃行数 = %d", rows)
	}
}

// TestApplicationMemberStatusAndRemovalScope 验证应用内启停/移除的隔离与状态检查。
func TestApplicationMemberStatusAndRemovalScope(t *testing.T) {
	env := prepareEnv(t)
	appA := env.newActiveApp()
	appB := env.newActiveApp()
	user := testOwnerOne
	memberA := env.addMember(appA.ID, user, app.MemberProfile{})
	env.addMember(appB.ID, user, app.MemberProfile{})

	// 停用应用A成员：只影响A，B与全局账户不受影响。
	disabled, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: memberA.RowVersion,
	})
	if err != nil || !disabled.Changed || disabled.Membership.Status != app.MembershipDisabled {
		t.Fatalf("停用A成员 = %+v err=%v", disabled, err)
	}
	if stored, _ := env.getMember(appB.ID, user); stored.Status != app.MembershipActive {
		t.Fatalf("停用A成员影响B：%+v", stored)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user); value != "active" {
		t.Fatalf("停用应用成员改变全局账户状态：%q", value)
	}
	// 重复停用幂等成功，不改版本。
	repeated, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: disabled.Membership.RowVersion,
	})
	if err != nil || repeated.Changed || repeated.Membership.RowVersion != disabled.Membership.RowVersion {
		t.Fatalf("重复停用 = %+v err=%v", repeated, err)
	}
	// 启用恢复。
	enabled, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: disabled.Membership.RowVersion,
	})
	if err != nil || !enabled.Changed || enabled.Membership.Status != app.MembershipActive {
		t.Fatalf("启用A成员 = %+v err=%v", enabled, err)
	}

	// 停用应用本身后：加入/启用/资料更新拒绝，停用/移除仍允许。
	appAStatus, err := env.service.GetApplication(context.Background(), env.system, appA.ID)
	if err != nil {
		t.Fatalf("读取应用A失败: %v", err)
	}
	if _, err := env.service.DisableApplication(context.Background(), env.system, app.StatusRequest{
		ApplicationID: appA.ID, ExpectedRowVersion: appAStatus.RowVersion,
	}); err != nil {
		t.Fatalf("停用应用A失败: %v", err)
	}
	env.insertUserWithStatus("usr_00000000000000000000000000000012", "newmember", "active")
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: appA.ID, UserID: "usr_00000000000000000000000000000012",
	}); !errors.Is(err, app.ErrApplicationInactive) {
		t.Fatalf("停用应用加入成员错误 = %v", err)
	}
	if _, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
		ApplicationID: appA.ID, UserID: user, Profile: app.MemberProfile{DisplayName: "x"}, ExpectedRowVersion: enabled.Membership.RowVersion,
	}); !errors.Is(err, app.ErrApplicationInactive) {
		t.Fatalf("停用应用更新成员资料错误 = %v", err)
	}
	disabledOnDisabledApp, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: enabled.Membership.RowVersion,
	})
	if err != nil {
		t.Fatalf("停用应用时仍应允许停用成员: %v", err)
	}
	if _, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appA.ID, UserID: user, ExpectedRowVersion: disabledOnDisabledApp.Membership.RowVersion,
	}); !errors.Is(err, app.ErrApplicationInactive) {
		t.Fatalf("停用应用中启用成员错误 = %v", err)
	}
	appAMembers, err := env.service.ListApplicationMembers(context.Background(), env.system, app.MemberListRequest{ApplicationID: appA.ID})
	if err != nil || len(appAMembers.Members) != 1 {
		t.Fatalf("停用应用后仍应可读取成员列表: %+v err=%v", appAMembers, err)
	}

	// 全局账户禁用后：启用/资料更新/加入拒绝，停用/移除仍允许。
	env.setUserStatus(testOwnerTwo, "disabled")
	disabledMemberB := env.addMemberForTestSetup(t, appB, testOwnerTwo)
	// 已是 active 的幂等启用不改状态，允许返回未变更；真正的 disabled->active
	// 转换必须要求全局账户 active。
	idempotentEnable, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, ExpectedRowVersion: disabledMemberB.RowVersion,
	})
	if err != nil || idempotentEnable.Changed {
		t.Fatalf("已 active 成员的幂等启用 = %+v err=%v", idempotentEnable, err)
	}
	disabledForUser, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, ExpectedRowVersion: idempotentEnable.Membership.RowVersion,
	})
	if err != nil {
		t.Fatalf("全局禁用时仍应允许停用成员: %v", err)
	}
	if _, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, ExpectedRowVersion: disabledForUser.Membership.RowVersion,
	}); !errors.Is(err, app.ErrUserNotEligible) {
		t.Fatalf("全局禁用用户启用成员错误 = %v", err)
	}
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo,
	}); !errors.Is(err, app.ErrUserNotEligible) {
		t.Fatalf("全局禁用用户加入错误 = %v", err)
	}
	if _, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, Profile: app.MemberProfile{Title: "x"}, ExpectedRowVersion: disabledForUser.Membership.RowVersion,
	}); !errors.Is(err, app.ErrUserNotEligible) {
		t.Fatalf("全局禁用用户资料更新错误 = %v", err)
	}

	// 移除不存在成员 / 版本冲突。
	if err := env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
		ApplicationID: appA.ID, UserID: testOwnerTwo, ExpectedRowVersion: 1,
	}); !errors.Is(err, app.ErrMemberNotFound) {
		t.Fatalf("移除非成员错误 = %v", err)
	}
	currentB, err := env.getMember(appB.ID, testOwnerTwo)
	if err != nil {
		t.Fatalf("读取B成员失败: %v", err)
	}
	if err := env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
		ApplicationID: appB.ID, UserID: testOwnerTwo, ExpectedRowVersion: currentB.RowVersion + 1,
	}); !errors.Is(err, app.ErrStateConflict) {
		t.Fatalf("过期版本移除错误 = %v", err)
	}
	if _, err := env.getMember(appB.ID, testOwnerTwo); err != nil {
		t.Fatalf("冲突移除不应删除成员: %v", err)
	}
}

// addMemberForTestSetup 在测试环境直接建立成员关系（绕过全局用户状态检查，仅用于
// 构造“成员已存在但全局账户被禁用”的场景）。
func (e *testEnv) addMemberForTestSetup(t *testing.T, application app.Application, userID string) app.Membership {
	t.Helper()
	// 先临时恢复账户状态完成加入，再按测试需要禁用账户。
	currentStatus := e.queryString(`SELECT status FROM users WHERE id=?`, userID)
	if currentStatus != "active" {
		e.setUserStatus(userID, "active")
	}
	membership := e.addMember(application.ID, userID, app.MemberProfile{})
	if currentStatus != "active" {
		e.setUserStatus(userID, currentStatus)
	}
	return membership
}

// TestApplicationMemberConcurrency 验证并发重复加入、并发启用、并发移除与并发资料
// 更新只产生一个成功终态，且成功/失败审计与最终状态一致。
func TestApplicationMemberConcurrency(t *testing.T) {
	env := prepareEnv(t)
	application := env.newActiveApp()
	user := testOwnerOne

	const workers = 4
	// 并发加入：1 成功，其余 CONFLICT。
	type addResult struct {
		membership app.Membership
		err        error
	}
	addResults := make(chan addResult, workers)
	var addWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		addWG.Add(1)
		go func() {
			defer addWG.Done()
			membership, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
				ApplicationID: application.ID, UserID: user,
				Profile: app.MemberProfile{DisplayName: "并发加入"},
			})
			addResults <- addResult{membership: membership, err: err}
		}()
	}
	addWG.Wait()
	close(addResults)
	successes, conflicts := 0, 0
	for result := range addResults {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, app.ErrMemberExists), errors.Is(result.err, app.ErrStateConflict):
			conflicts++
		default:
			t.Fatalf("并发加入意外错误 = %v", result.err)
		}
	}
	if successes != 1 || conflicts != workers-1 {
		t.Fatalf("并发加入结果 = 成功%d 冲突%d", successes, conflicts)
	}
	if env.memberRowCount(application.ID) != 1 {
		t.Fatalf("并发加入后成员行数 = %d", env.memberRowCount(application.ID))
	}
	if count := env.auditCount("application.member.add", "success", application.ID); count != 1 {
		t.Fatalf("并发加入成功审计数量 = %d", count)
	}
	if count := env.auditCount("application.member.add", "failure", application.ID); count != workers-1 {
		t.Fatalf("并发加入失败审计数量 = %d", count)
	}

	current, err := env.getMember(application.ID, user)
	if err != nil {
		t.Fatalf("读取成员失败: %v", err)
	}

	// 并发资料更新：1 成功，其余 CONFLICT；最终版本 +1。
	updateResults := make(chan error, workers)
	var updateWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		updateWG.Add(1)
		go func(index int) {
			defer updateWG.Done()
			_, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
				ApplicationID: application.ID, UserID: user,
				Profile:            app.MemberProfile{DisplayName: fmt.Sprintf("并发更新-%d", index)},
				ExpectedRowVersion: current.RowVersion,
			})
			updateResults <- err
		}(index)
	}
	updateWG.Wait()
	close(updateResults)
	updateSuccesses, updateConflicts := 0, 0
	for err := range updateResults {
		switch {
		case err == nil:
			updateSuccesses++
		case errors.Is(err, app.ErrStateConflict):
			updateConflicts++
		default:
			t.Fatalf("并发更新意外错误 = %v", err)
		}
	}
	if updateSuccesses != 1 || updateConflicts != workers-1 {
		t.Fatalf("并发更新结果 = 成功%d 冲突%d", updateSuccesses, updateConflicts)
	}
	afterUpdate, err := env.getMember(application.ID, user)
	if err != nil || afterUpdate.RowVersion != current.RowVersion+1 {
		t.Fatalf("并发更新后版本 = %d err=%v", afterUpdate.RowVersion, err)
	}

	// 并发启用（成员当前 active）：幂等成功，不错误地产生多次实际变更。
	enableResults := make(chan app.MemberStatusResult, workers)
	var enableWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		enableWG.Add(1)
		go func() {
			defer enableWG.Done()
			result, err := env.service.EnableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
				ApplicationID: application.ID, UserID: user, ExpectedRowVersion: afterUpdate.RowVersion,
			})
			if err != nil {
				t.Errorf("并发启用意外错误: %v", err)
			}
			enableResults <- result
		}()
	}
	enableWG.Wait()
	close(enableResults)
	changedCount := 0
	for result := range enableResults {
		if result.Changed {
			changedCount++
		}
	}
	if changedCount != 0 {
		t.Fatalf("已 active 成员并发启用 Changed 次数 = %d", changedCount)
	}

	// 并发移除：1 成功，其余 CONFLICT；最终无成员行，只有 1 条成功移除审计。
	final, err := env.getMember(application.ID, user)
	if err != nil {
		t.Fatalf("读取最终成员失败: %v", err)
	}
	removeResults := make(chan error, workers)
	var removeWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		removeWG.Add(1)
		go func() {
			defer removeWG.Done()
			removeResults <- env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
				ApplicationID: application.ID, UserID: user, ExpectedRowVersion: final.RowVersion,
			})
		}()
	}
	removeWG.Wait()
	close(removeResults)
	removeSuccesses, removeConflicts := 0, 0
	for err := range removeResults {
		switch {
		case err == nil:
			removeSuccesses++
		case errors.Is(err, app.ErrStateConflict), errors.Is(err, app.ErrMemberNotFound):
			// 并发移除中读取先后不同：读到旧行后条件删除失败为 CONFLICT，读到已
			// 删除的成员则为 NOT_FOUND；两者都不改变最终一致状态。
			removeConflicts++
		default:
			t.Fatalf("并发移除意外错误 = %v", err)
		}
	}
	if removeSuccesses != 1 || removeConflicts != workers-1 {
		t.Fatalf("并发移除结果 = 成功%d 冲突%d", removeSuccesses, removeConflicts)
	}
	if env.memberRowCount(application.ID) != 0 {
		t.Fatalf("并发移除后成员行数 = %d", env.memberRowCount(application.ID))
	}
	if count := env.auditCount("application.member.remove", "success", application.ID); count != 1 {
		t.Fatalf("并发移除成功审计数量 = %d", count)
	}
	if _, err := env.getMember(application.ID, user); !errors.Is(err, app.ErrMemberNotFound) {
		t.Fatalf("移除后读取成员错误 = %v", err)
	}
}

// TestApplicationMemberValidationBoundaries 验证成员请求、资料字段与分页边界。
func TestApplicationMemberValidationBoundaries(t *testing.T) {
	env := prepareEnv(t)
	application := env.newActiveApp()
	member := env.addMember(application.ID, testOwnerOne, app.MemberProfile{})
	user := testOwnerOne

	// 非法应用/用户 ID 与版本。
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: "not-an-app", UserID: user,
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("非法应用 ID 错误 = %v", err)
	}
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: application.ID, UserID: "not-a-user",
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 错误 = %v", err)
	}
	if _, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
		ApplicationID: application.ID, UserID: user, ExpectedRowVersion: 0,
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("零版本更新错误 = %v", err)
	}
	if _, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: application.ID, UserID: user, ExpectedRowVersion: -1,
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("负版本启停错误 = %v", err)
	}
	if err := env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
		ApplicationID: application.ID, UserID: user, ExpectedRowVersion: 0,
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("零版本移除错误 = %v", err)
	}

	// 应用/成员不存在。
	missingAppID := "app_ffffffffffffffffffffffffffffffff"
	if _, err := env.service.ListApplicationMembers(context.Background(), env.system, app.MemberListRequest{ApplicationID: missingAppID}); !errors.Is(err, app.ErrApplicationNotFound) {
		t.Fatalf("不存在应用列表错误 = %v", err)
	}
	if _, err := env.service.GetApplicationMember(context.Background(), env.system, application.ID,
		"usr_ffffffffffffffffffffffffffffffff"); !errors.Is(err, app.ErrMemberNotFound) {
		t.Fatalf("不存在成员读取错误 = %v", err)
	}
	if _, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
		ApplicationID: application.ID, UserID: "usr_ffffffffffffffffffffffffffffffff", ExpectedRowVersion: 1,
	}); !errors.Is(err, app.ErrMemberNotFound) {
		t.Fatalf("不存在成员更新错误 = %v", err)
	}
	if _, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: application.ID, UserID: "usr_ffffffffffffffffffffffffffffffff", ExpectedRowVersion: 1,
	}); !errors.Is(err, app.ErrMemberNotFound) {
		t.Fatalf("不存在成员启停错误 = %v", err)
	}

	// 资料字段边界。
	invalidProfiles := []struct {
		name    string
		profile app.MemberProfile
	}{
		{name: "显示名过长", profile: app.MemberProfile{DisplayName: strings.Repeat("名", app.MaxMemberDisplayNameRunes+1)}},
		{name: "职位含控制字符", profile: app.MemberProfile{Title: "bad\x00title"}},
		{name: "职位含换行", profile: app.MemberProfile{Title: "line1\nline2"}},
		{name: "备注过长", profile: app.MemberProfile{Note: strings.Repeat("备", app.MaxMemberNoteRunes+1)}},
		{name: "备注含控制字符", profile: app.MemberProfile{Note: "bad\x01note"}},
		{name: "显示名含格式字符", profile: app.MemberProfile{DisplayName: "bad\u202e显示"}},
	}
	for _, test := range invalidProfiles {
		t.Run(test.name, func(t *testing.T) {
			_, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
				ApplicationID: application.ID, UserID: user, Profile: test.profile,
				ExpectedRowVersion: member.RowVersion,
			})
			if !errors.Is(err, app.ErrInvalidRequest) {
				t.Fatalf("非法资料错误 = %v，期望 ErrInvalidRequest", err)
			}
			current, getErr := env.getMember(application.ID, user)
			if getErr != nil || current.RowVersion != member.RowVersion {
				t.Fatalf("非法资料更新不应改动成员：%+v err=%v", current, getErr)
			}
		})
	}

	// 列表分页/排序/状态边界。
	listCases := []struct {
		name    string
		request app.MemberListRequest
	}{
		{name: "每页过多", request: app.MemberListRequest{ApplicationID: application.ID, Limit: app.MaxListLimit + 1}},
		{name: "负偏移", request: app.MemberListRequest{ApplicationID: application.ID, Offset: -1}},
		{name: "偏移过大", request: app.MemberListRequest{ApplicationID: application.ID, Offset: app.MaxListOffset + 1}},
		{name: "非法排序", request: app.MemberListRequest{ApplicationID: application.ID, Sort: "profile_json"}},
		{name: "非法状态", request: app.MemberListRequest{ApplicationID: application.ID, Status: "pending"}},
	}
	for _, test := range listCases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := env.service.ListApplicationMembers(context.Background(), env.system, test.request); !errors.Is(err, app.ErrInvalidRequest) {
				t.Fatalf("列表边界错误 = %v", err)
			}
		})
	}

	// 正常分页与状态过滤（再补两名成员，其中一个停用）。
	env.addMember(application.ID, testOwnerTwo, app.MemberProfile{})
	env.insertUserWithStatus("usr_00000000000000000000000000000013", "memberthree", "active")
	third := env.addMember(application.ID, "usr_00000000000000000000000000000013", app.MemberProfile{})
	if _, err := env.service.DisableApplicationMember(context.Background(), env.system, app.MemberStatusRequest{
		ApplicationID: application.ID, UserID: third.UserID, ExpectedRowVersion: third.RowVersion,
	}); err != nil {
		t.Fatalf("停用第三名成员失败: %v", err)
	}
	firstPage, err := env.service.ListApplicationMembers(context.Background(), env.system, app.MemberListRequest{
		ApplicationID: application.ID, Limit: 2, Sort: app.MemberSortUserID,
	})
	if err != nil || len(firstPage.Members) != 2 || !firstPage.HasMore {
		t.Fatalf("分页第一页 = %+v err=%v", firstPage, err)
	}
	disabledPage, err := env.service.ListApplicationMembers(context.Background(), env.system, app.MemberListRequest{
		ApplicationID: application.ID, Status: app.MembershipDisabled,
	})
	if err != nil || len(disabledPage.Members) != 1 || disabledPage.Members[0].UserID != third.UserID {
		t.Fatalf("状态过滤 = %+v err=%v", disabledPage, err)
	}
}

// TestApplicationMemberAuditConsistencyAndFailClosed 验证成员关键变更与审计一致、
// 失败审计错误码按真实类别映射、移除事件包含应用与目标用户。
func TestApplicationMemberAuditConsistencyAndFailClosed(t *testing.T) {
	env := prepareEnv(t)
	application := env.newActiveApp()
	user := testOwnerOne

	// 审计存储故障时加入失败且不写成员行（fail-closed）。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_member_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit blocked'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: application.ID, UserID: user,
	}); !errors.Is(err, app.ErrAuditUnavailable) {
		t.Fatalf("审计故障加入错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if rows := env.memberRowCount(application.ID); rows != 0 {
		t.Fatalf("审计故障后成员行数 = %d，期望 0", rows)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_member_audit;`); err != nil {
		t.Fatalf("删除审计故障触发器失败: %v", err)
	}

	// 成员表写入故障：业务失败、无成员行、失败审计 error_code=DB_UNAVAILABLE。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_member_insert BEFORE INSERT ON app_memberships BEGIN SELECT RAISE(ABORT,'member blocked'); END;`); err != nil {
		t.Fatalf("创建成员表故障触发器失败: %v", err)
	}
	if _, err := env.service.AddApplicationMember(context.Background(), env.system, app.AddMemberRequest{
		ApplicationID: application.ID, UserID: user,
	}); !errors.Is(err, app.ErrStoreUnavailable) {
		t.Fatalf("成员写入故障错误 = %v，期望 ErrStoreUnavailable", err)
	}
	if rows := env.memberRowCount(application.ID); rows != 0 {
		t.Fatalf("成员写入故障后成员行数 = %d", rows)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.member.add' AND outcome='failure' AND error_code='DB_UNAVAILABLE'`); count != 1 {
		t.Errorf("成员写入故障失败审计 DB_UNAVAILABLE 数量 = %d", count)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_member_insert;`); err != nil {
		t.Fatalf("删除成员表故障触发器失败: %v", err)
	}

	// 正常加入与更新：审计含应用快照、目标用户、脱敏资料差异。
	member := env.addMember(application.ID, user, app.MemberProfile{DisplayName: "审计测试名", Note: "审计备注"})
	if count := env.auditCount("application.member.add", "success", application.ID); count != 1 {
		t.Fatalf("加入成功审计数量 = %d", count)
	}
	if value := env.queryString(`SELECT target_type || '|' || target_id FROM audit_events WHERE action='application.member.add' AND outcome='success' AND app_id_snapshot=?`, application.ID); value != "application_member|"+user {
		t.Fatalf("加入审计目标 = %q", value)
	}
	detail := env.queryString(`SELECT detail_json FROM audit_events WHERE action='application.member.add' AND outcome='success' AND app_id_snapshot=?`, application.ID)
	if strings.Contains(detail, "审计测试名") || !strings.Contains(detail, "profile.display_name") {
		t.Fatalf("加入审计资料差异未脱敏或缺少字段：%q", detail)
	}

	if _, err := env.service.UpdateApplicationMemberProfile(context.Background(), env.system, app.MemberProfileRequest{
		ApplicationID: application.ID, UserID: user,
		Profile:            app.MemberProfile{DisplayName: "新审计名"},
		ExpectedRowVersion: member.RowVersion,
	}); err != nil {
		t.Fatalf("更新资料失败: %v", err)
	}
	updateDetail := env.queryString(`SELECT detail_json FROM audit_events WHERE action='application.member.profile.update' AND outcome='success' AND app_id_snapshot=?`, application.ID)
	if strings.Contains(updateDetail, "新审计名") || !strings.Contains(updateDetail, `"before":"[REDACTED]"`) {
		t.Fatalf("更新审计资料差异未脱敏：%q", updateDetail)
	}

	// 移除事件保留应用与用户信息；行删除但审计不丢。
	current, err := env.getMember(application.ID, user)
	if err != nil {
		t.Fatalf("读取成员失败: %v", err)
	}
	if err := env.service.RemoveApplicationMember(context.Background(), env.system, app.RemoveMemberRequest{
		ApplicationID: application.ID, UserID: user, ExpectedRowVersion: current.RowVersion,
	}); err != nil {
		t.Fatalf("移除成员失败: %v", err)
	}
	if env.memberRowCount(application.ID) != 0 {
		t.Fatal("移除后成员行未删除")
	}
	if value := env.queryString(`SELECT target_type || '|' || target_id || '|' || outcome FROM audit_events WHERE action='application.member.remove' AND app_id_snapshot=?`, application.ID); value != "application_member|"+user+"|success" {
		t.Fatalf("移除审计 = %q", value)
	}
}

// TestApplicationMemberStoredProfileFailClosed 验证数据库中的异常 profile_json 不会
// 被静默接受。
func TestApplicationMemberStoredProfileFailClosed(t *testing.T) {
	env := prepareEnv(t)
	application := env.newActiveApp()
	user := testOwnerOne
	now := env.clock.Now().UnixMilli()
	insert := func(profileJSON string) error {
		_, err := env.raw.ExecContext(context.Background(),
			`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active',?,1,?,?)`, application.ID, user, profileJSON, now, now)
		return err
	}
	remove := func() error {
		_, err := env.raw.ExecContext(context.Background(),
			`DELETE FROM app_memberships WHERE app_id=? AND user_id=?`, application.ID, user)
		return err
	}

	// 这些值都是合法 JSON（数据库 json_valid 约束允许写入），但不是本包定义的
	// 规范资料结构；读取时必须 fail-closed。
	malformed := []string{
		`{}`,
		`[]`,
		`"text"`,
		`{"v":2}`,
		`{"v":1,"unknown":1}`,
		`{"v":1,"display_name":123}`,
		`{"v":1,"display_name":"  未规范化  "}`,
		`{"v":1,"display_name":"bad\u0000"}`,
	}
	for index, profileJSON := range malformed {
		t.Run(fmt.Sprintf("异常资料%d", index+1), func(t *testing.T) {
			if err := insert(profileJSON); err != nil {
				t.Fatalf("插入成员测试数据失败: %v", err)
			}
			if _, err := env.getMember(application.ID, user); !errors.Is(err, app.ErrStoreUnavailable) {
				t.Fatalf("异常 profile_json %s 应被拒绝，实际错误 = %v", profileJSON, err)
			}
			if err := remove(); err != nil {
				t.Fatalf("删除成员测试数据失败: %v", err)
			}
		})
	}

	// 服务写出的规范 JSON 可正常读取。
	member := env.addMember(application.ID, user, app.MemberProfile{DisplayName: "规范名", Title: "职位"})
	stored, err := env.getMember(application.ID, user)
	if err != nil || stored.Profile != member.Profile {
		t.Fatalf("规范资料读取 = %+v err=%v", stored, err)
	}
}
