// Copyright (c) Kagurazakayashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 251 公开授权接口的资源范围校验定向测试（经 app 公开 Go 门面）：
//   - AccessService.Check 在没有 ResourceID 时只判定功能权限，并在决策中明确
//     ResourceChecked=false；提供 ResourceID 时必须复用领域内核按数据范围判定，
//     不能只返回功能权限结论；
//   - 仅获准访问资源 A 的用户：A 允许、B 拒绝；数据范围 undefined/none 拒绝、
//     all 允许；同一权限键/同一资源字符串在另一个应用下按范围隔离拒绝；
//   - 空权限、非法编号/资源标识等输入按 REQ_INVALID 拒绝，不能靠空权限自证授权；
//   - 权限依赖不可用时默认拒绝（AUTHZ_UNAVAILABLE），不能放行；
//   - SessionService.Authorize 提供同样的可选资源级语义（会话 + 应用 + 权限 + 资源）。
//
// 说明：公开管理门面当前只能把角色分配给用户（data_scope_json 固定为 "{}"），
// 尚未提供写入数据范围的公开接口；本测试仅用 SQL 夹具补写分配记录的数据范围，
// 授权判定本身全部走真实公开门面与生产装配的授权内核，不使用测试替身。

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// accessScopeFixture 是本步测试使用的真实装配：两个启用的应用、一名同时属于两个
// 应用并持有各场景角色的成员用户，以及一名非成员用户。
type accessScopeFixture struct {
	runtime  *Runtime
	clock    *testClock
	appA     AdminApplication
	appB     AdminApplication
	member   User
	outsider User
}

// setupAccessScopeFixture 通过公开管理门面建立真实权限链，再用 SQL 夹具写入
// 角色分配的数据范围（公开分配接口尚不允许设置数据范围）。
func setupAccessScopeFixture(t *testing.T) *accessScopeFixture {
	t.Helper()
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	member := step207CreateProblemUser(t, ctx, runtime, "scope-member")
	outsider := step207CreateProblemUser(t, ctx, runtime, "scope-outsider")

	createEnabledApplication := func(name string) AdminApplication {
		t.Helper()
		created, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用 %s 失败: %v", name, err)
		}
		enabled, err := adminAPI.SetApplicationEnabled(ctx,
			AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: created.ID,
				Enabled: true, ExpectedRowVersion: created.RowVersion,
				RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("启用应用 %s 失败: %v", name, err)
		}
		return enabled
	}
	appA := createEnabledApplication("资源范围应用 A")
	appB := createEnabledApplication("资源范围应用 B")
	for _, application := range []AdminApplication{appA, appB} {
		if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
			Caller: local, ApplicationID: application.ID, UserID: member.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("成员加入应用 %s 失败: %v", application.ID, err)
		}
	}

	// createRoleWithPermission 在指定应用范围登记权限/角色、组合权限并分配给成员。
	createRoleWithPermission := func(scopeID, roleKey, permissionKey string) AdminRole {
		t.Helper()
		permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: scopeID, Key: permissionKey, Name: permissionKey,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建权限 %s（scope=%s）失败: %v", permissionKey, scopeID, err)
		}
		role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
			Caller: local, ScopeID: scopeID, Key: roleKey, Name: roleKey,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建角色 %s（scope=%s）失败: %v", roleKey, scopeID, err)
		}
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("角色 %s 组合权限失败: %v", roleKey, err)
		}
		if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
			Caller: local, UserID: member.ID, RoleID: role.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("分配角色 %s 失败: %v", roleKey, err)
		}
		return role
	}
	roleScoped := createRoleWithPermission(appA.ID, "scope-resources", "invoice.read")
	roleUndefined := createRoleWithPermission(appA.ID, "scope-undefined",
		"invoice.undefined.read")
	roleNone := createRoleWithPermission(appA.ID, "scope-none", "invoice.none.read")
	roleAll := createRoleWithPermission(appA.ID, "scope-all", "invoice.all.read")
	// 应用 B 登记同名权限键与同名资源字符串的另一份数据范围，用于跨应用隔离验证。
	roleCrossB := createRoleWithPermission(appB.ID, "scope-cross-b", "invoice.read")

	// 测试夹具：仅补写分配记录的数据范围；不修改权限/角色定义，不绕过授权判定。
	setAssignmentDataScope := func(roleID, scopeJSON string) {
		t.Helper()
		result, err := runtime.base.Store.DB().Exec(
			`UPDATE user_roles SET data_scope_json=? WHERE user_id=? AND role_id=?`,
			scopeJSON, member.ID, roleID)
		if err != nil {
			t.Fatalf("写入角色 %s 的数据范围失败: %v", roleID, err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			t.Fatalf("角色 %s 数据范围更新行数 = %d（err=%v），期望 1",
				roleID, affected, err)
		}
	}
	setAssignmentDataScope(roleScoped.ID,
		`{"v":1,"mode":"resources","resources":["invoice-1"]}`)
	setAssignmentDataScope(roleUndefined.ID, `{}`)
	setAssignmentDataScope(roleNone.ID, `{"v":1,"mode":"none"}`)
	setAssignmentDataScope(roleAll.ID, `{"v":1,"mode":"all"}`)
	setAssignmentDataScope(roleCrossB.ID,
		`{"v":1,"mode":"resources","resources":["invoice-2"]}`)

	return &accessScopeFixture{runtime: runtime, clock: clock, appA: appA, appB: appB,
		member: member, outsider: outsider}
}

// accessDecision 断言并返回一次公开 Access.Check 的判定结果。
func accessDecision(t *testing.T, fixture *accessScopeFixture,
	request AccessRequest) AccessDecision {
	t.Helper()
	decision, err := fixture.runtime.Access().Check(context.Background(), request)
	if err != nil {
		t.Fatalf("Access.Check(%+v) 返回错误: %v", request, err)
	}
	return decision
}

// assertResourceDecision 校验资源级判定：允许时无拒绝码，拒绝时必须带期望稳定码。
func assertResourceDecision(t *testing.T, name string, decision AccessDecision,
	wantAllowed bool, wantCode string) {
	t.Helper()
	if decision.Allowed != wantAllowed {
		t.Fatalf("%s: Allowed = %v，期望 %v（决策 %+v）",
			name, decision.Allowed, wantAllowed, decision)
	}
	if !wantAllowed && decision.Code != wantCode {
		t.Fatalf("%s: 拒绝码 = %q，期望 %q（决策 %+v）",
			name, decision.Code, wantCode, decision)
	}
	if wantAllowed && (decision.Code != "" || decision.Reason != "") {
		t.Fatalf("%s: 允许时不应带拒绝码/原因（决策 %+v）", name, decision)
	}
	if !decision.ResourceChecked {
		t.Fatalf("%s: 资源级请求应标记 ResourceChecked=true（决策 %+v）", name, decision)
	}
}

// TestAccessCheckEnforcesResourceScopeThroughPublicFacade 覆盖资源级判定的成功与
// 全部拒绝边界：资源 A 允许、B 拒绝、undefined/none 拒绝、all 允许、跨应用同名
// 资源按范围隔离拒绝、非成员/未知权限拒绝。
func TestAccessCheckEnforcesResourceScopeThroughPublicFacade(t *testing.T) {
	fixture := setupAccessScopeFixture(t)

	// 1) 不提供 ResourceID：只判定功能权限，决策必须明确“未校验具体资源”。
	const functionalRequestID = "req_251_functional_allowed"
	functional := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		RequestID: functionalRequestID})
	if !functional.Allowed || functional.ResourceChecked || functional.ResourceID != "" {
		t.Fatalf("功能权限判定异常（不应声称已校验资源）: %+v", functional)
	}
	if functional.Application != fixture.appA.ID || functional.RequestID != functionalRequestID {
		t.Fatalf("功能权限判定回显异常: %+v", functional)
	}

	// 2) 仅获准资源 invoice-1 的用户：同一应用内 invoice-1 允许、invoice-2 拒绝。
	const scopedRequestID = "req_251_resource_a_allowed"
	allowedA := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		ResourceID: "invoice-1", RequestID: scopedRequestID})
	assertResourceDecision(t, "资源 A 允许", allowedA, true, "")
	if allowedA.ResourceID != "invoice-1" || allowedA.RequestID != scopedRequestID ||
		allowedA.Application != fixture.appA.ID {
		t.Fatalf("资源 A 允许决策回显异常: %+v", allowedA)
	}
	deniedB := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		ResourceID: "invoice-2", RequestID: "req_251_resource_b_denied"})
	assertResourceDecision(t, "资源 B 拒绝", deniedB, false,
		string(login.CodeResourceForbidden))
	if deniedB.Reason != "resource_not_in_scope" || deniedB.ResourceID != "invoice-2" {
		t.Fatalf("资源 B 拒绝原因异常: %+v", deniedB)
	}

	// 3) 跨应用同名资源/同名权限键：应用 B 的授权只覆盖 invoice-2，拒绝 invoice-1。
	crossDenied := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appB.ID, Permission: "invoice.read",
		ResourceID: "invoice-1", RequestID: "req_251_cross_app_denied"})
	assertResourceDecision(t, "跨应用同名资源拒绝", crossDenied, false,
		string(login.CodeResourceForbidden))
	if crossDenied.Reason != "resource_not_in_scope" ||
		crossDenied.Application != fixture.appB.ID {
		t.Fatalf("跨应用拒绝原因/范围异常: %+v", crossDenied)
	}
	crossAllowed := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appB.ID, Permission: "invoice.read",
		ResourceID: "invoice-2", RequestID: "req_251_cross_app_allowed"})
	assertResourceDecision(t, "应用 B 自己的资源允许", crossAllowed, true, "")

	// 4) 数据范围 undefined（历史 {}）：功能权限可能通过，但资源级必须拒绝。
	undefinedDecision := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID,
		Permission: "invoice.undefined.read", ResourceID: "invoice-1",
		RequestID: "req_251_undefined_denied"})
	assertResourceDecision(t, "未声明数据范围拒绝", undefinedDecision, false,
		string(login.CodeResourceForbidden))
	if undefinedDecision.Reason != "data_scope_undefined" {
		t.Fatalf("未声明数据范围拒绝原因异常: %+v", undefinedDecision)
	}

	// 5) 数据范围 none：任何资源都拒绝。
	noneDecision := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID,
		Permission: "invoice.none.read", ResourceID: "invoice-1",
		RequestID: "req_251_none_denied"})
	assertResourceDecision(t, "none 数据范围拒绝", noneDecision, false,
		string(login.CodeResourceForbidden))
	if noneDecision.Reason != "data_scope_none" {
		t.Fatalf("none 数据范围拒绝原因异常: %+v", noneDecision)
	}

	// 6) 数据范围 all：任意资源都允许。
	allDecision := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID,
		Permission: "invoice.all.read", ResourceID: "invoice-any-other",
		RequestID: "req_251_all_allowed"})
	assertResourceDecision(t, "all 数据范围允许", allDecision, true, "")

	// 7) 未授权权限 + 资源：拒绝，不能因为提供了资源就放行。
	unknownDecision := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID,
		Permission: "invoice.never.granted", ResourceID: "invoice-1",
		RequestID: "req_251_unknown_permission"})
	if unknownDecision.Allowed || unknownDecision.Code != "PERMISSION_UNKNOWN" {
		t.Fatalf("未授权权限应返回 PERMISSION_UNKNOWN 拒绝: %+v", unknownDecision)
	}

	// 8) 非应用成员：功能权限与资源级判定都拒绝，且不泄露内部细节。
	outsiderFunctional := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.outsider.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		RequestID: "req_251_outsider_functional"})
	if outsiderFunctional.Allowed ||
		outsiderFunctional.Code != string(login.CodeAppMembershipRequired) {
		t.Fatalf("非成员功能权限判定应返回 APP_MEMBERSHIP_REQUIRED: %+v",
			outsiderFunctional)
	}
	outsiderResource := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.outsider.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		ResourceID: "invoice-1", RequestID: "req_251_outsider_resource"})
	if outsiderResource.Allowed ||
		outsiderResource.Code != string(login.CodeAppMembershipRequired) {
		t.Fatalf("非成员资源级判定应返回 APP_MEMBERSHIP_REQUIRED: %+v",
			outsiderResource)
	}

	// 9) 系统范围同名权限不存在：按未知权限拒绝，而不是把应用权限当成系统权限。
	crossScope := accessDecision(t, fixture, AccessRequest{
		UserID: fixture.member.ID, Permission: "invoice.read", ResourceID: "invoice-1",
		RequestID: "req_251_scope_mismatch"})
	if crossScope.Allowed || crossScope.Code != "PERMISSION_UNKNOWN" ||
		crossScope.Application != "" {
		t.Fatalf("系统范围不应复用应用权限: %+v", crossScope)
	}

	// 10) 拒绝决策同样贯穿请求编号，便于调用/审计/错误关联。
	if deniedB.RequestID != "req_251_resource_b_denied" {
		t.Fatalf("拒绝决策请求编号 = %q", deniedB.RequestID)
	}
}

// TestAccessCheckRejectsSelfAuthorizationInputs 验证空权限、非法主体/编号/资源标识
// 都不能变成“允许”，而是稳定 REQ_INVALID 错误。
func TestAccessCheckRejectsSelfAuthorizationInputs(t *testing.T) {
	fixture := setupAccessScopeFixture(t)
	ctx := context.Background()
	access := fixture.runtime.Access()

	// 空权限/空白权限不是“无需权限”，必须拒绝且带本次请求编号。
	for name, request := range map[string]AccessRequest{
		"空权限": {UserID: fixture.member.ID, AppID: fixture.appA.ID,
			RequestID: "req_251_empty_permission"},
		"空白权限": {UserID: fixture.member.ID, AppID: fixture.appA.ID,
			Permission: "   ", RequestID: "req_251_blank_permission"},
		"空权限带资源": {UserID: fixture.member.ID, AppID: fixture.appA.ID,
			ResourceID: "invoice-1", RequestID: "req_251_empty_perm_resource"},
	} {
		decision, err := access.Check(ctx, request)
		if err == nil {
			t.Fatalf("%s 必须返回错误（不允许 Allowed=true），实际决策 %+v", name, decision)
		}
		if !login.IsErrorCode(err, login.CodeReqInvalid) {
			t.Fatalf("%s 应返回 REQ_INVALID，实际 %v", name, err)
		}
		appError := step207AppError(t, err)
		if request.RequestID != "" && appError.RequestID() != request.RequestID {
			t.Fatalf("%s 错误请求编号 = %q，期望 %q", name,
				appError.RequestID(), request.RequestID)
		}
	}

	// 非法请求编号：拒绝且不回显非法值。
	_, err := access.Check(ctx, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		RequestID: "req 251\n注入"})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeReqInvalid || appError.RequestID() != "" {
		t.Fatalf("非法请求编号应返回不带编号的 REQ_INVALID，实际 %v", appError)
	}

	// 非法主体 ID。
	_, err = access.Check(ctx, AccessRequest{
		UserID: "not a user id", AppID: fixture.appA.ID, Permission: "invoice.read",
		RequestID: "req_251_bad_user"})
	if !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法主体应返回 REQ_INVALID，实际 %v", err)
	}

	// 非法资源标识（控制字符/首尾空白/超长）：不能按资源通过。
	for name, resourceID := range map[string]string{
		"控制字符资源标识": "invoice-1\ninjected",
		"空白资源标识":   "   ",
		"超长资源标识":   strings.Repeat("r", 257),
	} {
		_, err := access.Check(ctx, AccessRequest{
			UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
			ResourceID: resourceID, RequestID: "req_251_bad_resource"})
		if !login.IsErrorCode(err, login.CodeReqInvalid) {
			t.Fatalf("%s 应返回 REQ_INVALID，实际 %v", name, err)
		}
	}

	// 非法组合模式：资源级判定同样不接受未定义模式。
	_, err = access.Check(ctx, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		Mode: "some", ResourceID: "invoice-1", RequestID: "req_251_bad_mode"})
	if !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法组合模式应返回 REQ_INVALID，实际 %v", err)
	}
}

// TestSessionAuthorizeEnforcesResourceScope 验证会话联合授权入口新增的显式资源
// 参数：会话/应用/功能权限之外，按同一领域内核判定数据范围。
func TestSessionAuthorizeEnforcesResourceScope(t *testing.T) {
	fixture := setupAccessScopeFixture(t)
	ctx := context.Background()
	const password = "K8$wR3!nB6@yF1#v"
	loginResult, err := fixture.runtime.Auth().Login(ctx, LoginRequest{
		Username: fixture.member.Username, Password: password,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录成员用户失败: %v", err)
	}
	if loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("未启用第二因素的成员应得到完整会话: %+v", loginResult)
	}
	sessions := fixture.runtime.Sessions()

	// 不提供 ResourceID：会话/应用/功能权限允许，但不声称已校验具体资源。
	functional, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: "req_251_session_functional"})
	if err != nil || !functional.Allowed || functional.ResourceChecked ||
		functional.ResourceID != "" {
		t.Fatalf("会话功能权限判定异常: %+v err=%v", functional, err)
	}

	// 资源级：invoice-1 允许、invoice-2 拒绝。
	allowed, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read"}, ResourceID: "invoice-1",
		RequestID: "req_251_session_resource_allowed"})
	if err != nil {
		t.Fatalf("会话资源级判定出错: %v", err)
	}
	assertResourceDecision(t, "会话资源 A 允许", sessionAsAccessDecision(allowed),
		true, "")
	if allowed.ResourceID != "invoice-1" || allowed.UserID != fixture.member.ID ||
		allowed.AppID != fixture.appA.ID ||
		allowed.RequestID != "req_251_session_resource_allowed" {
		t.Fatalf("会话资源级允许回显异常: %+v", allowed)
	}
	denied, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read"}, ResourceID: "invoice-2",
		RequestID: "req_251_session_resource_denied"})
	if err != nil {
		t.Fatalf("会话资源级拒绝判定出错: %v", err)
	}
	if denied.Allowed || denied.Code != string(login.CodeResourceForbidden) ||
		denied.Reason != "resource_not_in_scope" || !denied.ResourceChecked {
		t.Fatalf("会话资源级拒绝语义异常: %+v", denied)
	}

	// 数据范围 undefined：会话/应用/功能权限通过后，资源级仍拒绝。
	undefined, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.undefined.read"}, ResourceID: "invoice-1",
		RequestID: "req_251_session_undefined"})
	if err != nil {
		t.Fatalf("会话未声明数据范围判定出错: %v", err)
	}
	if undefined.Allowed || undefined.Code != string(login.CodeResourceForbidden) ||
		undefined.Reason != "data_scope_undefined" || !undefined.ResourceChecked {
		t.Fatalf("会话未声明数据范围语义异常: %+v", undefined)
	}

	// 多权限 + 资源：拒绝含糊请求（资源级只接受单权限），不执行判定。
	if _, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read", "invoice.all.read"},
		ResourceID:  "invoice-1", RequestID: "req_251_session_multi"}); !login.IsErrorCode(
		err, login.CodeReqInvalid) {
		t.Fatalf("多权限资源级请求应返回 REQ_INVALID，实际 %v", err)
	}

	// 非法资源标识：REQ_INVALID，不进入判定。
	_, err = sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read"}, ResourceID: "invoice-1\x00",
		RequestID: "req_251_session_bad_resource"})
	if !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法资源标识应返回 REQ_INVALID，实际 %v", err)
	}

	// 应用绑定优先：绑定应用 A 的会话访问应用 B 的资源 → APP_SCOPE_MISMATCH，
	// 不进入资源判定（ResourceChecked=false）。
	appBound, err := fixture.runtime.Auth().Login(ctx, LoginRequest{
		Username: fixture.member.Username, Password: password, ClientIP: "127.0.0.1",
		AppID: fixture.appA.ID, RequestID: login.NewRequestID()})
	if err != nil || len(appBound.SessionSecret) == 0 {
		t.Fatalf("绑定应用 A 的登录失败: %+v err=%v", appBound, err)
	}
	mismatch, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: appBound.SessionSecret, AppID: fixture.appB.ID,
		Permissions: []string{"invoice.read"}, ResourceID: "invoice-2",
		RequestID: "req_251_session_app_mismatch"})
	if err != nil {
		t.Fatalf("应用绑定判定出错: %v", err)
	}
	if mismatch.Allowed || mismatch.Code != string(login.CodeAppScopeMismatch) ||
		mismatch.ResourceChecked || mismatch.Reason != "session_app_mismatch" {
		t.Fatalf("应用绑定优先语义异常: %+v", mismatch)
	}

	// 受限会话（未完成第二因素）即使带 ResourceID 也先被拒绝，不进入资源判定。
	const restrictedUsername = "scope-restricted"
	if userID, _, _ := setupUserWithTOTP(t, fixture.runtime, fixture.clock,
		restrictedUsername, password); userID == "" {
		t.Fatal("受限会话测试用户创建失败")
	}
	fixture.clock.Advance(30 * time.Second)
	restrictedLogin, err := fixture.runtime.Auth().Login(ctx, LoginRequest{
		Username: restrictedUsername, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !restrictedLogin.Restricted || len(restrictedLogin.SessionSecret) == 0 {
		t.Fatalf("绑定 TOTP 后登录应为受限会话: %+v err=%v", restrictedLogin, err)
	}
	restrictedDecision, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: restrictedLogin.SessionSecret, AppID: fixture.appA.ID,
		Permissions: []string{"invoice.read"}, ResourceID: "invoice-1",
		RequestID: "req_251_session_restricted_resource"})
	if err != nil {
		t.Fatalf("受限会话判定出错: %v", err)
	}
	if restrictedDecision.Allowed ||
		restrictedDecision.Code != string(login.CodeAccessDenied) ||
		restrictedDecision.Reason != "restricted_session" ||
		restrictedDecision.ResourceChecked ||
		restrictedDecision.ResourceID != "invoice-1" {
		t.Fatalf("受限会话优先语义异常: %+v", restrictedDecision)
	}
}

// sessionAsAccessDecision 把会话资源级决策投影为统一的资源断言输入（仅测试用）。
func sessionAsAccessDecision(decision SessionAccessDecision) AccessDecision {
	return AccessDecision{Allowed: decision.Allowed, Code: decision.Code,
		Reason: decision.Reason, RequestID: decision.RequestID, Application: decision.AppID,
		ResourceChecked: decision.ResourceChecked, ResourceID: decision.ResourceID}
}

// TestAccessCheckDependencyFailureDeniesByDefault 验证授权依赖不可用时功能权限与
// 资源级判定都默认拒绝（AUTHZ_UNAVAILABLE 决策，而不是错误或放行）。
func TestAccessCheckDependencyFailureDeniesByDefault(t *testing.T) {
	fixture := setupAccessScopeFixture(t)
	ctx := context.Background()
	// 会话与登录不依赖权限表，先取得完整会话用于会话联合授权对比。
	loginResult, err := fixture.runtime.Auth().Login(ctx, LoginRequest{
		Username: fixture.member.Username, Password: "K8$wR3!nB6@yF1#v",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("依赖故障前登录失败: %+v err=%v", loginResult, err)
	}
	// 故障注入（测试夹具，仅本临时库）：重命名权限表使授权内核读取失败。
	if _, err := fixture.runtime.base.Store.DB().Exec(
		`ALTER TABLE permissions RENAME TO permissions_unavailable`); err != nil {
		t.Fatalf("注入权限依赖故障失败: %v", err)
	}

	functional, err := fixture.runtime.Access().Check(ctx, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		RequestID: "req_251_dependency_functional"})
	if err != nil {
		t.Fatalf("依赖不可用应返回拒绝决策而不是内部错误: %v", err)
	}
	if functional.Allowed || functional.Code != string(login.CodeAuthzUnavailable) {
		t.Fatalf("功能权限依赖不可用必须默认拒绝: %+v", functional)
	}

	resource, err := fixture.runtime.Access().Check(ctx, AccessRequest{
		UserID: fixture.member.ID, AppID: fixture.appA.ID, Permission: "invoice.read",
		ResourceID: "invoice-1", RequestID: "req_251_dependency_resource"})
	if err != nil {
		t.Fatalf("资源级依赖不可用应返回拒绝决策而不是内部错误: %v", err)
	}
	if resource.Allowed || resource.Code != string(login.CodeAuthzUnavailable) ||
		!resource.ResourceChecked {
		t.Fatalf("资源级依赖不可用必须默认拒绝: %+v", resource)
	}

	sessionDecision, err := fixture.runtime.Sessions().Authorize(ctx,
		SessionAccessRequest{SessionSecret: loginResult.SessionSecret,
			AppID: fixture.appA.ID, Permissions: []string{"invoice.read"},
			RequestID: "req_251_dependency_session"})
	if err != nil {
		t.Fatalf("会话授权依赖不可用应返回拒绝决策: %v", err)
	}
	if sessionDecision.Allowed ||
		sessionDecision.Code != string(login.CodeAuthzUnavailable) {
		t.Fatalf("会话授权依赖不可用必须默认拒绝: %+v", sessionDecision)
	}
}
