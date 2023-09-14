package app

// 步骤 207 公开查询请求关联与未找到契约测试。
//
// 覆盖：
//   - RequestID 合法编号贯穿调用/领域审计/返回错误；空编号统一生成且每次不同；
//     非法编号在查询前拒绝（REQ_INVALID），不产生领域审计；
//   - 已通过权限检查的查询对目标不存在返回稳定的公开 NotFoundError（NOT_FOUND），
//     与参数非法（REQ_INVALID）和权限拒绝（ACCESS_DENIED）区分；外部模块用
//     app.IsNotFound 判断，不需要导入 internal；错误消息不回显查询值；
//   - LocalAdmin 可信宿主、正常管理员会话、无权限会话、跨 Runtime Caller、空
//     Caller、双模式伪造 Caller 的边界；
//   - 用户名 NFKC/大小写折叠匹配；
//   - 领域读审计不可用时 fail-closed 返回 AUDIT_WRITE_FAILED 并带同一请求编号；
//   - 写路径（CreateUser）同样把同一编号带入领域审计与返回错误。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// step207AuditRow 是测试直接读取的一条审计事件关键列。
type step207AuditRow struct {
	RequestID string
	ActorType string
	ActorID   string
	TargetID  string
}

// step207MaxAuditRowID 返回当前审计表最大 rowid，用于取“之后新增”的事件。
func step207MaxAuditRowID(t *testing.T, runtime *Runtime) int64 {
	t.Helper()
	var maxRowID int64
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT COALESCE(MAX(rowid),0) FROM audit_events`).Scan(&maxRowID); err != nil {
		t.Fatalf("读取审计最大 rowid 失败: %v", err)
	}
	return maxRowID
}

// step207AuditRowsAfter 返回指定动作在 afterRowID 之后新增的审计事件。
func step207AuditRowsAfter(t *testing.T, runtime *Runtime, action string,
	afterRowID int64) []step207AuditRow {
	t.Helper()
	rows, err := runtime.base.Store.DB().Query(
		`SELECT COALESCE(request_id,''), actor_type, COALESCE(actor_id,''),
		        COALESCE(target_id,'')
		   FROM audit_events WHERE action=? AND rowid>? ORDER BY rowid`,
		action, afterRowID)
	if err != nil {
		t.Fatalf("查询审计事件失败: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var result []step207AuditRow
	for rows.Next() {
		var row step207AuditRow
		if err := rows.Scan(&row.RequestID, &row.ActorType, &row.ActorID, &row.TargetID); err != nil {
			t.Fatalf("扫描审计事件失败: %v", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历审计事件失败: %v", err)
	}
	return result
}

// step207AuditCount 返回指定动作的审计事件数量（含成功/失败）。
func step207AuditCount(t *testing.T, runtime *Runtime, action string) int {
	t.Helper()
	var count int
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, action).Scan(&count); err != nil {
		t.Fatalf("统计审计事件失败: %v", err)
	}
	return count
}

// step207AppError 断言 err 是 *login.AppError 且返回该对象。
func step207AppError(t *testing.T, err error) *login.AppError {
	t.Helper()
	if err == nil {
		t.Fatal("期望返回错误，实际为 nil")
	}
	appError, ok := login.AsAppError(err)
	if !ok {
		t.Fatalf("期望 *login.AppError，实际 %T: %v", err, err)
	}
	return appError
}

// step207NotFound 断言 err 是公开 NotFoundError，并校验请求编号/资源/码。
func step207NotFound(t *testing.T, err error, resource, requestID string) *NotFoundError {
	t.Helper()
	if err == nil {
		t.Fatal("期望返回未找到错误，实际为 nil")
	}
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound = false，实际错误 %T: %v", err, err)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(err, ErrNotFound) = false，实际 %v", err)
	}
	notFound, ok := AsNotFound(err)
	if !ok {
		t.Fatalf("AsNotFound 失败，实际 %T", err)
	}
	if notFound.Code() != NotFoundCode || NotFoundCode != "NOT_FOUND" {
		t.Fatalf("未找到错误码 = %q，期望 %q", notFound.Code(), NotFoundCode)
	}
	if notFound.Resource != resource {
		t.Fatalf("未找到资源 = %q，期望 %q", notFound.Resource, resource)
	}
	if notFound.RequestID != requestID {
		t.Fatalf("未找到错误请求编号 = %q，期望 %q", notFound.RequestID, requestID)
	}
	if notFound.HTTPStatus() != 404 {
		t.Fatalf("未找到错误 HTTP 状态 = %d，期望 404", notFound.HTTPStatus())
	}
	return notFound
}

// step207CreateProblemUser 通过公开注册门面创建测试用户（真实哈希与存储）。
func step207CreateProblemUser(t *testing.T, ctx context.Context, runtime *Runtime,
	username string) User {
	t.Helper()
	created, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: username, Password: "K8$wR3!nB6@yF1#v", Nickname: username,
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建用户 %s 失败: %v", username, err)
	}
	return created
}

// TestAdminQueryRequestIDCorrelation 验证合法编号贯穿调用/审计/返回错误，空编号统一
// 生成且互不相同，非法编号在查询前拒绝并且不写领域审计。
func TestAdminQueryRequestIDCorrelation(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	alice := step207CreateProblemUser(t, ctx, runtime, "alice")
	step207CreateProblemUser(t, ctx, runtime, "bob")
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// ===== 合法编号：调用、领域审计与返回错误可关联 =====
	const listRequestID = "req_step207_list"
	before := step207MaxAuditRowID(t, runtime)
	page, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 10, Sort: "username", RequestID: listRequestID})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(page.Users) != 2 || page.HasMore {
		t.Fatalf("ListUsers 结果异常: %+v", page)
	}
	listRows := step207AuditRowsAfter(t, runtime, "user.list", before)
	if len(listRows) != 1 {
		t.Fatalf("user.list 审计条数 = %d，期望 1: %+v", len(listRows), listRows)
	}
	if listRows[0].RequestID != listRequestID {
		t.Fatalf("user.list 审计请求编号 = %q，期望 %q", listRows[0].RequestID, listRequestID)
	}
	if listRows[0].ActorType != "local_admin" || listRows[0].ActorID != "host-operator" {
		t.Fatalf("user.list 审计操作者异常: %+v", listRows[0])
	}

	const getRequestID = "req_step207_get"
	before = step207MaxAuditRowID(t, runtime)
	got, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "alice", RequestID: getRequestID})
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != alice.ID {
		t.Fatalf("GetUserByUsername ID = %q，期望 %q", got.ID, alice.ID)
	}
	getRows := step207AuditRowsAfter(t, runtime, "user.get", before)
	if len(getRows) != 1 {
		t.Fatalf("user.get 审计条数 = %d，期望 1: %+v", len(getRows), getRows)
	}
	if getRows[0].RequestID != getRequestID {
		t.Fatalf("user.get 审计请求编号 = %q，期望 %q", getRows[0].RequestID, getRequestID)
	}
	if getRows[0].ActorType != "local_admin" || getRows[0].TargetID != alice.ID {
		t.Fatalf("user.get 审计操作者/目标异常: %+v", getRows[0])
	}

	// ===== 空编号：统一生成，两次调用编号非空、合法且互不相同 =====
	before = step207MaxAuditRowID(t, runtime)
	for index := 0; index < 2; index++ {
		if _, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
			Caller: local, Limit: 10}); err != nil {
			t.Fatalf("空编号 ListUsers 第 %d 次失败: %v", index+1, err)
		}
	}
	generated := step207AuditRowsAfter(t, runtime, "user.list", before)
	if len(generated) != 2 {
		t.Fatalf("空编号 user.list 审计条数 = %d，期望 2", len(generated))
	}
	if generated[0].RequestID == "" || generated[1].RequestID == "" {
		t.Fatalf("空编号未生成审计请求编号: %+v", generated)
	}
	if generated[0].RequestID == generated[1].RequestID {
		t.Fatalf("空编号生成的请求编号重复: %q", generated[0].RequestID)
	}
	for _, row := range generated {
		if err := login.ValidateRequestID(row.RequestID); err != nil {
			t.Fatalf("生成的请求编号非法 %q: %v", row.RequestID, err)
		}
	}

	// ===== 合法编号贯穿返回错误（参数非法仍是 REQ_INVALID，不变成未找到） =====
	const invalidPaginationID = "req_step207_pagination"
	_, err = adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 1000, RequestID: invalidPaginationID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeReqInvalid {
		t.Fatalf("非法分页错误码 = %q，期望 REQ_INVALID", appError.Code())
	}
	if appError.RequestID() != invalidPaginationID {
		t.Fatalf("非法分页错误请求编号 = %q，期望 %q",
			appError.RequestID(), invalidPaginationID)
	}
	if IsNotFound(err) {
		t.Fatalf("参数非法不能被当成未找到: %v", err)
	}

	// 空编号的错误也必须带上统一生成的编号。
	_, err = adminAPI.ListUsers(ctx, AdminListUsersRequest{Caller: local, Limit: -1})
	appError = step207AppError(t, err)
	if appError.Code() != login.CodeReqInvalid {
		t.Fatalf("空编号非法分页错误码 = %q，期望 REQ_INVALID", appError.Code())
	}
	if appError.RequestID() == "" {
		t.Fatal("空编号的返回错误缺少统一生成的请求编号")
	}
	if validateErr := login.ValidateRequestID(appError.RequestID()); validateErr != nil {
		t.Fatalf("空编号生成的错误请求编号非法 %q: %v", appError.RequestID(), validateErr)
	}

	// ===== 非法编号：查询前拒绝，不带编号，且不产生领域审计 =====
	auditBefore := step207AuditCount(t, runtime, "user.get")
	for _, invalidID := range []string{
		"req 207", "req_step207\ninjected", "请求编号", " ",
		strings.Repeat("a", login.MaxCorrelationIDLength+1),
	} {
		_, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
			Caller: local, Username: "alice", RequestID: invalidID})
		appError := step207AppError(t, err)
		if appError.Code() != login.CodeReqInvalid {
			t.Fatalf("非法请求编号 %q 错误码 = %q，期望 REQ_INVALID", invalidID, appError.Code())
		}
		if appError.RequestID() != "" {
			t.Fatalf("非法请求编号 %q 不应被回显到错误对象，实际 %q",
				invalidID, appError.RequestID())
		}
	}
	if auditAfter := step207AuditCount(t, runtime, "user.get"); auditAfter != auditBefore {
		t.Fatalf("非法请求编号不应执行领域查询/审计: before=%d after=%d",
			auditBefore, auditAfter)
	}
}

// TestAdminAuthorizedQueryNotFoundContract 验证已授权查询的稳定未找到语义，且未授权
// 调用者不能借“未找到/存在”差异探测记录。
func TestAdminAuthorizedQueryNotFoundContract(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 2, 30, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	step207CreateProblemUser(t, ctx, runtime, "alice")
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	missingUserID, err := account.NewUserID(nil)
	if err != nil {
		t.Fatalf("生成测试用户 ID 失败: %v", err)
	}
	missingRoleID, err := role.NewRoleID(nil)
	if err != nil {
		t.Fatalf("生成测试角色 ID 失败: %v", err)
	}

	// ===== 已授权 + 目标不存在：稳定 NOT_FOUND 语义 =====
	const userLookupID = "req_step207_missing_user"
	_, err = adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "nobody207", RequestID: userLookupID})
	notFound := step207NotFound(t, err, "user", userLookupID)
	if strings.Contains(notFound.Error(), "nobody207") {
		t.Fatalf("未找到错误回显了查询值（可能被用于探测）: %s", notFound.Error())
	}

	const profileLookupID = "req_step207_missing_profile"
	_, err = adminAPI.GetUserProfile(ctx, AdminUserRequest{
		Caller: local, UserID: missingUserID, RequestID: profileLookupID})
	step207NotFound(t, err, "user", profileLookupID)

	const roleLookupID = "req_step207_missing_role"
	_, err = adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: local, RoleID: missingRoleID, RequestID: roleLookupID})
	step207NotFound(t, err, "role", roleLookupID)

	const permissionsLookupID = "req_step207_missing_permissions"
	_, err = adminAPI.EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: local, UserID: missingUserID, ScopeID: "system", RequestID: permissionsLookupID})
	step207NotFound(t, err, "user", permissionsLookupID)

	// 已存在用户仍正常返回，证明未找到并非“一切都未找到”。
	if _, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "alice", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("已存在用户查询失败: %v", err)
	}

	// ===== 参数非法仍是 REQ_INVALID，不能被折叠成 NOT_FOUND =====
	const invalidParamID = "req_step207_invalid_param"
	_, err = adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "   ", RequestID: invalidParamID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeReqInvalid {
		t.Fatalf("空用户名错误码 = %q，期望 REQ_INVALID", appError.Code())
	}
	if appError.RequestID() != invalidParamID {
		t.Fatalf("参数非法错误请求编号 = %q，期望 %q", appError.RequestID(), invalidParamID)
	}
	if IsNotFound(err) {
		t.Fatalf("参数非法不能被当成未找到: %v", err)
	}
	if _, err := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: local, RoleID: "not-a-role-id", RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法角色 ID 应返回 REQ_INVALID，实际 %v", err)
	}
	if IsNotFound(err) {
		t.Fatalf("非法角色 ID 不能被当成未找到: %v", err)
	}
	if _, err := adminAPI.EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: local, UserID: "not-a-user-id", ScopeID: "system",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法用户 ID 应返回 REQ_INVALID，实际 %v", err)
	}

	// ===== 无权限的真实会话：存在与不存在都返回 ACCESS_DENIED（防枚举） =====
	step207CreateProblemUser(t, ctx, runtime, "normal207")
	normalLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "normal207", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || normalLogin.Restricted {
		t.Fatalf("普通用户登录异常: %+v err=%v", normalLogin, err)
	}
	normalAdmin := runtime.AdminSession(normalLogin.SessionSecret)

	const deniedExistingID = "req_step207_denied_existing"
	if _, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: normalAdmin, Username: "alice", RequestID: deniedExistingID}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限查询已存在用户应返回 ACCESS_DENIED，实际 %v", err)
	} else if appError := step207AppError(t, err); appError.RequestID() != deniedExistingID {
		t.Fatalf("权限拒绝错误请求编号 = %q，期望 %q",
			appError.RequestID(), deniedExistingID)
	}
	const deniedMissingID = "req_step207_denied_missing"
	_, err = adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: normalAdmin, Username: "nobody207", RequestID: deniedMissingID})
	if !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限查询不存在用户应返回 ACCESS_DENIED，实际 %v", err)
	}
	if IsNotFound(err) {
		t.Fatalf("无权限调用者不应得到未找到语义（存在性泄露）: %v", err)
	}
	if _, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: normalAdmin, Limit: 10, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限列表应返回 ACCESS_DENIED，实际 %v", err)
	}
}

// TestAdminQueryNFKCAndCaseFolding 验证按用户名查询沿用登录一致的 NFKC + 大小写
// 折叠规则，而不是区分大小写的原始字符串匹配。
func TestAdminQueryNFKCAndCaseFolding(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	created := step207CreateProblemUser(t, ctx, runtime, "Alice")
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	for _, lookup := range []string{
		"alice", "ALICE", "aLiCe",
		"ＡＬＩＣＥ", // 全角字母（NFKC 兼容分解为 ASCII）
		"  Alice  ",
	} {
		got, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
			Caller: local, Username: lookup, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("按 %q 查询 NFKC/大小写等价用户名失败: %v", lookup, err)
		}
		if got.ID != created.ID {
			t.Fatalf("按 %q 查询得到 ID=%q，期望 %q", lookup, got.ID, created.ID)
		}
		if got.Username != "Alice" {
			t.Fatalf("按 %q 查询显示的原始用户名 = %q，期望 Alice", lookup, got.Username)
		}
	}
}

// TestAdminCallerTrustBoundaries 验证 LocalAdmin 可信宿主、正常管理员会话、跨 Runtime
// Caller、空 Caller、双模式伪造 Caller 与无效会话都按默认拒绝处理。
func TestAdminCallerTrustBoundaries(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 3, 30, 0, 0, time.UTC))
	runtimeA := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	runtimeB := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	step207CreateProblemUser(t, ctx, runtimeA, "alice")

	// LocalAdmin 是可信宿主通道：正常查询成功。
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: runtimeA.LocalAdmin(), Limit: 10,
		RequestID: "req_step207_local_host"}); err != nil {
		t.Fatalf("LocalAdmin 可信宿主查询失败: %v", err)
	}
	// 零值 Caller（空 Caller）拒绝。
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: AdminCaller{}, Limit: 10,
		RequestID: "req_step207_zero_caller"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("空 Caller 应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 跨 Runtime 的 LocalAdmin 与 AdminSession 都拒绝。
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: runtimeB.LocalAdmin(), Limit: 10,
		RequestID: "req_step207_cross_local"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("跨 Runtime LocalAdmin 应返回 ACCESS_DENIED，实际 %v", err)
	}
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: runtimeB.AdminSession([]byte("synthetic-session-secret")), Limit: 10,
		RequestID: "req_step207_cross_session"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("跨 Runtime AdminSession 应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 同时自称 LocalAdmin 且携带会话秘密的伪造组合拒绝（两种模式互斥）。
	forged := AdminCaller{runtime: runtimeA, local: true,
		sessionSecret: []byte("synthetic-session-secret")}
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: forged, Limit: 10,
		RequestID: "req_step207_forged_both"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("双模式伪造 Caller 应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 无效会话秘密拒绝。
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: runtimeA.AdminSession([]byte("synthetic-session-secret")), Limit: 10,
		RequestID: "req_step207_invalid_session"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无效会话秘密应返回 ACCESS_DENIED，实际 %v", err)
	}
	// nil Runtime 的 LocalAdmin 返回零值 Caller，不能自称可信。
	var nilRuntime *Runtime
	if _, err := runtimeA.Admin().ListUsers(ctx, AdminListUsersRequest{
		Caller: nilRuntime.LocalAdmin(), Limit: 10,
		RequestID: "req_step207_nil_runtime"}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("nil Runtime 的 LocalAdmin 应返回 ACCESS_DENIED，实际 %v", err)
	}
}

// TestAdminSessionPermissionCheckedBeforeQuery 验证真实管理员会话按当前权限判定，
// 权限检查先于目标查询，撤销权限后立即失效。
func TestAdminSessionPermissionCheckedBeforeQuery(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	step207CreateProblemUser(t, ctx, runtime, "alice")
	adminUser := step207CreateProblemUser(t, ctx, runtime, "admin207")
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// 本机受信操作者自举系统范围 users.read 权限与角色，并分配给管理员。
	readPermission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "users.read", Name: "读取用户",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建 users.read 权限失败: %v", err)
	}
	readerRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step207-reader", Name: "步骤207读取员",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建系统角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: readerRole.ID, PermissionID: readPermission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("为角色添加 users.read 失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: readerRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配系统角色给管理员失败: %v", err)
	}

	adminLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "admin207", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || adminLogin.Restricted {
		t.Fatalf("管理员登录应得到完整会话: %+v err=%v", adminLogin, err)
	}
	adminSession := runtime.AdminSession(adminLogin.SessionSecret)

	const grantRequestID = "req_step207_admin_session"
	before := step207MaxAuditRowID(t, runtime)
	page, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: adminSession, Limit: 10, Sort: "username", RequestID: grantRequestID})
	if err != nil {
		t.Fatalf("持有 users.read 的管理员会话查询失败: %v", err)
	}
	if len(page.Users) < 2 {
		t.Fatalf("管理员会话查询结果异常: %+v", page)
	}
	rows := step207AuditRowsAfter(t, runtime, "user.list", before)
	if len(rows) != 1 || rows[0].RequestID != grantRequestID ||
		rows[0].ActorType != "user" || rows[0].ActorID != adminUser.ID {
		t.Fatalf("管理员会话 user.list 审计异常: %+v", rows)
	}
	if _, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: adminSession, Username: "alice",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("持有 users.read 的管理员会话按用户名查询失败: %v", err)
	}

	// 撤销角色后同一会话立即失去权限（不缓存）：存在/不存在目标都返回拒绝。
	if err := adminAPI.RevokeApplicationRole(ctx, RevokeRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: readerRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤回管理员角色失败: %v", err)
	}
	const revokedID = "req_step207_admin_revoked"
	_, err = adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: adminSession, Username: "alice", RequestID: revokedID})
	if !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("撤销权限后查询应返回 ACCESS_DENIED，实际 %v", err)
	}
	if appError := step207AppError(t, err); appError.RequestID() != revokedID {
		t.Fatalf("撤销后拒绝错误请求编号 = %q，期望 %q", appError.RequestID(), revokedID)
	}
	if IsNotFound(err) {
		t.Fatalf("撤销权限后不能返回未找到语义: %v", err)
	}
}

// TestAdminQueryAuditFailureFailsClosed 验证领域读审计不可用时查询 fail-closed：
// 返回 AUDIT_WRITE_FAILED（带同一请求编号）且不返回用户数据、不产生假成功审计。
func TestAdminQueryAuditFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 30, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	alice := step207CreateProblemUser(t, ctx, runtime, "alice")
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// SQLite 触发器注入：所有 user.get / user.list 审计写入失败。
	if _, err := runtime.base.Store.DB().Exec(`
		CREATE TRIGGER step207_inject_read_audit_failure
		BEFORE INSERT ON audit_events
		WHEN NEW.action IN ('user.get','user.list')
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计故障失败: %v", err)
	}
	successBefore := step207AuditCount(t, runtime, "user.get")

	const auditFailID = "req_step207_audit_fail"
	user, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "alice", RequestID: auditFailID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeAuditWriteFailed {
		t.Fatalf("审计故障查询错误码 = %q，期望 AUDIT_WRITE_FAILED", appError.Code())
	}
	if appError.RequestID() != auditFailID {
		t.Fatalf("审计故障错误请求编号 = %q，期望 %q", appError.RequestID(), auditFailID)
	}
	if user.ID != "" {
		t.Fatalf("审计故障时不应返回用户数据: %+v", user)
	}
	if count := step207AuditCount(t, runtime, "user.get"); count != successBefore {
		t.Fatalf("审计故障不应产生成功审计: before=%d after=%d", successBefore, count)
	}

	_, err = adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 10, RequestID: "req_step207_audit_fail_list"})
	appError = step207AppError(t, err)
	if appError.Code() != login.CodeAuditWriteFailed {
		t.Fatalf("审计故障列表错误码 = %q，期望 AUDIT_WRITE_FAILED", appError.Code())
	}
	if appError.RequestID() != "req_step207_audit_fail_list" {
		t.Fatalf("审计故障列表请求编号 = %q，期望 req_step207_audit_fail_list",
			appError.RequestID())
	}

	// 撤销故障后同一查询恢复成功，证明未找到/失败不是数据被破坏。
	if _, err := runtime.base.Store.DB().Exec(
		`DROP TRIGGER step207_inject_read_audit_failure`); err != nil {
		t.Fatalf("撤销审计故障失败: %v", err)
	}
	recovered, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "alice", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("撤销审计故障后查询失败: %v", err)
	}
	if recovered.ID != alice.ID {
		t.Fatalf("恢复后查询 ID = %q，期望 %q", recovered.ID, alice.ID)
	}
}

// TestAdminWriteRequestIDCorrelation 验证写路径的请求编号同样贯穿领域审计与返回
// 错误（成功与冲突两条路径都不重新生成编号）。
func TestAdminWriteRequestIDCorrelation(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	const createRequestID = "req_step207_create"
	before := step207MaxAuditRowID(t, runtime)
	created, err := adminAPI.CreateUser(ctx, AdminCreateUserRequest{
		Caller: local, Username: "created207", Nickname: "被创建",
		RequestID: createRequestID})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	rows := step207AuditRowsAfter(t, runtime, "user.create", before)
	if len(rows) != 1 || rows[0].RequestID != createRequestID ||
		rows[0].TargetID != created.ID {
		t.Fatalf("user.create 审计关联异常: %+v", rows)
	}

	const conflictRequestID = "req_step207_create_conflict"
	_, err = adminAPI.CreateUser(ctx, AdminCreateUserRequest{
		Caller: local, Username: "created207", RequestID: conflictRequestID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeConflict {
		t.Fatalf("重复用户名错误码 = %q，期望 CONFLICT", appError.Code())
	}
	if appError.RequestID() != conflictRequestID {
		t.Fatalf("重复用户名错误请求编号 = %q，期望 %q",
			appError.RequestID(), conflictRequestID)
	}
}
