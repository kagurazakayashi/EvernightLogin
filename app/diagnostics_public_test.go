package app

// 步骤 233：脱敏运行诊断公开门面的授权、范围与脱敏测试。
//
// 使用真实临时 SQLite + 真实运行时：LocalAdmin 本地受信边界成功；普通用户业务
// 会话因缺少管理强认证与 diagnostics.read 被拒绝；合成秘密/邮箱/审计 detail 与
// 数据库路径不得出现在公开结果中。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const diagSyntheticSecret = "SYNTHETIC-DIAG-PUBLIC-SECRET-42"
const diagSyntheticEmail = "diag-public@example.test"

// seedDiagnosticsPublicFixtures 写入队列与审计夹具（含合成秘密/个人资料）。
func seedDiagnosticsPublicFixtures(t *testing.T, runtime *Runtime) {
	t.Helper()
	db := runtime.base.Store.DB()
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := db.Exec(`INSERT INTO jobs(id,kind,state,initiated_by_type,initiated_by_id,
timeout_seconds,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?)`,
		"diag-job-1", "mail.delivery", "queued", "system", "diag-test", 30, nowMS, nowMS); err != nil {
		t.Fatalf("写入任务夹具: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mail_deliveries(id,idempotency_key,template_kind,
recipient,owner_type,owner_id,state,sealed_payload,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "diag-mail-1", "diag-idem-1", "verification",
		diagSyntheticEmail, "user", "usr_00000000000000000000000000000091", "queued",
		[]byte("sealed-"+diagSyntheticSecret), nowMS, nowMS); err != nil {
		t.Fatalf("写入邮件夹具: %v", err)
	}
	detail := `{"smtp_password":"` + diagSyntheticSecret + `"}`
	if _, err := db.Exec(`INSERT INTO audit_events(id,occurred_at_ms,actor_type,actor_id,
action,target_type,target_id,outcome,error_code,reason_code,request_id,detail_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, "diag-audit-1", nowMS, "user",
		"usr_00000000000000000000000000000091", "diag.error", "user", "target",
		"failure", "AUTH_FAILED", "bad_credentials", "req_diag_public_1", detail); err != nil {
		t.Fatalf("写入审计夹具: %v", err)
	}
}

// TestDiagnosticsLocalAdminRedaction 验证 LocalAdmin 成功路径与脱敏白名单。
func TestDiagnosticsLocalAdminRedaction(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	seedDiagnosticsPublicFixtures(t, runtime)
	report, err := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: runtime.LocalAdmin(), RequestID: "req_diag_read_1"})
	if err != nil {
		t.Fatalf("LocalAdmin 诊断读取失败: %v", err)
	}
	if report.ScopeKind != "system" || report.ScopeID != "system" || report.ScopeID == "" {
		t.Fatalf("诊断范围异常: %+v", report)
	}
	if report.Storage.Status != "ok" || len(report.Queues.Jobs) == 0 ||
		len(report.Queues.MailDeliveries) == 0 {
		t.Fatalf("诊断区段缺失: %+v", report)
	}
	raw, _ := json.Marshal(report)
	output := string(raw)
	for _, forbidden := range []string{diagSyntheticSecret, diagSyntheticEmail,
		"usr_00000000000000000000000000000091", "target", "detail_json",
		"sealed-"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("诊断输出泄露 %q: %s", forbidden, output)
		}
	}
	// 关联错误查询：白名单字段、有界、无 detail/actor。
	list, err := runtime.Diagnostics().RelatedErrors(ctx, DiagnosticsErrorsRequest{
		Caller: runtime.LocalAdmin(), ErrorRequestID: "req_diag_public_1",
		Limit: 1, RequestID: "req_diag_errors_1"})
	if err != nil {
		t.Fatalf("关联错误查询失败: %v", err)
	}
	if list.Status != "ok" || len(list.Entries) != 1 || list.Entries[0].ErrorCode != "AUTH_FAILED" {
		t.Fatalf("关联错误结果异常: %+v", list)
	}
	listRaw, _ := json.Marshal(list)
	for _, forbidden := range []string{diagSyntheticSecret, diagSyntheticEmail,
		"usr_00000000000000000000000000000091", "target"} {
		if strings.Contains(string(listRaw), forbidden) {
			t.Fatalf("关联错误泄露 %q: %s", forbidden, listRaw)
		}
	}
	// 应用范围：明确 scope 生效且仍为系统级本地受信读取。
	appScope, err := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: runtime.LocalAdmin(), ScopeID: "app_000000000000000000000000000000e1"})
	if err != nil {
		t.Fatalf("应用范围诊断失败: %v", err)
	}
	if appScope.ScopeKind != "application" || appScope.ScopeID != "app_000000000000000000000000000000e1" {
		t.Fatalf("应用范围诊断结果异常: %+v", appScope)
	}
	if _, err := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: runtime.LocalAdmin(), ScopeID: "not-an-app"}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法范围应返回 REQ_INVALID: %v", err)
	}
}

// TestDiagnosticsSessionRequiresManagementAuth 验证普通业务会话不能读取诊断。
func TestDiagnosticsSessionRequiresManagementAuth(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "diag-denied-user", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	result, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: user.Username, Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录: %v", err)
	}
	caller := runtime.AdminSession(result.SessionSecret)
	_, err = runtime.Diagnostics().Read(ctx, DiagnosticsRequest{Caller: caller,
		RequestID: "req_diag_denied_1"})
	if err == nil {
		t.Fatal("普通用户业务会话不得读取运行诊断")
	}
	if !login.IsErrorCode(err, login.CodeAccessDenied) &&
		!login.IsErrorCode(err, login.CodeReauthRequired) &&
		!login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("拒绝错误码异常: %v", err)
	}
	// 伪造/跨运行时调用者一律拒绝。
	forged := AdminCaller{}
	if _, err := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{Caller: forged}); err == nil {
		t.Fatal("零值 AdminCaller 不得读取诊断")
	}
	other := openTestRuntime(t, Options{})
	if _, err := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: other.LocalAdmin()}); err == nil {
		t.Fatal("其他 Runtime 的本地管理员不得读取本运行时诊断")
	}
}

// TestDiagnosticsExportBounded 验证导出只返回有界脱敏数据。
func TestDiagnosticsExportBounded(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	seedDiagnosticsPublicFixtures(t, runtime)
	export, err := runtime.Diagnostics().Export(ctx, DiagnosticsErrorsRequest{
		Caller: runtime.LocalAdmin(), ErrorRequestID: "req_diag_public_1",
		Limit: 1, RequestID: "req_diag_export_1"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if export.Report.Status == "" || export.Errors == nil ||
		len(export.Errors.Entries) != 1 {
		t.Fatalf("导出结果异常: %+v", export)
	}
	raw, _ := json.Marshal(export)
	if strings.Contains(string(raw), diagSyntheticSecret) ||
		strings.Contains(string(raw), diagSyntheticEmail) {
		t.Fatalf("导出泄露合成秘密: %s", raw)
	}
}

// TestDiagnosticsManagementSessionWithPermission 验证真实管理强认证会话 +
// diagnostics.read 权限在公开门面中可读取脱敏诊断。
func TestDiagnosticsManagementSessionWithPermission(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "diag-managed-admin", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	nowMS := time.Now().UTC().UnixMilli()
	exec := func(query string, args ...any) {
		if _, execErr := runtime.base.Store.DB().ExecContext(ctx, query, args...); execErr != nil {
			t.Fatalf("播种诊断权限: %v", execErr)
		}
	}
	exec(`INSERT OR IGNORE INTO scopes(id,kind,app_id) VALUES('system','system','')`)
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"perm_diag_public_read", "system", "diagnostics.read", "查看运行诊断", "测试",
		"测试", 0, 0, 1, nowMS, nowMS)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,
enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"role_diag_public_reader", "system", "diag.public.reader", "诊断读者", "测试",
		"测试", 0, 1, nowMS, nowMS)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		"role_diag_public_reader", "perm_diag_public_read", "system")
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, user.ID, "role_diag_public_reader",
		"system", nowMS)
	now := time.Now().UTC()
	issued, loginErr := runtime.coreServices().Sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: user.ID, Username: user.Username,
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      now, StrongAuthCompletedAt: now, SecurityVersion: 1},
		RequestID: "req_diag_managed_login"})
	if loginErr != nil {
		t.Fatalf("签发管理强认证会话: %v", loginErr)
	}
	secret := []byte(issued.Secret.Reveal())
	report, readErr := runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: runtime.AdminSession(secret), RequestID: "req_diag_managed_read"})
	if readErr != nil {
		t.Fatalf("有权限管理会话读取诊断失败: %v", readErr)
	}
	if report.Status == "" || report.Storage.Status == "" {
		t.Fatalf("诊断报告不完整: %+v", report)
	}
}
