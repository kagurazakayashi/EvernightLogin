package serverapp

// 步骤 233：管理 API 脱敏诊断领域路由的授权与范围集成测试。
//
// 使用真实 OpenBase（临时 SQLite + 真实权限引擎/审计/会话依赖），直接调用
// DomainRoute 处理器验证：持有 diagnostics.read 的用户可读脱敏报告；无权限用户
// 被拒绝；非法范围返回 REQ_INVALID；输出不包含合成秘密/个人资料。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

const diagRouteAdminID = "usr_000000000000000000000000000000f1"
const diagRouteDeniedID = "usr_000000000000000000000000000000f2"

// newDiagnosticsRouteEnv 打开真实共享装配并播种 diagnostics.read 权限图。
func newDiagnosticsRouteEnv(t *testing.T) (*Base, []adminapi.DomainRoute) {
	t.Helper()
	base, err := OpenBase(context.Background(), BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	nowMS := testNow.UnixMilli()
	db := base.Store.DB()
	exec := func(query string, args ...any) {
		if _, execErr := db.ExecContext(context.Background(), query, args...); execErr != nil {
			t.Fatalf("播种诊断路由夹具: %v", execErr)
		}
	}
	for _, user := range []struct{ id, username string }{
		{diagRouteAdminID, "diag-route-admin"},
		{diagRouteDeniedID, "diag-route-denied"},
	} {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, user.id, user.username, user.username, nowMS, nowMS)
	}
	exec(`INSERT OR IGNORE INTO scopes(id,kind,app_id) VALUES('system','system','')`)
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "perm_diag_route_read", "system",
		"diagnostics.read", "查看运行诊断", "测试", "测试", 0, 0, 1, nowMS, nowMS)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,
enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"role_diag_route_reader", "system", "diag.route.reader", "诊断读者", "测试",
		"测试", 0, 1, nowMS, nowMS)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,?)`, "role_diag_route_reader", "perm_diag_route_read", "system")
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, diagRouteAdminID,
		"role_diag_route_reader", "system", nowMS)
	// 合成秘密/个人资料夹具：用于验证路由响应不泄露。
	exec(`INSERT INTO jobs(id,kind,state,initiated_by_type,initiated_by_id,
timeout_seconds,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?)`,
		"diag-route-job", "mail.delivery", "queued", "system", "diag-route", 30,
		nowMS, nowMS)
	exec(`INSERT INTO mail_deliveries(id,idempotency_key,template_kind,recipient,
owner_type,owner_id,state,sealed_payload,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "diag-route-mail", "diag-route-idem", "verification",
		"diag-route@example.test", "user", "usr_000000000000000000000000000000f9",
		"queued", []byte("sealed-diag-route-secret"), nowMS, nowMS)
	exec(`INSERT INTO audit_events(id,occurred_at_ms,actor_type,actor_id,action,
target_type,target_id,outcome,error_code,reason_code,request_id,detail_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, "diag-route-audit", nowMS, "user",
		"usr_000000000000000000000000000000f9", "diag.error", "user", "target",
		"failure", "AUTH_FAILED", "bad_credentials", "req_diag_route_1",
		`{"token":"diag-route-secret"}`)
	return base, buildAdminDiagnosticsRoutes(base.Deps, base.Managed)
}

// routeByPattern 返回指定模式的诊断路由。
func routeByPattern(routes []adminapi.DomainRoute, pattern string) adminapi.DomainRoute {
	for _, route := range routes {
		if route.Method == http.MethodGet && route.Pattern == pattern {
			return route
		}
	}
	return adminapi.DomainRoute{}
}

// TestDiagnosticsDomainRoutesAuthorization 验证持有/缺少 diagnostics.read 的用户。
func TestDiagnosticsDomainRoutesAuthorization(t *testing.T) {
	base, routes := newDiagnosticsRouteEnv(t)
	readRoute := routeByPattern(routes, "diagnostics")
	errorRoute := routeByPattern(routes, "diagnostics/errors")
	exportRoute := routeByPattern(routes, "diagnostics/export")
	if readRoute.Handler == nil || errorRoute.Handler == nil || exportRoute.Handler == nil {
		t.Fatalf("诊断路由未注册: %+v", routes)
	}
	caller, err := account.UserCaller(diagRouteAdminID)
	if err != nil {
		t.Fatalf("构造调用者: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/diagnostics", nil)
	result, routeErr := readRoute.Handler(context.Background(), caller, request)
	if routeErr != nil {
		t.Fatalf("有权限用户读取诊断失败: %v", routeErr)
	}
	raw, _ := json.Marshal(result)
	output := string(raw)
	for _, forbidden := range []string{"diag-route-secret", "diag-route@example.test",
		"usr_000000000000000000000000000000f9"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("诊断响应泄露 %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, `"status":"ok"`) ||
		!strings.Contains(output, `"jobs"`) {
		t.Fatalf("诊断响应缺少预期字段: %s", output)
	}

	// 无权限用户：ACCESS_DENIED。
	deniedCaller, _ := account.UserCaller(diagRouteDeniedID)
	if _, deniedErr := readRoute.Handler(context.Background(), deniedCaller,
		request); !domainErrorCode(deniedErr, "ACCESS_DENIED") {
		t.Fatalf("无权限用户应被拒绝: %v", deniedErr)
	}

	// 关联错误：白名单字段；非法范围/limit 返回 REQ_INVALID。
	errorRequest := httptest.NewRequest(http.MethodGet,
		"/admin/v1/diagnostics/errors?request_id=req_diag_route_1&limit=1", nil)
	errorResult, errorErr := errorRoute.Handler(context.Background(), caller, errorRequest)
	if errorErr != nil {
		t.Fatalf("关联错误查询失败: %v", errorErr)
	}
	errorRaw, _ := json.Marshal(errorResult)
	if strings.Contains(string(errorRaw), "diag-route-secret") ||
		!strings.Contains(string(errorRaw), "AUTH_FAILED") {
		t.Fatalf("关联错误响应异常: %s", errorRaw)
	}
	invalidScope := httptest.NewRequest(http.MethodGet,
		"/admin/v1/diagnostics?scope=not-an-app", nil)
	if _, scopeErr := readRoute.Handler(context.Background(), caller, invalidScope); !domainErrorCode(scopeErr, "REQ_INVALID") {
		t.Fatalf("非法范围应返回 REQ_INVALID: %v", scopeErr)
	}
	invalidLimit := httptest.NewRequest(http.MethodGet,
		"/admin/v1/diagnostics/errors?request_id=req_diag_route_1&limit=999", nil)
	if _, limitErr := errorRoute.Handler(context.Background(), caller, invalidLimit); !domainErrorCode(limitErr, "REQ_INVALID") {
		t.Fatalf("非法 limit 应返回 REQ_INVALID: %v", limitErr)
	}
	// 导出：有界脱敏。
	exportRequest := httptest.NewRequest(http.MethodGet,
		"/admin/v1/diagnostics/export?request_id=req_diag_route_1&limit=1", nil)
	exportResult, exportErr := exportRoute.Handler(context.Background(), caller, exportRequest)
	if exportErr != nil {
		t.Fatalf("诊断导出失败: %v", exportErr)
	}
	exportRaw, _ := json.Marshal(exportResult)
	if strings.Contains(string(exportRaw), "diag-route-secret") {
		t.Fatalf("诊断导出泄露秘密: %s", exportRaw)
	}
	_ = base
}

// domainErrorCode 判断领域路由错误是否为指定稳定码。
func domainErrorCode(err error, code string) bool {
	domainErr, ok := err.(*adminapi.DomainError)
	return ok && domainErr.Code == code
}
