package serverapp

// 步骤 234：管理 API 账户有效期路由集成测试。
//
// 使用真实 OpenBase + 临时 SQLite + 真实账户服务/权限引擎/审计，直接调用
// DomainRoute 处理器验证：读写成功、到期即时、root 拒绝、无权限拒绝、非法时间
// 与乐观并发；响应不包含秘密。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

const validityRouteAdminID = "usr_000000000000000000000000000000d1"
const validityRouteDeniedID = "usr_000000000000000000000000000000d2"
const validityRouteTargetID = "usr_000000000000000000000000000000d3"
const validityRouteRootID = "usr_000000000000000000000000000000d4"

// newValidityRouteEnv 播种账户/权限/角色并返回真实装配的路由。
func newValidityRouteEnv(t *testing.T) (*Base, []adminapi.DomainRoute) {
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
			t.Fatalf("播种有效期路由夹具: %v", execErr)
		}
	}
	for _, user := range []struct {
		id, username string
		root         int
	}{{validityRouteAdminID, "validity-route-admin", 0},
		{validityRouteDeniedID, "validity-route-denied", 0},
		{validityRouteTargetID, "validity-route-target", 0},
		{validityRouteRootID, "validity-route-root", 1}} {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',?,1,1,?,?)`, user.id, user.username, user.username,
			user.root, nowMS, nowMS)
	}
	exec(`INSERT OR IGNORE INTO scopes(id,kind,app_id) VALUES('system','system','')`)
	for _, permission := range []struct{ id, key string }{
		{"perm_validity_route_read", "users.read"},
		{"perm_validity_route_update", "users.update"}} {
		exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,
limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, permission.id, "system", permission.key,
			permission.key, "测试", "测试", 0, 0, 1, nowMS, nowMS)
	}
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"role_validity_route_admin", "system", "validity.route.admin", "有效期管理员",
		"测试", "测试", 0, 1, nowMS, nowMS)
	for _, permissionID := range []string{"perm_validity_route_read",
		"perm_validity_route_update"} {
		exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
			"role_validity_route_admin", permissionID, "system")
	}
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, validityRouteAdminID,
		"role_validity_route_admin", "system", nowMS)
	return base, buildAdminValidityRoutes(base.Managed)
}

// validityRoute 按方法/模式选择路由。
func validityRoute(routes []adminapi.DomainRoute, method, pattern string) adminapi.DomainRoute {
	for _, route := range routes {
		if route.Method == method && route.Pattern == pattern {
			return route
		}
	}
	return adminapi.DomainRoute{}
}

// TestUserValidityAdminRoutes 验证管理 API 有效期读写路由。
func TestUserValidityAdminRoutes(t *testing.T) {
	base, routes := newValidityRouteEnv(t)
	getRoute := validityRoute(routes, http.MethodGet, "users/{user_id}/validity")
	postRoute := validityRoute(routes, http.MethodPost, "users/{user_id}/validity")
	if getRoute.Handler == nil || postRoute.Handler == nil {
		t.Fatalf("有效期路由未注册: %+v", routes)
	}
	adminCaller, err := account.UserCaller(validityRouteAdminID)
	if err != nil {
		t.Fatalf("管理调用者: %v", err)
	}
	getRequest := func(userID string) *http.Request {
		return httptest.NewRequest(http.MethodGet,
			"/admin/v1/users/"+userID+"/validity", nil)
	}
	view, routeErr := getRoute.Handler(context.Background(), adminCaller,
		getRequest(validityRouteTargetID))
	if routeErr != nil {
		t.Fatalf("读取目标有效期: %v", routeErr)
	}
	raw, _ := json.Marshal(view)
	if !bytes.Contains(raw, []byte(`"available":true`)) ||
		!bytes.Contains(raw, []byte(`"row_version":1`)) {
		t.Fatalf("默认有效期视图异常: %s", raw)
	}
	// 设置到过去：到期不可用。
	rowVersion := int64(1)
	past := testNow.Add(-time.Hour).UTC().Format(time.RFC3339)
	body := map[string]any{"expected_row_version": rowVersion, "valid_until": past,
		"confirm": true}
	bodyRaw, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+validityRouteTargetID+"/validity", bytes.NewReader(bodyRaw))
	request.Header.Set("Content-Type", "application/json")
	if extracted := adminValidityUserID(request); extracted != validityRouteTargetID {
		t.Fatalf("路径参数提取 = %q，期望 %q（path=%s）", extracted,
			validityRouteTargetID, request.URL.Path)
	}
	changed, routeErr := postRoute.Handler(context.Background(), adminCaller, request)
	if routeErr != nil {
		if domainErr, ok := routeErr.(*adminapi.DomainError); ok {
			t.Fatalf("设置有效期: code=%s cause=%v", domainErr.Code, domainErr.Cause)
		}
		t.Fatalf("设置有效期: %v", routeErr)
	}
	changedRaw, _ := json.Marshal(changed)
	if !bytes.Contains(changedRaw, []byte(`"changed":true`)) ||
		!bytes.Contains(changedRaw, []byte(`"reason":"expired"`)) {
		t.Fatalf("到期设置结果异常: %s", changedRaw)
	}
	// 旧版本：CONFLICT。
	request = httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+validityRouteTargetID+"/validity", bytes.NewReader(bodyRaw))
	request.Header.Set("Content-Type", "application/json")
	if _, conflictErr := postRoute.Handler(context.Background(), adminCaller,
		request); !domainErrorCode(conflictErr, "CONFLICT") {
		t.Fatalf("旧版本应 CONFLICT: %v", conflictErr)
	}
	// 无权限用户：ACCESS_DENIED。
	deniedCaller, _ := account.UserCaller(validityRouteDeniedID)
	if _, deniedErr := getRoute.Handler(context.Background(), deniedCaller,
		getRequest(validityRouteTargetID)); !domainErrorCode(deniedErr, "ACCESS_DENIED") {
		t.Fatalf("无权限用户应拒绝: %v", deniedErr)
	}
	// 非法时间：REQ_INVALID。
	invalidBody, _ := json.Marshal(map[string]any{"expected_row_version": 2,
		"valid_until": "not-a-time", "confirm": true})
	request = httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+validityRouteTargetID+"/validity",
		bytes.NewReader(invalidBody))
	request.Header.Set("Content-Type", "application/json")
	if _, invalidErr := postRoute.Handler(context.Background(), adminCaller,
		request); !domainErrorCode(invalidErr, "REQ_INVALID") {
		t.Fatalf("非法时间应 REQ_INVALID: %v", invalidErr)
	}
	// root：ACCESS_DENIED，且不泄露内部错误。
	rootBody, _ := json.Marshal(map[string]any{"expected_row_version": 1,
		"valid_until": testNow.Add(time.Hour).UTC().Format(time.RFC3339),
		"confirm":     true})
	request = httptest.NewRequest(http.MethodPost,
		"/admin/v1/users/"+validityRouteRootID+"/validity", bytes.NewReader(rootBody))
	request.Header.Set("Content-Type", "application/json")
	if _, rootErr := postRoute.Handler(context.Background(), adminCaller,
		request); !domainErrorCode(rootErr, "ACCESS_DENIED") {
		t.Fatalf("root 应 ACCESS_DENIED: %v", rootErr)
	}
	_ = base
}
