package serverapp

// 步骤 235：管理页账户有效期真实装配集成测试。
//
// 使用真实 OpenBase/会话/权限/账户服务/页面适配器：有权限系统管理员可看到并
// 设置有效期；旧行版本返回 conflict；root 详情隐藏表单且伪造提交被拒绝；无
// users.update 的管理会话被拒绝；缺少 CSRF 令牌的页面提交被拒绝。页面与 234
// 管理 API 共用同一 users.read/users.update 判定与账户领域服务。

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// seedValidityPageFixtures 给管理/只读用户播种 users.read/users.update 权限。
func seedValidityPageFixtures(t *testing.T, env *adminSessionsIntegrationEnv) {
	t.Helper()
	nowMS := testNow.UnixMilli()
	db := env.base.Store.DB()
	exec := func(query string, args ...any) {
		if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
			t.Fatalf("播种有效期页面权限: %v", err)
		}
	}
	exec(`INSERT OR IGNORE INTO scopes(id,kind,app_id) VALUES('system','system','')`)
	for _, permission := range []struct{ id, key string }{
		{"perm_step235_read", "users.read"},
		{"perm_step235_update", "users.update"}} {
		exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,
limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, permission.id, "system", permission.key,
			permission.key, "测试", "测试", 0, 0, 1, nowMS, nowMS)
	}
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"role_step235_admin", "system", "step235.admin", "有效期管理员", "测试",
		"测试", 0, 1, nowMS, nowMS)
	for _, permissionID := range []string{"perm_step235_read",
		"perm_step235_update"} {
		exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
			"role_step235_admin", permissionID, "system")
	}
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, asAdminID, "role_step235_admin",
		"system", nowMS)
	// 只读管理会话：只有 users.read，无 users.update。
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,
is_builtin,enabled,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"role_step235_reader", "system", "step235.reader", "只读管理员", "测试",
		"测试", 0, 1, nowMS, nowMS)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		"role_step235_reader", "perm_step235_read", "system")
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, asTargetID, "role_step235_reader",
		"system", nowMS)
}

// pageCSRFToken 从页面 HTML 提取隐藏 CSRF 令牌。
func pageCSRFToken(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("页面未包含 CSRF 隐藏字段")
	}
	return match[1]
}

// TestAdminUserValidityPageRealServices 验证真实页面/适配器/领域授权闭环。
func TestAdminUserValidityPageRealServices(t *testing.T) {
	env := newAdminSessionsIntegrationEnv(t)
	seedValidityPageFixtures(t, env)
	_, adminCookie := env.login(t, asAdminID, "", true)

	detail := env.doPage(t, http.MethodGet,
		"/admin/users/detail?user_id="+asTargetID, adminCookie, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("有效期详情 = %d body=%s", detail.Code, detail.Body.String())
	}
	body := detail.Body.String()
	for _, want := range []string{"账户有效期", `name="valid_from"`,
		`name="valid_until"`, `name="reason"`, `name="confirm"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("详情缺少 %q", want)
		}
	}
	csrf := pageCSRFToken(t, body)
	future := testNow.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	form := url.Values{"csrf_token": {csrf}, "user_id": {asTargetID},
		"expected_row_version": {"1"}, "valid_until": {future},
		"reason": {"步骤235真实页面集成测试"}, "confirm": {"yes"}}
	set := env.doPage(t, http.MethodPost, "/admin/users/validity", adminCookie, form)
	if set.Code != http.StatusSeeOther {
		t.Fatalf("设置有效期 = %d body=%s", set.Code, set.Body.String())
	}
	var validUntilMS *int64
	if err := env.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT valid_until_ms FROM users WHERE id=?`, asTargetID).Scan(&validUntilMS); err != nil {
		t.Fatalf("读取有效期: %v", err)
	}
	if validUntilMS == nil || *validUntilMS != testNow.Add(24*time.Hour).UnixMilli() {
		t.Fatalf("有效期未落库: %v", validUntilMS)
	}
	// 页面变更理由审计：真实操作者/理由/请求编号在同一事件中。
	var actorID, requestID, detailJSON string
	if err := env.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT actor_id,request_id,detail_json FROM audit_events
WHERE action='user.validity.set.requested' ORDER BY occurred_at_ms DESC LIMIT 1`).
		Scan(&actorID, &requestID, &detailJSON); err != nil {
		t.Fatalf("读取有效期变更审计: %v", err)
	}
	if actorID != asAdminID || requestID == "" ||
		!strings.Contains(detailJSON, "步骤235真实页面集成测试") ||
		!strings.Contains(detailJSON, "valid_until") {
		t.Fatalf("变更理由审计异常: actor=%q request=%q detail=%s", actorID,
			requestID, detailJSON)
	}
	// 旧行版本：conflict。
	conflict := env.doPage(t, http.MethodPost, "/admin/users/validity", adminCookie, form)
	if conflict.Code != http.StatusBadRequest ||
		!strings.Contains(conflict.Body.String(), "数据已被其他操作修改") {
		t.Fatalf("旧版本冲突 = %d body=%s", conflict.Code, conflict.Body.String())
	}
	// root：详情隐藏表单，伪造提交被拒绝。
	rootDetail := env.doPage(t, http.MethodGet,
		"/admin/users/detail?user_id="+asRootID, adminCookie, nil)
	if rootDetail.Code != http.StatusOK ||
		!strings.Contains(rootDetail.Body.String(), "root 账户不接受普通期限管理") ||
		strings.Contains(rootDetail.Body.String(), `name="valid_from"`) {
		t.Fatalf("root 详情异常 = %d", rootDetail.Code)
	}
	rootForm := url.Values{"csrf_token": {pageCSRFToken(t, rootDetail.Body.String())},
		"user_id": {asRootID}, "expected_row_version": {"1"},
		"valid_until": {future}, "reason": {"root 伪造设置"}, "confirm": {"yes"}}
	rootSet := env.doPage(t, http.MethodPost, "/admin/users/validity", adminCookie, rootForm)
	if rootSet.Code != http.StatusForbidden {
		t.Fatalf("root 设置 = %d body=%s", rootSet.Code, rootSet.Body.String())
	}
	// 只读管理员：详情可读，设置被拒绝。
	_, readerCookie := env.login(t, asTargetID, "", true)
	readerDetail := env.doPage(t, http.MethodGet,
		"/admin/users/detail?user_id="+asTargetID, readerCookie, nil)
	if readerDetail.Code != http.StatusOK {
		t.Fatalf("只读管理员详情 = %d body=%s", readerDetail.Code, readerDetail.Body.String())
	}
	readerForm := url.Values{"csrf_token": {pageCSRFToken(t, readerDetail.Body.String())},
		"user_id": {asTargetID}, "expected_row_version": {"2"},
		"valid_until": {future}, "reason": {"越权设置"}, "confirm": {"yes"}}
	readerSet := env.doPage(t, http.MethodPost, "/admin/users/validity", readerCookie, readerForm)
	if readerSet.Code != http.StatusForbidden {
		t.Fatalf("只读管理员设置 = %d body=%s", readerSet.Code, readerSet.Body.String())
	}
	// 缺少 CSRF：拒绝且不写入。
	before := *validUntilMS
	noCSRF := url.Values{"user_id": {asTargetID}, "expected_row_version": {"2"},
		"valid_until": {testNow.Add(48 * time.Hour).UTC().Format(time.RFC3339)},
		"reason":      {"缺少 CSRF"}, "confirm": {"yes"}}
	missingCSRF := env.doPage(t, http.MethodPost, "/admin/users/validity", adminCookie, noCSRF)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF = %d", missingCSRF.Code)
	}
	var afterMS *int64
	if err := env.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT valid_until_ms FROM users WHERE id=?`, asTargetID).Scan(&afterMS); err != nil {
		t.Fatalf("复核有效期: %v", err)
	}
	if afterMS == nil || *afterMS != before {
		t.Fatalf("缺少 CSRF 不得写入: before=%v after=%v", before, afterMS)
	}
}
