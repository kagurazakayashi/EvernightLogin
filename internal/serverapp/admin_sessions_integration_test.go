package serverapp

// 步骤 187 生产装配集成测试：真实 SQLite + 真实会话/权限/敏感闸门 + 真实页面框架
// （OpenBase + BuildPages），验证管理员强制下线页面闭环：
//   - 正常管理强认证 + 显式确认执行撤销；目标旧 Cookie/CSRF/会话秘密立即失效；
//   - 跨应用范围撤销按幂等 0（不越权）、未授权范围拒绝、root/受保护目标拒绝；
//   - 重复撤销返回 0 且页面明确“不代表发生了撤销”；审计记录真实管理员操作者。
//
// 测试数据全部为合成用户/临时数据库；不读取真实业务库。

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// adminSessionsTestIDs 是本测试使用的合成稳定 ID。
const (
	asAdminID     = "usr_000000000000000000000000000000d1"
	asTargetID    = "usr_000000000000000000000000000000d2"
	asAppAdminID  = "usr_000000000000000000000000000000d3"
	asRootID      = "usr_000000000000000000000000000000d4"
	asProtectedID = "usr_000000000000000000000000000000d5"
	asAppA        = "app_000000000000000000000000000000e1"
	asAppB        = "app_000000000000000000000000000000e2"
)

// newAdminSessionsIntegrationEnv 打开真实共享装配、写入合成权限图并构造页面。
type adminSessionsIntegrationEnv struct {
	base  *Base
	pages *Pages
	web   *httptest.Server
}

func newAdminSessionsIntegrationEnv(t *testing.T) *adminSessionsIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	seedAdminSessionsFixtures(t, base)
	pages, err := BuildPages(base.Deps, base.Services, base.Managed, base.Security,
		base.Gate, nil)
	if err != nil {
		t.Fatalf("BuildPages: %v", err)
	}
	web := httptest.NewServer(pages.WebUI)
	t.Cleanup(web.Close)
	return &adminSessionsIntegrationEnv{base: base, pages: pages, web: web}
}

// seedAdminSessionsFixtures 写入系统/应用范围的 sessions.revoke 权限、角色与用户。
func seedAdminSessionsFixtures(t *testing.T, base *Base) {
	t.Helper()
	nowMS := testNow.UnixMilli()
	db := base.Store.DB()
	exec := func(query string, args ...any) {
		if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
			t.Fatalf("播种测试数据失败: %v", err)
		}
	}
	for _, user := range []struct {
		id, username string
		root         int
	}{
		{asAdminID, "as-admin", 0}, {asTargetID, "as-target", 0},
		{asAppAdminID, "as-app-admin", 0}, {asRootID, "as-root", 1},
		{asProtectedID, "as-protected", 0},
	} {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',?,1,1,?,?)`, user.id, user.username, user.username, user.root, nowMS, nowMS)
	}
	for _, app := range []struct{ id, name string }{{asAppA, "强制下线应用甲"}, {asAppB, "强制下线应用乙"}} {
		exec(`INSERT INTO applications(id,name,description,owner_user_id,status,client_type,
row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?,'active','confidential',1,?,?)`,
			app.id, app.name, "测试应用", asAdminID, nowMS, nowMS)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, app.id, app.id)
	}
	// 目标用户是应用 A/B 的有效成员，用于签发应用范围会话。
	profileJSON := `{"display_name":""}`
	for _, appID := range []string{asAppA, asAppB} {
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active',?,1,?,?)`,
			appID, asTargetID, profileJSON, nowMS, nowMS)
	}
	// 系统范围：sessions.revoke 角色赋给系统管理员；roles.manage 角色赋给受保护目标。
	exec(`INSERT OR IGNORE INTO scopes(id,kind,app_id) VALUES('system','system','')`)
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES('perm_as_sessions_revoke','system','sessions.revoke','强制下线会话','测试','测试',0,0,1,?,?)`,
		nowMS, nowMS)
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES('perm_as_roles_manage','system','roles.manage','管理角色','测试','测试',0,0,1,?,?)`,
		nowMS, nowMS)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,
enabled,created_at_ms,updated_at_ms)
VALUES('role_as_sessions_admin','system','as.sessions.admin','会话管理员','测试','无限',0,1,?,?)`,
		nowMS, nowMS)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,
enabled,created_at_ms,updated_at_ms)
VALUES('role_as_protected','system','as.protected','受保护管理角色','测试','无限',0,1,?,?)`,
		nowMS, nowMS)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES('role_as_sessions_admin','perm_as_sessions_revoke','system')`)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES('role_as_protected','perm_as_roles_manage','system')`)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, asAdminID, "role_as_sessions_admin", "system", nowMS)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, asProtectedID, "role_as_protected", "system", nowMS)
	// 应用 A 范围：应用管理员持有该应用范围的 sessions.revoke（应用 B 未授权）。
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,
is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES('perm_as_app_a_revoke',?,'sessions.revoke','应用内强制下线','测试','测试',0,0,1,?,?)`,
		asAppA, nowMS, nowMS)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,
enabled,created_at_ms,updated_at_ms)
VALUES('role_as_app_a_admin',?,'app.admin','应用管理员','测试','无限',0,1,?,?)`, asAppA, nowMS, nowMS)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES('role_as_app_a_admin','perm_as_app_a_revoke',?)`, asAppA)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,
created_at_ms) VALUES(?,?,?,'{}','test',?)`, asAppAdminID, "role_as_app_a_admin", asAppA, nowMS)
	exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active',?,1,?,?)`, asAppA, asAppAdminID, profileJSON, nowMS, nowMS)
}

// login 使用真实会话服务签发普通/强认证会话。
func (e *adminSessionsIntegrationEnv) login(t *testing.T, userID, appID string,
	strong bool) (session.IssuedSession, *http.Cookie) {
	t.Helper()
	result := authn.AuthenticateResult{UserID: userID, Username: userID,
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testNow, SecurityVersion: 1}
	if strong {
		result.StrongAuthCompletedAt = testNow
	}
	issued, err := e.base.Services.Sessions.Login(context.Background(), session.LoginRequest{
		Result: result, AppID: appID})
	if err != nil {
		t.Fatalf("签发会话失败: %v", err)
	}
	cookie, err := e.base.Services.Sessions.NewCookie(issued)
	if err != nil {
		t.Fatalf("构造 Cookie 失败: %v", err)
	}
	return issued, cookie
}

// stronglyAuthenticatedContext 为直接调用领域服务的测试补上真实 reauth 信号
// （页面/CLI 路径分别由页面证据与 186 证明注入；这里等价于强认证新鲜且已确认）。
func stronglyAuthenticatedContext() context.Context {
	return reauth.WithSignals(context.Background(), reauth.Signals{
		VerifiedAt: testNow, Strength: policy.StrengthStrong, Complete: true, Confirmed: true})
}

// doPage 执行页面请求。
func (e *adminSessionsIntegrationEnv) doPage(t *testing.T, method, target string,
	cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	request, err := http.NewRequest(method, e.web.URL+target, body)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	e.web.Config.Handler.ServeHTTP(recorder, request)
	return recorder
}

// TestAdminSessionsPageIntegrationRealServices 验证页面闭环与旧凭据失效证据。
func TestAdminSessionsPageIntegrationRealServices(t *testing.T) {
	env := newAdminSessionsIntegrationEnv(t)
	adminSession, adminCookie := env.login(t, asAdminID, "", true)
	oldTarget, oldCookie := env.login(t, asTargetID, asAppA, false)

	// 旧 CSRF：撤销前签发页面令牌，撤销后必须失效。
	oldCSRF, err := env.base.Services.Sessions.IssuePageCSRFToken(context.Background(),
		oldTarget.Secret.Reveal())
	if err != nil {
		t.Fatalf("签发页面 CSRF 失败: %v", err)
	}
	oldCSRFRequest, _ := http.NewRequest(http.MethodPost, "http://example.test/", nil)
	oldCSRFRequest.AddCookie(oldCookie)

	// 页面查询：显示目标活动会话（系统范围）。
	list := env.doPage(t, http.MethodGet, "/admin/sessions?target_user_id="+asTargetID,
		adminCookie, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), oldTarget.Session.ID) {
		t.Fatalf("页面查询失败: %d %s", list.Code, truncateBody(list.Body.String()))
	}
	// 撤销目标全部会话（系统范围）：显式确认 + 理由；再次认证来自页面会话解析登记的
	// 新鲜管理强认证事实（真实 SecurityGate/reauth 链）。
	revoke := env.doPage(t, http.MethodPost, "/admin/sessions/revoke", adminCookie, url.Values{
		"mode": {"user"}, "target_user_id": {asTargetID},
		"reason": {"安全事件处置"}, "confirm": {"yes"},
	})
	if revoke.Code != http.StatusOK || !strings.Contains(revoke.Body.String(), "已撤销活动会话数") {
		t.Fatalf("页面撤销失败: %d %s", revoke.Code, truncateBody(revoke.Body.String()))
	}

	// 旧会话秘密 / 旧 CSRF / 旧 Cookie 全部不能继续操作。
	if _, err := env.base.Services.Sessions.Validate(context.Background(),
		oldTarget.Secret.Reveal()); err == nil {
		t.Fatal("撤销后旧会话秘密仍然有效")
	}
	if err := env.base.Services.Sessions.ValidateCSRFToken(context.Background(),
		oldCSRFRequest, oldCSRF.Reveal()); err == nil {
		t.Fatal("撤销后旧 CSRF 令牌仍然有效")
	}
	expired := env.doPage(t, http.MethodGet, "/account/sessions", oldCookie, nil)
	if expired.Code != http.StatusUnauthorized && expired.Code != http.StatusForbidden {
		t.Fatalf("撤销后旧 Cookie 访问应 401/403，实际 %d", expired.Code)
	}

	// 重复撤销：幂等 0，页面明确不代表发生了撤销。
	repeat := env.doPage(t, http.MethodPost, "/admin/sessions/revoke", adminCookie, url.Values{
		"mode": {"user"}, "target_user_id": {asTargetID},
		"reason": {"重复处置"}, "confirm": {"yes"},
	})
	if repeat.Code != http.StatusOK || !strings.Contains(repeat.Body.String(), "不代表发生了撤销") {
		t.Fatalf("重复撤销应显示幂等说明: %d %s", repeat.Code, truncateBody(repeat.Body.String()))
	}

	// 跨应用：应用 A 管理员撤销应用 B 会话按幂等 0；撤销未授权范围拒绝。
	appAdminIssued, _ := env.login(t, asAppAdminID, "", true)
	appBTarget, _ := env.login(t, asTargetID, asAppB, false)
	result, err := env.base.Services.Sessions.AdminRevoke(stronglyAuthenticatedContext(),
		appAdminIssued.Secret.Reveal(), session.AdminRevokeRequest{
			ScopeAppID: asAppA, TargetSessionID: appBTarget.Session.ID})
	if err != nil || result.Revoked != 0 {
		t.Fatalf("跨应用撤销应为幂等 0: (%+v, %v)", result, err)
	}
	if _, err := env.base.Services.Sessions.AdminRevoke(stronglyAuthenticatedContext(),
		appAdminIssued.Secret.Reveal(), session.AdminRevokeRequest{
			ScopeAppID: asAppB, TargetSessionID: appBTarget.Session.ID}); err == nil {
		t.Fatal("应用 A 管理员在未授权应用 B 范围撤销应被拒绝")
	}

	// root 与受保护目标：管理页/领域均拒绝。
	if _, err := env.base.Services.Sessions.AdminRevoke(stronglyAuthenticatedContext(),
		adminSession.Secret.Reveal(), session.AdminRevokeRequest{
			TargetUserID: asRootID}); err == nil {
		t.Fatal("root 目标应被拒绝")
	}
	if _, err := env.base.Services.Sessions.AdminRevoke(stronglyAuthenticatedContext(),
		appAdminIssued.Secret.Reveal(), session.AdminRevokeRequest{
			ScopeAppID: asAppA, TargetUserID: asProtectedID}); err == nil {
		t.Fatal("应用范围撤销受保护目标应被拒绝")
	}

	// 审计：真实管理员操作者与理由。
	var actorID, action string
	var requestID sql.NullString
	err = env.base.Store.DB().QueryRowContext(context.Background(),
		`SELECT actor_id, action, request_id FROM audit_events
		 WHERE action='session.admin_revoke' AND target_type='user' AND target_id=?
		 ORDER BY rowid DESC LIMIT 1`, asTargetID).Scan(&actorID, &action, &requestID)
	if err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}
	if actorID != asAdminID || action != "session.admin_revoke" {
		t.Fatalf("审计操作者/动作不符: %s/%s", actorID, action)
	}
}
