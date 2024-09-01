package ui_test

// 步骤 70 应用管理页契约测试：受控 UIAppsBackend 渲染/表单/错误映射/秘密一次展示；
// 真实 app/oauthclient 服务集成见 ui_pages_apps_integration_test.go。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const appsTestAppID = "app_11111111111111111111111111111111"

type fakeAppsBackend struct {
	failCode      string
	failOn        string
	app           login.UIApplicationView
	members       []login.UIAppMemberView
	settings      login.UIOAuthSettings
	credentials   login.UIAppCredentials
	policy        login.UIAppPolicyView
	certificate   *login.UIAppCertificate
	secret        string
	profileUpdate login.UIApplicationChange
	// lastMemberQuery 记录最近一次成员列表查询，供搜索参数透传测试断言。
	lastMemberQuery login.UIAppMemberQuery
	createRequest   login.UIApplicationCreate
	canCreate       bool
	memberState     bool
	stateChanged    bool
	// 步骤 190：删除预览/逻辑删除。
	deleteImpact login.UIApplicationDeleteImpact
	deleteCalled bool
}

func (f *fakeAppsBackend) fail(method string) error {
	if f.failCode != "" && (f.failOn == "" || f.failOn == method) {
		return &login.UIAppsError{Code: f.failCode}
	}
	return nil
}

func (f *fakeAppsBackend) ListApplications(context.Context, string,
	login.UIAppQuery) (login.UIAppPage, error) {
	if err := f.fail("list"); err != nil {
		return login.UIAppPage{}, err
	}
	return login.UIAppPage{Applications: []login.UIApplicationView{f.app},
		NextOffset: 1}, nil
}

func (f *fakeAppsBackend) GetApplication(context.Context, string,
	string) (login.UIApplicationView, error) {
	if err := f.fail("get"); err != nil {
		return login.UIApplicationView{}, err
	}
	return f.app, nil
}

func (f *fakeAppsBackend) UpdateApplication(_ context.Context, _, _ string,
	change login.UIApplicationChange, _ int64,
	_ string) (login.UIApplicationView, error) {
	if err := f.fail("update"); err != nil {
		return login.UIApplicationView{}, err
	}
	f.profileUpdate = change
	updated := f.app
	updated.Name = change.Name
	updated.Description = change.Description
	updated.RowVersion++
	return updated, nil
}

func (f *fakeAppsBackend) CanCreateApplication(context.Context, string) (bool, error) {
	return f.canCreate, nil
}

func (f *fakeAppsBackend) CreateApplication(_ context.Context, _ string,
	create login.UIApplicationCreate, _ string) (login.UIApplicationView, error) {
	if err := f.fail("create"); err != nil {
		return login.UIApplicationView{}, err
	}
	f.createRequest = create
	created := f.app
	created.ID = "app_22222222222222222222222222222222"
	created.Name = create.Name
	created.Description = create.Description
	created.ClientType = create.ClientType
	created.Status = "disabled"
	created.RowVersion = 1
	return created, nil
}

func (f *fakeAppsBackend) SetApplicationState(_ context.Context, _, _ string, enable bool,
	_ int64, _ string) (login.UIApplicationView, bool, error) {
	if err := f.fail("state"); err != nil {
		return login.UIApplicationView{}, false, err
	}
	updated := f.app
	if enable {
		updated.Status = "active"
	} else {
		updated.Status = "disabled"
	}
	f.stateChanged = true
	return updated, true, nil
}

func (f *fakeAppsBackend) ListMembers(_ context.Context, _ string,
	_ string, query login.UIAppMemberQuery) (login.UIAppMemberPage, error) {
	f.lastMemberQuery = query
	if err := f.fail("members"); err != nil {
		return login.UIAppMemberPage{}, err
	}
	return login.UIAppMemberPage{Members: f.members}, nil
}

// GetApplicationDeleteImpact 实现步骤 190 的删除预览扩展契约。
func (f *fakeAppsBackend) GetApplicationDeleteImpact(_ context.Context, _,
	_ string) (login.UIApplicationDeleteImpact, error) {
	if err := f.fail("delete_impact"); err != nil {
		return login.UIApplicationDeleteImpact{}, err
	}
	impact := f.deleteImpact
	impact.Application = f.app
	return impact, nil
}

// DeleteApplication 实现步骤 190 的逻辑删除扩展契约（记录调用并返回已删除视图）。
func (f *fakeAppsBackend) DeleteApplication(_ context.Context, _, _ string,
	_ int64, _ string) (login.UIApplicationView, bool, error) {
	if err := f.fail("delete"); err != nil {
		return login.UIApplicationView{}, false, err
	}
	f.deleteCalled = true
	updated := f.app
	updated.DeletedAt = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	updated.RowVersion++
	return updated, true, nil
}
func (f *fakeAppsBackend) AddMember(context.Context, string, string, string,
	login.UIAppMemberProfile, string) (login.UIAppMemberView, error) {
	if err := f.fail("member_add"); err != nil {
		return login.UIAppMemberView{}, err
	}
	return login.UIAppMemberView{UserID: "usr_added", Status: "active", RowVersion: 1}, nil
}

func (f *fakeAppsBackend) UpdateMemberProfile(context.Context, string, string, string,
	login.UIAppMemberProfile, int64, string) (login.UIAppMemberView, error) {
	if err := f.fail("member_profile"); err != nil {
		return login.UIAppMemberView{}, err
	}
	return login.UIAppMemberView{UserID: "usr_member", Status: "active", RowVersion: 2}, nil
}

func (f *fakeAppsBackend) SetMemberState(_ context.Context, _, _, _ string, enable bool,
	_ int64, _ string) (login.UIAppMemberView, bool, error) {
	if err := f.fail("member_state"); err != nil {
		return login.UIAppMemberView{}, false, err
	}
	f.memberState = enable
	status := "disabled"
	if enable {
		status = "active"
	}
	return login.UIAppMemberView{UserID: "usr_member", Status: status, RowVersion: 2}, true, nil
}

func (f *fakeAppsBackend) RemoveMember(context.Context, string, string, string,
	int64, string) error {
	return f.fail("member_remove")
}

func (f *fakeAppsBackend) GetOAuthSettings(context.Context, string,
	string) (login.UIOAuthSettings, error) {
	if err := f.fail("security"); err != nil {
		return login.UIOAuthSettings{}, err
	}
	return f.settings, nil
}

func (f *fakeAppsBackend) RegisterClient(context.Context, string, string,
	login.UIOAuthRegister, string) (login.UIOAuthRegisterResult, error) {
	if err := f.fail("security_register"); err != nil {
		return login.UIOAuthRegisterResult{}, err
	}
	result := login.UIOAuthRegisterResult{Settings: f.settings}
	if f.certificate != nil {
		result.Certificate = f.certificate
	}
	if f.secret != "" {
		result.Secret = &login.UIAppRevealedSecret{Secret: f.secret,
			Info: login.UIAppSecretInfo{ID: "sec_once", Prefix: "elc_live_"}}
	}
	return result, nil
}

func (f *fakeAppsBackend) UpdateClientSettings(context.Context, string, string,
	login.UIOAuthChange, int64, string) (login.UIOAuthSettings, error) {
	if err := f.fail("security_update"); err != nil {
		return login.UIOAuthSettings{}, err
	}
	return f.settings, nil
}

func (f *fakeAppsBackend) GetCredentials(context.Context, string,
	string) (login.UIAppCredentials, error) {
	if err := f.fail("credentials"); err != nil {
		return login.UIAppCredentials{}, err
	}
	return f.credentials, nil
}

func (f *fakeAppsBackend) RotateSecret(context.Context, string, string,
	string) (login.UIAppRevealedSecret, error) {
	if err := f.fail("rotate"); err != nil {
		return login.UIAppRevealedSecret{}, err
	}
	return login.UIAppRevealedSecret{Secret: f.secret, Info: login.UIAppSecretInfo{
		ID: "sec_once", Prefix: "elc_live_", Status: "active",
		RetireAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}}, nil
}

func (f *fakeAppsBackend) RevokeSecret(context.Context, string, string, string,
	string) error {
	return f.fail("revoke")
}

func (f *fakeAppsBackend) GetManagedPolicy(context.Context, string,
	string) (login.UIAppPolicyView, error) {
	if err := f.fail("grants"); err != nil {
		return login.UIAppPolicyView{}, err
	}
	return f.policy, nil
}

func (f *fakeAppsBackend) RegisterCertificate(context.Context, string, string, string,
	string) (login.UIAppCertificate, error) {
	if err := f.fail("certificate"); err != nil {
		return login.UIAppCertificate{}, err
	}
	if f.certificate != nil {
		return *f.certificate, nil
	}
	return login.UIAppCertificate{ID: "cert_1", FingerprintSHA256: "aa", Subject: "CN=app"}, nil
}

func (f *fakeAppsBackend) RevokeCertificate(context.Context, string, string, string,
	string) error {
	return f.fail("certificate_revoke")
}

// appsTestSessions 是受控页面会话替身（真实会话框架不在本步范围）。
type appsTestSessions struct {
	userID     string
	management bool
}

func (s appsTestSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	kind := "user"
	if s.management {
		kind = "management"
	}
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: kind,
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s appsTestSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "apps-csrf-token", nil
}

// newAppsFakeBackend 构造默认的受控数据。
func newAppsFakeBackend() *fakeAppsBackend {
	return &fakeAppsBackend{
		app: login.UIApplicationView{ID: appsTestAppID, ScopeID: appsTestAppID,
			Name: "示例应用", Description: "初始描述", OwnerUserID: "usr_owner",
			ContactInfo: "ops@example.test", Status: "active", ClientType: "confidential",
			RowVersion: 3, CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
			Capabilities: login.UIApplicationCapabilities{Write: true,
				ManageMembers: true, ManageSecurity: true, ManageCredentials: true}},
		members: []login.UIAppMemberView{{UserID: "usr_member", DisplayName: "成员甲",
			Status: "active", RowVersion: 1}},
		settings: login.UIOAuthSettings{Registered: true, ClientID: appsTestAppID,
			ClientType: "confidential", GrantTypes: []string{"authorization_code"},
			RedirectURIs: []string{"https://client.example.test/callback"},
			Scopes:       []string{"openid"}, RequirePKCE: true, RowVersion: 1,
			AudienceTrustUnverified: true},
		credentials: login.UIAppCredentials{Registered: true, ClientType: "confidential",
			Secrets: []login.UIAppSecretInfo{{ID: "sec_existing", Prefix: "elc_old_",
				Status: "active"}}},
		secret:    "elc_live_super-secret-once-value",
		canCreate: true,
	}
}

// newAppsTestUI 构造带 PageApps 的页面框架。
func newAppsTestUI(t *testing.T, backend login.UIAppsBackend, management bool) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  appsTestSessions{userID: "usr_admin", management: management},
		PageApps: &login.UIPageAppsOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// newAppsTestUIWithDeleteReauth 构造带删除再次认证回调的页面框架。
func newAppsTestUIWithDeleteReauth(t *testing.T, backend login.UIAppsBackend,
	management bool, reauth func(context.Context, string, login.UIAppDeleteBinding) error) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  appsTestSessions{userID: "usr_admin", management: management},
		PageApps: &login.UIPageAppsOptions{Backend: backend, DeleteReauth: reauth}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// TestUIPageAppsDeletionPreviewAndReauth 覆盖步骤 190 页面删除：影响预览、显式确认、
// 目标/行版本绑定、再次认证失败关闭、未装配再认证 fail-closed 与成功状态。
func TestUIPageAppsDeletionPreviewAndReauth(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.app.Status = "disabled"
	backend.app.RowVersion = 4
	backend.deleteImpact = login.UIApplicationDeleteImpact{CanDelete: true,
		MemberCount: 2, ActiveMemberCount: 1, RoleCount: 1, PermissionCount: 3,
		GroupCount: 1, ActiveSessionCount: 2, OAuthClientCount: 1,
		RefreshTokenFamilyCount: 1, AuthorizationRequestCount: 1,
		CredentialCount: 1, InvitationCount: 0, WebhookEndpointCount: 1,
		AuditEventCount: 5}
	reauthCalls := 0
	var seenBinding login.UIAppDeleteBinding
	ui := newAppsTestUIWithDeleteReauth(t, backend, true,
		func(_ context.Context, _ string, binding login.UIAppDeleteBinding) error {
			reauthCalls++
			seenBinding = binding
			if binding.ApplicationID != appsTestAppID || binding.ExpectedRowVersion != 4 {
				return &login.UIAppsError{Code: "REQ_INVALID"}
			}
			return nil
		})
	page := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/status?app_id="+appsTestAppID, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("删除预览页 = %d", page.Code)
	}
	for _, want := range []string{"删除应用（逻辑删除）", "成员关系", "刷新令牌族",
		"安全审计事件", "逻辑删除是终态"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("删除预览缺少 %q", want)
		}
	}
	// 缺少确认：400 且不调用再认证/后端删除。
	noConfirm := serveAppsPage(ui, http.MethodPost, "/admin/applications/status/delete",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"row_version": {"4"}})
	if noConfirm.Code != http.StatusBadRequest || reauthCalls != 0 || backend.deleteCalled {
		t.Fatalf("缺少确认删除 = %d reauth=%d called=%v", noConfirm.Code,
			reauthCalls, backend.deleteCalled)
	}
	// 再认证拒绝：403 且不执行删除。
	denied := newAppsTestUIWithDeleteReauth(t, backend, true,
		func(context.Context, string, login.UIAppDeleteBinding) error {
			return &login.UIAppsError{Code: "ACCESS_DENIED"}
		})
	deniedResp := serveAppsPage(denied, http.MethodPost, "/admin/applications/status/delete",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"row_version": {"4"}, "confirm": {"yes"}})
	if deniedResp.Code != http.StatusForbidden || backend.deleteCalled {
		t.Fatalf("再认证拒绝的删除 = %d called=%v", deniedResp.Code, backend.deleteCalled)
	}
	// 未装配再认证回调：503 fail-closed。
	noReauthBackend := newAppsFakeBackend()
	noReauthUI := newAppsTestUI(t, noReauthBackend, true)
	noReauth := serveAppsPage(noReauthUI, http.MethodPost,
		"/admin/applications/status/delete",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"row_version": {"3"}, "confirm": {"yes"}})
	if noReauth.Code != http.StatusServiceUnavailable || noReauthBackend.deleteCalled {
		t.Fatalf("未装配再认证的删除 = %d called=%v", noReauth.Code,
			noReauthBackend.deleteCalled)
	}
	// 成功：再认证绑定实际目标与行版本，后端执行逻辑删除。
	done := serveAppsPage(ui, http.MethodPost, "/admin/applications/status/delete",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"row_version": {"4"}, "confirm": {"yes"}})
	if done.Code != http.StatusOK || !backend.deleteCalled ||
		!strings.Contains(done.Body.String(), "应用已逻辑删除") {
		t.Fatalf("逻辑删除成功页 = %d called=%v", done.Code, backend.deleteCalled)
	}
	if seenBinding.ApplicationID != appsTestAppID || seenBinding.ExpectedRowVersion != 4 {
		t.Fatalf("再次认证绑定 = %+v", seenBinding)
	}
}
func serveAppsPage(ui http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	var body *bytes.Reader
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(nil))
	if method == http.MethodPost {
		body = bytes.NewReader([]byte(form.Encode()))
		request = httptest.NewRequest(method, "http://example.test"+target, body)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestUIPageAppsRoutesContract 验证路由集合与依赖校验。
func TestUIPageAppsRoutesContract(t *testing.T) {
	ui := newAppsTestUI(t, newAppsFakeBackend(), true)
	routes := map[string]bool{}
	for _, route := range ui.Routes() {
		routes[route.Name] = true
	}
	for _, name := range []string{"admin.applications", "admin.application_profile",
		"admin.application_profile.submit", "admin.application_members",
		"admin.application_members.submit", "admin.application_security",
		"admin.application_security.submit", "admin.application_credentials",
		"admin.application_credentials.submit", "admin.application_grants",
		"admin.application_status", "admin.application_status.submit",
		"admin.application_create", "admin.application_create.submit"} {
		if !routes[name] {
			t.Fatalf("缺少步骤 70 路由 %s", name)
		}
	}
	if _, err := login.NewWebUI(login.WebUIOptions{PageApps: &login.UIPageAppsOptions{}}); err == nil {
		t.Fatal("空应用管理后端应拒绝构造")
	}
}

// TestUIPageAppsListAndProfile 验证列表渲染、资料只读身份与保存差异。
func TestUIPageAppsListAndProfile(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	list := serveAppsPage(ui, http.MethodGet, "/admin/applications", nil)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "示例应用") ||
		!strings.Contains(list.Body.String(), appsTestAppID) {
		t.Fatalf("应用列表渲染 = %d", list.Code)
	}
	profile := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/profile?app_id="+appsTestAppID, nil)
	if profile.Code != 200 || !strings.Contains(profile.Body.String(), "只读身份") {
		t.Fatalf("资料页渲染 = %d", profile.Code)
	}
	form := url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
		"name": {"改名后的应用"}, "description": {"新描述"}, "icon_ref": {""},
		"homepage": {"https://example.test"}, "owner_user_id": {"usr_owner"},
		"contact_info": {""}, "row_version": {"3"}}
	updated := serveAppsPage(ui, http.MethodPost, "/admin/applications/profile", form)
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), "实际生效的差异") ||
		!strings.Contains(updated.Body.String(), "改名后的应用") {
		t.Fatalf("资料保存差异 = %d", updated.Code)
	}
	if backend.profileUpdate.Name != "改名后的应用" {
		t.Fatalf("提交内容未被后端接收: %+v", backend.profileUpdate)
	}
	// 负责人不可变更时页面只读展示，不出现可编辑的负责人字段。
	readonly := newAppsFakeBackend()
	readonly.app.Capabilities.ChangeOwner = false
	readonlyUI := newAppsTestUI(t, readonly, true)
	body := serveAppsPage(readonlyUI, http.MethodGet,
		"/admin/applications/profile?app_id="+appsTestAppID, nil).Body.String()
	if !strings.Contains(body, "不能变更负责人") ||
		strings.Contains(body, `id="app-owner"`) {
		t.Fatal("负责人只读展示异常")
	}
}

// TestUIPageAppsSecretOnce 验证轮换秘密只在本次响应出现一次，后续页面只显示元数据。
func TestUIPageAppsSecretOnce(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	form := url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
		"action": {"rotate"}, "confirm": {"yes"}}
	rotated := serveAppsPage(ui, http.MethodPost, "/admin/applications/credentials", form)
	body := rotated.Body.String()
	if rotated.Code != 200 || !strings.Contains(body, backend.secret) ||
		!strings.Contains(body, "新客户端秘密仅显示这一次") {
		t.Fatalf("轮换秘密一次展示 = %d", rotated.Code)
	}
	if strings.Count(body, backend.secret) != 1 {
		t.Fatalf("秘密明文出现次数应恰好一次: %d", strings.Count(body, backend.secret))
	}
	if rotated.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("一次秘密响应缺少 no-store: %q", rotated.Header().Get("Cache-Control"))
	}
	// 后续读取元数据页不得回填明文。
	page := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/credentials?app_id="+appsTestAppID, nil)
	pageBody := page.Body.String()
	if page.Code != 200 || strings.Contains(pageBody, backend.secret) {
		t.Fatal("普通凭证页回填了明文秘密")
	}
	if !strings.Contains(pageBody, "sec_existing") || !strings.Contains(pageBody, "elc_old_") {
		t.Fatal("凭证元数据未显示编号/前缀")
	}
	// 轮换确认缺失时拒绝执行。
	noConfirm := serveAppsPage(ui, http.MethodPost, "/admin/applications/credentials",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID}, "action": {"rotate"}})
	if noConfirm.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的轮换应被拒绝: %d", noConfirm.Code)
	}
}

// TestUIPageAppsDangerousCallbackRejected 验证危险回调被真实接口拒绝时页面可纠正。
func TestUIPageAppsDangerousCallbackRejected(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.failOn = "security_register"
	backend.failCode = "REQ_INVALID"
	ui := newAppsTestUI(t, backend, true)
	form := url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
		"action": {"register"}, "grant_code": {"1"},
		"redirect_uris": {"http://evil.example.test/callback?x=*"},
		"confirm":       {"yes"}}
	rejected := serveAppsPage(ui, http.MethodPost, "/admin/applications/security", form)
	body := rejected.Body.String()
	if rejected.Code != http.StatusBadRequest ||
		!strings.Contains(body, "登记 OAuth 客户端安全设置未完成") ||
		strings.Contains(body, "elc_live_super-secret-once-value") {
		t.Fatalf("危险回调拒绝路径 = %d", rejected.Code)
	}
	// 首次登记表单不提供 password/implicit 授权选项，也不允许保密客户端默认无凭证。
	registration := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/security?app_id="+appsTestAppID, nil).Body.String()
	if strings.Contains(registration, `value="password"`) ||
		strings.Contains(registration, `value="implicit"`) {
		t.Fatal("页面出现 password/implicit 授权选项")
	}
}

// TestUIPageAppsGrantsPolicy 验证资源/接口/字段许可展示真实 managed API 策略，
// 或后端明确的“未配置/受信通道不可用”，不伪造“尚未启用”或可提交写控件。
func TestUIPageAppsGrantsPolicy(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.policy = login.UIAppPolicyView{State: "policy", ApplicationID: appsTestAppID,
		RowVersion: 4, UpdatedBy: "sys-policy-reader",
		Allowed: []login.UIAppPolicyOperation{{ID: "account.get", Object: "user",
			Write: false, ServiceOK: true}},
		ServiceAllowed: []login.UIAppPolicyOperation{{ID: "account.get", Object: "user"}},
		Objects:        []login.UIAppPolicyObject{{Object: "user", Mode: "all"}},
		Fields:         []login.UIAppPolicyFields{{Object: "user", Read: []string{"nickname"}}},
		Limits:         login.UIAppPolicyLimits{MaxLimit: 50, MaxOffset: 1000, MaxBatch: 10}}
	ui := newAppsTestUI(t, backend, true)
	page := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/grants?app_id="+appsTestAppID, nil)
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "account.get") ||
		!strings.Contains(body, "当前应用委托策略") ||
		!strings.Contains(body, "修改委托策略需受信管理端") {
		t.Fatalf("真实策略展示 = %d", page.Code)
	}
	if strings.Contains(body, `type="checkbox"`) || strings.Contains(body, "尚未启用") {
		t.Fatal("策略只读页出现假写控件或“尚未启用”冒充")
	}
	backend.policy = login.UIAppPolicyView{State: "not_configured",
		ApplicationID: appsTestAppID}
	notConfigured := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/grants?app_id="+appsTestAppID, nil).Body.String()
	if !strings.Contains(notConfigured, "尚未配置托管管理 API 委托策略") ||
		strings.Contains(notConfigured, "account.get") {
		t.Fatal("未配置策略状态显示异常")
	}
	backend.policy = login.UIAppPolicyView{State: "unavailable",
		Reason: "受信策略读取通道未获准读取该应用策略"}
	unavailable := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/grants?app_id="+appsTestAppID, nil).Body.String()
	if !strings.Contains(unavailable, "受信策略读取通道") ||
		!strings.Contains(unavailable, "受信策略读取通道未获准读取该应用策略") {
		t.Fatal("受信通道不可用状态显示异常")
	}
}

// TestUIPageAppsForbiddenAndSession 验证无权限与管理会话失效的 fail-closed。
func TestUIPageAppsForbiddenAndSession(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.failOn = "get"
	backend.failCode = "ACCESS_DENIED"
	ui := newAppsTestUI(t, backend, true)
	denied := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/profile?app_id="+appsTestAppID, nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("无权限读取资料 = %d", denied.Code)
	}
	ordinary := newAppsTestUI(t, newAppsFakeBackend(), false)
	blocked := serveAppsPage(ordinary, http.MethodGet, "/admin/applications", nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("普通会话访问管理页 = %d", blocked.Code)
	}
}

// TestUIPageAppsMembersAndState 验证成员状态与停用确认/Changed 语义。
func TestUIPageAppsMembersAndState(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	members := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/members?app_id="+appsTestAppID, nil)
	if members.Code != 200 || !strings.Contains(members.Body.String(), "成员甲") ||
		!strings.Contains(members.Body.String(), "只影响当前应用") {
		t.Fatalf("成员页渲染 = %d", members.Code)
	}
	// 停用成员缺少确认 → 拒绝且不调用后端。
	noConfirm := serveAppsPage(ui, http.MethodPost, "/admin/applications/members",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"disable"}, "user_id": {"usr_member"}, "row_version": {"1"}})
	if noConfirm.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的成员停用 = %d", noConfirm.Code)
	}
	confirmed := serveAppsPage(ui, http.MethodPost, "/admin/applications/members",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"disable"}, "user_id": {"usr_member"}, "row_version": {"1"},
			"confirm": {"yes"}})
	if confirmed.Code != 200 || backend.memberState ||
		!strings.Contains(confirmed.Body.String(), "全局账户及其他应用未改变") {
		t.Fatalf("成员停用成功路径 = %d", confirmed.Code)
	}
	// 应用停用要求确认，成功后显示真实 Changed。
	statusForm := url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
		"action": {"disable"}, "row_version": {"3"}}
	statusDenied := serveAppsPage(ui, http.MethodPost,
		"/admin/applications/status", statusForm)
	if statusDenied.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的应用停用 = %d", statusDenied.Code)
	}
	statusForm.Set("confirm", "yes")
	statusDone := serveAppsPage(ui, http.MethodPost,
		"/admin/applications/status", statusForm)
	if statusDone.Code != 200 || !backend.stateChanged ||
		!strings.Contains(statusDone.Body.String(), "应用状态已变更") {
		t.Fatalf("应用停用成功路径 = %d", statusDone.Code)
	}
}

// TestUIPageAppsAdditionalPaths 补成员移除/启用、证书登记结果、空态与失败保留上下文。
func TestUIPageAppsAdditionalPaths(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.certificate = &login.UIAppCertificate{ID: "cert_1",
		FingerprintSHA256: "ff00", Subject: "CN=app", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	backend.app.Status = "disabled"
	ui := newAppsTestUI(t, backend, true)
	// 应用启用（disabled → active），Changed 语义显示。
	enabled := serveAppsPage(ui, http.MethodPost, "/admin/applications/status",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"enable"}, "row_version": {"3"}})
	if enabled.Code != 200 || !strings.Contains(enabled.Body.String(), "应用状态已变更") {
		t.Fatalf("应用启用 = %d", enabled.Code)
	}
	// 成员移除成功（确认 + 行版本）。
	removed := serveAppsPage(ui, http.MethodPost, "/admin/applications/members",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"remove"}, "user_id": {"usr_member"}, "row_version": {"1"},
			"confirm": {"yes"}})
	if removed.Code != 200 || !strings.Contains(removed.Body.String(), "已移除当前应用成员关系") {
		t.Fatalf("成员移除 = %d", removed.Code)
	}
	// 证书登记：结果页展示指纹/Subject/有效期。
	certified := serveAppsPage(ui, http.MethodPost, "/admin/applications/credentials",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"register_certificate"}, "certificate_pem": {"-----BEGIN CERTIFICATE-----"}})
	if certified.Code != 200 || !strings.Contains(certified.Body.String(), "ff00") ||
		!strings.Contains(certified.Body.String(), "CN=app") {
		t.Fatalf("证书登记结果 = %d", certified.Code)
	}
	// 空成员/空应用列表状态。
	backend.members = nil
	emptyMembers := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/members?app_id="+appsTestAppID, nil)
	if emptyMembers.Code != 200 ||
		!strings.Contains(emptyMembers.Body.String(), "尚无成员") {
		t.Fatalf("空成员态 = %d", emptyMembers.Code)
	}
	// 状态写入失败保留应用上下文：不显示“无权限”伪造。
	backend.failOn = "state"
	backend.failCode = "CONFLICT"
	failed := serveAppsPage(ui, http.MethodPost, "/admin/applications/status",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"disable"}, "row_version": {"3"}, "confirm": {"yes"}})
	failedBody := failed.Body.String()
	if failed.Code != http.StatusConflict || strings.Contains(failedBody, "你没有权限查看此内容") ||
		!strings.Contains(failedBody, "示例应用") {
		t.Fatalf("状态失败保留上下文 = %d", failed.Code)
	}
}

// TestUIPageAppsSecurityCheckedAndEcho 验证安全页已选项正确勾选、失败回填与轮换精确文案。
func TestUIPageAppsSecurityCheckedAndEcho(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	page := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/security?app_id="+appsTestAppID, nil)
	body := page.Body.String()
	if page.Code != 200 ||
		!strings.Contains(body, `name="grant_code" value="1" checked`) ||
		!strings.Contains(body, `name="require_pkce" value="1" checked`) {
		t.Fatalf("已选授权类型/ PKCE 未正确勾选 = %d", page.Code)
	}
	// 危险回调失败：保留用户已填回调/Scope，并勾选已选授权类型。
	backend.failOn = "security_register"
	backend.failCode = "REQ_INVALID"
	failed := serveAppsPage(ui, http.MethodPost, "/admin/applications/security",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"register"}, "grant_code": {"1"},
			"redirect_uris": {"https://client.example.test/keep-this-callback"},
			"scopes":        {"openid keep-scope"}, "confirm": {"yes"}})
	failedBody := failed.Body.String()
	if failed.Code != http.StatusBadRequest ||
		!strings.Contains(failedBody, "keep-this-callback") ||
		!strings.Contains(failedBody, "keep-scope") ||
		!strings.Contains(failedBody, `name="grant_code" value="1" checked`) {
		t.Fatalf("安全设置失败未保留回填 = %d", failed.Code)
	}
	// 轮换失败：冲突保留精确稳定码说明，不误报“结果未知”。
	backend.failOn = "rotate"
	backend.failCode = "CONFLICT"
	rotateFailed := serveAppsPage(ui, http.MethodPost, "/admin/applications/credentials",
		url.Values{"csrf_token": {"token"}, "app_id": {appsTestAppID},
			"action": {"rotate"}, "confirm": {"yes"}})
	rotateBody := rotateFailed.Body.String()
	if rotateFailed.Code != http.StatusConflict ||
		!strings.Contains(rotateBody, "数据或凭证状态已变化") ||
		strings.Contains(rotateBody, "无法确认刚才的写入结果") {
		t.Fatalf("轮换冲突文案不精确 = %d", rotateFailed.Code)
	}
}

// fakeAppsNoCreate 只提供既有 UIAppsBackend，不实现可选新建契约；用于验证页面
// 不注册新建路由、不渲染静态按钮，而不是让按钮点击后失败。
type fakeAppsNoCreate struct {
	login.UIAppsBackend
}

// TestUIPageAppsCreate 验证新建应用页真实提交路径、默认停用提示与无能力后端隐藏。
func TestUIPageAppsCreate(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	list := serveAppsPage(ui, http.MethodGet, "/admin/applications", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "新建应用") {
		t.Fatalf("支持新建时列表缺少入口 = %d", list.Code)
	}
	formPage := serveAppsPage(ui, http.MethodGet, "/admin/applications/create", nil)
	if formPage.Code != http.StatusOK ||
		!strings.Contains(formPage.Body.String(), `name="client_type"`) {
		t.Fatalf("新建应用页渲染 = %d", formPage.Code)
	}
	created := serveAppsPage(ui, http.MethodPost, "/admin/applications/create",
		url.Values{"csrf_token": {"token"}, "name": {"页面新建应用"},
			"description": {"合成数据"}, "client_type": {"public"},
			"owner_user_id": {""}, "homepage": {""}, "icon_ref": {""},
			"contact_info": {""}})
	if created.Code != http.StatusOK ||
		!strings.Contains(created.Body.String(), "应用已创建（默认停用）") ||
		!strings.Contains(created.Body.String(), "app_22222222222222222222222222222222") ||
		backend.createRequest.Name != "页面新建应用" ||
		backend.createRequest.ClientType != "public" {
		t.Fatalf("新建应用提交 = %d body=%s", created.Code, created.Body.String())
	}

	// 后端未实现可选 Create 契约：不注册路由、不显示入口，避免静态按钮。
	noCreate := fakeAppsNoCreate{UIAppsBackend: newAppsFakeBackend()}
	noCreateUI := newAppsTestUI(t, noCreate, true)
	for _, route := range noCreateUI.Routes() {
		if route.Name == "admin.application_create" ||
			route.Name == "admin.application_create.submit" {
			t.Fatalf("无新建能力后端不应注册路由 %s", route.Name)
		}
	}
	noCreateList := serveAppsPage(noCreateUI, http.MethodGet, "/admin/applications", nil)
	if noCreateList.Code != http.StatusOK ||
		strings.Contains(noCreateList.Body.String(), "新建应用") {
		t.Fatalf("无新建能力时不应显示静态入口 = %d", noCreateList.Code)
	}
	missing := serveAppsPage(noCreateUI, http.MethodGet, "/admin/applications/create", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("无新建能力时创建路由应为 404，得到 %d", missing.Code)
	}
}

// TestUIPageAppsCreateInvalidForm 验证非法名称/客户端类型不会调用后端。
func TestUIPageAppsCreateInvalidForm(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	for name, form := range map[string]url.Values{
		"空名称":  {"csrf_token": {"token"}, "name": {""}, "client_type": {"public"}},
		"非法类型": {"csrf_token": {"token"}, "name": {"x"}, "client_type": {"browser"}},
	} {
		response := serveAppsPage(ui, http.MethodPost, "/admin/applications/create", form)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s 应返回 400，得到 %d", name, response.Code)
		}
		if backend.createRequest.Name != "" {
			t.Fatalf("%s 不应调用后端 CreateApplication", name)
		}
	}
}
