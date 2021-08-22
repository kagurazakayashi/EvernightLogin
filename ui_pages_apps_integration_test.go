package login_test

// 步骤 70 真实服务集成测试：临时 SQLite + 真实 app/oauthclient/account/delegation
// 服务；管理会话为受控 kind=management。测试只注入宿主授权器与敏感策略替身
// （生产由宿主真实 authz/reauth 注入），不联网、不监听端口、不真实外发。
// 覆盖：资料修改、成员状态、秘密一次展示、轮换/撤销、危险回调拒绝、接口字段
// 许可未启用、应用停用、跨应用读写拒绝。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// appsIntegrationSensitive 是客户端敏感策略的测试替身（生产使用 *reauth.Service）。
// 它只满足 OperationRunner 契约并返回已绑定的结果，不把替身当作生产鉴权。
type appsIntegrationSensitive struct{}

func (appsIntegrationSensitive) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID,
		UserID:   caller.Actor().ID,
		Decision: policy.Decision{Sensitive: true}}, nil
}

func (appsIntegrationSensitive) NotifyOutcome(context.Context, reauth.Result,
	reauth.Outcome) error {
	return nil
}

// appsIntegrationClientAuthorizer 是 oauthclient 管理授权器的宿主替身：允许本地
// 管理员与指定应用管理员，其他应用一律拒绝（生产由真实 authz 注入）。
type appsIntegrationClientAuthorizer struct {
	adminID    string
	appAdminID string
	appID      string
}

func (a appsIntegrationClientAuthorizer) AuthorizeClient(_ context.Context,
	caller oauthclient.Caller, applicationID string, _ oauthclient.Action) error {
	if caller.Actor().ID == a.adminID || (caller.Actor().ID == a.appAdminID &&
		applicationID == a.appID) {
		return nil
	}
	return oauthclient.ErrAccessDenied
}

// appsIntegrationManagedPolicy 是托管 API 策略读取的窄接口替身：返回真实
// managedapi.PolicyView 结构；真实服务行为由 internal/managedapi 自身测试覆盖。
type appsIntegrationManagedPolicy struct {
	view managedapi.PolicyView
	err  error
}

func (m *appsIntegrationManagedPolicy) GetPolicy(context.Context, audit.Actor, string,
	string) (managedapi.PolicyView, error) {
	return m.view, m.err
}

type appsIntegrationEnv struct {
	t           *testing.T
	adapter     *uiadminadapter.AppsAdapter
	apps        *app.Service
	oauth       *oauthclient.Service
	accounts    *account.Service
	sysCaller   account.Caller
	localCaller app.Caller
	adminID     string
	appAdmin    string
	appA        app.Application
	appB        app.Application
	policy      *appsIntegrationManagedPolicy
}

// newAppsIntegrationEnv 构造真实服务环境与两个应用。
func newAppsIntegrationEnv(t *testing.T) *appsIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "apps-pages.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	nowFunc := func() time.Time { return time.Now().UTC() }
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	accountStore, err := accountsqlite.New(storage)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	accountService, err := account.New(account.Options{Store: accountStore, Audit: recorder,
		Authorizer: allowAllAdmin{}, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("账户服务: %v", err)
	}
	sysCaller, err := account.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("账户系统操作者: %v", err)
	}
	createUser := func(username string) string {
		user, createErr := accountService.CreateUser(ctx, sysCaller,
			account.CreateRequest{Username: username, Nickname: username + "-nick"})
		if createErr != nil {
			t.Fatalf("创建账户: %v", createErr)
		}
		return user.ID
	}
	adminID := createUser("opsadmin")
	appAdmin := createUser("appadmin")
	_ = createUser("memberone")
	delegationStore, err := delegationsqlite.New(storage)
	if err != nil {
		t.Fatalf("委派存储: %v", err)
	}
	delegationService, err := delegation.New(delegation.Options{Store: delegationStore,
		Audit: recorder, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("委派服务: %v", err)
	}
	appStore, err := appsqlite.New(storage)
	if err != nil {
		t.Fatalf("应用存储: %v", err)
	}
	appAuthorizer, err := app.NewStaticAuthorizer(app.AuthorizerOptions{
		LocalAdminIDs:     []string{adminID},
		ApplicationAdmins: map[string][]string{},
	})
	if err != nil {
		t.Fatalf("应用授权器: %v", err)
	}
	appService, err := app.New(app.Options{Store: appStore, Audit: recorder,
		Authorizer: appAuthorizer, Transfers: delegationService, Now: nowFunc,
		Random: nil, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("应用服务: %v", err)
	}
	localCaller, err := app.LocalBootstrapCaller(adminID)
	if err != nil {
		t.Fatalf("本地操作者: %v", err)
	}
	createApp := func(name string) app.Application {
		created, createErr := appService.CreateApplication(ctx, localCaller,
			app.CreateRequest{Name: name, Description: "集成测试应用",
				OwnerUserID: adminID, ClientType: app.ClientTypeConfidential})
		if createErr != nil {
			t.Fatalf("创建应用: %v", createErr)
		}
		enabled, enableErr := appService.EnableApplication(ctx, localCaller,
			app.StatusRequest{ApplicationID: created.ID,
				ExpectedRowVersion: created.RowVersion})
		if enableErr != nil {
			t.Fatalf("启用应用: %v", enableErr)
		}
		return enabled.Application
	}
	appA := createApp("应用甲")
	appB := createApp("应用乙")
	if err := appAuthorizer.AssignApplicationAdmin(appA.ID, appAdmin); err != nil {
		t.Fatalf("分配应用管理员: %v", err)
	}
	// 页面管理身份是真实用户操作者（不是 local_admin 通道）；为测试账户显式分配
	// 应用管理范围，跨应用仍由服务端拒绝。
	for _, application := range []app.Application{appA, appB} {
		if err := appAuthorizer.AssignApplicationAdmin(application.ID, adminID); err != nil {
			t.Fatalf("分配测试管理员: %v", err)
		}
	}
	oauthStore, err := oauthclientsqlite.New(storage)
	if err != nil {
		t.Fatalf("客户端存储: %v", err)
	}
	oauthService, err := oauthclient.New(oauthclient.Options{Store: oauthStore,
		Audit: recorder,
		Authorizer: appsIntegrationClientAuthorizer{adminID: adminID,
			appAdminID: appAdmin, appID: appA.ID},
		Sensitive: appsIntegrationSensitive{}, Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("客户端服务: %v", err)
	}
	// 宿主页面层管理动作复核：本地管理员全部应用；应用管理员仅 appA。
	authorize := func(_ context.Context, adminUserID, action, applicationID string) error {
		if adminUserID == adminID {
			return nil
		}
		if adminUserID == appAdmin && applicationID == appA.ID &&
			action != "application.owner.change" {
			return nil
		}
		return errors.New("denied-by-host-page-authorizer")
	}
	policyReader := &appsIntegrationManagedPolicy{view: managedapi.PolicyView{
		ApplicationID: appA.ID, RowVersion: 2, UpdatedBy: "ui-policy-reader",
		Policy: managedapi.Policy{Version: 1,
			Operations: managedapi.PolicyOperations{Allowed: []string{"account.get"}},
			Objects:    []managedapi.ObjectScope{{Object: "user", Mode: "all"}},
			Fields:     []managedapi.ObjectFields{{Object: "user", Read: []string{"nickname"}}},
			Limits:     managedapi.PolicyLimits{MaxLimit: 20, MaxOffset: 100, MaxBatch: 5}}}}
	adapter, err := uiadminadapter.NewApps(uiadminadapter.AppOptions{
		Apps: appService, OAuth: oauthService, Authorize: authorize,
		ManagedAPI: policyReader,
		ManagedPolicyActor: audit.Actor{Type: audit.ActorSystem,
			ID: "ui-policy-reader"},
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("适配器: %v", err)
	}
	env := &appsIntegrationEnv{t: t, adapter: adapter, apps: appService,
		oauth: oauthService, accounts: accountService, sysCaller: sysCaller,
		localCaller: localCaller, adminID: adminID,
		appAdmin: appAdmin, appA: appA, appB: appB, policy: policyReader}
	return env
}

// ui 构造指定管理会话的页面框架。
func (e *appsIntegrationEnv) ui(userID string) *login.WebUI {
	e.t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  appsTestSessions{userID: userID, management: true},
		PageApps: &login.UIPageAppsOptions{Backend: e.adapter}})
	if err != nil {
		e.t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// get 执行 GET 页面请求。
func (e *appsIntegrationEnv) get(ui http.Handler, target string) *httptest.ResponseRecorder {
	e.t.Helper()
	return serveAppsPage(ui, http.MethodGet, target, nil)
}

// post 执行带表单的 POST 页面请求。
func (e *appsIntegrationEnv) post(ui http.Handler, target string,
	form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	return serveAppsPage(ui, http.MethodPost, target, form)
}

// appForm 构造应用资料表单。
func (e *appsIntegrationEnv) appForm(applicationID, name, description, iconRef,
	homepage, ownerUserID, contactInfo string, rowVersion int64) url.Values {
	return url.Values{"csrf_token": {"token"}, "app_id": {applicationID},
		"name": {name}, "description": {description},
		"icon_ref": {iconRef}, "homepage": {homepage},
		"owner_user_id": {ownerUserID},
		"contact_info":  {contactInfo},
		"row_version":   {strconv.FormatInt(rowVersion, 10)}}
}

// findMember 在成员列表中查找用户。
func (e *appsIntegrationEnv) findMember(applicationID, userID string) login.UIAppMemberView {
	e.t.Helper()
	page, err := e.adapter.ListMembers(context.Background(), e.adminID, applicationID,
		login.UIAppMemberQuery{Limit: 50})
	if err != nil {
		e.t.Fatalf("成员列表: %v", err)
	}
	for _, member := range page.Members {
		if member.UserID == userID {
			return member
		}
	}
	e.t.Fatalf("成员 %s 不存在", userID)
	return login.UIAppMemberView{}
}

// TestAppsIntegrationProfileAndMembers 覆盖资料白名单/只读身份/成员状态隔离。
func TestAppsIntegrationProfileAndMembers(t *testing.T) {
	env := newAppsIntegrationEnv(t)
	ui := env.ui(env.appAdmin)
	// 应用管理员资料页：ID/ScopeID/客户端类型只读，负责人不可变更。
	profile := env.get(ui, "/admin/applications/profile?app_id="+env.appA.ID)
	body := profile.Body.String()
	if profile.Code != 200 || !strings.Contains(body, env.appA.ID) ||
		!strings.Contains(body, "不能变更负责人") {
		t.Fatalf("资料页 = %d", profile.Code)
	}
	// 真实保存资料：修改名称与描述，服务端返回实际生效版本。
	form := env.appForm(env.appA.ID, env.appA.Name, env.appA.Description, env.appA.IconRef, env.appA.Homepage, env.appA.OwnerUserID, env.appA.ContactInfo, env.appA.RowVersion)
	form.Set("name", "应用甲改名")
	form.Set("description", "修改后的描述")
	saved := env.post(ui, "/admin/applications/profile", form)
	if saved.Code != 200 || !strings.Contains(saved.Body.String(), "应用甲改名") {
		t.Fatalf("资料保存 = %d", saved.Code)
	}
	updated, err := env.adapter.GetApplication(context.Background(), env.appAdmin, env.appA.ID)
	if err != nil || updated.Name != "应用甲改名" || updated.Description != "修改后的描述" {
		t.Fatalf("资料未真实保存: %+v err=%v", updated, err)
	}
	if updated.ID != env.appA.ID || updated.ClientType != string(env.appA.ClientType) ||
		updated.Status != "active" {
		t.Fatal("资料更新改动了只读身份字段")
	}
	// 应用管理员尝试变更负责人：真实服务拒绝，且不转移任何权限。
	ownerForm := env.appForm(updated.ID, updated.Name, updated.Description, updated.IconRef, updated.Homepage, env.appAdmin, updated.ContactInfo, updated.RowVersion)
	ownerForm.Set("name", updated.Name)
	ownerForm.Set("owner_user_id", env.appAdmin)
	ownerRejected := env.post(ui, "/admin/applications/profile", ownerForm)
	reread, _ := env.adapter.GetApplication(context.Background(), env.appAdmin, env.appA.ID)
	if reread.OwnerUserID != env.appA.OwnerUserID ||
		reread.RowVersion != updated.RowVersion {
		t.Fatalf("应用管理员变更负责人未被拒绝: owner=%s", reread.OwnerUserID)
	}
	if ownerRejected.Code < 400 {
		t.Fatalf("负责人变更拒绝状态 = %d", ownerRejected.Code)
	}
	// 成员关系由受信本地通道（生产为受控管理流程）建立；页面管理身份仍是真实用户。
	ctx := context.Background()
	memberID := env.findUserID(t, "memberone")
	if _, err := env.apps.AddApplicationMember(ctx, env.localCaller,
		app.AddMemberRequest{ApplicationID: env.appA.ID, UserID: memberID,
			Profile: app.MemberProfile{DisplayName: "应用内成员", Title: "运维"}}); err != nil {
		t.Fatalf("受信通道建立成员关系: %v", err)
	}
	globalUser, err := env.accounts.GetUser(ctx, env.sysCaller, memberID)
	if err != nil || globalUser.Nickname != "memberone-nick" {
		t.Fatalf("添加成员改动了全局资料: %+v err=%v", globalUser, err)
	}
	// 页面保存应用内成员资料：成功且不回写全局账户资料。
	member := env.findMember(env.appA.ID, memberID)
	profileForm := url.Values{"csrf_token": {"token"}, "app_id": {env.appA.ID},
		"action": {"profile"}, "user_id": {memberID},
		"display_name": {"应用内改名"}, "title": {"安全运维"}, "note": {"备注"},
		"row_version": {strconv.FormatInt(member.RowVersion, 10)}}
	profiled := env.post(ui, "/admin/applications/members", profileForm)
	if profiled.Code != 200 || !strings.Contains(profiled.Body.String(), "应用内成员资料已保存") {
		t.Fatalf("保存成员资料 = %d", profiled.Code)
	}
	member = env.findMember(env.appA.ID, memberID)
	if member.DisplayName != "应用内改名" || member.Title != "安全运维" {
		t.Fatalf("成员资料未真实保存: %+v", member)
	}
	globalUser, _ = env.accounts.GetUser(ctx, env.sysCaller, memberID)
	if globalUser.Nickname != "memberone-nick" {
		t.Fatal("应用内资料回写了全局账户")
	}
	// 停用成员：真实服务改变当前应用成员状态，不改变全局账户状态。
	stateForm := url.Values{"csrf_token": {"token"}, "app_id": {env.appA.ID},
		"action": {"disable"}, "user_id": {memberID},
		"row_version": {strconv.FormatInt(member.RowVersion, 10)}, "confirm": {"yes"}}
	disabled := env.post(ui, "/admin/applications/members", stateForm)
	if disabled.Code != 200 ||
		!strings.Contains(disabled.Body.String(), "全局账户及其他应用未改变") {
		t.Fatalf("停用成员 = %d", disabled.Code)
	}
	member = env.findMember(env.appA.ID, memberID)
	if member.Status != "disabled" {
		t.Fatalf("成员状态未真实变更: %s", member.Status)
	}
	globalUser, _ = env.accounts.GetUser(ctx, env.sysCaller, memberID)
	if globalUser.Status != account.StatusActive {
		t.Fatal("停用应用成员改动了全局账户状态")
	}
	// 缺少确认的停用会被页面拒绝（确认绑定实际目标，不是授权）。
	noConfirm := env.post(ui, "/admin/applications/members", url.Values{
		"csrf_token": {"token"}, "app_id": {env.appA.ID}, "action": {"disable"},
		"user_id": {memberID}, "row_version": {strconv.FormatInt(member.RowVersion, 10)}})
	if noConfirm.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的成员停用 = %d", noConfirm.Code)
	}
}

// findUserID 返回指定用户名的稳定 ID（测试数据由本测试创建）。
func (e *appsIntegrationEnv) findUserID(t *testing.T, username string) string {
	t.Helper()
	page, err := e.accounts.ListUsers(context.Background(), e.sysCaller,
		account.ListRequest{Limit: 100})
	if err != nil {
		t.Fatalf("用户列表: %v", err)
	}
	for _, user := range page.Users {
		if user.Username == username {
			return user.ID
		}
	}
	t.Fatalf("用户 %s 不存在", username)
	return ""
}

// TestAppsIntegrationSecretAndCallback 覆盖危险回调拒绝、秘密一次展示与轮换/撤销。
func TestAppsIntegrationSecretAndCallback(t *testing.T) {
	env := newAppsIntegrationEnv(t)
	ui := env.ui(env.adminID)
	// 危险回调：真实 oauthclient 服务拒绝，页面显示可纠正说明且未登记客户端。
	dangerous := env.post(ui, "/admin/applications/security", url.Values{
		"csrf_token": {"token"}, "app_id": {env.appA.ID}, "action": {"register"},
		"grant_code": {"1"}, "redirect_uris": {"http://evil.example.test/callback?x=1"},
		"confirm": {"yes"}})
	if dangerous.Code != http.StatusBadRequest ||
		!strings.Contains(dangerous.Body.String(), "安全设置") ||
		strings.Contains(dangerous.Body.String(), "elc_") {
		t.Fatalf("危险回调拒绝路径 = %d", dangerous.Code)
	}
	settings, err := env.adapter.GetOAuthSettings(context.Background(), env.adminID, env.appA.ID)
	if err != nil || settings.Registered {
		t.Fatalf("危险回调不应登记客户端: %+v err=%v", settings, err)
	}
	// 合法登记：秘密只在登记响应出现一次。
	registered := env.post(ui, "/admin/applications/security", url.Values{
		"csrf_token": {"token"}, "app_id": {env.appA.ID}, "action": {"register"},
		"grant_code": {"1"}, "auth_basic": {"1"},
		"redirect_uris": {"https://client.example.test/callback"},
		"scopes":        {"openid"}, "audiences": {"https://api.example.test"},
		"require_pkce": {"1"}, "confirm": {"yes"}})
	registerBody := registered.Body.String()
	if registered.Code != 200 || !strings.Contains(registerBody, "新客户端秘密仅显示这一次") ||
		!strings.Contains(registerBody, "ln-secret") {
		t.Fatalf("登记秘密一次展示 = %d", registered.Code)
	}
	secretID := extractOnceSecretID(t, registerBody)
	if secretID == "" {
		t.Fatal("登记响应缺少凭证编号")
	}
	// 已登记后再打开安全页：已有授权类型与 PKCE 必须正确预勾选，避免保存时误清。
	securityPage := env.get(ui,
		"/admin/applications/security?app_id="+env.appA.ID).Body.String()
	if !strings.Contains(securityPage, `name="grant_code" value="1" checked`) ||
		!strings.Contains(securityPage, `name="require_pkce" value="1" checked`) {
		t.Fatal("真实已登记安全设置的授权类型/PKCE 未预勾选")
	}
	// 后续元数据页不回填明文；秘密不出现在页面。
	credentialsPage := env.get(ui,
		"/admin/applications/credentials?app_id="+env.appA.ID).Body.String()
	if strings.Contains(credentialsPage, "elc_") &&
		strings.Contains(credentialsPage, "super") {
		t.Fatal("元数据页出现明文秘密")
	}
	if credentialsPage != "" && !strings.Contains(credentialsPage, secretID) {
		t.Fatal("元数据页缺少凭证编号")
	}
	// 轮换：新秘密只在响应出现一次；旧秘密进入过渡期而非立即失效。
	rotated := env.post(ui, "/admin/applications/credentials", url.Values{
		"csrf_token": {"token"}, "app_id": {env.appA.ID}, "action": {"rotate"},
		"confirm": {"yes"}})
	rotateBody := rotated.Body.String()
	if rotated.Code != 200 || strings.Count(rotateBody, `class="ln-secret"`) != 1 {
		t.Fatalf("轮换秘密一次展示 = %d", rotated.Code)
	}
	credentials, err := env.adapter.GetCredentials(context.Background(), env.adminID, env.appA.ID)
	if err != nil || len(credentials.Secrets) != 2 {
		t.Fatalf("轮换后凭证数量 = %d err=%v", len(credentials.Secrets), err)
	}
	var retiring bool
	for _, secret := range credentials.Secrets {
		if secret.Status == "retiring" {
			retiring = true
		}
	}
	if !retiring {
		t.Fatal("轮换后旧凭证未进入真实过渡期状态")
	}
	// 撤销旧凭证成功；撤销最后一个可用凭证由服务端拒绝（页面映射 CONFLICT）。
	var revocableOld string
	for _, secret := range credentials.Secrets {
		if secret.Status == "retiring" {
			revocableOld = secret.ID
		}
	}
	if err := env.adapter.RevokeSecret(context.Background(), env.adminID, env.appA.ID,
		revocableOld, "req_revoke_old"); err != nil {
		t.Fatalf("撤销旧凭证: %v", err)
	}
	credentials, _ = env.adapter.GetCredentials(context.Background(), env.adminID, env.appA.ID)
	var lastID string
	for _, secret := range credentials.Secrets {
		if secret.Status == "active" {
			lastID = secret.ID
		}
	}
	if lastID == "" {
		t.Fatal("缺少可用凭证")
	}
	if err := env.adapter.RevokeSecret(context.Background(), env.adminID, env.appA.ID,
		lastID, "req_revoke_last"); err == nil {
		t.Fatal("撤销最后一个可用凭证未被拒绝")
	} else {
		var publicErr *login.UIAppsError
		if !errors.As(err, &publicErr) || publicErr.Code != "CONFLICT" {
			t.Fatalf("最后凭证撤销错误码 = %v", err)
		}
	}
}

// extractOnceSecretID 从一次展示页面提取凭证编号（仅用于测试断言，不处理明文）。
func extractOnceSecretID(t *testing.T, body string) string {
	t.Helper()
	index := strings.Index(body, "ocs_")
	if index < 0 {
		return ""
	}
	rest := body[index:]
	end := strings.IndexAny(rest, "<\" \n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// TestAppsIntegrationGrantsStatusAndCrossApp 覆盖许可未启用、应用停用与跨应用拒绝。
func TestAppsIntegrationGrantsStatusAndCrossApp(t *testing.T) {
	env := newAppsIntegrationEnv(t)
	adminUI := env.ui(env.adminID)
	appAdminUI := env.ui(env.appAdmin)
	// 资源/接口字段许可：真实应用上下文下仍只显示“尚未启用”，无假开关。
	// 资源/接口/字段许可：展示真实 managed API 策略（操作/对象/字段/上限/版本）
	// 与“修改需受信管理端”说明；只读页不提供可提交写控件，也不写“尚未启用”。
	grants := env.get(appAdminUI, "/admin/applications/grants?app_id="+env.appA.ID)
	grantsBody := grants.Body.String()
	if grants.Code != 200 || !strings.Contains(grantsBody, "account.get") ||
		!strings.Contains(grantsBody, "当前应用委托策略") ||
		!strings.Contains(grantsBody, "修改委托策略需受信管理端") ||
		!strings.Contains(grantsBody, "nickname") ||
		strings.Contains(grantsBody, "尚未启用") ||
		strings.Contains(grantsBody, `type="checkbox"`) {
		t.Fatalf("许可页 = %d", grants.Code)
	}
	// 后端明确未配置 / 受信通道不可用时显示真实状态，不显示假策略。
	env.policy.err = managedapi.ErrPolicyDisabled
	notConfigured := env.get(appAdminUI,
		"/admin/applications/grants?app_id="+env.appA.ID).Body.String()
	if !strings.Contains(notConfigured, "尚未配置托管管理 API 委托策略") {
		t.Fatal("未配置策略状态未展示")
	}
	env.policy.err = managedapi.ErrAccessDenied
	unavailable := env.get(appAdminUI,
		"/admin/applications/grants?app_id="+env.appA.ID).Body.String()
	if !strings.Contains(unavailable, "受信策略读取通道未获准") {
		t.Fatal("受信通道不可用状态未展示")
	}
	env.policy.err = nil
	// 跨应用读取：appA 的应用管理员读取 appB 被拒绝，且不泄露 appB 名称。
	crossRead := env.get(appAdminUI, "/admin/applications/profile?app_id="+env.appB.ID)
	if crossRead.Code != http.StatusForbidden ||
		strings.Contains(crossRead.Body.String(), env.appB.Name) {
		t.Fatalf("跨应用读取 = %d", crossRead.Code)
	}
	// 跨应用写入：改 appB 资料同样被拒绝，appB 保持原值。
	crossForm := env.appForm(env.appB.ID, env.appB.Name, env.appB.Description, env.appB.IconRef, env.appB.Homepage, env.appB.OwnerUserID, env.appB.ContactInfo, env.appB.RowVersion)
	crossForm.Set("name", "被篡改的名字")
	crossWrite := env.post(appAdminUI, "/admin/applications/profile", crossForm)
	rereadB, _ := env.adapter.GetApplication(context.Background(), env.adminID, env.appB.ID)
	if crossWrite.Code != http.StatusForbidden || rereadB.Name == "被篡改的名字" {
		t.Fatalf("跨应用写入 = %d", crossWrite.Code)
	}
	// 停用应用：真实 Changed 语义；停用后成员写入被 CLIENT_DISABLED 拒绝。
	statusForm := url.Values{"csrf_token": {"token"}, "app_id": {env.appA.ID},
		"action":      {"disable"},
		"row_version": {strconv.FormatInt(env.appA.RowVersion, 10)},
		"confirm":     {"yes"}}
	disabled := env.post(adminUI, "/admin/applications/status", statusForm)
	if disabled.Code != 200 || !strings.Contains(disabled.Body.String(), "应用状态已变更") {
		t.Fatalf("应用停用 = %d", disabled.Code)
	}
	blockedMember := env.post(adminUI, "/admin/applications/members", url.Values{
		"csrf_token": {"token"}, "app_id": {env.appA.ID}, "action": {"add"},
		"user_id": {env.findUserID(t, "memberone")}})
	if blockedMember.Code < 400 {
		t.Fatalf("停用应用的成员写入未失败: %d", blockedMember.Code)
	}
	// 幂等停用：Changed=false 显示“已处于目标状态”，不伪造第二次变更。
	disabledApp, err := env.adapter.GetApplication(context.Background(), env.adminID, env.appA.ID)
	if err != nil || disabledApp.Status != "disabled" {
		t.Fatalf("停用后状态 = %+v err=%v", disabledApp, err)
	}
}
