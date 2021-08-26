package login_test

// 步骤 72 敏感策略/安全通知页面契约测试：受控 UISecurityPolicyBackend 渲染、三值、
// 版本预览、自身保护额外确认、冲突保留草稿、恢复范围预览、秘密遮罩与拒绝路径。
// 真实 policy.Service 集成见 ui_pages_security_policy_integration_test.go。

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const (
	securityPolicyTestUserID       = "usr_00000000000000000000000000000001"
	securityPolicyTestCSRF         = "security-policy-csrf-token"
	securityPolicyTestPreviewToken = "prev_test_token"
)

// fakeSecurityPolicyBackend 是受控页面后端替身（仅测试页面契约）。
type fakeSecurityPolicyBackend struct {
	caps        login.UISecurityPolicyCapabilities
	snapshot    login.UISecurityPolicySnapshot
	settings    login.UINotificationSettings
	preview     login.UISecurityPolicyPreview
	restore     login.UISecurityPolicyRestorePreview
	writeResult login.UISecurityPolicyWriteResult
	template    login.UINotificationTemplatePreview
	testResult  login.UINotificationTestResult
	secret      login.UINotificationSecretResult

	failOn             string
	failCode           string
	snapshotSeq        int
	lastRecipient      string
	lastSecret         string
	lastChange         login.UISecurityPolicyValues
	lastVersion        int64
	lastAll            bool
	lastPreviewToken   string
	lastIdempotencyKey string
}

func (f *fakeSecurityPolicyBackend) fail(method string) error {
	if f.failCode != "" && (f.failOn == "" || f.failOn == method) {
		return &login.UISecurityPolicyError{Code: f.failCode}
	}
	return nil
}

func (f *fakeSecurityPolicyBackend) Capabilities(context.Context,
	string) (login.UISecurityPolicyCapabilities, error) {
	if err := f.fail("capabilities"); err != nil {
		return login.UISecurityPolicyCapabilities{}, err
	}
	return f.caps, nil
}

func (f *fakeSecurityPolicyBackend) Snapshot(context.Context, string,
	string) (login.UISecurityPolicySnapshot, error) {
	if err := f.fail("snapshot"); err != nil {
		return login.UISecurityPolicySnapshot{}, err
	}
	return f.snapshot, nil
}

func (f *fakeSecurityPolicyBackend) PreviewPolicy(_ context.Context, _, _, _ string,
	change login.UISecurityPolicyValues) (login.UISecurityPolicyPreview, error) {
	if err := f.fail("preview"); err != nil {
		return login.UISecurityPolicyPreview{}, err
	}
	f.lastChange = change
	return f.preview, nil
}

func (f *fakeSecurityPolicyBackend) SavePolicy(_ context.Context, _, _, operationID string,
	change login.UISecurityPolicyValues, expectedVersion int64, previewToken,
	_ string) (login.UISecurityPolicyWriteResult, error) {
	f.lastPreviewToken = previewToken
	if err := f.fail("save"); err != nil {
		return login.UISecurityPolicyWriteResult{}, err
	}
	f.lastChange = change
	f.lastVersion = expectedVersion
	return f.writeResult, nil
}

func (f *fakeSecurityPolicyBackend) PreviewRestore(_ context.Context, _, _,
	_ string, all bool) (login.UISecurityPolicyRestorePreview, error) {
	if err := f.fail("restore_preview"); err != nil {
		return login.UISecurityPolicyRestorePreview{}, err
	}
	f.lastAll = all
	return f.restore, nil
}

func (f *fakeSecurityPolicyBackend) RestorePolicy(_ context.Context, _, _, _ string, all bool,
	expectedVersion int64, previewToken, _ string) (login.UISecurityPolicyWriteResult, error) {
	f.lastPreviewToken = previewToken
	if err := f.fail("restore"); err != nil {
		return login.UISecurityPolicyWriteResult{}, err
	}
	f.lastAll = all
	f.lastVersion = expectedVersion
	return f.writeResult, nil
}

func (f *fakeSecurityPolicyBackend) NotificationSettings(context.Context,
	string) (login.UINotificationSettings, error) {
	if err := f.fail("settings"); err != nil {
		return login.UINotificationSettings{}, err
	}
	return f.settings, nil
}

func (f *fakeSecurityPolicyBackend) PreviewTemplate(_ context.Context, _,
	kind string) (login.UINotificationTemplatePreview, error) {
	if err := f.fail("template"); err != nil {
		return login.UINotificationTemplatePreview{}, err
	}
	return f.template, nil
}

func (f *fakeSecurityPolicyBackend) SendTestMail(_ context.Context, _, recipient, kind,
	idempotencyKey, _ string) (login.UINotificationTestResult, error) {
	f.lastIdempotencyKey = idempotencyKey
	if err := f.fail("test"); err != nil {
		return login.UINotificationTestResult{}, err
	}
	f.lastRecipient = recipient
	return f.testResult, nil
}

func (f *fakeSecurityPolicyBackend) ReplaceSMTPSecret(_ context.Context, _, newSecret,
	idempotencyKey, _ string) (login.UINotificationSecretResult, error) {
	f.lastIdempotencyKey = idempotencyKey
	if err := f.fail("secret"); err != nil {
		return login.UINotificationSecretResult{}, err
	}
	f.lastSecret = newSecret
	return f.secret, nil
}

// securityPolicyOperationFixture 构造一条可选覆盖的操作视图。
func securityPolicyOperationFixture(operationID string,
	override bool) login.UISecurityPolicyOperation {
	effective := login.UISecurityPolicyValues{Sensitive: true, ReauthRequired: true,
		MaxAuthAgeSeconds: 300, Strength: "password", ConfirmationRequired: true,
		NotificationRequired: true}
	operation := login.UISecurityPolicyOperation{
		OperationID: operationID, Domain: "password", Name: "修改账户密码",
		Description: "验证旧密码后设置新密码并撤销其他会话。",
		Default:     effective, HasDefault: true, Effective: effective, Source: "default",
		PermissionKey: "account.password.change", RootOnly: false, AuditRequired: true,
		Implemented: true, StrengthAvailable: true,
	}
	if override {
		overrideValues := effective
		overrideValues.MaxAuthAgeSeconds = 600
		operation.Override = &overrideValues
		operation.Effective = overrideValues
		operation.Source = "override"
		operation.ChangedFields = login.SecurityPolicyChangedFields(operation.Default, overrideValues)
	}
	return operation
}

// newSecurityPolicyFakeBackend 构造默认受控数据（root 可写）。
func newSecurityPolicyFakeBackend() *fakeSecurityPolicyBackend {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	password := securityPolicyOperationFixture("account.password.change", true)
	selfOperation := securityPolicyOperationFixture("security.policy.change", false)
	selfOperation.RootOnly = true
	selfOperation.ImmutableSensitive = true
	selfOperation.Name = "修改敏感操作策略"
	snapshot := login.UISecurityPolicySnapshot{
		ScopeID: "system", ScopeName: "system", Version: 4, CatalogVersion: "1.0.0",
		AvailableStrengths: []string{"none", "password"},
		Operations:         []login.UISecurityPolicyOperation{password, selfOperation},
	}
	settings := login.UINotificationSettings{
		Capabilities: login.UINotificationCapabilities{Read: true, TestMail: true,
			ReplaceSecret: true},
		From: "n***@example.test", SMTPAddr: "127.0.0.1:2525",
		SMTPHost: "127.0.0.1", TLSMode: "none", SMTPTimeoutSeconds: 10,
		MaxAttempts: 3, DeliveryTimeoutSeconds: 120, AllowPlaintextLocal: true,
		SenderConfigured: true, SecretConfigured: true, SecretStatusKnown: true,
		TemplatesConfigured: true, TemplateSource: "builtin",
		Templates: []login.UINotificationTemplate{{
			Kind: "security_notice", Subject: "EvernightLogin 安全提醒：{{.Event}}",
			Body: "你好 {{.DisplayName}}：\n\n事件：{{.Event}}\n", Source: "builtin"}},
		NotificationRequiredOperations: 6, NotificationRequiredKnown: true,
		NoticesAvailable: true,
		Notices: []login.UINotificationNotice{{OperationID: "account.password.change",
			Outcome: "success", State: "no_verified_email", RecipientMasked: "a***@example.test",
			CreatedAt: now}},
	}
	return &fakeSecurityPolicyBackend{
		caps: login.UISecurityPolicyCapabilities{ReadPolicies: true, WritePolicies: true,
			ReadNotifications: true, TestMail: true, ReplaceSecret: true},
		snapshot: snapshot,
		settings: settings,
		preview: login.UISecurityPolicyPreview{
			OperationID: "account.password.change", HasDefault: true,
			Token:   securityPolicyTestPreviewToken,
			Default: password.Default, Current: password.Effective,
			Proposed: login.UISecurityPolicyValues{Sensitive: true, ReauthRequired: false,
				MaxAuthAgeSeconds: 0, Strength: "none", ConfirmationRequired: false,
				NotificationRequired: true},
			ChangedFields: []string{"reauth_required", "max_auth_age_seconds",
				"strength", "confirmation_required"},
			DerivedFields: []string{"max_auth_age_seconds", "strength"},
		},
		restore: login.UISecurityPolicyRestorePreview{
			ScopeID: "system", ScopeName: "system", Version: 4, All: true,
			Token:      securityPolicyTestPreviewToken,
			Operations: []login.UISecurityPolicyOperation{password},
			NoChanges:  false,
		},
		writeResult: login.UISecurityPolicyWriteResult{Snapshot: snapshot, Changed: true,
			NotificationStatus: "unknown"},
		template: login.UINotificationTemplatePreview{Kind: "security_notice",
			Subject:  "EvernightLogin 安全提醒：测试安全告知（合成数据）",
			TextBody: "你好 测试收件人：\n", Valid: true},
		testResult: login.UINotificationTestResult{Status: "accepted",
			Kind: "security_notice", RecipientMasked: "t***@example.test",
			AttemptedAt: now},
		secret: login.UINotificationSecretResult{Replaced: true, SecretConfigured: true},
	}
}

// securityPolicyTestSessions 是管理会话替身。
type securityPolicyTestSessions struct {
	userID string
	err    error
}

func (s securityPolicyTestSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	if s.err != nil {
		return login.UISession{}, s.err
	}
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: "management",
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (securityPolicyTestSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "security-policy-csrf-token", nil
}

// newSecurityPolicyTestUI 构造带步骤 72 页面的 WebUI。
func newSecurityPolicyTestUI(t *testing.T, backend login.UISecurityPolicyBackend) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: securityPolicyTestSessions{userID: securityPolicyTestUserID},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		PageSecurityPolicy: &login.UIPageSecurityPolicyOptions{Backend: backend,
			ValidateCSRF: func(_ context.Context, _ *http.Request, token string) error {
				if token != securityPolicyTestCSRF {
					return errors.New("invalid csrf token")
				}
				return nil
			}}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// serveSecurityPolicyPage 执行页面请求。
func serveSecurityPolicyPage(ui http.Handler, method, target string,
	form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(nil))
	if method == http.MethodPost {
		request = httptest.NewRequest(method, "http://example.test"+target,
			bytes.NewReader([]byte(form.Encode())))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// policyForm 构造策略六字段表单。
func policyForm(extra map[string]string) url.Values {
	values := url.Values{}
	for key, value := range extra {
		values.Set(key, value)
	}
	values.Set("csrf_token", securityPolicyTestCSRF)
	return values
}

// confirmedPolicyForm 是保存/恢复表单：除 CSRF 外附带一次性预览令牌。
func confirmedPolicyForm(extra map[string]string) url.Values {
	values := policyForm(extra)
	values.Set("preview_token", securityPolicyTestPreviewToken)
	return values
}

// TestUIPageSecurityPolicyRoutesContract 验证路由集合、依赖校验与全部模板可解析。
func TestUIPageSecurityPolicyRoutesContract(t *testing.T) {
	ui := newSecurityPolicyTestUI(t, newSecurityPolicyFakeBackend())
	routes := map[string]bool{}
	for _, route := range ui.Routes() {
		routes[route.Name] = true
	}
	for _, name := range []string{"admin.security_policies", "admin.security_policy_detail",
		"admin.security_policy_preview", "admin.security_policy_save",
		"admin.security_policy_diff", "admin.security_policy_restore_preview",
		"admin.security_policy_restore", "admin.notification_mail",
		"admin.notification_mail_template_preview", "admin.notification_mail_test",
		"admin.notification_mail_secret"} {
		if !routes[name] {
			t.Fatalf("缺少步骤 72 路由 %s", name)
		}
	}
	validate := func(context.Context, *http.Request, string) error { return nil }
	if _, err := login.NewWebUI(login.WebUIOptions{
		PageSecurityPolicy: &login.UIPageSecurityPolicyOptions{
			ValidateCSRF: validate}}); err == nil {
		t.Fatal("空敏感策略后端应拒绝构造")
	}
	if _, err := login.NewWebUI(login.WebUIOptions{
		PageSecurityPolicy: &login.UIPageSecurityPolicyOptions{
			Backend: newSecurityPolicyFakeBackend()}}); err == nil {
		t.Fatal("缺少 CSRF 校验器应拒绝构造（fail-closed 装配门禁）")
	}
}

// TestUIPageSecurityPolicyListAndForbidden 验证目录三值、只读态与无读取许可。
func TestUIPageSecurityPolicyListAndForbidden(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	ui := newSecurityPolicyTestUI(t, backend)
	list := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/security/policies", nil)
	body := list.Body.String()
	if list.Code != 200 || !strings.Contains(body, "account.password.change") ||
		!strings.Contains(body, "策略覆盖") || !strings.Contains(body, "未设置覆盖") ||
		!strings.Contains(body, "当前读取 2 条操作") {
		t.Fatalf("目录渲染 = %d", list.Code)
	}
	// 无写入能力：只读提示，不出现编辑表单。
	backend.caps.WritePolicies = false
	detail := serveSecurityPolicyPage(ui, http.MethodGet,
		"/admin/security/policies/detail?operation=security.policy.change", nil)
	detailBody := detail.Body.String()
	if detail.Code != 200 || !strings.Contains(detailBody, "只有真实 root 可以修改") ||
		strings.Contains(detailBody, "预览未执行的修改") {
		t.Fatalf("只读详情 = %d", detail.Code)
	}
	// 无读取许可：不披露目录。
	backend.caps.ReadPolicies = false
	forbidden := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/security/policies", nil)
	if forbidden.Code != http.StatusForbidden ||
		!strings.Contains(forbidden.Body.String(), "你没有读取敏感操作策略的许可") ||
		strings.Contains(forbidden.Body.String(), "account.password.change") {
		t.Fatalf("无权限 = %d", forbidden.Code)
	}
}

// TestUIPageSecurityPolicyPreviewAndSelfConfirm 验证预览未执行、自身保护额外确认。
func TestUIPageSecurityPolicyPreviewAndSelfConfirm(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	ui := newSecurityPolicyTestUI(t, backend)
	preview := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/security/policies/preview",
		policyForm(map[string]string{"operation_id": "account.password.change",
			"expected_version": "4", "sensitive": "on", "notification_required": "on",
			"strength": "password", "max_auth_age_seconds": "600",
			"confirmation_required": "on"}))
	body := preview.Body.String()
	if preview.Code != 200 || !strings.Contains(body, "提交前预览，尚未执行") ||
		!strings.Contains(body, "拟提交值") || !strings.Contains(body, "派生") {
		t.Fatalf("预览 = %d", preview.Code)
	}
	// 未确认不能保存。
	noConfirm := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/save", confirmedPolicyForm(map[string]string{
			"operation_id": "account.password.change", "expected_version": "4",
			"sensitive": "on", "strength": "password", "max_auth_age_seconds": "600"}))
	if noConfirm.Code != http.StatusBadRequest ||
		!strings.Contains(noConfirm.Body.String(), "请先核对提交前预览") {
		t.Fatalf("未确认保存 = %d", noConfirm.Code)
	}
	// 自身保护修改必须额外勾选。
	backend.writeResult = login.UISecurityPolicyWriteResult{
		Snapshot: backend.snapshot, Changed: true, NotificationStatus: "unknown"}
	selfMissing := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/save", confirmedPolicyForm(map[string]string{
			"operation_id": "security.policy.change", "expected_version": "4",
			"sensitive": "on", "reauth_required": "on", "strength": "password",
			"max_auth_age_seconds": "300", "confirm": "yes"}))
	if selfMissing.Code != http.StatusBadRequest ||
		!strings.Contains(selfMissing.Body.String(), "必须单独勾选") {
		t.Fatalf("自身保护缺少额外确认 = %d", selfMissing.Code)
	}
	selfOK := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/security/policies/save",
		confirmedPolicyForm(map[string]string{"operation_id": "security.policy.change",
			"expected_version": "4", "sensitive": "on", "reauth_required": "on",
			"strength": "password", "max_auth_age_seconds": "300",
			"confirm": "yes", "self_confirm": "yes"}))
	if selfOK.Code != 200 || !strings.Contains(selfOK.Body.String(), "策略已保存") {
		t.Fatalf("自身保护保存 = %d", selfOK.Code)
	}
}

// TestUIPageSecurityPolicyConflictAndDraft 验证冲突提示、重新读取与草稿保留。
func TestUIPageSecurityPolicyConflictAndDraft(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	backend.failOn, backend.failCode = "save", "CONFLICT"
	ui := newSecurityPolicyTestUI(t, backend)
	response := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/security/policies/save",
		confirmedPolicyForm(map[string]string{"operation_id": "account.password.change",
			"expected_version": "4", "sensitive": "on", "reauth_required": "on",
			"strength": "password", "max_auth_age_seconds": "900",
			"notification_required": "on", "confirm": "yes"}))
	body := response.Body.String()
	if response.Code != http.StatusConflict ||
		!strings.Contains(body, "本次未保存") ||
		!strings.Contains(body, "900") || !strings.Contains(body, "禁止直接覆盖") {
		t.Fatalf("冲突处理 = %d conflict=%v age=%v draft=%v body=%s", response.Code,
			strings.Contains(body, "本次未保存"), strings.Contains(body, "900"),
			strings.Contains(body, "禁止直接覆盖"), body[:1200])
	}
}

// TestUIPageSecurityPolicyRestore 验证整体恢复预览、真实数量、保留声明与过期范围。
func TestUIPageSecurityPolicyRestore(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	backend.restore.Declared = []login.UISecurityPolicyOperation{{
		OperationID: "mail.export.report", Source: "application", Name: "导出报表"}}
	ui := newSecurityPolicyTestUI(t, backend)
	preview := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/restore/preview", policyForm(map[string]string{"mode": "all"}))
	body := preview.Body.String()
	if preview.Code != 200 || !strings.Contains(body, "实际影响范围") ||
		!strings.Contains(body, "本次将删除 1 条真实覆盖") ||
		!strings.Contains(body, "保留 1 项") {
		t.Fatalf("整体恢复预览 = %d", preview.Code)
	}
	// 逐项恢复预览绑定具体操作与版本，不混入整作用域范围。
	backend.restore.All = false
	backend.restore.OperationID = "password.change"
	single := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/restore/preview", policyForm(map[string]string{
			"mode": "one", "operation_id": "password.change"}))
	if single.Code != 200 || !strings.Contains(single.Body.String(), "恢复一个操作的默认策略") ||
		backend.lastAll {
		t.Fatalf("逐项恢复预览 = %d", single.Code)
	}
	backend.restore.All = true
	backend.restore.OperationID = ""
	// 已过期范围（数量被篡改）必须拒绝，不继续执行。
	stale := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/restore", confirmedPolicyForm(map[string]string{
			"mode": "all", "expected_version": "4", "affected_count": "9",
			"confirm": "yes", "self_protection": "0"}))
	if stale.Code != http.StatusConflict ||
		!strings.Contains(stale.Body.String(), "旧确认已失效") {
		t.Fatalf("过期恢复范围 = %d", stale.Code)
	}
	ok := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/security/policies/restore",
		confirmedPolicyForm(map[string]string{"mode": "all", "expected_version": "4",
			"affected_count": "1", "confirm": "yes", "self_protection": "0"}))
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), "恢复默认已执行") {
		t.Fatalf("整体恢复执行 = %d", ok.Code)
	}
}

// TestUIPageSecurityPolicyNotificationStates 验证通知设置真实状态、秘密遮罩、测试目标。
func TestUIPageSecurityPolicyNotificationStates(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	ui := newSecurityPolicyTestUI(t, backend)
	page := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/notifications/mail", nil)
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "账户没有已验证邮箱") ||
		!strings.Contains(body, "已配置 SMTP 密码，现有值不可查看") ||
		!strings.Contains(body, "••••••••") || strings.Contains(body, "smtp-secret-value") ||
		!strings.Contains(body, "运行时模板编辑能力尚未提供") {
		t.Fatalf("通知页 = %d", page.Code)
	}
	// 未配置真实状态与未配置模板。
	backend.settings.SenderConfigured = false
	backend.settings.TemplatesConfigured = false
	backend.settings.Templates = nil
	backend.settings.Capabilities.TestMail = false
	backend.caps.TestMail = false
	unconfigured := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/notifications/mail", nil)
	if !strings.Contains(unconfigured.Body.String(), "未配置") ||
		!strings.Contains(unconfigured.Body.String(), "不显示可提交的假发送控件") {
		t.Fatalf("未配置状态 = %d", unconfigured.Code)
	}
	// 测试邮件：空目标拒绝。
	empty := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/notifications/mail/test",
		policyForm(map[string]string{"kind": "security_notice", "confirm": "yes"}))
	if empty.Code != http.StatusBadRequest ||
		!strings.Contains(empty.Body.String(), "必须明确填写本次测试收件地址") {
		t.Fatalf("空目标 = %d", empty.Code)
	}
	// 未配置发送器：真实 not_configured，不伪造成功。
	backend.failOn = ""
	backend.testResult = login.UINotificationTestResult{Status: "not_configured",
		Kind: "security_notice"}
	notConfigured := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/test", policyForm(map[string]string{
			"recipient": "tester@example.test", "kind": "security_notice",
			"confirm": "yes"}))
	if !strings.Contains(notConfigured.Body.String(), "当前不能发送") {
		t.Fatalf("未配置测试发送 = %d", notConfigured.Code)
	}
	if backend.lastRecipient != "tester@example.test" {
		t.Fatalf("测试目标 = %q", backend.lastRecipient)
	}
}

// TestUIPageSecurityPolicyTemplateAndSecret 验证合成预览与秘密替换不回显。
func TestUIPageSecurityPolicyTemplateAndSecret(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	ui := newSecurityPolicyTestUI(t, backend)
	invalid := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/template/preview", policyForm(map[string]string{
			"kind": "unknown_kind"}))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("非法模板用途 = %d", invalid.Code)
	}
	preview := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/template/preview", policyForm(map[string]string{
			"kind": "security_notice"}))
	body := preview.Body.String()
	if preview.Code != 200 || !strings.Contains(body, "合成预览结果") ||
		!strings.Contains(body, "测试安全告知") || strings.Contains(body, "https://example.invalid/reset") {
		t.Fatalf("模板预览 = %d", preview.Code)
	}
	// 秘密替换：成功后不回显新秘密。
	const newSecret = "unit-test-new-smtp-secret-value"
	replaced := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/secret", policyForm(map[string]string{
			"secret_password": newSecret, "confirm": "yes"}))
	if replaced.Code != 200 || strings.Contains(replaced.Body.String(), newSecret) ||
		!strings.Contains(replaced.Body.String(), "秘密已替换") {
		t.Fatalf("秘密替换 = %d", replaced.Code)
	}
	if backend.lastSecret != newSecret {
		t.Fatalf("替换值未提交")
	}
	// 能力未提供：拒绝且不回声。
	backend.caps.ReplaceSecret = false
	removed := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/secret", policyForm(map[string]string{
			"secret_password": newSecret, "confirm": "yes"}))
	if removed.Code != http.StatusForbidden ||
		strings.Contains(removed.Body.String(), newSecret) {
		t.Fatalf("秘密能力未提供 = %d", removed.Code)
	}
}

// TestUIPageSecurityPolicyReadOnlyNoWriteForms 验证 N1：只读详情不渲染写表单。
func TestUIPageSecurityPolicyReadOnlyNoWriteForms(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	backend.caps.WritePolicies = false
	ui := newSecurityPolicyTestUI(t, backend)
	detail := serveSecurityPolicyPage(ui, http.MethodGet,
		"/admin/security/policies/detail?operation=account.password.change", nil)
	body := detail.Body.String()
	if detail.Code != 200 || strings.Contains(body, "恢复此操作的默认策略") ||
		strings.Contains(body, "/admin/security/policies/restore/preview") {
		t.Fatalf("只读详情仍渲染写表单: %d", detail.Code)
	}
}

// TestUIPageSecurityPolicyListLoadFailure 验证 N2：快照读取失败走正式错误态而非纯文本 500。
func TestUIPageSecurityPolicyListLoadFailure(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	backend.failOn, backend.failCode = "snapshot", "DB_UNAVAILABLE"
	ui := newSecurityPolicyTestUI(t, backend)
	failed := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/security/policies", nil)
	body := failed.Body.String()
	if failed.Code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "无法读取敏感操作策略") ||
		!strings.Contains(body, "重试") || strings.Contains(body, "页面暂时不可用") {
		t.Fatalf("列表读取失败状态 = %d body=%s", failed.Code, body[:400])
	}
}

// TestUIPageSecurityPolicyErrorKeysAndTokens 验证 N3 中文错误键、CSRF 拒绝与预览令牌要求。
func TestUIPageSecurityPolicyErrorKeysAndTokens(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	ui := newSecurityPolicyTestUI(t, backend)
	// CSRF 缺失：页面层 fail-closed，不进入业务。
	missingCSRF := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/preview", url.Values{"operation_id": {"account.password.change"}})
	if missingCSRF.Code != http.StatusForbidden ||
		!strings.Contains(missingCSRF.Body.String(), "表单安全令牌缺失或无效") {
		t.Fatalf("CSRF 缺失 = %d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}
	// 预览令牌缺失：保存必须先预览。
	noToken := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/save", policyForm(map[string]string{
			"operation_id": "account.password.change", "expected_version": "4",
			"sensitive": "on", "strength": "password", "max_auth_age_seconds": "600",
			"confirm": "yes"}))
	if noToken.Code != http.StatusBadRequest ||
		!strings.Contains(noToken.Body.String(), "一次性预览令牌") {
		t.Fatalf("缺少预览令牌 = %d", noToken.Code)
	}
	// 服务端 REQ_INVALID：显示中文摘要而非原始 i18n 键。
	backend.failOn, backend.failCode = "save", "REQ_INVALID"
	invalid := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/security/policies/save", confirmedPolicyForm(map[string]string{
			"operation_id": "account.password.change", "expected_version": "4",
			"sensitive": "on", "strength": "password", "max_auth_age_seconds": "600",
			"confirm": "yes"}))
	if invalid.Code != http.StatusBadRequest ||
		strings.Contains(invalid.Body.String(), "page.admin.security_policy.save.failed") ||
		!strings.Contains(invalid.Body.String(), "策略保存未完成") {
		t.Fatalf("REQ_INVALID 文案 = %d", invalid.Code)
	}
}

// TestUIPageSecurityPolicyDuplicateActions 验证幂等重复提交提示（M2 页面侧）。
func TestUIPageSecurityPolicyDuplicateActions(t *testing.T) {
	backend := newSecurityPolicyFakeBackend()
	backend.testResult = login.UINotificationTestResult{Status: "accepted",
		Kind: "security_notice", RecipientMasked: "t***@example.test", Duplicate: true}
	backend.secret = login.UINotificationSecretResult{Replaced: true,
		SecretConfigured: true, Duplicate: true}
	ui := newSecurityPolicyTestUI(t, backend)
	test := serveSecurityPolicyPage(ui, http.MethodPost, "/admin/notifications/mail/test",
		policyForm(map[string]string{"recipient": "tester@example.test",
			"kind": "security_notice", "confirm": "yes", "idempotency_key": "idem-1"}))
	if test.Code != 200 || !strings.Contains(test.Body.String(), "已存在相同测试请求") {
		t.Fatalf("重复测试发送提示 = %d", test.Code)
	}
	if backend.lastIdempotencyKey != "idem-1" {
		t.Fatalf("幂等键未传给后端: %q", backend.lastIdempotencyKey)
	}
	secret := serveSecurityPolicyPage(ui, http.MethodPost,
		"/admin/notifications/mail/secret", policyForm(map[string]string{
			"secret_password": "new-secret", "confirm": "yes",
			"idempotency_key": "idem-2"}))
	if secret.Code != 200 ||
		!strings.Contains(secret.Body.String(), "同一替换请求已处理") {
		t.Fatalf("重复秘密替换提示 = %d", secret.Code)
	}
}

// TestUIPageSecurityPolicySessionExpired 验证管理会话过期 fail-closed。
func TestUIPageSecurityPolicySessionExpired(t *testing.T) {
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: securityPolicyTestSessions{err: login.ErrUISessionExpired},
		PageSecurityPolicy: &login.UIPageSecurityPolicyOptions{
			Backend: newSecurityPolicyFakeBackend(),
			ValidateCSRF: func(context.Context, *http.Request, string) error {
				return nil
			}}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	response := serveSecurityPolicyPage(ui, http.MethodGet, "/admin/security/policies", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("会话过期 = %d", response.Code)
	}
}
