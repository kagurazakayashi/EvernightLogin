package login_test

// 步骤 72 真实服务集成测试（安全修复轮）：临时 SQLite + 真实 policy.Service
// （sqlite 存储、审计、root 判定、ExpectedVersion、ImmutableSensitive、恢复语义）+
// 真实 uiadminadapter.SecurityPolicyAdapter。宿主端口用测试替身并明确声明：Authorize
// 白名单、Reauth 记录/可拒绝、进程内本地捕获发送器（不联网）；领域判定为真实实现。
//
// 覆盖安全审计 M1（预览令牌绑定目标/参数、换目标/换参数/重复使用拒绝、恢复范围绑定、
// reauth 收到同一参数摘要）、M2（秘密替换/测试邮件 reauth+审计+幂等）、M3（CSRF 构造期
// 门禁与请求期拒绝）。

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	policyIntegrationRootID   = "usr_00000000000000000000000000000001"
	policyIntegrationReaderID = "usr_00000000000000000000000000000002"
	policyIntegrationOtherID  = "usr_00000000000000000000000000000003"
	policyIntegrationCSRF     = "security-policy-csrf-token"
)

// captureSender 是进程内本地邮件捕获器（仅测试；不发往任何网络地址）。
type captureSender struct {
	mu       sync.Mutex
	messages []mailer.Message
	failure  error
}

func (s *captureSender) Send(_ context.Context, message mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	s.messages = append(s.messages, message)
	return nil
}

func (s *captureSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// policyIntegrationEnv 是真实策略服务 + 页面适配器环境。
type policyIntegrationEnv struct {
	t          *testing.T
	adapter    *uiadminadapter.SecurityPolicyAdapter
	storage    *storagesqlite.Store
	recorder   *audit.Recorder
	sender     *captureSender
	mu         sync.Mutex
	reauthFail bool
	bindings   []login.UISecurityPolicyActionBinding
	secrets    []string
}

// fakePolicyAuthorizer 是策略读取授权替身：root 与显式 reader 能读；写仍由
// policy.Service 强制真实 root。
type fakePolicyAuthorizer struct{ readerID string }

func (a fakePolicyAuthorizer) AuthorizePolicy(_ context.Context, caller policy.Caller,
	_ string, write bool) error {
	if write {
		return nil
	}
	id := caller.Actor().ID
	if id == a.readerID || id == policyIntegrationRootID {
		return nil
	}
	return policy.ErrAccessDenied
}

// newPolicyIntegrationEnv 构造隔离数据库与真实服务。
func newPolicyIntegrationEnv(t *testing.T) *policyIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "policy-pages.db")))
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
	nowMillis := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC).UnixMilli()
	for _, user := range []struct {
		id       string
		username string
		root     int
	}{
		{policyIntegrationRootID, "rootuser", 1},
		{policyIntegrationReaderID, "policyreader", 0},
		{policyIntegrationOtherID, "normaluser", 0},
	} {
		if _, err := storage.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',?,1,1,?,?)`,
			user.id, user.username, user.username, user.root, nowMillis, nowMillis); err != nil {
			t.Fatalf("用户: %v", err)
		}
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	policyStore, err := policysqlite.New(storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	env := &policyIntegrationEnv{t: t, storage: storage, recorder: recorder,
		sender: &captureSender{}}
	service, err := policy.New(policy.Options{
		Store: policyStore, Audit: recorder,
		ReauthVerifier: policy.ReauthVerifierFunc(func(context.Context, policy.Caller, string) error {
			env.mu.Lock()
			defer env.mu.Unlock()
			if env.reauthFail {
				return policy.ErrReauthRequired
			}
			return nil
		}),
		Authorizer:         fakePolicyAuthorizer{readerID: policyIntegrationReaderID},
		AvailableStrengths: []policy.Strength{policy.StrengthNone, policy.StrengthPassword},
		Now:                time.Now, Logger: testDiscardLogger(),
	})
	if err != nil {
		t.Fatalf("策略服务: %v", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("默认模板: %v", err)
	}
	adapter, err := uiadminadapter.NewSecurityPolicy(uiadminadapter.SecurityPolicyOptions{
		Policy: service,
		Authorize: func(_ context.Context, userID, _ string) error {
			switch userID {
			case policyIntegrationRootID, policyIntegrationReaderID:
				return nil
			default:
				return errors.New("denied-by-host-authorizer")
			}
		},
		Reauth: func(_ context.Context, userID string,
			binding login.UISecurityPolicyActionBinding) error {
			env.mu.Lock()
			defer env.mu.Unlock()
			if env.reauthFail {
				return errors.New("reauth-denied")
			}
			binding.UserID = userID
			env.bindings = append(env.bindings, binding)
			return nil
		},
		Audit: recorder,
		Mail: &uiadminadapter.NotificationMailOptions{
			Sender: env.sender, Templates: templates, TemplateSource: "builtin",
			FromAddress: "security@example.test", SMTPAddr: "127.0.0.1:2525",
			SMTPHost: "127.0.0.1", TLSMode: "none", SMTPTimeoutSeconds: 10,
			MaxAttempts: 3, DeliveryTimeoutSeconds: 120, AllowPlaintextLocal: true,
			SecretConfigured: true, SecretStatusKnown: true,
			ReplaceSecret: func(_ context.Context, userID, newSecret, _ string) error {
				env.mu.Lock()
				defer env.mu.Unlock()
				env.secrets = append(env.secrets, userID+":"+newSecret)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("页面适配器: %v", err)
	}
	env.adapter = adapter
	return env
}

// newPolicyIntegrationUI 构造指定管理员的页面处理器。
func newPolicyIntegrationUI(t *testing.T, env *policyIntegrationEnv, userID string) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: securityPolicyTestSessions{userID: userID},
		PageSecurityPolicy: &login.UIPageSecurityPolicyOptions{Backend: env.adapter,
			ValidateCSRF: func(_ context.Context, _ *http.Request, token string) error {
				if token != policyIntegrationCSRF {
					return errors.New("invalid csrf token")
				}
				return nil
			}}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// postPolicyForm 发送表单请求。
func postPolicyForm(ui http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "http://example.test"+target,
		bytes.NewReader([]byte(form.Encode())))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// getPolicyPage 发送 GET 请求。
func getPolicyPage(ui http.Handler, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// previewFormValues 构造带 CSRF 的预览表单（预览不接受 confirm 字段）。
func previewFormValues(operationID, age, strength string) url.Values {
	values := policyFormValues(operationID, age, strength)
	values.Del("confirm")
	return values
}

// policyFormValues 构造带 CSRF 的六字段表单。
func policyFormValues(operationID, age, strength string) url.Values {
	return url.Values{
		"csrf_token":            {policyIntegrationCSRF},
		"operation_id":          {operationID},
		"expected_version":      {"0"},
		"sensitive":             {"on"},
		"reauth_required":       {"on"},
		"max_auth_age_seconds":  {age},
		"strength":              {strength},
		"confirmation_required": {"on"},
		"notification_required": {"on"},
		"confirm":               {"yes"},
	}
}

// cloneValues 复制表单值（避免多次提交共享同一 url.Values 被互相修改）。
func cloneValues(values url.Values) url.Values {
	clone := url.Values{}
	for key, items := range values {
		for _, item := range items {
			clone.Add(key, item)
		}
	}
	return clone
}

// hiddenValue 从 HTML 中提取隐藏输入值。
func hiddenValue(body, name string) string {
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// previewSaveToken 取得保存预览令牌。
func previewSaveToken(t *testing.T, ui http.Handler, form url.Values) string {
	t.Helper()
	response := postPolicyForm(ui, "/admin/security/policies/preview", form)
	if response.Code != http.StatusOK {
		t.Fatalf("预览失败 = %d", response.Code)
	}
	token := hiddenValue(response.Body.String(), "preview_token")
	if token == "" {
		t.Fatalf("预览未返回令牌: %s", response.Body.String()[:400])
	}
	return token
}

// countAudit 统计指定动作的审计事件数。
func (e *policyIntegrationEnv) countAudit(action string) int {
	e.t.Helper()
	var count int
	if err := e.storage.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, action).Scan(&count); err != nil {
		e.t.Fatalf("审计计数: %v", err)
	}
	return count
}

// lastBinding 返回最后一次再次认证绑定。
func (e *policyIntegrationEnv) lastBinding() login.UISecurityPolicyActionBinding {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.bindings) == 0 {
		return login.UISecurityPolicyActionBinding{}
	}
	return e.bindings[len(e.bindings)-1]
}

// TestPolicyIntegrationBindingAndConflict 验证 M1 预览/再次认证绑定与并发冲突。
func TestPolicyIntegrationBindingAndConflict(t *testing.T) {
	env := newPolicyIntegrationEnv(t)
	ui := newPolicyIntegrationUI(t, env, policyIntegrationRootID)
	if list := getPolicyPage(ui, "/admin/security/policies"); list.Code != http.StatusOK ||
		!strings.Contains(list.Body.String(), "security.policy.change") {
		t.Fatalf("目录 = %d", list.Code)
	}
	previewA := previewFormValues("password.change", "900", "password")
	tokenA := previewSaveToken(t, ui, previewA)
	previewB := previewFormValues("password.change", "1200", "password")
	tokenB := previewSaveToken(t, ui, previewB)
	formA := policyFormValues("password.change", "900", "password")
	formB := policyFormValues("password.change", "1200", "password")
	// 换参数：预览 900，提交 1200 + 同一令牌必须拒绝。
	changed := cloneValues(formA)
	changed.Set("max_auth_age_seconds", "1200")
	changed.Set("preview_token", tokenA)
	if rejected := postPolicyForm(ui, "/admin/security/policies/save", changed); rejected.Code != http.StatusConflict ||
		!strings.Contains(rejected.Body.String(), "预览已过期或与提交内容不一致") {
		t.Fatalf("换参数应拒绝 = %d body=%s", rejected.Code, rejected.Body.String())
	}
	// 换目标：同一令牌用于另一操作必须拒绝。
	targetSwap := cloneValues(formA)
	targetSwap.Set("operation_id", "mfa.add")
	targetSwap.Set("preview_token", tokenA)
	if rejected := postPolicyForm(ui, "/admin/security/policies/save", targetSwap); rejected.Code != http.StatusConflict {
		t.Fatalf("换目标应拒绝 = %d", rejected.Code)
	}
	// 正常保存：令牌绑定值与再次认证参数摘要。
	formA.Set("preview_token", tokenA)
	saved := postPolicyForm(ui, "/admin/security/policies/save", formA)
	if saved.Code != http.StatusOK {
		idx := strings.Index(saved.Body.String(), "ln-banner--error")
		snippet := ""
		if idx >= 0 && idx+260 <= len(saved.Body.String()) {
			snippet = saved.Body.String()[idx : idx+260]
		}
		t.Fatalf("保存 = %d token=%q ver=%q snippet=%s", saved.Code,
			formA.Get("preview_token"), formA.Get("expected_version"), snippet)
	}
	binding := env.lastBinding()
	if binding.Action != "policy.save" || binding.OperationID != "password.change" ||
		binding.ChangeDigest == "" || binding.Version != 0 {
		t.Fatalf("再次认证绑定 = %+v", binding)
	}
	// 重复使用同一预览令牌必须拒绝（一次性消费）。
	if reused := postPolicyForm(ui, "/admin/security/policies/save", formA); reused.Code != http.StatusConflict {
		t.Fatalf("重复使用令牌应拒绝 = %d", reused.Code)
	}
	// 版本冲突：tokenB 绑定版本 0，但服务端版本已递增 → CONFLICT。
	formB.Set("preview_token", tokenB)
	if conflict := postPolicyForm(ui, "/admin/security/policies/save", formB); conflict.Code != http.StatusConflict ||
		!strings.Contains(conflict.Body.String(), "本次未保存") {
		t.Fatalf("版本冲突 = %d", conflict.Code)
	}
	// 真实成功的自身保护修改：额外 self_confirm + 绑定摘要含 SelfProtection。
	selfPreview := previewFormValues("security.policy.change", "600", "password")
	selfPreview.Set("expected_version", "1")
	selfToken := previewSaveToken(t, ui, selfPreview)
	selfForm := policyFormValues("security.policy.change", "600", "password")
	selfForm.Set("expected_version", "1")
	selfForm.Set("preview_token", selfToken)
	selfForm.Set("self_confirm", "yes")
	if savedSelf := postPolicyForm(ui, "/admin/security/policies/save", selfForm); savedSelf.Code != http.StatusOK {
		t.Fatalf("自身保护修改 = %d", savedSelf.Code)
	}
	if binding := env.lastBinding(); !binding.SelfProtection ||
		binding.OperationID != "security.policy.change" {
		t.Fatalf("自身保护再次认证绑定 = %+v", binding)
	}
}

// TestPolicyIntegrationRestoreBinding 验证恢复范围预览令牌绑定。
func TestPolicyIntegrationRestoreBinding(t *testing.T) {
	env := newPolicyIntegrationEnv(t)
	ui := newPolicyIntegrationUI(t, env, policyIntegrationRootID)
	token := previewSaveToken(t, ui, previewFormValues("password.change", "900", "password"))
	form := policyFormValues("password.change", "900", "password")
	form.Set("preview_token", token)
	if saved := postPolicyForm(ui, "/admin/security/policies/save", form); saved.Code != http.StatusOK {
		t.Fatalf("建立覆盖 = %d", saved.Code)
	}
	restorePreview := postPolicyForm(ui, "/admin/security/policies/restore/preview",
		url.Values{"csrf_token": {policyIntegrationCSRF}, "mode": {"all"}})
	if restorePreview.Code != http.StatusOK {
		t.Fatalf("恢复预览 = %d", restorePreview.Code)
	}
	restoreToken := hiddenValue(restorePreview.Body.String(), "preview_token")
	if restoreToken == "" {
		t.Fatal("恢复预览未签发令牌")
	}
	// 换范围：预览 all，提交 one 必须拒绝。
	swap := url.Values{"csrf_token": {policyIntegrationCSRF}, "mode": {"one"},
		"operation_id": {"password.change"}, "expected_version": {"1"},
		"affected_count": {"1"}, "self_protection": {"0"},
		"confirm": {"yes"}, "preview_token": {restoreToken}}
	if rejected := postPolicyForm(ui, "/admin/security/policies/restore", swap); rejected.Code != http.StatusConflict {
		t.Fatalf("换恢复范围应拒绝 = %d", rejected.Code)
	}
	ok := url.Values{"csrf_token": {policyIntegrationCSRF}, "mode": {"all"},
		"expected_version": {"1"}, "affected_count": {"1"}, "self_protection": {"0"},
		"confirm": {"yes"}, "preview_token": {restoreToken}}
	if restored := postPolicyForm(ui, "/admin/security/policies/restore", ok); restored.Code != http.StatusOK ||
		!strings.Contains(restored.Body.String(), "恢复默认已执行") {
		t.Fatalf("恢复执行 = %d", restored.Code)
	}
}

// TestPolicyIntegrationNonRoot 验证非 root 只读、无写控件与写入拒绝。
func TestPolicyIntegrationNonRoot(t *testing.T) {
	env := newPolicyIntegrationEnv(t)
	rootUI := newPolicyIntegrationUI(t, env, policyIntegrationRootID)
	// 先由 root 建立覆盖，供只读详情检查。
	form := policyFormValues("password.change", "900", "password")
	form.Set("preview_token", previewSaveToken(t, rootUI,
		previewFormValues("password.change", "900", "password")))
	if saved := postPolicyForm(rootUI, "/admin/security/policies/save", form); saved.Code != http.StatusOK {
		t.Fatalf("root 覆盖 = %d", saved.Code)
	}
	readerUI := newPolicyIntegrationUI(t, env, policyIntegrationReaderID)
	list := getPolicyPage(readerUI, "/admin/security/policies")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "只读视图") {
		t.Fatalf("只读目录 = %d", list.Code)
	}
	detail := getPolicyPage(readerUI,
		"/admin/security/policies/detail?operation=password.change")
	if detail.Code != http.StatusOK ||
		strings.Contains(detail.Body.String(), "/admin/security/policies/restore/preview") ||
		strings.Contains(detail.Body.String(), "恢复此操作的默认策略") {
		t.Fatalf("只读详情不应有写表单 = %d", detail.Code)
	}
	// 非 root 直接写：处理器收下但领域 root 判定拒绝。
	deniedForm := policyFormValues("password.change", "900", "password")
	deniedForm.Set("expected_version", "1")
	readerPreview := previewFormValues("password.change", "900", "password")
	readerPreview.Set("expected_version", "1")
	preview := postPolicyForm(readerUI, "/admin/security/policies/preview", readerPreview)
	if preview.Code != http.StatusOK {
		t.Fatalf("只读预览 = %d", preview.Code)
	}
	deniedForm.Set("preview_token", hiddenValue(preview.Body.String(), "preview_token"))
	deniedForm.Set("expected_version", "1")
	if denied := postPolicyForm(readerUI, "/admin/security/policies/save", deniedForm); denied.Code != http.StatusForbidden {
		t.Fatalf("非 root 写入 = %d token=%q version=%q", denied.Code,
			deniedForm.Get("preview_token"), deniedForm.Get("expected_version"))
	}
	// 无读取许可用户：403 且不披露目录。
	otherUI := newPolicyIntegrationUI(t, env, policyIntegrationOtherID)
	if forbidden := getPolicyPage(otherUI, "/admin/security/policies"); forbidden.Code != http.StatusForbidden ||
		strings.Contains(forbidden.Body.String(), "password.change") {
		t.Fatalf("无读取许可 = %d", forbidden.Code)
	}
}

// TestPolicyIntegrationReauthAndCSRF 验证再次认证拒绝与 CSRF 缺省拒绝。
func TestPolicyIntegrationReauthAndCSRF(t *testing.T) {
	env := newPolicyIntegrationEnv(t)
	ui := newPolicyIntegrationUI(t, env, policyIntegrationRootID)
	token := previewSaveToken(t, ui, previewFormValues("password.change", "900", "password"))
	// CSRF 缺失/错误：必须 fail-closed。
	if missing := postPolicyForm(ui, "/admin/security/policies/save", url.Values{
		"operation_id": {"password.change"}, "expected_version": {"0"},
		"sensitive": {"on"}, "strength": {"password"},
		"max_auth_age_seconds": {"900"}, "confirm": {"yes"},
		"preview_token": {token}}); missing.Code != http.StatusForbidden {
		t.Fatalf("CSRF 缺失 = %d", missing.Code)
	}
	wrongCSRF := policyFormValues("password.change", "900", "password")
	wrongCSRF.Set("csrf_token", "forged-token")
	wrongCSRF.Set("preview_token", token)
	if wrong := postPolicyForm(ui, "/admin/security/policies/save", wrongCSRF); wrong.Code != http.StatusForbidden {
		t.Fatalf("CSRF 错误 = %d", wrong.Code)
	}
	// 再次认证拒绝：令牌有效、CSRF 有效，但宿主 Reauth 拒绝 → 403 REAUTH_REQUIRED。
	env.mu.Lock()
	env.reauthFail = true
	env.mu.Unlock()
	valid := policyFormValues("password.change", "900", "password")
	valid.Set("preview_token", token)
	if denied := postPolicyForm(ui, "/admin/security/policies/save", valid); denied.Code != http.StatusForbidden ||
		!strings.Contains(denied.Body.String(), "需要为本次实际操作重新完成") {
		t.Fatalf("再次认证拒绝 = %d", denied.Code)
	}
}

// TestPolicyIntegrationNotificationAuditAndIdempotency 验证 M2 再认证/审计/幂等。
func TestPolicyIntegrationNotificationAuditAndIdempotency(t *testing.T) {
	env := newPolicyIntegrationEnv(t)
	ui := newPolicyIntegrationUI(t, env, policyIntegrationRootID)
	page := getPolicyPage(ui, "/admin/notifications/mail")
	if page.Code != http.StatusOK {
		t.Fatalf("通知页 = %d", page.Code)
	}
	body := page.Body.String()
	idempotency := hiddenValue(body, "idempotency_key")
	if idempotency == "" {
		t.Fatal("通知页未签发幂等键")
	}
	// 秘密替换：真实回调 + 再次认证 + 审计，页面不回显。
	const newSecret = "integration-new-smtp-secret"
	secretForm := url.Values{"csrf_token": {policyIntegrationCSRF},
		"secret_password": {newSecret}, "confirm": {"yes"},
		"idempotency_key": {idempotency}}
	replaced := postPolicyForm(ui, "/admin/notifications/mail/secret", secretForm)
	if replaced.Code != http.StatusOK ||
		strings.Contains(replaced.Body.String(), newSecret) ||
		!strings.Contains(replaced.Body.String(), "秘密已替换") {
		t.Fatalf("秘密替换 = %d", replaced.Code)
	}
	env.mu.Lock()
	secretCount := len(env.secrets)
	env.mu.Unlock()
	if secretCount != 1 {
		t.Fatalf("宿主替换回调次数 = %d", secretCount)
	}
	if binding := env.lastBinding(); binding.Action != "mail.secret.replace" ||
		binding.ChangeDigest == "" {
		t.Fatalf("秘密替换再次认证绑定 = %+v", binding)
	}
	if env.countAudit("notification.mail.secret.replace") != 1 {
		t.Fatal("秘密替换缺少成功审计")
	}
	// 重复提交同一幂等键：不再调用宿主、不再新增审计。
	duplicate := postPolicyForm(ui, "/admin/notifications/mail/secret", secretForm)
	if duplicate.Code != http.StatusOK ||
		!strings.Contains(duplicate.Body.String(), "同一替换请求已处理") {
		t.Fatalf("重复秘密替换 = %d", duplicate.Code)
	}
	env.mu.Lock()
	if len(env.secrets) != secretCount {
		env.mu.Unlock()
		t.Fatal("幂等键未阻止重复替换")
	}
	env.mu.Unlock()
	if env.countAudit("notification.mail.secret.replace") != 1 {
		t.Fatal("幂等重复不应新增审计")
	}
	// 测试邮件：明确目标 + 再次认证 + 审计 + 幂等。
	testKey := hiddenValue(page.Body.String(), "idempotency_key")
	testForm := url.Values{"csrf_token": {policyIntegrationCSRF},
		"recipient": {"capture@example.test"}, "kind": {"security_notice"},
		"confirm": {"yes"}, "idempotency_key": {testKey}}
	sent := postPolicyForm(ui, "/admin/notifications/mail/test", testForm)
	if sent.Code != http.StatusOK || !strings.Contains(sent.Body.String(), "发送后端已接受测试邮件") {
		t.Fatalf("测试发送 = %d", sent.Code)
	}
	if env.sender.count() != 1 {
		t.Fatalf("本地捕获器数量 = %d", env.sender.count())
	}
	if binding := env.lastBinding(); binding.Action != "mail.test" ||
		binding.RecipientDigest == "" || binding.Kind != "security_notice" {
		t.Fatalf("测试邮件再次认证绑定 = %+v", binding)
	}
	if env.countAudit("notification.mail.test") != 1 {
		t.Fatal("测试邮件缺少成功审计")
	}
	repeat := postPolicyForm(ui, "/admin/notifications/mail/test", testForm)
	if repeat.Code != http.StatusOK ||
		!strings.Contains(repeat.Body.String(), "已存在相同测试请求") {
		t.Fatalf("重复测试发送 = %d", repeat.Code)
	}
	if env.sender.count() != 1 {
		t.Fatalf("幂等键未阻止重复发送 = %d", env.sender.count())
	}
	// 发送失败：真实错误码 + 失败审计，不伪造成功。
	env.sender.mu.Lock()
	env.sender.failure = &mailer.SendError{Kind: mailer.FailurePermanent,
		Code: mailer.CodeRejected, Err: errors.New("5xx")}
	env.sender.mu.Unlock()
	failedForm := url.Values{"csrf_token": {policyIntegrationCSRF},
		"recipient": {"capture@example.test"}, "kind": {"security_notice"},
		"confirm": {"yes"}, "idempotency_key": {"idem-fail-1"}}
	failed := postPolicyForm(ui, "/admin/notifications/mail/test", failedForm)
	if failed.Code != http.StatusOK ||
		!strings.Contains(failed.Body.String(), "测试邮件发送失败") ||
		!strings.Contains(failed.Body.String(), "MAIL_SEND_REJECTED") {
		t.Fatalf("发送失败状态 = %d", failed.Code)
	}
	if env.countAudit("notification.mail.test") < 2 {
		t.Fatal("测试邮件失败缺少审计")
	}
	// 非 root：收到通知只读页但无测试/替换能力。
	readerUI := newPolicyIntegrationUI(t, env, policyIntegrationReaderID)
	readerPage := getPolicyPage(readerUI, "/admin/notifications/mail")
	if readerPage.Code != http.StatusOK ||
		strings.Contains(readerPage.Body.String(), "测试收件邮箱") {
		t.Fatalf("只读管理员通知页 = %d", readerPage.Code)
	}
	if denied := postPolicyForm(readerUI, "/admin/notifications/mail/secret",
		url.Values{"csrf_token": {policyIntegrationCSRF}, "secret_password": {"x"},
			"confirm": {"yes"}}); denied.Code != http.StatusForbidden {
		t.Fatalf("只读管理员替换秘密 = %d", denied.Code)
	}
}
