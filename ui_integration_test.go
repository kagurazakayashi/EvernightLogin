package login

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// realPageSessions 用真实 session 服务实现页面会话契约（模块内集成适配器；
// 生产装配由后续 instance/HTTP 装配步骤提供，README 已声明）。
type realPageSessions struct {
	service *session.Service
}

// ResolvePageSession 校验真实会话并返回公开安全摘要。
func (r realPageSessions) ResolvePageSession(ctx context.Context,
	request *http.Request) (UISession, error) {
	secret, ok := r.service.SessionSecretFromRequest(request)
	if !ok {
		return UISession{}, ErrUISessionExpired
	}
	record, err := r.service.Validate(ctx, secret)
	if err != nil {
		return UISession{}, ErrUISessionExpired
	}
	kind := "normal"
	if record.IsRestricted() {
		kind = "restricted"
	}
	return UISession{Authenticated: true, UserID: record.UserID, AppID: record.AppID,
		Kind: kind, ExpiresAt: record.AbsoluteExpiresAt}, nil
}

// IssueCSRFToken 为服务端渲染表单签发与会话绑定的页面 CSRF 令牌。
func (r realPageSessions) IssueCSRFToken(ctx context.Context,
	request *http.Request) (string, error) {
	secret, ok := r.service.SessionSecretFromRequest(request)
	if !ok {
		return "", ErrUISessionExpired
	}
	token, err := r.service.IssuePageCSRFToken(ctx, secret)
	if err != nil {
		return "", ErrUISessionExpired
	}
	return token.Reveal(), nil
}

// uiIntegrationEnv 是真实 SQLite + 真实会话 + 真实传输层的页面集成环境。
type uiIntegrationEnv struct {
	sessions *session.Service
	secret   string
	userID   string
	now      time.Time
}

// newUIIntegrationEnv 准备隔离数据库、账户与会话。
func newUIIntegrationEnv(t *testing.T) *uiIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "ui.db")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	now := time.Date(2026, 11, 17, 20, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: slog.New(slog.NewTextHandler(
		io.Discard, nil)), Now: clock})
	if err != nil {
		t.Fatalf("构造审计失败: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("生成密钥环失败: %v", err)
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	sessions, err := session.New(sessionStore, session.Options{AllowLegacyWithoutSensitive: true,
		Store: sessionStore, Audit: recorder, Keyring: keyring,
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 2 * time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	userID := "usr_00000000000000000000000000000042"
	if _, err := raw.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,status,
is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, "uiuser", "uiuser",
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入测试账户失败: %v", err)
	}
	issued, err := sessions.Login(ctx, session.LoginRequest{Result: authn.AuthenticateResult{
		UserID: userID, Username: "uiuser", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      now, SecurityVersion: 1}, RequestID: "req_ui_login"})
	if err != nil {
		t.Fatalf("签发会话失败: %v", err)
	}
	return &uiIntegrationEnv{sessions: sessions, secret: issued.Secret.Reveal(),
		userID: userID, now: now}
}

// csrfFormToken 从 HTML 表单提取隐藏 CSRF 令牌。
func csrfFormToken(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("页面未包含 CSRF 隐藏字段")
	}
	return match[1]
}

// TestWebUIIntegrationWithRealSession 验证真实会话 + 真实传输层：页面 CSP、
// 请求编号、无 JS 表单 CSRF、资源缓存、会话过期与 API 不受影响。
func TestWebUIIntegrationWithRealSession(t *testing.T) {
	env := newUIIntegrationEnv(t)
	pageSessions := realPageSessions{service: env.sessions}
	ui, err := NewWebUI(WebUIOptions{Prefix: "/login", Session: pageSessions,
		EnableComponentPreview: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("构造页面处理器失败: %v", err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{Prefix: "/login",
		UI: &UIHTTPOptions{Handler: ui,
			PageContentSecurityPolicy: DefaultUIPageContentSecurityPolicy},
		Protection: &HTTPProtectionOptions{CSRF: CSRFPolicy{Enabled: true,
			AllowedOrigins:              []string{"http://example.com"},
			RequireForAllUnsafeRequests: true,
			TokenValidator:              env.sessions}}})
	if err != nil {
		t.Fatalf("构造 HTTP Handler 失败: %v", err)
	}
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	// 受保护页面：真实会话 + 页面 CSP + 请求编号 + 无 JS 表单 CSRF。
	get := httptest.NewRequest(http.MethodGet, "http://example.com/login/_ui/preview", nil)
	get.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	recorder := serve(get)
	if recorder.Code != http.StatusOK {
		t.Fatalf("受保护页面应 200，实际 %d", recorder.Code)
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("HTML 页面 CSP 未覆盖: %q", recorder.Header().Get("Content-Security-Policy"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("HTML 页面应 no-store，实际 %q", recorder.Header().Get("Cache-Control"))
	}
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("页面响应缺少 X-Request-ID")
	}
	body := recorder.Body.String()
	token := csrfFormToken(t, body)
	// 同一会话重复渲染令牌稳定（多标签页可用）。
	secondGet := httptest.NewRequest(http.MethodGet, "http://example.com/login/_ui/preview", nil)
	secondGet.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	if second := serve(secondGet); csrfFormToken(t, second.Body.String()) != token {
		t.Fatal("同一会话的页面 CSRF 令牌应稳定")
	}
	// 无 JavaScript 表单 POST：隐藏字段 + 同源 Origin → 通过同一 CSRF 校验器。
	form := url.Values{"display_name": {"示例"}, "csrf_token": {token}}
	post := httptest.NewRequest(http.MethodPost, "http://example.com/login/_ui/preview",
		strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://example.com")
	post.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	postRecorder := serve(post)
	if postRecorder.Code != http.StatusOK || !strings.Contains(postRecorder.Body.String(), "操作已完成") {
		t.Fatalf("无 JS 表单应通过 CSRF 并渲染成功状态，实际 %d", postRecorder.Code)
	}
	// 缺少隐藏字段、重复字段与跨源 Origin 一律拒绝。
	missing := url.Values{"display_name": {"示例"}}
	missingPost := httptest.NewRequest(http.MethodPost, "http://example.com/login/_ui/preview",
		strings.NewReader(missing.Encode()))
	missingPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingPost.Header.Set("Origin", "http://example.com")
	missingPost.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	if recorder := serve(missingPost); recorder.Code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 字段应 403，实际 %d", recorder.Code)
	}
	duplicated := url.Values{"csrf_token": {token, token}}
	duplicatedPost := httptest.NewRequest(http.MethodPost,
		"http://example.com/login/_ui/preview", strings.NewReader(duplicated.Encode()))
	duplicatedPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	duplicatedPost.Header.Set("Origin", "http://example.com")
	duplicatedPost.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	if recorder := serve(duplicatedPost); recorder.Code != http.StatusForbidden {
		t.Fatalf("重复 CSRF 字段应 403，实际 %d", recorder.Code)
	}
	crossOrigin := httptest.NewRequest(http.MethodPost, "http://example.com/login/_ui/preview",
		strings.NewReader(form.Encode()))
	crossOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOrigin.Header.Set("Origin", "http://evil.example")
	crossOrigin.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	if recorder := serve(crossOrigin); recorder.Code != http.StatusForbidden {
		t.Fatalf("跨源表单应 403，实际 %d", recorder.Code)
	}
	// 静态资源带指纹且可长期缓存。
	assetMatch := regexp.MustCompile(`href="(/login/assets/[^"]+/css/base\.css)"`).
		FindStringSubmatch(body)
	if len(assetMatch) != 2 {
		t.Fatal("页面未引用带指纹的本地样式资源")
	}
	assetRequest := httptest.NewRequest(http.MethodGet, "http://example.com"+assetMatch[1], nil)
	assetRecorder := serve(assetRequest)
	if assetRecorder.Code != http.StatusOK ||
		assetRecorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("静态资源响应不正确: %d %q", assetRecorder.Code,
			assetRecorder.Header().Get("Cache-Control"))
	}
	// 会话过期（退出后旧 Cookie）→ 401 状态页，不伪装成功。
	if err := env.sessions.Logout(context.Background(), env.secret); err != nil {
		t.Fatalf("退出会话失败: %v", err)
	}
	expiredGet := httptest.NewRequest(http.MethodGet, "http://example.com/login/_ui/preview", nil)
	expiredGet.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: env.secret})
	if recorder := serve(expiredGet); recorder.Code != http.StatusUnauthorized ||
		!strings.Contains(recorder.Body.String(), "会话已过期") {
		t.Fatalf("过期会话应 401 状态页，实际 %d", recorder.Code)
	}
	// API 路由不受页面挂载影响。
	for _, path := range []string{"/login/healthz", "/login/openapi.json"} {
		apiRequest := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		apiRecorder := serve(apiRequest)
		if apiRecorder.Code != http.StatusOK || !strings.HasPrefix(
			apiRecorder.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s 应保持 JSON API 响应，实际 %d %q", path, apiRecorder.Code,
				apiRecorder.Header().Get("Content-Type"))
		}
	}
}

// TestWebUIDisabledKeepsAPIAvailable 验证禁用内置页面后核心 API 与协议空间仍可用。
func TestWebUIDisabledKeepsAPIAvailable(t *testing.T) {
	ui, err := NewWebUI(WebUIOptions{Prefix: "/login", DisableBuiltinPages: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("禁用内置页面构造失败: %v", err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{Prefix: "/login",
		UI: &UIHTTPOptions{Handler: ui, PageContentSecurityPolicy: DefaultUIPageContentSecurityPolicy}})
	if err != nil {
		t.Fatalf("构造 HTTP Handler 失败: %v", err)
	}
	for _, path := range []string{"/login/healthz", "/login/openapi.json"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("禁用内置 UI 后 %s 应可用，实际 %d", path, recorder.Code)
		}
	}
	// 内置页面关闭 → 404，不伪装成功。
	request := httptest.NewRequest(http.MethodGet, "http://example.com/login/403", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("禁用内置 UI 后页面应 404，实际 %d", recorder.Code)
	}
}
