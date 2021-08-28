package login_test

// 步骤 74 HTTP 页面 ↔ 真实 auditops 服务联调测试：真实 SQLite + 真实 internal/audit
// 写入 + 真实 internal/auditops + 真实 uiadminadapter 适配器，经 NewWebUI 渲染页面。
// 边界处（权限引擎、root、再次认证、任务执行）使用测试替身，不冒充生产鉴权；
// 真实任务执行器执行与浏览器视口另列未实测项。

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// httpAuditAuthorizer 只按调用者 + 权限键 + 作用范围放行。
type httpAuditAuthorizer struct {
	grants map[string]auditops.ScopeGrant
}

func (f *httpAuditAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	key := caller.Actor().ID + "|" + permissionKey + "|" + scopeID
	if grant, ok := f.grants[key]; ok {
		return grant, nil
	}
	return auditops.ScopeGrant{Allowed: false}, nil
}

type httpAuditRoot struct{ roots map[string]bool }

func (f *httpAuditRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	return f.roots[caller.Actor().ID], nil
}

type httpAuditSensitive struct{}

func (httpAuditSensitive) Authorize(context.Context, reauth.Caller,
	reauth.Request) (reauth.Result, error) {
	return reauth.Result{}, nil
}

func (httpAuditSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

type httpAuditEnqueuer struct{ next int }

func (f *httpAuditEnqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	f.next++
	return task.Job{ID: "job_http_it_" + string(rune('a'+f.next)), Kind: request.Kind,
		State: task.StateQueued, CreatedAt: time.Now()}, nil
}

type httpAuditCanceller struct{}

func (httpAuditCanceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelRequested}, nil
}

// httpAuditSessions 提供页面会话；kind 为 management 或 normal。
type httpAuditSessions struct {
	userID string
	kind   string
}

func (s httpAuditSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	kind := s.kind
	if kind == "" {
		kind = "management"
	}
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: kind,
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (httpAuditSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "http-csrf", nil
}

// newHTTPAuditHandler 构造真实服务 + 真实适配器 + 页面框架的环境。sessionUser 是
// 页面会话用户；eventActor 是真实写入审计事件的操作者。返回页面处理器与事件 ID。
func newHTTPAuditHandler(t *testing.T, sessionUser, eventActor string) (http.Handler, string) {
	return newHTTPAuditHandlerKind(t, sessionUser, eventActor, "management")
}

// newHTTPAuditHandlerKind 同上，允许指定页面会话种类（management/normal）。
func newHTTPAuditHandlerKind(t *testing.T, sessionUser, eventActor, kind string) (http.Handler, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	raw, err := storagesqlite.Open(ctx,
		storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "audit_http.db")))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	opStore, err := auditopssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造 auditops 仓储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	authorizer := &httpAuditAuthorizer{grants: map[string]auditops.ScopeGrant{
		eventActor + "|" + auditops.PermissionRead + "|" + auditops.ScopeSystem: {Allowed: true, AllData: true},
	}}
	service, err := auditops.New(auditops.Options{
		Store: opStore, Audit: recorder, Authorizer: authorizer,
		Root:      &httpAuditRoot{roots: map[string]bool{}},
		Sensitive: httpAuditSensitive{}, Enqueuer: &httpAuditEnqueuer{},
		Canceller: httpAuditCanceller{}, OutputDir: t.TempDir(), RetentionDays: 180,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("构造 auditops 服务失败: %v", err)
	}
	adapter, err := uiadminadapter.NewAudit(uiadminadapter.AuditOptions{
		Audit: service, Authorizer: authorizer, Recorder: recorder,
		IsRoot: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatalf("构造审计页适配器失败: %v", err)
	}
	if err := recorder.Record(ctx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorUser, ID: eventActor},
		Action: "session.revoke", Target: audit.Target{Type: "session", ID: "sess_http"},
		Outcome: audit.OutcomeSuccess, RequestID: "req_http_it"}); err != nil {
		t.Fatalf("写入审计事件失败: %v", err)
	}
	page, err := adapter.ListAudit(ctx, eventActor, login.UIAuditQuery{
		ScopeID: auditops.ScopeSystem, Limit: 20})
	if err != nil || len(page.Events) == 0 {
		t.Fatalf("读取真实事件失败: %+v err=%v", page, err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: httpAuditSessions{userID: sessionUser, kind: kind},
		PageAudit: &login.UIPageAuditOptions{Backend: adapter,
			// 与 auditops 固定时钟一致，使日期边界钳制可确定复现。
			Now:          func() time.Time { return now },
			ValidateCSRF: func(context.Context, *http.Request, string) error { return nil }},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造页面框架失败: %v", err)
	}
	return ui, page.Events[0].ID
}

func httpAuditGet(handler http.Handler, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestAuditHTTPPageWithRealService 联调请求→审计→页面→公开错误说明的追踪链。
func TestAuditHTTPPageWithRealService(t *testing.T) {
	userID := "usr_0123456789abcdef0123456789abcdef"
	handler, eventID := newHTTPAuditHandler(t, userID, userID)
	list := httpAuditGet(handler, "/admin/audit?request_id=req_http_it")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "session.revoke") {
		t.Fatalf("真实服务列表 = %d %s", list.Code, firstRunes(list.Body.String(), 200))
	}
	detail := httpAuditGet(handler, "/admin/audit/detail?event_id="+eventID)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "审计事件详情") {
		t.Fatalf("真实服务详情 = %d", detail.Code)
	}
	// 伪造编号：真实服务判定不存在，页面显示查无记录。
	missing := httpAuditGet(handler, "/admin/audit/detail?event_id="+
		"aud_ffffffffffffffffffffffffffffffff")
	if missing.Code != http.StatusNotFound ||
		!strings.Contains(missing.Body.String(), "未找到该记录") {
		t.Fatalf("真实服务查无记录 = %d", missing.Code)
	}
	// 无 audit.read 授权的会话：真实服务拒绝，页面显示无权限且不泄露记录正文。
	otherUser := "usr_ffffffffffffffffffffffffffffffff"
	deniedHandler, _ := newHTTPAuditHandler(t, otherUser, userID)
	denied := httpAuditGet(deniedHandler, "/admin/audit")
	if denied.Code != http.StatusForbidden ||
		strings.Contains(denied.Body.String(), "session.revoke") {
		t.Fatalf("未授权用户页面 = %d", denied.Code)
	}
	// 日期边界：to=今天（2026-11-18）不再被判未来，真实 auditops 返回 200 且含当日记录；
	// to=未来日期按钳制语义同样 200（上界=当前时间+1 分钟），语义明确。
	today := httpAuditGet(handler, "/admin/audit?to=2026-11-18")
	if today.Code != http.StatusOK || !strings.Contains(today.Body.String(), "session.revoke") {
		t.Fatalf("to=今天 真实服务 = %d %s", today.Code, firstRunes(today.Body.String(), 200))
	}
	future := httpAuditGet(handler, "/admin/audit?to=2026-12-31")
	if future.Code != http.StatusOK {
		t.Fatalf("to=未来日期 应钳制而非拒绝，状态 = %d", future.Code)
	}
	// 本人安全活动页使用真实本人查询通道，只显示本人记录（普通会话）。
	ownHandler, _ := newHTTPAuditHandlerKind(t, userID, userID, "normal")
	own := httpAuditGet(ownHandler, "/account/activity")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), "我的安全活动") ||
		!strings.Contains(own.Body.String(), "session.revoke") {
		t.Fatalf("真实本人活动页 = %d", own.Code)
	}
}
