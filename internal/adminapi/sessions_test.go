package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// revokerSession 在 stubSession 之上实现 SessionAdminRevoker。
type revokerSession struct {
	*stubSession
	result     session.AdminRevokeResult
	err        error
	called     bool
	signals    reauth.Signals
	listResult session.AdminSessionListResult
	listErr    error
	listCalled bool
}

func (r *revokerSession) AdminRevoke(ctx context.Context, _ string,
	_ session.AdminRevokeRequest) (session.AdminRevokeResult, error) {
	r.called = true
	r.signals = reauth.SignalsFromContext(ctx)
	return r.result, r.err
}

func (r *revokerSession) AdminListSessions(context.Context, string,
	session.AdminSessionListRequest) (session.AdminSessionListResult, error) {
	r.listCalled = true
	return r.listResult, r.listErr
}

// TestSessionAdminRevokeRoute 覆盖步骤 151 管理 API：路由/确认/理由/成功返回，
// 以及强认证缺失映射和未实现 revoker 时不挂载路由。
func TestSessionAdminRevokeRoute(t *testing.T) {
	stub := &revokerSession{
		stubSession: &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"},
		result:      session.AdminRevokeResult{Revoked: 2},
	}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes()})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	body := `{"confirm":true,"target_user_id":"usr_00000000000000000000000000000002","reason":"security incident response"}`
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	if reply.status != http.StatusOK || !stub.called {
		t.Fatalf("管理员强制下线应成功: status=%d body=%s", reply.status, reply.body)
	}
	if !strings.Contains(string(reply.body), `"revoked":2`) {
		t.Fatalf("响应缺少撤销数量: %s", reply.body)
	}

	// 缺少确认/理由：400，不调用领域服务。
	for _, bad := range []string{
		`{"target_user_id":"usr_00000000000000000000000000000002","reason":"x"}`,
		`{"confirm":true,"target_user_id":"usr_00000000000000000000000000000002"}`,
	} {
		reply = callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", bad, "Bearer s3cret", nil)
		requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	}

	// 强认证过期：映射 REAUTH_REQUIRED。
	stub.err = session.ErrStrongAuthRequired
	stub.result = session.AdminRevokeResult{}
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")

	// 普通 stubSession 不实现可选接口：不挂载路由，返回 404 而不是放行。
	plain := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	plainServer := newStubServer(t, plain)
	reply = callAPI(t, plainServer, http.MethodPost, "/admin/v1/sessions/revoke", body, "Bearer s3cret", nil)
	if reply.status != http.StatusNotFound {
		t.Fatalf("未装配 revoker 时路由应为 404，实际 %d", reply.status)
	}
}

// TestSessionAdminListRoute 覆盖步骤 187 管理 API 查询路由：GET /sessions 返回
// 目标活动会话公开摘要（不含秘密），未装配 lister 时不挂载路由。
func TestSessionAdminListRoute(t *testing.T) {
	now := time.Now().UTC()
	stub := &revokerSession{
		stubSession: &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"},
		listResult: session.AdminSessionListResult{
			TargetUserID: "usr_00000000000000000000000000000002",
			Page:         1, PageSize: 20, Total: 1, HasMore: false,
			Sessions: []session.SessionSummary{{
				ID: "ses_00000000000000000000000000000003", Kind: session.KindNormal,
				CreatedAt: now, LastSeenAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
				Client: session.ClientInfo{UserAgent: "cli/1.0", Address: "127.0.0.1"},
			}},
		},
	}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes()})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	reply := callAPI(t, server, http.MethodGet,
		"/admin/v1/sessions?target_user_id=usr_00000000000000000000000000000002", "", "Bearer s3cret", nil)
	if reply.status != http.StatusOK || !stub.listCalled {
		t.Fatalf("管理员会话查询应成功: status=%d body=%s", reply.status, reply.body)
	}
	body := string(reply.body)
	for _, want := range []string{`"target_user_id":"usr_00000000000000000000000000000002"`,
		`"sessions":[`, `"total":1`, `"ses_00000000000000000000000000000003"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("查询响应缺少 %s: %s", want, body)
		}
	}
	// 普通 stubSession 不实现 lister：路由 404。
	plain := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	plainServer := newStubServer(t, plain)
	reply = callAPI(t, plainServer, http.MethodGet, "/admin/v1/sessions?target_user_id=x", "", "Bearer s3cret", nil)
	if reply.status != http.StatusNotFound {
		t.Fatalf("未装配 lister 时路由应为 404，实际 %d", reply.status)
	}
}

// TestManagementSignalsInjection 验证 handler 在不覆盖 186 证明的前提下注入管理
// 会话强认证事实，并只在显式 confirm 后把 Confirmed 置 true。
func TestManagementSignalsInjection(t *testing.T) {
	record := session.Session{UserID: "usr_00000000000000000000000000000001",
		Kind: session.KindNormal, StrongAuthVerifiedAt: time.Now().UTC()}
	ctx := withManagementSessionSignals(context.Background(), record)
	signals := reauth.SignalsFromContext(ctx)
	if signals.VerifiedAt.IsZero() || !signals.Complete || signals.Confirmed ||
		signals.Strength != "strong" {
		t.Fatalf("基础信号不符: %+v", signals)
	}
	confirmed := reauth.SignalsFromContext(withExplicitConfirm(ctx))
	if !confirmed.Confirmed || confirmed.VerifiedAt.IsZero() {
		t.Fatalf("显式确认后的信号不符: %+v", confirmed)
	}
	// 186 中间件注入的证明必须原样保留，不被会话事实覆盖。
	proofCtx := reauth.WithSignals(context.Background(), reauth.Signals{
		VerifiedAt: time.Now().UTC(), Strength: "strong", Complete: true,
		Confirmed: true, ApprovalToken: "proof-token"})
	kept := reauth.SignalsFromContext(withManagementSessionSignals(proofCtx, record))
	if kept.ApprovalToken != "proof-token" || !kept.Confirmed {
		t.Fatalf("186 证明被覆盖: %+v", kept)
	}
	if merged := reauth.SignalsFromContext(withExplicitConfirm(proofCtx)); merged.ApprovalToken != "proof-token" {
		t.Fatalf("显式确认丢失批准令牌: %+v", merged)
	}
}
