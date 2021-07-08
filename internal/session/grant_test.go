package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	grantTestUser = "usr_00000000000000000000000000000021"
	grantTestApp  = "app_00000000000000000000000000000021"
	grantTestID   = "qrl_0123456789abcdef0123456789abcdef"
)

// recordingGrantGate 记录门控调用并返回固定结果。
type recordingGrantGate struct {
	calls    int
	last     session.LoginGrantRequest
	err      error
	callback func(request session.LoginGrantRequest) error
}

func (g *recordingGrantGate) AuthorizeLoginGrant(_ context.Context,
	request session.LoginGrantRequest) error {
	g.calls++
	g.last = request
	if g.callback != nil {
		return g.callback(request)
	}
	return g.err
}

// grantRequest 构造默认合法的登录批准请求。
func grantRequest() session.LoginGrantRequest {
	return session.LoginGrantRequest{
		GrantID: grantTestID, UserID: grantTestUser, SecurityVersion: 1,
		AppID: grantTestApp, AuthMethods: []authn.Method{authn.MethodPassword, authn.MethodPasskey},
	}
}

// grantTestEnv 构造带应用/成员/用户的测试环境。
func grantTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	env.insertUser(grantTestUser, "grantuser", account.StatusActive, 1)
	env.insertApplication(grantTestApp, "active")
	env.insertMembership(grantTestApp, grantTestUser, "active")
	return env
}

// TestIssueLoginGrantSessionFlow 验证可信登录批准可签发目标应用普通会话：
// 认证方法来自批准快照、不继承强认证时间、审计记录批准来源。
func TestIssueLoginGrantSessionFlow(t *testing.T) {
	env := grantTestEnv(t)
	gate := &recordingGrantGate{}
	issued, err := env.session.IssueLoginGrantSession(env.ctx, grantRequest(), gate)
	if err != nil {
		t.Fatalf("登录批准签发失败: %v", err)
	}
	if gate.calls != 1 || gate.last.GrantID != grantTestID {
		t.Fatalf("门控应被调用一次并收到批准标识，实际 %+v", gate.last)
	}
	if issued.Session.Kind != session.KindNormal || issued.Session.AppID != grantTestApp ||
		issued.Session.UserID != grantTestUser {
		t.Fatalf("签发会话不符合预期: %+v", issued.Session)
	}
	if !issued.Session.StrongAuthVerifiedAt.IsZero() {
		t.Fatal("登录批准会话不得继承确认端强认证时间")
	}
	if len(issued.Session.AuthMethods) != 2 {
		t.Fatalf("认证方法应来自批准快照，实际 %v", issued.Session.AuthMethods)
	}
	validated, err := env.session.AuthorizeBusiness(env.ctx, issued.Secret.Reveal())
	if err != nil || validated.UserID != grantTestUser {
		t.Fatalf("签发的会话应可访问业务接口: %+v err=%v", validated, err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=?`,
		string(session.ActionSessionLoginGrantIssued)); got != 1 {
		t.Fatalf("应写 1 条登录批准签发审计，实际 %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND detail_json LIKE '%`+
		grantTestID+`%'`, string(session.ActionSessionLoginGrantIssued)); got != 1 {
		t.Fatalf("审计应关联批准标识，实际 %d", got)
	}
}

// TestIssueLoginGrantSessionGateFailures 验证缺失门控或门控拒绝时一律拒绝签发。
func TestIssueLoginGrantSessionGateFailures(t *testing.T) {
	env := grantTestEnv(t)
	if _, err := env.session.IssueLoginGrantSession(env.ctx, grantRequest(), nil); !errors.Is(err, session.ErrLoginGrantDenied) {
		t.Fatalf("缺少门控应返回 ErrLoginGrantDenied，实际 %v", err)
	}
	gate := &recordingGrantGate{err: errors.New("grant revoked")}
	if _, err := env.session.IssueLoginGrantSession(env.ctx, grantRequest(), gate); !errors.Is(err, session.ErrLoginGrantDenied) {
		t.Fatalf("门控拒绝应返回 ErrLoginGrantDenied，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 0 {
		t.Fatalf("门控拒绝时不得签发会话，实际 %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='failure' AND reason_code='login_grant_not_authorized'`,
		string(session.ActionSessionIssue)); got != 1 {
		t.Fatalf("门控拒绝应写失败审计，实际 %d", got)
	}
}

// TestIssueLoginGrantSessionEligibilityFirst 验证账户/成员不满足时在消费批准前拒绝。
func TestIssueLoginGrantSessionEligibilityFirst(t *testing.T) {
	env := grantTestEnv(t)
	env.exec(`UPDATE users SET status='disabled' WHERE id=?`, grantTestUser)
	gate := &recordingGrantGate{}
	if _, err := env.session.IssueLoginGrantSession(env.ctx, grantRequest(), gate); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("账户禁用应返回 ErrAccountNotEligible，实际 %v", err)
	}
	if gate.calls != 0 {
		t.Fatal("资格不满足时不得消费一次性批准")
	}
	// 成员移除同样拒绝。
	env.exec(`UPDATE users SET status='active' WHERE id=?`, grantTestUser)
	env.exec(`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`,
		grantTestApp, grantTestUser)
	gate = &recordingGrantGate{}
	if _, err := env.session.IssueLoginGrantSession(env.ctx, grantRequest(), gate); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("成员失效应返回 ErrAccountNotEligible，实际 %v", err)
	}
	if gate.calls != 0 {
		t.Fatal("成员失效时不得消费一次性批准")
	}
}

// TestIssueLoginGrantSessionRejectsInvalidFields 验证批准字段与认证方法校验。
func TestIssueLoginGrantSessionRejectsInvalidFields(t *testing.T) {
	env := grantTestEnv(t)
	cases := []struct {
		name   string
		mutate func(*session.LoginGrantRequest)
	}{
		{"批准标识非法", func(r *session.LoginGrantRequest) { r.GrantID = "" }},
		{"用户非法", func(r *session.LoginGrantRequest) { r.UserID = "bad" }},
		{"安全版本缺失", func(r *session.LoginGrantRequest) { r.SecurityVersion = 0 }},
		{"目标应用缺失", func(r *session.LoginGrantRequest) { r.AppID = "" }},
		{"认证方法为空", func(r *session.LoginGrantRequest) { r.AuthMethods = nil }},
		{"认证方法未知", func(r *session.LoginGrantRequest) {
			r.AuthMethods = []authn.Method{authn.Method("unknown_method")}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := grantRequest()
			test.mutate(&request)
			gate := &recordingGrantGate{}
			if _, err := env.session.IssueLoginGrantSession(env.ctx, request, gate); !errors.Is(err, session.ErrInvalidRequest) {
				t.Fatalf("应返回 ErrInvalidRequest，实际 %v", err)
			}
			if gate.calls != 0 {
				t.Fatal("字段非法时不得调用门控")
			}
		})
	}
}

// TestVerifyActiveSession 验证领取前复核确认端会话仍有效。
func TestVerifyActiveSession(t *testing.T) {
	env := grantTestEnv(t)
	issued := env.loginComplete(grantTestUser, 1)
	if err := env.session.VerifyActiveSession(env.ctx, grantTestUser, issued.Session.ID); err != nil {
		t.Fatalf("活动会话校验应通过: %v", err)
	}
	if err := env.session.VerifyActiveSession(env.ctx, "usr_00000000000000000000000000000099",
		issued.Session.ID); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("用户归属不符应拒绝，实际 %v", err)
	}
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("退出会话失败: %v", err)
	}
	if err := env.session.VerifyActiveSession(env.ctx, grantTestUser, issued.Session.ID); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("已撤销会话应拒绝，实际 %v", err)
	}
	// 新会话在账户禁用后不可再用。
	issued = env.loginComplete(grantTestUser, 1)
	env.exec(`UPDATE users SET status='disabled',row_version=row_version+1 WHERE id=?`, grantTestUser)
	if err := env.session.VerifyActiveSession(env.ctx, grantTestUser, issued.Session.ID); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("账户禁用后应拒绝，实际 %v", err)
	}
}

// TestIssuePageCSRFToken 验证服务端页面 CSRF 令牌：确定性、与既有随机 CSRF 令牌
// 共存、会话撤销/错会话后失效、非法秘密拒绝。
func TestIssuePageCSRFToken(t *testing.T) {
	env := grantTestEnv(t)
	issued := env.loginComplete(grantTestUser, 1)
	first, err := env.session.IssuePageCSRFToken(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("签发页面 CSRF 令牌失败: %v", err)
	}
	second, err := env.session.IssuePageCSRFToken(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("再次签发页面 CSRF 令牌失败: %v", err)
	}
	if first.Reveal() != second.Reveal() {
		t.Fatal("同一活动会话的页面 CSRF 令牌应稳定（多标签页可用）")
	}
	if first.Reveal() == issued.CSRFSecret.Reveal() {
		t.Fatal("页面 CSRF 令牌不得等于登录时随机 CSRF 令牌")
	}
	// 既有随机 CSRF 令牌仍可校验（兼容旧客户端）。
	requestWith := func(secret, csrf string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: secret})
		_ = csrf
		return req
	}
	if err := env.session.ValidateCSRFToken(env.ctx, requestWith(issued.Secret.Reveal(), first.Reveal()), first.Reveal()); err != nil {
		t.Fatalf("页面 CSRF 令牌应通过同一校验器: %v", err)
	}
	if err := env.session.ValidateCSRFToken(env.ctx, requestWith(issued.Secret.Reveal(), issued.CSRFSecret.Reveal()), issued.CSRFSecret.Reveal()); err != nil {
		t.Fatalf("既有随机 CSRF 令牌应继续有效: %v", err)
	}
	if err := env.session.ValidateCSRFToken(env.ctx, requestWith(issued.Secret.Reveal(), "wrong"), "wrong"); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("错误页面 CSRF 令牌应拒绝，实际 %v", err)
	}
	// 另一个会话的秘密不能验证本会话令牌。
	other := env.loginComplete(grantTestUser, 1)
	if err := env.session.ValidateCSRFToken(env.ctx, requestWith(other.Secret.Reveal(), first.Reveal()), first.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("跨会话页面 CSRF 令牌应拒绝，实际 %v", err)
	}
	// 登出后页面令牌失效。
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("退出失败: %v", err)
	}
	if _, err := env.session.IssuePageCSRFToken(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("已撤销会话不应签发页面 CSRF 令牌，实际 %v", err)
	}
}
