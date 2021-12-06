package loginte2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// 本文件用**真实 internal/adminapi 处理器**做管理 API 套件验收：会话认证边界用
// 测试替身（adminapi 自己的测试同样如此），路由、信封、错误码投影、CSRF 契约与
// 方法/路径校验都是真实实现。

const adminTestUserID = "usr_00000000000000000000000000000001"

// stubManagementSession 是管理会话边界的测试替身：只替换“会话秘密→管理会话”的
// 认证交互，不改变 adminapi 的授权/CSRF/路由逻辑。
type stubManagementSession struct {
	secret string
}

// SessionSecretFromRequest 从 Bearer 或会话 Cookie 读取秘密（与生产契约一致）。
func (s stubManagementSession) SessionSecretFromRequest(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	if cookie, err := request.Cookie(DefaultSessionCookieName); err == nil && cookie != nil &&
		strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value), true
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}

// AuthorizeManagement 每次请求重新校验会话；错误秘密返回 ErrSessionInvalid。
func (s stubManagementSession) AuthorizeManagement(_ context.Context,
	secret string) (session.Session, error) {
	if secret != s.secret {
		return session.Session{}, session.ErrSessionInvalid
	}
	return session.Session{ID: "ses_00000000000000000000000000000001",
		UserID: adminTestUserID, Kind: session.KindNormal,
		StrongAuthVerifiedAt: time.Now().Add(-time.Minute)}, nil
}

// ValidateCSRFToken 在 Bearer 场景不会走到；测试替身直接放行以隔离认证边界。
func (s stubManagementSession) ValidateCSRFToken(context.Context, *http.Request, string) error {
	return nil
}

// adminErrorCodes 返回 adminapi 必需的根包错误码投影（含传输层固定码与常用码）。
func adminErrorCodes() []adminapi.ErrorCodeInfo {
	definitions := []struct {
		code    string
		message string
		status  int
	}{
		{"REQ_INVALID", "请求参数无效", 400},
		{"AUTH_FAILED", "身份验证失败", 401},
		{"ACCESS_DENIED", "请求未获准", 403},
		{"REAUTH_REQUIRED", "需要重新验证身份", 403},
		{"CONFLICT", "请求状态已变化", 409},
		{"INTERNAL_ERROR", "服务发生未预期错误", 500},
		{"DB_UNAVAILABLE", "服务暂时不可用", 503},
		{"RATE_LIMITED", "请求过于频繁", 429},
		{"PERMISSION_REQUIRED", "缺少当前操作所需权限", 403},
	}
	result := make([]adminapi.ErrorCodeInfo, 0, len(definitions))
	for _, item := range definitions {
		result = append(result, adminapi.ErrorCodeInfo{Code: item.code,
			Message: item.message, HTTPStatus: item.status})
	}
	return result
}

// newAdminTestServer 构造真实 adminapi 处理器与 httptest 服务。
func newAdminTestServer(t *testing.T, sessionSecret string) (*httptest.Server, *adminapi.Server) {
	t.Helper()
	server, err := adminapi.New(adminapi.Options{
		Session:    stubManagementSession{secret: sessionSecret},
		ErrorCodes: adminErrorCodes(),
		Now:        time.Now,
	})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return httpServer, server
}

// TestAdminAPISuiteAgainstRealHandler 对真实 adminapi 处理器运行 adminapi 套件。
func TestAdminAPISuiteAgainstRealHandler(t *testing.T) {
	const adminSecret = "adm_0123456789abcdef0123456789abcdef"
	httpServer, server := newAdminTestServer(t, adminSecret)
	client, err := New(Config{Server: httpServer.URL, AdminSessionSecret: adminSecret,
		AdminBasePath: server.BasePath()})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	report, runErr := client.Run(context.Background(), SuiteAdminAPI)
	if runErr != nil {
		t.Fatalf("adminapi 套件无法继续: %v", runErr)
	}
	reportFailureDetails(t, report)
	if report.Summary.Fail > 0 {
		t.Fatalf("adminapi 套件有 %d 条失败", report.Summary.Fail)
	}
	if report.Summary.Pass < 5 {
		t.Fatalf("adminapi 套件通过用例过少：%d", report.Summary.Pass)
	}
	assertReportNoSecret(t, report, adminSecret)
	for _, result := range report.Results {
		if result.Status == StatusSkip {
			t.Logf("[SKIP] %s: %s", result.Case, result.Detail)
		}
	}
}

// TestAdminAPISuiteWithoutSecretSkips 验证缺少管理会话时如实 skip（不伪造通过）。
func TestAdminAPISuiteWithoutSecretSkips(t *testing.T) {
	httpServer, server := newAdminTestServer(t, "unused-secret")
	client, err := New(Config{Server: httpServer.URL, AdminBasePath: server.BasePath()})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	report, runErr := client.Run(context.Background(), SuiteAdminAPI)
	if runErr != nil {
		t.Fatalf("套件无法继续: %v", runErr)
	}
	if report.Summary.Fail != 0 {
		t.Fatalf("缺少管理会话时不应产生失败用例")
	}
	if report.Summary.Pass != 0 {
		t.Fatalf("缺少管理会话时不应有通过用例")
	}
	if report.ExitCode() != ExitUnavailable {
		t.Fatalf("全 skip 退出码 = %d，期望 %d", report.ExitCode(), ExitUnavailable)
	}
}

// TestAdminAPISuiteRejectsWrongSecret 验证错误管理会话被真实处理器拒绝。
func TestAdminAPISuiteRejectsWrongSecret(t *testing.T) {
	httpServer, server := newAdminTestServer(t, "correct-secret")
	client, err := New(Config{Server: httpServer.URL,
		AdminSessionSecret: "wrong-secret", AdminBasePath: server.BasePath()})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	report, runErr := client.Run(context.Background(), SuiteAdminAPI)
	if runErr != nil {
		t.Fatalf("套件无法继续: %v", runErr)
	}
	// 错误会话属于前置条件问题：整个套件如实 skip，并以退出码 3 表示“环境未就绪”，
	// 而不是伪装成通过。
	if report.Summary.Fail != 0 || report.Summary.Pass != 0 {
		t.Fatalf("错误管理会话不应得到通过/失败结论: %+v", report.Summary)
	}
	if report.ExitCode() != ExitUnavailable {
		t.Fatalf("错误管理会话退出码 = %d，期望 %d", report.ExitCode(), ExitUnavailable)
	}
}
