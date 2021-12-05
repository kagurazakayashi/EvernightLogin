package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// stubSession 是管理会话边界的测试替身，只替换认证/CSRF 交互点；权限、数据范围、
// 敏感策略与审计全部由测试中的真实领域服务判定（见 audit_test.go）。
type stubSession struct {
	secret  string
	csrf    string
	userID  string
	authErr error
	csrfErr error
	// session 非零时作为 AuthorizeManagement 的返回值（用于测试强认证分支）。
	session session.Session
}

func (s *stubSession) SessionSecretFromRequest(r *http.Request) (string, bool) {
	// 与 internal/session.Service.SessionSecretFromRequest 保持同一优先级：Cookie
	// 优先，其次才是 Authorization: Bearer（scheme 大小写不敏感）。
	if cookie, err := r.Cookie(session.DefaultCookieName); err == nil && cookie.Value != "" {
		return strings.TrimSpace(cookie.Value), true
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

func (s *stubSession) AuthorizeManagement(_ context.Context, secret string) (session.Session, error) {
	if s.authErr != nil {
		return session.Session{}, s.authErr
	}
	if secret != s.secret {
		return session.Session{}, session.ErrSessionInvalid
	}
	if s.session.UserID != "" {
		return s.session, nil
	}
	return session.Session{UserID: s.userID, Kind: session.KindNormal,
		StrongAuthVerifiedAt: time.Now()}, nil
}

func (s *stubSession) ValidateCSRFToken(_ context.Context, _ *http.Request, token string) error {
	if s.csrfErr != nil {
		return s.csrfErr
	}
	if token != s.csrf {
		return session.ErrSessionInvalid
	}
	return nil
}

// testCodes 返回测试使用的错误码投影（消息简化，状态与根包注册表一致）。
func testCodes() []ErrorCodeInfo {
	return []ErrorCodeInfo{
		{Code: "REQ_INVALID", Message: "请求内容不符合要求", HTTPStatus: 400},
		{Code: "AUTH_FAILED", Message: "无法完成登录", HTTPStatus: 401},
		{Code: "ACCESS_DENIED", Message: "请求未获准", HTTPStatus: 403},
		{Code: "PERMISSION_REQUIRED", Message: "缺少当前操作所需权限", HTTPStatus: 403},
		{Code: "REAUTH_REQUIRED", Message: "需要再次验证身份", HTTPStatus: 403},
		{Code: "RESOURCE_FORBIDDEN", Message: "不能操作该记录", HTTPStatus: 403},
		{Code: "REPORT_ACCESS_DENIED", Message: "无权读取此报告", HTTPStatus: 403},
		{Code: "CONFLICT", Message: "数据已被其他操作修改", HTTPStatus: 409},
		{Code: "TASK_CANCEL_CONFLICT", Message: "任务已结束或不能在当前阶段取消", HTTPStatus: 409},
		{Code: "TASK_CANCELLED", Message: "任务已取消", HTTPStatus: 0},
		{Code: "TASK_TIMEOUT", Message: "任务执行超时", HTTPStatus: 0},
		{Code: "DB_UNAVAILABLE", Message: "数据库暂时不可用", HTTPStatus: 503},
		{Code: "AUTHZ_UNAVAILABLE", Message: "暂时无法判定访问权限", HTTPStatus: 503},
		{Code: "AUDIT_WRITE_FAILED", Message: "关键操作未能可靠记录", HTTPStatus: 503},
		{Code: "EXPORT_PATH_UNSAFE", Message: "导出位置不安全", HTTPStatus: 400},
		{Code: "BACKUP_INVALID", Message: "备份文件校验未通过", HTTPStatus: 422},
		{Code: "BACKUP_FAILED", Message: "备份失败", HTTPStatus: 0},
		{Code: "BACKUP_CANCEL_FORBIDDEN", Message: "无权取消该任务", HTTPStatus: 403},
		{Code: "REPORT_GENERATION_FAILED", Message: "报告未能生成", HTTPStatus: 0},
		{Code: "MAIL_DELIVERY_FAILED", Message: "邮件未成功投递", HTTPStatus: 0},
		{Code: "INTERNAL_ERROR", Message: "服务发生未预期错误", HTTPStatus: 500},
	}
}

// apiReply 是一次测试请求的响应快照。
type apiReply struct {
	status int
	header http.Header
	body   []byte
	parsed map[string]any
}

// callAPI 通过 httptest 发送请求；authorization 为空表示不带认证头。
func callAPI(t *testing.T, handler http.Handler, method, path, body, authorization string,
	extraHeaders map[string]string) apiReply {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range extraHeaders {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	reply := apiReply{status: recorder.Code, header: recorder.Header(),
		body: recorder.Body.Bytes()}
	var parsed map[string]any
	if err := json.Unmarshal(reply.body, &parsed); err == nil {
		reply.parsed = parsed
	}
	return reply
}

// requireStatus 断言 HTTP 状态并返回解析后的 JSON 对象。
func requireStatus(t *testing.T, reply apiReply, want int) map[string]any {
	t.Helper()
	if reply.status != want {
		t.Fatalf("HTTP 状态 = %d，期望 %d，响应=%s", reply.status, want, string(reply.body))
	}
	if reply.parsed == nil {
		t.Fatalf("响应不是 JSON 对象: %s", string(reply.body))
	}
	return reply.parsed
}

// requireErrorCode 断言统一错误响应：ok=false、稳定错误码、请求编号非空。
func requireErrorCode(t *testing.T, reply apiReply, wantStatus int, wantCode string) map[string]any {
	t.Helper()
	payload := requireStatus(t, reply, wantStatus)
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("错误响应 ok 应为 false: %s", string(reply.body))
	}
	if got, _ := payload["code"].(string); got != wantCode {
		t.Fatalf("错误码 = %q，期望 %q，响应=%s", got, wantCode, string(reply.body))
	}
	if requestID, _ := payload["request_id"].(string); requestID == "" {
		t.Fatalf("错误响应缺少 request_id: %s", string(reply.body))
	}
	return payload
}

// requireSuccess 断言统一成功响应并返回 data 对象。
func requireSuccess(t *testing.T, reply apiReply) map[string]any {
	t.Helper()
	payload := requireStatus(t, reply, http.StatusOK)
	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("成功响应 ok 应为 true: %s", string(reply.body))
	}
	if requestID, _ := payload["request_id"].(string); requestID == "" {
		t.Fatalf("成功响应缺少 request_id: %s", string(reply.body))
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("成功响应缺少 data 对象: %s", string(reply.body))
	}
	return data
}

// newStubServer 构造只有基础端点（meta/error-codes）的管理 API，供传输契约测试。
func newStubServer(t *testing.T, stub *stubSession) *Server {
	t.Helper()
	server, err := New(Options{Session: stub, ErrorCodes: testCodes()})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	return server
}
