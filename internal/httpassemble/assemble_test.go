package httpassemble

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// TestNewHTTPHandlerEndpoints 验证根级公开入口（经本包组装）真实提供健康检查与
// OpenAPI 文档，且错误码注册表被投影进文档。
func TestNewHTTPHandlerEndpoints(t *testing.T) {
	handler, err := NewHTTPHandler(httpapi.HTTPOptions{Prefix: "/api"}, "test-version")
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "http://example.test/api/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("健康检查状态 = %d，body=%s", health.Code, health.Body.String())
	}
	openAPI := httptest.NewRecorder()
	handler.ServeHTTP(openAPI, httptest.NewRequest(http.MethodGet, "http://example.test/api/openapi.json", nil))
	if openAPI.Code != http.StatusOK {
		t.Fatalf("OpenAPI 状态 = %d", openAPI.Code)
	}
	var document map[string]any
	if err := json.Unmarshal(openAPI.Body.Bytes(), &document); err != nil {
		t.Fatalf("OpenAPI 不是合法 JSON: %v", err)
	}
	if !bytes.Contains(openAPI.Body.Bytes(), []byte(errs.CodeReqInvalid)) {
		t.Fatal("OpenAPI 文档缺少错误码注册表投影（REQ_INVALID）")
	}
	// 前缀之外的路径 404，不做清理重写。
	miss := httptest.NewRecorder()
	handler.ServeHTTP(miss, httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil))
	if miss.Code != http.StatusNotFound {
		t.Fatalf("前缀外路径状态 = %d，期望 404", miss.Code)
	}
}

// TestNewHTTPHandlerConfigErrors 验证公开选项非法时仍返回 CONFIG_INVALID 且不
// 创建监听/协程。
func TestNewHTTPHandlerConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		options httpapi.HTTPOptions
	}{
		{"非法前缀", httpapi.HTTPOptions{Prefix: "api"}},
		{"只设置限流一半", httpapi.HTTPOptions{Protection: &httpapi.HTTPProtectionOptions{
			RateLimit: httpapi.RateLimitOptions{ClientIP: httpapi.RateLimitPolicy{Limit: 1}}}}},
		{"非法 Cookie 策略", httpapi.HTTPOptions{Protection: &httpapi.HTTPProtectionOptions{
			CookiePolicy: &httpapi.CookiePolicy{SameSite: http.SameSiteDefaultMode, Path: "/"}}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewHTTPHandler(test.options, "test-version")
			if !errs.IsErrorCode(err, errs.CodeConfigInvalid) {
				t.Fatalf("期望 CONFIG_INVALID，实际 %v", err)
			}
		})
	}
}

// TestNormalizeProtectionMapping 验证公开防护选项到内部配置的字段映射完整（不
// 复制校验逻辑；此处检查适配层不丢字段）。
func TestNormalizeProtectionMapping(t *testing.T) {
	validator := httpapi.CSRFValidatorFunc(func(context.Context, *http.Request, string) error {
		return nil
	})
	protection, err := normalizeProtection(&httpapi.HTTPProtectionOptions{
		TrustedProxies: []string{"127.0.0.1"},
		RateLimit: httpapi.RateLimitOptions{
			ClientIP: httpapi.RateLimitPolicy{Limit: 10, Window: time.Minute},
			Capacity: 128, CleanupInterval: time.Second,
		},
		RequestTimeout:        5 * time.Second,
		MaxConcurrentRequests: 8,
		CORS: httpapi.CORSOptions{AllowedOrigins: []string{"https://example.test"},
			AllowCredentials: true},
		CSRF: httpapi.CSRFPolicy{Enabled: true, CookieName: "session",
			TokenHeader: "X-CSRF-Token", TokenValidator: validator,
			PublicFormPaths: []string{"/login"}},
		SecurityHeaders: &httpapi.SecurityHeaderOptions{
			ContentSecurityPolicy: "default-src 'none'", EnableHSTS: true},
		ExpensivePaths: []string{"/api/report"},
	})
	if err != nil {
		t.Fatalf("normalizeProtection: %v", err)
	}
	if len(protection.TrustedProxies) != 1 || protection.TrustedProxies[0] != "127.0.0.1" {
		t.Fatalf("可信代理映射异常: %+v", protection.TrustedProxies)
	}
	if protection.RequestTimeout != 5*time.Second || protection.MaxConcurrentRequests != 8 {
		t.Fatalf("超时/并发映射异常: %+v", protection)
	}
	if protection.RateLimit.ClientIP.Limit != 10 ||
		protection.RateLimit.Capacity != 128 ||
		protection.RateLimit.CleanupInterval != time.Second {
		t.Fatalf("限流映射异常: %+v", protection.RateLimit)
	}
	if len(protection.CORS.AllowedOrigins) != 1 || !protection.CORS.AllowCredentials {
		t.Fatalf("CORS 映射异常: %+v", protection.CORS)
	}
	if !protection.CSRF.Enabled || protection.CSRF.ValidateToken == nil ||
		protection.CSRF.PublicFormPaths[0] != "/login" {
		t.Fatalf("CSRF 映射异常: %+v", protection.CSRF)
	}
	if protection.SecurityHeaders.ContentSecurityPolicy != "default-src 'none'" ||
		!protection.SecurityHeaders.EnableHSTS {
		t.Fatalf("安全头映射异常: %+v", protection.SecurityHeaders)
	}
	if len(protection.ExpensivePaths) != 1 {
		t.Fatalf("昂贵路径映射异常: %+v", protection.ExpensivePaths)
	}
	if nilProtection, err := normalizeProtection(nil); err != nil || nilProtection != nil {
		t.Fatalf("nil 防护选项应返回 nil, nil；实际 %v, %v", nilProtection, err)
	}
}

// TestIdentityAdapterMapping 验证宿主身份解析错误被映射为稳定传输层错误码，
// AppError 的码/状态/公开消息保留，其他错误统一 AUTH_FAILED。
func TestIdentityAdapterMapping(t *testing.T) {
	accessDenied := errs.NewAppError(errs.CodeAccessDenied, "无权访问")
	adapter := resolveIdentity(httpapi.IdentityResolverFunc(
		func(context.Context, *http.Request) (httpapi.Identity, error) {
			return httpapi.Identity{}, accessDenied
		}))
	_, err := adapter(context.Background(), httptest.NewRequest(http.MethodGet, "http://x/", nil))
	identityErr, ok := err.(*transport.IdentityError)
	if !ok {
		t.Fatalf("期望 *transport.IdentityError，实际 %T", err)
	}
	if identityErr.Code != string(errs.CodeAccessDenied) || identityErr.Status != http.StatusForbidden {
		t.Fatalf("AppError 身份错误映射异常: %+v", identityErr)
	}

	invalidAdapter := resolveIdentity(httpapi.IdentityResolverFunc(
		func(context.Context, *http.Request) (httpapi.Identity, error) {
			return httpapi.Identity{Kind: httpapi.IdentityKindUser}, nil
		}))
	_, err = invalidAdapter(context.Background(),
		httptest.NewRequest(http.MethodGet, "http://x/", nil))
	identityErr, ok = err.(*transport.IdentityError)
	if !ok || identityErr.Code != string(errs.CodeAuthFailed) ||
		identityErr.Message != "无法完成登录" {
		t.Fatalf("非法身份应映射 AUTH_FAILED，实际 %v", err)
	}

	good := resolveIdentity(httpapi.IdentityResolverFunc(
		func(context.Context, *http.Request) (httpapi.Identity, error) {
			return httpapi.Identity{Kind: httpapi.IdentityKindUser, SubjectID: "usr_1"}, nil
		}))
	identity, err := good(context.Background(), httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if err != nil || identity.SubjectID != "usr_1" {
		t.Fatalf("合法身份适配失败: %+v err=%v", identity, err)
	}
	if resolveIdentity(nil) != nil {
		t.Fatal("nil resolver 应映射为 nil")
	}
}

// TestContextRoundtrip 验证身份上下文适配与非法身份拒绝。
func TestContextRoundtrip(t *testing.T) {
	identity := httpapi.Identity{Kind: httpapi.IdentityKindUser, SubjectID: "usr_1"}
	ctx, err := WithIdentity(context.Background(), identity)
	if err != nil {
		t.Fatalf("WithIdentity: %v", err)
	}
	got, ok := IdentityFromContext(ctx)
	if !ok || got.SubjectID != "usr_1" || got.Kind != httpapi.IdentityKindUser {
		t.Fatalf("身份上下文往返失败: %+v ok=%v", got, ok)
	}
	if _, ok := IdentityFromContext(context.Background()); ok {
		t.Fatal("空上下文不应返回身份")
	}
	if _, err := WithIdentity(context.Background(), httpapi.Identity{Kind: "bad"}); err == nil {
		t.Fatal("非法身份必须拒绝")
	}
	if RequestIDFromContext(context.Background()) != "" {
		t.Fatal("空上下文请求编号应为空")
	}
}
