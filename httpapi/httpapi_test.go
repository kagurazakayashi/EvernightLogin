package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// TestIdentityContract 覆盖可信身份结构校验的成功与拒绝路径。
func TestIdentityContract(t *testing.T) {
	if err := (httpapi.Identity{Kind: httpapi.IdentityKindUser,
		SubjectID: "usr_abc.def-1"}).Validate(); err != nil {
		t.Fatalf("合法用户身份应通过: %v", err)
	}
	if err := (httpapi.Identity{Kind: httpapi.IdentityKindApplication,
		SubjectID: "app_service", AppID: "app_x"}).Validate(); err != nil {
		t.Fatalf("合法应用身份应通过: %v", err)
	}
	cases := []struct {
		name     string
		identity httpapi.Identity
		wantErr  bool
	}{
		{"未知类型", httpapi.Identity{Kind: "root", SubjectID: "x"}, true},
		{"空主体", httpapi.Identity{Kind: httpapi.IdentityKindUser}, true},
		{"应用缺范围", httpapi.Identity{Kind: httpapi.IdentityKindApplication,
			SubjectID: "app_x"}, true},
		{"非法字符", httpapi.Identity{Kind: httpapi.IdentityKindUser,
			SubjectID: "user id"}, true},
		{"系统身份合法", httpapi.Identity{Kind: httpapi.IdentityKindSystem,
			SubjectID: "system-1"}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.identity.Validate()
			if test.wantErr && !errors.Is(err, httpapi.ErrIdentityInvalid) {
				t.Fatalf("期望 ErrIdentityInvalid，实际 %v", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("不应返回错误: %v", err)
			}
		})
	}
}

// TestDefaultValuesContract 锁定公开安全默认值（传输层从本包派生，parity 测试
// 在 internal/transport 复核）。
func TestDefaultValuesContract(t *testing.T) {
	if httpapi.DefaultHTTPMaxBodyBytes != 1<<20 || httpapi.MinHTTPMaxBodyBytes != 1<<10 ||
		httpapi.MaxHTTPMaxBodyBytes != 16<<20 {
		t.Fatalf("请求体上限默认/范围异常")
	}
	if httpapi.DefaultHTTPRequestTimeout != 30*time.Second ||
		httpapi.MinHTTPRequestTimeout != 10*time.Millisecond ||
		httpapi.MaxHTTPRequestTimeout != 5*time.Minute {
		t.Fatalf("请求期限默认/范围异常")
	}
	if httpapi.DefaultHTTPMaxConcurrentRequests != 256 ||
		httpapi.MinHTTPMaxConcurrentRequests != 1 ||
		httpapi.MaxHTTPMaxConcurrentRequests != 1024 {
		t.Fatalf("并发上限默认/范围异常")
	}
	if httpapi.DefaultHTTPRateLimitMaxEntries != 4096 ||
		httpapi.DefaultHTTPRateLimitCleanupInterval != 30*time.Second {
		t.Fatalf("限流容量/清理间隔异常")
	}
	options := httpapi.DefaultRateLimitOptions()
	want := map[string]struct {
		limit  int
		window time.Duration
	}{
		"ClientIP":    {600, time.Minute},
		"User":        {300, time.Minute},
		"Application": {300, time.Minute},
		"Endpoint":    {1200, time.Minute},
		"Expensive":   {30, time.Minute},
	}
	got := map[string]httpapi.RateLimitPolicy{
		"ClientIP": options.ClientIP, "User": options.User,
		"Application": options.Application, "Endpoint": options.Endpoint,
		"Expensive": options.Expensive,
	}
	for name, policy := range got {
		if policy.Limit != want[name].limit || policy.Window != want[name].window {
			t.Errorf("%s 默认限流 = %d/%s，期望 %d/%s", name,
				policy.Limit, policy.Window, want[name].limit, want[name].window)
		}
	}
	if options.Capacity != httpapi.DefaultHTTPRateLimitMaxEntries ||
		options.CleanupInterval != httpapi.DefaultHTTPRateLimitCleanupInterval {
		t.Fatalf("限流默认容量/清理间隔异常: %+v", options)
	}
	if httpapi.DefaultHTTPCSRFCookieName != "__Host-login_session" ||
		httpapi.DefaultHTTPCSRFTokenHeader != "X-CSRF-Token" {
		t.Fatalf("CSRF Cookie/头默认值异常")
	}
}

// TestCookiePolicyContract 覆盖单一 Cookie 策略实现的默认值与安全校验。
func TestCookiePolicyContract(t *testing.T) {
	policy := httpapi.DefaultCookiePolicy()
	if !policy.Secure || !policy.HttpOnly || policy.SameSite != http.SameSiteLaxMode ||
		policy.Path != "/" || policy.Domain != "" || policy.MaxAge != 0 {
		t.Fatalf("默认 Cookie 策略异常: %+v", policy)
	}
	cookie, err := policy.NewCookie("__Host-login_session", "session-value")
	if err != nil {
		t.Fatalf("默认策略构造会话 Cookie 失败: %v", err)
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" ||
		cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("会话 Cookie 安全属性异常: %+v", cookie)
	}
	insecureNone := policy
	insecureNone.SameSite = http.SameSiteNoneMode
	insecureNone.Secure = false
	if err := insecureNone.Validate(); err == nil {
		t.Fatal("SameSite=None 且非 Secure 必须拒绝")
	}
	badPath := policy
	badPath.Path = "relative"
	if err := badPath.Validate(); err == nil {
		t.Fatal("非绝对路径必须拒绝")
	}
	hostPrefixWithDomain := policy
	hostPrefixWithDomain.Domain = "example.com"
	if _, err := hostPrefixWithDomain.NewCookie("__Host-login_session", "v"); err == nil {
		t.Fatal("__Host- Cookie 设置 Domain 必须拒绝")
	}
	if _, err := policy.NewCookie("bad name", "v"); err == nil {
		t.Fatal("非法 Cookie 名必须拒绝")
	}
	if !httpapi.ValidCookieToken("X-CSRF-Token") || httpapi.ValidCookieToken("bad name") {
		t.Fatal("Cookie 名 token 校验异常")
	}
}

// TestCSRFValidatorFunc 覆盖函数适配器的空值与正常转发。
func TestCSRFValidatorFunc(t *testing.T) {
	var nilValidator httpapi.CSRFValidatorFunc
	request, err := http.NewRequest(http.MethodPost, "https://example.test/", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if err := nilValidator.ValidateCSRFToken(context.Background(), request, "t"); err == nil {
		t.Fatal("空 CSRF 校验器必须拒绝")
	}
	seen := ""
	validator := httpapi.CSRFValidatorFunc(func(_ context.Context, _ *http.Request, token string) error {
		seen = token
		return nil
	})
	if err := validator.ValidateCSRFToken(context.Background(), request, "token-1"); err != nil {
		t.Fatalf("正常校验器不应失败: %v", err)
	}
	if seen != "token-1" {
		t.Fatalf("校验器收到 token = %q", seen)
	}
}
