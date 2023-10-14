package transport

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// TestPublicDefaultsParity 断言传输层内部默认值与公开契约 httpapi 单一来源一致：
// 这些数值（超时/并发/限流/容量/CSRF Cookie 名与头名/可信代理上限/请求体上限）
// 属于公开安全默认值，任何漂移都必须被本测试发现（步骤 213）。
func TestPublicDefaultsParity(t *testing.T) {
	if DefaultRateLimitMaxEntries != httpapi.DefaultHTTPRateLimitMaxEntries {
		t.Errorf("限流容量 = %d，公开契约 = %d",
			DefaultRateLimitMaxEntries, httpapi.DefaultHTTPRateLimitMaxEntries)
	}
	if DefaultRateLimitCleanupAfter != httpapi.DefaultHTTPRateLimitCleanupInterval {
		t.Errorf("限流清理间隔 = %s，公开契约 = %s",
			DefaultRateLimitCleanupAfter, httpapi.DefaultHTTPRateLimitCleanupInterval)
	}
	if DefaultRequestTimeout != httpapi.DefaultHTTPRequestTimeout ||
		MinRequestTimeout != httpapi.MinHTTPRequestTimeout ||
		MaxRequestTimeout != httpapi.MaxHTTPRequestTimeout {
		t.Errorf("请求期限默认/范围与公开契约不一致")
	}
	if DefaultMaxConcurrentRequests != httpapi.DefaultHTTPMaxConcurrentRequests ||
		MinConcurrentRequests != httpapi.MinHTTPMaxConcurrentRequests ||
		MaxConcurrentRequests != httpapi.MaxHTTPMaxConcurrentRequests {
		t.Errorf("并发上限默认/范围与公开契约不一致")
	}
	if MaxTrustedProxies != httpapi.MaxHTTPTrustedProxies {
		t.Errorf("可信代理上限 = %d，公开契约 = %d", MaxTrustedProxies, httpapi.MaxHTTPTrustedProxies)
	}
	if DefaultCSRFCookieName != httpapi.DefaultHTTPCSRFCookieName {
		t.Errorf("CSRF Cookie 名 = %q，公开契约 = %q",
			DefaultCSRFCookieName, httpapi.DefaultHTTPCSRFCookieName)
	}
	if DefaultCSRFTokenHeader != httpapi.DefaultHTTPCSRFTokenHeader {
		t.Errorf("CSRF 头名 = %q，公开契约 = %q",
			DefaultCSRFTokenHeader, httpapi.DefaultHTTPCSRFTokenHeader)
	}
	if DefaultMaxBodyBytes != httpapi.DefaultHTTPMaxBodyBytes ||
		MinMaxBodyBytes != httpapi.MinHTTPMaxBodyBytes ||
		MaxMaxBodyBytes != httpapi.MaxHTTPMaxBodyBytes {
		t.Errorf("请求体上限默认/范围与公开契约不一致")
	}
	public := httpapi.DefaultRateLimitOptions()
	for name, pair := range map[string][2]int{
		"ClientIP":  {DefaultClientIPRateLimit.Limit, public.ClientIP.Limit},
		"User":      {DefaultUserRateLimit.Limit, public.User.Limit},
		"App":       {DefaultApplicationRateLimit.Limit, public.Application.Limit},
		"Endpoint":  {DefaultEndpointRateLimit.Limit, public.Endpoint.Limit},
		"Expensive": {DefaultExpensiveRateLimit.Limit, public.Expensive.Limit},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s 限流默认值 = %d，公开契约 = %d", name, pair[0], pair[1])
		}
	}
}
