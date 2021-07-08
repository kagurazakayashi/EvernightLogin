package transport

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	// DefaultContentSecurityPolicy 是 JSON/API 响应的默认 CSP：禁止加载任何资源、
	// 禁止被嵌入、禁止 <base> 与跨源表单提交。未来 HTML 页面（扫码/授权页）需要
	// 通过 SecurityHeaderConfig.ContentSecurityPolicy 显式放宽，而不是关闭全部头。
	DefaultContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	// DefaultPermissionsPolicy 是默认浏览器能力禁用策略。
	DefaultPermissionsPolicy = "camera=(), geolocation=(), microphone=()"
	// hstsValue 是启用 HSTS 时输出的固定策略（一年，含子域）。
	hstsValue = "max-age=31536000; includeSubDomains"
	// maxCSPBytes 是自定义 CSP 长度上限，防止响应头放大。
	maxCSPBytes = 2048
)

// securityHeaders 是构造时冻结的安全响应头配置。
type securityHeaders struct {
	contentSecurityPolicy string
	frameOptions          string
	enableHSTS            bool
}

// newSecurityHeaders 校验并构造安全响应头。空配置使用 API 安全默认值；
// AllowFraming 只放宽为同源嵌入，避免为嵌入完全移除防点击劫持保护。
func newSecurityHeaders(config SecurityHeaderConfig) (securityHeaders, error) {
	csp := config.ContentSecurityPolicy
	if csp == "" {
		csp = DefaultContentSecurityPolicy
		if config.AllowFraming {
			// 允许同源嵌入时不能继续声明 frame-ancestors 'none'，否则合法
			// 扫码/授权页面即使设置 X-Frame-Options=SAMEORIGIN 仍会被 CSP 拒绝。
			csp = "default-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"
		}
	}
	if len(csp) > maxCSPBytes {
		return securityHeaders{}, fmt.Errorf("Content-Security-Policy 过长")
	}
	for _, character := range csp {
		if character < 0x20 || character == 0x7f {
			return securityHeaders{}, fmt.Errorf("Content-Security-Policy 不能包含控制字符")
		}
	}
	frameOptions := "DENY"
	if config.AllowFraming {
		frameOptions = "SAMEORIGIN"
	}
	return securityHeaders{
		contentSecurityPolicy: csp,
		frameOptions:          frameOptions,
		enableHSTS:            config.EnableHSTS,
	}, nil
}

// validateUIPageContentSecurityPolicy 校验 HTML 页面 CSP：必须保留禁止插件/嵌入/
// base/跨源表单等基线，且不允许 unsafe-inline/unsafe-eval；不要求与 API 默认值
// 相同，但不得退化为过宽策略。
func validateUIPageContentSecurityPolicy(csp string) error {
	if csp == "" {
		return fmt.Errorf("HTML 页面必须显式提供内容安全策略")
	}
	if len(csp) > maxCSPBytes {
		return fmt.Errorf("HTML 页面内容安全策略过长")
	}
	for _, character := range csp {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("HTML 页面内容安全策略不能包含控制字符")
		}
	}
	lower := strings.ToLower(csp)
	required := []string{
		"default-src 'none'", "script-src 'self'", "object-src 'none'",
		"base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
	}
	for _, directive := range required {
		if !strings.Contains(lower, directive) {
			return fmt.Errorf("HTML 页面内容安全策略缺少基线指令 %s", directive)
		}
	}
	if strings.Contains(lower, "unsafe-inline") || strings.Contains(lower, "unsafe-eval") {
		return fmt.Errorf("HTML 页面内容安全策略不允许 unsafe-inline/unsafe-eval")
	}
	return nil
}

// apply 在响应写出前设置安全头；调用方应在任何处理程序写响应之前调用。
func (h securityHeaders) apply(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", h.frameOptions)
	header.Set("Content-Security-Policy", h.contentSecurityPolicy)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", DefaultPermissionsPolicy)
	header.Set("X-Permitted-Cross-Domain-Policies", "none")
	header.Set("Cache-Control", "no-store")
	if h.enableHSTS {
		header.Set("Strict-Transport-Security", hstsValue)
	}
}
