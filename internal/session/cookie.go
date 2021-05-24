package session

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultCookieName 是浏览器会话 Cookie 的默认名字。它与 internal/transport
	// 的 CSRF 契约默认名一致（__Host- 前缀要求 Secure、Path=/ 且无 Domain），
	// 因此既有 CSRF 中间件能识别本包签发的 Cookie。根包测试会核对两者相等。
	DefaultCookieName = "__Host-login_session"
	// maxCookieValueBytes 是会话 Cookie 值长度上限。
	maxCookieValueBytes = 256
)

// CookiePolicy 是会话 Cookie 的安全属性策略。零值不是有效策略；请使用
// DefaultCookiePolicy 或显式设置。默认 Secure、HttpOnly、SameSite=Lax、Path=/
// 适合同站与顶层导航；仅当协议端点确实需要跨站 Cookie 时才可 SameSite=None
// （仍必须 Secure），并必须由协议层完成来源/CSRF 校验，不能用 SameSite=None
// 代替 CSRF。
//
// 该类型与根包 login.CookiePolicy 语义一致，但 internal 包不能 import 根包；
// 根包测试会核对默认值一致，避免两套策略漂移。
type CookiePolicy struct {
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Path     string
	Domain   string
	MaxAge   time.Duration
}

// DefaultCookiePolicy 返回会话 Cookie 的安全默认值：Secure、HttpOnly、
// SameSite=Lax、Path=/、不设置 Domain、浏览器会话 Cookie（MaxAge=0，绝对到期由
// 服务端控制）。
func DefaultCookiePolicy() CookiePolicy {
	return CookiePolicy{
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

// Validate 校验 Cookie 策略：SameSite 必须明确且合法，SameSite=None 必须 Secure，
// Path 必须是安全的绝对路径，Domain 必须是规范主机名；__Host-/__Secure- 前缀
// 规则在 NewCookie 中结合名字强制满足。
func (p CookiePolicy) Validate() error {
	switch p.SameSite {
	case http.SameSiteLaxMode, http.SameSiteStrictMode, http.SameSiteNoneMode:
	default:
		return fmt.Errorf("Cookie SameSite 必须明确设置为 Lax、Strict 或 None")
	}
	if p.SameSite == http.SameSiteNoneMode && !p.Secure {
		return fmt.Errorf("SameSite=None 的 Cookie 必须启用 Secure")
	}
	if len(p.Path) == 0 || p.Path[0] != '/' || len(p.Path) > 256 {
		return fmt.Errorf("Cookie Path 必须是 / 开头的绝对路径")
	}
	for _, character := range p.Path {
		if character < 0x21 || character > 0x7e || character == ';' || character == ',' {
			return fmt.Errorf("Cookie Path 包含不安全字符")
		}
	}
	if err := validateCookieDomain(p.Domain); err != nil {
		return err
	}
	if p.MaxAge < 0 || p.MaxAge > 365*24*time.Hour {
		return fmt.Errorf("Cookie MaxAge 超出允许范围")
	}
	return nil
}

// NewCookie 按策略构造 Cookie。name/value 必须非空且不含控制字符；只负责安全
// 属性，不判断会话有效性。
func (p CookiePolicy) NewCookie(name, value string) (*http.Cookie, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !isCookieToken(name) {
		return nil, fmt.Errorf("Cookie 名无效")
	}
	if value == "" || len(value) > 4096 {
		return nil, fmt.Errorf("Cookie 值无效")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == ';' || character == ',' {
			return nil, fmt.Errorf("Cookie 值包含不安全字符")
		}
	}
	if strings.HasPrefix(name, "__Host-") {
		if !p.Secure || p.Path != "/" || p.Domain != "" {
			return nil, fmt.Errorf("__Host- Cookie 必须 Secure、Path=/ 且不能设置 Domain")
		}
	}
	if strings.HasPrefix(name, "__Secure-") && !p.Secure {
		return nil, fmt.Errorf("__Secure- Cookie 必须启用 Secure")
	}
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     p.Path,
		Domain:   p.Domain,
		MaxAge:   int(p.MaxAge / time.Second),
		Secure:   p.Secure,
		HttpOnly: p.HttpOnly,
		SameSite: p.SameSite,
	}, nil
}

// validateCookieDomain 校验可选 Domain：空表示主机专用 Cookie；非空时不允许带
// 端口、路径或前导点。
func validateCookieDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("Cookie Domain 无效")
	}
	for index := 0; index < len(domain); index++ {
		character := domain[index]
		if character <= 0x20 || character >= 0x7f {
			return fmt.Errorf("Cookie Domain 无效")
		}
		switch character {
		case '/', '\\', ':', ';', ',', '?', '#', '@', '[', ']':
			return fmt.Errorf("Cookie Domain 无效")
		}
	}
	return nil
}

// isCookieToken 报告 Cookie 名是否为 RFC 6265 token。
func isCookieToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// NewCookie 把签发结果转换为浏览器 Cookie。只有 IssuedSession 中仍持有秘密时
// 才能调用；Cookie 值 = 会话 ID + "." + 会话秘密，服务端仍只保存验证摘要。会话
// 秘密只在这里从内存写入 Cookie，不进入日志。
func (s *Service) NewCookie(issued IssuedSession) (*http.Cookie, error) {
	if !issued.Secret.IsSet() || issued.Session.ID == "" {
		return nil, fmt.Errorf("%w: 签发结果缺少会话秘密", ErrInvalidRequest)
	}
	value := issued.Secret.Reveal()
	if !strings.HasPrefix(value, issued.Session.ID+secretSeparator) {
		return nil, fmt.Errorf("%w: 会话秘密与会话 ID 不匹配", ErrInvalidRequest)
	}
	if len(value) > maxCookieValueBytes {
		return nil, fmt.Errorf("%w: 会话 Cookie 值过长", ErrInvalidRequest)
	}
	return s.cookiePolicy.NewCookie(s.cookieName, value)
}

// ClearCookie 返回删除浏览器会话 Cookie 的 Cookie（MaxAge<0，立即失效）。
func (s *Service) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     s.cookiePolicy.Path,
		Domain:   s.cookiePolicy.Domain,
		MaxAge:   -1,
		Secure:   s.cookiePolicy.Secure,
		HttpOnly: s.cookiePolicy.HttpOnly,
		SameSite: s.cookiePolicy.SameSite,
	}
}

// SessionSecretFromRequest 从请求读取会话秘密：优先 Cookie，其次
// Authorization: Bearer。它绝不读取查询参数、表单或自定义身份头，避免把会话
// 秘密放进 URL 或让客户端自填身份生效。返回值为 Cookie 值或 Bearer 令牌原文，
// 调用方不得记录。
func (s *Service) SessionSecretFromRequest(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	if cookie, err := request.Cookie(s.cookieName); err == nil && cookie != nil {
		value := strings.TrimSpace(cookie.Value)
		if value != "" && len(value) <= maxCookieValueBytes {
			return value, true
		}
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxSecretInputBytes {
		return "", false
	}
	return token, true
}
