package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CookiePolicy 是 Cookie 会话的安全属性策略。零值不是有效策略；请使用
// DefaultCookiePolicy 或显式设置。默认 Secure/HttpOnly/Lax/Path=/ 适合同站与
// 顶层导航；仅当协议端点确实需要跨站 Cookie 时才可 SameSite=None（仍必须
// Secure），并必须由协议层完成来源/CSRF 校验，不能用 SameSite=None 代替 CSRF。
// __Host- 前缀 Cookie 必须 Secure、Path=/ 且无 Domain。
//
// 本类型是会话 Cookie 策略的单一实现：根包与 internal/session 通过类型别名/
// 包装复用，避免两套安全属性判断漂移。
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

// NewCookie 按策略构造 Cookie。name/value 必须非空；只负责安全属性，不判断
// 会话有效性。同名 Cookie 的创建仍由会话服务负责。
func (p CookiePolicy) NewCookie(name, value string) (*http.Cookie, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !ValidCookieToken(name) {
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

// ValidCookieToken 报告 Cookie 名是否为 RFC 6265 token（会话服务创建 Cookie
// 前也复用它，避免重复实现名字校验）。
func ValidCookieToken(value string) bool {
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
