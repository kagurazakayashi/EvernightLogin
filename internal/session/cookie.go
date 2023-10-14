package session

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
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
// DefaultCookiePolicy 或显式设置。默认 Secure/HttpOnly/Lax/Path=/ 适合同站与
// 顶层导航；仅当协议端点确实需要跨站 Cookie 时才可 SameSite=None（仍必须
// Secure），并必须由协议层完成来源/CSRF 校验，不能用 SameSite=None 代替 CSRF。
//
// 类型与校验的单一实现位于公开叶子包 httpapi；本包通过类型别名复用，避免根包/
// 会话层两套 Cookie 安全策略漂移（步骤 213）。
type CookiePolicy = httpapi.CookiePolicy

// DefaultCookiePolicy 返回会话 Cookie 的安全默认值：Secure、HttpOnly、
// SameSite=Lax、Path=/、不设置 Domain、浏览器会话 Cookie（MaxAge=0，绝对到期由
// 服务端控制）。
func DefaultCookiePolicy() CookiePolicy {
	return httpapi.DefaultCookiePolicy()
}

// isCookieToken 保持会话包内部调用口径；RFC 6265 token 校验的单一实现在 httpapi。
func isCookieToken(value string) bool { return httpapi.ValidCookieToken(value) }

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
