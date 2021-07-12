// Package pagecsrf 实现匿名 HTML 表单的签名双提交 CSRF 令牌（步骤 63）。
//
// 方案：服务端在公开页面 GET 时下发 HttpOnly/Secure/SameSite=Lax Cookie 与同值隐藏
// 字段；值格式为 `v1.<key_id>.<purpose>.<unix>.<nonce>.<sig>`，sig 由
// secrets.Keyring.HMACDigest(domain=page-anon-csrf-v1, message=keyID|purpose|unix|nonce)
// 计算。POST 时 transport 在公开表单路径上要求 Origin/Referer 精确匹配（既有逻辑）、
// 单一表单字段，并调用本包校验：kid 存在、用途与路径绑定一致、短时效、Cookie 与表单
// 值恒时相等、签名恒时匹配。令牌绝不放入 URL，也不削弱会话 CSRF 校验。
//
// 边界：这是无服务端状态的签名双提交（同一令牌在有效期内可重复用于同一用途表单，
// 属该方案的已知语义）；真正的防重放依赖服务端一次性凭证/条件状态迁移。生产必须
// HTTPS 且 Origin 白名单与真实外部地址一致。
package pagecsrf

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// DefaultTTL 是匿名表单令牌默认有效期。
	DefaultTTL = 15 * time.Minute
	// MinTTL/MaxTTL 是有效期边界。
	MinTTL = time.Minute
	MaxTTL = time.Hour
	// CookieName 是匿名表单令牌 Cookie 名（HttpOnly；与隐藏字段同值）。
	CookieName = "ln_page_csrf"
	// digestDomain 是 HMAC 派生的用途域。
	digestDomain = "page-anon-csrf-v1"
	// tokenVersion 是令牌版本前缀。
	tokenVersion = "v1"
	// tokenSeparator 分隔令牌字段（用途含点号，不能用点号分隔）。
	tokenSeparator = ":"
	// maxTokenBytes 是令牌长度上限。
	maxTokenBytes = 512
	// nonceBytes 是随机 nonce 字节数。
	nonceBytes = 16
)

// 领域错误（只用于内部分类；调用方对客户端统一返回 CSRF 失败）。
var (
	ErrProviderInvalid = errors.New("页面 CSRF 提供者无效")
	ErrTokenInvalid    = errors.New("页面 CSRF 令牌无效")
)

// Provider 签发与校验匿名页面 CSRF 令牌。构造后不可变、可并发使用。
type Provider struct {
	ring       *secrets.Keyring
	ttl        time.Duration
	cookiePath string
	now        func() time.Time
	random     io.Reader
}

// Options 是 Provider 构造参数。
type Options struct {
	Keyring *secrets.Keyring
	// TTL 是令牌有效期；0 使用 DefaultTTL，必须在 MinTTL～MaxTTL 之间。
	TTL time.Duration
	// CookiePath 是 Cookie Path（通常等于部署 BasePath 或 /）；必须以 / 开头。
	CookiePath string
	Now        func() time.Time
	Random     io.Reader
}

// New 校验参数并构造 Provider。
func New(options Options) (*Provider, error) {
	if options.Keyring == nil || options.Keyring.CurrentKeyID() == "" ||
		!options.Keyring.HasKey(options.Keyring.CurrentKeyID()) {
		return nil, fmt.Errorf("%w: 密钥环缺失或缺少当前写密钥", ErrProviderInvalid)
	}
	ttl := options.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return nil, fmt.Errorf("%w: 令牌有效期必须在 %s～%s 之间", ErrProviderInvalid, MinTTL, MaxTTL)
	}
	cookiePath := options.CookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	if !strings.HasPrefix(cookiePath, "/") || strings.ContainsAny(cookiePath, "?#") {
		return nil, fmt.Errorf("%w: Cookie Path 无效", ErrProviderInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &Provider{ring: options.Keyring, ttl: ttl, cookiePath: cookiePath,
		now: options.Now, random: options.Random}, nil
}

// IssueFormToken 为指定用途签发令牌并返回对应 Cookie 与隐藏字段值。
func (p *Provider) IssueFormToken(_ context.Context, _ *http.Request,
	purpose string) (string, *http.Cookie, error) {
	if !validPurpose(purpose) {
		return "", nil, fmt.Errorf("%w: 表单用途无效", ErrProviderInvalid)
	}
	keyID := p.ring.CurrentKeyID()
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(p.random, nonce); err != nil {
		return "", nil, fmt.Errorf("%w: 安全随机源不可用", ErrProviderInvalid)
	}
	issuedAt := p.now().UTC().Unix()
	message := signatureMessage(keyID, purpose, issuedAt, nonce)
	signature, err := p.ring.HMACDigest(keyID, digestDomain, message)
	if err != nil {
		return "", nil, fmt.Errorf("%w: 无法派生令牌签名", ErrProviderInvalid)
	}
	token := strings.Join([]string{tokenVersion, keyID, purpose,
		strconv.FormatInt(issuedAt, 10), base64.RawURLEncoding.EncodeToString(nonce),
		hex.EncodeToString(signature)}, tokenSeparator)
	cookie := &http.Cookie{Name: CookieName, Value: token, Path: p.cookiePath,
		MaxAge: int(p.ttl / time.Second), HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode}
	return token, cookie, nil
}

// Issue 实现页面框架的匿名表单令牌提供者契约。
func (p *Provider) Issue(ctx context.Context, request *http.Request,
	purpose string) (string, *http.Cookie, error) {
	return p.IssueFormToken(ctx, request, purpose)
}

// Validate 校验某公开路径的表单令牌：用途与路径绑定、Kid 存在、未过期、Cookie 与
// 表单值恒时相等、签名恒时匹配。任何失败都返回错误（调用方统一 403）。
func (p *Provider) Validate(ctx context.Context, request *http.Request, path string,
	purposes map[string]string, token string) error {
	if p == nil || request == nil {
		return ErrTokenInvalid
	}
	purpose, ok := purposes[path]
	if !ok || !validPurpose(purpose) {
		return ErrTokenInvalid
	}
	if len(token) == 0 || len(token) > maxTokenBytes {
		return ErrTokenInvalid
	}
	parts := strings.Split(token, tokenSeparator)
	if len(parts) != 6 || parts[0] != tokenVersion {
		return ErrTokenInvalid
	}
	keyID, tokenPurpose := parts[1], parts[2]
	if tokenPurpose != purpose || !validPurpose(tokenPurpose) {
		return ErrTokenInvalid
	}
	issuedAt, parseErr := strconv.ParseInt(parts[3], 10, 64)
	if parseErr != nil || issuedAt <= 0 {
		return ErrTokenInvalid
	}
	nonce, decodeErr := base64.RawURLEncoding.DecodeString(parts[4])
	if decodeErr != nil || len(nonce) != nonceBytes {
		return ErrTokenInvalid
	}
	signature, decodeSigErr := hex.DecodeString(parts[5])
	if decodeSigErr != nil || len(signature) != 32 {
		return ErrTokenInvalid
	}
	delta := p.now().UTC().Unix() - issuedAt
	if delta < -60 || delta > int64(p.ttl/time.Second) {
		return ErrTokenInvalid
	}
	// Cookie 必须存在且与隐藏字段同值（双提交），防止攻击者只伪造表单字段。
	cookie, cookieErr := request.Cookie(CookieName)
	if cookieErr != nil {
		return ErrTokenInvalid
	}
	if len(cookie.Value) != len(token) ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
		return ErrTokenInvalid
	}
	expected, err := p.ring.HMACDigest(keyID, digestDomain,
		signatureMessage(keyID, tokenPurpose, issuedAt, nonce))
	if err != nil || len(expected) != len(signature) {
		return ErrTokenInvalid
	}
	if subtle.ConstantTimeCompare(expected, signature) != 1 {
		return ErrTokenInvalid
	}
	return nil
}

// Validator 返回适配 transport 公开表单校验函数（路径→用途映射在构造时给定）。
func (p *Provider) Validator(purposes map[string]string) func(ctx context.Context,
	request *http.Request, path, token string) error {
	copied := make(map[string]string, len(purposes))
	for path, purpose := range purposes {
		copied[path] = purpose
	}
	return func(ctx context.Context, request *http.Request, path, token string) error {
		return p.Validate(ctx, request, path, copied, token)
	}
}

// signatureMessage 构造签名覆盖的稳定字节串。
func signatureMessage(keyID, purpose string, issuedAt int64, nonce []byte) []byte {
	return []byte(keyID + "\x00" + purpose + "\x00" +
		strconv.FormatInt(issuedAt, 10) + "\x00" + base64.RawURLEncoding.EncodeToString(nonce))
}

// validPurpose 校验用途标识（小写字母/数字/点/下划线/连字符，长度有界）。
func validPurpose(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') &&
			character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
