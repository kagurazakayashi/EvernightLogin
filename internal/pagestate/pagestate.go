// Package pagestate 实现服务端页面短期状态的签名封装（步骤 64）。
//
// 使用场景：第二因素挑战/尝试令牌、强认证初始化状态等只应在相邻页面间传递、
// 绝不进入 URL 或长期存储的一次性页面状态。状态被封装为 HMAC-SHA256 签名的
// 短时效令牌，放在 HttpOnly/Secure/SameSite=Lax Cookie 中；服务端每次读取都验证
// 签名、密钥 ID、用途域与到期时间，任一项失败 fail-closed。
//
// 安全边界：签名保证完整性但不加密；调用方不得把长期秘密、密码、恢复代码或
// 超出“用户自己本次流程已有”范围的秘密放入状态。令牌不写日志/审计/URL。
package pagestate

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// DefaultTTL 是页面状态默认有效期。
	DefaultTTL = 15 * time.Minute
	// MinTTL/MaxTTL 是有效期边界。
	MinTTL = time.Minute
	MaxTTL = time.Hour
	// maxTokenBytes 是封装令牌长度上限。
	maxTokenBytes = 8192
	tokenVersion  = "v1"
	separator     = "."
)

// 领域错误；调用方对客户端只返回统一页面失效说明。
var (
	ErrOptionsInvalid = errors.New("页面状态选项无效")
	ErrStateInvalid   = errors.New("页面状态无效或已失效")
)

// Codec 是按用途域签发/校验页面状态的不可变编解码器。
type Codec struct {
	ring *secrets.Keyring
	ttl  time.Duration
	now  func() time.Time
}

// Options 是 Codec 构造参数。
type Options struct {
	Keyring *secrets.Keyring
	TTL     time.Duration
	Now     func() time.Time
}

// New 校验参数并构造 Codec。
func New(options Options) (*Codec, error) {
	if options.Keyring == nil || options.Keyring.CurrentKeyID() == "" {
		return nil, fmt.Errorf("%w: 缺少密钥环", ErrOptionsInvalid)
	}
	ttl := options.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return nil, fmt.Errorf("%w: 有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinTTL, MaxTTL)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Codec{ring: options.Keyring, ttl: ttl, now: now}, nil
}

// envelope 是签名载荷的固定字段；ExpiresAt 由服务端时间决定，不信任客户端时钟。
type envelope struct {
	Purpose   string          `json:"purpose"`
	ExpiresAt int64           `json:"expires_at_ms"`
	Data      json.RawMessage `json:"data"`
}

// Seal 把 value 序列化并封装为指定用途的短时效令牌。value 必须可 JSON 序列化且
// 不含长期秘密；purpose 是稳定用途域（例如 "mfa.second_factor"）。
func (c *Codec) Seal(purpose string, value any) (string, error) {
	if c == nil || c.ring == nil {
		return "", ErrOptionsInvalid
	}
	if purpose == "" || len(purpose) > 128 {
		return "", fmt.Errorf("%w: 用途域无效", ErrOptionsInvalid)
	}
	for _, character := range purpose {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' {
			continue
		}
		return "", fmt.Errorf("%w: 用途域无效", ErrOptionsInvalid)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: 状态序列化失败", ErrOptionsInvalid)
	}
	if len(raw) > maxTokenBytes/2 {
		return "", fmt.Errorf("%w: 状态过大", ErrOptionsInvalid)
	}
	envelopeRaw, err := json.Marshal(envelope{Purpose: purpose,
		ExpiresAt: c.now().UTC().Add(c.ttl).UnixMilli(), Data: raw})
	if err != nil {
		return "", fmt.Errorf("%w: 状态序列化失败", ErrOptionsInvalid)
	}
	payload := base64.RawURLEncoding.EncodeToString(envelopeRaw)
	keyID := c.ring.CurrentKeyID()
	signature, err := c.sign(keyID, purpose, payload)
	if err != nil {
		return "", ErrOptionsInvalid
	}
	token := strings.Join([]string{tokenVersion, keyID, payload,
		base64.RawURLEncoding.EncodeToString(signature)}, separator)
	if len(token) > maxTokenBytes {
		return "", fmt.Errorf("%w: 状态过大", ErrOptionsInvalid)
	}
	return token, nil
}

// Open 校验令牌并反序列化到 value。用途不符、签名/密钥/到期失败一律返回
// ErrStateInvalid（调用方不得区分细节）。
func (c *Codec) Open(purpose, token string, value any) error {
	if c == nil || c.ring == nil {
		return ErrStateInvalid
	}
	if token == "" || len(token) > maxTokenBytes {
		return ErrStateInvalid
	}
	parts := strings.Split(token, separator)
	if len(parts) != 4 || parts[0] != tokenVersion || parts[1] == "" || parts[2] == "" {
		return ErrStateInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(signature) == 0 {
		return ErrStateInvalid
	}
	expected, err := c.sign(parts[1], purpose, parts[2])
	if err != nil || subtle.ConstantTimeCompare(expected, signature) != 1 {
		return ErrStateInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrStateInvalid
	}
	var decoded envelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ErrStateInvalid
	}
	if decoded.Purpose != purpose || decoded.ExpiresAt <= 0 ||
		!c.now().UTC().Before(time.UnixMilli(decoded.ExpiresAt)) {
		return ErrStateInvalid
	}
	if value != nil {
		if err := json.Unmarshal(decoded.Data, value); err != nil {
			return ErrStateInvalid
		}
	}
	return nil
}

// sign 计算用途域绑定的 HMAC 签名。
func (c *Codec) sign(keyID, purpose, payload string) ([]byte, error) {
	message := []byte(strconv.FormatInt(int64(len(purpose)), 10) + ":" + purpose + "|" + payload)
	return c.ring.HMACDigest(keyID, "page-state-v1", message)
}
