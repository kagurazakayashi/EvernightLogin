package credential

import (
	"fmt"
	"log/slog"
	"time"
)

// Kind 是一次性凭证的形态。
type Kind string

const (
	// KindToken 表示高熵令牌：crypto/rand 生成，数据库只保存 SHA-256 摘要。
	KindToken Kind = "token"
	// KindCode 表示低熵验证码：固定长度十进制短码，数据库保存受密钥保护的
	// HMAC-SHA256 摘要。
	KindCode Kind = "code"
)

// valid 报告 Kind 是否为已定义形态。
func (k Kind) valid() bool {
	return k == KindToken || k == KindCode
}

const (
	// DefaultTokenTTL 是高熵令牌未指定有效期时的默认值。
	DefaultTokenTTL = 30 * time.Minute
	// DefaultCodeTTL 是低熵验证码未指定有效期时的默认值。
	DefaultCodeTTL = 10 * time.Minute
	// MinTTL 是一次性凭证允许的最短有效期。
	MinTTL = time.Minute
	// MaxTTL 是一次性凭证允许的最长有效期。
	MaxTTL = 24 * time.Hour
	// DefaultMaxAttempts 是低熵验证码的默认尝试上限。
	DefaultMaxAttempts = 5
	// MinMaxAttempts 是允许的最小尝试上限。
	MinMaxAttempts = 1
	// MaxMaxAttempts 是允许的最大尝试上限。
	MaxMaxAttempts = 10
	// CodeLength 是低熵验证码的固定十进制位数（含前导零）。
	CodeLength = 8
	// TokenSize 是高熵令牌的随机字节数（256 位）。
	TokenSize = 32
	// TokenSecretLength 是高熵令牌的 base64url 文本长度。
	TokenSecretLength = 43
	// CredentialIDPrefix 是凭证 ID 的固定前缀。
	CredentialIDPrefix = "otc_"
	// MaxCleanupRetention 是过期清理允许保留的最长时间。
	MaxCleanupRetention = 30 * 24 * time.Hour
)

const (
	maxPurposeBytes         = 64
	maxTargetBytes          = 128
	maxAppIDBytes           = 64
	maxTokenInputBytes      = 128
	maxCodeInputBytes       = 32
	credentialIDRandomBytes = 16
	credentialIDHexBytes    = 2 * credentialIDRandomBytes
	// hmacDomain 是低熵验证码 HMAC 子密钥派生使用的用途域。
	hmacDomain = "one-time-credential-v1"
	// tokenDigestDomain 与 codeDigestDomain 区分两种凭证的摘要输入，防止令牌
	// 摘要与验证码摘要互相冒用。
	tokenDigestDomain = "evernight-login/one-time-credential/token/v1"
	codeDigestDomain  = "evernight-login/one-time-credential/code/v1"
)

// Secret 保存签发结果中只展示一次的令牌或验证码明文。
//
// 默认的字符串化、格式化与 JSON 序列化都只输出脱敏标记；投递代码必须显式调用
// Reveal 取得副本，并自行限制副本在内存、日志、队列和数据库中的生命周期。
// 本类型不是内存清零或防内存取证的承诺。
type Secret struct {
	value string
}

// newSecret 构造已设置的秘密；只允许包内从安全随机源生成后调用。
func newSecret(value string) Secret {
	return Secret{value: value}
}

// IsSet 报告秘密是否有值；不暴露内容。
func (s Secret) IsSet() bool {
	return s.value != ""
}

// Reveal 返回秘密明文的副本，用于投递邮件等受控路径。调用方不得记录、持久化
// 到普通位置或转发给无必要的组件。
func (s Secret) Reveal() string {
	return s.value
}

// String 实现 fmt.Stringer，固定输出脱敏标记。
func (s Secret) String() string {
	if s.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer，覆盖 %#v 输出。
func (s Secret) GoString() string {
	return s.String()
}

// Format 实现 fmt.Formatter，覆盖 %v、%s、%q、%x 等格式化动词。
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(s.String()))
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// LogValue 实现 slog.LogValuer，避免结构化日志泄露令牌或验证码。
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(s.String())
}

// IssueRequest 是签发一次性凭证的参数。零值 TTL/MaxAttempts 使用默认值；
// ReplaceActive 为 true 时在同一事务内撤销同用途、同目标、同应用的活动凭证。
type IssueRequest struct {
	// Purpose 是用途标识，例如 "email.verify"，只允许可见 ASCII。
	Purpose string
	// Target 是接收方/目标对象标识，例如用户 ID；只允许可见 ASCII。
	Target string
	// AppID 是可选应用绑定；空字符串表示系统范围。
	AppID string
	// Kind 是凭证形态；必填。
	Kind Kind
	// TTL 是有效期；0 使用该形态的默认值，必须在 MinTTL～MaxTTL 之间。
	TTL time.Duration
	// MaxAttempts 是低熵验证码的尝试上限；0 使用 DefaultMaxAttempts，
	// 必须在 MinMaxAttempts～MaxMaxAttempts 之间。高熵令牌比较失败不消耗
	// 尝试次数，该值只作为记录属性保留。
	MaxAttempts int
	// ReplaceActive 为 true 时先撤销同作用域的活动凭证，再写入新凭证。
	ReplaceActive bool
}

// IssuedCredential 是签发结果。Secret 明文只在本次调用返回，服务端只保存摘要；
// 调用方必须立即投递给接收方，不得写入日志或普通存储。
type IssuedCredential struct {
	ID        string
	Kind      Kind
	Purpose   string
	Target    string
	AppID     string
	ExpiresAt time.Time
	Secret    Secret
}

// VerifyRequest 是验证并消费凭证的参数。ID 是签发时返回的凭证 ID；Secret 是
// 用户提交的令牌或验证码明文，调用方不得把它写入日志。
type VerifyRequest struct {
	Kind    Kind
	ID      string
	Purpose string
	Target  string
	AppID   string
	Secret  string
}

// VerifiedCredential 是验证并成功消费后返回的可信结果。
type VerifiedCredential struct {
	ID         string
	Purpose    string
	Target     string
	AppID      string
	ConsumedAt time.Time
}

// CancelRequest 是按 ID 与绑定信息撤销活动凭证的参数。
type CancelRequest struct {
	ID      string
	Purpose string
	Target  string
	AppID   string
}

// CleanupReport 汇总一次过期清理结果。Cutoff 之前的过期凭证已被删除。
type CleanupReport struct {
	Deleted int64
	Cutoff  time.Time
}

// normalizeIssueRequest 填充默认值并校验签发参数。错误只描述字段与范围，不回显
// 用户输入内容。
func normalizeIssueRequest(request IssueRequest) (IssueRequest, error) {
	if !request.Kind.valid() {
		return IssueRequest{}, requestInvalid("凭证形态必须是 %q 或 %q", KindToken, KindCode)
	}
	if err := validateBindingField("用途", request.Purpose, maxPurposeBytes); err != nil {
		return IssueRequest{}, err
	}
	if err := validateBindingField("目标", request.Target, maxTargetBytes); err != nil {
		return IssueRequest{}, err
	}
	if err := validateOptionalAppID(request.AppID); err != nil {
		return IssueRequest{}, err
	}
	ttl, err := normalizeTTL(request.Kind, request.TTL)
	if err != nil {
		return IssueRequest{}, err
	}
	maxAttempts, err := normalizeMaxAttempts(request.MaxAttempts)
	if err != nil {
		return IssueRequest{}, err
	}
	request.TTL = ttl
	request.MaxAttempts = maxAttempts
	return request, nil
}

// validate 校验验证请求的字段格式。凭证是否存在与状态不在这里判断，避免把
// 参数错误和凭证失效混为一谈。
func (r VerifyRequest) validate() error {
	if !r.Kind.valid() {
		return requestInvalid("凭证形态必须是 %q 或 %q", KindToken, KindCode)
	}
	if err := validateCredentialID(r.ID); err != nil {
		return err
	}
	if err := validateBindingField("用途", r.Purpose, maxPurposeBytes); err != nil {
		return err
	}
	if err := validateBindingField("目标", r.Target, maxTargetBytes); err != nil {
		return err
	}
	if err := validateOptionalAppID(r.AppID); err != nil {
		return err
	}
	if r.Kind == KindToken {
		return validateTokenSecret(r.Secret)
	}
	return validateCodeSecret(r.Secret)
}

// validate 校验取消请求的字段格式。
func (r CancelRequest) validate() error {
	if err := validateCredentialID(r.ID); err != nil {
		return err
	}
	if err := validateBindingField("用途", r.Purpose, maxPurposeBytes); err != nil {
		return err
	}
	if err := validateBindingField("目标", r.Target, maxTargetBytes); err != nil {
		return err
	}
	return validateOptionalAppID(r.AppID)
}

// normalizeTTL 应用默认有效期并校验范围。
func normalizeTTL(kind Kind, ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		if kind == KindToken {
			ttl = DefaultTokenTTL
		} else {
			ttl = DefaultCodeTTL
		}
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return 0, requestInvalid("有效期必须在 %s 到 %s 之间", MinTTL, MaxTTL)
	}
	return ttl, nil
}

// normalizeMaxAttempts 应用默认尝试上限并校验范围。
func normalizeMaxAttempts(maxAttempts int) (int, error) {
	if maxAttempts == 0 {
		return DefaultMaxAttempts, nil
	}
	if maxAttempts < MinMaxAttempts || maxAttempts > MaxMaxAttempts {
		return 0, requestInvalid("尝试上限必须在 %d 到 %d 之间", MinMaxAttempts, MaxMaxAttempts)
	}
	return maxAttempts, nil
}

// validateBindingField 校验绑定字段非空、长度受限且只包含可见 ASCII 字符。
// 错误只包含字段名与规则，不回显字段值。
func validateBindingField(name, value string, max int) error {
	if value == "" {
		return requestInvalid("%s不能为空", name)
	}
	if len(value) > max {
		return requestInvalid("%s超过 %d 字节", name, max)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return requestInvalid("%s只能包含可见 ASCII 字符", name)
		}
	}
	return nil
}

// validateOptionalAppID 校验可选应用绑定：空字符串表示系统范围。
func validateOptionalAppID(appID string) error {
	if appID == "" {
		return nil
	}
	return validateBindingField("应用 ID", appID, maxAppIDBytes)
}

// validateCredentialID 校验凭证 ID 格式：固定前缀加十六进制随机串。
func validateCredentialID(id string) error {
	if len(id) != len(CredentialIDPrefix)+credentialIDHexBytes {
		return requestInvalid("凭证 ID 格式无效")
	}
	if id[:len(CredentialIDPrefix)] != CredentialIDPrefix {
		return requestInvalid("凭证 ID 格式无效")
	}
	for i := len(CredentialIDPrefix); i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return requestInvalid("凭证 ID 格式无效")
		}
	}
	return nil
}

// validateTokenSecret 校验高熵令牌输入的长度与字符范围。不要求特定字母表，
// 以避免把“格式错误”和“令牌不匹配”做成可区分响应。
func validateTokenSecret(secret string) error {
	if secret == "" || len(secret) > maxTokenInputBytes {
		return requestInvalid("令牌长度无效")
	}
	for i := 0; i < len(secret); i++ {
		if secret[i] < 0x21 || secret[i] > 0x7e {
			return requestInvalid("令牌只能包含可见 ASCII 字符")
		}
	}
	return nil
}

// validateCodeSecret 校验低熵验证码输入：只允许十进制数字，长度受限。
func validateCodeSecret(secret string) error {
	if secret == "" || len(secret) > maxCodeInputBytes {
		return requestInvalid("验证码长度无效")
	}
	for i := 0; i < len(secret); i++ {
		if secret[i] < '0' || secret[i] > '9' {
			return requestInvalid("验证码只能包含十进制数字")
		}
	}
	return nil
}

// contextJSON 返回写入 context_json 的诊断元数据；只记录形态与格式版本，不包含
// 任何凭证明文、摘要或接收方信息。
func contextJSON(kind Kind) string {
	return `{"v":1,"kind":"` + string(kind) + `"}`
}
