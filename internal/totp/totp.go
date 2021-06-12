// Package totp 实现标准 TOTP（RFC 6238）绑定的种子加密保存、首次确认、登录验证
// 与安全解除。
//
// 兼容性：使用 HMAC-SHA1、Base32 种子与标准 otpauth://totp/... 导入 URI，可被
// Google Authenticator/Authy 等常见验证器导入；二维码数据只提供 URI 字符串，不做
// 二维码 UI。注意：RFC 测试向量与协议实现通过不等于真实设备/验证器实测，宿主
// 接入页面时仍需用真实验证器人工验收。
//
// 安全不变量：
//   - 种子由 crypto/rand 生成（20 字节）；由 internal/secrets.Sealer 认证加密后保存，
//     绑定用途 mfa.totp、对象为绑定 ID、范围 system；明文种子/URI 只出现在绑定开始
//     响应的必要字段中，绝不写入日志、审计、普通查询或导出；查询只返回元数据。
//   - 装配约束：BeginBinding 只能从完整（非受限）已认证会话调用；高权限账户的
//     绑定/更换强因素必须在完成强认证后进行。服务层不额外判断会话是否受限，宿主
//     必须拒绝把待第二因素/受限会话接到绑定入口，否则会退化为主密码即可绑定因素。
//   - 绑定状态区分 pending（绑定中，等待验证码确认）与 active（已激活）。重绑时
//     先创建并验证新绑定，再在同一审计事务内替换旧 active，不会先删后绑导致失去
//     因素。首次绑定入口要求步骤 39/40 的近期认证/敏感策略（注入 Reauth）。
//   - 服务端使用自身时钟（可注入以便测试，生产默认 time.Now）；时间步长与窗口
//     有界（period 15～60 秒、窗口 0～3 步、位数 6～8）。登录验证记录并原子推进
//     last_accepted_step，只接受严格更大的时间步，同一步并发/重放只有一方成功。
//   - 解除绑定必须先验证当前 TOTP 验证码（证明持有），再检查宿主 Policy 强制 MFA：
//     当前只有 TOTP 是强第二因素，强制 MFA 下拒绝移除，避免移除最后一个可用因素；
//     后续 Passkey/FIDO2 接入后按“其他强因素数量”判断。
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// SecretBytes 是随机种子长度（RFC 4226/6238 建议 SHA1 至少 160 位）。
	SecretBytes = 20
	// DefaultPeriodSeconds 是默认时间步长。
	DefaultPeriodSeconds = 30
	// MinPeriodSeconds/MaxPeriodSeconds 是允许配置的时间步长边界。
	MinPeriodSeconds = 15
	MaxPeriodSeconds = 60
	// DefaultDigits 是默认验证码位数。
	DefaultDigits = 6
	// MinDigits/MaxDigits 是允许的验证码位数。
	MinDigits = 6
	MaxDigits = 8
	// DefaultWindowSteps 是默认允许的时钟偏移步数（前后各 1 步）。
	DefaultWindowSteps = 1
	// MaxWindowSteps 是允许的最大偏移步数。
	MaxWindowSteps = 3
	// DefaultBindingTTL 是绑定中状态默认有效期。
	DefaultBindingTTL = 10 * time.Minute
	// MinBindingTTL/MaxBindingTTL 是绑定中有效期边界。
	MinBindingTTL = 5 * time.Minute
	MaxBindingTTL = 15 * time.Minute
	// DefaultMaxAttempts 是绑定确认允许的错误尝试上限。
	DefaultMaxAttempts = 5
	// MaxPendingBindings 是同一用户允许同时存在的绑定中记录上限。
	MaxPendingBindings = 2
)

// 领域错误哨兵。错误文本不包含种子或验证码。
var (
	ErrOptionsInvalid    = errors.New("TOTP 服务选项无效")
	ErrInvalidRequest    = errors.New("TOTP 请求无效")
	ErrAccessDenied      = errors.New("未获准执行该 TOTP 操作")
	ErrReauthRequired    = errors.New("TOTP 绑定需要近期身份验证")
	ErrMFARequired       = errors.New("当前不能移除最后一个强因素")
	ErrBindingNotFound   = errors.New("未找到 TOTP 绑定")
	ErrBindingExpired    = errors.New("TOTP 绑定已过期")
	ErrCodeInvalid       = errors.New("TOTP 验证码无效")
	ErrAttemptsExceeded  = errors.New("TOTP 绑定尝试次数已用尽")
	ErrReplay            = errors.New("该时间步验证码已被使用")
	ErrFactorRequired    = errors.New("强制 MFA 策略下不能移除最后一个强因素")
	ErrRateLimited       = errors.New("TOTP 请求过于频繁")
	ErrSealFailed        = errors.New("TOTP 种子加密不可用")
	ErrPolicyUnavailable = errors.New("TOTP 策略检查暂时不可用")
	ErrStoreUnavailable  = errors.New("TOTP 存储暂时不可用")
	ErrAuditUnavailable  = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是 TOTP 领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired      ErrorCode = "MFA_REQUIRED"
	CodeChallengeInvalid ErrorCode = "CHALLENGE_INVALID"
	CodeRateLimited      ErrorCode = "RATE_LIMITED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeAuthzUnavailable ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 TOTP 领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrBindingNotFound),
		errors.Is(err, ErrBindingExpired):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired), errors.Is(err, ErrFactorRequired):
		return CodeMFARequired
	case errors.Is(err, ErrCodeInvalid), errors.Is(err, ErrReplay),
		errors.Is(err, ErrAttemptsExceeded):
		return CodeChallengeInvalid
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrPolicyUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrSealFailed):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// SessionInvalidator 在解除强因素（TOTP）后撤销该用户既有会话；生产实现为
// *internal/session.Service。即使未注入，解除绑定也会在同一审计事务内递增
// security_version 让既有会话失效。nil 表示未接线（仍会递增安全版本）。
type SessionInvalidator interface {
	RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error)
}

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor audit.Actor
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// Algorithm 是 TOTP 哈希算法；第一版只支持 SHA1（常见验证器默认）。
type Algorithm string

const (
	// AlgorithmSHA1 是 RFC 6238 常见默认算法。
	AlgorithmSHA1 Algorithm = "SHA1"
)

// Binding 是 TOTP 绑定快照；SealedSecret 只在包内/存储层使用，对外查询不返回。
type Binding struct {
	ID               string
	UserID           string
	Status           string
	Algorithm        Algorithm
	Digits           int
	PeriodSeconds    int
	WindowSteps      int
	LastAcceptedStep int64
	Attempts         int
	MaxAttempts      int
	ExpiresAt        time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ActivatedAt      time.Time
	sealedSecret     []byte
}

// SealedSecret 返回加密种子信封（仅供存储层读写，不对外查询）。
func (b Binding) SealedSecret() []byte { return b.sealedSecret }

// SetSealedSecret 设置加密种子信封（仅供存储层反序列化）。
func (b *Binding) SetSealedSecret(sealed []byte) { b.sealedSecret = sealed }

// GenerateSecret 生成随机 TOTP 种子。
func GenerateSecret(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, SecretBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return nil, fmt.Errorf("%w: 安全随机源不可用", ErrSealFailed)
	}
	return buffer, nil
}

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSecret 把种子编码为验证器使用的 Base32（无填充、大写）。
func EncodeSecret(secret []byte) string {
	return base32NoPadding.EncodeToString(secret)
}

// DecodeSecret 解码导入 URI 的 Base32 种子。
func DecodeSecret(encoded string) ([]byte, error) {
	value := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(encoded), " ", ""))
	value = strings.TrimRight(value, "=")
	secret, err := base32NoPadding.DecodeString(value)
	if err != nil || len(secret) < 10 {
		return nil, fmt.Errorf("%w: TOTP 种子格式无效", ErrInvalidRequest)
	}
	return secret, nil
}

// BuildURI 生成标准 otpauth://totp 导入 URI（二维码只提供该字符串）。
func BuildURI(secret []byte, issuer, account string, periodSeconds, digits int) (string, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(account) == "" {
		return "", fmt.Errorf("%w: 签发者与账户名不能为空", ErrInvalidRequest)
	}
	if periodSeconds < MinPeriodSeconds || periodSeconds > MaxPeriodSeconds {
		return "", fmt.Errorf("%w: 时间步长非法", ErrInvalidRequest)
	}
	if digits < MinDigits || digits > MaxDigits {
		return "", fmt.Errorf("%w: 验证码位数非法", ErrInvalidRequest)
	}
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{}
	query.Set("secret", EncodeSecret(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", string(AlgorithmSHA1))
	query.Set("digits", strconv.Itoa(digits))
	query.Set("period", strconv.Itoa(periodSeconds))
	return "otpauth://totp/" + label + "?" + query.Encode(), nil
}

// GenerateCode 按 RFC 6238 计算指定时间所在时间步的验证码，并返回该时间步。
// 只用于服务端验证、测试与隔离示例；调用方不得把种子写入日志。
func GenerateCode(secret []byte, at time.Time, periodSeconds, digits int) (string, int64, error) {
	if len(secret) < 10 {
		return "", 0, fmt.Errorf("%w: 种子长度不足", ErrOptionsInvalid)
	}
	if periodSeconds < MinPeriodSeconds || periodSeconds > MaxPeriodSeconds || digits < MinDigits || digits > MaxDigits {
		return "", 0, fmt.Errorf("%w: TOTP 参数非法", ErrOptionsInvalid)
	}
	step := at.UTC().Unix() / int64(periodSeconds)
	return codeForStep(secret, step, digits), step, nil
}

// codeForStep 计算单个时间步的验证码。
func codeForStep(secret []byte, step int64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for index := 0; index < digits; index++ {
		modulus *= 10
	}
	code := value % modulus
	return fmt.Sprintf("%0*d", digits, code)
}

// VerifyCode 是供测试与隔离示例使用的校验函数：在 at 前后 window 步内查找匹配
// 验证码并返回时间步；它不读写数据库、不推进防重放状态。
func VerifyCode(secret []byte, code string, at time.Time, periodSeconds, digits, windowSteps int) (int64, bool) {
	if len(secret) < 10 || periodSeconds < MinPeriodSeconds || periodSeconds > MaxPeriodSeconds ||
		digits < MinDigits || digits > MaxDigits || windowSteps < 0 || windowSteps > MaxWindowSteps {
		return 0, false
	}
	return verifyWindow(secret, code, at, periodSeconds, windowSteps, digits)
}

// verifyWindow 在 now 前后 window 步内查找匹配的验证码，返回匹配到的时间步。
// 使用常量时间比较；优先返回最大的匹配步，减少同一步被并发重复利用的机会。
func verifyWindow(secret []byte, code string, now time.Time, periodSeconds, windowSteps, digits int) (int64, bool) {
	if len(code) != digits {
		return 0, false
	}
	center := now.UTC().Unix() / int64(periodSeconds)
	for offset := int64(windowSteps); offset >= -int64(windowSteps); offset-- {
		step := center + offset
		candidate := codeForStep(secret, step, digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
