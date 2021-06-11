// Package passkey 基于 WebAuthn 标准实现 Passkey（可发现凭证）的注册、用户名登录、
// 可发现凭证登录与凭证管理。
//
// 协议与密码学全部由 github.com/go-webauthn/webauthn 完成，本包不自行实现
// CBOR、认证器数据解析、签名或挑战校验；本包只负责：固定 RP ID 与允许来源、
// 服务端挑战与一次性消费、用户句柄、凭证元数据与唯一性、用户在场/用户验证要求、
// 同步凭证计数器语义、近期认证（再次验证）与敏感策略接入、最后登录方式保护、
// 审计与会话签发接入。
//
// 安全不变量：
//   - RP ID 与允许来源来自宿主的显式配置，绝不从请求 Host/Origin 或转发头推导；
//     配置非法（含 http 非 localhost、来源主机不属于 RP ID）一律拒绝启动。
//   - 挑战、操作类型（注册/认证）、来源、RP ID、签名、用户在场（UP）与按配置
//     要求的用户验证（UV）都由库在 Finish 阶段校验；挑战只保存在服务端，并在
//     校验前一次性原子消费，重放与并发重复提交只有一方成功。
//   - 用户句柄是 crypto/rand 生成的 32 字节随机值，与用户 ID 无关且不随更名改变；
//     注册时由服务端挑战绑定用户，忽略客户端声称的身份；凭证 ID 全表唯一，防止
//     把他人的凭证登记到自己名下。
//   - 新增/删除凭证是近期认证后的敏感操作（复用 internal/reauth 与步骤 38 策略
//     目录 passkey.register/passkey.remove）；未接线或策略不满足时 fail-closed。
//   - 同步凭证（backup eligible）的签名计数器允许不递增；非同步凭证计数器
//     不递增按可能的凭证复制（clone）严格拒绝。备份状态（BS）变化会被记录。
//   - 删除凭证前检查是否还有其他可用登录方式（其他 Passkey 或主密码），不允许
//     删除最后一个登录方式；未实现恢复代码等通道，宿主接入新通道后应扩展。
//   - 验证成功且满足 UV 策略的 Passkey 可直接完成登录：本包不追加同源第二因素，
//     会话签发通过 internal/session 完成；应用作用域的登录挑战在开始阶段绑定
//     app_id，完成阶段只能以同一 app_id 签发，不会被升级为全局会话，并通过
//     防御性复验确认结果作用域。
//
// 未实现（不宣称）：HTTP 路由与页面、真实浏览器/Windows Hello/安全密钥实测
// （测试使用模拟认证器）、FIDO2 作为第二因素、认证方式选择策略、恢复代码、
// 凭证清理任务、元数据服务（MDS）校验、attestation 证书链校验（仅接受
// attestation none 语义的常规注册结果）。
package passkey

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	// HandleBytes 是 WebAuthn 用户句柄的随机字节数（规范上限 64 字节）。
	HandleBytes = 32
	// DefaultCeremonyTTL 是注册/认证挑战默认有效期。
	DefaultCeremonyTTL = 5 * time.Minute
	// MinCeremonyTTL/MaxCeremonyTTL 是挑战有效期上下界。
	MinCeremonyTTL = 1 * time.Minute
	MaxCeremonyTTL = 15 * time.Minute
	// DefaultMaxCredentialsPerUser 是单账户默认凭证上限。
	DefaultMaxCredentialsPerUser = 10
	// MaxCredentialsPerUser 是单账户凭证上限的硬上限。
	MaxCredentialsPerUser = 50
	// MaxCredentialNameRunes 是凭证显示名最大字符数。
	MaxCredentialNameRunes = 64
	// MaxResponseBytes 是认证器响应 JSON 的字节上限。
	MaxResponseBytes = 64 * 1024
	// DefaultRPDisplayName 是未配置时的 RP 显示名。
	DefaultRPDisplayName = "EvernightLogin"
	// usageLogin 是 Passkey 作为主登录凭证的用途标记（步骤 43 第二因素另用）。
	usageLogin = "login"
)

// UserVerification 是登录/注册挑战要求的用户验证（UV）策略。
type UserVerification string

const (
	// UserVerificationRequired 要求认证器完成用户验证（生物识别/PIN）；默认值。
	UserVerificationRequired UserVerification = "required"
	// UserVerificationPreferred 优先 UV 但不强制（较弱，宿主显式选择）。
	UserVerificationPreferred UserVerification = "preferred"
	// UserVerificationDiscouraged 不要求 UV（仅用于极弱场景，通常不应使用）。
	UserVerificationDiscouraged UserVerification = "discouraged"
)

// Valid 报告 UV 策略是否已定义。
func (v UserVerification) Valid() bool {
	switch v {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

// protocolValue 返回库对应的 UV 要求。
func (v UserVerification) protocolValue() protocol.UserVerificationRequirement {
	switch v {
	case UserVerificationPreferred:
		return protocol.VerificationPreferred
	case UserVerificationDiscouraged:
		return protocol.VerificationDiscouraged
	default:
		return protocol.VerificationRequired
	}
}

// Config 是 Passkey 的依赖方（RP）配置。RPID 与允许来源必须由宿主显式给出，
// 不允许从请求推导；修改后需要重启服务。
type Config struct {
	// RPID 是 WebAuthn Relying Party ID，通常是可注册域名（如 example.com）。
	// 不能是 IP 地址、不能带协议/端口/路径；Passkey 不跨 RP ID 通用。
	RPID string
	// RPDisplayName 是浏览器展示的依赖方名称；空时使用 DefaultRPDisplayName。
	RPDisplayName string
	// Origins 是允许的浏览器来源完整列表（scheme://host[:port]），至少一个；
	// 只接受 https，或显式用于本地开发的 http://localhost。
	Origins []string
	// UserVerification 是注册与登录要求的 UV 策略；空时默认 required。
	UserVerification UserVerification
	// CeremonyTTL 是挑战有效期；0 使用 DefaultCeremonyTTL。
	CeremonyTTL time.Duration
	// MaxCredentialsPerUser 是单账户凭证数量上限；0 使用默认值。
	MaxCredentialsPerUser int
}

// validated 校验并填充默认值；返回不可变的规范化配置。
func (c Config) validated() (Config, error) {
	if c.RPDisplayName == "" {
		c.RPDisplayName = DefaultRPDisplayName
	}
	if err := ValidateRPConfig(c.RPID, c.Origins); err != nil {
		return Config{}, err
	}
	if c.UserVerification == "" {
		c.UserVerification = UserVerificationRequired
	}
	if !c.UserVerification.Valid() {
		return Config{}, fmt.Errorf("%w: 用户验证策略必须是 required/preferred/discouraged", ErrOptionsInvalid)
	}
	if c.CeremonyTTL == 0 {
		c.CeremonyTTL = DefaultCeremonyTTL
	}
	if c.CeremonyTTL < MinCeremonyTTL || c.CeremonyTTL > MaxCeremonyTTL {
		return Config{}, fmt.Errorf("%w: 挑战有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinCeremonyTTL, MaxCeremonyTTL)
	}
	if c.MaxCredentialsPerUser == 0 {
		c.MaxCredentialsPerUser = DefaultMaxCredentialsPerUser
	}
	if c.MaxCredentialsPerUser < 1 || c.MaxCredentialsPerUser > MaxCredentialsPerUser {
		return Config{}, fmt.Errorf("%w: 单账户凭证上限必须在 1～%d 之间",
			ErrOptionsInvalid, MaxCredentialsPerUser)
	}
	return c, nil
}

// ValidateRPConfig 校验 RP ID 与允许来源（根配置与宿主可直接复用）。
//
// 规则：RP ID 必须是可注册域名字符串（库的 ValidateRPID，拒绝 IP 与协议/路径）；
// 至少一个来源；来源必须是绝对 URL、无凭证/查询/片段、路径为空或 /；scheme
// 必须是 https，或主机恰为 localhost 的 http（浏览器对 localhost 的安全上下文
// 例外）；来源主机必须等于 RP ID 或是其子域，避免同一 RP ID 接受无关站点。
func ValidateRPConfig(rpID string, origins []string) error {
	if strings.TrimSpace(rpID) == "" {
		return fmt.Errorf("%w: RP ID 为空", ErrOptionsInvalid)
	}
	if rpID != strings.TrimSpace(rpID) || strings.ContainsAny(rpID, "/: @?#") {
		return fmt.Errorf("%w: RP ID 必须是裸域名字符串，不能包含协议/端口/路径", ErrOptionsInvalid)
	}
	if err := protocol.ValidateRPID(rpID); err != nil {
		return fmt.Errorf("%w: RP ID 不是合法域名: %v", ErrOptionsInvalid, err)
	}
	if len(origins) == 0 {
		return fmt.Errorf("%w: 至少需要一个允许来源", ErrOptionsInvalid)
	}
	for index, raw := range origins {
		if strings.TrimSpace(raw) == "" || raw != strings.TrimSpace(raw) {
			return fmt.Errorf("%w: 第 %d 个允许来源为空或含空白", ErrOptionsInvalid, index+1)
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("%w: 第 %d 个允许来源不是绝对 URL", ErrOptionsInvalid, index+1)
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: 允许来源不能包含用户信息", ErrOptionsInvalid)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%w: 允许来源不能包含查询或片段", ErrOptionsInvalid)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return fmt.Errorf("%w: 允许来源不能包含路径", ErrOptionsInvalid)
		}
		host := strings.ToLower(parsed.Hostname())
		switch {
		case parsed.Scheme == "https":
		case parsed.Scheme == "http" && host == "localhost":
			// 本地开发例外：浏览器把 localhost 视作安全上下文。
		default:
			return fmt.Errorf("%w: 允许来源必须使用 https（本地开发只允许 http://localhost）", ErrOptionsInvalid)
		}
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("%w: 允许来源主机必须是 RP ID 或其子域", ErrOptionsInvalid)
		}
	}
	return nil
}

// 领域错误哨兵。错误文本不包含挑战、凭证 ID、公钥、签名或会话秘密。
var (
	ErrOptionsInvalid       = errors.New("Passkey 服务选项无效")
	ErrInvalidRequest       = errors.New("Passkey 请求无效")
	ErrAccessDenied         = errors.New("未获准执行该 Passkey 操作")
	ErrReauthRequired       = errors.New("Passkey 操作需要近期身份验证")
	ErrMFARequired          = errors.New("当前策略要求强认证")
	ErrAuthenticationFailed = errors.New("Passkey 认证失败")
	ErrCeremonyInvalid      = errors.New("Passkey 挑战无效")
	ErrCeremonyExpired      = errors.New("Passkey 挑战已过期")
	ErrCredentialNotFound   = errors.New("未找到 Passkey 凭证")
	ErrCredentialConflict   = errors.New("该 Passkey 凭证已存在")
	ErrCredentialLimit      = errors.New("Passkey 凭证数量已达上限")
	ErrCloneDetected        = errors.New("Passkey 凭证可能已被复制")
	ErrLastLoginMethod      = errors.New("不能删除最后一个可用登录方式")
	ErrSessionUnavailable   = errors.New("会话签发暂时不可用")
	ErrStoreUnavailable     = errors.New("Passkey 存储暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
	ErrInternal             = errors.New("Passkey 内部错误")
)

// ErrorCode 是 Passkey 领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired      ErrorCode = "MFA_REQUIRED"
	CodeAuthFailed       ErrorCode = "AUTH_FAILED"
	CodeChallengeInvalid ErrorCode = "CHALLENGE_INVALID"
	CodeRateLimited      ErrorCode = "RATE_LIMITED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 Passkey 领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrCredentialNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrAuthenticationFailed), errors.Is(err, ErrCloneDetected):
		return CodeAuthFailed
	case errors.Is(err, ErrCeremonyInvalid), errors.Is(err, ErrCeremonyExpired):
		return CodeChallengeInvalid
	case errors.Is(err, ErrCredentialConflict), errors.Is(err, ErrCredentialLimit),
		errors.Is(err, ErrLastLoginMethod):
		return CodeConflict
	case errors.Is(err, ErrSessionUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。本包只接受普通用户身份。
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

// Operation 是挑战绑定的操作类型；注册挑战不能用于认证，反之亦然。
type Operation string

const (
	// OperationRegistration 是注册（credential create）操作。
	OperationRegistration Operation = "registration"
	// OperationAuthentication 是登录（credential get）操作。
	OperationAuthentication Operation = "authentication"
)

// Valid 报告操作类型是否已定义。
func (o Operation) Valid() bool {
	return o == OperationRegistration || o == OperationAuthentication
}

// UserState 是 Passkey 登录/注册所需的账户快照（来自 users 表，只读）。
type UserState struct {
	UserID          string
	Username        string
	Status          string
	IsRoot          bool
	SecurityVersion int64
	// Handle 是该用户的 WebAuthn 用户句柄；首次注册前可能为空。
	Handle []byte
}

// Active 报告账户是否可用于 Passkey 登录（仅 active）。
func (u UserState) Active() bool { return u.Status == "active" }

// Credential 是一条 Passkey 凭证的服务端记录。PublicKey 是 COSE 公钥字节，
// 不是秘密；任何对外结构都不得返回完整记录。
type Credential struct {
	ID             string
	UserID         string
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         []byte
	RPID           string
	Name           string
	SignCount      uint32
	Transports     []string
	BackupEligible bool
	BackedUp       bool
	UserPresent    bool
	UserVerified   bool
	Attachment     string
	Usage          string
	Version        int64
	LastUsedAt     time.Time
	RevokedAt      time.Time
	RevokedReason  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// CredentialMetadata 是返回给用户的凭证元数据（不含公钥等协议细节）。
type CredentialMetadata struct {
	ID             string
	Name           string
	BackupEligible bool
	BackedUp       bool
	Transports     []string
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// Ceremony 是一条服务端挑战记录。
type Ceremony struct {
	ID          string
	UserID      string // 为空表示可发现凭证登录尚未确定用户
	Operation   Operation
	Challenge   string
	RPID        string
	SessionData []byte
	AppID       string
	RememberMe  bool
	UserAgent   string
	Address     string
	RequestID   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  time.Time
}

// SessionIssuer 是会话签发契约；生产实现为 *internal/session.Service。
type SessionIssuer interface {
	Login(ctx context.Context, request session.LoginRequest) (session.IssuedSession, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// CompletedAuthentication 把一次真实验证完成的 Passkey 认证转换为 authn 认证结果。
// 会话服务要求 SecurityVersion 与账户当前值一致；本包在认证完成时重新读取用户状态。
func completedAuthentication(state UserState, at time.Time) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID:           state.UserID,
		Username:         state.Username,
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPasskey},
		CompletedAt:      at,
		Restricted:       false,
		SecurityVersion:  state.SecurityVersion,
	}
}
