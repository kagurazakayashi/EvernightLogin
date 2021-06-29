// Package token 实现 OAuth/OIDC 令牌签发与验证核心、签名密钥轮换与 JWKS 公钥发布。
//
// 范围与安全不变量（对应步骤 50）：
//   - 采用成熟 JOSE 库（github.com/go-jose/go-jose/v4）完成 JWS 签名/验证，本包不
//     自行实现密码学；算法固定为 ES256（P-256/ECDSA/SHA-256），验证时以库的允许
//     算法列表强制拒绝其它 alg（含 none/HS256 等）。签名密钥为 ECDSA P-256，私钥
//     以 PKCS#8 编码后经 internal/secrets.Sealer 认证加密保存，绝不发布、打印或写入
//     审计；公钥以 JWKS 结构发布（kty/crv/kid/use/alg，无私有字段）。
//   - 密钥有 next（预发布）、active（当前签名）、retired（已退役但在保留期内仍可
//     验签）、revoked（紧急撤销）四种状态；同一时刻最多一个 active。退役保留期
//     （KeyRetention）必须覆盖已签令牌最长有效期与时钟容差，退役后验证拒绝、JWKS
//     不再发布；紧急撤销立即让该密钥签发的令牌验证失败。
//   - Access Token 采用 RFC 9068 约定：JOSE 头 typ=at+jwt，声明 iss/aud/sub/client_id/
//     scope/iat/exp/jti/token_use="access"；ID Token 使用 typ=JWT、token_use="id"、
//     aud=client_id（单一）。两者按 header typ 与 token_use 双重区分，不能互相冒用。
//   - 验证器只使用本地受控密钥集（kid 必须属于已发布且可验证集合），**不依据 token
//     头部任意请求远程密钥**：拒绝 jku/x5u/x5c/jwk/crit 等未受控密钥引用；固定校验
//     issuer、audience、类型、必需声明、有效期与可注入时钟容差。
//   - 签发入口只接受可信调用者上下文：Caller 由宿主边界构造，不能由请求参数自称；
//     普通用户只能为自己签发，系统/本地管理员代表其他主体签发必须经注入的
//     IssuanceAuthorizer 显式批准（默认缺失即拒绝，fail-closed）。客户端、Scope 与
//     目标 audience 必须来自 oauthclient 已登记配置（本包提供生产适配器）。
//   - 刷新令牌为不透明秘密，本步不实现；本包不暴露 HTTP 路由/Discovery 端点。
package token

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 领域错误哨兵。错误文本不包含令牌原文、私钥或密钥材料。
var (
	ErrOptionsInvalid      = errors.New("令牌服务选项无效")
	ErrInvalidRequest      = errors.New("令牌请求无效")
	ErrAccessDenied        = errors.New("未获准执行该令牌操作")
	ErrClientNotFound      = errors.New("OAuth 客户端不存在")
	ErrClientInactive      = errors.New("OAuth 客户端所属应用不可用")
	ErrScopeNotAllowed     = errors.New("请求的 Scope 未在客户端登记")
	ErrAudienceNotAllowed  = errors.New("请求的目标资源未在客户端登记")
	ErrGrantNotAllowed     = errors.New("客户端不支持该授权类型")
	ErrSubjectNotAllowed   = errors.New("不能为其他主体签发令牌")
	ErrRefreshNotSupported = errors.New("本版本不实现刷新令牌")
	ErrKeyUnavailable      = errors.New("签名密钥不可用")
	ErrMalformedToken      = errors.New("令牌格式无效")
	ErrWrongAlgorithm      = errors.New("令牌签名算法不被允许")
	ErrUnknownKey          = errors.New("令牌引用了未知或不可用的密钥")
	ErrMaliciousKeyRef     = errors.New("令牌包含未受控的密钥引用")
	ErrSignatureInvalid    = errors.New("令牌签名验证失败")
	ErrMissingClaims       = errors.New("令牌缺少必需声明")
	ErrWrongIssuer         = errors.New("令牌签发方不匹配")
	ErrWrongType           = errors.New("令牌类型不匹配")
	ErrAudienceMismatch    = errors.New("令牌接收方与当前资源不匹配")
	ErrTokenExpired        = errors.New("令牌已过期")
	ErrTokenNotYetValid    = errors.New("令牌尚未生效")
	ErrKeyRevoked          = errors.New("签名密钥已被撤销")
	ErrStoreUnavailable    = errors.New("令牌存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
	ErrSigningFailed       = errors.New("令牌签名失败")
)

// ErrorCode 是令牌领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid            ErrorCode = "REQ_INVALID"
	CodeAccessDenied          ErrorCode = "ACCESS_DENIED"
	CodeTokenInvalid          ErrorCode = "TOKEN_INVALID"
	CodeTokenExpired          ErrorCode = "TOKEN_EXPIRED"
	CodeTokenRevoked          ErrorCode = "TOKEN_REVOKED"
	CodeTokenAudienceMismatch ErrorCode = "TOKEN_AUDIENCE_MISMATCH"
	CodeClientDisabled        ErrorCode = "CLIENT_DISABLED"
	CodeConflict              ErrorCode = "CONFLICT"
	CodeDBUnavailable         ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed      ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把令牌领域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrClientNotFound),
		errors.Is(err, ErrScopeNotAllowed), errors.Is(err, ErrAudienceNotAllowed),
		errors.Is(err, ErrGrantNotAllowed), errors.Is(err, ErrRefreshNotSupported):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrSubjectNotAllowed):
		return CodeAccessDenied
	case errors.Is(err, ErrClientInactive):
		return CodeClientDisabled
	case errors.Is(err, ErrTokenExpired):
		return CodeTokenExpired
	case errors.Is(err, ErrAudienceMismatch):
		return CodeTokenAudienceMismatch
	case errors.Is(err, ErrKeyRevoked):
		return CodeTokenRevoked
	case errors.Is(err, ErrKeyUnavailable):
		return CodeConflict
	case errors.Is(err, ErrMalformedToken), errors.Is(err, ErrWrongAlgorithm),
		errors.Is(err, ErrUnknownKey), errors.Is(err, ErrMaliciousKeyRef),
		errors.Is(err, ErrSignatureInvalid), errors.Is(err, ErrMissingClaims),
		errors.Is(err, ErrWrongIssuer), errors.Is(err, ErrWrongType),
		errors.Is(err, ErrTokenNotYetValid):
		return CodeTokenInvalid
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor audit.Actor
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) { return newCaller(audit.ActorUser, userID) }

// SystemCaller 构造受信系统组件调用者（通常为授权码/设备码流程编排服务）。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// LocalAdminCaller 构造本地受信管理员调用者（密钥轮换/撤销等受控操作）。
func LocalAdminCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// IsTrusted 报告是否为系统/本地管理员等可信基础设施身份。
func (c Caller) IsTrusted() bool {
	return c.actor.Type == audit.ActorSystem || c.actor.Type == audit.ActorLocalAdmin
}

// GrantType 是签发 Access Token 时使用的授权类型；刷新令牌本步不实现。
type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	// GrantDeviceCode 必须与 OAuth 客户端登记的授权类型一致（RFC 8628 的 URN），
	// 否则 token 服务的 grantAllowed 与 oauthclient 登记值永远不匹配。
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantClientCredentials GrantType = "client_credentials"
)

// Valid 报告授权类型是否受支持（refresh_token 明确不支持）。
func (g GrantType) Valid() bool {
	switch g {
	case GrantAuthorizationCode, GrantDeviceCode, GrantClientCredentials:
		return true
	default:
		return false
	}
}

// UserSubject 报告该授权类型是否代表用户主体（否则为客户端服务主体）。
func (g GrantType) UserSubject() bool {
	return g == GrantAuthorizationCode || g == GrantDeviceCode
}

// KeyStatus 是签名密钥状态。
type KeyStatus string

const (
	// KeyNext 是已生成、公钥可预发布、尚未用于签名的下一把密钥。
	KeyNext KeyStatus = "next"
	// KeyActive 是当前唯一的签名密钥。
	KeyActive KeyStatus = "active"
	// KeyRetired 是已退役但在保留期内仍可验证旧令牌的密钥。
	KeyRetired KeyStatus = "retired"
	// KeyRevoked 是被紧急撤销的密钥，其签发令牌立即无效。
	KeyRevoked KeyStatus = "revoked"
)

// Valid 报告密钥状态是否已定义。
func (s KeyStatus) Valid() bool {
	switch s {
	case KeyNext, KeyActive, KeyRetired, KeyRevoked:
		return true
	default:
		return false
	}
}

// 固定允许的签名算法与密钥类型。
const (
	// AlgorithmES256 是本服务唯一签名算法（ECDSA P-256 + SHA-256）。
	AlgorithmES256 = "ES256"
	// AccessTokenType 是 Access Token 的 JOSE typ（RFC 9068）。
	AccessTokenType = "at+jwt"
	// IDTokenType 是 ID Token 的 JOSE typ（OIDC 惯用 JWT）。
	IDTokenType = "JWT"
	// TokenUseAccess / TokenUseID 是令牌用途声明，防止 Access/ID Token 混用。
	TokenUseAccess = "access"
	TokenUseID     = "id"
	// TokenSubjectTypeUser / TokenSubjectTypeService 是 Access Token 主体类型：
	// user 表示代表真实用户（授权码/设备码），service 表示应用自身服务身份
	// （client_credentials）。资源服务据此区分程序自身行为与代表用户行为。
	TokenSubjectTypeUser    = "user"
	TokenSubjectTypeService = "service"
	// KeyUseSignature 是 JWK use 值。
	KeyUseSignature = "sig"
	// keyIDPrefix 是签名密钥公开标识前缀。
	keyIDPrefix = "kid_"
	// jtiRandomBytes 是令牌唯一标识随机字节数。
	jtiRandomBytes = 16
)

// 有效期与保留期默认值与边界。
const (
	DefaultAccessTTL    = 15 * time.Minute
	MinAccessTTL        = time.Minute
	MaxAccessTTL        = 24 * time.Hour
	DefaultIDTokenTTL   = 10 * time.Minute
	MinIDTokenTTL       = time.Minute
	MaxIDTokenTTL       = time.Hour
	DefaultKeyRetention = 24 * time.Hour
	MinKeyRetention     = time.Hour
	MaxKeyRetention     = 90 * 24 * time.Hour
	DefaultClockSkew    = time.Minute
	MaxClockSkew        = 5 * time.Minute
)

// ClientInfo 是令牌服务需要的已登记客户端配置快照（来自 internal/oauthclient）。
type ClientInfo struct {
	ClientID      string
	ApplicationID string
	// ClientType 是 public/confidential。
	ClientType string
	// AppActive 表示所属应用当前是否启用。
	AppActive bool
	// GrantTypes/Scopes/Audiences 是客户端登记允许的授权类型、Scope 与目标资源。
	GrantTypes []string
	Scopes     []string
	Audiences  []string
}

// ClientSource 读取客户端登记配置；实现必须 fail-closed（不存在/存储故障返回错误）。
type ClientSource interface {
	LoadClient(ctx context.Context, clientID string) (ClientInfo, error)
}

// IssuanceRequest 是签发授权判定请求的核心内容（不含令牌内容）。
type IssuanceRequest struct {
	ClientID      string
	SubjectUserID string
	GrantType     GrantType
	Scopes        []string
	Audiences     []string
	// TokenKind 是 "access" 或 "id"（ID Token 与 Access Token 分别授权）。
	TokenKind string
}

// IssuanceAuthorizer 判定调用者是否获准在给定上下文签发令牌；未注入或拒绝时
// 签发 fail-closed。生产装配应只允许受信 OAuth 编排服务/已同意授权上下文。
type IssuanceAuthorizer interface {
	AuthorizeIssuance(ctx context.Context, caller Caller, request IssuanceRequest) error
}

// IssuanceAuthorizerFunc 是函数适配器。
type IssuanceAuthorizerFunc func(ctx context.Context, caller Caller, request IssuanceRequest) error

// AuthorizeIssuance 实现 IssuanceAuthorizer；nil 函数按拒绝处理。
func (f IssuanceAuthorizerFunc) AuthorizeIssuance(ctx context.Context, caller Caller, request IssuanceRequest) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, request)
}

// AccessClaims 是已验证通过的 Access Token 声明（不含原始令牌）。
type AccessClaims struct {
	Issuer   string
	Subject  string
	Audience []string
	ClientID string
	Scopes   []string
	TokenID  string
	TokenUse string
	// SubjectType 是 user/service；空值（旧令牌）按 user 解释。
	SubjectType string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	KeyID       string
}

// IDTokenClaims 是已验证通过的 ID Token 声明（不含原始令牌）。
type IDTokenClaims struct {
	Issuer   string
	Subject  string
	Audience string
	ClientID string
	TokenID  string
	TokenUse string
	Nonce    string
	AuthTime time.Time
	// AMR/ACR 是认证方法引用与认证上下文（来自服务端真实认证事实）。
	AMR []string
	ACR string
	// AuthorizedParty 是授权方客户端（azp）；aud 多值时必填，本流程恒为 client_id。
	AuthorizedParty string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	KeyID           string
}

// Token 是签发结果中的令牌原文。默认字符串化/格式化/JSON/slog 全部脱敏；调用方
// 必须显式 Reveal() 后交给传输层，不得写入日志、审计、URL 或普通存储。本类型不是
// 内存清零承诺，也不应当被复制到不受控位置。
type Token struct{ value string }

// NewTokenValue 把已签发/不透明令牌原文包装为默认脱敏的类型（用于刷新令牌等
// 高熵秘密在服务间传递）；调用方只应在投递时 Reveal()，不得写入日志/审计。
func NewTokenValue(value string) Token { return Token{value: value} }

// Reveal 返回令牌原文副本（只用于投递给调用方/HTTP 传输层）。
func (t Token) Reveal() string { return t.value }

// IsSet 报告令牌是否有值；不暴露内容。
func (t Token) IsSet() bool { return t.value != "" }

// String 实现 fmt.Stringer，固定输出脱敏标记。
func (t Token) String() string {
	if t.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (t Token) GoString() string { return t.String() }

// Format 实现 fmt.Formatter，覆盖 %v/%s/%q/%x 等格式化动词。
func (t Token) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(t.String()))
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + t.String() + `"`), nil }

// IssuedToken 是签发结果；Token 原文只在此返回一次，不得写入日志/审计/普通存储。
type IssuedToken struct {
	Token     Token
	TokenID   string
	KeyID     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Subject   string
	Audience  []string
}

// GenerateKeyID 生成签名密钥公开标识。
func generateKeyID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return keyIDPrefix + fmt.Sprintf("%x", buffer), nil
}

// validKeyID 校验签名密钥标识格式。
func validKeyID(kid string) bool {
	if len(kid) != len(keyIDPrefix)+32 || !strings.HasPrefix(kid, keyIDPrefix) {
		return false
	}
	for _, r := range kid[len(keyIDPrefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validateIssuer 校验固定签发方：必须是绝对 https URL（本地测试可用 http 回环），
// 不含用户信息/查询/片段/首尾空白。
func validateIssuer(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return fmt.Errorf("%w: 签发方为空或格式非法", ErrOptionsInvalid)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: 签发方必须是绝对的 http(s) 地址且不含查询/片段/用户信息", ErrOptionsInvalid)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("%w: 非回环地址的签发方必须使用 https", ErrOptionsInvalid)
	default:
		return fmt.Errorf("%w: 签发方协议只允许 https（回环地址可 http）", ErrOptionsInvalid)
	}
}

// validSubject 校验令牌主体标识（用户或客户端稳定 ID）。
func validSubject(value string) bool {
	return account.ValidUserID(value) || validApplicationClientID(value)
}

// validApplicationClientID 校验客户端/应用稳定 ID 格式（app_ + 32 位十六进制）。
func validApplicationClientID(value string) bool {
	if len(value) != 4+32 || !strings.HasPrefix(value, "app_") {
		return false
	}
	for _, r := range value[4:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// normalizeStrings 去重并保留顺序地校验字符串列表。
func normalizeStrings(values []string, max int, validator func(string) bool) ([]string, error) {
	if len(values) > max {
		return nil, fmt.Errorf("%w: 列表元素过多（上限 %d）", ErrInvalidRequest, max)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validator(value) {
			return nil, fmt.Errorf("%w: 列表元素 %q 非法", ErrInvalidRequest, value)
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

// containsAll 报告 allowed 是否包含 requested 的全部元素（都是已去重的稳定集合）。
func containsAll(allowed, requested []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	for _, value := range requested {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}
