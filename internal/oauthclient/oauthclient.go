// Package oauthclient 实现应用作为 OAuth 客户端所需的安全设置登记、回调规则与
// 客户端身份验证（步骤 49），把应用展示资料（internal/app）与可信托管配置分开。
//
// 安全不变量：
//   - 每个应用最多一个客户端配置，client_id = 应用稳定 ID；客户端类型必须与
//     applications.client_type 一致，创建后不可通过资料更新改变。
//   - 公开客户端（public）没有 secret/证书，令牌端点身份验证方式为空，强制 PKCE，
//     且不能使用 client_credentials；保密客户端（confidential）必须配置至少一种
//     身份验证方式（client_secret_basic / client_secret_post / tls_client_auth）。
//     公开客户端不得用打包密钥假装保密。明确拒绝 password/implicit 授权类型。
//   - 回调地址精确匹配（区分大小写、百分号编码、路径与查询串；禁止片段、通配符、
//     userinfo、开放重定向与子域包含）。“精确”是字节级相等；唯一例外是 RFC 8252
//     原生应用的回环地址动态端口（http://127.0.0.1 或 http://[::1]，仅忽略端口，
//     路径/查询仍精确），自定义 scheme 仅允许公开客户端且不参与 http(s) 规则。
//   - 客户端密钥明文只在登记/轮换响应出现一次，库中只保存前缀与 32 字节 SHA-256
//     摘要；列表只返回 ID/前缀/时间，不返回明文或摘要。密钥支持到期、撤销与轮换
//     过渡期（新密钥立即可用，旧密钥在退休时间前仍可用，超出即拒绝）。
//   - 客户端证书身份只保存公钥证书与 SHA-256 指纹，不保存私钥；验证时要求证书
//     当前有效期、指纹与某个未撤销的登记证书精确一致。证书链信任由 TLS 层负责，
//     本包只回答“呈现的客户端证书是否为该客户端登记的身份”。
//   - 安全设置的登记/变更/凭证轮换/撤销都要求当前管理权限（Authorizer）与步骤
//     38/39 敏感操作再次验证（reauth），并写审计；拒绝路径写失败审计。客户端
//     身份验证成功/失败也写审计，但不代表该客户端的任意用户已认证。
//   - 本包不实现授权端点、令牌签发、动态客户端注册、第三方登录或页面；只有具备
//     管理权限的受信调用者能登记或修改客户端配置。
package oauthclient

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 领域错误哨兵。错误文本不包含 secret、摘要、证书私钥或未授权细节。
var (
	ErrOptionsInvalid        = errors.New("OAuth 客户端服务选项无效")
	ErrInvalidRequest        = errors.New("OAuth 客户端请求无效")
	ErrAccessDenied          = errors.New("未获准管理该 OAuth 客户端")
	ErrClientNotFound        = errors.New("OAuth 客户端未登记")
	ErrClientDisabled        = errors.New("应用已停用，客户端不可用")
	ErrClientAuthFailed      = errors.New("客户端身份验证失败")
	ErrClientTypeMismatch    = errors.New("客户端类型与应用登记不一致")
	ErrInvalidConfiguration  = errors.New("OAuth 客户端安全设置组合非法")
	ErrUnsupportedGrantType  = errors.New("不支持该授权类型")
	ErrUnsupportedAuthMethod = errors.New("不支持该客户端身份验证方式")
	ErrRedirectMismatch      = errors.New("回调地址与登记不一致")
	ErrVersionConflict       = errors.New("OAuth 客户端配置已被其他操作修改")
	ErrCredentialConflict    = errors.New("客户端凭证状态冲突")
	ErrLastCredential        = errors.New("不能撤销最后一个可用客户端凭证")
	ErrReauthRequired        = errors.New("需要完成近期身份验证")
	ErrMFARequired           = errors.New("需要完成两步验证")
	ErrAuthzUnavailable      = errors.New("暂时无法判定客户端管理权限")
	ErrStoreUnavailable      = errors.New("OAuth 客户端存储暂时不可用")
	ErrAuditUnavailable      = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是 OAuth 客户端领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeClientAuthFailed ErrorCode = "CLIENT_AUTH_FAILED"
	CodeClientDisabled   ErrorCode = "CLIENT_DISABLED"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired      ErrorCode = "MFA_REQUIRED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeAuthzUnavailable ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 OAuth 客户端领域错误映射为已登记错误码；未知错误统一内部错误。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrClientTypeMismatch),
		errors.Is(err, ErrInvalidConfiguration), errors.Is(err, ErrUnsupportedGrantType),
		errors.Is(err, ErrUnsupportedAuthMethod), errors.Is(err, ErrRedirectMismatch),
		errors.Is(err, ErrClientNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrClientAuthFailed):
		return CodeClientAuthFailed
	case errors.Is(err, ErrClientDisabled):
		return CodeClientDisabled
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrCredentialConflict),
		errors.Is(err, ErrLastCredential):
		return CodeConflict
	case errors.Is(err, ErrAuthzUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// PermissionKey 常量与 internal/preset 目录一致；新增权限时同步复查。
const (
	// PermissionApplicationsUpdate 修改应用资料/安全设置。
	PermissionApplicationsUpdate = "applications.update"
	// PermissionCredentialsManage 轮换或撤销应用凭证。
	PermissionCredentialsManage = "applications.credentials.manage"
)

// 敏感操作目录标识；新增时同步 internal/policy 目录。
const (
	OperationClientRegister       = "oauth.client.register"
	OperationClientSettingsChange = "oauth.client.settings.change"
	OperationCredentialRotate     = "application.credential.rotate"
)

// 审计动作。
const (
	ActionClientRegistered      = "oauth.client.registered"
	ActionClientSettingsChanged = "oauth.client.settings_changed"
	ActionSecretRotated         = "oauth.client.secret_rotated"
	ActionSecretRevoked         = "oauth.client.secret_revoked"
	ActionCertificateRegistered = "oauth.client.certificate_registered"
	ActionCertificateRevoked    = "oauth.client.certificate_revoked"
	ActionClientAuthenticated   = "oauth.client.authenticated"
	ActionClientDenied          = "oauth.client.denied"
)

// ClientType 区分公开客户端与保密客户端。
type ClientType string

const (
	// ClientTypePublic 是公开客户端（浏览器/桌面/移动）：没有 secret，强制 PKCE。
	ClientTypePublic ClientType = "public"
	// ClientTypeConfidential 是保密客户端（服务端）：必须配置一种身份验证方式。
	ClientTypeConfidential ClientType = "confidential"
)

// Valid 报告客户端类型是否已定义。
func (c ClientType) Valid() bool {
	return c == ClientTypePublic || c == ClientTypeConfidential
}

// GrantType 是允许登记的 OAuth 授权类型。
type GrantType string

const (
	// GrantAuthorizationCode 是授权码模式（配合 PKCE）。
	GrantAuthorizationCode GrantType = "authorization_code"
	// GrantRefreshToken 是刷新令牌（依赖授权码或设备码）。
	GrantRefreshToken GrantType = "refresh_token"
	// GrantClientCredentials 是客户端凭证模式（仅保密客户端）。
	GrantClientCredentials GrantType = "client_credentials"
	// GrantDeviceCode 是设备授权模式。
	GrantDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// ParseGrantType 解析授权类型；password/implicit 明确不支持。
func ParseGrantType(raw string) (GrantType, error) {
	switch GrantType(strings.TrimSpace(raw)) {
	case GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantDeviceCode:
		return GrantType(strings.TrimSpace(raw)), nil
	case "password", "implicit":
		return "", fmt.Errorf("%w: 不支持 password/implicit 授权", ErrUnsupportedGrantType)
	default:
		return "", fmt.Errorf("%w: 未知授权类型", ErrUnsupportedGrantType)
	}
}

// AuthMethod 是令牌端点客户端身份验证方式。
type AuthMethod string

const (
	// AuthMethodSecretBasic 使用 HTTP Basic 提交客户端密钥。
	AuthMethodSecretBasic AuthMethod = "client_secret_basic"
	// AuthMethodSecretPost 使用表单提交客户端密钥。
	AuthMethodSecretPost AuthMethod = "client_secret_post"
	// AuthMethodTLSClientAuth 使用 TLS 客户端证书身份（mTLS）。
	AuthMethodTLSClientAuth AuthMethod = "tls_client_auth"
)

// ParseAuthMethod 解析身份验证方式；公开客户端不接受任何身份验证方式。
func ParseAuthMethod(raw string) (AuthMethod, error) {
	switch AuthMethod(strings.TrimSpace(raw)) {
	case AuthMethodSecretBasic, AuthMethodSecretPost, AuthMethodTLSClientAuth:
		return AuthMethod(strings.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("%w: 未知客户端身份验证方式", ErrUnsupportedAuthMethod)
	}
}

// IsSecretMethod 报告是否为基于客户端密钥的身份验证方式。
func (a AuthMethod) IsSecretMethod() bool {
	return a == AuthMethodSecretBasic || a == AuthMethodSecretPost
}

// 长度与数量边界。
const (
	// MaxClientIDBytes 是 client_id（应用 ID）长度上限。
	MaxClientIDBytes = 128
	// MaxGrantTypes 是授权类型数量上限。
	MaxGrantTypes = 8
	// MaxRedirectURIs 是回调地址数量上限。
	MaxRedirectURIs = 20
	// MaxPostLogoutRedirectURIs 是退出回调数量上限。
	MaxPostLogoutRedirectURIs = 20
	// MaxScopes 是登记 Scope 数量上限。
	MaxScopes = 50
	// MaxAudiences 是允许目标资源数量上限。
	MaxAudiences = 20
	// MaxAuthMethods 是身份验证方式数量上限。
	MaxAuthMethods = 3
	// MaxRedirectURIBytes 是单个回调地址长度上限。
	MaxRedirectURIBytes = 2048
	// MaxScopeTokenBytes 是单个 Scope 长度上限。
	MaxScopeTokenBytes = 128
	// MaxAudienceBytes 是单个目标资源标识长度上限。
	MaxAudienceBytes = 256
)

// 客户端密钥有效期与轮换过渡期默认值与边界。
const (
	// DefaultSecretTTL 是客户端密钥默认有效期（180 天）。
	DefaultSecretTTL = 180 * 24 * time.Hour
	// MinSecretTTL/MaxSecretTTL 是密钥有效期边界。
	MinSecretTTL = 24 * time.Hour
	MaxSecretTTL = 5 * 365 * 24 * time.Hour
	// DefaultRotationGracePeriod 是轮换后旧密钥默认仍可用的过渡期（24 小时）。
	DefaultRotationGracePeriod = 24 * time.Hour
	// MinRotationGracePeriod/MaxRotationGracePeriod 是过渡期边界。
	MinRotationGracePeriod = time.Minute
	MaxRotationGracePeriod = 30 * 24 * time.Hour
)

// 凭证与证书数量边界。
const (
	// MaxActiveClientSecrets 是同一客户端同时可用的密钥上限（轮换过渡期用）。
	MaxActiveClientSecrets = 5
	// MaxActiveClientCertificates 是同一客户端同时可用的证书上限。
	MaxActiveClientCertificates = 5
	// MaxCertificatePEMBytes 是登记证书 PEM 大小上限。
	MaxCertificatePEMBytes = 16 * 1024
)

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// UserCaller 构造已认证管理用户调用者。
func UserCaller(userID string) (Caller, error) {
	return newCaller(audit.ActorUser, userID)
}

// SystemCaller 构造受信系统组件调用者。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// LocalAdminCaller 构造本地受信管理员调用者。
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

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// Client 是 OAuth 客户端安全设置的脱敏视图（不含任何凭证材料）。
type Client struct {
	ClientID               string
	ClientType             ClientType
	GrantTypes             []GrantType
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	AuthMethods            []AuthMethod
	RequirePKCE            bool
	RowVersion             int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// ClientSecretInfo 是客户端密钥的展示信息；不包含明文或摘要。
type ClientSecretInfo struct {
	ID        string
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RetireAt  time.Time
	RevokedAt time.Time
}

// RevealedClientSecret 是只在登记/轮换响应出现一次的密钥明文。
type RevealedClientSecret struct {
	Info ClientSecretInfo
	// Secret 是明文客户端密钥；调用方必须立即安全保存，服务端不再返回。
	Secret string
}

// ClientCertificateInfo 是客户端证书身份的展示信息（证书本身是公开材料）。
type ClientCertificateInfo struct {
	ID                string
	FingerprintSHA256 string
	Subject           string
	NotBefore         time.Time
	NotAfter          time.Time
	CreatedAt         time.Time
	RevokedAt         time.Time
}

// ClientIdentity 是客户端身份验证成功后的可信身份；不代表该客户端的用户已认证。
type ClientIdentity struct {
	ClientID   string
	ClientType ClientType
	AuthMethod AuthMethod
}

// AppSnapshot 是验证客户端时读取的应用状态快照。
type AppSnapshot struct {
	ApplicationID string
	ClientType    ClientType
	Status        string
}

// ClientRecord 是持久化的客户端配置。
type ClientRecord struct {
	Client
	AppStatus string
}

// SecretRecord 是持久化的客户端密钥验证记录（摘要只在存储内部使用）。
type SecretRecord struct {
	ID        string
	ClientID  string
	Prefix    string
	Digest    [32]byte
	CreatedAt time.Time
	ExpiresAt time.Time
	RetireAt  time.Time
	RevokedAt time.Time
}

// CertificateRecord 是持久化的客户端证书身份。
type CertificateRecord struct {
	ID                string
	ClientID          string
	FingerprintSHA256 [32]byte
	Subject           string
	NotBefore         time.Time
	NotAfter          time.Time
	CertificatePEM    string
	CreatedAt         time.Time
	RevokedAt         time.Time
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Store 是 OAuth 客户端配置与凭证的持久化契约，由 internal/oauthclient/sqlite 实现。
type Store interface {
	// LookupApplication 读取应用类型与状态；不存在返回 false。
	LookupApplication(ctx context.Context, applicationID string) (AppSnapshot, bool, error)
	// GetClient 读取客户端配置（含应用状态）；未登记返回 false。
	GetClient(ctx context.Context, clientID string) (ClientRecord, bool, error)
	// CreateClientTx 在审计事务内创建客户端配置与初始凭证。
	CreateClientTx(ctx context.Context, tx audit.Tx, record ClientRecord, secret *SecretRecord, certificate *CertificateRecord) error
	// UpdateClientTx 按行版本条件更新安全设置；返回是否成功。
	UpdateClientTx(ctx context.Context, tx audit.Tx, update ClientUpdate) (bool, error)
	// ListSecrets 列出客户端全部密钥记录（只用于验证与展示，不含明文）。
	ListSecrets(ctx context.Context, clientID string) ([]SecretRecord, error)
	// InsertSecretTx 在审计事务内插入新密钥。
	InsertSecretTx(ctx context.Context, tx audit.Tx, record SecretRecord) error
	// RetireActiveSecretsTx 把客户端当前可用密钥标记为过渡期退休（保留已撤销状态）。
	RetireActiveSecretsTx(ctx context.Context, tx audit.Tx, clientID string, retireAt, now time.Time) (int64, error)
	// RevokeSecretTx 条件撤销指定密钥；返回是否成功。
	RevokeSecretTx(ctx context.Context, tx audit.Tx, clientID, secretID string, now time.Time) (bool, error)
	// ListCertificates 列出客户端全部证书记录。
	ListCertificates(ctx context.Context, clientID string) ([]CertificateRecord, error)
	// InsertCertificateTx 在审计事务内插入证书身份。
	InsertCertificateTx(ctx context.Context, tx audit.Tx, record CertificateRecord) error
	// RevokeCertificateTx 条件撤销指定证书；返回是否成功。
	RevokeCertificateTx(ctx context.Context, tx audit.Tx, clientID, certificateID string, now time.Time) (bool, error)
}

// ClientUpdate 是一次条件安全设置更新。
type ClientUpdate struct {
	ClientID               string
	GrantTypes             []GrantType
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Scopes                 []string
	Audiences              []string
	RequirePKCE            bool
	UpdatedAt              time.Time
	ExpectedRowVersion     int64
}

// Action 是客户端管理动作，用于 Authorizer 判定当前权限。
type Action string

const (
	// ActionRead 读取客户端安全设置与凭证元数据。
	ActionRead Action = "oauth.client.read"
	// ActionUpdateSettings 登记/修改客户端安全设置。
	ActionUpdateSettings Action = "oauth.client.settings"
	// ActionManageCredentials 轮换/撤销客户端凭证。
	ActionManageCredentials Action = "oauth.client.credentials"
)

// Authorizer 判定调用者能否管理指定应用的 OAuth 客户端安全设置；任何不确定或
// 依赖故障都必须返回错误，调用方按 ACCESS_DENIED fail-closed。
type Authorizer interface {
	AuthorizeClient(ctx context.Context, caller Caller, applicationID string, action Action) error
}

// ===== 内部辅助 =====

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// validScopeToken 校验 RFC 6749 scope-token：%x21 / %x23-5B / %x5D-7E。
func validScopeToken(token string) bool {
	if token == "" || len(token) > MaxScopeTokenBytes || !utf8.ValidString(token) {
		return false
	}
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character == 0x21 || (character >= 0x23 && character <= 0x5B) ||
			(character >= 0x5D && character <= 0x7E) {
			continue
		}
		return false
	}
	return true
}

func normalizeStrings(values []string, maxCount int, validator func(string) bool) ([]string, error) {
	if len(values) > maxCount {
		return nil, fmt.Errorf("%w: 数量超过上限 %d", ErrInvalidRequest, maxCount)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validator(value) {
			return nil, fmt.Errorf("%w: 条目格式无效", ErrInvalidRequest)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("%w: 条目重复", ErrInvalidRequest)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

// ParseGrantTypes 校验并规范化授权类型组合；明确拒绝 password/implicit。
func ParseGrantTypes(raw []string) ([]GrantType, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 至少登记一种授权类型", ErrInvalidRequest)
	}
	if len(raw) > MaxGrantTypes {
		return nil, fmt.Errorf("%w: 授权类型数量超过上限", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(raw))
	grants := make([]GrantType, 0, len(raw))
	hasAuthCode, hasRefresh := false, false
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("%w: 授权类型重复", ErrInvalidRequest)
		}
		seen[value] = struct{}{}
		grant, err := ParseGrantType(value)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
		switch grant {
		case GrantAuthorizationCode:
			hasAuthCode = true
		case GrantRefreshToken:
			hasRefresh = true
		case GrantClientCredentials:
			// 允许登记；公开客户端的组合校验在 validateClientSettings 中完成。
		}
	}
	if hasRefresh && !hasAuthCode && !containsGrant(grants, GrantDeviceCode) {
		return nil, fmt.Errorf("%w: refresh_token 只能与 authorization_code 或设备码一起登记", ErrInvalidConfiguration)
	}
	return grants, nil
}

func containsGrant(grants []GrantType, target GrantType) bool {
	for _, grant := range grants {
		if grant == target {
			return true
		}
	}
	return false
}

// ParseScopes 校验并规范化登记 Scope（令牌授权范围，不是角色权限）。
func ParseScopes(raw []string) ([]string, error) {
	return normalizeStrings(raw, MaxScopes, validScopeToken)
}

// ParseAudiences 校验并规范化允许的目标资源标识：必须是绝对 URI，禁止片段与
// userinfo；资源服务器标识不能是任意自由文本，避免未约束的令牌接收方。
func ParseAudiences(raw []string) ([]string, error) {
	return normalizeStrings(raw, MaxAudiences, func(value string) bool {
		if len(value) > MaxAudienceBytes || strings.ContainsAny(value, " \t\r\n") {
			return false
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
			parsed.User != nil || parsed.Fragment != "" {
			return false
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "http" {
			return false
		}
		if scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
			return false
		}
		return true
	})
}

// ParseAuthMethods 校验并规范化客户端身份验证方式。
func ParseAuthMethods(raw []string) ([]AuthMethod, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxAuthMethods {
		return nil, fmt.Errorf("%w: 身份验证方式数量超过上限", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(raw))
	methods := make([]AuthMethod, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("%w: 身份验证方式重复", ErrInvalidRequest)
		}
		seen[value] = struct{}{}
		method, err := ParseAuthMethod(value)
		if err != nil {
			return nil, err
		}
		methods = append(methods, method)
	}
	return methods, nil
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func hasSecretMethod(methods []AuthMethod) bool {
	for _, method := range methods {
		if method.IsSecretMethod() {
			return true
		}
	}
	return false
}

func hasTLSMethod(methods []AuthMethod) bool {
	for _, method := range methods {
		if method == AuthMethodTLSClientAuth {
			return true
		}
	}
	return false
}

// ValidateRedirectURI 校验回调地址：https 绝对地址；http 只允许 RFC 8252 回环
// IP 字面量（动态端口）；自定义 scheme 只允许公开客户端。禁止片段、通配符、
// userinfo、空 host 与非绝对地址。
func ValidateRedirectURI(raw string, clientType ClientType) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxRedirectURIBytes || !utf8.ValidString(raw) {
		return fmt.Errorf("%w: 回调地址长度或编码无效", ErrInvalidRequest)
	}
	if strings.ContainsAny(raw, "* ") || strings.Contains(raw, "\x00") {
		return fmt.Errorf("%w: 回调地址不能包含通配符或空白", ErrInvalidRequest)
	}
	if strings.Contains(raw, "#") {
		return fmt.Errorf("%w: 回调地址不能包含片段", ErrInvalidRequest)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%w: 回调地址不是合法绝对 URI", ErrInvalidRequest)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
		if parsed.Host == "" || parsed.Opaque != "" {
			return fmt.Errorf("%w: https 回调必须包含主机", ErrInvalidRequest)
		}
		return nil
	case "http":
		if clientType != ClientTypePublic {
			return fmt.Errorf("%w: 只有公开客户端可使用回环 http 回调", ErrInvalidRequest)
		}
		host := parsed.Hostname()
		if parsed.Host == "" || !isLoopbackHost(host) || parsed.Opaque != "" {
			return fmt.Errorf("%w: http 回调只允许回环 IP 字面量", ErrInvalidRequest)
		}
		if parsed.Port() == "" {
			return fmt.Errorf("%w: 回环回调必须显式声明端口", ErrInvalidRequest)
		}
		if _, portErr := parsePort(parsed.Port()); portErr != nil {
			return fmt.Errorf("%w: 回环回调端口无效", ErrInvalidRequest)
		}
		return nil
	default:
		if clientType != ClientTypePublic {
			return fmt.Errorf("%w: 自定义 scheme 回调只允许公开客户端", ErrInvalidRequest)
		}
		// RFC 8252 私有 scheme：scheme:path，无 host，path 必须以 / 开始。
		target := parsed.Opaque
		if target == "" {
			target = parsed.Path
		}
		if parsed.Host != "" || !strings.HasPrefix(target, "/") {
			return fmt.Errorf("%w: 自定义 scheme 回调格式无效", ErrInvalidRequest)
		}
		return nil
	}
}

func parsePort(port string) (int, error) {
	if port == "" || len(port) > 5 {
		return 0, fmt.Errorf("%w: 端口无效", ErrInvalidRequest)
	}
	value := 0
	for index := 0; index < len(port); index++ {
		character := port[index]
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%w: 端口无效", ErrInvalidRequest)
		}
		value = value*10 + int(character-'0')
	}
	if value < 1 || value > 65535 {
		return 0, fmt.Errorf("%w: 端口无效", ErrInvalidRequest)
	}
	return value, nil
}

// MatchRedirectURI 按登记的精确回调匹配请求中的 redirect_uri，返回命中的登记值。
// 唯一的宽松点：公开客户端的回环 http 回调忽略端口（RFC 8252 动态端口），其余
// scheme/host/path/query 与百分号编码逐字节比较；https 子域、大小写与编码差异
// 一律不匹配（不实现通配符或前缀匹配）。
func MatchRedirectURI(registered []string, requested string, clientType ClientType) (string, error) {
	if err := ValidateRedirectURI(requested, clientType); err != nil {
		return "", err
	}
	for _, candidate := range registered {
		if candidate == requested {
			return candidate, nil
		}
		if loopbackRedirectMatch(candidate, requested, clientType) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: 回调地址与登记不一致", ErrRedirectMismatch)
}

// MatchPostLogoutRedirectURI 按登记的退出回调精确匹配；规则与授权回调一致。
func MatchPostLogoutRedirectURI(registered []string, requested string, clientType ClientType) (string, error) {
	return MatchRedirectURI(registered, requested, clientType)
}

// loopbackRedirectMatch 实现 RFC 8252 回环地址动态端口匹配：两者都是公开客户端
// 的 http 回环 URI、主机相同、路径与查询串逐字节相同，仅端口不同。
func loopbackRedirectMatch(registered, requested string, clientType ClientType) bool {
	if clientType != ClientTypePublic {
		return false
	}
	registeredURI, err := url.Parse(registered)
	if err != nil || strings.ToLower(registeredURI.Scheme) != "http" {
		return false
	}
	requestedURI, err := url.Parse(requested)
	if err != nil || strings.ToLower(requestedURI.Scheme) != "http" {
		return false
	}
	if !isLoopbackHost(registeredURI.Hostname()) || !isLoopbackHost(requestedURI.Hostname()) {
		return false
	}
	if registeredURI.Hostname() != requestedURI.Hostname() {
		return false
	}
	if registeredURI.EscapedPath() != requestedURI.EscapedPath() {
		return false
	}
	registeredQuery, _ := url.ParseQuery(registeredURI.RawQuery)
	requestedQuery, _ := url.ParseQuery(requestedURI.RawQuery)
	if len(registeredQuery) != len(requestedQuery) {
		return false
	}
	for key, values := range registeredQuery {
		other, ok := requestedQuery[key]
		if !ok || len(values) != len(other) {
			return false
		}
		for index := range values {
			if values[index] != other[index] {
				return false
			}
		}
	}
	return true
}

// digestSecret 计算客户端密钥摘要（高熵随机密钥用 SHA-256 足够；验证值不可逆）。
func digestSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

// constantTimeEqual 比较两个摘要。
func constantTimeEqual(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

// hexFingerprint 把指纹转为小写十六进制（列表展示用）。
func hexFingerprint(fingerprint [32]byte) string {
	return hex.EncodeToString(fingerprint[:])
}
