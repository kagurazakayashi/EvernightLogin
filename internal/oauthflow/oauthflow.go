// Package oauthflow 实现 OAuth 2.0 授权码 + PKCE 的授权请求、用户确认、授权码发行
// 与 Token 端点兑换（步骤 51）。
//
// 信任边界与安全不变量：
//   - 授权端点：校验 client_id、redirect_uri（逐字节精确匹配，回环动态端口例外复用
//     internal/oauthclient 规则）、response_type=code、PKCE S256、scope/audience
//     属于客户端登记配置。无效 client/redirect **不重定向**，避免开放重定向与向
//     未登记地址泄露错误；其余协议错误只在已登记回调上以标准 error 参数返回。
//   - 用户确认：必须绑定真实用户会话（internal/session 校验完整会话），不接受任何
//     客户端自报用户；用户拒绝、会话失效、成员关系失效都拒绝。确认前按敏感操作
//     策略经 internal/reauth 要求近期认证；未接线时 fail-closed。绝不自动批准。
//   - 授权码：高熵随机值只保存 SHA-256 摘要；短时（默认 5 分钟）、一次性、绑定
//     user+client+精确 redirect_uri+PKCE challenge+scope+audience+会话安全版本快照，
//     nonce 保存供后续 OIDC 使用。明文授权码只出现在确认成功响应中，不写日志/审计/
//     普通存储。
//   - Token 端点：客户端认证（保密客户端 secret/证书，公开客户端必须 PKCE）、
//     code_verifier 校验、逐项绑定校验、原子条件消费（并发兑换单赢家）；重复兑换
//     记录 replayed_at_ms 并按标准 invalid_grant 拒绝（访问令牌为无状态 JWT，撤销
//     列表/刷新家族属步骤 54，本步不宣称已撤销已签发令牌）。错误一律使用标准 OAuth
//     error/error_description 字段与 HTTP 状态，不使用项目通用业务响应格式。
//   - 本包不做浏览器页面与 HTTP 路由（步骤 65 建 UI）；宿主通过 Go API 渲染确认页、
//     执行重定向与 Token JSON 响应。禁止 password/隐式授权，也不签发刷新令牌。
package oauthflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

const (
	// DefaultRequestTTL 是授权确认请求的默认有效期（用户完成确认的时间窗口）。
	DefaultRequestTTL = 10 * time.Minute
	// MinRequestTTL/MaxRequestTTL 是确认请求有效期边界。
	MinRequestTTL = time.Minute
	MaxRequestTTL = 15 * time.Minute
	// DefaultCodeTTL 是授权码默认有效期。
	DefaultCodeTTL = 5 * time.Minute
	// MinCodeTTL/MaxCodeTTL 是授权码有效期边界（规范建议不超过 10 分钟）。
	MinCodeTTL = time.Minute
	MaxCodeTTL = 10 * time.Minute
	// MaxStateBytes 是 state 长度上限（不透明、原样回传）。
	MaxStateBytes = 1024
	// MaxNonceBytes 是 OIDC nonce 长度上限。
	MaxNonceBytes = 512
	// MaxScopes 是单次授权请求 Scope 数量上限。
	MaxScopes = 50
	// MaxAudiences 是单次授权请求目标资源数量上限。
	MaxAudiences = 20
	// MaxScopeTokenBytes/MaxAudienceBytes 是单项长度上限。
	MaxScopeTokenBytes = 128
	MaxAudienceBytes   = 256
	// MaxRedirectURIBytes 是回调地址长度上限。
	MaxRedirectURIBytes = 2048
	// authorizationRequestPrefix/authorizationCodePrefix 是内部稳定 ID 前缀。
	authorizationRequestPrefix = "oar_"
	authorizationCodePrefix    = "oac_"
	// codeRandomBytes 是授权码随机字节数（base64url 后远高于规范熵要求）。
	codeRandomBytes = 32
	// pkceMinVerifierLength/PKCEMaxVerifierLength 是 RFC 7636 边界。
	pkceMinVerifierLength = 43
	pkceMaxVerifierLength = 128
	// operationAuthorizationApprove 是步骤 38 敏感操作目录中的授权确认操作 ID。
	operationAuthorizationApprove = "oauth.authorization.approve"
	// tokenRequestPrefix 是内部请求编号前缀。
	tokenRequestPrefix = "otr_"
)

// 领域错误（宿主可据此写失败审计/诊断）。协议错误另外用 *OAuthError 表达。
var (
	ErrOptionsInvalid   = errors.New("OAuth 授权流程选项无效")
	ErrInvalidRequest   = errors.New("OAuth 授权请求无效")
	ErrStoreUnavailable = errors.New("OAuth 授权流程存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	ErrConsentNotFound  = errors.New("授权确认请求不存在或已失效")
)

// ErrorCode 是本领域对根包错误码注册表的投影（只复用既有 46 码），用于宿主内部
// 诊断；协议响应仍使用标准 OAuth 错误，不使用这些业务码。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired      ErrorCode = "MFA_REQUIRED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把本领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrConsentNotFound):
		return CodeReqInvalid
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// OAuthError 是标准 OAuth 2.0 协议错误。它包含可选的合法回调地址与 state 用于授权
// 端点错误重定向；数值状态码遵循 RFC 6749（invalid_client 401，其余 400/500/503）。
// 错误描述只包含稳定、非敏感文本，不泄露客户端/用户/内部存储细节。
type OAuthError struct {
	// Code 是 RFC 6749 error 值（invalid_request/invalid_client/unauthorized_client/
	// unsupported_response_type/invalid_scope/access_denied/invalid_grant/
	// unsupported_grant_type/server_error/temporarily_unavailable）。
	Code string
	// Description 是安全的中文/英文描述；不含秘密。
	Description string
	// HTTPStatus 是宿主应返回的 HTTP 状态码。
	HTTPStatus int
	// RedirectURI/State 仅在授权端点且 client/redirect 已验证时非空；此时宿主可以
	// 用 RedirectLocation 生成标准错误重定向。为空表示禁止重定向。
	RedirectURI string
	State       string
}

// Error 实现 error；只输出协议错误码与安全描述，不含秘密。
func (e *OAuthError) Error() string {
	if e == nil {
		return "OAuth 协议错误"
	}
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Body 返回标准 OAuth 错误响应字段（宿主按 JSON 返回，不使用项目业务响应格式）。
func (e *OAuthError) Body() map[string]string {
	if e == nil {
		return map[string]string{"error": "server_error"}
	}
	body := map[string]string{"error": e.Code}
	if e.Description != "" {
		body["error_description"] = e.Description
	}
	return body
}

// RedirectLocation 生成授权端点错误重定向 URL；第二个返回值表示是否允许重定向。
// client/redirect 无效或未登记时禁止重定向（避免开放重定向与信息泄露）。
func (e *OAuthError) RedirectLocation() (string, bool) {
	if e == nil || e.RedirectURI == "" || e.HTTPStatus == 0 {
		return "", false
	}
	parsed, err := url.Parse(e.RedirectURI)
	if err != nil {
		return "", false
	}
	values := parsed.Query()
	values.Set("error", e.Code)
	if e.Description != "" {
		values.Set("error_description", e.Description)
	}
	if e.State != "" {
		values.Set("state", e.State)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), true
}

// Is 允许 errors.Is 按协议错误码匹配（"invalid_grant" 等稳定字符串）。
func (e *OAuthError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	var other *OAuthError
	if !errors.As(target, &other) {
		return false
	}
	return e.Code == other.Code
}

// OAuth 协议错误值构造器（内部使用）。
func newOAuthError(code, description string, status int) *OAuthError {
	return &OAuthError{Code: code, Description: description, HTTPStatus: status}
}

func oauthInvalidRequest(description string) *OAuthError {
	return newOAuthError("invalid_request", description, 400)
}

func oauthInvalidClient() *OAuthError {
	return newOAuthError("invalid_client", "客户端身份验证失败", 401)
}

func oauthUnauthorizedClient() *OAuthError {
	return newOAuthError("unauthorized_client", "该客户端不允许使用授权码模式", 400)
}

func oauthUnsupportedResponseType() *OAuthError {
	return newOAuthError("unsupported_response_type", "只支持 response_type=code", 400)
}

func oauthInvalidScope() *OAuthError {
	return newOAuthError("invalid_scope", "请求的 scope 不在客户端登记范围内", 400)
}

func oauthInvalidGrant(description string) *OAuthError {
	return newOAuthError("invalid_grant", description, 400)
}

func oauthUnsupportedGrantType() *OAuthError {
	return newOAuthError("unsupported_grant_type", "只支持 authorization_code", 400)
}

func oauthServerError() *OAuthError {
	return newOAuthError("server_error", "授权服务暂时不可用", 500)
}

func oauthTemporarilyUnavailable() *OAuthError {
	return newOAuthError("temporarily_unavailable", "授权服务暂时不可用", 503)
}

// withRedirect 给授权端点的协议错误附加已验证的合法回调与 state（仅当安全时调用）。
func (e *OAuthError) withRedirect(redirectURI, state string) *OAuthError {
	if e == nil {
		return nil
	}
	e.RedirectURI = redirectURI
	e.State = state
	return e
}

// ClientInfo 是授权流程需要的客户端登记配置快照（来自 internal/oauthclient）。
type ClientInfo struct {
	ClientID     string
	ClientType   oauthclient.ClientType
	AppStatus    string
	GrantTypes   []oauthclient.GrantType
	RedirectURIs []string
	Scopes       []string
	Audiences    []string
	RequirePKCE  bool
}

// Active 报告客户端所属应用是否启用。
func (c ClientInfo) Active() bool { return c.AppStatus == "active" }

// GrantsAuthorizationCode 报告客户端是否登记授权码模式。
func (c ClientInfo) GrantsAuthorizationCode() bool {
	for _, grant := range c.GrantTypes {
		if grant == oauthclient.GrantAuthorizationCode {
			return true
		}
	}
	return false
}

// ClientSource 读取客户端登记配置；不存在返回 found=false。实现必须 fail-closed。
type ClientSource interface {
	LoadClient(ctx context.Context, clientID string) (ClientInfo, bool, error)
}

// ClientAuthenticator 是 Token 端点客户端身份验证契约；生产实现为
// *internal/oauthclient.Service（VerifyClientSecret/VerifyClientCertificate）。
type ClientAuthenticator interface {
	VerifyClientSecret(ctx context.Context, clientID, secret string) (oauthclient.ClientIdentity, error)
	VerifyClientCertificate(ctx context.Context, clientID, certificatePEM string) (oauthclient.ClientIdentity, error)
}

// Sessions 是用户会话校验契约；生产实现为 *internal/session.Service。
type Sessions interface {
	Validate(ctx context.Context, secret string) (session.Session, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// TokenIssuer 是 Access Token 签发契约；生产实现为 *internal/token.Service。
type TokenIssuer interface {
	IssueAccessToken(ctx context.Context, caller token.Caller, request token.IssueAccessTokenRequest) (token.IssuedToken, error)
}

// AuthorizeRequest 是授权端点请求。字段由宿主从已解析的 HTTP 参数填充，但所有
// 校验在本包内重新执行；客户端不能通过省略/额外参数绕过。
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	Resource            []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// RequestID 是客户端可选请求编号（仅用于审计关联）。
	RequestID string
}

// ConsentPrompt 是返回给宿主的授权确认页面数据（最小化，不含任何秘密）。
type ConsentPrompt struct {
	RequestID    string
	ClientID     string
	ClientType   oauthclient.ClientType
	Scopes       []string
	Audiences    []string
	RedirectURI  string
	ExpiresAt    time.Time
	StatePresent bool
}

// DecideRequest 是用户对授权确认请求的决定。Approve=false 表示明确拒绝。
type DecideRequest struct {
	RequestID string
	Approve   bool
	// RequestID 字段名与客户端请求编号冲突，这里使用 DecisionRequestID 仅用于审计。
	DecisionRequestID string
}

// AuthorizationResult 是授权确认成功/拒绝后的结果；Code 明文只在 Approve=true 时
// 出现且只出现一次，宿主必须立即写入重定向 URL 并丢弃，不得记录到日志。
type AuthorizationResult struct {
	RequestID     string
	Approved      bool
	Code          string
	RedirectURL   string
	State         string
	CodeExpiresAt time.Time
}

// ExchangeRequest 是 Token 端点授权码兑换请求。ClientSecret 与 ClientCertificatePEM
// 只用于客户端认证；公开客户端必须提供 code_verifier。
type ExchangeRequest struct {
	GrantType            string
	Code                 string
	RedirectURI          string
	ClientID             string
	ClientSecret         string
	ClientCertificatePEM string
	CodeVerifier         string
	RequestID            string
}

// TokenResponse 是 Token 端点成功响应。AccessToken 是脱敏类型，宿主必须显式
// Reveal() 后渲染 JSON，不得记录到日志/审计。
type TokenResponse struct {
	AccessToken token.Token
	TokenType   string
	ExpiresIn   int64
	Scope       string
	// RequestID/CodeID 是内部关联标识（不含秘密）。
	RequestID string
	CodeID    string
}

// 编译期契约断言：生产适配器与核心接口一致。
var (
	_ ClientAuthenticator = (*oauthclient.Service)(nil)
	_ Sessions            = (*session.Service)(nil)
	_ TokenIssuer         = (*token.Service)(nil)
)

// ===== 规范化与校验辅助 =====

// normalizeScopes 规范化 Scope 列表：去空白、去重、排序、校验字符与数量并保证是
// 客户端登记 Scope 的子集（由调用方提供 allowed）。
func normalizeScopes(raw []string, allowed []string) ([]string, *OAuthError) {
	if len(raw) > MaxScopes {
		return nil, oauthInvalidScope()
	}
	seen := make(map[string]struct{}, len(raw))
	scopes := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > MaxScopeTokenBytes || !validScopeToken(value) {
			return nil, oauthInvalidScope()
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		if !containsString(allowed, value) {
			return nil, oauthInvalidScope()
		}
		scopes = append(scopes, value)
	}
	sort.Strings(scopes)
	return scopes, nil
}

// validScopeToken 与 internal/oauthclient 的 Scope 字符规则一致（RFC 6749 scope-token）。
func validScopeToken(token string) bool {
	if token == "" || !utf8.ValidString(token) {
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

// normalizeAudiences 规范化目标资源列表并校验属于客户端登记范围。
func normalizeAudiences(raw []string, allowed []string) ([]string, *OAuthError) {
	if len(raw) > MaxAudiences {
		return nil, oauthInvalidRequest("目标资源数量过多")
	}
	seen := make(map[string]struct{}, len(raw))
	audiences := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > MaxAudienceBytes || !utf8.ValidString(value) ||
			strings.ContainsFunc(value, unicode.IsControl) {
			return nil, oauthInvalidRequest("目标资源参数无效")
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		if !containsString(allowed, value) {
			return nil, oauthInvalidRequest("目标资源不在客户端登记范围内")
		}
		audiences = append(audiences, value)
	}
	sort.Strings(audiences)
	return audiences, nil
}

// validOpaque 校验 state/nonce 等不透明回传值：非控制字符、UTF-8、有界。
func validOpaque(value string, maxBytes int) bool {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

// validPKCEChallenge 校验 S256 challenge：43 位 base64url（UTF-8 可见）且无填充。
func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	for index := 0; index < len(challenge); index++ {
		character := challenge[index]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

// validPKCEVerifier 校验 RFC 7636 code_verifier 字符与长度。
func validPKCEVerifier(verifier string) bool {
	if len(verifier) < pkceMinVerifierLength || len(verifier) > pkceMaxVerifierLength {
		return false
	}
	for index := 0; index < len(verifier); index++ {
		character := verifier[index]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '.' || character == '_' || character == '~' {
			continue
		}
		return false
	}
	return true
}

// pkceS256 计算 base64url(SHA256(verifier))，用于与 challenge 恒定比较。
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// joinScopes 把规范 Scope 列表序列化为空格连接字符串。
func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

// parseStoredScopes 把持久化空格连接字符串还原为列表。
func parseStoredScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Fields(value)
}

// audienceJSON/AudiencesFromJSON 处理 audience 持久化（JSON 数组）。
func audienceJSON(audiences []string) (string, error) {
	if audiences == nil {
		audiences = []string{}
	}
	encoded, err := json.Marshal(audiences)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func audiencesFromJSON(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	var audiences []string
	if err := json.Unmarshal([]byte(value), &audiences); err != nil {
		return nil, err
	}
	return audiences, nil
}

// hashAuthorizationCode 计算授权码摘要（只存摘要，不存明文）。
func hashAuthorizationCode(code string) [32]byte {
	return sha256.Sum256([]byte(code))
}

// validRequestID 复用 account 的请求编号规则（客户端可选字段）。
func validRequestID(value string) error { return account.ValidateRequestID(value) }

// sessionActor 把会话用户映射为审计身份。
func sessionActor(userID string) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: userID}
}

// reauthCaller 构造步骤 39 的再次认证调用者。
func reauthCaller(userID string) (reauth.Caller, error) {
	return reauth.UserCaller(userID)
}

// normalizeContext 保证 nil context 不导致 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
