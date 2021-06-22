// Package oidc 在授权码流程之上实现 OpenID Connect 登录能力：Discovery 文档、
// ID Token（auth_time/amr/acr/nonce、按客户端配对 subject）与 UserInfo。
//
// 安全不变量：
//   - 只有授权请求包含 openid scope 时才签发 ID Token；未配置本服务时 openid 在
//     授权请求阶段即被拒绝，不声明未实现能力。
//   - ID Token 的 iss/aud/exp/iat 由 internal/token 固定签发方与 JOSE 签名保证；
//     nonce 原样回传；auth_time 来自授权确认时会话的真实登录时间，amr/acr 由
//     internal/authfact 从会话真实认证方法映射，调用方不能自述或伪造强度。
//   - subject 采用按客户端配对的稳定假名（HMAC-SHA256(主机秘密, client_id|user_id)），
//     同一用户对不同客户端不可关联；UserInfo 返回的 sub 与 ID Token 一致。
//   - Discovery 只声明真实实现的端点/能力（authorization_code + PKCE S256 + ES256 +
//     pairwise subject + 已实现端点），不声明设备码/撤销/结束会话等未实现能力。
//   - UserInfo 必须验证 Access Token 的签名/签发方/类型/目标资源（issuer 作为
//     UserInfo 资源受众，客户端需把 issuer 登记到允许 audience 才能调用）、openid
//     scope 与 scope 决定的字段集合；email/email_verified 反映数据库真实验证状态，
//     不输出密码、MFA、凭证、会话或找回材料。
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 领域错误哨兵。错误文本不包含令牌原文或用户秘密。
var (
	ErrOptionsInvalid    = errors.New("OIDC 服务选项无效")
	ErrInvalidRequest    = errors.New("OIDC 请求无效")
	ErrAccessDenied      = errors.New("OIDC 请求未获准")
	ErrTokenInvalid      = errors.New("Access Token 无效")
	ErrInsufficientScope = errors.New("Access Token 缺少 openid scope")
	ErrUserUnavailable   = errors.New("用户当前不可用")
	ErrStoreUnavailable  = errors.New("OIDC 用户存储暂时不可用")
)

// ErrorCode 是 OIDC 领域对根包错误码注册表的投影（只复用既有 46 码）。
type ErrorCode string

const (
	CodeReqInvalid    ErrorCode = "REQ_INVALID"
	CodeTokenInvalid  ErrorCode = "TOKEN_INVALID"
	CodeAccessDenied  ErrorCode = "ACCESS_DENIED"
	CodeUserDisabled  ErrorCode = "USER_DISABLED"
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 OIDC 领域错误映射为已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrTokenInvalid):
		return CodeTokenInvalid
	case errors.Is(err, ErrInsufficientScope), errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrUserUnavailable):
		return CodeUserDisabled
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	}
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) {
		switch protocolErr.Code {
		case "invalid_token":
			return CodeTokenInvalid
		case "insufficient_scope":
			return CodeAccessDenied
		case "invalid_request":
			return CodeReqInvalid
		}
	}
	switch {
	default:
		return CodeInternalError
	}
}

// ProtocolError 是 OIDC UserInfo 端点的协议错误（RFC 6750/OIDC Core）。
type ProtocolError struct {
	// Code 是标准协议错误码：invalid_token / insufficient_scope / invalid_request。
	Code        string
	Description string
	Status      int
}

// Error 实现 error；描述只含稳定原因，不含令牌或用户秘密。
func (e *ProtocolError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func tokenInvalidError(description string) *ProtocolError {
	return &ProtocolError{Code: "invalid_token", Description: description, Status: 401}
}

func insufficientScopeError(description string) *ProtocolError {
	return &ProtocolError{Code: "insufficient_scope", Description: description, Status: 403}
}

// UserInfoRecord 是 UserInfo 需要的用户字段快照（来自 users/user_emails）。
type UserInfoRecord struct {
	UserID        string
	Username      string
	Nickname      string
	Language      string
	Timezone      string
	Status        string
	Email         string
	EmailVerified bool
	UpdatedAt     time.Time
}

// Active 报告账户是否可用于 UserInfo。
func (r UserInfoRecord) Active() bool { return r.Status == "active" }

// UserInfoSource 读取用户资料与已验证邮箱状态；实现必须 fail-closed。
type UserInfoSource interface {
	LoadUserInfo(ctx context.Context, userID string) (UserInfoRecord, bool, error)
}

// TokenService 是本包使用的令牌最小契约；生产实现 *internal/token.Service。
type TokenService interface {
	IssueIDToken(ctx context.Context, caller token.Caller, request token.IssueIDTokenRequest) (token.IssuedToken, error)
	VerifyAccessToken(ctx context.Context, raw, expectedAudience string) (token.AccessClaims, error)
}

// Options 是 OIDC 服务依赖与固定公开配置。
type Options struct {
	// Issuer 是固定公开签发方（与令牌 iss 一致），不得带尾斜杠，缺省端口规则与端点
	// 必须保持同一来源与路径前缀。
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
	Tokens                TokenService
	Users                 UserInfoSource
	// SubjectSecret 是按客户端配对 subject 的 HMAC 秘密（至少 32 字节）；宿主必须
	// 持久保存，轮换会使既有 subject 变化（本步不实现轮换）。
	SubjectSecret []byte
	// SupportedScopes 是允许声明的 Scope，默认 openid/profile/email；必须包含
	// openid，且不能声明未实现的 Scope。
	SupportedScopes []string
	Now             func() time.Time
}

// Service 是 OIDC 发现、ID Token 签发与 UserInfo 服务。构造后不可变，不启动协程。
type Service struct {
	opts   Options
	scopes []string
}

// 默认 Scope 与认证/签名能力。
var defaultScopes = []string{"openid", "profile", "email"}

// New 校验配置并构造服务；任何缺失/不一致都返回错误（fail-closed）。
func New(options Options) (*Service, error) {
	if err := validateIssuer(options.Issuer); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	if err := validateEndpoint(options.Issuer, options.AuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("%w: 授权端点: %v", ErrOptionsInvalid, err)
	}
	if err := validateEndpoint(options.Issuer, options.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("%w: 令牌端点: %v", ErrOptionsInvalid, err)
	}
	if err := validateEndpoint(options.Issuer, options.UserInfoEndpoint); err != nil {
		return nil, fmt.Errorf("%w: UserInfo 端点: %v", ErrOptionsInvalid, err)
	}
	if err := validateEndpoint(options.Issuer, options.JWKSURI); err != nil {
		return nil, fmt.Errorf("%w: JWKS 地址: %v", ErrOptionsInvalid, err)
	}
	if isNil(options.Tokens) {
		return nil, fmt.Errorf("%w: 令牌服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Users) {
		return nil, fmt.Errorf("%w: 用户资料来源为空", ErrOptionsInvalid)
	}
	if len(options.SubjectSecret) < 32 {
		return nil, fmt.Errorf("%w: subject 秘密至少 32 字节", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	scopes := options.SupportedScopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	hasOpenID := false
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !validScope(scope) {
			return nil, fmt.Errorf("%w: Scope 标识无效", ErrOptionsInvalid)
		}
		if scope == ScopeOpenID {
			hasOpenID = true
		}
		if scope != ScopeOpenID && scope != ScopeProfile && scope != ScopeEmail {
			return nil, fmt.Errorf("%w: 未实现的 Scope 不能声明", ErrOptionsInvalid)
		}
		normalized = append(normalized, scope)
	}
	if !hasOpenID {
		return nil, fmt.Errorf("%w: openid scope 必须启用", ErrOptionsInvalid)
	}
	return &Service{opts: options, scopes: normalized}, nil
}

// Scope 常量。
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

// DiscoveryDocument 是 OIDC Discovery 文档。只包含真实实现的能力字段。
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
}

// Discovery 返回固定公开发现文档；只声明本服务真实实现的能力。
func (s *Service) Discovery() DiscoveryDocument {
	return DiscoveryDocument{
		Issuer:                 s.opts.Issuer,
		AuthorizationEndpoint:  s.opts.AuthorizationEndpoint,
		TokenEndpoint:          s.opts.TokenEndpoint,
		UserInfoEndpoint:       s.opts.UserInfoEndpoint,
		JWKSURI:                s.opts.JWKSURI,
		ScopesSupported:        append([]string(nil), s.scopes...),
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query"},
		// 只声明已实现：授权码（刷新令牌与设备码本步未实现）。
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "tls_client_auth"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{"iss", "sub", "aud", "azp", "exp", "iat", "auth_time",
			"nonce", "amr", "acr", "name", "preferred_username", "locale", "zoneinfo",
			"updated_at", "email", "email_verified"},
		ClaimsParameterSupported:     false,
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}
}

// Subject 计算某用户对某客户端的稳定 pairwise subject（同一用户不同客户端不可关联）。
func (s *Service) Subject(clientID, userID string) (string, error) {
	if clientID == "" || userID == "" {
		return "", fmt.Errorf("%w: client_id 或用户 ID 为空", ErrInvalidRequest)
	}
	mac := hmac.New(sha256.New, s.opts.SubjectSecret)
	_, _ = mac.Write([]byte("oidc-sub-v1\x00" + clientID + "\x00" + userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// IssueLoginIDToken 在授权码兑换成功后签发 ID Token：auth_time/amr/acr 来自授权
// 确认时保存的会话真实认证事实；nonce 原样回传；subject 使用按客户端配对假名。
func (s *Service) IssueLoginIDToken(ctx context.Context, request oauthflow.LoginIDTokenRequest) (token.IssuedToken, error) {
	ctx = normalizeContext(ctx)
	if request.ClientID == "" || request.UserID == "" {
		return token.IssuedToken{}, fmt.Errorf("%w: 客户端或用户为空", ErrInvalidRequest)
	}
	if !containsScope(request.Scopes, ScopeOpenID) {
		return token.IssuedToken{}, fmt.Errorf("%w: 未请求 openid scope，不得签发 ID Token", ErrInvalidRequest)
	}
	if request.AuthTime.IsZero() {
		return token.IssuedToken{}, fmt.Errorf("%w: 缺少真实认证时间", ErrInvalidRequest)
	}
	set, err := authFactSet(request.AuthMethods, request.AuthTime)
	if err != nil {
		return token.IssuedToken{}, err
	}
	subject, err := s.Subject(request.ClientID, request.UserID)
	if err != nil {
		return token.IssuedToken{}, err
	}
	caller, err := token.SystemCaller("oidc")
	if err != nil {
		return token.IssuedToken{}, fmt.Errorf("%w: 无法构造签发身份", ErrOptionsInvalid)
	}
	issued, err := s.opts.Tokens.IssueIDToken(ctx, caller, token.IssueIDTokenRequest{
		ClientID: request.ClientID, SubjectUserID: request.UserID, Subject: subject,
		Nonce: request.Nonce, AuthTime: request.AuthTime.UTC(),
		AMR: authfact.AMR(set), ACR: authfact.ACR(set), RequestID: request.RequestID,
	})
	if err != nil {
		return token.IssuedToken{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return issued, nil
}

// LoginIDTokenRequest 是授权码兑换服务交给 OIDC 的 ID Token 请求别名（与
// internal/oauthflow 契约同一类型，便于宿主直接使用）。
type LoginIDTokenRequest = oauthflow.LoginIDTokenRequest

// UserInfoResponse 是 UserInfo 成功响应；按 scope 裁剪字段。
type UserInfoResponse struct {
	Subject           string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Locale            string `json:"locale,omitempty"`
	ZoneInfo          string `json:"zoneinfo,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
}

// UserInfo 验证 Access Token 并返回允许披露的字段。
//
// 要求：签名/签发方/类型/有效期由令牌服务校验；access token 的 audience 必须包含
// 本服务 issuer（UserInfo 资源），scope 必须包含 openid；profile/email 字段只在对应
// scope 内返回。email_verified 如实反映数据库验证状态，无已验证邮箱时不返回 email。
func (s *Service) UserInfo(ctx context.Context, accessToken string) (UserInfoResponse, error) {
	ctx = normalizeContext(ctx)
	if accessToken == "" {
		return UserInfoResponse{}, tokenInvalidError("缺少访问令牌")
	}
	claims, err := s.opts.Tokens.VerifyAccessToken(ctx, accessToken, s.opts.Issuer)
	if err != nil {
		return UserInfoResponse{}, tokenInvalidError("访问令牌无效或已过期")
	}
	if claims.TokenUse != token.TokenUseAccess || claims.ClientID == "" {
		return UserInfoResponse{}, tokenInvalidError("访问令牌类型不匹配")
	}
	if !containsScope(claims.Scopes, ScopeOpenID) {
		return UserInfoResponse{}, insufficientScopeError("访问令牌缺少 openid scope")
	}
	record, found, err := s.opts.Users.LoadUserInfo(ctx, claims.Subject)
	if err != nil {
		return UserInfoResponse{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	if !found {
		return UserInfoResponse{}, tokenInvalidError("访问令牌主体不可用")
	}
	if !record.Active() {
		return UserInfoResponse{}, tokenInvalidError("账户当前不可用")
	}
	if claims.Subject != record.UserID {
		return UserInfoResponse{}, tokenInvalidError("访问令牌主体不匹配")
	}
	subject, err := s.Subject(claims.ClientID, claims.Subject)
	if err != nil {
		return UserInfoResponse{}, fmt.Errorf("%w: 无法计算 subject", ErrInvalidRequest)
	}
	response := UserInfoResponse{Subject: subject}
	if containsScope(claims.Scopes, ScopeProfile) {
		response.Name = record.Nickname
		response.PreferredUsername = record.Username
		response.Locale = record.Language
		response.ZoneInfo = record.Timezone
		if !record.UpdatedAt.IsZero() {
			response.UpdatedAt = record.UpdatedAt.UTC().Unix()
		}
	}
	if containsScope(claims.Scopes, ScopeEmail) && record.EmailVerified && record.Email != "" {
		verified := true
		response.Email = record.Email
		response.EmailVerified = &verified
	}
	return response, nil
}

// ===== 内部辅助 =====

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// validateIssuer 校验固定公开 issuer：绝对 http(s) URL、无查询/片段/userinfo、
// 无尾斜杠（路径允许，根路径除外也不能带尾斜杠）。
func validateIssuer(value string) error {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 2048 {
		return fmt.Errorf("issuer 为空或包含空白")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("issuer 必须是绝对 URL 且不含查询/片段/userinfo")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopback(parsed.Hostname())) {
		return fmt.Errorf("issuer 必须使用 https（本地回环测试可用 http）")
	}
	if strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("issuer 不能带尾斜杠")
	}
	return nil
}

// validateEndpoint 校验端点与 issuer 同源，且路径位于 issuer 路径前缀下。
func validateEndpoint(issuer, endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("端点为空")
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("端点必须是绝对 URL 且不含片段/userinfo")
	}
	if !strings.EqualFold(parsed.Scheme, issuerURL.Scheme) ||
		!strings.EqualFold(parsed.Host, issuerURL.Host) {
		return fmt.Errorf("端点必须与 issuer 同源")
	}
	issuerPath := strings.TrimSuffix(issuerURL.EscapedPath(), "/")
	escapedPath := parsed.EscapedPath()
	if strings.Contains(escapedPath, "..") || strings.Contains(escapedPath, "%2e") {
		return fmt.Errorf("端点路径不能包含 .. 段")
	}
	if !strings.HasPrefix(escapedPath, issuerPath+"/") {
		return fmt.Errorf("端点路径必须位于 issuer 路径前缀下")
	}
	return nil
}

func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func validScope(scope string) bool {
	if scope == "" || len(scope) > 128 {
		return false
	}
	for index := 0; index < len(scope); index++ {
		character := scope[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}

// authFactSet 把会话真实认证方法映射为 authfact 集合；未知/空方法拒绝（不伪造 amr）。
func authFactSet(methods []string, authTime time.Time) (authfact.Set, error) {
	if len(methods) == 0 {
		return authfact.Set{}, fmt.Errorf("%w: 缺少真实认证方法", ErrInvalidRequest)
	}
	facts := make([]authfact.Fact, 0, len(methods))
	for _, method := range methods {
		parsed, err := authfact.ParseMethod(method)
		if err != nil {
			return authfact.Set{}, fmt.Errorf("%w: 认证方法标识未知", ErrInvalidRequest)
		}
		facts = append(facts, authfact.Fact{Method: parsed, VerifiedAt: authTime})
	}
	set, err := authfact.NewSet(facts...)
	if err != nil {
		return authfact.Set{}, fmt.Errorf("%w: 认证事实无效", ErrInvalidRequest)
	}
	return set, nil
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// isNil 识别 typed-nil 依赖。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// 编译期确认实现 internal/oauthflow 的 ID Token 签发契约。
var _ oauthflow.IDTokenIssuer = (*Service)(nil)
