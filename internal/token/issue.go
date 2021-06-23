package token

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// 令牌原文与声明的有界长度，避免无界输入进入解析/日志。
const (
	// MaxTokenBytes 是客户端提交令牌的最大字节数（防御超大输入）。
	MaxTokenBytes = 16 * 1024
	// maxClaimBytes 是解码后声明 JSON 的最大长度。
	maxClaimBytes = 8 * 1024
)

// accessTokenClaims 是 Access Token 的声明集合（RFC 9068 子集）。
type accessTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope,omitempty"`
	TokenUse string   `json:"token_use"`
	// SubjectType 区分代表用户的访问令牌（user）与代表应用/服务自身的令牌
	// （service，仅 client_credentials）；旧令牌缺失该声明按 user 解释。
	SubjectType string `json:"subject_type,omitempty"`
	IssuedAt    int64  `json:"iat"`
	NotBefore   int64  `json:"nbf,omitempty"`
	ExpiresAt   int64  `json:"exp"`
	TokenID     string `json:"jti"`
}

// idTokenClaims 是 ID Token 的声明集合（OIDC 子集）。
type idTokenClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        string   `json:"aud"`
	ClientID        string   `json:"client_id"`
	AuthorizedParty string   `json:"azp,omitempty"`
	TokenUse        string   `json:"token_use"`
	Nonce           string   `json:"nonce,omitempty"`
	AuthTime        int64    `json:"auth_time,omitempty"`
	AMR             []string `json:"amr,omitempty"`
	ACR             string   `json:"acr,omitempty"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"`
	TokenID         string   `json:"jti"`
}

// IssueAccessTokenRequest 是签发 Access Token 的请求。调用者不能自述身份：
// Caller 由宿主可信边界构造，且 SubjectUserID 必须与普通用户调用者一致。
type IssueAccessTokenRequest struct {
	ClientID      string
	SubjectUserID string
	GrantType     GrantType
	Scopes        []string
	Audiences     []string
	RequestID     string
}

// IssueIDTokenRequest 是签发 ID Token 的请求（授权码/设备码流程完成后由受信流程调用）。
type IssueIDTokenRequest struct {
	ClientID      string
	SubjectUserID string
	// Subject 是写入 ID Token 的 `sub` 声明；为空时使用 SubjectUserID。OIDC 流程可
	// 传按客户端配对的稳定假名（pairwise），此时 SubjectUserID 仍是真实用户 ID，
	// 用于审计与授权判定，不会写进令牌。
	Subject string
	Nonce   string
	// AuthTime 是本次认证真实发生时间（会话登录时间），不得由客户端自述。
	AuthTime time.Time
	// AMR/ACR 是来自服务端真实认证事实的方法引用与认证上下文，不得伪造强度；
	// 为空时 ID Token 不声明对应字段。
	AMR       []string
	ACR       string
	RequestID string
}

// IssueAccessToken 签发 Access Token。签发前校验调用者可信身份、客户端登记配置
// （授权类型/Scope/audience）、主体归属与注入的 IssuanceAuthorizer；任何不确定或
// 拒绝都 fail-closed 并写失败审计。签发使用当前 active 签名密钥（无密钥时引导建钥，
// 系统主体审计）。
func (s *Service) IssueAccessToken(ctx context.Context, caller Caller, request IssueAccessTokenRequest) (IssuedToken, error) {
	ctx = normalizeContext(ctx)
	if err := s.validateCaller(ctx, caller); err != nil {
		return IssuedToken{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_request_id", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if request.GrantType == "refresh_token" {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "refresh_not_supported", ErrRefreshNotSupported)
		return IssuedToken{}, ErrRefreshNotSupported
	}
	if !request.GrantType.Valid() {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_grant_type", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: 授权类型无效", ErrInvalidRequest)
	}
	scopes, err := oauthclient.ParseScopes(request.Scopes)
	if err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_scopes", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: Scope 列表非法", ErrInvalidRequest)
	}
	audiences, err := oauthclient.ParseAudiences(request.Audiences)
	if err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_audiences", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: 目标资源列表非法", ErrInvalidRequest)
	}
	if len(audiences) == 0 {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "audience_required", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: Access Token 必须声明目标资源 audience", ErrInvalidRequest)
	}
	client, err := s.loadClient(ctx, request.ClientID)
	if err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "client_unavailable", err)
		return IssuedToken{}, err
	}
	if !grantAllowed(client, request.GrantType) {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "grant_not_allowed", ErrGrantNotAllowed)
		return IssuedToken{}, ErrGrantNotAllowed
	}
	if !containsAll(client.Scopes, scopes) {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "scope_not_allowed", ErrScopeNotAllowed)
		return IssuedToken{}, ErrScopeNotAllowed
	}
	if !containsAll(client.Audiences, audiences) {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "audience_not_allowed", ErrAudienceNotAllowed)
		return IssuedToken{}, ErrAudienceNotAllowed
	}
	subject, err := s.resolveSubject(ctx, caller, request, client)
	if err != nil {
		return IssuedToken{}, err
	}
	issuance := IssuanceRequest{
		ClientID: client.ClientID, SubjectUserID: request.SubjectUserID,
		GrantType: request.GrantType, Scopes: scopes, Audiences: audiences, TokenKind: TokenUseAccess,
	}
	if err := s.opts.Authorizer.AuthorizeIssuance(ctx, caller, issuance); err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "issuance_not_authorized", ErrAccessDenied)
		return IssuedToken{}, ErrAccessDenied
	}
	key, err := s.ensureActiveKey(ctx)
	if err != nil {
		return IssuedToken{}, err
	}
	now := s.clockNow()
	tokenID, err := s.newTokenID()
	if err != nil {
		return IssuedToken{}, err
	}
	subjectType := TokenSubjectTypeUser
	if request.GrantType == GrantClientCredentials {
		subjectType = TokenSubjectTypeService
	}
	claims := accessTokenClaims{
		Issuer: s.opts.Issuer, Subject: subject, Audience: audiences,
		ClientID: client.ClientID, Scope: strings.Join(scopes, " "), TokenUse: TokenUseAccess,
		SubjectType: subjectType,
		IssuedAt:    now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(s.accessTTL).Unix(),
		TokenID: tokenID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("%w: 无法编码 Access Token 声明", ErrInternal)
	}
	compact, err := s.signClaims(key, payload, AccessTokenType)
	if err != nil {
		return IssuedToken{}, err
	}
	issued := IssuedToken{
		Token: Token{value: compact}, TokenID: tokenID, KeyID: key.Kid,
		IssuedAt: now, ExpiresAt: now.Add(s.accessTTL), Subject: subject, Audience: audiences,
	}
	auditChanges := []audit.FieldChange{
		{Field: "subject", After: subject},
		{Field: "client_id", After: client.ClientID},
		{Field: "audience", After: strings.Join(audiences, " ")},
		{Field: "scope", After: strings.Join(scopes, " ")},
		{Field: "token_use", After: TokenUseAccess},
		{Field: "jti", After: tokenID},
		{Field: "kid", After: key.Kid},
		{Field: "expires_at", After: issued.ExpiresAt.UTC().Format(time.RFC3339)},
	}
	if err := s.recordIssued(ctx, caller, "token.access.issued", "oauth_client",
		client.ClientID, auditChanges, request.RequestID); err != nil {
		return IssuedToken{}, err
	}
	s.logger.Info("Access Token 已签发",
		"client_id", client.ClientID, "subject", subject, "jti", tokenID, "kid", key.Kid)
	return issued, nil
}

// IssueIDToken 签发 ID Token。只允许代表真实用户主体（Authorization Code/Device
// Code 流程完成后），普通用户只能为自己签发；audience 固定为 client_id。
func (s *Service) IssueIDToken(ctx context.Context, caller Caller, request IssueIDTokenRequest) (IssuedToken, error) {
	ctx = normalizeContext(ctx)
	if err := s.validateCaller(ctx, caller); err != nil {
		return IssuedToken{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_request_id", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.SubjectUserID) {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_subject", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: ID Token 主体无效", ErrInvalidRequest)
	}
	if caller.IsUser() && caller.actor.ID != request.SubjectUserID {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "subject_not_self", ErrSubjectNotAllowed)
		return IssuedToken{}, ErrSubjectNotAllowed
	}
	if !validNonce(request.Nonce) {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_nonce", ErrInvalidRequest)
		return IssuedToken{}, fmt.Errorf("%w: nonce 非法", ErrInvalidRequest)
	}
	claimSubject := request.SubjectUserID
	if request.Subject != "" {
		if !validPairwiseSubject(request.Subject) {
			s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_claim_subject", ErrInvalidRequest)
			return IssuedToken{}, fmt.Errorf("%w: ID Token 主体声明无效", ErrInvalidRequest)
		}
		claimSubject = request.Subject
	}
	amr, err := normalizeAMR(request.AMR)
	if err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_amr", ErrInvalidRequest)
		return IssuedToken{}, err
	}
	if err := validACR(request.ACR); err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "invalid_acr", ErrInvalidRequest)
		return IssuedToken{}, err
	}
	client, err := s.loadClient(ctx, request.ClientID)
	if err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", request.ClientID, "client_unavailable", err)
		return IssuedToken{}, err
	}
	// ID Token 只能产生于授权码/设备码流程；client_credentials 与未登记授权码的
	// 客户端不得凭 ID Token 接口获得身份令牌（步骤 52 会使用本校验）。
	if !grantAllowed(client, GrantAuthorizationCode) && !grantAllowed(client, GrantDeviceCode) {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID,
			"id_token_grant_not_allowed", ErrGrantNotAllowed)
		return IssuedToken{}, ErrGrantNotAllowed
	}
	issuance := IssuanceRequest{
		ClientID: client.ClientID, SubjectUserID: request.SubjectUserID,
		GrantType: GrantAuthorizationCode, TokenKind: TokenUseID,
	}
	if err := s.opts.Authorizer.AuthorizeIssuance(ctx, caller, issuance); err != nil {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "id_token_not_authorized", ErrAccessDenied)
		return IssuedToken{}, ErrAccessDenied
	}
	key, err := s.ensureActiveKey(ctx)
	if err != nil {
		return IssuedToken{}, err
	}
	now := s.clockNow()
	tokenID, err := s.newTokenID()
	if err != nil {
		return IssuedToken{}, err
	}
	claims := idTokenClaims{
		Issuer: s.opts.Issuer, Subject: claimSubject, Audience: client.ClientID,
		ClientID: client.ClientID, AuthorizedParty: client.ClientID, TokenUse: TokenUseID,
		Nonce: request.Nonce, AMR: amr, ACR: request.ACR,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(s.idTokenTTL).Unix(), TokenID: tokenID,
	}
	if !request.AuthTime.IsZero() {
		claims.AuthTime = request.AuthTime.UTC().Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return IssuedToken{}, fmt.Errorf("%w: 无法编码 ID Token 声明", ErrInternal)
	}
	compact, err := s.signClaims(key, payload, IDTokenType)
	if err != nil {
		return IssuedToken{}, err
	}
	issued := IssuedToken{
		Token: Token{value: compact}, TokenID: tokenID, KeyID: key.Kid,
		IssuedAt: now, ExpiresAt: now.Add(s.idTokenTTL), Subject: claimSubject,
		Audience: []string{client.ClientID},
	}
	idAuditChanges := []audit.FieldChange{
		{Field: "subject", After: request.SubjectUserID},
		{Field: "client_id", After: client.ClientID},
		{Field: "token_use", After: TokenUseID},
		{Field: "jti", After: tokenID},
		{Field: "kid", After: key.Kid},
		{Field: "expires_at", After: issued.ExpiresAt.UTC().Format(time.RFC3339)},
	}
	if err := s.recordIssued(ctx, caller, "token.id_token.issued", "oauth_client",
		client.ClientID, idAuditChanges, request.RequestID); err != nil {
		return IssuedToken{}, err
	}
	s.logger.Info("ID Token 已签发", "client_id", client.ClientID, "jti", tokenID, "kid", key.Kid)
	return issued, nil
}

// VerifyAccessToken 验证 Access Token 并返回声明：固定允许算法 ES256、typ=at+jwt、
// token_use=access、issuer 固定、audience 必须包含 expectedAudience、kid 必须属于
// 当前可验证密钥集合（active 或保留期内 retired，revoked 拒绝），拒绝 jku/x5u/x5c/
// jwk/crit 等未受控密钥引用，有效期按可注入时钟与容差校验。
func (s *Service) VerifyAccessToken(ctx context.Context, raw, expectedAudience string) (AccessClaims, error) {
	ctx = normalizeContext(ctx)
	if expectedAudience == "" {
		return AccessClaims{}, fmt.Errorf("%w: 期望 audience 为空", ErrInvalidRequest)
	}
	claims, err := s.verifyJWS(ctx, raw, AccessTokenType)
	if err != nil {
		return AccessClaims{}, err
	}
	var access accessTokenClaims
	if err := decodeClaimsStrict(claims.payload, &access); err != nil {
		return AccessClaims{}, ErrMalformedToken
	}
	if err := s.validateAccessClaims(access, expectedAudience); err != nil {
		return AccessClaims{}, err
	}
	return AccessClaims{
		Issuer: access.Issuer, Subject: access.Subject, Audience: access.Audience,
		ClientID: access.ClientID, Scopes: strings.Fields(access.Scope),
		TokenID: access.TokenID, TokenUse: access.TokenUse,
		SubjectType: access.SubjectType,
		IssuedAt:    time.Unix(access.IssuedAt, 0).UTC(),
		NotBefore: func() time.Time {
			if access.NotBefore == 0 {
				return time.Time{}
			}
			return time.Unix(access.NotBefore, 0).UTC()
		}(),
		ExpiresAt: time.Unix(access.ExpiresAt, 0).UTC(), KeyID: claims.kid,
	}, nil
}

// VerifyIDToken 验证 ID Token：typ=JWT、token_use=id、audience 精确等于 clientID，
// 其余签名/密钥/时间校验与 Access Token 相同；ID Token 不能用于业务 API。
func (s *Service) VerifyIDToken(ctx context.Context, raw, clientID string) (IDTokenClaims, error) {
	ctx = normalizeContext(ctx)
	if clientID == "" {
		return IDTokenClaims{}, fmt.Errorf("%w: clientID 为空", ErrInvalidRequest)
	}
	verified, err := s.verifyJWS(ctx, raw, IDTokenType)
	if err != nil {
		return IDTokenClaims{}, err
	}
	var idToken idTokenClaims
	if err := decodeClaimsStrict(verified.payload, &idToken); err != nil {
		return IDTokenClaims{}, ErrMalformedToken
	}
	if idToken.TokenUse != TokenUseID {
		return IDTokenClaims{}, ErrWrongType
	}
	if idToken.Issuer != s.opts.Issuer {
		return IDTokenClaims{}, ErrWrongIssuer
	}
	if idToken.Audience != clientID {
		return IDTokenClaims{}, ErrAudienceMismatch
	}
	// aud 为单一 client_id；若声明 azp，必须与 client_id 一致（多值 aud 时必填）。
	if idToken.AuthorizedParty != "" && idToken.AuthorizedParty != clientID {
		return IDTokenClaims{}, ErrAudienceMismatch
	}
	// sub 允许真实用户 ID（public 约定）或按客户端配对的稳定假名（pairwise）。
	if (!account.ValidUserID(idToken.Subject) && !validPairwiseSubject(idToken.Subject)) ||
		idToken.TokenID == "" || idToken.ClientID == "" {
		return IDTokenClaims{}, ErrMissingClaims
	}
	if idToken.ExpiresAt <= 0 {
		return IDTokenClaims{}, ErrMissingClaims
	}
	now := s.clockNow()
	if !now.Before(time.Unix(idToken.ExpiresAt, 0).Add(s.clockSkew)) {
		return IDTokenClaims{}, ErrTokenExpired
	}
	if idToken.IssuedAt <= 0 || time.Unix(idToken.IssuedAt, 0).After(now.Add(s.clockSkew)) {
		return IDTokenClaims{}, ErrTokenNotYetValid
	}
	claims := IDTokenClaims{
		Issuer: idToken.Issuer, Subject: idToken.Subject, Audience: idToken.Audience,
		ClientID: idToken.ClientID, AuthorizedParty: idToken.AuthorizedParty,
		TokenID: idToken.TokenID, TokenUse: idToken.TokenUse,
		Nonce: idToken.Nonce, AMR: append([]string(nil), idToken.AMR...), ACR: idToken.ACR,
		IssuedAt:  time.Unix(idToken.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(idToken.ExpiresAt, 0).UTC(), KeyID: verified.kid,
	}
	if idToken.AuthTime > 0 {
		claims.AuthTime = time.Unix(idToken.AuthTime, 0).UTC()
	}
	return claims, nil
}

// verifiedJWS 是已验证签名的最小结果（payload + kid）。
type verifiedJWS struct {
	payload []byte
	kid     string
	alg     string
}

// verifyJWS 完成 JWS 解析、头部安全校验、密钥查找与签名验证；不验证业务声明。
func (s *Service) verifyJWS(ctx context.Context, raw, expectedType string) (verifiedJWS, error) {
	if raw == "" || len(raw) > MaxTokenBytes || strings.Count(raw, ".") != 2 {
		return verifiedJWS{}, ErrMalformedToken
	}
	parts := strings.Split(raw, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerJSON) == 0 || len(headerJSON) > 4096 {
		return verifiedJWS{}, ErrMalformedToken
	}
	// 严格拒绝重复顶层/嵌套字段，避免 encoding/json 覆盖语义造成头部/声明歧义。
	if err := rejectDuplicateJSONFields(headerJSON); err != nil {
		return verifiedJWS{}, ErrMalformedToken
	}
	var rawHeader map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &rawHeader); err != nil {
		return verifiedJWS{}, ErrMalformedToken
	}
	// 关键安全边界：绝不允许令牌头部指定远程/内嵌密钥或关键扩展。
	for _, forbidden := range []string{"jku", "x5u", "x5c", "jwk", "crit", "enc"} {
		if _, exists := rawHeader[forbidden]; exists {
			return verifiedJWS{}, ErrMaliciousKeyRef
		}
	}
	alg, typ, kid, err := readJWSHeader(rawHeader)
	if err != nil {
		return verifiedJWS{}, err
	}
	if alg != AlgorithmES256 {
		return verifiedJWS{}, ErrWrongAlgorithm
	}
	if typ != expectedType {
		return verifiedJWS{}, ErrWrongType
	}
	if !validKeyID(kid) {
		return verifiedJWS{}, ErrUnknownKey
	}
	object, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return verifiedJWS{}, ErrMalformedToken
	}
	if len(object.Signatures) != 1 {
		return verifiedJWS{}, ErrMalformedToken
	}
	signature := object.Signatures[0]
	if signature.Header.KeyID != kid || signature.Header.Algorithm != AlgorithmES256 ||
		signature.Header.JSONWebKey != nil {
		return verifiedJWS{}, ErrMalformedToken
	}
	record, found, err := s.opts.Store.GetKey(ctx, kid)
	if err != nil {
		return verifiedJWS{}, ErrStoreUnavailable
	}
	if !found || record.Algorithm != AlgorithmES256 {
		return verifiedJWS{}, ErrUnknownKey
	}
	now := s.clockNow()
	if record.Status == KeyRevoked {
		return verifiedJWS{}, ErrKeyRevoked
	}
	if !record.Verifiable(now) {
		return verifiedJWS{}, ErrUnknownKey
	}
	var publicKey jose.JSONWebKey
	if err := json.Unmarshal(record.PublicJWK, &publicKey); err != nil || !publicKey.IsPublic() {
		return verifiedJWS{}, ErrUnknownKey
	}
	payload, err := object.Verify(&publicKey)
	if err != nil {
		return verifiedJWS{}, ErrSignatureInvalid
	}
	if len(payload) == 0 || len(payload) > maxClaimBytes {
		return verifiedJWS{}, ErrMalformedToken
	}
	return verifiedJWS{payload: payload, kid: kid, alg: alg}, nil
}

// readJWSHeader 严格读取头部 alg/typ/kid 三个字符串字段。
func readJWSHeader(raw map[string]json.RawMessage) (string, string, string, error) {
	read := func(name string) (string, error) {
		value, exists := raw[name]
		if !exists {
			return "", ErrMalformedToken
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return "", ErrMalformedToken
		}
		return text, nil
	}
	alg, err := read("alg")
	if err != nil {
		return "", "", "", err
	}
	typ, err := read("typ")
	if err != nil {
		return "", "", "", err
	}
	kid, err := read("kid")
	if err != nil {
		return "", "", "", err
	}
	return alg, typ, kid, nil
}

// decodeClaimsStrict 解码声明 JSON 并拒绝重复的顶层字段（防止解析差异/覆盖攻击）。
func decodeClaimsStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	seen := make(map[string]struct{})
	first, err := decoder.Token()
	if err != nil {
		return ErrMalformedToken
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return ErrMalformedToken
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrMalformedToken
		}
		key, ok := token.(string)
		if !ok {
			return ErrMalformedToken
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrMalformedToken
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return ErrMalformedToken
		}
	}
	if _, err := decoder.Token(); err != nil {
		return ErrMalformedToken
	}
	if decoder.More() {
		return ErrMalformedToken
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return ErrMalformedToken
	}
	return nil
}

// validateAccessClaims 校验 Access Token 的 iss/aud/type/时间/必需声明。
func (s *Service) validateAccessClaims(claims accessTokenClaims, expectedAudience string) error {
	if claims.Issuer != s.opts.Issuer {
		return ErrWrongIssuer
	}
	if claims.TokenUse != TokenUseAccess {
		return ErrWrongType
	}
	if claims.Subject == "" || claims.ClientID == "" || claims.TokenID == "" || len(claims.Audience) == 0 {
		return ErrMissingClaims
	}
	switch claims.SubjectType {
	case "", TokenSubjectTypeUser:
		// 旧令牌缺失 subject_type 按用户令牌解释。
	case TokenSubjectTypeService:
		// 服务身份令牌的 subject 必须就是客户端自身，绝不能是用户/root。
		if claims.Subject != claims.ClientID {
			return ErrMissingClaims
		}
	default:
		return ErrMissingClaims
	}
	if claims.ExpiresAt <= 0 {
		return ErrMissingClaims
	}
	audienceMatched := false
	for _, audience := range claims.Audience {
		if subtle.ConstantTimeCompare([]byte(audience), []byte(expectedAudience)) == 1 {
			audienceMatched = true
			break
		}
	}
	if !audienceMatched {
		return ErrAudienceMismatch
	}
	now := s.clockNow()
	if !now.Before(time.Unix(claims.ExpiresAt, 0).Add(s.clockSkew)) {
		return ErrTokenExpired
	}
	if claims.IssuedAt <= 0 {
		return ErrMissingClaims
	}
	if time.Unix(claims.IssuedAt, 0).After(now.Add(s.clockSkew)) {
		return ErrTokenNotYetValid
	}
	if claims.NotBefore > 0 && time.Unix(claims.NotBefore, 0).After(now.Add(s.clockSkew)) {
		return ErrTokenNotYetValid
	}
	return nil
}

// validateCaller 校验调用者是已定义的可信身份（匿名/未知身份拒绝）。
func (s *Service) validateCaller(ctx context.Context, caller Caller) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if caller.actor.Type == audit.ActorAnonymous {
		s.recordFailure(ctx, caller.actor, "token.issuance_denied", "oauth_client", "unknown",
			"anonymous_caller", string(CodeAccessDenied))
		return ErrAccessDenied
	}
	return nil
}

// loadClient 读取并校验客户端登记信息（应用停用返回 CLIENT_DISABLED）。
func (s *Service) loadClient(ctx context.Context, clientID string) (ClientInfo, error) {
	if !validApplicationClientID(clientID) {
		return ClientInfo{}, fmt.Errorf("%w: 客户端标识无效", ErrInvalidRequest)
	}
	client, err := s.opts.Clients.LoadClient(ctx, clientID)
	if err != nil {
		switch {
		case errors.Is(err, ErrClientNotFound):
			return ClientInfo{}, ErrClientNotFound
		case errors.Is(err, ErrClientInactive):
			return ClientInfo{}, ErrClientInactive
		case errors.Is(err, ErrStoreUnavailable):
			return ClientInfo{}, ErrStoreUnavailable
		default:
			return ClientInfo{}, ErrClientNotFound
		}
	}
	if client.ClientID != clientID {
		return ClientInfo{}, ErrClientNotFound
	}
	if !client.AppActive {
		return ClientInfo{}, ErrClientInactive
	}
	return client, nil
}

// grantAllowed 报告客户端是否登记了该授权类型。
func grantAllowed(client ClientInfo, grant GrantType) bool {
	for _, registered := range client.GrantTypes {
		if registered == string(grant) {
			return true
		}
	}
	return false
}

// resolveSubject 校验签发主体归属：普通用户只能为自己签发；client_credentials 只
// 允许保密客户端且主体为客户端自身；系统/本地管理员代表其他主体时仍须通过
// IssuanceAuthorizer（在调用方之后单独判定）。
func (s *Service) resolveSubject(ctx context.Context, caller Caller, request IssueAccessTokenRequest, client ClientInfo) (string, error) {
	if request.GrantType == GrantClientCredentials {
		// 服务身份令牌只能由受信系统/本地管理员通道（完成客户端认证后的编排层）
		// 签发；普通用户会话不能替客户端铸造服务令牌，不借用负责人或 root 身份。
		if caller.IsUser() {
			s.denyIssuance(ctx, caller, "oauth_client", client.ClientID,
				"client_credentials_user_caller", ErrAccessDenied)
			return "", ErrAccessDenied
		}
		clientType := strings.ToLower(strings.TrimSpace(client.ClientType))
		if clientType != "confidential" {
			s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "client_credentials_requires_confidential", ErrGrantNotAllowed)
			return "", ErrGrantNotAllowed
		}
		if request.SubjectUserID != "" {
			s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "client_credentials_subject_not_allowed", ErrSubjectNotAllowed)
			return "", ErrSubjectNotAllowed
		}
		return client.ClientID, nil
	}
	if !account.ValidUserID(request.SubjectUserID) {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "invalid_user_subject", ErrInvalidRequest)
		return "", fmt.Errorf("%w: 用户主体标识无效", ErrInvalidRequest)
	}
	if caller.IsUser() && caller.actor.ID != request.SubjectUserID {
		s.denyIssuance(ctx, caller, "oauth_client", client.ClientID, "subject_not_self", ErrSubjectNotAllowed)
		return "", ErrSubjectNotAllowed
	}
	return request.SubjectUserID, nil
}

// recordIssued 写成功审计（不含令牌原文）。签发是安全关键操作：审计不可用时整个
// 签发按失败处理（token 不返回、不写日志成功），避免出现“有令牌无审计”的不一致。
func (s *Service) recordIssued(ctx context.Context, caller Caller, action, targetType, targetID string,
	changes []audit.FieldChange, requestID string) error {
	event := audit.Event{
		Actor: caller.actor, Action: action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: audit.OutcomeSuccess, Changes: changes,
	}
	if account.ValidateRequestID(requestID) == nil {
		event.RequestID = requestID
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.logger.Warn("令牌签发审计写入失败，按 fail-closed 拒绝签发",
			"action", action, "error_category", "audit_unavailable")
		return ErrAuditUnavailable
	}
	return nil
}

// denyIssuance 写失败审计（不含令牌/秘密）。
func (s *Service) denyIssuance(ctx context.Context, caller Caller, targetType, targetID, reason string, cause error) {
	s.recordFailure(ctx, caller.actor, "token.issuance_denied", targetType, targetID, reason,
		string(CodeOf(cause)))
}

// newTokenID 生成 128 位安全随机 jti。
func (s *Service) newTokenID() (string, error) {
	buffer := make([]byte, jtiRandomBytes)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成令牌标识", ErrInternal)
	}
	return "jti_" + hex.EncodeToString(buffer), nil
}

// validNonce 校验 OIDC nonce：可选、长度有界、仅可见 ASCII。
// validPairwiseSubject 校验 ID Token 的 sub 假名：base64url（无填充）稳定标识。
func validPairwiseSubject(subject string) bool {
	if len(subject) < 16 || len(subject) > 128 {
		return false
	}
	for index := 0; index < len(subject); index++ {
		character := subject[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

// normalizeAMR 校验并去重 OIDC amr 取值（RFC 8176 稳定方法引用）。
func normalizeAMR(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 10 {
		return nil, fmt.Errorf("%w: amr 数量过多", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) == 0 || len(value) > 32 {
			return nil, fmt.Errorf("%w: amr 取值无效", ErrInvalidRequest)
		}
		for index := 0; index < len(value); index++ {
			character := value[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
				continue
			}
			return nil, fmt.Errorf("%w: amr 取值无效", ErrInvalidRequest)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

// validACR 校验内部稳定性 ACR 标识（不宣称外部认证等级承诺）。
func validACR(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 128 || !strings.HasPrefix(value, "urn:evernight:acr:") {
		return fmt.Errorf("%w: acr 取值无效", ErrInvalidRequest)
	}
	return nil
}

func validNonce(nonce string) bool {
	if nonce == "" {
		return true
	}
	if len(nonce) > 256 {
		return false
	}
	for _, r := range nonce {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
