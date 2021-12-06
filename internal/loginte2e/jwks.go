package loginte2e

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// 本文件用 Go 标准库实现 JWKS 解析与 JWT/JWS 签名验证（不引入第三方 JOSE 库）。
// 支持 ES256（本服务声明的唯一 ID Token 算法）与 RS256（通用性/未来兼容），
// 只接受显式算法，拒绝 "none" 与算法替换。

// jwksDocument 是 RFC 7517 公钥集合。
type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

// jsonWebKey 是 JWKS 中的单把公钥。只保留验证所需字段。
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseJWKS 解析并做基本结构校验（条数、kty、必填参数）。
func parseJWKS(payload []byte) (*jwksDocument, error) {
	var document jwksDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("JWKS 不是合法 JSON")
	}
	if len(document.Keys) == 0 {
		return nil, fmt.Errorf("JWKS 不含任何公钥")
	}
	for index := range document.Keys {
		key := document.Keys[index]
		switch key.Kty {
		case "EC":
			if key.Crv != "P-256" {
				return nil, fmt.Errorf("JWKS 第 %d 把 EC 公钥曲线不是 P-256", index)
			}
			if key.X == "" || key.Y == "" {
				return nil, fmt.Errorf("JWKS 第 %d 把 EC 公钥缺少 x/y", index)
			}
		case "RSA":
			if key.N == "" || key.E == "" {
				return nil, fmt.Errorf("JWKS 第 %d 把 RSA 公钥缺少 n/e", index)
			}
		default:
			return nil, fmt.Errorf("JWKS 第 %d 把公钥类型 %q 不受支持", index, key.Kty)
		}
	}
	return &document, nil
}

// IDTokenClaims 是工具关心的 ID Token 声明子集（不保存原始 JWT）。
type IDTokenClaims struct {
	Issuer    string
	Audience  []string
	Subject   string
	Nonce     string
	Expiry    time.Time
	IssuedAt  time.Time
	AuthTime  time.Time
	Methods   []string
	Algorithm string
	KeyID     string
}

// VerifyExpectations 是独立验证 ID Token 的期望值。
type VerifyExpectations struct {
	// Issuer 必须与 iss 完全一致（必填）。
	Issuer string
	// ClientID 必须出现在 aud 中（必填）。
	ClientID string
	// Nonce 必须与 nonce 声明完全一致（必填）。
	Nonce string
	// Now 是校验当前时间；nil 使用 time.Now。
	Now time.Time
	// AllowedAlgorithms 是允许的签名算法；空表示只允许 ES256（本服务声明值）。
	AllowedAlgorithms []string
}

// jwtParts 是拆分后的 JWT 三段。
type jwtParts struct{ header, payload, signature []byte }

// splitJWT 拆分紧凑序列化 JWT 并校验段数与 base64url 编码。
func splitJWT(raw string) (jwtParts, error) {
	segments := strings.Split(strings.TrimSpace(raw), ".")
	if len(segments) != 3 {
		return jwtParts{}, fmt.Errorf("ID Token 不是三段式 JWT")
	}
	decode := func(segment string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(segment)
	}
	header, err := decode(segments[0])
	if err != nil {
		return jwtParts{}, fmt.Errorf("ID Token 头部不是 base64url")
	}
	payload, err := decode(segments[1])
	if err != nil {
		return jwtParts{}, fmt.Errorf("ID Token 载荷不是 base64url")
	}
	signature, err := decode(segments[2])
	if err != nil {
		return jwtParts{}, fmt.Errorf("ID Token 签名不是 base64url")
	}
	return jwtParts{header: header, payload: payload, signature: signature}, nil
}

// jwtHeader 是 JWS 头部。
type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// audienceClaim 兼容 aud 是字符串或字符串数组两种编码。
type audienceClaim []string

// UnmarshalJSON 实现 aud 的双形态解析。
func (a *audienceClaim) UnmarshalJSON(payload []byte) error {
	var single string
	if err := json.Unmarshal(payload, &single); err == nil {
		*a = audienceClaim{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(payload, &multiple); err != nil {
		return errors.New("aud 既不是字符串也不是字符串数组")
	}
	*a = audienceClaim(multiple)
	return nil
}

// idTokenPayload 是解码后的声明。
type idTokenPayload struct {
	Issuer   string        `json:"iss"`
	Audience audienceClaim `json:"aud"`
	Subject  string        `json:"sub"`
	Nonce    string        `json:"nonce"`
	Expiry   int64         `json:"exp"`
	IssuedAt int64         `json:"iat"`
	AuthTime int64         `json:"auth_time"`
	Methods  []string      `json:"amr"`
}

// VerifyIDToken 用 JWKS 公钥独立验证 ID Token：签名、alg/kid、iss、aud、exp、nonce。
// 任何一项失败都拒绝；错误文本只含算法/kid/声明名，不含令牌内容。
func VerifyIDToken(raw string, jwksJSON []byte, expect VerifyExpectations) (*IDTokenClaims, error) {
	if expected := strings.TrimSpace(expect.Issuer); expected == "" {
		return nil, fmt.Errorf("验证期望缺少 issuer")
	}
	if strings.TrimSpace(expect.ClientID) == "" {
		return nil, fmt.Errorf("验证期望缺少 client_id")
	}
	parts, err := splitJWT(raw)
	if err != nil {
		return nil, err
	}
	var header jwtHeader
	if err := json.Unmarshal(parts.header, &header); err != nil {
		return nil, fmt.Errorf("ID Token 头部不是合法 JSON")
	}
	allowed := expect.AllowedAlgorithms
	if len(allowed) == 0 {
		allowed = []string{"ES256"}
	}
	if !containsString(allowed, header.Algorithm) {
		return nil, fmt.Errorf("ID Token 算法 %q 不在允许集合 %v 内", header.Algorithm, allowed)
	}
	set, err := parseJWKS(jwksJSON)
	if err != nil {
		return nil, err
	}
	verified := false
	for index := range set.Keys {
		key := set.Keys[index]
		if header.KeyID != "" && key.Kid != header.KeyID {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		signatureErr := verifyJWSSignature(header.Algorithm, key, parts)
		if signatureErr == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("ID Token 签名无法用 JWKS 验证（alg=%s kid=%q）",
			header.Algorithm, header.KeyID)
	}
	var payload idTokenPayload
	if err := json.Unmarshal(parts.payload, &payload); err != nil {
		return nil, fmt.Errorf("ID Token 载荷不是合法 JSON")
	}
	if payload.Issuer != expect.Issuer {
		return nil, fmt.Errorf("iss 不匹配：期望 %q，实际 %q", expect.Issuer, payload.Issuer)
	}
	if !containsString(payload.Audience, expect.ClientID) {
		return nil, fmt.Errorf("aud 不含期望的 client_id")
	}
	now := expect.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if payload.Expiry <= 0 {
		return nil, fmt.Errorf("ID Token 缺少 exp")
	}
	expiry := time.Unix(payload.Expiry, 0).UTC()
	if !expiry.After(now) {
		return nil, fmt.Errorf("ID Token 已过期（exp=%s）", expiry.Format(time.RFC3339))
	}
	if expect.Nonce != "" && payload.Nonce != expect.Nonce {
		return nil, fmt.Errorf("nonce 不匹配")
	}
	claims := &IDTokenClaims{
		Issuer: payload.Issuer, Audience: append([]string(nil), payload.Audience...),
		Subject: payload.Subject, Nonce: payload.Nonce, Expiry: expiry,
		Algorithm: header.Algorithm, KeyID: header.KeyID,
		Methods: append([]string(nil), payload.Methods...),
	}
	if payload.IssuedAt > 0 {
		claims.IssuedAt = time.Unix(payload.IssuedAt, 0).UTC()
	}
	if payload.AuthTime > 0 {
		claims.AuthTime = time.Unix(payload.AuthTime, 0).UTC()
	}
	return claims, nil
}

// verifyJWSSignature 按算法验证签名。
func verifyJWSSignature(algorithm string, key jsonWebKey, parts jwtParts) error {
	signingInput := []byte(base64.RawURLEncoding.EncodeToString(parts.header) + "." +
		base64.RawURLEncoding.EncodeToString(parts.payload))
	digest := sha256.Sum256(signingInput)
	switch algorithm {
	case "ES256":
		publicKey, err := ecdsaPublicKey(key)
		if err != nil {
			return err
		}
		if len(parts.signature) != 64 {
			return fmt.Errorf("ES256 签名长度不是 64 字节")
		}
		r := new(big.Int).SetBytes(parts.signature[:32])
		s := new(big.Int).SetBytes(parts.signature[32:])
		if !ecdsa.Verify(publicKey, digest[:], r, s) {
			return fmt.Errorf("ES256 签名验证失败")
		}
		return nil
	case "RS256", "PS256":
		publicKey, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		if algorithm == "RS256" {
			return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], parts.signature)
		}
		return rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], parts.signature,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "RS384":
		publicKey, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		sum := sha512.Sum384(signingInput)
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, sum[:], parts.signature)
	default:
		return fmt.Errorf("不支持的 JWS 算法 %q", algorithm)
	}
}

// ecdsaPublicKey 从 JWK 构造 P-256 ECDSA 公钥。
func ecdsaPublicKey(key jsonWebKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("JWK x 不是 base64url")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("JWK y 不是 base64url")
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("JWK 公钥不在 P-256 曲线上")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// rsaPublicKey 从 JWK 构造 RSA 公钥。
func rsaPublicKey(key jsonWebKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("JWK n 不是 base64url")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("JWK e 不是 base64url")
	}
	exponent := 0
	for _, value := range eBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent > 1<<31 {
		return nil, fmt.Errorf("JWK e 超出范围")
	}
	modulus := new(big.Int).SetBytes(nBytes)
	if modulus.BitLen() < 2048 {
		return nil, fmt.Errorf("JWK RSA 公钥长度不足 2048 位")
	}
	return &rsa.PublicKey{N: modulus, E: exponent}, nil
}

// containsString 判断切片是否包含指定字符串。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
