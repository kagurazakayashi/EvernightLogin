package loginte2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// 本文件用标准库构造真实 ES256 密钥与 JWT，验证 VerifyIDToken 不是空操作。
// 不引入第三方 JOSE 库（与工具本身的依赖约束一致）。

const testKeyID = "test-signing-key-1"

// testSigner 是 ES256 测试签名器。
type testSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

// newTestSigner 生成 P-256 私钥。
func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	return &testSigner{key: key, kid: testKeyID}
}

// jwksJSON 生成对应 JWKS 文档。
func (s *testSigner) jwksJSON(t *testing.T) []byte {
	t.Helper()
	size := (s.key.Curve.Params().BitSize + 7) / 8
	encode := func(value *big.Int) string {
		buffer := make([]byte, size)
		value.FillBytes(buffer)
		return base64.RawURLEncoding.EncodeToString(buffer)
	}
	document := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": s.kid, "use": "sig", "alg": "ES256",
		"x": encode(s.key.X), "y": encode(s.key.Y),
	}}}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("编码 JWKS 失败: %v", err)
	}
	return payload
}

// sign 用指定算法签名声明（alg 非 ES256 时用于 alg=none 负例构造）。
func (s *testSigner) sign(t *testing.T, claims map[string]any, alg string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": alg, "kid": s.kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("编码 JWT 头部失败: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("编码 JWT 载荷失败: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	if alg == "none" {
		return signingInput + "."
	}
	digest := sha256.Sum256([]byte(signingInput))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	size := (s.key.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, size*2)
	r.FillBytes(signature[:size])
	ss.FillBytes(signature[size:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// validClaims 返回一组会通过校验的声明。
func validClaims(issuer, audience, nonce string, now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": audience, "sub": "usr_00000000000000000000000000000001",
		"nonce": nonce, "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "auth_time": now.Unix(), "amr": []string{"pwd"},
	}
}

// expect 返回与有效声明匹配的期望值。
func expectFor(issuer, clientID, nonce string, now time.Time) VerifyExpectations {
	return VerifyExpectations{Issuer: issuer, ClientID: clientID, Nonce: nonce, Now: now,
		AllowedAlgorithms: []string{"ES256"}}
}

// TestVerifyIDTokenValid 验证正确的 ES256 ID Token 可以通过签名与声明校验。
func TestVerifyIDTokenValid(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	claims := signer.sign(t, validClaims("https://issuer.example.test",
		"app_00000000000000000000000000000001", "nonce-value", now), "ES256")
	verified, err := VerifyIDToken(claims, signer.jwksJSON(t), expectFor(
		"https://issuer.example.test", "app_00000000000000000000000000000001",
		"nonce-value", now))
	if err != nil {
		t.Fatalf("合法 ID Token 校验失败: %v", err)
	}
	if verified.Subject == "" || verified.Algorithm != "ES256" {
		t.Fatalf("校验结果字段不完整: %+v", verified)
	}
}

// TestVerifyIDTokenRejects 覆盖签名/声明不匹配的各种负例。
func TestVerifyIDTokenRejects(t *testing.T) {
	signer := newTestSigner(t)
	jwks := signer.jwksJSON(t)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	issuer := "https://issuer.example.test"
	clientID := "app_00000000000000000000000000000001"

	cases := []struct {
		name   string
		token  func() string
		expect VerifyExpectations
	}{
		{
			name: "nonce mismatch",
			token: func() string {
				return signer.sign(t, validClaims(issuer, clientID, "nonce-a", now), "ES256")
			},
			expect: expectFor(issuer, clientID, "nonce-b", now),
		},
		{
			name: "expired",
			token: func() string {
				claims := validClaims(issuer, clientID, "nonce", now)
				claims["exp"] = now.Add(-time.Minute).Unix()
				return signer.sign(t, claims, "ES256")
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
		{
			name: "wrong issuer",
			token: func() string {
				return signer.sign(t, validClaims("https://other.example.test", clientID,
					"nonce", now), "ES256")
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
		{
			name: "wrong audience",
			token: func() string {
				return signer.sign(t, validClaims(issuer, "app_other", "nonce", now), "ES256")
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
		{
			name: "alg none",
			token: func() string {
				return signer.sign(t, validClaims(issuer, clientID, "nonce", now), "none")
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
		{
			name: "tampered payload",
			token: func() string {
				return tamperPayload(signer.sign(t, validClaims(issuer, clientID, "nonce", now),
					"ES256"))
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
		{
			name: "wrong kid",
			token: func() string {
				other := newTestSigner(t)
				other.kid = "other-kid"
				return other.sign(t, validClaims(issuer, clientID, "nonce", now), "ES256")
			},
			expect: expectFor(issuer, clientID, "nonce", now),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := VerifyIDToken(testCase.token(), jwks, testCase.expect); err == nil {
				t.Fatalf("期望校验失败，实际通过")
			}
		})
	}
}

// TestParseJWKSRejectsInvalid 验证 JWKS 结构校验。
func TestParseJWKSRejectsInvalid(t *testing.T) {
	cases := []string{
		`{}`,
		`{"keys":[]}`,
		`not-json`,
		`{"keys":[{"kty":"oct","k":"abc"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-384","x":"a","y":"b"}]}`,
	}
	for _, payload := range cases {
		if _, err := parseJWKS([]byte(payload)); err == nil {
			t.Fatalf("期望 JWKS 校验失败: %s", payload)
		}
	}
}
