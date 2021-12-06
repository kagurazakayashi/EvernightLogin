package loginte2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// runJWKSSuite 拉取 JWKS 并用标准库 crypto 独立验证 ID Token。
func (r *Runner) runJWKSSuite(ctx context.Context) error {
	document, err := r.document(ctx)
	if err != nil {
		return err
	}
	var (
		jwksPayload []byte
		idToken     string
		nonce       string
	)
	r.run("jwks_document", func() error {
		payload, fetchErr := r.client.jwks(ctx)
		if fetchErr != nil {
			return fetchErr
		}
		if _, parseErr := parseJWKS(payload); parseErr != nil {
			return parseErr
		}
		jwksPayload = payload
		return nil
	})
	r.run("jwks_signing_key_metadata", func() error {
		if jwksPayload == nil {
			return skipf("前置用例未取得 JWKS")
		}
		set, parseErr := parseJWKS(jwksPayload)
		if parseErr != nil {
			return parseErr
		}
		allowed := allowedIDTokenAlgorithms(document)
		for index := range set.Keys {
			key := set.Keys[index]
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			if key.Kid == "" {
				return fmt.Errorf("签名公钥缺少 kid（无法处理轮换）")
			}
			if key.Alg != "" && !containsString(allowed, key.Alg) {
				return fmt.Errorf("公钥 alg=%q 不在 Discovery 声明的签名算法内", key.Alg)
			}
			return nil
		}
		return fmt.Errorf("JWKS 中没有可用于验签的公钥")
	})

	if err := r.requireRedirect(); err != nil {
		for _, name := range []string{"id_token_signature_and_claims",
			"id_token_tamper_rejected", "id_token_nonce_mismatch_rejected"} {
			r.run(name, func() error { return err })
		}
		return nil
	}
	if err := r.requireSession(); err != nil {
		for _, name := range []string{"id_token_signature_and_claims",
			"id_token_tamper_rejected", "id_token_nonce_mismatch_rejected"} {
			r.run(name, func() error { return err })
		}
		return nil
	}

	r.run("id_token_signature_and_claims", func() error {
		obtained, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		issued, err := r.client.exchangeAuthorizationCode(ctx, obtained.Code, obtained.Verifier)
		if err != nil {
			return err
		}
		if issued.IDToken == "" {
			return fmt.Errorf("令牌响应缺少 id_token")
		}
		if jwksPayload == nil {
			payload, fetchErr := r.client.jwks(ctx)
			if fetchErr != nil {
				return fetchErr
			}
			jwksPayload = payload
		}
		claims, verifyErr := VerifyIDToken(issued.IDToken, jwksPayload, VerifyExpectations{
			Issuer: document.Issuer, ClientID: r.client.cfg.ClientID, Nonce: obtained.Nonce,
			Now: r.client.nowTime(), AllowedAlgorithms: allowedIDTokenAlgorithms(document)})
		if verifyErr != nil {
			return verifyErr
		}
		if strings.TrimSpace(claims.Subject) == "" {
			return fmt.Errorf("ID Token 缺少 sub")
		}
		idToken = issued.IDToken
		nonce = obtained.Nonce
		return nil
	})

	r.run("id_token_tamper_rejected", func() error {
		if idToken == "" {
			return skipf("前置用例未取得 ID Token")
		}
		if jwksPayload == nil {
			return skipf("前置用例未取得 JWKS")
		}
		expect := VerifyExpectations{Issuer: document.Issuer,
			ClientID: r.client.cfg.ClientID, Nonce: nonce, Now: r.client.nowTime(),
			AllowedAlgorithms: allowedIDTokenAlgorithms(document)}
		if _, verifyErr := VerifyIDToken(tamperPayload(idToken), jwksPayload, expect); verifyErr == nil {
			return fmt.Errorf("篡改载荷后的 ID Token 仍通过验签")
		}
		if _, verifyErr := VerifyIDToken(algNoneToken(idToken), jwksPayload, expect); verifyErr == nil {
			return fmt.Errorf("alg=none 的 ID Token 仍通过验签")
		}
		return nil
	})

	r.run("id_token_nonce_mismatch_rejected", func() error {
		if idToken == "" {
			return skipf("前置用例未取得 ID Token")
		}
		if jwksPayload == nil {
			return skipf("前置用例未取得 JWKS")
		}
		wrongNonce, err := NewNonce()
		if err != nil {
			return err
		}
		expect := VerifyExpectations{Issuer: document.Issuer,
			ClientID: r.client.cfg.ClientID, Nonce: wrongNonce, Now: r.client.nowTime(),
			AllowedAlgorithms: allowedIDTokenAlgorithms(document)}
		if _, verifyErr := VerifyIDToken(idToken, jwksPayload, expect); verifyErr == nil {
			return fmt.Errorf("nonce 不匹配的 ID Token 仍通过验证")
		}
		return nil
	})
	return nil
}

// allowedIDTokenAlgorithms 返回本工具支持的、且 Discovery 声明的签名算法集合。
func allowedIDTokenAlgorithms(document *DiscoveryDocument) []string {
	supported := []string{"ES256", "RS256", "PS256"}
	if document == nil || len(document.IDTokenSigningAlgValuesSupported) == 0 {
		return []string{"ES256"}
	}
	var allowed []string
	for _, algorithm := range document.IDTokenSigningAlgValuesSupported {
		if containsString(supported, algorithm) || algorithm == "RS384" {
			allowed = append(allowed, algorithm)
		}
	}
	if len(allowed) == 0 {
		return []string{"ES256"}
	}
	return allowed
}

// tamperPayload 返回一个“载荷被改、签名未变”的 JWT，用来证明验签不是空操作。
func tamperPayload(raw string) string {
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return raw
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return raw
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return raw
	}
	claims["sub"] = "usr_00000000000000000000000000000000"
	modified, err := json.Marshal(claims)
	if err != nil {
		return raw
	}
	segments[1] = base64.RawURLEncoding.EncodeToString(modified)
	return strings.Join(segments, ".")
}

// algNoneToken 返回 alg=none 且签名为空的 JWT，验证器必须拒绝。
func algNoneToken(raw string) string {
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return raw
	}
	header, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return raw
	}
	var parsed map[string]any
	if err := json.Unmarshal(header, &parsed); err != nil {
		return raw
	}
	parsed["alg"] = "none"
	modified, err := json.Marshal(parsed)
	if err != nil {
		return raw
	}
	return base64.RawURLEncoding.EncodeToString(modified) + "." + segments[1] + "."
}
