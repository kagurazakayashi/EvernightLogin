package loginte2e

import (
	"strings"
	"testing"
)

// TestChallengeForVerifierRFC7636 使用 RFC 7636 附录 B 的测试向量验证 S256 实现。
func TestChallengeForVerifierRFC7636(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := ChallengeForVerifier(verifier); got != want {
		t.Fatalf("S256 challenge = %q，期望 %q", got, want)
	}
}

// TestNewPKCE 验证新生成的 verifier/challenge 成对、长度符合 RFC 7636。
func TestNewPKCE(t *testing.T) {
	first, err := NewPKCE()
	if err != nil {
		t.Fatalf("生成 PKCE 失败: %v", err)
	}
	second, err := NewPKCE()
	if err != nil {
		t.Fatalf("生成 PKCE 失败: %v", err)
	}
	if first.Verifier == second.Verifier {
		t.Fatalf("两次生成的 verifier 不应相同")
	}
	if len(first.Verifier) < 43 || len(first.Verifier) > 128 {
		t.Fatalf("verifier 长度 %d 超出 RFC 7636 范围", len(first.Verifier))
	}
	if ChallengeForVerifier(first.Verifier) != first.Challenge {
		t.Fatalf("challenge 与 verifier 不匹配")
	}
	if strings.ContainsAny(first.Verifier, "=+/") {
		t.Fatalf("verifier 必须是 base64url 无填充字符集")
	}
}

// TestNewStateNonce 验证 state/nonce 随机且非空。
func TestNewStateNonce(t *testing.T) {
	state, err := NewState()
	if err != nil || state == "" {
		t.Fatalf("生成 state 失败: %v", err)
	}
	other, err := NewState()
	if err != nil || other == state {
		t.Fatalf("state 必须随机")
	}
	nonce, err := NewNonce()
	if err != nil || len(nonce) < 16 {
		t.Fatalf("生成 nonce 失败或过短: %v", err)
	}
}
