package credential

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestEncodeDigestMessageBindsEveryField 验证摘要输入对域、ID、用途、目标、应用
// 和秘密的每一项都敏感，避免搬移绑定信息后摘要不变。
func TestEncodeDigestMessageBindsEveryField(t *testing.T) {
	base := encodeDigestMessage("domain", "id", "purpose", "target", "app", "secret")
	if len(base) == 0 {
		t.Fatal("摘要输入为空")
	}
	variants := []struct {
		name    string
		message []byte
	}{
		{name: "域不同", message: encodeDigestMessage("domain2", "id", "purpose", "target", "app", "secret")},
		{name: "ID 不同", message: encodeDigestMessage("domain", "id2", "purpose", "target", "app", "secret")},
		{name: "用途不同", message: encodeDigestMessage("domain", "id", "purpose2", "target", "app", "secret")},
		{name: "目标不同", message: encodeDigestMessage("domain", "id", "purpose", "target2", "app", "secret")},
		{name: "应用不同", message: encodeDigestMessage("domain", "id", "purpose", "target", "app2", "secret")},
		{name: "秘密不同", message: encodeDigestMessage("domain", "id", "purpose", "target", "app", "secret2")},
	}
	for _, variant := range variants {
		if bytes.Equal(base, variant.message) {
			t.Fatalf("%s时摘要输入未变化", variant.name)
		}
	}
	if !bytes.Equal(base, encodeDigestMessage("domain", "id", "purpose", "target", "app", "secret")) {
		t.Fatal("相同输入产生不同摘要输入")
	}
}

// TestDigestFieldBoundaryIsUnambiguous 验证长度前缀能区分字段边界，防止
// "ab"+"c" 与 "a"+"bc" 这类拼接歧义。
func TestDigestFieldBoundaryIsUnambiguous(t *testing.T) {
	first := encodeDigestMessage("domain", "ab", "c", "target", "app", "secret")
	second := encodeDigestMessage("domain", "a", "bc", "target", "app", "secret")
	if bytes.Equal(first, second) {
		t.Fatal("字段边界存在拼接歧义")
	}
}

// TestTokenVerifierHash 验证高熵令牌摘要长度、确定性与域绑定。
func TestTokenVerifierHash(t *testing.T) {
	first := tokenVerifierHash("id", "purpose", "target", "app", "token")
	if len(first) != sha256.Size {
		t.Fatalf("摘要长度 = %d，期望 %d", len(first), sha256.Size)
	}
	if !bytes.Equal(first, tokenVerifierHash("id", "purpose", "target", "app", "token")) {
		t.Fatal("相同输入产生不同摘要")
	}
	if bytes.Equal(first, tokenVerifierHash("id", "purpose", "target", "app", "other-token")) {
		t.Fatal("不同令牌产生相同摘要")
	}
	expected := sha256.Sum256(encodeDigestMessage(tokenDigestDomain, "id", "purpose", "target", "app", "token"))
	if !bytes.Equal(first, expected[:]) {
		t.Fatal("令牌摘要未使用令牌域编码")
	}
}

// TestCodeDigestMessageIsDomainSeparated 验证验证码摘要输入与令牌摘要域分开。
func TestCodeDigestMessageIsDomainSeparated(t *testing.T) {
	codeMessage := codeDigestMessage("id", "purpose", "target", "app", "12345678")
	if bytes.Equal(codeMessage, encodeDigestMessage(tokenDigestDomain, "id", "purpose", "target", "app", "12345678")) {
		t.Fatal("验证码与令牌使用了相同摘要域")
	}
	if !bytes.Equal(codeMessage, encodeDigestMessage(codeDigestDomain, "id", "purpose", "target", "app", "12345678")) {
		t.Fatal("验证码摘要输入未使用验证码域编码")
	}
}
