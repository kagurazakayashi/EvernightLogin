package secrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestHMACDigestDeterministicAndBound 验证受密钥保护摘要的确定性、长度与对密钥、
// 消息和用途域的绑定。
func TestHMACDigestDeterministicAndBound(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	first, err := ring.HMACDigest("k1", "one-time-credential-v1", []byte("message-a"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if len(first) != KeyedDigestSize {
		t.Fatalf("摘要长度 = %d，期望 %d", len(first), KeyedDigestSize)
	}
	again, err := ring.HMACDigest("k1", "one-time-credential-v1", []byte("message-a"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("相同输入得到不同摘要")
	}
	otherMessage, err := ring.HMACDigest("k1", "one-time-credential-v1", []byte("message-b"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if bytes.Equal(first, otherMessage) {
		t.Fatal("不同消息得到相同摘要")
	}
	otherDomain, err := ring.HMACDigest("k1", "other-domain-v1", []byte("message-a"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if bytes.Equal(first, otherDomain) {
		t.Fatal("不同用途域得到相同摘要")
	}
	// 相同 key_id、不同密钥材料必须得到不同摘要，避免把 key_id 当成密钥身份。
	otherRing := mustGenerateKeyring(t, "k1")
	otherMaterial, err := otherRing.HMACDigest("k1", "one-time-credential-v1", []byte("message-a"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if bytes.Equal(first, otherMaterial) {
		t.Fatal("不同密钥材料得到相同摘要")
	}
}

// TestHMACDigestHistoricalKeyAfterRotation 验证轮换后历史密钥仍可复算旧摘要，
// 因此未过期的一次性验证码在密钥轮换后仍可验证；这是 key_id 字段存在的意义。
func TestHMACDigestHistoricalKeyAfterRotation(t *testing.T) {
	ring1 := mustGenerateKeyring(t, "k1")
	oldDigest, err := ring1.HMACDigest("k1", "one-time-credential-v1", []byte("old-code"))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	ring2, err := ring1.RotateTo("k2", testMaterial(5), fixedTestTime())
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	historical, err := ring2.HMACDigest("k1", "one-time-credential-v1", []byte("old-code"))
	if err != nil {
		t.Fatalf("轮换后历史密钥摘要失败: %v", err)
	}
	if !bytes.Equal(oldDigest, historical) {
		t.Fatal("轮换后同一历史密钥与消息的摘要不一致")
	}
	current, err := ring2.HMACDigest("k2", "one-time-credential-v1", []byte("old-code"))
	if err != nil {
		t.Fatalf("当前密钥摘要失败: %v", err)
	}
	if bytes.Equal(oldDigest, current) {
		t.Fatal("新写密钥与历史密钥产生了相同摘要")
	}
}

// TestHMACDigestRejectsInvalid 验证空密钥环、未知 key_id、非法用途域都明确失败，
// 且错误不泄露密钥材料。
func TestHMACDigestRejectsInvalid(t *testing.T) {
	var nilRing *Keyring
	if _, err := nilRing.HMACDigest("k1", "one-time-credential-v1", []byte("x")); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil 密钥环错误 = %v", err)
	}
	ring := mustGenerateKeyring(t, "k1")
	if _, err := ring.HMACDigest("missing", "one-time-credential-v1", []byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("未知 key_id 错误 = %v", err)
	}
	if _, err := ring.HMACDigest("k1", "", []byte("x")); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("空用途域错误 = %v", err)
	}
	if _, err := ring.HMACDigest("k1", "bad/domain", []byte("x")); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("非法用途域错误 = %v", err)
	}
	if _, err := ring.HMACDigest("k1", strings.Repeat("d", MaxDigestDomainBytes+1), []byte("x")); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("超长用途域错误 = %v", err)
	}
	// 错误信息不得包含密钥材料或密钥环文档。
	document, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	_, keyErr := ring.HMACDigest("missing", "one-time-credential-v1", []byte("x"))
	if keyErr == nil {
		t.Fatal("未知 key_id 未失败")
	}
	if strings.Contains(keyErr.Error(), string(document)) {
		t.Fatal("错误信息泄露密钥环文档")
	}
}
