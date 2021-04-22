package secrets

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// 测试辅助函数集中在这里，避免各测试文件重复构造密钥环与 Sealer。

// fixedTestTime 是测试用的固定时间，保证序列化结果可比较。
func fixedTestTime() time.Time {
	return time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
}

// mustGenerateKeyring 生成只含一个当前写密钥的密钥环。
func mustGenerateKeyring(t *testing.T, keyID string) *Keyring {
	t.Helper()
	ring, err := GenerateKeyring(keyID, fixedTestTime())
	if err != nil {
		t.Fatalf("GenerateKeyring(%q) 失败: %v", keyID, err)
	}
	return ring
}

// mustSealer 基于密钥环创建 Sealer，日志输出丢弃。
func mustSealer(t *testing.T, ring *Keyring) *Sealer {
	t.Helper()
	sealer, err := NewSealer(ring, nil)
	if err != nil {
		t.Fatalf("NewSealer 失败: %v", err)
	}
	return sealer
}

// mustSeal 加密并断言成功。
func mustSeal(t *testing.T, sealer *Sealer, binding Binding, plaintext []byte) []byte {
	t.Helper()
	sealed, err := sealer.Seal(binding, plaintext)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	return sealed
}

// mustOpen 解密并断言得到原明文。
func mustOpen(t *testing.T, sealer *Sealer, binding Binding, sealed []byte) []byte {
	t.Helper()
	plaintext, err := sealer.Open(binding, sealed)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	return plaintext
}

// testBinding 返回一个合法的绑定信息；参数为空时使用默认值。
func testBinding(purpose, objectID, scopeID string) Binding {
	if purpose == "" {
		purpose = "mfa.totp"
	}
	if objectID == "" {
		objectID = "mfa-0000000000000001"
	}
	if scopeID == "" {
		scopeID = ScopeSystem
	}
	return Binding{Purpose: purpose, ObjectID: objectID, ScopeID: scopeID}
}

// testMaterial 返回可预测的 32 字节测试密钥材料。只用于构造错误文档，不能用于
// 生产密钥。
func testMaterial(fill byte) []byte {
	material := make([]byte, KeyMaterialSize)
	for i := range material {
		material[i] = fill + byte(i)
	}
	return material
}

// newBufferLogger 返回写入缓冲区的日志器，便于断言日志内容。
func newBufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// assertLogDoesNotContainKeyMaterial 断言日志没有输出密钥环中的 base64 密钥材料。
// 密钥编号可以出现在日志中，材料本身绝对不允许出现。
func assertLogDoesNotContainKeyMaterial(t *testing.T, logData []byte, ring *Keyring) {
	t.Helper()
	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	var parsed keyringDocument
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("解析密钥环文档失败: %v", err)
	}
	for _, key := range parsed.Keys {
		if key.Material == "" {
			t.Fatalf("密钥环文档存在空材料")
		}
		if bytes.Contains(logData, []byte(key.Material)) {
			t.Fatalf("日志泄露密钥 %s 的材料", key.ID)
		}
	}
}
