package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// buildValidDocument 返回一个可解析的密钥环文档结构。
func buildValidDocument(t *testing.T, keyID string) keyringDocument {
	t.Helper()
	return keyringDocument{
		Format:       KeyringFormat,
		Version:      KeyringVersion,
		CurrentKeyID: keyID,
		Keys: []keyringEntry{{
			ID:        keyID,
			Material:  base64.StdEncoding.EncodeToString(testMaterial(1)),
			CreatedAt: fixedTestTime().Format(time.RFC3339),
		}},
	}
}

// marshalDocument 把文档编码为 JSON，失败直接终止测试。
func marshalDocument(t *testing.T, doc keyringDocument) []byte {
	t.Helper()
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal 失败: %v", err)
	}
	return encoded
}

func TestGenerateAndParseKeyringDocument(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	if got := ring.CurrentKeyID(); got != "k1" {
		t.Fatalf("CurrentKeyID = %q, 期望 k1", got)
	}
	if ids := ring.KeyIDs(); len(ids) != 1 || ids[0] != "k1" {
		t.Fatalf("KeyIDs = %v, 期望 [k1]", ids)
	}
	if !ring.HasKey("k1") || ring.HasKey("k2") {
		t.Fatal("HasKey 判断错误")
	}

	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if !bytes.Contains(doc, []byte(KeyringFormat)) {
		t.Fatal("文档缺少格式标识")
	}
	parsed, err := ParseKeyringDocument(doc)
	if err != nil {
		t.Fatalf("ParseKeyringDocument 失败: %v", err)
	}
	if parsed.CurrentKeyID() != "k1" {
		t.Fatalf("解析后当前密钥 = %q", parsed.CurrentKeyID())
	}
	reencoded, err := parsed.Document()
	if err != nil {
		t.Fatalf("解析后 Document 失败: %v", err)
	}
	if !bytes.Equal(doc, reencoded) {
		t.Fatal("文档序列化-解析-序列化结果不一致")
	}

	// 两次独立生成的密钥材料必须不同，且不包含硬编码默认密钥。
	other := mustGenerateKeyring(t, "k1")
	otherDoc, err := other.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if bytes.Equal(doc, otherDoc) {
		t.Fatal("两次生成的密钥环完全相同，疑似使用固定默认密钥")
	}
}

func TestParseKeyringDocumentAcceptsMultipleKeys(t *testing.T) {
	doc := keyringDocument{
		Format:       KeyringFormat,
		Version:      KeyringVersion,
		CurrentKeyID: "k2",
		Keys: []keyringEntry{
			{ID: "k2", Material: base64.StdEncoding.EncodeToString(testMaterial(2)), CreatedAt: "2026-11-14T09:30:00Z"},
			{ID: "k1", Material: base64.StdEncoding.EncodeToString(testMaterial(1))},
		},
	}
	ring, err := ParseKeyringDocument(marshalDocument(t, doc))
	if err != nil {
		t.Fatalf("ParseKeyringDocument 失败: %v", err)
	}
	ids := ring.KeyIDs()
	if len(ids) != 2 || ids[0] != "k1" || ids[1] != "k2" {
		t.Fatalf("KeyIDs = %v, 期望按字典序 [k1 k2]", ids)
	}
	if ring.CurrentKeyID() != "k2" {
		t.Fatalf("CurrentKeyID = %q, 期望 k2", ring.CurrentKeyID())
	}
}

func TestParseKeyringDocumentRejectsInvalid(t *testing.T) {
	valid := buildValidDocument(t, "k1")
	withExtra := buildValidDocument(t, "k1")

	tooManyKeys := buildValidDocument(t, "k1")
	tooManyKeys.Keys = nil
	for i := 0; i <= MaxKeyringKeys; i++ {
		tooManyKeys.Keys = append(tooManyKeys.Keys, keyringEntry{
			ID:       "k" + strings.Repeat("x", i),
			Material: base64.StdEncoding.EncodeToString(testMaterial(byte(i))),
		})
	}

	cases := []struct {
		name string
		doc  []byte
	}{
		{name: "空文档", doc: nil},
		{name: "非 JSON", doc: []byte("not-json")},
		{name: "未知字段", doc: func() []byte {
			encoded, _ := json.Marshal(withExtra)
			return []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown_field":1}`)
		}()},
		{name: "追加第二个 JSON 值", doc: append(marshalDocument(t, valid), []byte("{}")...)},
		{name: "格式标识错误", doc: func() []byte {
			doc := valid
			doc.Format = "other-format"
			return marshalDocument(t, doc)
		}()},
		{name: "版本不支持", doc: func() []byte {
			doc := valid
			doc.Version = KeyringVersion + 1
			return marshalDocument(t, doc)
		}()},
		{name: "当前密钥为空", doc: func() []byte {
			doc := valid
			doc.CurrentKeyID = ""
			return marshalDocument(t, doc)
		}()},
		{name: "当前密钥不在列表", doc: func() []byte {
			doc := valid
			doc.CurrentKeyID = "k9"
			return marshalDocument(t, doc)
		}()},
		{name: "没有密钥", doc: func() []byte {
			doc := valid
			doc.Keys = nil
			return marshalDocument(t, doc)
		}()},
		{name: "重复密钥编号", doc: func() []byte {
			doc := valid
			doc.Keys = append(doc.Keys, doc.Keys[0])
			return marshalDocument(t, doc)
		}()},
		{name: "密钥编号含非法字符", doc: func() []byte {
			doc := valid
			doc.Keys[0].ID = "k/1"
			doc.CurrentKeyID = "k/1"
			return marshalDocument(t, doc)
		}()},
		{name: "密钥编号过长", doc: func() []byte {
			doc := valid
			doc.Keys[0].ID = strings.Repeat("k", MaxKeyIDBytes+1)
			doc.CurrentKeyID = doc.Keys[0].ID
			return marshalDocument(t, doc)
		}()},
		{name: "材料非 base64", doc: func() []byte {
			doc := valid
			doc.Keys[0].Material = "!!!!"
			return marshalDocument(t, doc)
		}()},
		{name: "材料长度不足", doc: func() []byte {
			doc := valid
			doc.Keys[0].Material = base64.StdEncoding.EncodeToString(testMaterial(1)[:KeyMaterialSize-1])
			return marshalDocument(t, doc)
		}()},
		{name: "材料长度超过", doc: func() []byte {
			doc := valid
			doc.Keys[0].Material = base64.StdEncoding.EncodeToString(append(testMaterial(1), 0))
			return marshalDocument(t, doc)
		}()},
		{name: "材料全零", doc: func() []byte {
			doc := valid
			doc.Keys[0].Material = base64.StdEncoding.EncodeToString(make([]byte, KeyMaterialSize))
			return marshalDocument(t, doc)
		}()},
		{name: "创建时间非法", doc: func() []byte {
			doc := valid
			doc.Keys[0].CreatedAt = "yesterday"
			return marshalDocument(t, doc)
		}()},
		{name: "密钥数量超过上限", doc: marshalDocument(t, tooManyKeys)},
		{name: "文档超过大小上限", doc: bytes.Repeat([]byte(" "), MaxKeyringDocumentBytes+1)},
		{name: "顶层不是对象", doc: []byte(`[1,2,3]`)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseKeyringDocument(testCase.doc); err == nil {
				t.Fatalf("ParseKeyringDocument 接受了非法文档")
			}
		})
	}
}

func TestKeyringRotateToKeepsHistoricalKeys(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	originalDoc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	material := testMaterial(9)
	rotated, err := ring.RotateTo("k2", material, fixedTestTime())
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	if rotated.CurrentKeyID() != "k2" {
		t.Fatalf("轮换后当前密钥 = %q, 期望 k2", rotated.CurrentKeyID())
	}
	ids := rotated.KeyIDs()
	if len(ids) != 2 || ids[0] != "k1" || ids[1] != "k2" {
		t.Fatalf("轮换后 KeyIDs = %v, 期望 [k1 k2]", ids)
	}
	// 原密钥环不被修改。
	if ring.CurrentKeyID() != "k1" || len(ring.KeyIDs()) != 1 {
		t.Fatal("RotateTo 修改了原密钥环")
	}
	sameOriginal, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if !bytes.Equal(originalDoc, sameOriginal) {
		t.Fatal("RotateTo 修改了原密钥环文档")
	}

	// 新密钥材料是调用方切片的副本：调用方之后修改切片不得影响密钥环。
	before, err := rotated.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	material[0] ^= 0xff
	after, err := rotated.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("密钥环保存了外部可变切片，材料可被外部修改")
	}

	// 轮换文档可以重新解析，当前密钥与历史密钥保持。
	parsed, err := ParseKeyringDocument(before)
	if err != nil {
		t.Fatalf("解析轮换文档失败: %v", err)
	}
	if parsed.CurrentKeyID() != "k2" || len(parsed.KeyIDs()) != 2 {
		t.Fatalf("解析轮换文档结果错误: current=%q ids=%v", parsed.CurrentKeyID(), parsed.KeyIDs())
	}
}

func TestKeyringRotateToRejectsInvalid(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	if _, err := ring.RotateTo("", testMaterial(1), fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("空密钥编号错误 = %v", err)
	}
	if _, err := ring.RotateTo("k1", testMaterial(1), fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("重复密钥编号错误 = %v", err)
	}
	if _, err := ring.RotateTo("k2", testMaterial(1)[:KeyMaterialSize-1], fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("材料长度错误 = %v", err)
	}
	if _, err := ring.RotateTo("k2", make([]byte, KeyMaterialSize), fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("全零密钥材料错误 = %v", err)
	}

	// 达到密钥数量上限后拒绝继续轮换。
	current := mustGenerateKeyring(t, "k0")
	for i := 1; i < MaxKeyringKeys; i++ {
		next, err := current.RotateTo("k"+string(rune('a'+i)), testMaterial(byte(i)), fixedTestTime())
		if err != nil {
			t.Fatalf("第 %d 次轮换失败: %v", i, err)
		}
		current = next
	}
	if _, err := current.RotateTo("overflow", testMaterial(3), fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("超过密钥数量上限错误 = %v", err)
	}
}

func TestKeyringWithoutKey(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	ring2, err := ring.RotateTo("k2", testMaterial(2), fixedTestTime())
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	retired, err := ring2.WithoutKey("k1")
	if err != nil {
		t.Fatalf("WithoutKey(k1) 失败: %v", err)
	}
	if retired.CurrentKeyID() != "k2" || len(retired.KeyIDs()) != 1 || retired.HasKey("k1") {
		t.Fatalf("移除历史密钥结果错误: current=%q ids=%v", retired.CurrentKeyID(), retired.KeyIDs())
	}
	// 原密钥环不受影响。
	if len(ring2.KeyIDs()) != 2 {
		t.Fatal("WithoutKey 修改了原密钥环")
	}
	if _, err := ring2.WithoutKey("k2"); !errors.Is(err, ErrCurrentKeyRetire) {
		t.Fatalf("移除当前密钥错误 = %v", err)
	}
	if _, err := ring2.WithoutKey("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("移除不存在密钥错误 = %v", err)
	}
}

func TestKeyringNilSafety(t *testing.T) {
	var ring *Keyring
	if ring.CurrentKeyID() != "" {
		t.Fatal("nil Keyring CurrentKeyID 非空")
	}
	if ring.KeyIDs() != nil {
		t.Fatal("nil Keyring KeyIDs 非 nil")
	}
	if ring.HasKey("k1") {
		t.Fatal("nil Keyring HasKey 为 true")
	}
	if _, err := ring.Document(); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil Keyring Document 错误 = %v", err)
	}
	if _, err := ring.RotateTo("k2", testMaterial(1), fixedTestTime()); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil Keyring RotateTo 错误 = %v", err)
	}
	if _, err := ring.WithoutKey("k1"); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil Keyring WithoutKey 错误 = %v", err)
	}
}

func TestGenerateKeyringRejectsInvalidKeyID(t *testing.T) {
	if _, err := GenerateKeyring("", fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("空密钥编号错误 = %v", err)
	}
	if _, err := GenerateKeyring("含中文", fixedTestTime()); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("非 ASCII 密钥编号错误 = %v", err)
	}
}

func TestGenerateKeyMaterialLengthAndRandomness(t *testing.T) {
	first, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatalf("GenerateKeyMaterial 失败: %v", err)
	}
	second, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatalf("GenerateKeyMaterial 失败: %v", err)
	}
	if len(first) != KeyMaterialSize || len(second) != KeyMaterialSize {
		t.Fatalf("材料长度 = %d/%d, 期望 %d", len(first), len(second), KeyMaterialSize)
	}
	if bytes.Equal(first, second) {
		t.Fatal("两次生成的密钥材料相同")
	}
}

// FuzzParseKeyringDocument 验证严格 JSON 密钥环解析对任意输入都不 panic；解析
// 成功的文档必须满足“当前写密钥存在”的不可变式，并且可以重新序列化后再次解析。
func FuzzParseKeyringDocument(f *testing.F) {
	ring, err := GenerateKeyring("k1", fixedTestTime())
	if err != nil {
		f.Fatalf("GenerateKeyring 失败: %v", err)
	}
	doc, err := ring.Document()
	if err != nil {
		f.Fatalf("Document 失败: %v", err)
	}
	f.Add(doc)
	f.Add([]byte{})
	f.Add([]byte("{}"))
	f.Add([]byte(`{"format":"evernight-login-keyring","version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseKeyringDocument(data)
		if err != nil {
			return
		}
		if parsed.CurrentKeyID() == "" || !parsed.HasKey(parsed.CurrentKeyID()) {
			t.Fatal("解析成功但当前写密钥不在密钥表中")
		}
		reencoded, err := parsed.Document()
		if err != nil {
			t.Fatalf("解析成功的密钥环无法重新序列化: %v", err)
		}
		if _, err := ParseKeyringDocument(reencoded); err != nil {
			t.Fatalf("重新序列化的密钥环无法再次解析: %v", err)
		}
	})
}
