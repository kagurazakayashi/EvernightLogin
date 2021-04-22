package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// envelopeHeaderLen 返回测试中计算信封头长度的方法。
func envelopeHeaderLen(keyID string) int {
	return envelopeHeaderFixedSize + len(keyID)
}

// extractNonce 从信封中取出 nonce，供唯一性检查使用。
func extractNonce(t *testing.T, sealed []byte, keyID string) []byte {
	t.Helper()
	offset := envelopeHeaderLen(keyID)
	if len(sealed) < offset+NonceSize {
		t.Fatalf("密文长度不足以取得 nonce")
	}
	return sealed[offset : offset+NonceSize]
}

func TestSealOpenRoundTrip(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	bindings := []Binding{
		testBinding("mfa.totp", "mfa-1", ScopeSystem),
		testBinding("mfa.totp", "mfa-2", ScopeSystem),
		testBinding("oauth.client", "client-1", "app_01"),
		testBinding("recovery.contact", "user-1", "app_02"),
	}
	plaintexts := [][]byte{
		[]byte("JBSWY3DPEHPK3PXP"),
		bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 500),
		{},
	}
	for _, binding := range bindings {
		for _, plaintext := range plaintexts {
			sealed := mustSeal(t, sealer, binding, plaintext)
			if !bytes.HasPrefix(sealed, []byte(EnvelopeMagic)) {
				t.Fatal("密文缺少信封魔数")
			}
			keyID, err := KeyIDOf(sealed)
			if err != nil {
				t.Fatalf("KeyIDOf 失败: %v", err)
			}
			if keyID != "k1" {
				t.Fatalf("KeyIDOf = %q, 期望 k1", keyID)
			}
			if len(plaintext) > 0 && bytes.Contains(sealed, plaintext) {
				t.Fatal("密文直接包含明文")
			}
			got := mustOpen(t, sealer, binding, sealed)
			if !bytes.Equal(got, plaintext) {
				t.Fatal("解密结果与明文不一致")
			}
		}
	}
}

func TestSealUsesFreshRandomNonce(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	binding := testBinding("", "", "")
	plaintext := []byte("same-plaintext")
	seenNonces := make(map[string]struct{}, 200)
	seenSealed := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		sealed := mustSeal(t, sealer, binding, plaintext)
		nonce := extractNonce(t, sealed, "k1")
		if len(nonce) != NonceSize {
			t.Fatalf("nonce 长度 = %d", len(nonce))
		}
		seenNonces[string(nonce)] = struct{}{}
		seenSealed[string(sealed)] = struct{}{}
	}
	if len(seenNonces) != 200 {
		t.Fatalf("nonce 出现重复：200 次加密只有 %d 个不同 nonce", len(seenNonces))
	}
	if len(seenSealed) != 200 {
		t.Fatalf("相同明文的密文出现重复：只有 %d 个不同密文", len(seenSealed))
	}
}

func TestOpenRejectsTamperedEnvelope(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	binding := testBinding("", "", "")
	plaintext := []byte("tamper-me")
	sealed := mustSeal(t, sealer, binding, plaintext)
	headerLen := envelopeHeaderLen("k1")

	cases := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr error
	}{
		{name: "魔数被改", mutate: func(b []byte) []byte { b[0] ^= 0xff; return b }, wantErr: ErrSealedMalformed},
		{name: "版本被改", mutate: func(b []byte) []byte { b[4] = EnvelopeVersion + 1; return b }, wantErr: ErrSealedVersionUnsupported},
		{name: "key_id 长度被改", mutate: func(b []byte) []byte { b[5] = 0; return b }, wantErr: ErrSealedMalformed},
		{name: "key_id 未知", mutate: func(b []byte) []byte { b[6] = '9'; return b }, wantErr: ErrKeyNotFound},
		{name: "key_id 非法字符", mutate: func(b []byte) []byte { b[6] = '/'; return b }, wantErr: ErrSealedMalformed},
		{name: "nonce 被改", mutate: func(b []byte) []byte { b[headerLen] ^= 0xff; return b }, wantErr: ErrDecryptFailed},
		{name: "密文首字节被改", mutate: func(b []byte) []byte { b[headerLen+NonceSize] ^= 0xff; return b }, wantErr: ErrDecryptFailed},
		{name: "认证标签被改", mutate: func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b }, wantErr: ErrDecryptFailed},
		{name: "截断", mutate: func(b []byte) []byte { return b[:len(b)-1] }, wantErr: ErrDecryptFailed},
		{name: "追加字节", mutate: func(b []byte) []byte { return append(b, 0x00) }, wantErr: ErrDecryptFailed},
		{name: "整体为空", mutate: func(b []byte) []byte { return nil }, wantErr: ErrSealedMalformed},
		{name: "只有魔数", mutate: func(b []byte) []byte { return append([]byte(nil), b[:4]...) }, wantErr: ErrSealedMalformed},
		{name: "超过大小上限", mutate: func(b []byte) []byte { return make([]byte, MaxSealedBytes+1) }, wantErr: ErrSealedTooLarge},
		{name: "短 key_id 的超大密文", mutate: func(b []byte) []byte {
			// 信封总长仍在上限内，但单条密文超过 MaxPlaintextBytes+TagSize：
			// 明文上限不能因为 key_id 较短而放宽。
			oversized := make([]byte, envelopeHeaderLen("k1")+NonceSize+MaxPlaintextBytes+TagSize+1)
			copy(oversized, b[:envelopeHeaderLen("k1")])
			return oversized
		}, wantErr: ErrSealedTooLarge},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			tampered := testCase.mutate(append([]byte(nil), sealed...))
			_, err := sealer.Open(binding, tampered)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Open 错误 = %v, 期望 %v", err, testCase.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "tamper-me") {
				t.Fatal("错误信息泄露明文")
			}
		})
	}
}

func TestOpenRejectsWrongBinding(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	original := Binding{Purpose: "mfa.totp", ObjectID: "mfa-1", ScopeID: ScopeSystem}
	sealed := mustSeal(t, sealer, original, []byte("binding-bound-secret"))

	wrongs := []Binding{
		{Purpose: "oauth.client", ObjectID: original.ObjectID, ScopeID: original.ScopeID},
		{Purpose: original.Purpose, ObjectID: "mfa-2", ScopeID: original.ScopeID},
		{Purpose: original.Purpose, ObjectID: original.ObjectID, ScopeID: "app_01"},
	}
	for _, wrong := range wrongs {
		if _, err := sealer.Open(wrong, sealed); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("错误绑定 %v 未按 ErrDecryptFailed 拒绝: %v", wrong, err)
		}
	}
	// 正确绑定仍然可解密，确认失败不是因为密文本身损坏。
	if got := mustOpen(t, sealer, original, sealed); string(got) != "binding-bound-secret" {
		t.Fatalf("正确绑定解密结果 = %q", got)
	}
}

func TestBindingValidation(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	invalidBindings := []Binding{
		{Purpose: "", ObjectID: "obj", ScopeID: ScopeSystem},
		{Purpose: "mfa.totp", ObjectID: "", ScopeID: ScopeSystem},
		{Purpose: "mfa.totp", ObjectID: "obj", ScopeID: ""},
		{Purpose: strings.Repeat("p", MaxPurposeBytes+1), ObjectID: "obj", ScopeID: ScopeSystem},
		{Purpose: "mfa.totp", ObjectID: strings.Repeat("o", MaxBindingFieldBytes+1), ScopeID: ScopeSystem},
		{Purpose: "mfa.totp", ObjectID: "obj", ScopeID: strings.Repeat("s", MaxBindingFieldBytes+1)},
		{Purpose: "mfa totp", ObjectID: "obj", ScopeID: ScopeSystem},
		{Purpose: "mfa.totp\n", ObjectID: "obj", ScopeID: ScopeSystem},
		{Purpose: "含中文", ObjectID: "obj", ScopeID: ScopeSystem},
	}
	for _, binding := range invalidBindings {
		if _, err := sealer.Seal(binding, []byte("x")); !errors.Is(err, ErrBindingInvalid) {
			t.Fatalf("Seal 未拒绝非法绑定 %v: %v", binding, err)
		}
		if _, err := sealer.Open(binding, mustSeal(t, sealer, testBinding("", "", ""), []byte("x"))); !errors.Is(err, ErrBindingInvalid) {
			t.Fatalf("Open 未拒绝非法绑定 %v: %v", binding, err)
		}
	}
}

func TestOpenRejectsWrongOrMissingKey(t *testing.T) {
	ringA := mustGenerateKeyring(t, "k1")
	sealerA := mustSealer(t, ringA)
	binding := testBinding("", "", "")
	sealed := mustSeal(t, sealerA, binding, []byte("wrong-key-secret"))

	// 相同 key_id、不同材料：应视为认证失败，而不是回退到其它密钥。
	ringB := mustGenerateKeyring(t, "k1")
	sealerB := mustSealer(t, ringB)
	if _, err := sealerB.Open(binding, sealed); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("错误密钥材料错误 = %v", err)
	}

	// 密钥环完全没有该 key_id：明确报缺失，不生成新密钥猜测。
	ringC := mustGenerateKeyring(t, "k2")
	sealerC := mustSealer(t, ringC)
	if _, err := sealerC.Open(binding, sealed); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("缺失 key_id 错误 = %v", err)
	}
}

func TestOldCiphertextReadableAfterRotation(t *testing.T) {
	ring1 := mustGenerateKeyring(t, "k1")
	sealer1 := mustSealer(t, ring1)
	binding := testBinding("", "", "")
	oldSealed := mustSeal(t, sealer1, binding, []byte("old-secret"))

	ring2, err := ring1.RotateTo("k2", testMaterial(7), fixedTestTime())
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	sealer2 := mustSealer(t, ring2)

	// 旧数据用轮换后的密钥环仍可读取（历史读密钥）。
	oldPlaintext := mustOpen(t, sealer2, binding, oldSealed)
	if string(oldPlaintext) != "old-secret" {
		t.Fatalf("旧数据读取结果 = %q", oldPlaintext)
	}
	// 新写入使用当前写密钥。
	newSealed := mustSeal(t, sealer2, binding, []byte("new-secret"))
	newKeyID, err := KeyIDOf(newSealed)
	if err != nil {
		t.Fatalf("KeyIDOf 失败: %v", err)
	}
	if newKeyID != "k2" {
		t.Fatalf("新密文 key_id = %q, 期望 k2", newKeyID)
	}
	if got := mustOpen(t, sealer2, binding, newSealed); string(got) != "new-secret" {
		t.Fatalf("新数据读取结果 = %q", got)
	}
	// 只有旧密钥的 Sealer 无法解新密文：不会退化为任意密钥尝试。
	if _, err := sealer1.Open(binding, newSealed); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("旧密钥环解新密文错误 = %v", err)
	}
}

func TestSealRejectsOversizedPlaintext(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	if _, err := sealer.Seal(testBinding("", "", ""), make([]byte, MaxPlaintextBytes+1)); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("超长明文错误 = %v", err)
	}
	// 恰好达到上限应当成功。
	if _, err := sealer.Seal(testBinding("", "", ""), make([]byte, MaxPlaintextBytes)); err != nil {
		t.Fatalf("上限内明文加密失败: %v", err)
	}
}

// failingReader 模拟安全随机源失败。
type failingReader struct {
	limit int
	err   error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.limit <= 0 {
		return 0, r.err
	}
	if len(p) > r.limit {
		p = p[:r.limit]
	}
	for i := range p {
		p[i] = 0x42
	}
	n := len(p)
	r.limit -= n
	return n, nil
}

func TestSealFailsWhenRandomSourceFails(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	sealer.random = &failingReader{limit: 0, err: errors.New("entropy unavailable")}
	sealed, err := sealer.Seal(testBinding("", "", ""), []byte("secret"))
	if !errors.Is(err, ErrRandomSource) {
		t.Fatalf("Seal 错误 = %v, 期望 ErrRandomSource", err)
	}
	if sealed != nil {
		t.Fatal("随机源失败时仍返回了密文")
	}

	// 随机源只返回部分字节也必须失败，不能补零或复用 nonce。
	sealer.random = &failingReader{limit: NonceSize - 1, err: io.EOF}
	if _, err := sealer.Seal(testBinding("", "", ""), []byte("secret")); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("短 nonce 读取错误 = %v", err)
	}
}

func TestNewSealerRequiresKeyring(t *testing.T) {
	if _, err := NewSealer(nil, nil); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil 密钥环错误 = %v", err)
	}
	// 当前写密钥缺失或不在密钥表中时必须失败，不能猜测使用其它密钥。
	missingCurrent := &Keyring{
		currentKeyID: "missing",
		keys:         map[string]keyringKey{"k1": {material: testMaterial(1)}},
	}
	if _, err := NewSealer(missingCurrent, nil); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("当前写密钥缺失错误 = %v", err)
	}
	var sealer *Sealer
	if _, err := sealer.Seal(testBinding("", "", ""), []byte("x")); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil Sealer Seal 错误 = %v", err)
	}
	if _, err := sealer.Open(testBinding("", "", ""), []byte("x")); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil Sealer Open 错误 = %v", err)
	}
	if sealer.CurrentKeyID() != "" {
		t.Fatal("nil Sealer CurrentKeyID 非空")
	}
}

func TestSealingErrorsDoNotLeakPlaintextOrKeyMaterial(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	material, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	sealer := mustSealer(t, ring)
	binding := testBinding("", "", "")
	plaintext := []byte("very-secret-totp-seed-value")
	sealed := mustSeal(t, sealer, binding, plaintext)
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xff

	_, openErr := sealer.Open(binding, tampered)
	if openErr == nil {
		t.Fatal("篡改密文未被拒绝")
	}
	_, bindingErr := sealer.Open(testBinding("other.purpose", "", ""), sealed)
	if bindingErr == nil {
		t.Fatal("错误用途未被拒绝")
	}
	for _, err := range []error{openErr, bindingErr} {
		message := err.Error()
		if strings.Contains(message, string(plaintext)) {
			t.Fatal("错误信息泄露明文")
		}
		if strings.Contains(message, string(material)) {
			t.Fatal("错误信息泄露密钥环文档")
		}
	}
}

func TestKeyIDOfRejectsMalformed(t *testing.T) {
	if _, err := KeyIDOf(nil); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("空密文错误 = %v", err)
	}
	if _, err := KeyIDOf([]byte("LNS1\x02")); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("过短密文错误 = %v", err)
	}
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	valid := mustSeal(t, sealer, testBinding("", "", ""), []byte("x"))
	keyID, err := KeyIDOf(valid)
	if err != nil || keyID != "k1" {
		t.Fatalf("KeyIDOf = %q, %v", keyID, err)
	}
}

func TestBindingStringFormat(t *testing.T) {
	binding := testBinding("mfa.totp", "mfa-1", "system")
	if got := binding.String(); got != "mfa.totp/system/mfa-1" {
		t.Fatalf("Binding.String = %q", got)
	}
}

func TestEnvelopeSizes(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	plaintext := make([]byte, 128)
	sealed := mustSeal(t, sealer, testBinding("", "", ""), plaintext)
	want := envelopeHeaderLen("k1") + NonceSize + len(plaintext) + TagSize
	if len(sealed) != want {
		t.Fatalf("信封长度 = %d, 期望 %d", len(sealed), want)
	}
	if fmt.Sprintf("%x", sealed[:4]) != fmt.Sprintf("%x", []byte(EnvelopeMagic)) {
		t.Fatal("信封魔数字节不正确")
	}
}

// TestSealerConcurrentUse 验证文档声明的并发安全：多个 goroutine 共享同一个
// Sealer 时各自加密/解密互不干扰，且不会产生共享状态竞争（可用 -race 复验）。
func TestSealerConcurrentUse(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	binding := testBinding("mfa.totp", "mfa-concurrent", ScopeSystem)
	const goroutines = 8
	const iterations = 50
	var waitGroup sync.WaitGroup
	errCh := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for i := 0; i < iterations; i++ {
				plaintext := []byte(fmt.Sprintf("secret-%d-%d", worker, i))
				sealed, err := sealer.Seal(binding, plaintext)
				if err != nil {
					errCh <- fmt.Errorf("worker %d Seal 失败: %w", worker, err)
					return
				}
				got, err := sealer.Open(binding, sealed)
				if err != nil {
					errCh <- fmt.Errorf("worker %d Open 失败: %w", worker, err)
					return
				}
				if !bytes.Equal(got, plaintext) {
					errCh <- fmt.Errorf("worker %d 解密结果与明文不一致", worker)
					return
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// FuzzOpenEnvelope 验证信封解析与认证解密对任意输入都不 panic、不越界，失败时
// 只返回本包定义的安全错误。种子包含合法信封、截断信封与随机字节；常规
// go test 只运行种子语料，持续模糊测试需显式使用 -fuzz。
func FuzzOpenEnvelope(f *testing.F) {
	ring, err := GenerateKeyring("k1", fixedTestTime())
	if err != nil {
		f.Fatalf("GenerateKeyring 失败: %v", err)
	}
	sealer, err := NewSealer(ring, nil)
	if err != nil {
		f.Fatalf("NewSealer 失败: %v", err)
	}
	binding := testBinding("mfa.totp", "mfa-fuzz", ScopeSystem)
	seeded, err := sealer.Seal(binding, []byte("fuzz-seed"))
	if err != nil {
		f.Fatalf("Seal 失败: %v", err)
	}
	f.Add(seeded)
	f.Add(seeded[:len(seeded)/2])
	f.Add([]byte{})
	f.Add([]byte(EnvelopeMagic))
	f.Add([]byte("LNS1\x01\x01k"))
	f.Fuzz(func(t *testing.T, data []byte) {
		keyID, err := KeyIDOf(data)
		if err == nil && keyID == "" {
			t.Fatal("KeyIDOf 成功但返回空 key_id")
		}
		if _, err := sealer.Open(binding, data); err != nil {
			if !errors.Is(err, ErrSealedMalformed) &&
				!errors.Is(err, ErrSealedVersionUnsupported) &&
				!errors.Is(err, ErrSealedTooLarge) &&
				!errors.Is(err, ErrKeyNotFound) &&
				!errors.Is(err, ErrDecryptFailed) {
				t.Fatalf("Open 返回未预期的错误类别: %v", err)
			}
		}
	})
}
