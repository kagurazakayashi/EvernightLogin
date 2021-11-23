package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// memRecord 是内存存储中的一条密文记录。
type memRecord struct {
	ID      string
	Binding Binding
	Sealed  []byte
}

// memStore 是 SealedStore 的测试替身，只用于验证重加密算法的中断、恢复与
// 并发修改检查；它不是生产数据库实现。
type memStore struct {
	mu      sync.Mutex
	records map[string]memRecord

	loadErr      error
	nextReplErr  error
	noopReplace  bool
	onReplace    func(id string, count int)
	replaceCount int
}

// newMemStore 创建空的内存存储。
func newMemStore() *memStore {
	return &memStore{records: make(map[string]memRecord)}
}

// put 写入一条记录。
func (m *memStore) put(record SealedRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[record.ID] = memRecord{
		ID:      record.ID,
		Binding: record.Binding,
		Sealed:  append([]byte(nil), record.Sealed...),
	}
}

// get 读取一条记录副本。
func (m *memStore) get(t *testing.T, id string) memRecord {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[id]
	if !ok {
		t.Fatalf("记录 %s 不存在", id)
	}
	record.Sealed = append([]byte(nil), record.Sealed...)
	return record
}

// LoadBatch 实现 SealedStore。
func (m *memStore) LoadBatch(ctx context.Context, sourceKeyID, afterID string, limit int) ([]SealedRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	ids := make([]string, 0, len(m.records))
	for id := range m.records {
		if id > afterID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	records := make([]SealedRecord, 0, limit)
	for _, id := range ids {
		record := m.records[id]
		keyID, err := KeyIDOf(record.Sealed)
		if err != nil || keyID != sourceKeyID {
			continue
		}
		records = append(records, SealedRecord{
			ID:      record.ID,
			Binding: record.Binding,
			Sealed:  append([]byte(nil), record.Sealed...),
		})
		if len(records) >= limit {
			break
		}
	}
	return records, nil
}

// Replace 实现 SealedStore，带乐观并发检查与故障注入点。
func (m *memStore) Replace(ctx context.Context, id string, oldSealed, newSealed []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.nextReplErr != nil {
		err := m.nextReplErr
		m.nextReplErr = nil
		m.mu.Unlock()
		return err
	}
	record, ok := m.records[id]
	if !ok || !bytes.Equal(record.Sealed, oldSealed) {
		m.mu.Unlock()
		return ErrRecordStale
	}
	if m.noopReplace {
		m.replaceCount++
		hook := m.onReplace
		count := m.replaceCount
		m.mu.Unlock()
		if hook != nil {
			hook(id, count)
		}
		return nil
	}
	record.Sealed = append([]byte(nil), newSealed...)
	m.records[id] = record
	m.replaceCount++
	hook := m.onReplace
	count := m.replaceCount
	m.mu.Unlock()
	if hook != nil {
		hook(id, count)
	}
	return nil
}

// countByKey 统计指定密钥的记录数。
func (m *memStore) countByKey(t *testing.T, keyID string) int {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, record := range m.records {
		actual, err := KeyIDOf(record.Sealed)
		if err == nil && actual == keyID {
			total++
		}
	}
	return total
}

// reencryptFixture 构造“旧密钥写入 N 条记录、已轮换到新密钥”的测试场景。
type reencryptFixture struct {
	ring1     *Keyring
	ring2     *Keyring
	sealer1   *Sealer
	sealer2   *Sealer
	store     *memStore
	bindings  map[string]Binding
	plaintext map[string][]byte
}

func newReencryptFixture(t *testing.T, count int) *reencryptFixture {
	t.Helper()
	fixture := &reencryptFixture{
		store:     newMemStore(),
		bindings:  make(map[string]Binding),
		plaintext: make(map[string][]byte),
	}
	fixture.ring1 = mustGenerateKeyring(t, "k1")
	fixture.sealer1 = mustSealer(t, fixture.ring1)
	material, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatalf("GenerateKeyMaterial 失败: %v", err)
	}
	fixture.ring2, err = fixture.ring1.RotateTo("k2", material, fixedTestTime())
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	fixture.sealer2 = mustSealer(t, fixture.ring2)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("mfa-%03d", i+1)
		binding := Binding{Purpose: "mfa.totp", ObjectID: id, ScopeID: ScopeSystem}
		plaintext := []byte(fmt.Sprintf("totp-seed-%03d-%s", i+1, bytes.Repeat([]byte("A"), i)))
		sealed := mustSeal(t, fixture.sealer1, binding, plaintext)
		fixture.store.put(SealedRecord{ID: id, Binding: binding, Sealed: sealed})
		fixture.bindings[id] = binding
		fixture.plaintext[id] = plaintext
	}
	return fixture
}

// assertAllReadable 断言所有记录都能用 sealer 解密，并返回当前 key_id 统计。
func assertAllReadable(t *testing.T, fixture *reencryptFixture, sealer *Sealer) map[string]int {
	t.Helper()
	keys := make(map[string]int)
	for id, binding := range fixture.bindings {
		record := fixture.store.get(t, id)
		keyID, err := KeyIDOf(record.Sealed)
		if err != nil {
			t.Fatalf("记录 %s KeyIDOf 失败: %v", id, err)
		}
		keys[keyID]++
		plaintext, err := sealer.Open(binding, record.Sealed)
		if err != nil {
			t.Fatalf("记录 %s 解密失败: %v", id, err)
		}
		if !bytes.Equal(plaintext, fixture.plaintext[id]) {
			t.Fatalf("记录 %s 解密结果与原文不一致", id)
		}
	}
	return keys
}

func TestReencryptCompletesAndPreservesData(t *testing.T) {
	fixture := newReencryptFixture(t, 6)
	var logBuffer bytes.Buffer
	rotator, err := NewRotator(fixture.ring2, fixture.store, newBufferLogger(&logBuffer))
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{})
	if err != nil {
		t.Fatalf("Reencrypt 失败: %v", err)
	}
	if report.Updated != 6 {
		t.Fatalf("Updated = %d, 期望 6", report.Updated)
	}
	if report.Remaining != 0 {
		t.Fatalf("Remaining = %d, 期望 0", report.Remaining)
	}
	if len(report.SourceKeyIDs) != 1 || report.SourceKeyIDs[0] != "k1" {
		t.Fatalf("SourceKeyIDs = %v, 期望 [k1]", report.SourceKeyIDs)
	}
	if remaining := fixture.store.countByKey(t, "k1"); remaining != 0 {
		t.Fatalf("仍有 %d 条记录使用旧密钥", remaining)
	}
	keys := assertAllReadable(t, fixture, fixture.sealer2)
	if keys["k2"] != 6 {
		t.Fatalf("新密钥记录数 = %d, 期望 6", keys["k2"])
	}

	// 重加密保留绑定：错误用途/对象仍然无法解密，正确绑定可用。
	record := fixture.store.get(t, "mfa-001")
	wrong := fixture.bindings["mfa-001"]
	wrong.ObjectID = "mfa-999"
	if _, err := fixture.sealer2.Open(wrong, record.Sealed); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("重加密后错误对象未被拒绝: %v", err)
	}

	// 日志只包含密钥编号与计数，不包含明文或密钥材料。
	logText := logBuffer.String()
	for id, plaintext := range fixture.plaintext {
		if bytes.Contains(logBuffer.Bytes(), plaintext) {
			t.Fatalf("日志泄露记录 %s 的明文", id)
		}
	}
	if !bytes.Contains([]byte(logText), []byte("k1")) || !bytes.Contains([]byte(logText), []byte("k2")) {
		t.Fatalf("日志缺少密钥编号，无法诊断轮换: %s", logText)
	}
	if bytes.Contains([]byte(logText), []byte("mfa-001")) {
		t.Log("提示：日志包含记录 ID 属于可接受的诊断信息")
	}
	// 日志可以包含密钥编号，但绝不能包含密钥材料。
	assertLogDoesNotContainKeyMaterial(t, logBuffer.Bytes(), fixture.ring1)
	assertLogDoesNotContainKeyMaterial(t, logBuffer.Bytes(), fixture.ring2)
}

func TestReencryptResumesAfterInterruption(t *testing.T) {
	fixture := newReencryptFixture(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.store.onReplace = func(_ string, count int) {
		if count == 3 {
			cancel()
		}
	}
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(ctx, ReencryptOptions{BatchSize: 2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("中断错误 = %v, 期望 context.Canceled", err)
	}
	if report.Updated != 3 {
		t.Fatalf("中断时 Updated = %d, 期望 3", report.Updated)
	}
	if k1Count := fixture.store.countByKey(t, "k1"); k1Count != 7 {
		t.Fatalf("中断后旧密钥记录数 = %d, 期望 7", k1Count)
	}
	if k2Count := fixture.store.countByKey(t, "k2"); k2Count != 3 {
		t.Fatalf("中断后新密钥记录数 = %d, 期望 3", k2Count)
	}
	// 中断状态下所有数据仍可正常读取。
	assertAllReadable(t, fixture, fixture.sealer2)

	// 重新运行会从源密钥剩余记录继续，不需要额外进度表。
	fixture.store.onReplace = nil
	report, err = rotator.Reencrypt(context.Background(), ReencryptOptions{BatchSize: 4})
	if err != nil {
		t.Fatalf("恢复重加密失败: %v", err)
	}
	if report.Updated != 7 {
		t.Fatalf("恢复时 Updated = %d, 期望 7", report.Updated)
	}
	if report.Remaining != 0 {
		t.Fatalf("恢复后 Remaining = %d, 期望 0", report.Remaining)
	}
	if k1Count := fixture.store.countByKey(t, "k1"); k1Count != 0 {
		t.Fatalf("恢复后仍有 %d 条旧密钥记录", k1Count)
	}
	assertAllReadable(t, fixture, fixture.sealer2)
}

func TestReencryptRecoversFromTransientStoreError(t *testing.T) {
	fixture := newReencryptFixture(t, 5)
	fixture.store.nextReplErr = ErrStoreUnavailable
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{})
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("存储错误 = %v, 期望 ErrStoreUnavailable", err)
	}
	if report.Updated != 0 {
		t.Fatalf("首次失败前 Updated = %d, 期望 0", report.Updated)
	}
	if k2Count := fixture.store.countByKey(t, "k2"); k2Count != 0 {
		t.Fatalf("失败后新密钥记录数 = %d, 期望 0", k2Count)
	}

	report, err = rotator.Reencrypt(context.Background(), ReencryptOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("重试失败: %v", err)
	}
	if report.Updated != 5 || report.Remaining != 0 {
		t.Fatalf("重试报告 = %+v", report)
	}
	assertAllReadable(t, fixture, fixture.sealer2)
}

func TestReencryptAbortsOnCorruptRecord(t *testing.T) {
	fixture := newReencryptFixture(t, 3)
	corrupt := fixture.store.get(t, "mfa-002")
	corrupt.Sealed[len(corrupt.Sealed)-1] ^= 0xff
	fixture.store.put(SealedRecord{ID: corrupt.ID, Binding: corrupt.Binding, Sealed: corrupt.Sealed})

	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{})
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("错误 = %v, 期望 ErrDecryptFailed", err)
	}
	if report.Updated != 1 {
		t.Fatalf("损坏记录前已更新 %d 条, 期望 1", report.Updated)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("mfa-002")) {
		t.Fatalf("错误信息缺少记录 ID: %v", err)
	}
	if bytes.Contains([]byte(err.Error()), fixture.plaintext["mfa-002"]) {
		t.Fatal("错误信息泄露明文")
	}
	// 损坏记录保持原状，未被静默跳过或覆盖；后续记录未被处理。
	if keyID, _ := KeyIDOf(fixture.store.get(t, "mfa-002").Sealed); keyID != "k1" {
		t.Fatalf("损坏记录密钥被改动为 %q", keyID)
	}
	if keyID, _ := KeyIDOf(fixture.store.get(t, "mfa-003").Sealed); keyID != "k1" {
		t.Fatalf("损坏记录之后的记录被提前处理: %q", keyID)
	}
}

func TestReencryptAbortsOnBindingMismatch(t *testing.T) {
	fixture := newReencryptFixture(t, 2)
	record := fixture.store.get(t, "mfa-001")
	record.Binding.ObjectID = "mfa-999"
	fixture.store.put(SealedRecord{ID: record.ID, Binding: record.Binding, Sealed: record.Sealed})

	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	if _, err := rotator.Reencrypt(context.Background(), ReencryptOptions{}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("绑定不一致错误 = %v, 期望 ErrDecryptFailed", err)
	}
}

func TestReencryptDetectsIncompleteStoreUpdate(t *testing.T) {
	fixture := newReencryptFixture(t, 4)
	fixture.store.noopReplace = true
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{})
	if !errors.Is(err, ErrReencryptIncomplete) {
		t.Fatalf("存储未真正更新时错误 = %v, 期望 ErrReencryptIncomplete", err)
	}
	if report.Remaining != 4 {
		t.Fatalf("Remaining = %d, 期望 4", report.Remaining)
	}
}

func TestReencryptRejectsInvalidOptions(t *testing.T) {
	fixture := newReencryptFixture(t, 1)
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	cases := []struct {
		name string
		opts ReencryptOptions
		want error
	}{
		{name: "源密钥为当前写密钥", opts: ReencryptOptions{SourceKeyIDs: []string{"k2"}}, want: ErrKeyringInvalid},
		{name: "源密钥不存在", opts: ReencryptOptions{SourceKeyIDs: []string{"k9"}}, want: ErrKeyNotFound},
		{name: "空源密钥编号", opts: ReencryptOptions{SourceKeyIDs: []string{""}}, want: ErrKeyringInvalid},
		{name: "批大小为负", opts: ReencryptOptions{BatchSize: -1}, want: ErrOptionsInvalid},
		{name: "批大小超过上限", opts: ReencryptOptions{BatchSize: MaxReencryptBatchSize + 1}, want: ErrOptionsInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := rotator.Reencrypt(context.Background(), testCase.opts); !errors.Is(err, testCase.want) {
				t.Fatalf("错误 = %v, 期望 %v", err, testCase.want)
			}
		})
	}
}

func TestReencryptNothingToDo(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	sealer := mustSealer(t, ring)
	store := newMemStore()
	binding := testBinding("", "", "")
	store.put(SealedRecord{ID: "mfa-001", Binding: binding, Sealed: mustSeal(t, sealer, binding, []byte("x"))})
	rotator, err := NewRotator(ring, store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{})
	if err != nil {
		t.Fatalf("Reencrypt 失败: %v", err)
	}
	if report.Updated != 0 || len(report.SourceKeyIDs) != 0 {
		t.Fatalf("无旧密钥时报告 = %+v", report)
	}
	if store.replaceCount != 0 {
		t.Fatalf("无旧密钥时仍调用了 Replace %d 次", store.replaceCount)
	}
}

func TestReencryptRequiresStore(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	rotator, err := NewRotator(ring, nil, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	if _, err := rotator.Reencrypt(context.Background(), ReencryptOptions{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("缺少存储时错误 = %v", err)
	}
	if _, _, err := rotator.RetireKey(context.Background(), "k1", RetireOptions{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("缺少存储时退役错误 = %v", err)
	}
}

func TestRetireKeyGuardsReferences(t *testing.T) {
	fixture := newReencryptFixture(t, 3)
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	retired, report, err := rotator.RetireKey(context.Background(), "k1", RetireOptions{})
	if !errors.Is(err, ErrKeyStillReferenced) {
		t.Fatalf("仍有引用时退役错误 = %v", err)
	}
	if report.Referenced != 3 {
		t.Fatalf("Referenced = %d, 期望 3", report.Referenced)
	}
	if retired != nil {
		t.Fatal("仍有引用时返回了新密钥环")
	}

	// 重加密后旧密钥不再被引用，允许退役。
	if _, err := rotator.Reencrypt(context.Background(), ReencryptOptions{}); err != nil {
		t.Fatalf("Reencrypt 失败: %v", err)
	}
	retired, report, err = rotator.RetireKey(context.Background(), "k1", RetireOptions{})
	if err != nil {
		t.Fatalf("退役失败: %v", err)
	}
	if report.Referenced != 0 {
		t.Fatalf("退役时 Referenced = %d, 期望 0", report.Referenced)
	}
	if retired.HasKey("k1") || retired.CurrentKeyID() != "k2" {
		t.Fatalf("退役后密钥环 = current %q ids %v", retired.CurrentKeyID(), retired.KeyIDs())
	}
	// 退役后的密钥环可以持久化并重新加载。
	doc, err := retired.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	reloaded, err := ParseKeyringDocument(doc)
	if err != nil {
		t.Fatalf("解析退役后文档失败: %v", err)
	}
	if reloaded.HasKey("k1") {
		t.Fatal("退役密钥仍在持久化文档中")
	}
	// 新密钥环仍可读取重加密后的数据。
	assertAllReadable(t, fixture, mustSealer(t, reloaded))

	// 当前写密钥与不存在的密钥不能退役。
	if _, _, err := rotator.RetireKey(context.Background(), "k2", RetireOptions{}); !errors.Is(err, ErrCurrentKeyRetire) {
		t.Fatalf("退役当前密钥错误 = %v", err)
	}
	if _, _, err := rotator.RetireKey(context.Background(), "missing", RetireOptions{}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("退役不存在密钥错误 = %v", err)
	}
}

func TestRetireKeyFailsClosedOnStoreError(t *testing.T) {
	fixture := newReencryptFixture(t, 1)
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	fixture.store.loadErr = ErrStoreUnavailable
	if _, _, err := rotator.RetireKey(context.Background(), "k1", RetireOptions{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("存储不可用退役错误 = %v, 期望 ErrStoreUnavailable", err)
	}
}

func TestRotateGeneratesNewCurrentKey(t *testing.T) {
	ring1 := mustGenerateKeyring(t, "k1")
	sealer1 := mustSealer(t, ring1)
	binding := testBinding("", "", "")
	oldSealed := mustSeal(t, sealer1, binding, []byte("old-secret"))

	var logBuffer bytes.Buffer
	rotator, err := NewRotator(ring1, newMemStore(), newBufferLogger(&logBuffer))
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	ring2, err := rotator.Rotate("k2")
	if err != nil {
		t.Fatalf("Rotate 失败: %v", err)
	}
	if ring2.CurrentKeyID() != "k2" || len(ring2.KeyIDs()) != 2 {
		t.Fatalf("轮换结果 = current %q ids %v", ring2.CurrentKeyID(), ring2.KeyIDs())
	}
	// 原密钥环不被修改。
	if ring1.CurrentKeyID() != "k1" || len(ring1.KeyIDs()) != 1 {
		t.Fatal("Rotate 修改了原密钥环")
	}
	// 新密钥环可读取旧数据，并用新密钥写新数据。
	sealer2 := mustSealer(t, ring2)
	if got := mustOpen(t, sealer2, binding, oldSealed); string(got) != "old-secret" {
		t.Fatalf("轮换后旧数据 = %q", got)
	}
	newSealed := mustSeal(t, sealer2, binding, []byte("new-secret"))
	if keyID, _ := KeyIDOf(newSealed); keyID != "k2" {
		t.Fatalf("轮换后新密文 key_id = %q", keyID)
	}
	logText := logBuffer.String()
	if !bytes.Contains([]byte(logText), []byte("k1")) || !bytes.Contains([]byte(logText), []byte("k2")) {
		t.Fatalf("轮换日志缺少密钥编号: %s", logText)
	}
	if bytes.Contains([]byte(logText), []byte("material")) {
		t.Fatalf("轮换日志出现密钥材料字段: %s", logText)
	}
	assertLogDoesNotContainKeyMaterial(t, logBuffer.Bytes(), ring2)

	// 重复编号轮换失败。
	if _, err := rotator.Rotate("k1"); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("重复编号轮换错误 = %v", err)
	}
}

func TestNewRotatorRequiresKeyring(t *testing.T) {
	if _, err := NewRotator(nil, newMemStore(), nil); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil 密钥环错误 = %v", err)
	}
}

func TestReencryptContextCancellationBeforeStart(t *testing.T) {
	fixture := newReencryptFixture(t, 2)
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rotator.Reencrypt(ctx, ReencryptOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误 = %v, 期望 context.Canceled", err)
	}
	if count := fixture.store.countByKey(t, "k2"); count != 0 {
		t.Fatalf("取消后仍更新了 %d 条记录", count)
	}
}

// disorderedStore 故意返回不前进的记录顺序，用于验证 Rotator 对存储契约违反的
// 防御性检查；它不是生产实现。
type disorderedStore struct {
	record SealedRecord
}

// LoadBatch 实现 SealedStore，忽略 afterID 并重复返回同一条记录。
func (s *disorderedStore) LoadBatch(context.Context, string, string, int) ([]SealedRecord, error) {
	return []SealedRecord{s.record, s.record}, nil
}

// Replace 实现 SealedStore，不改变存储内容。
func (s *disorderedStore) Replace(context.Context, string, []byte, []byte) error {
	return nil
}

func TestRotatorCurrentKeyID(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	rotator, err := NewRotator(ring, newMemStore(), nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	if got := rotator.CurrentKeyID(); got != "k1" {
		t.Fatalf("CurrentKeyID = %q, 期望 k1", got)
	}
	var nilRotator *Rotator
	if got := nilRotator.CurrentKeyID(); got != "" {
		t.Fatalf("nil Rotator CurrentKeyID = %q, 期望空", got)
	}
}

func TestRotateDoesNotRequireStore(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	rotator, err := NewRotator(ring, nil, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	rotated, err := rotator.Rotate("k2")
	if err != nil {
		t.Fatalf("无存储时 Rotate 失败: %v", err)
	}
	if rotated.CurrentKeyID() != "k2" || !rotated.HasKey("k1") {
		t.Fatalf("轮换结果错误: current=%q ids=%v", rotated.CurrentKeyID(), rotated.KeyIDs())
	}
}

func TestReencryptPreservesContextErrorsFromStore(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "取消", err: context.Canceled},
		{name: "超时", err: context.DeadlineExceeded},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newReencryptFixture(t, 2)
			fixture.store.loadErr = testCase.err
			rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
			if err != nil {
				t.Fatalf("NewRotator 失败: %v", err)
			}
			if _, err := rotator.Reencrypt(context.Background(), ReencryptOptions{}); !errors.Is(err, testCase.err) {
				t.Fatalf("Reencrypt 错误 = %v, 期望 %v", err, testCase.err)
			}
			if _, _, err := rotator.RetireKey(context.Background(), "k1", RetireOptions{}); !errors.Is(err, testCase.err) {
				t.Fatalf("RetireKey 错误 = %v, 期望 %v", err, testCase.err)
			}
		})
	}
}

func TestReencryptDeduplicatesExplicitSourceKeys(t *testing.T) {
	fixture := newReencryptFixture(t, 3)
	rotator, err := NewRotator(fixture.ring2, fixture.store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator.Reencrypt(context.Background(), ReencryptOptions{
		SourceKeyIDs: []string{"k1", "k1", "k1"},
	})
	if err != nil {
		t.Fatalf("Reencrypt 失败: %v", err)
	}
	if len(report.SourceKeyIDs) != 1 || report.SourceKeyIDs[0] != "k1" {
		t.Fatalf("SourceKeyIDs = %v, 期望去重后 [k1]", report.SourceKeyIDs)
	}
	if report.Updated != 3 {
		t.Fatalf("Updated = %d, 期望 3", report.Updated)
	}
	assertAllReadable(t, fixture, fixture.sealer2)
}

func TestReencryptRejectsNonAdvancingStoreOrder(t *testing.T) {
	fixture := newReencryptFixture(t, 1)
	binding := Binding{Purpose: "mfa.totp", ObjectID: "rec-1", ScopeID: ScopeSystem}
	sealed := mustSeal(t, fixture.sealer1, binding, []byte("store-contract"))
	store := &disorderedStore{record: SealedRecord{ID: "rec-1", Binding: binding, Sealed: sealed}}
	rotator, err := NewRotator(fixture.ring2, store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	if _, err := rotator.Reencrypt(context.Background(), ReencryptOptions{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("记录顺序不前进错误 = %v, 期望 ErrStoreUnavailable", err)
	}
}

// TestKeyRotationPersistenceAndKeyLossFlow 验证文件级主密钥的完整流程：受保护文件
// 写入与加载、轮换并持久化、重启后读取旧数据、重加密、退役旧密钥，以及主密钥
// 文件丢失时明确失败且不静默生成新密钥。
func TestKeyRotationPersistenceAndKeyLossFlow(t *testing.T) {
	ctx := context.Background()
	dir := testutil.TempDir(t)
	keyPath := filepath.Join(dir, "master-key.json")
	binding := Binding{Purpose: "mfa.totp", ObjectID: "mfa-flow-1", ScopeID: ScopeSystem}
	oldPlaintext := []byte("flow-initial-totp-seed")

	ring1, err := GenerateKeyring("k1", fixedTestTime())
	if err != nil {
		t.Fatalf("GenerateKeyring 失败: %v", err)
	}
	doc1, err := ring1.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if err := WriteProtectedFile(keyPath, doc1); err != nil {
		t.Fatalf("WriteProtectedFile 失败: %v", err)
	}
	if err := CheckProtectedFile(keyPath); err != nil {
		t.Fatalf("写入后受保护文件检查失败: %v", err)
	}
	provider, err := NewFileProvider(keyPath)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	loaded1, err := LoadKeyring(ctx, provider)
	if err != nil {
		t.Fatalf("LoadKeyring 失败: %v", err)
	}
	sealer1, err := NewSealer(loaded1, nil)
	if err != nil {
		t.Fatalf("NewSealer 失败: %v", err)
	}
	oldSealed, err := sealer1.Seal(binding, oldPlaintext)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	store := newMemStore()
	store.put(SealedRecord{ID: binding.ObjectID, Binding: binding, Sealed: oldSealed})

	// 轮换：生成新写密钥并持久化；旧密钥保留为历史读密钥，旧数据仍可读取。
	rotator1, err := NewRotator(loaded1, store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	ring2, err := rotator1.Rotate("k2")
	if err != nil {
		t.Fatalf("Rotate 失败: %v", err)
	}
	doc2, err := ring2.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if err := WriteProtectedFile(keyPath, doc2); err != nil {
		t.Fatalf("持久化轮换后密钥环失败: %v", err)
	}
	reloaded, err := LoadKeyring(ctx, provider)
	if err != nil {
		t.Fatalf("重新加载轮换后密钥环失败: %v", err)
	}
	sealer2, err := NewSealer(reloaded, nil)
	if err != nil {
		t.Fatalf("NewSealer 失败: %v", err)
	}
	got, err := sealer2.Open(binding, oldSealed)
	if err != nil {
		t.Fatalf("轮换后读取旧数据失败: %v", err)
	}
	if !bytes.Equal(got, oldPlaintext) {
		t.Fatal("轮换后旧数据解密结果不一致")
	}

	// 重加密完成后记录改用新写密钥，重启加载的密钥环仍可解密。
	rotator2, err := NewRotator(reloaded, store, nil)
	if err != nil {
		t.Fatalf("NewRotator 失败: %v", err)
	}
	report, err := rotator2.Reencrypt(ctx, ReencryptOptions{})
	if err != nil {
		t.Fatalf("Reencrypt 失败: %v", err)
	}
	if report.Updated != 1 || report.Remaining != 0 {
		t.Fatalf("重加密报告 = %+v", report)
	}
	stored := store.get(t, binding.ObjectID)
	if keyID, err := KeyIDOf(stored.Sealed); err != nil || keyID != "k2" {
		t.Fatalf("重加密后 key_id = %q, %v", keyID, err)
	}

	// 零引用后退役旧密钥并持久化；旧密文明确返回 ErrKeyNotFound，而不是静默
	// 生成新密钥或退回其它密钥。
	retired, retireReport, err := rotator2.RetireKey(ctx, "k1", RetireOptions{})
	if err != nil {
		t.Fatalf("RetireKey 失败: %v", err)
	}
	if retireReport.Referenced != 0 || retired.HasKey("k1") {
		t.Fatalf("退役结果 = referenced %d, hasK1 %v", retireReport.Referenced, retired.HasKey("k1"))
	}
	doc3, err := retired.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if err := WriteProtectedFile(keyPath, doc3); err != nil {
		t.Fatalf("持久化退役后密钥环失败: %v", err)
	}
	reloaded2, err := LoadKeyring(ctx, provider)
	if err != nil {
		t.Fatalf("重新加载退役后密钥环失败: %v", err)
	}
	sealer3, err := NewSealer(reloaded2, nil)
	if err != nil {
		t.Fatalf("NewSealer 失败: %v", err)
	}
	if _, err := sealer3.Open(binding, oldSealed); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("退役后旧密文错误 = %v, 期望 ErrKeyNotFound", err)
	}
	if _, err := sealer3.Open(binding, stored.Sealed); err != nil {
		t.Fatalf("退役后解密当前数据失败: %v", err)
	}

	// 主密钥文件丢失时必须明确失败，且不创建新的密钥文件。
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("删除密钥文件失败: %v", err)
	}
	if _, err := LoadKeyring(ctx, provider); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("密钥文件丢失错误 = %v, 期望 ErrFileInvalid", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("密钥文件丢失后被重新创建: %v", err)
	}
}
