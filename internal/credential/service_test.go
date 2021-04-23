package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const testCredentialID = "otc_0123456789abcdef0123456789abcdef"

// fakeStore 是 Store 的测试替身，用于验证服务层错误映射、日志与时钟行为；
// 真实 SQLite 语义由 internal/credential/sqlite 的测试验证。
type fakeStore struct {
	mu sync.Mutex

	inserted     []Record
	insertErr    error
	replaceCalls int
	replaceErr   error

	loadRecord Record
	loadFound  bool
	loadErr    error

	consumeOK    bool
	consumeErr   error
	consumeCalls int

	failedAttempts int
	failedResult   FailedAttemptResult
	failedErr      error

	revokeOK  bool
	revokeErr error

	deleted   int64
	deleteErr error
}

// Insert 实现 Store。
func (f *fakeStore) Insert(_ context.Context, record Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserted = append(f.inserted, record)
	return nil
}

// ReplaceActiveAndInsert 实现 Store。
func (f *fakeStore) ReplaceActiveAndInsert(_ context.Context, record Record, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceCalls++
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.inserted = append(f.inserted, record)
	return nil
}

// LoadByID 实现 Store。
func (f *fakeStore) LoadByID(_ context.Context, _ string) (Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return Record{}, false, f.loadErr
	}
	return f.loadRecord, f.loadFound, nil
}

// Consume 实现 Store。
func (f *fakeStore) Consume(_ context.Context, _ ConsumeCondition) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumeCalls++
	if f.consumeErr != nil {
		return false, f.consumeErr
	}
	return f.consumeOK, nil
}

// RecordFailedAttempt 实现 Store。
func (f *fakeStore) RecordFailedAttempt(_ context.Context, _ string, _ time.Time) (FailedAttemptResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failedAttempts++
	if f.failedErr != nil {
		return FailedAttemptResult{}, f.failedErr
	}
	return f.failedResult, nil
}

// Revoke 实现 Store。
func (f *fakeStore) Revoke(_ context.Context, _ RevokeCondition) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return false, f.revokeErr
	}
	return f.revokeOK, nil
}

// DeleteExpired 实现 Store。
func (f *fakeStore) DeleteExpired(_ context.Context, _ time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return f.deleted, nil
}

// mutableClock 是可注入的测试时钟。
type mutableClock struct {
	now time.Time
}

// Now 返回当前测试时间。
func (c *mutableClock) Now() time.Time {
	return c.now
}

// advance 前进时间。
func (c *mutableClock) advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

// newTestKeyring 生成只用于测试的密钥环。
func newTestKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	ring, err := secrets.GenerateKeyring("k1", time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateKeyring 失败: %v", err)
	}
	return ring
}

// newTestClock 返回从固定时间开始的测试时钟。
func newTestClock() *mutableClock {
	return &mutableClock{now: time.Date(2026, 11, 15, 12, 0, 0, 123456789, time.UTC)}
}

// newTestService 用给定替换存储构造服务。
func newTestService(t *testing.T, store Store, options Options) *Service {
	t.Helper()
	if options.Keyring == nil {
		options.Keyring = newTestKeyring(t)
	}
	service, err := New(store, options)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return service
}

// TestNewRejectsInvalidOptions 验证 nil/typed nil 存储与缺失密钥环都明确失败。
func TestNewRejectsInvalidOptions(t *testing.T) {
	ring := newTestKeyring(t)
	if _, err := New(nil, Options{Keyring: ring}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 存储错误 = %v", err)
	}
	var typedNil *fakeStore
	if _, err := New(typedNil, Options{Keyring: ring}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("typed nil 存储错误 = %v", err)
	}
	if _, err := New(&fakeStore{}, Options{}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 密钥环错误 = %v", err)
	}
	service, err := New(&fakeStore{}, Options{Keyring: ring})
	if err != nil {
		t.Fatalf("合法选项失败: %v", err)
	}
	_ = service
}

// TestIssueTokenStoresOnlyDigestAndTruncatesClock 验证高熵令牌只保存摘要、key_id
// 为空，并验证时间按 UTC 毫秒截断。
func TestIssueTokenStoresOnlyDigestAndTruncatesClock(t *testing.T) {
	store := &fakeStore{}
	clock := newTestClock()
	service := newTestService(t, store, Options{Now: clock.Now})
	issued, err := service.Issue(context.Background(), IssueRequest{
		Purpose: "email.verify",
		Target:  "user-1",
		Kind:    KindToken,
		TTL:     10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if len(store.inserted) != 1 {
		t.Fatalf("写入记录数 = %d", len(store.inserted))
	}
	record := store.inserted[0]
	wantCreated := clock.now.UTC().Truncate(time.Millisecond)
	if !record.CreatedAt.Equal(wantCreated) {
		t.Fatalf("CreatedAt = %s，期望 %s", record.CreatedAt, wantCreated)
	}
	if !record.ExpiresAt.Equal(wantCreated.Add(10 * time.Minute)) {
		t.Fatalf("ExpiresAt = %s", record.ExpiresAt)
	}
	if record.KeyID != "" {
		t.Fatalf("高熵令牌 key_id = %q，期望空", record.KeyID)
	}
	if len(record.VerifierHash) != 32 {
		t.Fatalf("摘要长度 = %d", len(record.VerifierHash))
	}
	if record.ContextJSON == "" || strings.Contains(record.ContextJSON, issued.Secret.Reveal()) {
		t.Fatalf("context_json 异常: %s", record.ContextJSON)
	}
	if len(issued.Secret.Reveal()) != TokenSecretLength {
		t.Fatalf("令牌长度 = %d", len(issued.Secret.Reveal()))
	}
	if issued.ID != record.ID || issued.Kind != KindToken {
		t.Fatalf("签发结果与记录不一致: %+v", issued)
	}
}

// TestIssueCodeUsesCurrentKeyAndKeyedDigest 验证低熵验证码使用当前密钥与
// HMAC-SHA256 受密钥保护摘要。
func TestIssueCodeUsesCurrentKeyAndKeyedDigest(t *testing.T) {
	store := &fakeStore{}
	ring := newTestKeyring(t)
	service := newTestService(t, store, Options{Keyring: ring})
	issued, err := service.Issue(context.Background(), IssueRequest{
		Purpose: "password.reset",
		Target:  "user-2",
		Kind:    KindCode,
	})
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	record := store.inserted[0]
	if record.KeyID != ring.CurrentKeyID() {
		t.Fatalf("key_id = %q，期望当前写密钥", record.KeyID)
	}
	if len(record.VerifierHash) != secrets.KeyedDigestSize {
		t.Fatalf("摘要长度 = %d", len(record.VerifierHash))
	}
	expected, err := ring.HMACDigest(record.KeyID, hmacDomain,
		codeDigestMessage(record.ID, record.Purpose, record.Target, record.AppID, issued.Secret.Reveal()))
	if err != nil {
		t.Fatalf("HMACDigest 失败: %v", err)
	}
	if !bytes.Equal(expected, record.VerifierHash) {
		t.Fatal("验证码摘要与密钥环派生结果不一致")
	}
	code := issued.Secret.Reveal()
	if len(code) != CodeLength {
		t.Fatalf("验证码长度 = %d", len(code))
	}
}

// TestReplaceUsesReplacePath 验证 Replace 强制走原子替换路径。
func TestReplaceUsesReplacePath(t *testing.T) {
	store := &fakeStore{}
	service := newTestService(t, store, Options{})
	if _, err := service.Replace(context.Background(), IssueRequest{
		Purpose: "email.verify",
		Target:  "user-1",
		Kind:    KindToken,
	}); err != nil {
		t.Fatalf("Replace 失败: %v", err)
	}
	if store.replaceCalls != 1 {
		t.Fatalf("替换路径调用次数 = %d", store.replaceCalls)
	}
}

// TestIssueRandomSourceFailure 验证随机源失败不会签发凭证。
func TestIssueRandomSourceFailure(t *testing.T) {
	store := &fakeStore{}
	service := newTestService(t, store, Options{
		Random: failingReader{err: errors.New("熵源不可用")},
	})
	if _, err := service.Issue(context.Background(), IssueRequest{
		Purpose: "email.verify",
		Target:  "user-1",
		Kind:    KindToken,
	}); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("错误 = %v，期望 ErrRandomSource", err)
	}
	if len(store.inserted) != 0 {
		t.Fatal("随机源失败后仍写入了记录")
	}
}

// TestStoreFailureNeverReturnsSuccess 验证各类存储错误都映射为 ErrStoreUnavailable
// 且不返回成功结果；context 取消保留原语义。
func TestStoreFailureNeverReturnsSuccess(t *testing.T) {
	tokenBinding := struct{ purpose, target, appID string }{"email.verify", "user-1", ""}
	validToken := "token-value"
	validRecord := Record{
		ID:           testCredentialID,
		Purpose:      tokenBinding.purpose,
		Target:       tokenBinding.target,
		AppID:        tokenBinding.appID,
		VerifierHash: tokenVerifierHash(testCredentialID, tokenBinding.purpose, tokenBinding.target, tokenBinding.appID, validToken),
		MaxAttempts:  DefaultMaxAttempts,
		CreatedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	tokenRequest := VerifyRequest{
		Kind:    KindToken,
		ID:      testCredentialID,
		Purpose: tokenBinding.purpose,
		Target:  tokenBinding.target,
		Secret:  validToken,
	}
	cases := []struct {
		name  string
		store *fakeStore
		run   func(*Service) error
	}{
		{
			name:  "写入失败",
			store: &fakeStore{insertErr: errors.New("写失败")},
			run: func(service *Service) error {
				_, err := service.Issue(context.Background(), IssueRequest{Purpose: "p", Target: "t", Kind: KindToken})
				return err
			},
		},
		{
			name:  "替换写入失败",
			store: &fakeStore{replaceErr: errors.New("写失败")},
			run: func(service *Service) error {
				_, err := service.Replace(context.Background(), IssueRequest{Purpose: "p", Target: "t", Kind: KindToken})
				return err
			},
		},
		{
			name:  "读取失败",
			store: &fakeStore{loadErr: errors.New("读失败")},
			run: func(service *Service) error {
				_, err := service.VerifyAndConsume(context.Background(), tokenRequest)
				return err
			},
		},
		{
			name:  "消费失败",
			store: &fakeStore{loadFound: true, loadRecord: validRecord, consumeErr: errors.New("消费失败")},
			run: func(service *Service) error {
				_, err := service.VerifyAndConsume(context.Background(), tokenRequest)
				return err
			},
		},
		{
			name:  "清理失败",
			store: &fakeStore{deleteErr: errors.New("删除失败")},
			run: func(service *Service) error {
				_, err := service.Cleanup(context.Background(), 0)
				return err
			},
		},
		{
			name:  "取消失败",
			store: &fakeStore{revokeErr: errors.New("撤销失败")},
			run: func(service *Service) error {
				return service.Cancel(context.Background(), CancelRequest{ID: testCredentialID, Purpose: "p", Target: "t"})
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := newTestService(t, testCase.store, Options{})
			err := testCase.run(service)
			if !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("错误 = %v，期望 ErrStoreUnavailable", err)
			}
			if testCase.name == "消费失败" {
				// 错误路径已经返回 ErrStoreUnavailable，不能同时得到成功结果；
				// run 只返回错误，因此这里断言错误类别即可。
				if err == nil {
					t.Fatal("存储失败时返回了成功")
				}
			}
		})
	}

	// 存储返回 context 错误时保留取消/超时语义，便于上层停止重试。
	ctxService := newTestService(t, &fakeStore{loadErr: context.Canceled}, Options{})
	if _, err := ctxService.VerifyAndConsume(context.Background(), tokenRequest); !errors.Is(err, context.Canceled) {
		t.Fatalf("context 语义错误 = %v", err)
	}
}

// TestVerifyInvalidReasons 验证所有失效原因对外都是同一个 ErrInvalidCredential，
// 但内部原因可诊断。
func TestVerifyInvalidReasons(t *testing.T) {
	clock := newTestClock()
	now := clock.now.UTC().Truncate(time.Millisecond)
	consumed := now
	revoked := now
	baseRecord := Record{
		ID:           testCredentialID,
		Purpose:      "email.verify",
		Target:       "user-1",
		VerifierHash: tokenVerifierHash(testCredentialID, "email.verify", "user-1", "", "oracle-secret"),
		MaxAttempts:  DefaultMaxAttempts,
		CreatedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Hour),
	}
	request := VerifyRequest{
		Kind:    KindToken,
		ID:      testCredentialID,
		Purpose: "email.verify",
		Target:  "user-1",
		Secret:  "oracle-secret",
	}
	expiredRecord := baseRecord
	expiredRecord.ExpiresAt = now
	consumedRecord := baseRecord
	consumedRecord.ConsumedAt = &consumed
	revokedRecord := baseRecord
	revokedRecord.RevokedAt = &revoked
	exhaustedRecord := baseRecord
	exhaustedRecord.Attempts = DefaultMaxAttempts
	cases := []struct {
		name       string
		store      *fakeStore
		request    VerifyRequest
		wantReason Reason
	}{
		{name: "不存在", store: &fakeStore{loadFound: false}, request: request, wantReason: ReasonNotFound},
		{name: "绑定不符", store: &fakeStore{loadFound: true, loadRecord: baseRecord}, request: VerifyRequest{Kind: KindToken, ID: testCredentialID, Purpose: "other", Target: "user-1", Secret: "oracle-secret"}, wantReason: ReasonBindingMismatch},
		{name: "已过期", store: &fakeStore{loadFound: true, loadRecord: expiredRecord}, request: request, wantReason: ReasonExpired},
		{name: "已消费", store: &fakeStore{loadFound: true, loadRecord: consumedRecord}, request: request, wantReason: ReasonConsumed},
		{name: "已撤销", store: &fakeStore{loadFound: true, loadRecord: revokedRecord}, request: request, wantReason: ReasonRevoked},
		{name: "尝试用尽", store: &fakeStore{loadFound: true, loadRecord: exhaustedRecord}, request: request, wantReason: ReasonAttemptsExhausted},
		{name: "令牌不匹配", store: &fakeStore{loadFound: true, loadRecord: baseRecord}, request: VerifyRequest{Kind: KindToken, ID: testCredentialID, Purpose: "email.verify", Target: "user-1", Secret: "wrong-secret"}, wantReason: ReasonSecretMismatch},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := newTestService(t, testCase.store, Options{Now: clock.Now})
			_, err := service.VerifyAndConsume(context.Background(), testCase.request)
			if !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("错误 = %v，期望 ErrInvalidCredential", err)
			}
			if err.Error() != ErrInvalidCredential.Error() {
				t.Fatalf("错误文本可区分: %q", err.Error())
			}
			reason, ok := InvalidReason(err)
			if !ok || reason != testCase.wantReason {
				t.Fatalf("内部原因 = %v/%v，期望 %v", reason, ok, testCase.wantReason)
			}
		})
	}

	// 高熵令牌内容不匹配不消耗尝试次数。
	tokenStore := &fakeStore{loadFound: true, loadRecord: baseRecord}
	tokenService := newTestService(t, tokenStore, Options{Now: clock.Now})
	if _, err := tokenService.VerifyAndConsume(context.Background(), VerifyRequest{
		Kind: KindToken, ID: testCredentialID, Purpose: "email.verify", Target: "user-1", Secret: "wrong-secret",
	}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("令牌不匹配错误 = %v", err)
	}
	if tokenStore.failedAttempts != 0 {
		t.Fatalf("令牌不匹配仍登记了 %d 次失败尝试", tokenStore.failedAttempts)
	}

	// 低熵验证码不匹配会登记失败尝试，并按剩余次数给出内部原因。
	codeRecord := Record{
		ID:           testCredentialID,
		Purpose:      "email.verify",
		Target:       "user-1",
		KeyID:        newTestKeyring(t).CurrentKeyID(),
		VerifierHash: bytes.Repeat([]byte{0x11}, 32),
		MaxAttempts:  DefaultMaxAttempts,
		CreatedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Hour),
	}
	codeStore := &fakeStore{loadFound: true, loadRecord: codeRecord, failedResult: FailedAttemptResult{Remaining: 2, Active: true}}
	codeService := newTestService(t, codeStore, Options{Now: clock.Now})
	_, err := codeService.VerifyAndConsume(context.Background(), VerifyRequest{
		Kind: KindCode, ID: testCredentialID, Purpose: "email.verify", Target: "user-1", Secret: "00000000",
	})
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("验证码不匹配错误 = %v", err)
	}
	if codeStore.failedAttempts != 1 {
		t.Fatalf("验证码失败尝试登记次数 = %d", codeStore.failedAttempts)
	}
	if reason, _ := InvalidReason(err); reason != ReasonSecretMismatch {
		t.Fatalf("验证码失败原因 = %v", reason)
	}

	codeStore.failedResult = FailedAttemptResult{Remaining: 0, Active: false}
	_, err = codeService.VerifyAndConsume(context.Background(), VerifyRequest{
		Kind: KindCode, ID: testCredentialID, Purpose: "email.verify", Target: "user-1", Secret: "00000000",
	})
	if reason, _ := InvalidReason(err); reason != ReasonAttemptsExhausted {
		t.Fatalf("尝试用尽原因 = %v", reason)
	}
}

// TestVerifyConsumeSuccessAndConflict 验证成功消费返回结果，条件消费失败不返回成功。
func TestVerifyConsumeSuccessAndConflict(t *testing.T) {
	clock := newTestClock()
	now := clock.now.UTC().Truncate(time.Millisecond)
	secret := "token-value"
	record := Record{
		ID:           testCredentialID,
		Purpose:      "email.verify",
		Target:       "user-1",
		VerifierHash: tokenVerifierHash(testCredentialID, "email.verify", "user-1", "", secret),
		MaxAttempts:  DefaultMaxAttempts,
		CreatedAt:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Hour),
	}
	request := VerifyRequest{Kind: KindToken, ID: testCredentialID, Purpose: "email.verify", Target: "user-1", Secret: secret}

	successStore := &fakeStore{loadFound: true, loadRecord: record, consumeOK: true}
	service := newTestService(t, successStore, Options{Now: clock.Now})
	result, err := service.VerifyAndConsume(context.Background(), request)
	if err != nil {
		t.Fatalf("消费失败: %v", err)
	}
	if result.ID != record.ID || result.Target != record.Target || !result.ConsumedAt.Equal(now) {
		t.Fatalf("消费结果 = %+v", result)
	}
	if successStore.consumeCalls != 1 {
		t.Fatalf("条件消费调用次数 = %d", successStore.consumeCalls)
	}

	conflictStore := &fakeStore{loadFound: true, loadRecord: record, consumeOK: false}
	conflictService := newTestService(t, conflictStore, Options{Now: clock.Now})
	_, err = conflictService.VerifyAndConsume(context.Background(), request)
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("条件消费失败错误 = %v", err)
	}
	if reason, _ := InvalidReason(err); reason != ReasonConsumeConflict {
		t.Fatalf("条件消费失败原因 = %v", reason)
	}
}

// TestCancelAndCleanup 验证取消与清理的校验与错误映射。
func TestCancelAndCleanup(t *testing.T) {
	clock := newTestClock()
	request := CancelRequest{ID: testCredentialID, Purpose: "email.verify", Target: "user-1"}
	okStore := &fakeStore{revokeOK: true}
	service := newTestService(t, okStore, Options{Now: clock.Now})
	if err := service.Cancel(context.Background(), request); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	inactiveStore := &fakeStore{revokeOK: false}
	inactiveService := newTestService(t, inactiveStore, Options{Now: clock.Now})
	if err := inactiveService.Cancel(context.Background(), request); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("非活动凭证取消失败错误 = %v", err)
	}
	if reason, _ := InvalidReason(inactiveService.Cancel(context.Background(), request)); reason != ReasonNotActive {
		t.Fatalf("取消失败原因 = %v", reason)
	}

	cleanupStore := &fakeStore{deleted: 3}
	cleanupService := newTestService(t, cleanupStore, Options{Now: clock.Now})
	report, err := cleanupService.Cleanup(context.Background(), 0)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if report.Deleted != 3 || !report.Cutoff.Equal(clock.now.UTC().Truncate(time.Millisecond)) {
		t.Fatalf("清理报告 = %+v", report)
	}
	if _, err := cleanupService.Cleanup(context.Background(), -1); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("负保留时长错误 = %v", err)
	}
	if _, err := cleanupService.Cleanup(context.Background(), MaxCleanupRetention+time.Hour); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("超长保留时长错误 = %v", err)
	}
}

// TestLogsDoNotLeakSecrets 验证签发与验证日志不包含令牌/验证码，并包含内部原因。
func TestLogsDoNotLeakSecrets(t *testing.T) {
	var buffer strings.Builder
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := &fakeStore{}
	service := newTestService(t, store, Options{Logger: logger})
	issued, err := service.Issue(context.Background(), IssueRequest{
		Purpose: "password.reset",
		Target:  "user-1",
		Kind:    KindCode,
	})
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	code := issued.Secret.Reveal()
	if strings.Contains(buffer.String(), code) {
		t.Fatal("签发日志泄露验证码")
	}
	// 让验证失败并触发内部原因日志。
	service.store = &fakeStore{loadFound: false}
	_, err = service.VerifyAndConsume(context.Background(), VerifyRequest{
		Kind: KindCode, ID: issued.ID, Purpose: "password.reset", Target: "user-1", Secret: "00000000",
	})
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("验证错误 = %v", err)
	}
	logText := buffer.String()
	if strings.Contains(logText, code) || strings.Contains(logText, "00000000") {
		t.Fatalf("验证日志泄露秘密: %s", logText)
	}
	if !strings.Contains(logText, string(ReasonNotFound)) {
		t.Fatalf("验证日志缺少内部原因: %s", logText)
	}
}

// TestInvalidReasonHelper 验证包装后的错误仍可提取内部原因。
func TestInvalidReasonHelper(t *testing.T) {
	wrapped := fmt.Errorf("上层包装: %w", newInvalid(ReasonExpired))
	reason, ok := InvalidReason(wrapped)
	if !ok || reason != ReasonExpired {
		t.Fatalf("包装错误原因 = %v/%v", reason, ok)
	}
	if _, ok := InvalidReason(errors.New("普通错误")); ok {
		t.Fatal("普通错误被识别为凭证无效")
	}
}
