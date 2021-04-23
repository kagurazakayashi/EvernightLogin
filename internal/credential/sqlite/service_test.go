package sqlite_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// TestTokenIssueAndConsumeOnlyOnce 验证高熵令牌签发、首次消费成功、重复消费失败，
// 数据库只保存摘要而非令牌明文。
func TestTokenIssueAndConsumeOnlyOnce(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueToken("email.verify", "user-1", "")
	secret := issued.Secret.Reveal()
	if len(issued.ID) == 0 || len(secret) == 0 {
		t.Fatal("签发结果缺少 ID 或秘密")
	}
	// 数据库 verifier_hash 为 32 字节二进制摘要，不含令牌明文。
	var storedHash []byte
	rows, err := env.sqliteStore.QueryContext(context.Background(),
		`SELECT verifier_hash FROM one_time_credentials WHERE id=?`, issued.ID)
	if err != nil {
		t.Fatalf("读取摘要失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("凭证记录不存在")
	}
	if err := rows.Scan(&storedHash); err != nil {
		t.Fatalf("扫描摘要失败: %v", err)
	}
	if len(storedHash) != 32 {
		t.Fatalf("摘要长度 = %d", len(storedHash))
	}
	if bytes.Contains(storedHash, []byte(secret)) {
		t.Fatal("数据库摘要包含令牌明文")
	}

	verified, err := env.verifyIssued(issued, secret)
	if err != nil {
		t.Fatalf("首次验证失败: %v", err)
	}
	if verified.ID != issued.ID || verified.Target != "user-1" {
		t.Fatalf("验证结果 = %+v", verified)
	}
	if _, _, consumedAt, _, _ := env.rowState(issued.ID); !consumedAt.Valid {
		t.Fatal("成功消费后 consumed_at_ms 为空")
	}
	// 重复消费必须失败，且不泄露内部状态。
	if _, err := env.verifyIssued(issued, secret); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("重复消费错误 = %v", err)
	}
}

// TestCodeIssueAndConsumeOnlyOnce 验证低熵验证码首次消费成功、重复失败，且数据库
// 保存的是当前密钥派生的摘要。
func TestCodeIssueAndConsumeOnlyOnce(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueCode("email.verify", "user-1", "")
	code := issued.Secret.Reveal()
	if len(code) != 8 {
		t.Fatalf("验证码长度 = %d", len(code))
	}
	attempts, maxAttempts, consumedAt, _, keyID := env.rowState(issued.ID)
	if attempts != 0 || maxAttempts != 5 || consumedAt.Valid {
		t.Fatalf("初始行状态 = attempts %d max %d consumed %v", attempts, maxAttempts, consumedAt.Valid)
	}
	if !keyID.Valid || keyID.String != env.ring.CurrentKeyID() {
		t.Fatalf("key_id = %+v，期望当前写密钥", keyID)
	}
	if _, err := env.verifyIssued(issued, code); err != nil {
		t.Fatalf("首次验证失败: %v", err)
	}
	if _, err := env.verifyIssued(issued, code); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("重复消费错误 = %v", err)
	}
}

// TestWrongBindingRejected 验证错误用途/目标/应用都被拒绝，且错误不消耗凭证。
func TestWrongBindingRejected(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueToken("email.verify", "user-1", "")
	token := issued.Secret.Reveal()
	cases := []struct {
		name    string
		purpose string
		target  string
		appID   string
	}{
		{name: "错误用途", purpose: "password.reset", target: "user-1"},
		{name: "错误目标", purpose: "email.verify", target: "user-2"},
		{name: "错误应用", purpose: "email.verify", target: "user-1", appID: testAppA},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := env.verify(issued.ID, credential.KindToken, testCase.purpose, testCase.target, testCase.appID, token); !errors.Is(err, credential.ErrInvalidCredential) {
				t.Fatalf("错误绑定错误 = %v", err)
			}
		})
	}
	// 错误绑定不改变状态，正确绑定仍可消费。
	if _, err := env.verifyIssued(issued, token); err != nil {
		t.Fatalf("正确绑定验证失败: %v", err)
	}

	codeIssued := env.issueCode("email.verify", "user-1", "")
	if _, err := env.verify(codeIssued.ID, credential.KindCode, "email.verify", "user-1", "", "99999999"); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("错误验证码错误 = %v", err)
	}
	if attempts, _, _, _, _ := env.rowState(codeIssued.ID); attempts != 1 {
		t.Fatalf("错误验证码后 attempts = %d，期望 1", attempts)
	}
	// 错误绑定不应消耗尝试次数。
	if _, err := env.verify(codeIssued.ID, credential.KindCode, "other.purpose", "user-1", "", codeIssued.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("错误绑定错误 = %v", err)
	}
	if attempts, _, _, _, _ := env.rowState(codeIssued.ID); attempts != 1 {
		t.Fatalf("错误绑定不应增加尝试次数，实际 = %d", attempts)
	}
	if _, err := env.verifyIssued(codeIssued, codeIssued.Secret.Reveal()); err != nil {
		t.Fatalf("正确验证码验证失败: %v", err)
	}
}

// TestExpiryBoundary 验证恰好到期前一毫秒可用、到期即失效（令牌与验证码）。
func TestExpiryBoundary(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	ttl := 10 * time.Minute

	token := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-1", Kind: credential.KindToken, TTL: ttl,
	})
	code := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-2", Kind: credential.KindCode, TTL: ttl,
	})
	// 推进到到期前一毫秒：两者都应成功。
	env.clock.Advance(ttl - time.Millisecond)
	if _, err := env.verifyIssued(token, token.Secret.Reveal()); err != nil {
		t.Fatalf("令牌到期前一毫秒验证失败: %v", err)
	}
	if _, err := env.verifyIssued(code, code.Secret.Reveal()); err != nil {
		t.Fatalf("验证码到期前一毫秒验证失败: %v", err)
	}

	// 新凭证推进到恰好到期：两者都必须失败。
	exactToken := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-3", Kind: credential.KindToken, TTL: ttl,
	})
	exactCode := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-4", Kind: credential.KindCode, TTL: ttl,
	})
	env.clock.Advance(ttl)
	if _, err := env.verifyIssued(exactToken, exactToken.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("恰得到期令牌错误 = %v", err)
	}
	if _, err := env.verifyIssued(exactCode, exactCode.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("恰得到期验证码错误 = %v", err)
	}
	if reason, _ := credential.InvalidReason(mustVerifyError(t, env, exactCode, exactCode.Secret.Reveal())); reason != credential.ReasonExpired {
		t.Fatalf("到期内部原因 = %v", reason)
	}
}

// mustVerifyError 再次验证并返回错误，用于检查内部原因。
func mustVerifyError(t *testing.T, env *testEnv, issued credential.IssuedCredential, secret string) error {
	t.Helper()
	_, err := env.verifyIssued(issued, secret)
	if err == nil {
		t.Fatal("预期验证失败，但成功了")
	}
	return err
}

// TestAttemptLimit 验证低熵验证码尝试上限：错误次数受数据库约束，达到上限后
// 正确验证码也不能使用，且不会继续增加尝试次数。
func TestAttemptLimit(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-1", Kind: credential.KindCode, MaxAttempts: 3,
	})
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := env.verifyIssued(issued, "00000000"); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Fatalf("第 %d 次错误尝试错误 = %v", attempt, err)
		}
	}
	attempts, maxAttempts, _, _, _ := env.rowState(issued.ID)
	if attempts != 3 || maxAttempts != 3 {
		t.Fatalf("尝试次数 = %d/%d，期望 3/3", attempts, maxAttempts)
	}
	// 达到上限后正确验证码也失败，并保持尝试次数不变。
	if _, err := env.verifyIssued(issued, issued.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("尝试上限后正确验证码错误 = %v", err)
	}
	if attempts, _, _, _, _ := env.rowState(issued.ID); attempts != 3 {
		t.Fatalf("尝试上限后 attempts = %d", attempts)
	}
	if _, err := env.verifyIssued(issued, "11111111"); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("尝试上限后错误尝试错误 = %v", err)
	}
	if attempts, _, _, _, _ := env.rowState(issued.ID); attempts != 3 {
		t.Fatalf("尝试上限后错误尝试使 attempts = %d", attempts)
	}
}

// TestConcurrentTokenConsumptionOnlyOneSuccess 验证 6 个并发验证同一令牌只有一次
// 成功消费，其余得到统一无效错误。
func TestConcurrentTokenConsumptionOnlyOneSuccess(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueToken("oauth.confirm", "user-1", "")
	token := issued.Secret.Reveal()

	const goroutines = 6
	start := make(chan struct{})
	results := make(chan error, goroutines)
	successes := make(chan credential.VerifiedCredential, goroutines)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			verified, err := env.verifyIssued(issued, token)
			if err != nil {
				results <- err
				return
			}
			successes <- verified
			results <- nil
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(successes)

	successCount := 0
	for result := range results {
		if result == nil {
			successCount++
			continue
		}
		if !errors.Is(result, credential.ErrInvalidCredential) {
			t.Fatalf("并发消费错误类别 = %v", result)
		}
	}
	if successCount != 1 {
		t.Fatalf("并发消费成功次数 = %d，期望 1", successCount)
	}
	if success := <-successes; success.ID != issued.ID {
		t.Fatalf("成功结果 = %+v", success)
	}
}

// TestConcurrentWrongAttemptsBounded 验证并发错误验证码不会突破尝试上限。
func TestConcurrentWrongAttemptsBounded(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-1", Kind: credential.KindCode, MaxAttempts: 3,
	})
	const goroutines = 6
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	errorsCh := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := env.verifyIssued(issued, "00000000")
			errorsCh <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if !errors.Is(err, credential.ErrInvalidCredential) {
			t.Fatalf("并发错误尝试错误类别 = %v", err)
		}
	}
	attempts, maxAttempts, _, _, _ := env.rowState(issued.ID)
	if attempts != 3 || maxAttempts != 3 {
		t.Fatalf("并发后 attempts = %d/%d，期望 3/3", attempts, maxAttempts)
	}
	if _, err := env.verifyIssued(issued, issued.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("尝试上限后正确验证码错误 = %v", err)
	}
}

// TestCancel 验证取消只能撤销活动凭证，绑定不符与重复取消都失败。
func TestCancel(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueToken("email.verify", "user-1", "")
	request := credential.CancelRequest{ID: issued.ID, Purpose: "email.verify", Target: "user-1"}
	if err := env.service.Cancel(context.Background(), request); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	if _, _, _, revokedAt, _ := env.rowState(issued.ID); !revokedAt.Valid {
		t.Fatal("取消后 revoked_at_ms 为空")
	}
	if _, err := env.verifyIssued(issued, issued.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("取消后验证错误 = %v", err)
	}
	if err := env.service.Cancel(context.Background(), request); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("重复取消错误 = %v", err)
	}
	wrongBinding := credential.CancelRequest{ID: issued.ID, Purpose: "email.verify", Target: "user-2"}
	if err := env.service.Cancel(context.Background(), wrongBinding); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("错误绑定取消错误 = %v", err)
	}
}

// TestReplace 验证替换会撤销同作用域旧凭证，新凭证可用；其它作用域不受影响。
func TestReplace(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	env.insertApplication(testAppA)
	old := env.issueCode("email.verify", "user-1", "")
	newIssued := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-1", Kind: credential.KindCode, ReplaceActive: true,
	})
	if newIssued.ID == old.ID {
		t.Fatal("替换后 ID 未变化")
	}
	if _, _, _, revokedAt, _ := env.rowState(old.ID); !revokedAt.Valid {
		t.Fatal("替换后旧凭证未被撤销")
	}
	if _, err := env.verifyIssued(old, old.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("替换后旧凭证验证错误 = %v", err)
	}
	if _, err := env.verifyIssued(newIssued, newIssued.Secret.Reveal()); err != nil {
		t.Fatalf("替换后新凭证验证失败: %v", err)
	}

	// 应用作用域的替换不影响系统作用域凭证。
	systemIssued := env.issueToken("email.verify", "user-2", "")
	env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-2", AppID: testAppA, Kind: credential.KindToken, ReplaceActive: true,
	})
	if _, err := env.verifyIssued(systemIssued, systemIssued.Secret.Reveal()); err != nil {
		t.Fatalf("应用作用域替换影响了系统作用域凭证: %v", err)
	}
}

// TestApplicationBinding 验证应用绑定：只允许在签发时的应用作用域验证。
func TestApplicationBinding(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	env.insertApplication(testAppA)
	env.insertApplication(testAppB)
	issued := env.issueCode("email.verify", "user-1", testAppA)
	code := issued.Secret.Reveal()
	if _, err := env.verify(issued.ID, credential.KindCode, "email.verify", "user-1", testAppB, code); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("错误应用验证错误 = %v", err)
	}
	if _, err := env.verify(issued.ID, credential.KindCode, "email.verify", "user-1", "", code); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("系统作用域验证应用凭证错误 = %v", err)
	}
	if _, err := env.verify(issued.ID, credential.KindCode, "email.verify", "user-1", testAppA, code); err != nil {
		t.Fatalf("正确应用验证失败: %v", err)
	}
}

// TestCleanupExpired 验证过期清理只删除到期超过保留时长的记录，活动凭证不受影响。
func TestCleanupExpired(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	expiredToken := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-1", Kind: credential.KindToken, TTL: 10 * time.Minute,
	})
	activeToken := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-2", Kind: credential.KindToken, TTL: 24 * time.Hour,
	})
	env.clock.Advance(10 * time.Minute)
	report, err := env.service.Cleanup(context.Background(), 0)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if report.Deleted != 1 {
		t.Fatalf("清理删除数量 = %d，期望 1", report.Deleted)
	}
	if env.countCredentials() != 1 {
		t.Fatalf("清理后剩余记录 = %d，期望 1", env.countCredentials())
	}
	if _, err := env.verifyIssued(expiredToken, expiredToken.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("已清理凭证验证错误 = %v", err)
	}
	if _, err := env.verifyIssued(activeToken, activeToken.Secret.Reveal()); err != nil {
		t.Fatalf("活动凭证被误删: %v", err)
	}
	// 保留时长内的记录不应被提前删除。
	retained := env.issue(credential.IssueRequest{
		Purpose: "email.verify", Target: "user-3", Kind: credential.KindToken, TTL: 10 * time.Minute,
	})
	env.clock.Advance(10 * time.Minute)
	if report, err := env.service.Cleanup(context.Background(), time.Hour); err != nil || report.Deleted != 0 {
		t.Fatalf("保留时长内清理 = %+v, %v", report, err)
	}
	if _, err := env.verifyIssued(retained, retained.Secret.Reveal()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("已过期但保留中凭证验证错误 = %v", err)
	}
}

// TestDatabaseFailureNeverReturnsSuccess 验证数据库关闭后所有操作明确失败。
func TestDatabaseFailureNeverReturnsSuccess(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	issued := env.issueToken("email.verify", "user-1", "")
	if err := env.sqliteStore.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	if _, err := env.verifyIssued(issued, issued.Secret.Reveal()); !errors.Is(err, credential.ErrStoreUnavailable) {
		t.Fatalf("关闭数据库后验证错误 = %v，期望 ErrStoreUnavailable", err)
	}
	if _, err := env.service.Issue(context.Background(), credential.IssueRequest{
		Purpose: "email.verify", Target: "user-2", Kind: credential.KindToken,
	}); !errors.Is(err, credential.ErrStoreUnavailable) {
		t.Fatalf("关闭数据库后签发错误 = %v，期望 ErrStoreUnavailable", err)
	}
	if _, err := env.service.Cleanup(context.Background(), 0); !errors.Is(err, credential.ErrStoreUnavailable) {
		t.Fatalf("关闭数据库后清理错误 = %v，期望 ErrStoreUnavailable", err)
	}
	// 已取消上下文保持取消语义，而不是伪装成存储失败成功。
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := env.service.VerifyAndConsume(canceledCtx, credential.VerifyRequest{
		Kind: credential.KindToken, ID: issued.ID, Purpose: "email.verify", Target: "user-1", Secret: issued.Secret.Reveal(),
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消上下文错误 = %v", err)
	}
}

// TestKeyRotationKeepsOutstandingCodeVerifiable 验证轮换主密钥后未失效的历史验证码
// 仍可验证，新验证码使用新写密钥。
func TestKeyRotationKeepsOutstandingCodeVerifiable(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	oldIssued := env.issueCode("email.verify", "user-1", "")
	material, err := secrets.GenerateKeyMaterial()
	if err != nil {
		t.Fatalf("GenerateKeyMaterial 失败: %v", err)
	}
	rotatedRing, err := env.ring.RotateTo("k2", material, testBaseTime)
	if err != nil {
		t.Fatalf("RotateTo 失败: %v", err)
	}
	rotatedService := env.serviceWith(rotatedRing, nil)
	// 历史验证码使用旧 key_id，轮换后的密钥环保留历史读密钥。
	if _, err := rotatedService.VerifyAndConsume(context.Background(), credential.VerifyRequest{
		Kind: credential.KindCode, ID: oldIssued.ID, Purpose: oldIssued.Purpose,
		Target: oldIssued.Target, Secret: oldIssued.Secret.Reveal(),
	}); err != nil {
		t.Fatalf("轮换后历史验证码验证失败: %v", err)
	}
	newIssued, err := rotatedService.Issue(context.Background(), credential.IssueRequest{
		Purpose: "email.verify", Target: "user-2", Kind: credential.KindCode,
	})
	if err != nil {
		t.Fatalf("轮换后签发失败: %v", err)
	}
	if _, _, _, _, keyID := env.rowState(newIssued.ID); !keyID.Valid || keyID.String != "k2" {
		t.Fatalf("新验证码 key_id = %+v，期望 k2", keyID)
	}
	if _, err := rotatedService.VerifyAndConsume(context.Background(), credential.VerifyRequest{
		Kind: credential.KindCode, ID: newIssued.ID, Purpose: newIssued.Purpose,
		Target: newIssued.Target, Secret: newIssued.Secret.Reveal(),
	}); err != nil {
		t.Fatalf("轮换后新验证码验证失败: %v", err)
	}
}

// TestInvalidCredentialErrorsAreUniform 验证所有失效路径的外部错误文本一致，
// 内部原因可区分。
func TestInvalidCredentialErrorsAreUniform(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	token := env.issueToken("email.verify", "user-1", "")
	secret := token.Secret.Reveal()
	unknownID := "otc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// 错误秘密、错误绑定、未知 ID。
	failures := []error{}
	if _, err := env.verifyIssued(token, "wrong-token"); err != nil {
		failures = append(failures, err)
	}
	if _, err := env.verify(unknownID, credential.KindToken, "email.verify", "user-1", "", secret); err != nil {
		failures = append(failures, err)
	}
	if _, err := env.verify(token.ID, credential.KindToken, "other.purpose", "user-1", "", secret); err != nil {
		failures = append(failures, err)
	}
	if len(failures) != 3 {
		t.Fatalf("失败路径数量 = %d，期望 3", len(failures))
	}
	for _, err := range failures {
		if !errors.Is(err, credential.ErrInvalidCredential) {
			t.Fatalf("错误类别 = %v", err)
		}
		if err.Error() != credential.ErrInvalidCredential.Error() {
			t.Fatalf("外部错误文本不一致: %q", err.Error())
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token.ID) {
			t.Fatalf("错误文本泄露凭证信息: %q", err.Error())
		}
	}
	reasons := make(map[credential.Reason]bool)
	for _, err := range failures {
		reason, ok := credential.InvalidReason(err)
		if !ok {
			t.Fatalf("缺少内部原因: %v", err)
		}
		reasons[reason] = true
	}
	if len(reasons) < 2 {
		t.Fatalf("内部原因无法区分: %v", reasons)
	}
}

// TestLogsDoNotLeakSecrets 验证生产路径日志不含令牌、验证码或摘要，并包含内部原因。
func TestLogsDoNotLeakSecrets(t *testing.T) {
	var logBuffer strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env := newTestEnv(t, envConfig{logger: logger})
	codeIssued := env.issueCode("email.verify", "user-1", "")
	code := codeIssued.Secret.Reveal()
	if strings.Contains(logBuffer.String(), code) {
		t.Fatal("签发日志泄露验证码")
	}
	if _, err := env.verifyIssued(codeIssued, "00000000"); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("错误验证码验证错误 = %v", err)
	}
	tokenIssued := env.issueToken("email.verify", "user-2", "")
	if _, err := env.verifyIssued(tokenIssued, tokenIssued.Secret.Reveal()); err != nil {
		t.Fatalf("令牌验证失败: %v", err)
	}
	logText := logBuffer.String()
	for _, secretText := range []string{code, tokenIssued.Secret.Reveal(), "00000000"} {
		if strings.Contains(logText, secretText) {
			t.Fatalf("日志泄露秘密 %q: %s", secretText, logText)
		}
	}
	if !strings.Contains(logText, string(credential.ReasonSecretMismatch)) {
		t.Fatalf("日志缺少内部失败原因: %s", logText)
	}
}

// TestRowNoPlaintextSecret 验证验证码与令牌都不会明文写入 verifier_hash。
func TestRowNoPlaintextSecret(t *testing.T) {
	env := newTestEnv(t, envConfig{})
	codeIssued := env.issueCode("email.verify", "user-1", "")
	rows, err := env.sqliteStore.QueryContext(context.Background(),
		`SELECT verifier_hash FROM one_time_credentials WHERE id=?`, codeIssued.ID)
	if err != nil {
		t.Fatalf("读取摘要失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("凭证记录不存在")
	}
	var hash []byte
	if err := rows.Scan(&hash); err != nil {
		t.Fatalf("扫描摘要失败: %v", err)
	}
	if bytes.Contains(hash, []byte(codeIssued.Secret.Reveal())) {
		t.Fatal("验证码摘要包含明文")
	}
}
