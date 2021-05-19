package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// fakeClock 是可手动推进的并发安全时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前测试时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进测试时间。
func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// newTestLimiter 构造带假时钟的限流器。
func newTestLimiter(t *testing.T, policy Policy, maxEntries int) (*Limiter, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	limiter, err := New(Options{Policy: policy, MaxEntries: maxEntries, Now: clock.Now})
	if err != nil {
		t.Fatalf("构造限流器失败: %v", err)
	}
	return limiter, clock
}

// TestPolicyValidation 验证策略启用与边界。
func TestPolicyValidation(t *testing.T) {
	valid := []Policy{
		{},
		{Limit: 1, Window: MinWindow},
		{Limit: MaxRequestsPerWindow, Window: MaxWindow},
	}
	for _, policy := range valid {
		if err := policy.Validate(); err != nil {
			t.Fatalf("合法策略 %+v 被拒绝: %v", policy, err)
		}
	}
	invalid := []Policy{
		{Limit: 1},
		{Window: time.Second},
		{Limit: -1, Window: time.Second},
		{Limit: 1, Window: -time.Second},
		{Limit: MaxRequestsPerWindow + 1, Window: time.Second},
		{Limit: 1, Window: MinWindow - time.Nanosecond},
		{Limit: 1, Window: MaxWindow + time.Hour},
	}
	for _, policy := range invalid {
		if err := policy.Validate(); err == nil {
			t.Fatalf("非法策略 %+v 应被拒绝", policy)
		}
	}
	if (Policy{}).Enabled() || !(Policy{Limit: 1, Window: time.Second}).Enabled() {
		t.Fatal("Enabled 判定错误")
	}
}

// TestNewValidation 验证限流器构造参数边界。
func TestNewValidation(t *testing.T) {
	base := Options{Policy: Policy{Limit: 5, Window: time.Second}}
	if _, err := New(Options{}); err == nil {
		t.Fatal("未启用策略应拒绝构造")
	}
	if _, err := New(base); err != nil {
		t.Fatalf("默认容量构造失败: %v", err)
	}
	bad := []Options{
		{Policy: base.Policy, MaxEntries: -1},
		{Policy: base.Policy, MaxEntries: MaxMaxEntries + 1},
		{Policy: base.Policy, CleanupInterval: -1},
		{Policy: base.Policy, CleanupInterval: MaxCleanupInterval + time.Second},
	}
	for _, options := range bad {
		if _, err := New(options); err == nil {
			t.Fatalf("非法选项 %+v 应被拒绝", options)
		}
	}
	if _, err := New(Options{Policy: Policy{Limit: 1}}); err == nil {
		t.Fatal("策略缺窗口应拒绝构造")
	}
}

// TestAllowWindowAndRetry 验证固定窗口计数、拒绝等待与窗口重置。
func TestAllowWindowAndRetry(t *testing.T) {
	limiter, clock := newTestLimiter(t, Policy{Limit: 2, Window: 100 * time.Millisecond}, 8)
	for index := 0; index < 2; index++ {
		decision := limiter.Allow("client")
		if !decision.Allowed || decision.Reason != "" {
			t.Fatalf("第 %d 次请求应允许: %+v", index+1, decision)
		}
	}
	denied := limiter.Allow("client")
	if denied.Allowed || denied.Reason != "limit" {
		t.Fatalf("超过窗口限制应拒绝: %+v", denied)
	}
	if denied.RetryAfter <= 0 || denied.RetryAfter > 100*time.Millisecond {
		t.Fatalf("等待建议 = %s", denied.RetryAfter)
	}
	// 其他键不受影响。
	if decision := limiter.Allow("other"); !decision.Allowed {
		t.Fatalf("其他键应允许: %+v", decision)
	}
	clock.Advance(100 * time.Millisecond)
	if decision := limiter.Allow("client"); !decision.Allowed {
		t.Fatalf("新窗口应允许: %+v", decision)
	}
	if limiter.Len() != 1 {
		t.Fatalf("新窗口机会式清理后键数量 = %d，期望 1", limiter.Len())
	}
}

// TestCapacityAndCleanup 验证容量上限 fail-closed 与过期条目清理。
func TestCapacityAndCleanup(t *testing.T) {
	limiter, clock := newTestLimiter(t, Policy{Limit: 10, Window: time.Minute}, 2)
	if !limiter.Allow("key-1").Allowed || !limiter.Allow("key-2").Allowed {
		t.Fatal("容量未满时请求应允许")
	}
	denied := limiter.Allow("key-3")
	if denied.Allowed || denied.Reason != "capacity" {
		t.Fatalf("容量耗尽时新键应拒绝: %+v", denied)
	}
	if denied.RetryAfter != time.Minute {
		t.Fatalf("容量拒绝等待建议 = %s", denied.RetryAfter)
	}
	// 已有键仍可继续计数。
	if decision := limiter.Allow("key-1"); !decision.Allowed {
		t.Fatalf("已有键应允许: %+v", decision)
	}
	clock.Advance(time.Minute)
	if removed := limiter.Cleanup(); removed != 2 {
		t.Fatalf("清理条目数 = %d，期望 2", removed)
	}
	if limiter.Len() != 0 {
		t.Fatalf("清理后键数量 = %d", limiter.Len())
	}
	if decision := limiter.Allow("key-3"); !decision.Allowed {
		t.Fatalf("清理后新键应允许: %+v", decision)
	}
}

// TestLongKeyBounded 验证超长键内部哈希，不无限占用内存。
func TestLongKeyBounded(t *testing.T) {
	limiter, _ := newTestLimiter(t, Policy{Limit: 1, Window: time.Minute}, 2)
	longKey := ""
	for index := 0; index < 1000; index++ {
		longKey += "segment/"
	}
	if decision := limiter.Allow(longKey); !decision.Allowed {
		t.Fatalf("超长键首次请求应允许: %+v", decision)
	}
	if decision := limiter.Allow(longKey); decision.Allowed {
		t.Fatal("同一超长键第二次应被限制")
	}
	if decision := limiter.Allow(""); !decision.Allowed {
		t.Fatal("空键应被当作普通键处理")
	}
}

// TestConcurrentAllow 验证并发计数准确、无数据竞争。
func TestConcurrentAllow(t *testing.T) {
	limiter, _ := newTestLimiter(t, Policy{Limit: 3, Window: time.Minute}, 8)
	const goroutines = 6
	var waitGroup sync.WaitGroup
	var mutex sync.Mutex
	allowed := 0
	denied := 0
	for index := 0; index < goroutines; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			decision := limiter.Allow("shared")
			mutex.Lock()
			defer mutex.Unlock()
			if decision.Allowed {
				allowed++
			} else {
				denied++
			}
		}()
	}
	waitGroup.Wait()
	if allowed != 3 || denied != 3 {
		t.Fatalf("并发结果 allowed=%d denied=%d，期望 3/3", allowed, denied)
	}
	if limiter.Len() != 1 {
		t.Fatalf("并发后键数量 = %d", limiter.Len())
	}
}

// TestNilSafety 验证 nil 限流器默认放行且方法安全。
func TestNilSafety(t *testing.T) {
	var limiter *Limiter
	if !limiter.Allow("key").Allowed {
		t.Fatal("nil 限流器应默认放行")
	}
	if limiter.Len() != 0 || limiter.Cleanup() != 0 {
		t.Fatal("nil 限流器辅助方法应安全")
	}
	if limiter.Policy().Enabled() {
		t.Fatal("nil 限流器策略不应启用")
	}
}

// TestBoundKey 验证空键与超长键的归一。
func TestBoundKey(t *testing.T) {
	if boundKey("") != "empty" {
		t.Fatalf("空键归一 = %q", boundKey(""))
	}
	if boundKey("normal") != "normal" {
		t.Fatalf("普通键不应改变: %q", boundKey("normal"))
	}
	longKey := ""
	for index := 0; index < MaxKeyBytes; index++ {
		longKey += "a"
	}
	if got := boundKey(longKey); got != longKey {
		t.Fatalf("边界长度键不应哈希: %q", got)
	}
	hashed := boundKey(longKey + "b")
	if len(hashed) != len("sha256:")+64 {
		t.Fatalf("超长键哈希长度 = %d", len(hashed))
	}
	if hashed == longKey+"b" {
		t.Fatal("超长键未被哈希")
	}
}

// TestPeekDoesNotConsume 验证 Peek 只读：反复 Peek 不消耗配额，只有 Allow 计数。
func TestPeekDoesNotConsume(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	limiter, err := New(Options{Policy: Policy{Limit: 2, Window: time.Minute}, Now: clock.Now})
	if err != nil {
		t.Fatalf("New() 失败: %v", err)
	}
	for index := 0; index < 10; index++ {
		if decision := limiter.Peek("key"); !decision.Allowed {
			t.Fatalf("第 %d 次 Peek 被拒绝: %+v", index, decision)
		}
	}
	if limiter.Len() != 0 {
		t.Fatalf("Peek 新增了 %d 个条目，期望 0", limiter.Len())
	}
	if decision := limiter.Allow("key"); !decision.Allowed {
		t.Fatalf("Allow 第 1 次被拒绝: %+v", decision)
	}
	if decision := limiter.Allow("key"); !decision.Allowed {
		t.Fatalf("Allow 第 2 次被拒绝: %+v", decision)
	}
	if decision := limiter.Peek("key"); decision.Allowed || decision.Reason != "limit" {
		t.Fatalf("达到上限后 Peek = %+v，期望拒绝且 Reason=limit", decision)
	}
	if decision := limiter.Allow("key"); decision.Allowed {
		t.Fatalf("超过上限后 Allow 仍允许: %+v", decision)
	}
}
