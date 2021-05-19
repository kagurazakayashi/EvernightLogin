package authn

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// testFailurePolicy 是测试用小阈值失败策略；延迟用毫秒级便于断言。
func testFailurePolicy() FailurePolicy {
	return FailurePolicy{
		Window:              time.Minute,
		MaxFailures:         3,
		LockDuration:        2 * time.Minute,
		MaxLockDuration:     10 * time.Minute,
		DelayBase:           10 * time.Millisecond,
		DelayMax:            25 * time.Millisecond,
		MaxEntries:          16,
		MaxSweepIdentifiers: 5,
		MaxSweepEntries:     16,
	}
}

// fakeClock 是可注入测试时钟。
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

// Advance 前进测试时间。
func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// TestDelayTrackerProgressive 验证账户维度渐进延迟：指数增长、封顶与成功重置。
func TestDelayTrackerProgressive(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	policy := testFailurePolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("测试策略应合法: %v", err)
	}
	tracker := newDelayTracker(policy, clock.Now)
	const key = "acct:usr_00000000000000000000000000000001"
	if delay := tracker.record(key); delay != 10*time.Millisecond {
		t.Fatalf("第一次延迟 = %v，期望 10ms", delay)
	}
	if delay := tracker.record(key); delay != 20*time.Millisecond {
		t.Fatalf("第二次延迟 = %v，期望 20ms", delay)
	}
	if delay := tracker.record(key); delay != 25*time.Millisecond {
		t.Fatalf("第三次延迟 = %v，期望封顶 25ms", delay)
	}
	for index := 0; index < 10; index++ {
		if delay := tracker.record(key); delay > policy.DelayMax {
			t.Fatalf("延迟 = %v，超过上限", delay)
		}
	}
	tracker.reset(key)
	if delay := tracker.record(key); delay != 10*time.Millisecond {
		t.Fatalf("reset 后延迟 = %v，期望重新从 10ms 开始", delay)
	}
	// 窗口过期后计数重新开始。
	clock.Advance(policy.Window)
	if delay := tracker.record(key); delay != 10*time.Millisecond {
		t.Fatalf("窗口过期后延迟 = %v，期望 10ms", delay)
	}
}

// TestFailureTrackerLockRecoveryAndRetention 验证临时锁定、指数退避、到期恢复，
// 以及容量压力下锁定条目不被淘汰。
func TestFailureTrackerLockRecoveryAndRetention(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	policy := testFailurePolicy()
	tracker := newFailureTracker(policy, clock.Now)
	const key = "acct:usr_00000000000000000000000000000001|ipv4:203.0.113.10"
	if allowed, _, _ := tracker.recordFailure(key); !allowed {
		t.Fatal("第一次失败不应锁定")
	}
	if allowed, _, _ := tracker.recordFailure(key); !allowed {
		t.Fatal("第二次失败不应锁定")
	}
	allowed, retry, capacity := tracker.recordFailure(key)
	if allowed || capacity || retry != 2*time.Minute {
		t.Fatalf("第三次失败 = (%v,%v,%v)，期望 2 分钟锁定", allowed, retry, capacity)
	}
	if locked, wait := tracker.check(key); !locked || wait != 2*time.Minute {
		t.Fatalf("check = (%v,%v)，期望锁定 2 分钟", locked, wait)
	}
	// 锁定到期自动恢复；再次触发指数退避为 4 分钟。
	clock.Advance(2 * time.Minute)
	if locked, _ := tracker.check(key); locked {
		t.Fatal("锁定到期后仍被锁定")
	}
	if allowed, _, _ := tracker.recordFailure(key); !allowed {
		t.Fatal("锁定到期后首次失败不应立即重新锁定")
	}
	tracker.recordFailure(key)
	if allowed, retry, _ := tracker.recordFailure(key); allowed || retry != 4*time.Minute {
		t.Fatalf("第二次锁定 = (%v,%v)，期望指数退避 4 分钟", allowed, retry)
	}
	tracker.reset(key)
	if locked, _ := tracker.check(key); locked {
		t.Fatal("reset 后仍被锁定")
	}

	// 容量压力下：先锁定若干键，再用新键灌入，锁定条目必须保留。
	smallPolicy := testFailurePolicy()
	smallPolicy.MaxEntries = 4
	smallTracker := newFailureTracker(smallPolicy, clock.Now)
	lockedKeys := []string{"victim-a", "victim-b", "victim-c", "victim-d"}
	for _, victim := range lockedKeys {
		for attempt := 0; attempt < smallPolicy.MaxFailures; attempt++ {
			smallTracker.recordFailure(victim)
		}
	}
	for _, victim := range lockedKeys {
		if locked, _ := smallTracker.check(victim); !locked {
			t.Fatalf("锁定条目 %q 在容量压力前已丢失", victim)
		}
	}
	allowed, retry, capacity = smallTracker.recordFailure("new-key")
	if allowed || !capacity || retry <= 0 {
		t.Fatalf("容量占满后的新键 = (%v,%v,%v)，期望 fail-closed 容量拒绝", allowed, retry, capacity)
	}
	for _, victim := range lockedKeys {
		if locked, _ := smallTracker.check(victim); !locked {
			t.Fatalf("容量压力后锁定条目 %q 被淘汰", victim)
		}
	}
}

// TestFailureTrackerBoundedAndConcurrent 验证失败跟踪表有界且并发安全。
func TestFailureTrackerBoundedAndConcurrent(t *testing.T) {
	policy := testFailurePolicy()
	tracker := newFailureTracker(policy, nil)
	delays := newDelayTracker(policy, nil)
	sweep := newSweepGuard(policy, nil)
	const workers = 16
	const perWorker = 20
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for index := 0; index < perWorker; index++ {
				key := "worker-key-" + string(rune('a'+worker)) + "-" + string(rune('a'+index%26))
				tracker.recordFailure(key)
				tracker.check(key)
				delays.record(key)
				sweep.record("ipv4:203.0.113."+string(rune('0'+worker%10)), key)
			}
		}(worker)
	}
	waitGroup.Wait()
	if length := tracker.len(); length > policy.MaxEntries {
		t.Fatalf("锁定跟踪表长度 = %d，超过上限 %d", length, policy.MaxEntries)
	}
	if length := delays.len(); length > policy.MaxEntries {
		t.Fatalf("延迟跟踪表长度 = %d，超过上限 %d", length, policy.MaxEntries)
	}
	if length := sweep.len(); length > policy.MaxSweepEntries {
		t.Fatalf("扫描跟踪表长度 = %d，超过上限 %d", length, policy.MaxSweepEntries)
	}
}

// TestSweepGuardLimitsIdentifierFanout 验证单一来源不能无限对唯一标识失败。
func TestSweepGuardLimitsIdentifierFanout(t *testing.T) {
	policy := testFailurePolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("测试策略应合法: %v", err)
	}
	guard := newSweepGuard(policy, nil)
	const source = "ipv6:20010db800000000"
	for index := 0; index < policy.MaxSweepIdentifiers; index++ {
		if !guard.record(source, "acct:user-"+string(rune('a'+index))) {
			t.Fatalf("第 %d 个标识被提前拒绝", index+1)
		}
	}
	if guard.record(source, "acct:user-overflow") {
		t.Fatal("超过标识扫描阈值仍未拒绝")
	}
	// 同一标识重复失败只算一次。
	if !guard.record(source, "acct:user-a") {
		t.Fatal("重复失败同一标识被拒绝")
	}
	// 其他来源不受影响。
	if !guard.record("ipv6:20010db800000001", "acct:user-overflow") {
		t.Fatal("其他来源被错误限流")
	}
}

// TestFailurePolicyValidate 验证失败策略参数边界。
func TestFailurePolicyValidate(t *testing.T) {
	if err := DefaultFailurePolicy().Validate(); err != nil {
		t.Fatalf("默认失败策略应合法: %v", err)
	}
	bad := []FailurePolicy{
		{Window: time.Millisecond},
		{MaxFailures: 1},
		{LockDuration: time.Hour + time.Second},
		{LockDuration: 2 * time.Hour, MaxLockDuration: time.Hour},
		{DelayMax: time.Millisecond, DelayBase: time.Second},
		{MaxEntries: 1},
		{MaxSweepIdentifiers: 1},
		{MaxSweepEntries: 1},
	}
	for _, policy := range bad {
		if err := policy.Validate(); !errors.Is(err, ErrOptionsInvalid) {
			t.Errorf("策略 %+v 错误 = %v，期望 ErrOptionsInvalid", policy, err)
		}
	}
}
