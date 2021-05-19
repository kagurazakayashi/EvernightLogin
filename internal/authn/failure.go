package authn

import (
	"fmt"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
)

const (
	// DefaultFailureMaxEntries 是延迟/锁定跟踪表默认最大键数；状态有界，避免被
	// 大量不同标识耗尽内存。
	DefaultFailureMaxEntries = 8192
	// MinFailureMaxEntries/MaxFailureMaxEntries 是跟踪容量范围。
	MinFailureMaxEntries = 16
	MaxFailureMaxEntries = 65536
	// DefaultSweepMaxIdentifiers 是单个客户端地址前缀在一个窗口内允许失败的
	// 不同账户/标识数；用于阻止少数来源灌入大量唯一标识来填满失败跟踪表。
	DefaultSweepMaxIdentifiers = 50
	// MinSweepMaxIdentifiers/MaxSweepMaxIdentifiers 是扫描阈值的允许范围。
	MinSweepMaxIdentifiers = 5
	MaxSweepMaxIdentifiers = 1000
	// DefaultSweepMaxEntries 是地址前缀扫描跟踪表容量。
	DefaultSweepMaxEntries = 1024
	// MinSweepMaxEntries/MaxSweepMaxEntries 是扫描跟踪容量范围。
	MinSweepMaxEntries = 16
	MaxSweepMaxEntries = 65536
)

// FailurePolicy 是失败限制策略：账户维度渐进延迟、按“账户 + 客户端地址前缀”的
// 临时锁定与指数退避、以及客户端地址的标识扫描阈值。锁定只作用于同一来源
// （IPv4 地址或 IPv6 /64 前缀），因此单个攻击来源无法把他人或 root 账户长期
// 锁死；账户维度的渐进延迟对所有来源生效但只延迟、不阻断。锁定到期自动恢复，
// 成功认证清除状态，绝不永久锁号。
type FailurePolicy struct {
	// Window 是连续失败计数窗口；窗口结束后失败计数重新开始。
	Window time.Duration
	// MaxFailures 是窗口内达到多少个失败后触发临时锁定（按账户+来源）。
	MaxFailures int
	// LockDuration 是首次临时锁定时长。
	LockDuration time.Duration
	// MaxLockDuration 是重复触发时的锁定上限（指数退避封顶）。
	MaxLockDuration time.Duration
	// DelayBase 是第一次失败后的渐进延迟基准（账户维度）。
	DelayBase time.Duration
	// DelayMax 是渐进延迟上限。
	DelayMax time.Duration
	// MaxEntries 是延迟与锁定跟踪表容量上限；0 使用 DefaultFailureMaxEntries。
	MaxEntries int
	// MaxSweepIdentifiers 是单个来源窗口内允许失败的不同标识数；0 使用默认值。
	MaxSweepIdentifiers int
	// MaxSweepEntries 是来源扫描跟踪表容量；0 使用默认值。
	MaxSweepEntries int
}

// DefaultFailurePolicy 返回默认失败限制：15 分钟窗口内 10 次失败后按同一来源
// 临时锁定 5 分钟（重复触发指数增长，最多 1 小时）；延迟 0.2s 增长到最多 2s；
// 单个来源窗口内最多对 50 个不同标识失败。
func DefaultFailurePolicy() FailurePolicy {
	return FailurePolicy{
		Window:              15 * time.Minute,
		MaxFailures:         10,
		LockDuration:        5 * time.Minute,
		MaxLockDuration:     time.Hour,
		DelayBase:           200 * time.Millisecond,
		DelayMax:            2 * time.Second,
		MaxEntries:          DefaultFailureMaxEntries,
		MaxSweepIdentifiers: DefaultSweepMaxIdentifiers,
		MaxSweepEntries:     DefaultSweepMaxEntries,
	}
}

// normalize 填充零值默认；不修改调用方值。
func (p FailurePolicy) normalize() FailurePolicy {
	if p.Window == 0 {
		p.Window = 15 * time.Minute
	}
	if p.MaxFailures == 0 {
		p.MaxFailures = 10
	}
	if p.LockDuration == 0 {
		p.LockDuration = 5 * time.Minute
	}
	if p.MaxLockDuration == 0 {
		p.MaxLockDuration = time.Hour
	}
	if p.DelayBase == 0 {
		p.DelayBase = 200 * time.Millisecond
	}
	if p.DelayMax == 0 {
		p.DelayMax = 2 * time.Second
	}
	if p.MaxEntries == 0 {
		p.MaxEntries = DefaultFailureMaxEntries
	}
	if p.MaxSweepIdentifiers == 0 {
		p.MaxSweepIdentifiers = DefaultSweepMaxIdentifiers
	}
	if p.MaxSweepEntries == 0 {
		p.MaxSweepEntries = DefaultSweepMaxEntries
	}
	return p
}

// Validate 校验失败限制参数范围，避免配置出永久锁定、无限延迟或无界状态。
func (p FailurePolicy) Validate() error {
	normalized := p.normalize()
	if normalized.Window < time.Second || normalized.Window > 24*time.Hour {
		return fmt.Errorf("%w: 失败计数窗口必须在 1 秒～24 小时之间", ErrOptionsInvalid)
	}
	if normalized.MaxFailures < 2 || normalized.MaxFailures > 1000 {
		return fmt.Errorf("%w: 失败锁定阈值必须在 2～1000 次之间", ErrOptionsInvalid)
	}
	if normalized.LockDuration < time.Second || normalized.LockDuration > time.Hour {
		return fmt.Errorf("%w: 临时锁定时长必须在 1 秒～1 小时之间", ErrOptionsInvalid)
	}
	if normalized.MaxLockDuration < normalized.LockDuration || normalized.MaxLockDuration > 24*time.Hour {
		return fmt.Errorf("%w: 锁定上限必须在首次锁定时长～24 小时之间", ErrOptionsInvalid)
	}
	if normalized.DelayBase < 0 || normalized.DelayBase > 10*time.Second {
		return fmt.Errorf("%w: 渐进延迟基准必须在 0～10 秒之间", ErrOptionsInvalid)
	}
	if normalized.DelayMax < normalized.DelayBase || normalized.DelayMax > 30*time.Second {
		return fmt.Errorf("%w: 渐进延迟上限必须在基准～30 秒之间", ErrOptionsInvalid)
	}
	if normalized.MaxEntries < MinFailureMaxEntries || normalized.MaxEntries > MaxFailureMaxEntries {
		return fmt.Errorf("%w: 失败跟踪容量必须在 %d～%d 之间",
			ErrOptionsInvalid, MinFailureMaxEntries, MaxFailureMaxEntries)
	}
	if normalized.MaxSweepIdentifiers < MinSweepMaxIdentifiers ||
		normalized.MaxSweepIdentifiers > MaxSweepMaxIdentifiers {
		return fmt.Errorf("%w: 来源标识扫描阈值必须在 %d～%d 之间",
			ErrOptionsInvalid, MinSweepMaxIdentifiers, MaxSweepMaxIdentifiers)
	}
	if normalized.MaxSweepEntries < MinSweepMaxEntries ||
		normalized.MaxSweepEntries > MaxSweepMaxEntries {
		return fmt.Errorf("%w: 来源扫描跟踪容量必须在 %d～%d 之间",
			ErrOptionsInvalid, MinSweepMaxEntries, MaxSweepMaxEntries)
	}
	return nil
}

// RateLimitPolicy 是地址与操作两个维度的固定窗口限流策略（复用
// internal/ratelimit）。两者都为 0 表示该维度禁用；生产默认两者均启用。
// 只统计失败尝试：成功认证不消耗配额（认证开始前用 Peek 判断是否已超限）。
type RateLimitPolicy struct {
	// IP 是客户端地址前缀维度失败预算，默认 5 分钟 30 次失败。
	IP ratelimit.Policy
	// Operation 是认证操作全局维度失败预算，默认 1 分钟 3000 次失败；用于在
	// 分布式撞库/慢速攻击时限制造总体失败速率。
	Operation ratelimit.Policy
}

// DefaultRateLimitPolicy 返回默认地址/操作限流策略。
func DefaultRateLimitPolicy() RateLimitPolicy {
	return RateLimitPolicy{
		IP:        ratelimit.Policy{Limit: 30, Window: 5 * time.Minute},
		Operation: ratelimit.Policy{Limit: 3000, Window: time.Minute},
	}
}

// Validate 校验两个维度的固定窗口策略。
func (p RateLimitPolicy) Validate() error {
	if err := p.IP.Validate(); err != nil {
		return fmt.Errorf("%w: 地址维度限流策略无效: %v", ErrOptionsInvalid, err)
	}
	if err := p.Operation.Validate(); err != nil {
		return fmt.Errorf("%w: 操作维度限流策略无效: %v", ErrOptionsInvalid, err)
	}
	return nil
}

// delayEntry 是单个账户的渐进延迟状态。
type delayEntry struct {
	failures    int
	windowStart time.Time
	lastSeen    time.Time
}

// delayTracker 是按账户（用户名/邮箱归并到账户 ID）统计失败次数并返回渐进延迟
// 的有界跟踪器。它只延迟、不锁定，因此容量淘汰不会造成可用性风险。
type delayTracker struct {
	policy  FailurePolicy
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*delayEntry
}

// newDelayTracker 构造延迟跟踪器；policy 必须已 Validate。
func newDelayTracker(policy FailurePolicy, now func() time.Time) *delayTracker {
	if now == nil {
		now = time.Now
	}
	return &delayTracker{
		policy:  policy,
		now:     now,
		entries: make(map[string]*delayEntry, minInt(policy.MaxEntries, 64)),
	}
}

// record 记录一次账户维度失败并返回本次应施加的渐进延迟。
func (t *delayTracker) record(key string) time.Duration {
	if t == nil {
		return 0
	}
	now := t.now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= t.policy.MaxEntries {
		t.cleanupLocked(now)
		if len(t.entries) >= t.policy.MaxEntries {
			t.evictOldestLocked()
		}
	}
	entry, found := t.entries[key]
	if !found {
		entry = &delayEntry{windowStart: now}
		t.entries[key] = entry
	}
	if now.Sub(entry.windowStart) >= t.policy.Window {
		entry.failures = 0
		entry.windowStart = now
	}
	entry.failures++
	entry.lastSeen = now
	delay := t.policy.DelayBase
	for index := 1; index < entry.failures; index++ {
		if delay >= t.policy.DelayMax {
			return t.policy.DelayMax
		}
		delay *= 2
	}
	if delay > t.policy.DelayMax {
		delay = t.policy.DelayMax
	}
	return delay
}

// reset 清除账户的失败状态（成功认证后调用）。
func (t *delayTracker) reset(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// len 返回当前跟踪的键数量。
func (t *delayTracker) len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// cleanupLocked 删除窗口已过期的条目；调用方必须持有锁。
func (t *delayTracker) cleanupLocked(now time.Time) {
	for key, entry := range t.entries {
		if now.Sub(entry.windowStart) >= t.policy.Window {
			delete(t.entries, key)
		}
	}
}

// evictOldestLocked 淘汰最久未使用的延迟条目；延迟不是安全锁，淘汰只会减少
// 延迟，不会造成锁定被清除或永久放行。调用方必须持有锁。
func (t *delayTracker) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, entry := range t.entries {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}

// lockEntry 是按“账户 + 来源前缀”的临时锁定状态。
type lockEntry struct {
	failures    int
	windowStart time.Time
	lastSeen    time.Time
	lockedUntil time.Time
	lockLevel   int
}

// failureTracker 是按“账户 + 客户端地址前缀”键的临时锁定跟踪器。
//
// 语义：
//   - 失败按窗口计数；达到阈值后临时锁定该“账户 + 来源”组合，锁定时长按连续
//     锁定次数指数增长并封顶，到期自动恢复；成功认证清除该组合。
//   - 容量耗尽时只清理过期条目并淘汰未加锁条目；正在锁定的条目绝不淘汰。若
//     全部条目都在锁定中，新键返回容量拒绝（fail-closed），既不清除受害者锁定，
//     也不让跟踪表无界增长。
type failureTracker struct {
	policy  FailurePolicy
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*lockEntry
}

// newFailureTracker 构造锁定跟踪器；policy 必须已经过 Validate。
func newFailureTracker(policy FailurePolicy, now func() time.Time) *failureTracker {
	if now == nil {
		now = time.Now
	}
	return &failureTracker{
		policy:  policy,
		now:     now,
		entries: make(map[string]*lockEntry, minInt(policy.MaxEntries, 64)),
	}
}

// check 判定键当前是否被临时锁定。
func (t *failureTracker) check(key string) (locked bool, retryAfter time.Duration) {
	if t == nil {
		return false, 0
	}
	now := t.now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, found := t.entries[key]
	if !found {
		return false, 0
	}
	if !entry.lockedUntil.IsZero() {
		if now.Before(entry.lockedUntil) {
			return true, entry.lockedUntil.Sub(now)
		}
		entry.lockedUntil = time.Time{}
		entry.failures = 0
		entry.windowStart = now
	}
	return false, 0
}

// recordFailure 记录一次失败并返回是否触发锁定。
//
// 返回值：
//   - allowed=false 且 capacity=false 表示本次失败触发临时锁定，retryAfter 为等待时间；
//   - allowed=false 且 capacity=true 表示跟踪表已被锁定条目占满，本次按容量拒绝
//     （fail-closed，不清除任何锁定）；
//   - allowed=true 表示未锁定。
func (t *failureTracker) recordFailure(key string) (allowed bool, retryAfter time.Duration, capacity bool) {
	if t == nil {
		return true, 0, false
	}
	now := t.now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, found := t.entries[key]
	if !found {
		if !t.ensureCapacityLocked(now) {
			return false, t.policy.Window, true
		}
		entry = &lockEntry{windowStart: now}
		t.entries[key] = entry
	}
	if !entry.lockedUntil.IsZero() {
		if now.Before(entry.lockedUntil) {
			return false, entry.lockedUntil.Sub(now), false
		}
		entry.lockedUntil = time.Time{}
		entry.failures = 0
		entry.windowStart = now
	}
	if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= t.policy.Window {
		entry.failures = 0
		entry.windowStart = now
	}
	entry.failures++
	entry.lastSeen = now
	if entry.failures >= t.policy.MaxFailures {
		entry.lockLevel++
		lock := t.policy.LockDuration
		for level := 1; level < entry.lockLevel; level++ {
			lock *= 2
			if lock >= t.policy.MaxLockDuration {
				lock = t.policy.MaxLockDuration
				break
			}
		}
		if lock > t.policy.MaxLockDuration {
			lock = t.policy.MaxLockDuration
		}
		entry.lockedUntil = now.Add(lock)
		return false, lock, false
	}
	return true, 0, false
}

// reset 清除键的全部锁定状态（成功认证后调用）。
func (t *failureTracker) reset(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// len 返回当前跟踪的键数量。
func (t *failureTracker) len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// ensureCapacityLocked 为新键腾出位置：先清理过期条目，再淘汰未锁定条目；
// 正在锁定的条目绝不淘汰。返回 false 表示容量全部被锁定条目占用。
// 调用方必须持有锁。
func (t *failureTracker) ensureCapacityLocked(now time.Time) bool {
	if len(t.entries) < t.policy.MaxEntries {
		return true
	}
	for key, entry := range t.entries {
		if !entry.lockedUntil.IsZero() {
			if now.Sub(entry.lockedUntil) >= t.policy.MaxLockDuration {
				delete(t.entries, key)
			}
			continue
		}
		if now.Sub(entry.lastSeen) >= t.policy.Window {
			delete(t.entries, key)
		}
	}
	for len(t.entries) >= t.policy.MaxEntries {
		oldestKey := ""
		var oldest time.Time
		for key, entry := range t.entries {
			if !entry.lockedUntil.IsZero() {
				continue
			}
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey = key
				oldest = entry.lastSeen
			}
		}
		if oldestKey == "" {
			return false
		}
		delete(t.entries, oldestKey)
	}
	return true
}

// sweepEntry 是单个客户端来源前缀的标识扫描状态。
type sweepEntry struct {
	windowStart time.Time
	lastSeen    time.Time
	seen        map[string]struct{}
}

// sweepGuard 限制单个客户端来源前缀在一个窗口内可以失败的不同账户/标识数量，
// 防止少数来源用大量唯一标识灌入失败跟踪表、挤掉其他锁定或放大探测范围。
type sweepGuard struct {
	policy  FailurePolicy
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*sweepEntry
}

// newSweepGuard 构造来源扫描跟踪器；policy 必须已 Validate。
func newSweepGuard(policy FailurePolicy, now func() time.Time) *sweepGuard {
	if now == nil {
		now = time.Now
	}
	return &sweepGuard{
		policy:  policy,
		now:     now,
		entries: make(map[string]*sweepEntry, minInt(policy.MaxSweepEntries, 64)),
	}
}

// record 记录一次来源对某标识的失败；返回 false 表示该来源已超出标识扫描阈值，
// 调用方应限流。同一标识重复失败只计一次。
func (g *sweepGuard) record(source, identifierKey string) bool {
	if g == nil {
		return true
	}
	now := g.now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, found := g.entries[source]
	if !found || now.Sub(entry.windowStart) >= g.policy.Window {
		if !found && len(g.entries) >= g.policy.MaxSweepEntries {
			g.cleanupLocked(now)
			if len(g.entries) >= g.policy.MaxSweepEntries {
				g.evictOldestLocked()
			}
		}
		entry = &sweepEntry{windowStart: now, seen: make(map[string]struct{}, g.policy.MaxSweepIdentifiers)}
		g.entries[source] = entry
	}
	entry.lastSeen = now
	if _, exists := entry.seen[identifierKey]; exists {
		return true
	}
	if len(entry.seen) >= g.policy.MaxSweepIdentifiers {
		return false
	}
	entry.seen[identifierKey] = struct{}{}
	return true
}

// len 返回当前跟踪的来源数量。
func (g *sweepGuard) len() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

// cleanupLocked 清理窗口过期的来源条目；调用方必须持有锁。
func (g *sweepGuard) cleanupLocked(now time.Time) {
	for source, entry := range g.entries {
		if now.Sub(entry.windowStart) >= g.policy.Window {
			delete(g.entries, source)
		}
	}
}

// evictOldestLocked 淘汰最久未使用的来源条目；只降低扫描保护范围，不涉及锁定
// 清除。调用方必须持有锁。
func (g *sweepGuard) evictOldestLocked() {
	oldestSource := ""
	var oldest time.Time
	for source, entry := range g.entries {
		if oldestSource == "" || entry.lastSeen.Before(oldest) {
			oldestSource = source
			oldest = entry.lastSeen
		}
	}
	if oldestSource != "" {
		delete(g.entries, oldestSource)
	}
}

// minInt 返回较小值。
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
