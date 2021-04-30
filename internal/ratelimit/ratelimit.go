// Package ratelimit 实现单维、有容量上限且并发安全的固定窗口限流器。
//
// 每个限流器只负责一个维度（例如客户端地址、用户、应用或接口），由传输层组合
// 多个限流器实现多维限流。固定窗口语义简单、可预测：窗口内前 Limit 个请求通过，
// 后续请求拒绝并给出窗口剩余时间作为等待建议；进入下一窗口后重新计数。
//
// 安全性边界：
//   - 键由调用方从可信上下文构造；本包不解析请求，也不信任客户端自填身份。
//   - 条目数有硬上限；容量耗尽时先清理过期条目，仍不足则拒绝新键（fail-closed），
//     已有键继续按窗口限制，不会因为容量压力而放行无限新键。
//   - 超长键用 SHA-256 归一到固定长度，避免以超长路径/ID 消耗内存。
//   - 所有方法并发安全；清理只在持有锁时进行，外部可显式调用 Cleanup。
package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries 是单个限流器默认最大键数量。
	DefaultMaxEntries = 4096
	// MinMaxEntries/MaxMaxEntries 是容量上限允许范围。
	MinMaxEntries = 1
	MaxMaxEntries = 65536
	// MaxKeyBytes 是键的原始字节上限；超过时在内部哈希为固定长度。
	MaxKeyBytes = 256
	// MinWindow/MaxWindow 是窗口范围（1 毫秒～24 小时）。
	MinWindow = time.Millisecond
	MaxWindow = 24 * time.Hour
	// MaxRequestsPerWindow 是单个窗口允许的请求数上限。
	MaxRequestsPerWindow = 1_000_000
	// DefaultCleanupInterval 是机会式清理的默认最小间隔。
	DefaultCleanupInterval = time.Minute
	// MinCleanupInterval/MaxCleanupInterval 是清理间隔允许范围。
	MinCleanupInterval = time.Millisecond
	MaxCleanupInterval = 24 * time.Hour
)

// Policy 是固定窗口限流策略：Window 内最多允许 Limit 个请求。两者都为 0 表示
// 该维度禁用；只设置一个值是非法的。
type Policy struct {
	Limit  int
	Window time.Duration
}

// Enabled 报告策略是否启用。
func (p Policy) Enabled() bool {
	return p.Limit > 0 && p.Window > 0
}

// Validate 校验策略：要么两者都为 0（禁用），要么都在允许范围内。
func (p Policy) Validate() error {
	if p.Limit == 0 && p.Window == 0 {
		return nil
	}
	if p.Limit <= 0 || p.Window <= 0 {
		return fmt.Errorf("限流策略的请求数与窗口必须同时设置")
	}
	if p.Limit > MaxRequestsPerWindow {
		return fmt.Errorf("限流请求数不能超过 %d", MaxRequestsPerWindow)
	}
	if p.Window < MinWindow || p.Window > MaxWindow {
		return fmt.Errorf("限流窗口必须在 %s～%s 之间", MinWindow, MaxWindow)
	}
	return nil
}

// Options 是构造限流器的参数。
type Options struct {
	// Policy 是限流策略；必须启用。
	Policy Policy
	// MaxEntries 是最大键数量；0 使用 DefaultMaxEntries。
	MaxEntries int
	// CleanupInterval 是机会式清理最小间隔；0 使用默认值（不超过窗口）。
	CleanupInterval time.Duration
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
}

// Decision 是一次限流判定结果。Allowed=false 时 RetryAfter 是建议等待时间；
// Reason 是内部诊断原因（"limit" 或 "capacity"），不得直接暴露给客户端。
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
}

// entry 是单个键在当前窗口的计数。
type entry struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

// Limiter 是单维固定窗口限流器；构造后不可变，可并发使用。
type Limiter struct {
	policy          Policy
	maxEntries      int
	cleanupInterval time.Duration
	now             func() time.Time

	mu          sync.Mutex
	entries     map[string]entry
	lastCleanup time.Time
}

// New 构造并校验限流器。策略未启用或参数越界时返回错误。
func New(options Options) (*Limiter, error) {
	if err := options.Policy.Validate(); err != nil {
		return nil, err
	}
	if !options.Policy.Enabled() {
		return nil, fmt.Errorf("限流策略未启用")
	}
	maxEntries := options.MaxEntries
	if maxEntries == 0 {
		maxEntries = DefaultMaxEntries
	}
	if maxEntries < MinMaxEntries || maxEntries > MaxMaxEntries {
		return nil, fmt.Errorf("限流容量必须在 %d～%d 之间", MinMaxEntries, MaxMaxEntries)
	}
	cleanupInterval := options.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = options.Policy.Window
		if cleanupInterval > DefaultCleanupInterval {
			cleanupInterval = DefaultCleanupInterval
		}
	}
	if cleanupInterval < MinCleanupInterval || cleanupInterval > MaxCleanupInterval {
		return nil, fmt.Errorf("限流清理间隔必须在 %s～%s 之间", MinCleanupInterval, MaxCleanupInterval)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		policy:          options.Policy,
		maxEntries:      maxEntries,
		cleanupInterval: cleanupInterval,
		now:             now,
		entries:         make(map[string]entry, minInt(maxEntries, 64)),
	}, nil
}

// Policy 返回限流器使用的策略副本。
func (l *Limiter) Policy() Policy {
	if l == nil {
		return Policy{}
	}
	return l.policy
}

// Allow 判定 key 当前是否允许通过，并在允许时消耗一次配额。
//
// 容量耗尽时新键返回 Allowed=false、Reason="capacity"、RetryAfter=窗口长度；
// 已有键仍按正常窗口计数。限流器为 nil 或策略未启用时默认放行（调用方不应
// 构造这种实例；该分支只保证 nil 安全）。
func (l *Limiter) Allow(key string) Decision {
	if l == nil || !l.policy.Enabled() {
		return Decision{Allowed: true}
	}
	key = boundKey(key)
	now := l.now().UTC()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastCleanup) >= l.cleanupInterval || len(l.entries) >= l.maxEntries {
		l.cleanupLocked(now)
	}
	current, found := l.entries[key]
	if found && now.Sub(current.windowStart) >= l.policy.Window {
		found = false
	}
	if !found {
		if len(l.entries) >= l.maxEntries {
			return Decision{
				Allowed:    false,
				RetryAfter: l.policy.Window,
				Reason:     "capacity",
			}
		}
		l.entries[key] = entry{windowStart: now, count: 1, lastSeen: now}
		return Decision{Allowed: true}
	}
	if current.count >= l.policy.Limit {
		remaining := current.windowStart.Add(l.policy.Window).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		current.lastSeen = now
		l.entries[key] = current
		return Decision{Allowed: false, RetryAfter: remaining, Reason: "limit"}
	}
	current.count++
	current.lastSeen = now
	l.entries[key] = current
	return Decision{Allowed: true}
}

// Cleanup 立即清理已过窗口的条目并返回清理数量。可用于测试或宿主周期维护；
// Allow 也会按间隔机会式清理，因此不需要后台 goroutine。
func (l *Limiter) Cleanup() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	removed := l.cleanupLocked(now)
	l.lastCleanup = now
	return removed
}

// Len 返回当前跟踪的键数量，用于容量与清理测试。
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// cleanupLocked 删除窗口已结束的条目；调用方必须持有锁。
func (l *Limiter) cleanupLocked(now time.Time) int {
	removed := 0
	for key, current := range l.entries {
		if now.Sub(current.windowStart) >= l.policy.Window {
			delete(l.entries, key)
			removed++
		}
	}
	l.lastCleanup = now
	return removed
}

// boundKey 把空键与超长键归一为固定、可比较的字符串；普通键保持原样以方便
// 诊断，但不把键写入日志或响应。
func boundKey(key string) string {
	if key == "" {
		return "empty"
	}
	if len(key) > MaxKeyBytes {
		sum := sha256.Sum256([]byte(key))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return key
}

// minInt 返回较小值。
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
