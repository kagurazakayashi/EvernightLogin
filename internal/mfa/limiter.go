package mfa

import (
	"sync"
	"time"
)

// RatePolicy 是 MFA 账户维度有界限流策略（挑战创建、验证尝试、重发）。
// 传输层 IP/接口限流仍由 internal/ratelimit 与 HTTP 接线负责，本策略只防单账户
// 无限重建挑战爆破验证码与邮件轰炸。
type RatePolicy struct {
	// ChallengeLimit/ChallengeWindow 是每账户窗口内可创建的挑战数（含因素新增）。
	ChallengeLimit  int
	ChallengeWindow time.Duration
	// VerifyLimit/VerifyWindow 是每账户窗口内可提交的验证码验证次数总预算。
	VerifyLimit  int
	VerifyWindow time.Duration
	// ResendLimit/ResendWindow 是每账户窗口内可重发验证码次数。
	ResendLimit  int
	ResendWindow time.Duration
}

// DefaultRatePolicy 返回保守默认值：每账户每小时 10 个挑战、每 10 分钟 30 次验证、
// 每小时 5 次重发。
func DefaultRatePolicy() RatePolicy {
	return RatePolicy{
		ChallengeLimit: 10, ChallengeWindow: time.Hour,
		VerifyLimit: 30, VerifyWindow: 10 * time.Minute,
		ResendLimit: 5, ResendWindow: time.Hour,
	}
}

// resolve 校验并合并默认值。
func (p RatePolicy) resolve() (RatePolicy, error) {
	if p.challengeUnset() {
		p = DefaultRatePolicy()
	}
	if p.ChallengeLimit < 1 || p.ChallengeLimit > 100 {
		return RatePolicy{}, ErrOptionsInvalid
	}
	if p.ChallengeWindow < time.Minute || p.ChallengeWindow > 24*time.Hour {
		return RatePolicy{}, ErrOptionsInvalid
	}
	if p.VerifyLimit < 1 || p.VerifyLimit > 1000 {
		return RatePolicy{}, ErrOptionsInvalid
	}
	if p.VerifyWindow < time.Minute || p.VerifyWindow > 24*time.Hour {
		return RatePolicy{}, ErrOptionsInvalid
	}
	if p.ResendLimit < 1 || p.ResendLimit > 100 {
		return RatePolicy{}, ErrOptionsInvalid
	}
	if p.ResendWindow < time.Minute || p.ResendWindow > 24*time.Hour {
		return RatePolicy{}, ErrOptionsInvalid
	}
	return p, nil
}

// challengeUnset 报告策略是否完全未配置（使用默认值）。
func (p RatePolicy) challengeUnset() bool {
	return p.ChallengeLimit == 0 && p.ChallengeWindow == 0 && p.VerifyLimit == 0 &&
		p.VerifyWindow == 0 && p.ResendLimit == 0 && p.ResendWindow == 0
}

// counterLimiter 是有界进程内滑动窗口计数限流器；单实例语义，多实例时每实例各自
// 计数（保守上限仍成立）。容量超限时清理最旧键。
type counterLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

func newCounterLimiter(limit int, window time.Duration) *counterLimiter {
	return &counterLimiter{limit: limit, window: window, entries: make(map[string][]time.Time)}
}

// allow 判断并记录一次请求；达到上限返回 false（不记录）。
func (l *counterLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.entries[key]
	retained := kept[:0]
	for _, timestamp := range kept {
		if timestamp.After(cutoff) {
			retained = append(retained, timestamp)
		}
	}
	if len(retained) >= l.limit {
		l.entries[key] = retained
		return false
	}
	l.entries[key] = append(retained, now)
	if len(l.entries) > 10000 {
		for candidate, timestamps := range l.entries {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.entries, candidate)
			}
		}
	}
	return true
}
