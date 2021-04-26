package task

import (
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultRetryBaseDelay 是首次重试前的基础退避时长。
	DefaultRetryBaseDelay = 1 * time.Second
	// DefaultRetryMaxDelay 是单次退避上限。
	DefaultRetryMaxDelay = 5 * time.Minute
	// MinRetryDelay/MaxRetryDelay 是退避时长允许范围；下限允许测试使用毫秒级
	// 退避，生产默认仍是秒级。
	MinRetryDelay = 10 * time.Millisecond
	MaxRetryDelay = 1 * time.Hour
)

// RetryPolicy 是非终止失败后的有界退避策略。
//
// 退避为指数式：第 n 次尝试失败后的等待 = BaseDelay * 2^(n-1)，封顶 MaxDelay。
// 不使用随机抖动，保证可复现与可测试；调用方必须同时用任务的 MaxAttempts 做
// 次数上限，本包不会无限重试。
type RetryPolicy struct {
	// BaseDelay 是首次重试等待；0 使用默认值。
	BaseDelay time.Duration
	// MaxDelay 是单次等待上限；0 使用默认值。
	MaxDelay time.Duration
}

// normalize 校验并填充默认值。
func (p RetryPolicy) normalize() (RetryPolicy, error) {
	base := p.BaseDelay
	if base == 0 {
		base = DefaultRetryBaseDelay
	}
	maxDelay := p.MaxDelay
	if maxDelay == 0 {
		maxDelay = DefaultRetryMaxDelay
	}
	if base < MinRetryDelay || base > MaxRetryDelay {
		return RetryPolicy{}, fmt.Errorf("%w: 重试基础退避必须在 %s～%s 之间", ErrOptionsInvalid, MinRetryDelay, MaxRetryDelay)
	}
	if maxDelay < base || maxDelay > MaxRetryDelay {
		return RetryPolicy{}, fmt.Errorf("%w: 重试最大退避必须在基础退避～%s 之间", ErrOptionsInvalid, MaxRetryDelay)
	}
	return RetryPolicy{BaseDelay: base, MaxDelay: maxDelay}, nil
}

// delayAfter 返回第 attempt 次尝试失败后的退避时长；attempt 从 1 开始，
// 超过 62 时按最大值处理，避免移位溢出。
func (p RetryPolicy) delayAfter(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := p.BaseDelay
	for step := 1; step < attempt; step++ {
		if delay >= p.MaxDelay/2 {
			return p.MaxDelay
		}
		delay *= 2
	}
	if delay > p.MaxDelay {
		return p.MaxDelay
	}
	return delay
}

// nonRetryableError 标记处理器错误为不可重试；包装后仍可用 errors.Is/As 检查
// 原始错误。
type nonRetryableError struct {
	err error
}

// Error 返回原始错误文本；错误文本仅进入受限失败说明，不进入公开错误码。
func (e *nonRetryableError) Error() string { return e.err.Error() }

// Unwrap 暴露原始错误，便于调用方继续用 errors.Is 判断原因。
func (e *nonRetryableError) Unwrap() error { return e.err }

// NonRetryable 把处理器错误标记为不可重试。nil 原样返回 nil；已标记的错误
// 不会重复包装。
func NonRetryable(err error) error {
	if err == nil {
		return nil
	}
	var existing *nonRetryableError
	if errors.As(err, &existing) {
		return err
	}
	return &nonRetryableError{err: err}
}

// IsNonRetryable 报告错误是否被显式标记为不可重试。
func IsNonRetryable(err error) bool {
	var target *nonRetryableError
	return errors.As(err, &target)
}
