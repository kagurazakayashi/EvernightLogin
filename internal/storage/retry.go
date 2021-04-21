package storage

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RetryPolicy 定义有界重试。执行器只对调用方判定为可重试的错误重试，最多
// MaxAttempts 次（含首次），等待时间从 InitialDelay 起倍增且不超过 MaxDelay；
// 禁止无限循环。总时长还受调用方 ctx 期限约束。
type RetryPolicy struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
}

const (
	// maxRetryAttempts 是重试次数上限，避免误配置导致长时间占用连接。
	maxRetryAttempts = 10
	// maxRetryDelay 是单次等待上限。
	maxRetryDelay = 5 * time.Second
)

// DefaultRetryPolicy 返回只处理并发忙/锁冲突的默认有界重试策略：最多 3 次，
// 10ms 起、100ms 封顶；业务层应自行设置 ctx 超时。
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}
}

// Validate 检查策略是否在安全范围内。
func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 {
		return fmt.Errorf("重试次数必须至少为 1")
	}
	if p.MaxAttempts > maxRetryAttempts {
		return fmt.Errorf("重试次数不能超过 %d", maxRetryAttempts)
	}
	if p.InitialDelay < 0 {
		return fmt.Errorf("重试初始等待不能为负数")
	}
	if p.MaxDelay < p.InitialDelay {
		return fmt.Errorf("重试最大等待不能小于初始等待")
	}
	if p.MaxDelay > maxRetryDelay {
		return fmt.Errorf("重试最大等待不能超过 %s", maxRetryDelay)
	}
	return nil
}

// Retryable 报告错误是否属于可重试的并发忙/锁冲突。唯一性、约束、版本冲突、
// 权限、磁盘、损坏与 ctx 取消都不可重试。
func Retryable(err error) bool {
	return errors.Is(err, ErrBusy)
}

// Retry 执行 operation，并在 retryable 判定为真时按 policy 有界重试。
//
// operation 可能被执行多次，必须可安全重入（通常应是完整事务函数）；不得把
// 不可撤销的外部副作用放进 operation。ctx 取消时停止等待并返回 ctx 错误与最后
// 一次错误的组合。retryable 为 nil 时只执行一次。
func Retry(ctx context.Context, policy RetryPolicy, retryable func(error) bool, operation func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if operation == nil {
		return New(ErrUnavailable, "重试操作不能为空", nil)
	}
	if err := policy.Validate(); err != nil {
		return New(ErrUnavailable, "重试策略不合法", err)
	}
	if retryable == nil {
		return operation(ctx)
	}

	delay := policy.InitialDelay
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return joinContextError(lastErr, err)
		}
		lastErr = operation(ctx)
		if lastErr == nil {
			return nil
		}
		if !retryable(lastErr) {
			return lastErr
		}
		if attempt == policy.MaxAttempts {
			break
		}
		if err := waitContext(ctx, delay); err != nil {
			return joinContextError(lastErr, err)
		}
		delay *= 2
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
		}
	}
	return lastErr
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func joinContextError(lastErr, ctxErr error) error {
	if lastErr == nil {
		return ctxErr
	}
	return errors.Join(lastErr, ctxErr)
}
