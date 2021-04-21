package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeResult struct {
	rows int64
	err  error
}

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return r.rows, r.err }

func TestErrorKindAndSafeMessage(t *testing.T) {
	cause := errors.New("driver raw error: table users SQL path C:/secret/login.db")
	storageErr := New(ErrBusy, "数据库正忙，请稍后重试", cause)
	if storageErr.Error() != "数据库正忙，请稍后重试" {
		t.Errorf("Error() = %q", storageErr.Error())
	}
	if strings.Contains(storageErr.Error(), "secret") || strings.Contains(storageErr.Error(), "SQL") {
		t.Errorf("公开错误泄露内部原因：%q", storageErr.Error())
	}
	if !errors.Is(storageErr, ErrBusy) {
		t.Error("errors.Is 未识别错误类别")
	}
	if errors.Is(storageErr, ErrUniqueViolation) {
		t.Error("错误类别不应互相匹配")
	}
	if !errors.Is(storageErr, cause) {
		t.Error("errors.Is 应能沿原因链识别原始错误，供受限诊断")
	}
	if storageErr.Kind() != ErrBusy {
		t.Errorf("Kind() = %v", storageErr.Kind())
	}
	if storageErr.Cause() != cause {
		t.Error("Cause() 应保留原始错误")
	}
}

func TestCheckVersionedUpdate(t *testing.T) {
	if err := CheckVersionedUpdate(fakeResult{rows: 1}); err != nil {
		t.Errorf("单行更新应成功：%v", err)
	}
	if err := CheckVersionedUpdate(fakeResult{rows: 0}); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("0 行更新错误 = %v，期望 ErrVersionConflict", err)
	}
	if err := CheckVersionedUpdate(fakeResult{rows: 2}); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("多行更新错误 = %v，期望 ErrVersionConflict", err)
	}
	if err := CheckVersionedUpdate(fakeResult{rows: 1, err: errors.New("驱动错误")}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("无法确认行数错误 = %v，期望 ErrUnavailable", err)
	}
	if err := CheckVersionedUpdate(nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("nil result 错误 = %v", err)
	}
}

func TestRetryPolicyValidation(t *testing.T) {
	if err := DefaultRetryPolicy().Validate(); err != nil {
		t.Errorf("默认策略不合法：%v", err)
	}
	invalid := []RetryPolicy{
		{MaxAttempts: 0},
		{MaxAttempts: 11},
		{MaxAttempts: 2, InitialDelay: -1},
		{MaxAttempts: 2, InitialDelay: 10 * time.Millisecond, MaxDelay: time.Millisecond},
		{MaxAttempts: 2, InitialDelay: time.Second, MaxDelay: 10 * time.Second},
	}
	for _, policy := range invalid {
		if err := policy.Validate(); err == nil {
			t.Errorf("非法策略 %+v 未报错", policy)
		}
	}
}

func TestRetry(t *testing.T) {
	t.Run("成功不重试", func(t *testing.T) {
		attempts := 0
		err := Retry(context.Background(), DefaultRetryPolicy(), Retryable, func(context.Context) error {
			attempts++
			return nil
		})
		if err != nil || attempts != 1 {
			t.Errorf("err=%v attempts=%d", err, attempts)
		}
	})

	t.Run("忙碌错误有界重试直到成功", func(t *testing.T) {
		attempts := 0
		err := Retry(context.Background(), DefaultRetryPolicy(), Retryable, func(context.Context) error {
			attempts++
			if attempts < 3 {
				return New(ErrBusy, "", nil)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Retry() = %v", err)
		}
		if attempts != 3 {
			t.Errorf("尝试次数 = %d，期望 3", attempts)
		}
	})

	t.Run("达到上限后返回最后错误", func(t *testing.T) {
		attempts := 0
		policy := RetryPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
		err := Retry(context.Background(), policy, Retryable, func(context.Context) error {
			attempts++
			return New(ErrBusy, "", nil)
		})
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("Retry() = %v，期望 ErrBusy", err)
		}
		if attempts != 2 {
			t.Errorf("尝试次数 = %d，期望 2", attempts)
		}
	})

	t.Run("不可重试错误立即返回", func(t *testing.T) {
		attempts := 0
		unique := New(ErrUniqueViolation, "", nil)
		err := Retry(context.Background(), DefaultRetryPolicy(), Retryable, func(context.Context) error {
			attempts++
			return unique
		})
		if !errors.Is(err, ErrUniqueViolation) || attempts != 1 {
			t.Errorf("err=%v attempts=%d", err, attempts)
		}
	})

	t.Run("上下文取消停止重试", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempts := 0
		policy := RetryPolicy{MaxAttempts: 10, InitialDelay: 50 * time.Millisecond, MaxDelay: 50 * time.Millisecond}
		err := Retry(ctx, policy, Retryable, func(context.Context) error {
			attempts++
			cancel()
			return New(ErrBusy, "", nil)
		})
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrBusy) {
			t.Fatalf("Retry() = %v，期望同时包含取消与忙碌", err)
		}
		if attempts != 1 {
			t.Errorf("取消后不应继续尝试，实际 %d 次", attempts)
		}
	})
}
