package task

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// fakeStore 是 Store 的测试替身，仅用于验证执行器生命周期与参数校验；真实
// SQLite/审计语义由 internal/task/sqlite 的测试覆盖。
type fakeStore struct {
	mu sync.Mutex

	jobs       map[string]Job
	claimJob   *Job
	recoverErr error
	recovered  int
	enqueueErr error
	getErr     error
}

// Enqueue 实现 Store。
func (f *fakeStore) Enqueue(_ context.Context, job NewJob) (Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enqueueErr != nil {
		return Job{}, f.enqueueErr
	}
	if f.jobs == nil {
		f.jobs = make(map[string]Job)
	}
	record := Job{
		ID:                 job.ID,
		Kind:               job.Kind,
		State:              StateQueued,
		Initiator:          job.Initiator,
		Payload:            job.Payload,
		MutexKey:           job.MutexKey,
		TimeoutSeconds:     job.TimeoutSeconds,
		MaxAttempts:        job.MaxAttempts,
		PermissionRequired: job.PermissionRequired,
		RequestID:          job.RequestID,
		CreatedAt:          job.CreatedAt,
		UpdatedAt:          job.CreatedAt,
	}
	f.jobs[job.ID] = record
	return record, nil
}

// Claim 实现 Store。
func (f *fakeStore) Claim(context.Context, string, time.Time) (Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimJob == nil {
		return Job{}, false, nil
	}
	job := *f.claimJob
	f.claimJob = nil
	return job, true, nil
}

// Complete 实现 Store。
func (f *fakeStore) Complete(_ context.Context, completion Completion) (Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job := f.jobs[completion.JobID]
	job.State = completion.State
	f.jobs[completion.JobID] = job
	return job, nil
}

// RequestCancel 实现 Store。
func (f *fakeStore) RequestCancel(context.Context, CancelCommand) (CancelResult, error) {
	return CancelResult{}, nil
}

// RecoverInterrupted 实现 Store。
func (f *fakeStore) RecoverInterrupted(context.Context, string, time.Time) (int, error) {
	return f.recovered, f.recoverErr
}

// Get 实现 Store。
func (f *fakeStore) Get(_ context.Context, id string) (Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return Job{}, false, f.getErr
	}
	job, ok := f.jobs[id]
	return job, ok, nil
}

// Retry 实现 Store：测试替身把任务放回 queued；真实重试状态与审计由 SQLite
// 测试覆盖。
func (f *fakeStore) Retry(_ context.Context, command RetryCommand) (Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, ok := f.jobs[command.JobID]
	if !ok {
		return Job{}, false, ErrTaskNotFound
	}
	job.State = StateQueued
	f.jobs[command.JobID] = job
	return job, true, nil
}

// Attempts 实现 Store。
func (f *fakeStore) Attempts(context.Context, string) ([]Attempt, error) {
	return nil, nil
}

// TestStateValidAndTerminal 验证状态枚举与终态集合。
func TestStateValidAndTerminal(t *testing.T) {
	all := []State{StateQueued, StateRunning, StateSucceeded, StateFailed, StateCancelRequested, StateCancelled, StateTimedOut}
	for _, state := range all {
		if !state.Valid() {
			t.Fatalf("%q 应为合法状态", state)
		}
	}
	for _, state := range []State{StateSucceeded, StateFailed, StateCancelled, StateTimedOut} {
		if !state.Terminal() {
			t.Fatalf("%q 应为终态", state)
		}
	}
	for _, state := range []State{StateQueued, StateRunning, StateCancelRequested} {
		if state.Terminal() {
			t.Fatalf("%q 不应为终态", state)
		}
	}
	for _, state := range []State{"", "done", "RUNNING"} {
		if state.Valid() {
			t.Fatalf("%q 不应为合法状态", state)
		}
	}
}

// TestNewJobIDAndValidation 验证任务编号格式。
func TestNewJobIDAndValidation(t *testing.T) {
	first := mustJobID(t)
	second := mustJobID(t)
	if first == second {
		t.Fatal("两次生成的任务编号相同")
	}
	if err := validateJobID(first); err != nil {
		t.Fatalf("生成的任务编号不合格式: %v", err)
	}
	for _, invalid := range []string{"", "job_", "job_0123", "JOB_0123456789abcdef0123456789abcdef", "job_0123456789ABCDEF0123456789abcdef"} {
		if err := validateJobID(invalid); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("任务编号 %q 错误 = %v", invalid, err)
		}
	}
}

// mustJobID 生成测试任务编号。
func mustJobID(t *testing.T) string {
	t.Helper()
	id, err := NewJobID()
	if err != nil {
		t.Fatalf("NewJobID 失败: %v", err)
	}
	return id
}

// TestNormalizeEnqueueRequest 验证入队默认值与拒绝规则。
func TestNormalizeEnqueueRequest(t *testing.T) {
	valid := EnqueueRequest{Kind: "notification.email", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}}
	normalized, err := normalizeEnqueueRequest(valid)
	if err != nil {
		t.Fatalf("合法入队参数被拒绝: %v", err)
	}
	if normalized.TimeoutSeconds != DefaultTimeoutSeconds {
		t.Fatalf("默认超时 = %d", normalized.TimeoutSeconds)
	}
	if string(normalized.Payload) != "{}" {
		t.Fatalf("默认载荷 = %q", normalized.Payload)
	}
	valid.MutexKey = "user-notification"
	valid.Payload = json.RawMessage(`{"to":"user-1"}`)
	valid.TimeoutSeconds = MinTimeoutSeconds
	valid.RequestID = "req_1"
	if _, err := normalizeEnqueueRequest(valid); err != nil {
		t.Fatalf("边界入队参数被拒绝: %v", err)
	}

	invalid := []EnqueueRequest{
		{Kind: "", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}},
		{Kind: "bad kind", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorAnonymous, ID: ""}},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: ""}},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Payload: json.RawMessage(`{bad`)},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Payload: json.RawMessage(`"` + strings.Repeat("x", MaxPayloadBytes) + `"`)},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, TimeoutSeconds: -1},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, TimeoutSeconds: MaxTimeoutSeconds + 1},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, MutexKey: "bad key"},
		{Kind: "k", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, RequestID: "_bad"},
	}
	for index, request := range invalid {
		if _, err := normalizeEnqueueRequest(request); !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrUntrustedActor) {
			t.Fatalf("第 %d 个非法入队参数错误 = %v", index, err)
		}
	}
}

// TestNormalizeCancelRequest 验证取消参数规则。
func TestNormalizeCancelRequest(t *testing.T) {
	valid := CancelRequest{
		JobID:  mustJobID(t),
		Actor:  audit.Actor{Type: audit.ActorUser, ID: "user-1"},
		Reason: "用户不再需要该通知",
	}
	if _, err := normalizeCancelRequest(valid); err != nil {
		t.Fatalf("合法取消参数被拒绝: %v", err)
	}
	invalid := []CancelRequest{
		{JobID: "bad", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Reason: "x"},
		{JobID: mustJobID(t), Actor: audit.Actor{Type: audit.ActorAnonymous, ID: ""}, Reason: "x"},
		{JobID: mustJobID(t), Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Reason: ""},
		{JobID: mustJobID(t), Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Reason: "line\nbreak"},
		{JobID: mustJobID(t), Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"}, Reason: strings.Repeat("x", MaxReasonBytes+1)},
	}
	for index, request := range invalid {
		if _, err := normalizeCancelRequest(request); !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrUntrustedActor) {
			t.Fatalf("第 %d 个非法取消参数错误 = %v", index, err)
		}
	}
}

// TestSanitizeFailureReason 验证失败说明去控制字符与长度限制。
func TestSanitizeFailureReason(t *testing.T) {
	got := sanitizeFailureReason("line1\nline2\t\r")
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("失败说明仍含控制字符: %q", got)
	}
	if !strings.Contains(got, "line1line2") {
		t.Fatalf("失败说明内容异常: %q", got)
	}
	if sanitizeFailureReason("   ") != "任务处理器失败" {
		t.Fatalf("空失败说明未使用默认值")
	}
	long := sanitizeFailureReason(strings.Repeat("x", maxFailureReasonBytes+100))
	if len(long) > maxFailureReasonBytes {
		t.Fatalf("失败说明长度 = %d", len(long))
	}
}

// TestNewExecutorValidation 验证构造选项校验。
func TestNewExecutorValidation(t *testing.T) {
	store := &fakeStore{}
	handlers := map[string]Handler{"kind": func(context.Context, Job) error { return nil }}
	if _, err := New(nil, Options{Handlers: handlers, ExecutorID: "exec-1"}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 存储错误 = %v", err)
	}
	var typedNil *fakeStore
	if _, err := New(typedNil, Options{Handlers: handlers, ExecutorID: "exec-1"}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("typed nil 存储错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: handlers}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("空执行器标识错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: map[string]Handler{"bad kind": func(context.Context, Job) error { return nil }}, ExecutorID: "exec-1"}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("非法任务类型错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: map[string]Handler{"kind": nil}, ExecutorID: "exec-1"}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 处理器错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: handlers, ExecutorID: "exec-1", MaxConcurrent: MaxAllowedConcurrent + 1}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("并发超限错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: handlers, ExecutorID: "exec-1", PollInterval: time.Millisecond}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("轮询间隔过短错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: handlers, ExecutorID: "exec-1", ShutdownTimeout: time.Hour}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("关闭期限过长错误 = %v", err)
	}
	if _, err := New(store, Options{Handlers: handlers, ExecutorID: "exec-1"}); err != nil {
		t.Fatalf("合法选项失败: %v", err)
	}
	// 允许不注册任何处理器；未知类型任务会在执行时失败并记录。
	if _, err := New(store, Options{ExecutorID: "exec-1"}); err != nil {
		t.Fatalf("空处理器集合不应拒绝构造: %v", err)
	}
}

// TestExecutorLifecycleAndEnqueueValidation 验证 Start/Stop 状态机与取消/查询
// 参数校验；任务执行语义由真实 SQLite 测试覆盖。
func TestExecutorLifecycleAndEnqueueValidation(t *testing.T) {
	store := &fakeStore{}
	executor, err := New(store, Options{
		Handlers:        map[string]Handler{"job.kind": func(context.Context, Job) error { return nil }},
		ExecutorID:      "exec-1",
		PollInterval:    MinPollInterval,
		ShutdownTimeout: MinShutdownTimeout,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	// 未启动允许入队；匿名入队被拒绝。
	if _, err := executor.Enqueue(context.Background(), EnqueueRequest{
		Kind: "job.kind", Actor: audit.Actor{Type: audit.ActorAnonymous, ID: ""},
	}); !errors.Is(err, ErrUntrustedActor) {
		t.Fatalf("匿名入队错误 = %v", err)
	}
	enqueued, err := executor.Enqueue(context.Background(), EnqueueRequest{
		Kind: "job.kind", Actor: audit.Actor{Type: audit.ActorUser, ID: "user-1"},
	})
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if _, err := executor.Get(context.Background(), enqueued.ID); err != nil {
		t.Fatalf("查询已入队任务失败: %v", err)
	}
	if _, err := executor.Get(context.Background(), "bad-id"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法任务编号错误 = %v", err)
	}

	// Stop 在 Start 前可调用，之后不能再启动。
	if err := executor.Stop(context.Background()); err != nil {
		t.Fatalf("未启动 Stop 失败: %v", err)
	}
	if err := executor.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("停止后 Start 错误 = %v", err)
	}

	// 新执行器：Start 成功后拒绝重复 Start，Stop 后拒绝再次 Start。
	executor2, err := New(store, Options{
		Handlers:        map[string]Handler{"job.kind": func(context.Context, Job) error { return nil }},
		ExecutorID:      "exec-2",
		PollInterval:    MinPollInterval,
		ShutdownTimeout: MinShutdownTimeout,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := executor2.Start(context.Background()); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	if err := executor2.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("重复 Start 错误 = %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := executor2.Stop(stopCtx); err != nil {
		t.Fatalf("Stop 失败: %v", err)
	}
	if err := executor2.Stop(stopCtx); err != nil {
		t.Fatalf("重复 Stop 失败: %v", err)
	}
	if err := executor2.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("再次 Start 错误 = %v", err)
	}
}

// TestExecutorRecoveryFailure 验证恢复失败时 Start 拒绝启动且可重试。
func TestExecutorRecoveryFailure(t *testing.T) {
	store := &fakeStore{recoverErr: errors.New("恢复失败")}
	executor, err := New(store, Options{ExecutorID: "exec-1", PollInterval: MinPollInterval, ShutdownTimeout: MinShutdownTimeout})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := executor.Start(context.Background()); !errors.Is(err, ErrRecoveryFailed) {
		t.Fatalf("恢复失败错误 = %v", err)
	}
	store.mu.Lock()
	store.recoverErr = nil
	store.mu.Unlock()
	if err := executor.Start(context.Background()); err != nil {
		t.Fatalf("恢复失败后重试 Start 失败: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := executor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop 失败: %v", err)
	}
}
