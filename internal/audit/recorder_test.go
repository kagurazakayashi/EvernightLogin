package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeStore 是 Store 的测试替身，用于验证 Recorder 的错误映射、失败审计与告警；
// 真实 SQLite 事务语义由 internal/audit/sqlite 的测试验证。
type fakeStore struct {
	mu sync.Mutex

	appended       []Event
	appendErr      error
	appendCtxErr   error
	appendCalls    int
	businessWrites int
	runCriticalFn  func(ctx context.Context, success Event, change func(context.Context, Tx) error) error
}

// Append 实现 Store。
func (f *fakeStore) Append(ctx context.Context, event Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appendCalls++
	f.appendCtxErr = ctx.Err()
	if f.appendErr != nil {
		return f.appendErr
	}
	f.appended = append(f.appended, event)
	return nil
}

// RunCritical 实现 Store。
func (f *fakeStore) RunCritical(ctx context.Context, success Event, change func(context.Context, Tx) error) error {
	if f.runCriticalFn != nil {
		return f.runCriticalFn(ctx, success, change)
	}
	tx := &fakeTx{store: f}
	if err := change(ctx, tx); err != nil {
		return err
	}
	return f.Append(ctx, success)
}

// snapshot 返回已记录事件副本。
func (f *fakeStore) snapshot() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]Event, len(f.appended))
	copy(copied, f.appended)
	return copied
}

// fakeTx 是 Tx 的测试替身。
type fakeTx struct {
	store *fakeStore
}

// AppendEvent 实现 Tx。
func (t *fakeTx) AppendEvent(ctx context.Context, event Event) error {
	return t.store.Append(ctx, event)
}

// ExecContext 实现 Tx。
func (t *fakeTx) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	t.store.businessWrites++
	return fakeResult{}, nil
}

// fakeResult 是 sql.Result 的最小测试实现。
type fakeResult struct{}

// LastInsertId 实现 sql.Result。
func (fakeResult) LastInsertId() (int64, error) { return 0, nil }

// RowsAffected 实现 sql.Result。
func (fakeResult) RowsAffected() (int64, error) { return 1, nil }

// fakeAlerter 记录告警。
type fakeAlerter struct {
	mu     sync.Mutex
	alarms []Alarm
}

// Alarm 实现 Alerter。
func (a *fakeAlerter) Alarm(_ context.Context, alarm Alarm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alarms = append(a.alarms, alarm)
}

// snapshot 返回告警副本。
func (a *fakeAlerter) snapshot() []Alarm {
	a.mu.Lock()
	defer a.mu.Unlock()
	copied := make([]Alarm, len(a.alarms))
	copy(copied, a.alarms)
	return copied
}

// fakeClock 是可注入时钟。
type fakeClock struct {
	now time.Time
}

// Now 返回当前测试时间。
func (c *fakeClock) Now() time.Time {
	return c.now
}

// newTestRecorder 构造使用替身存储与告警的 Recorder。
func newTestRecorder(t *testing.T, store Store, alerter Alerter) (*Recorder, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 11, 15, 10, 0, 0, 123456789, time.UTC)}
	recorder, err := New(store, Options{
		Now:     clock.Now,
		Alerter: alerter,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return recorder, clock
}

// sampleEvent 返回未填 ID/时间的测试事件。
func sampleEvent() Event {
	return Event{
		Actor:   Actor{Type: ActorUser, ID: "user-1"},
		AppID:   "app_1",
		Action:  "users.disable",
		Target:  Target{Type: "user", ID: "user-2"},
		Outcome: OutcomeSuccess,
		Changes: []FieldChange{{Field: "status", Before: "active", After: "disabled"}},
	}
}

// TestNewRejectsInvalidOptions 验证空存储、typed nil 与非法期限都被拒绝。
func TestNewRejectsInvalidOptions(t *testing.T) {
	if _, err := New(nil, Options{}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 存储错误 = %v", err)
	}
	var typedNil *fakeStore
	if _, err := New(typedNil, Options{}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("typed nil 存储错误 = %v", err)
	}
	if _, err := New(&fakeStore{}, Options{FailureAuditTimeout: time.Minute + time.Second}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("超长失败审计期限错误 = %v", err)
	}
	if _, err := New(&fakeStore{}, Options{FailureAuditTimeout: -time.Second}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("负失败审计期限错误 = %v", err)
	}
}

// TestRecordSetsTimeAndIDAndValidates 验证 Record 自动生成 ID、覆盖时间并校验事件。
func TestRecordSetsTimeAndIDAndValidates(t *testing.T) {
	store := &fakeStore{}
	recorder, clock := newTestRecorder(t, store, &fakeAlerter{})
	if err := recorder.Record(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Record 失败: %v", err)
	}
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("写入事件数 = %d", len(events))
	}
	event := events[0]
	if event.ID == "" {
		t.Fatal("事件 ID 未生成")
	}
	if err := validateEventID(event.ID); err != nil {
		t.Fatalf("事件 ID 格式错误: %v", err)
	}
	wantTime := clock.now.UTC().Truncate(time.Millisecond)
	if !event.OccurredAt.Equal(wantTime) {
		t.Fatalf("发生时间 = %s，期望 %s", event.OccurredAt, wantTime)
	}
	if event.Outcome != OutcomeSuccess {
		t.Fatalf("结果 = %s", event.Outcome)
	}

	invalid := sampleEvent()
	invalid.Action = ""
	if err := recorder.Record(context.Background(), invalid); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("非法事件错误 = %v", err)
	}
	if got := len(store.snapshot()); got != 1 {
		t.Fatalf("非法事件仍被写入，事件数 = %d", got)
	}
}

// TestRecordDuplicateAndAuditFailure 验证重复与写入失败映射及告警。
func TestRecordDuplicateAndAuditFailure(t *testing.T) {
	alerter := &fakeAlerter{}
	duplicateStore := &fakeStore{appendErr: ErrDuplicateEvent}
	duplicateRecorder, _ := newTestRecorder(t, duplicateStore, alerter)
	if err := duplicateRecorder.Record(context.Background(), sampleEvent()); !errors.Is(err, ErrDuplicateEvent) {
		t.Fatalf("重复事件错误 = %v", err)
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatal("幂等重复不应触发审计故障告警")
	}

	failingStore := &fakeStore{appendErr: errors.New("磁盘不可用")}
	failingRecorder, _ := newTestRecorder(t, failingStore, alerter)
	err := failingRecorder.Record(context.Background(), sampleEvent())
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("写入失败错误 = %v，期望 ErrAuditUnavailable", err)
	}
	alarms := alerter.snapshot()
	if len(alarms) != 1 || alarms[0].Kind != AlarmAuditWriteFailed {
		t.Fatalf("告警 = %+v", alarms)
	}
}

// TestRecordCancelledContext 验证普通记录在调用方取消时不写、不伪装成功。
func TestRecordCancelledContext(t *testing.T) {
	store := &fakeStore{appendErr: errors.New("不应调用")}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.Record(ctx, sampleEvent()); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误 = %v", err)
	}
	if store.appendCalls != 0 {
		t.Fatalf("取消后仍调用 Append %d 次", store.appendCalls)
	}
}

// TestRecordFailureSurvivesCancellation 验证失败审计使用独立 context 并保存。
func TestRecordFailureSurvivesCancellation(t *testing.T) {
	store := &fakeStore{}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.RecordFailure(ctx, sampleEvent()); err != nil {
		t.Fatalf("RecordFailure 失败: %v", err)
	}
	if len(store.snapshot()) != 1 {
		t.Fatalf("失败审计未保存")
	}
	if store.appendCtxErr != nil {
		t.Fatalf("失败审计写入 context 已取消: %v", store.appendCtxErr)
	}
}

// TestRecordFailureAuditFailureAlarms 验证失败审计写入失败会告警并返回
// ErrAuditUnavailable。
func TestRecordFailureAuditFailureAlarms(t *testing.T) {
	alerter := &fakeAlerter{}
	store := &fakeStore{appendErr: errors.New("审计库不可用")}
	recorder, _ := newTestRecorder(t, store, alerter)
	if err := recorder.RecordFailure(context.Background(), sampleEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("错误 = %v", err)
	}
	if len(alerter.snapshot()) != 1 {
		t.Fatalf("未触发告警")
	}
}

// TestExecuteCriticalSuccess 验证关键变更与成功审计一致提交。
func TestExecuteCriticalSuccess(t *testing.T) {
	store := &fakeStore{}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	request := CriticalRequest{Event: sampleEvent()}
	err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE business SET v=1")
		return err
	})
	if err != nil {
		t.Fatalf("ExecuteCritical 失败: %v", err)
	}
	if store.businessWrites != 1 {
		t.Fatalf("业务写入次数 = %d", store.businessWrites)
	}
	events := store.snapshot()
	if len(events) != 1 || events[0].Outcome != OutcomeSuccess {
		t.Fatalf("成功审计事件 = %+v", events)
	}
}

// TestExecuteCriticalBusinessFailureRecordsFailure 验证业务失败回滚后失败审计仍保存。
func TestExecuteCriticalBusinessFailureRecordsFailure(t *testing.T) {
	store := &fakeStore{}
	alerter := &fakeAlerter{}
	recorder, _ := newTestRecorder(t, store, alerter)
	businessErr := errors.New("业务冲突")
	request := CriticalRequest{
		Event:             sampleEvent(),
		FailureErrorCode:  "CONFLICT",
		FailureReasonCode: "version_conflict",
	}
	err := recorder.ExecuteCritical(context.Background(), request, func(ctx context.Context, tx Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE business SET v=1"); err != nil {
			return err
		}
		return businessErr
	})
	if !errors.Is(err, businessErr) {
		t.Fatalf("错误 = %v，期望业务错误", err)
	}
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("审计事件数 = %d，期望失败事件 1 条", len(events))
	}
	failure := events[0]
	if failure.Outcome != OutcomeFailure || failure.ErrorCode != "CONFLICT" || failure.ReasonCode != "version_conflict" {
		t.Fatalf("失败审计字段 = %+v", failure)
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatal("业务失败但审计成功时不应告警")
	}
}

// TestExecuteCriticalAuditFailureRejectsChange 验证审计故障拒绝关键变更并告警。
func TestExecuteCriticalAuditFailureRejectsChange(t *testing.T) {
	alerter := &fakeAlerter{}
	store := &fakeStore{}
	store.runCriticalFn = func(ctx context.Context, success Event, change func(context.Context, Tx) error) error {
		tx := &fakeTx{store: store}
		if err := change(ctx, tx); err != nil {
			return err
		}
		return fmt.Errorf("%w: 注入的审计写入失败", ErrAuditUnavailable)
	}
	recorder, _ := newTestRecorder(t, store, alerter)
	err := recorder.ExecuteCritical(context.Background(), CriticalRequest{Event: sampleEvent()}, func(ctx context.Context, tx Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE business SET v=1")
		return err
	})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("错误 = %v，期望 ErrAuditUnavailable", err)
	}
	alarms := alerter.snapshot()
	if len(alarms) == 0 || alarms[0].Kind != AlarmAuditWriteFailed {
		t.Fatalf("未触发审计故障告警: %+v", alarms)
	}
	// 失败事件仍被独立记录（业务回滚可追踪）。
	events := store.snapshot()
	if len(events) != 1 || events[0].Outcome != OutcomeFailure {
		t.Fatalf("失败审计事件 = %+v", events)
	}
}

// TestExecuteCriticalDuplicateDoesNotRunChange 验证幂等重放不执行业务变更。
func TestExecuteCriticalDuplicateDoesNotRunChange(t *testing.T) {
	store := &fakeStore{runCriticalFn: func(context.Context, Event, func(context.Context, Tx) error) error {
		return ErrDuplicateEvent
	}}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	changeCalled := false
	err := recorder.ExecuteCritical(context.Background(), CriticalRequest{Event: sampleEvent()}, func(context.Context, Tx) error {
		changeCalled = true
		return nil
	})
	if !errors.Is(err, ErrDuplicateEvent) {
		t.Fatalf("错误 = %v，期望 ErrDuplicateEvent", err)
	}
	if changeCalled {
		t.Fatal("幂等重放仍执行了关键变更")
	}
	if len(store.snapshot()) != 0 {
		t.Fatal("幂等重放写入了重复审计事件")
	}
}

// TestExecuteCriticalValidationAndCancellation 验证参数校验与取消路径。
func TestExecuteCriticalValidationAndCancellation(t *testing.T) {
	store := &fakeStore{}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	changeCalled := false
	change := func(context.Context, Tx) error {
		changeCalled = true
		return nil
	}
	invalidCode := CriticalRequest{Event: sampleEvent(), FailureErrorCode: "bad-code"}
	if err := recorder.ExecuteCritical(context.Background(), invalidCode, change); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("非法失败错误码错误 = %v", err)
	}
	if changeCalled {
		t.Fatal("参数校验失败仍执行了变更")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.ExecuteCritical(ctx, CriticalRequest{Event: sampleEvent()}, change); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误 = %v", err)
	}
	if changeCalled {
		t.Fatal("取消后仍执行了变更")
	}
}

// TestExecuteCriticalCancellationDuringChangeRecordsFailure 验证变更因取消失败时
// 仍补写失败审计。
func TestExecuteCriticalCancellationDuringChangeRecordsFailure(t *testing.T) {
	store := &fakeStore{}
	store.runCriticalFn = func(ctx context.Context, success Event, change func(context.Context, Tx) error) error {
		tx := &fakeTx{store: store}
		return change(ctx, tx)
	}
	recorder, _ := newTestRecorder(t, store, &fakeAlerter{})
	err := recorder.ExecuteCritical(context.Background(), CriticalRequest{Event: sampleEvent()}, func(ctx context.Context, tx Tx) error {
		if _, writeErr := tx.ExecContext(ctx, "UPDATE business SET v=1"); writeErr != nil {
			return writeErr
		}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("错误 = %v，期望 context.Canceled", err)
	}
	events := store.snapshot()
	if len(events) != 1 || events[0].Outcome != OutcomeFailure {
		t.Fatalf("取消后的失败审计 = %+v", events)
	}
}

// TestAlarmPanicIsContained 验证告警实现 panic 不影响审计失败结果。
func TestAlarmPanicIsContained(t *testing.T) {
	store := &fakeStore{appendErr: errors.New("审计失败")}
	recorder, err := New(store, Options{Alerter: AlerterFunc(func(context.Context, Alarm) {
		panic("告警处理器故障")
	})})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := recorder.Record(context.Background(), sampleEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("错误 = %v，期望 ErrAuditUnavailable", err)
	}
}
