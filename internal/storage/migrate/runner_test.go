package migrate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBackend 是迁移执行器的可控内存后端，只用于测试。它模拟排他锁、已应用
// 记录、失败记录和故障注入，不执行真实 SQL，也不是生产实现。
type fakeBackend struct {
	lockCh chan struct{}

	stateMu            sync.Mutex
	applied            []AppliedMigration
	failed             []FailedMigration
	applyCalls         int
	applyStatements    [][]string
	applyErr           map[string]error
	recordFailureErr   error
	clearFailureCalls  map[string]int
	ensureCalls        int
	currentLocks       int
	maxConcurrentLocks int
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		lockCh:            make(chan struct{}, 1),
		applyErr:          make(map[string]error),
		clearFailureCalls: make(map[string]int),
	}
}

func (f *fakeBackend) Lock(ctx context.Context, fn func(context.Context) error) error {
	select {
	case f.lockCh <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-f.lockCh }()

	f.stateMu.Lock()
	f.currentLocks++
	if f.currentLocks > f.maxConcurrentLocks {
		f.maxConcurrentLocks = f.currentLocks
	}
	f.stateMu.Unlock()
	defer func() {
		f.stateMu.Lock()
		f.currentLocks--
		f.stateMu.Unlock()
	}()
	return fn(ctx)
}

func (f *fakeBackend) EnsureBookkeeping(context.Context) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.ensureCalls++
	return nil
}

func (f *fakeBackend) LoadApplied(context.Context) ([]AppliedMigration, error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	records := make([]AppliedMigration, len(f.applied))
	copy(records, f.applied)
	return records, nil
}

func (f *fakeBackend) LoadFailed(context.Context) ([]FailedMigration, error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	records := make([]FailedMigration, len(f.failed))
	copy(records, f.failed)
	return records, nil
}

func (f *fakeBackend) Apply(_ context.Context, statements []string, record AppliedMigration) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.applyCalls++
	if err := f.applyErr[record.Version]; err != nil {
		return err
	}
	copied := make([]string, len(statements))
	copy(copied, statements)
	f.applyStatements = append(f.applyStatements, copied)
	f.applied = append(f.applied, record)
	return nil
}

func (f *fakeBackend) RecordFailure(_ context.Context, record FailedMigration) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if f.recordFailureErr != nil {
		return f.recordFailureErr
	}
	kept := f.failed[:0]
	for _, existing := range f.failed {
		if existing.Version != record.Version {
			kept = append(kept, existing)
		}
	}
	f.failed = append(kept, record)
	return nil
}

func (f *fakeBackend) ClearFailure(_ context.Context, version string) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.clearFailureCalls[version]++
	kept := f.failed[:0]
	for _, existing := range f.failed {
		if existing.Version != version {
			kept = append(kept, existing)
		}
	}
	f.failed = kept
	return nil
}

func (f *fakeBackend) setApplyError(version string, err error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if err == nil {
		delete(f.applyErr, version)
		return
	}
	f.applyErr[version] = err
}

func (f *fakeBackend) setRecordFailureError(err error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.recordFailureErr = err
}

func (f *fakeBackend) seedApplied(records ...AppliedMigration) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.applied = append(f.applied, records...)
}

func (f *fakeBackend) seedFailed(records ...FailedMigration) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.failed = append(f.failed, records...)
}

func (f *fakeBackend) snapshotApplied() []AppliedMigration {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	records := make([]AppliedMigration, len(f.applied))
	copy(records, f.applied)
	return records
}

func (f *fakeBackend) snapshotFailed() []FailedMigration {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	records := make([]FailedMigration, len(f.failed))
	copy(records, f.failed)
	return records
}

func (f *fakeBackend) applyCount() int {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.applyCalls
}

func testMigrations() []Migration {
	return []Migration{
		{
			Version:     "0001",
			Description: "first step",
			FileName:    "0001_first_step.sql",
			Checksum:    "1111111111111111111111111111111111111111111111111111111111111111",
			Statements:  []string{"CREATE TABLE first (id TEXT);"},
		},
		{
			Version:     "0002",
			Description: "second step",
			FileName:    "0002_second_step.sql",
			Checksum:    "2222222222222222222222222222222222222222222222222222222222222222",
			Statements:  []string{"CREATE TABLE second (id TEXT);", "CREATE INDEX ix_second ON second(id);"},
		},
	}
}

func TestRunnerAppliesPendingInOrderAndIsIdempotent(t *testing.T) {
	backend := newFakeBackend()
	fixed := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	runner, err := NewRunner(backend, testMigrations(), WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}

	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() 失败：%v", err)
	}
	if result.UpToDate {
		t.Error("首次运行不应为 UpToDate")
	}
	if len(result.Applied) != 2 {
		t.Fatalf("已应用数量 = %d", len(result.Applied))
	}
	if result.Applied[0].Version != "0001" || result.Applied[1].Version != "0002" {
		t.Errorf("应用顺序 = %+v", result.Applied)
	}
	if !result.Applied[0].AppliedAt.Equal(fixed) {
		t.Errorf("applied_at = %v，期望注入的 UTC 时间 %v", result.Applied[0].AppliedAt, fixed)
	}
	if got := backend.snapshotApplied(); len(got) != 2 {
		t.Fatalf("后端已应用记录 = %d", len(got))
	}
	if backend.applyCount() != 2 {
		t.Errorf("Apply 调用次数 = %d，期望 2", backend.applyCount())
	}

	// 第二次运行（新的 Runner，同一个持久化后端）必须识别已应用版本。
	second, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	result, err = second.Run(context.Background())
	if err != nil {
		t.Fatalf("重复 Run() 失败：%v", err)
	}
	if !result.UpToDate || len(result.Applied) != 0 {
		t.Errorf("已应用后再次运行结果 = %+v", result)
	}
	if backend.applyCount() != 2 {
		t.Errorf("重复运行不应再次 Apply，调用次数 = %d", backend.applyCount())
	}
}

func TestRunnerPassesNonTransactionalFlag(t *testing.T) {
	migrations := testMigrations()
	migrations[1].NonTransactional = true
	backend := newFakeBackend()
	runner, err := NewRunner(backend, migrations)
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() 失败：%v", err)
	}
	applied := backend.snapshotApplied()
	if len(applied) != 2 || applied[1].NonTransactional != true {
		t.Errorf("非事务标记未传递给后端：%+v", applied)
	}
}

func TestRunnerChecksumMismatch(t *testing.T) {
	backend := newFakeBackend()
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() 失败：%v", err)
	}

	changed := testMigrations()
	changed[0].Checksum = "3333333333333333333333333333333333333333333333333333333333333333"
	changed[0].Statements = []string{"CREATE TABLE first (id TEXT, altered TEXT);"}
	second, err := NewRunner(backend, changed)
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	before := backend.applyCount()
	if _, err := second.Run(context.Background()); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("错误 = %v，期望 ErrChecksumMismatch", err)
	}
	if backend.applyCount() != before {
		t.Error("校验和不符时不得执行新迁移")
	}
}

func TestRunnerOrderMismatch(t *testing.T) {
	backend := newFakeBackend()
	migrations := testMigrations()
	backend.seedApplied(AppliedMigration{
		Version:  "0002",
		Checksum: migrations[1].Checksum,
	})
	runner, err := NewRunner(backend, migrations)
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := runner.Run(context.Background()); !errors.Is(err, ErrMigrationOrder) {
		t.Fatalf("错误 = %v，期望 ErrMigrationOrder", err)
	}
}

func TestRunnerUnknownAppliedMigration(t *testing.T) {
	backend := newFakeBackend()
	backend.seedApplied(AppliedMigration{Version: "0009", Checksum: "abc"})
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := runner.Run(context.Background()); !errors.Is(err, ErrUnknownAppliedMigration) {
		t.Fatalf("错误 = %v，期望 ErrUnknownAppliedMigration", err)
	}
}

func TestRunnerFailureRecordsAndRetry(t *testing.T) {
	backend := newFakeBackend()
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}

	applyCause := errors.New("模拟建表失败 line1\nline2")
	backend.setApplyError("0002", applyCause)
	result, err := runner.Run(context.Background())
	if err == nil {
		t.Fatal("迁移失败应返回错误")
	}
	if !errors.Is(err, applyCause) {
		t.Errorf("错误未包含原始原因：%v", err)
	}
	if len(result.Applied) != 1 || result.Applied[0].Version != "0001" {
		t.Errorf("失败后应只应用 0001：%+v", result.Applied)
	}

	failures := backend.snapshotFailed()
	if len(failures) != 1 {
		t.Fatalf("失败记录数量 = %d", len(failures))
	}
	failure := failures[0]
	if failure.Version != "0002" || failure.Checksum != testMigrations()[1].Checksum {
		t.Errorf("失败记录 = %+v", failure)
	}
	if failure.FailedAt.IsZero() {
		t.Error("失败记录缺少时间")
	}
	if containsControl(failure.ErrorSummary) {
		t.Errorf("失败摘要包含控制字符：%q", failure.ErrorSummary)
	}
	if len([]rune(failure.ErrorSummary)) > maxErrorSummaryRunes {
		t.Errorf("失败摘要超长：%d", len([]rune(failure.ErrorSummary)))
	}

	// 再次运行必须拒绝，而不是在未知结构上继续。
	before := backend.applyCount()
	second, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := second.Run(context.Background()); !errors.Is(err, ErrFailurePending) {
		t.Fatalf("再次运行错误 = %v，期望 ErrFailurePending", err)
	}
	if backend.applyCount() != before {
		t.Error("存在失败记录时不得执行新迁移")
	}

	// 人工清理失败记录后可以重试。
	if err := second.ClearFailure(context.Background(), "0002"); err != nil {
		t.Fatalf("ClearFailure() 失败：%v", err)
	}
	backend.setApplyError("0002", nil)
	result, err = second.Run(context.Background())
	if err != nil {
		t.Fatalf("清理失败记录后 Run() 失败：%v", err)
	}
	if len(result.Applied) != 1 || result.Applied[0].Version != "0002" {
		t.Errorf("重试结果 = %+v", result)
	}
	if len(backend.snapshotFailed()) != 0 {
		t.Error("成功重试后失败记录应已清理")
	}
}

func TestRunnerRecordFailureErrorJoined(t *testing.T) {
	backend := newFakeBackend()
	applyCause := errors.New("迁移失败")
	recordCause := errors.New("写入失败记录失败")
	backend.setApplyError("0001", applyCause)
	backend.setRecordFailureError(recordCause)

	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	_, err = runner.Run(context.Background())
	if !errors.Is(err, applyCause) || !errors.Is(err, recordCause) {
		t.Fatalf("错误应同时包含迁移失败与记录失败：%v", err)
	}
}

func TestRunnerConcurrentRuns(t *testing.T) {
	backend := newFakeBackend()
	const workers = 8
	results := make([]error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			runner, err := NewRunner(backend, testMigrations())
			if err != nil {
				results[index] = err
				return
			}
			_, results[index] = runner.Run(context.Background())
		}(worker)
	}
	wait.Wait()

	for index, err := range results {
		if err != nil {
			t.Errorf("并发 Run %d 失败：%v", index, err)
		}
	}
	applied := backend.snapshotApplied()
	if len(applied) != 2 {
		t.Fatalf("并发运行后已应用记录 = %d，期望 2", len(applied))
	}
	if backend.applyCount() != 2 {
		t.Errorf("Apply 调用次数 = %d，期望每条迁移只执行一次", backend.applyCount())
	}
	if backend.maxConcurrentLocks != 1 {
		t.Errorf("并发持锁数 = %d，期望 1", backend.maxConcurrentLocks)
	}
}

func TestRunnerLockReleasedAfterError(t *testing.T) {
	backend := newFakeBackend()
	backend.setApplyError("0001", errors.New("失败"))
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := runner.Run(context.Background()); err == nil {
		t.Fatal("应返回迁移失败")
	}
	// 若锁未释放，这次调用会一直阻塞；使用带超时的 ctx 防止测试卡死。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	second, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if _, err := second.Run(ctx); !errors.Is(err, ErrFailurePending) {
		t.Fatalf("错误 = %v，期望 ErrFailurePending", err)
	}
}

func TestRunnerContextCancelledBeforeRun(t *testing.T) {
	backend := newFakeBackend()
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("错误 = %v，期望 context.Canceled", err)
	}
	if backend.applyCount() != 0 {
		t.Error("ctx 已取消时不得执行迁移")
	}
}

func TestRunnerInconsistentHistory(t *testing.T) {
	migrations := testMigrations()

	t.Run("失败记录与已应用冲突", func(t *testing.T) {
		backend := newFakeBackend()
		backend.seedApplied(AppliedMigration{Version: "0001", Checksum: migrations[0].Checksum})
		backend.seedFailed(FailedMigration{Version: "0001", Checksum: migrations[0].Checksum})
		runner, err := NewRunner(backend, migrations)
		if err != nil {
			t.Fatalf("NewRunner() 失败：%v", err)
		}
		if _, err := runner.Run(context.Background()); !errors.Is(err, ErrMigrationHistoryInvalid) {
			t.Fatalf("错误 = %v，期望 ErrMigrationHistoryInvalid", err)
		}
	})

	t.Run("失败记录版本未知", func(t *testing.T) {
		backend := newFakeBackend()
		backend.seedFailed(FailedMigration{Version: "0009", Checksum: "abc"})
		runner, err := NewRunner(backend, migrations)
		if err != nil {
			t.Fatalf("NewRunner() 失败：%v", err)
		}
		if _, err := runner.Run(context.Background()); !errors.Is(err, ErrMigrationHistoryInvalid) {
			t.Fatalf("错误 = %v，期望 ErrMigrationHistoryInvalid", err)
		}
	})
}

func TestClearFailureUnknownVersion(t *testing.T) {
	backend := newFakeBackend()
	runner, err := NewRunner(backend, testMigrations())
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	if err := runner.ClearFailure(context.Background(), "0009"); !errors.Is(err, ErrInvalidMigration) {
		t.Fatalf("错误 = %v，期望 ErrInvalidMigration", err)
	}
}

func TestNewRunnerRejectsInvalidSetup(t *testing.T) {
	if _, err := NewRunner(nil, testMigrations()); !errors.Is(err, ErrInvalidMigration) {
		t.Errorf("nil 后端错误 = %v", err)
	}

	cases := []struct {
		name       string
		migrations []Migration
		wantErr    error
	}{
		{
			name: "重复版本",
			migrations: []Migration{
				{Version: "0001", Description: "a", Checksum: "a", Statements: []string{"SELECT 1;"}},
				{Version: "0001", Description: "b", Checksum: "b", Statements: []string{"SELECT 2;"}},
			},
			wantErr: ErrDuplicateMigrationVersion,
		},
		{
			name: "未排序",
			migrations: []Migration{
				{Version: "0002", Description: "b", Checksum: "b", Statements: []string{"SELECT 2;"}},
				{Version: "0001", Description: "a", Checksum: "a", Statements: []string{"SELECT 1;"}},
			},
			wantErr: ErrInvalidMigration,
		},
		{
			name: "版本格式错误",
			migrations: []Migration{
				{Version: "1", Description: "a", Checksum: "a", Statements: []string{"SELECT 1;"}},
			},
			wantErr: ErrInvalidMigration,
		},
		{
			name: "空语句",
			migrations: []Migration{
				{Version: "0001", Description: "a", Checksum: "a", Statements: []string{"   "}},
			},
			wantErr: ErrInvalidMigration,
		},
		{
			name: "缺少校验和",
			migrations: []Migration{
				{Version: "0001", Description: "a", Statements: []string{"SELECT 1;"}},
			},
			wantErr: ErrInvalidMigration,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRunner(newFakeBackend(), test.migrations); !errors.Is(err, test.wantErr) {
				t.Fatalf("错误 = %v，期望 errors.Is(%v)", err, test.wantErr)
			}
		})
	}
}

func TestRunnerWithNoMigrations(t *testing.T) {
	backend := newFakeBackend()
	runner, err := NewRunner(backend, nil)
	if err != nil {
		t.Fatalf("NewRunner() 失败：%v", err)
	}
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() 失败：%v", err)
	}
	if !result.UpToDate || len(result.Applied) != 0 {
		t.Errorf("无迁移时结果 = %+v", result)
	}
}

func TestSummarizeError(t *testing.T) {
	if got := summarizeError(nil); got != "未知错误" {
		t.Errorf("nil 错误 = %q", got)
	}
	long := "错误\n第二行\r\t" + strings.Repeat("长", maxErrorSummaryRunes+100)
	summary := summarizeError(errors.New(long))
	if containsControl(summary) {
		t.Errorf("摘要包含控制字符：%q", summary)
	}
	if len([]rune(summary)) > maxErrorSummaryRunes {
		t.Errorf("摘要长度 = %d", len([]rune(summary)))
	}
}

func containsControl(text string) bool {
	for _, character := range text {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
