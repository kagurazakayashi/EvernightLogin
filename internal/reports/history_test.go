package reports

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// fakeHistory 是明确标注的历史持久化替身：记录服务端写入的受控历史条目。
// 只用于验证终态写入语义，不进入生产装配。
type fakeHistory struct {
	mu      sync.Mutex
	entries []HistoryRecord
	err     error
}

// RecordReportHistory 实现 HistoryRecorder。
func (f *fakeHistory) RecordReportHistory(_ context.Context,
	record HistoryRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, record)
	return nil
}

// last 返回最近一条历史条目。
func (f *fakeHistory) last() (HistoryRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) == 0 {
		return HistoryRecord{}, false
	}
	return f.entries[len(f.entries)-1], true
}

// count 返回历史条目数量。
func (f *fakeHistory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// newHistoryEnv 构造带历史持久化替身的完整测试环境。
func newHistoryEnv(t *testing.T) (*testEnv, *fakeHistory) {
	t.Helper()
	env := newTestEnv(t)
	history := &fakeHistory{}
	service, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller, Tasks: env.tasks,
		OutputDir: env.outputDir, MaxDetailRows: 50, Now: env.now,
		History: history})
	if err != nil {
		t.Fatalf("构造带历史持久化的报告服务失败: %v", err)
	}
	env.service = service
	return env, history
}

// TestHistoryWritesTerminalStates 验证成功/失败/取消/超时终态都写入真实历史，
// 且不产生假成功记录。
func TestHistoryWritesTerminalStates(t *testing.T) {
	cases := []struct {
		name      string
		prepare   func(env *testEnv)
		wantState string
		wantCode  string
	}{
		{name: "succeeded", prepare: func(env *testEnv) {},
			wantState: StateSucceeded},
		{name: "failed", prepare: func(env *testEnv) {
			env.source.err = errors.New("source unavailable")
		}, wantState: StateFailed},
		{name: "timed_out", prepare: func(env *testEnv) {
			env.source.err = context.DeadlineExceeded
		}, wantState: "timed_out", wantCode: string(CodeTaskTimeout)},
		{name: "cancelled", prepare: func(env *testEnv) {
			env.source.cancelled = true
		}, wantState: StateCancelled},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			env, history := newHistoryEnv(t)
			env.grantAll(testUserID(1), ScopeSystem,
				stats.ScopeGrant{Allowed: true, AllData: true})
			request := env.startRequest(t)
			view, err := env.service.Start(context.Background(), request)
			if err != nil {
				t.Fatalf("创建报告失败: %v", err)
			}
			testCase.prepare(env)
			job := env.enqueuer.last()
			env.tasks.jobs[job.ID] = job
			_ = env.service.GenerateHandler(context.Background(), job)
			entry, found := history.last()
			if !found {
				t.Fatal("终态没有写入历史")
			}
			if entry.ReportID != view.ID {
				t.Fatalf("历史报告编号 = %s，期望 %s", entry.ReportID, view.ID)
			}
			if entry.State != testCase.wantState {
				t.Fatalf("历史状态 = %q，期望 %q", entry.State, testCase.wantState)
			}
			if testCase.wantCode != "" && entry.ErrorCode != testCase.wantCode {
				t.Fatalf("历史错误码 = %q，期望 %q", entry.ErrorCode, testCase.wantCode)
			}
			if entry.Owner.ID == "" || entry.ScopeID != ScopeSystem {
				t.Fatalf("历史缺少操作者/范围: %+v", entry)
			}
			// 排队与运行中的状态也是真实状态，但绝不能出现“未完成却成功”。
			history.mu.Lock()
			entries := append([]HistoryRecord(nil), history.entries...)
			history.mu.Unlock()
			if len(entries) < 2 {
				t.Fatalf("历史条目数 = %d，期望至少包含排队/运行/终态", len(entries))
			}
			if entries[0].State != StateQueued {
				t.Fatalf("首个历史状态 = %q，期望 queued", entries[0].State)
			}
			if testCase.name != "succeeded" {
				for _, item := range entries {
					if item.State == StateSucceeded {
						t.Fatal("失败/取消/超时路径出现了成功历史记录")
					}
				}
			}
			if testCase.name == "succeeded" && len(entry.ArtifactsJSON) == 0 ||
				testCase.name == "succeeded" && len(entry.SnapshotJSON) == 0 {
				t.Fatal("成功历史缺少快照或产物引用")
			}
		})
	}
}

// TestHistoryScheduledDenied 验证计划触发的执行前权限复验拒绝会写入
// “未生成”历史（failed + ACCESS_DENIED），且不创建报告记录、不产生成功记录。
func TestHistoryScheduledDenied(t *testing.T) {
	env, history := newHistoryEnv(t)
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	caller := testCaller(t, 1)
	env.authorizer.deny(PermissionRead, ScopeSystem)
	payload, err := json.Marshal(planPayload{
		Version: planPayloadVersion, Name: "每日安全报告",
		ScopeID: ScopeSystem, ScopeKind: "system", Granularity: "day",
		WindowDays: 1, Formats: []string{"html"}, DetailRows: 20,
		TimeZone: "Asia/Shanghai", Owner: actorRecordOf(caller.Actor()),
	})
	if err != nil {
		t.Fatalf("编码计划载荷失败: %v", err)
	}
	job := task.Job{ID: "job-denied", Kind: TaskKindPlannedReportGenerate,
		Initiator: caller.Actor(), Payload: payload}
	if err := env.service.GenerateScheduledHandler(context.Background(), job); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权计划生成错误 = %v，期望 ErrAccessDenied", err)
	}
	entry, found := history.last()
	if !found {
		t.Fatal("执行前拒绝没有写入历史")
	}
	if entry.State != StateFailed || entry.ErrorCode != string(CodeAccessDenied) {
		t.Fatalf("拒绝历史 state=%q code=%q，期望 failed/ACCESS_DENIED",
			entry.State, entry.ErrorCode)
	}
	if entry.FailureReason == "" {
		t.Fatal("拒绝历史缺少可公开原因")
	}
	env.service.mu.Lock()
	defer env.service.mu.Unlock()
	if len(env.service.records) != 0 {
		t.Fatalf("执行前拒绝却创建了 %d 条报告记录", len(env.service.records))
	}
}

// TestHistoryWriteFailureDoesNotFakeSuccess 验证历史写入失败不会伪造成功、也不会
// 改变已提交的报告真实终态。
func TestHistoryWriteFailureDoesNotFakeSuccess(t *testing.T) {
	env, history := newHistoryEnv(t)
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	history.mu.Lock()
	history.err = errors.New("history store unavailable")
	history.mu.Unlock()
	request := env.startRequest(t)
	view, err := env.service.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("历史写入失败时创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	if err := env.service.GenerateHandler(context.Background(), job); err != nil {
		t.Fatalf("历史写入失败改变了生成结果: %v", err)
	}
	final, err := env.service.Get(context.Background(), request.Caller, view.ID)
	if err != nil || final.State != StateSucceeded {
		t.Fatalf("报告真实终态 = %q err=%v，期望 succeeded", final.State, err)
	}
	if history.count() != 0 {
		t.Fatalf("历史写入失败仍产生了 %d 条条目", history.count())
	}
}
