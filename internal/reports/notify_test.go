package reports

// 本文件验证报告结果通知契约：完成/失败/取消各通知一次、只包含受认证页面入口、
// 通知失败不改变真实报告状态（通知是附属结果，不是生成状态的一部分）。

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// fakeNotifier 是报告结果通知替身：记录通知事件并可模拟发送失败。
type fakeNotifier struct {
	mu      sync.Mutex
	events  []ReportNotification
	failAll bool
}

// NotifyReport 实现 Notifier。
func (f *fakeNotifier) NotifyReport(_ context.Context,
	notification ReportNotification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, notification)
	if f.failAll {
		return errors.New("邮件后端不可用")
	}
	return nil
}

// snapshot 返回已记录的通知副本。
func (f *fakeNotifier) snapshot() []ReportNotification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ReportNotification(nil), f.events...)
}

// newNotifierEnv 构造带通知替身的报告环境。
func newNotifierEnv(t *testing.T) (*testEnv, *fakeNotifier) {
	t.Helper()
	env := newTestEnv(t)
	notifier := &fakeNotifier{}
	service, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller, Tasks: env.tasks,
		OutputDir: env.outputDir, MaxDetailRows: 50, Now: env.now,
		Notifier: notifier})
	if err != nil {
		t.Fatalf("构造带通知的报告服务失败: %v", err)
	}
	env.service = service
	return env, notifier
}

// TestNotificationResultIsolation 验证通知成功/失败都不污染报告生成状态，且通知
// 只包含受认证入口（不含下载令牌或公开链接）。
func TestNotificationResultIsolation(t *testing.T) {
	ctx := context.Background()
	env, notifier := newNotifierEnv(t)
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, view := env.startAndGenerate(t, env.startRequest(t))
	if view.State != StateSucceeded {
		t.Fatalf("报告状态 = %q，期望 succeeded", view.State)
	}
	events := notifier.snapshot()
	if len(events) != 1 {
		t.Fatalf("成功通知数量 = %d，期望 1", len(events))
	}
	event := events[0]
	if event.Kind != NotificationFinished || event.ReportID != reportID ||
		event.State != StateSucceeded || event.AuthenticatedEntry != "admin.report_download" {
		t.Fatalf("成功通知内容不正确: %+v", event)
	}
	if event.Owner != env.service.records[reportID].RequestedBy {
		t.Fatalf("通知所有者不正确: %+v", event.Owner)
	}
	// 通知发送失败不得改变报告真实终态或历史状态。
	env2, failing := newNotifierEnv(t)
	env2.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	failing.failAll = true
	reportID2, view2 := env2.startAndGenerate(t, env2.startRequest(t))
	if view2.State != StateSucceeded {
		t.Fatalf("通知失败后报告状态 = %q，期望 succeeded", view2.State)
	}
	queried, err := env2.service.Get(ctx, testCaller(t, 1), reportID2)
	if err != nil || queried.State != StateSucceeded {
		t.Fatalf("通知失败后查询 = %+v err=%v", queried, err)
	}
	if len(failing.snapshot()) != 1 {
		t.Fatalf("失败通知尝试未记录")
	}
	// 生成失败时通知 failed（不是成功）。
	env3, notifyFail := newNotifierEnv(t)
	env3.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	env3.source.err = errors.New("source unavailable")
	created3, err := env3.service.Start(ctx, env3.startRequest(t))
	if err != nil {
		t.Fatalf("创建失败用例报告失败: %v", err)
	}
	job3 := env3.enqueuer.last()
	env3.tasks.jobs[job3.ID] = job3
	if genErr := env3.service.GenerateHandler(ctx, job3); genErr == nil {
		t.Fatal("来源不可用时生成应失败")
	}
	failedView, err := env3.service.Get(ctx, testCaller(t, 1), created3.ID)
	if err != nil || failedView.State != StateFailed {
		t.Fatalf("生成失败状态 = %q err=%v，期望 failed", failedView.State, err)
	}
	failEvents := notifyFail.snapshot()
	if len(failEvents) != 1 || failEvents[0].Kind != NotificationFailed ||
		failEvents[0].ErrorCode != string(CodeReportGeneration) {
		t.Fatalf("失败通知 = %+v，期望 failed/REPORT_GENERATION_FAILED", failEvents)
	}
	// 取消通知走取消路径，不并发推送成功。
	env4, cancelNotifier := newNotifierEnv(t)
	env4.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	created, err := env4.service.Start(ctx, env4.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	if _, err := env4.service.Cancel(ctx, testCaller(t, 1), created.ID,
		"不再需要", "req-cancel-notify"); err != nil {
		t.Fatalf("取消报告失败: %v", err)
	}
	cancelEvents := cancelNotifier.snapshot()
	if len(cancelEvents) != 1 || cancelEvents[0].Kind != NotificationCancelled {
		t.Fatalf("取消通知 = %+v，期望 cancelled", cancelEvents)
	}
}
