package lifecycle_test

import (
	"context"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/lifecycle"
)

func TestLifecycleContracts(t *testing.T) {
	if lifecycle.StateNew.String() != "new" || !lifecycle.LifecycleStarted.Valid() {
		t.Fatal("生命周期常量异常")
	}
	if lifecycle.LifecycleEventKind("bogus").Valid() {
		t.Fatal("未知事件分类应无效")
	}
	var database lifecycle.Database = lifecycle.DatabaseFunc(nil)
	if err := database.Ping(context.Background()); err == nil {
		t.Fatal("nil DatabaseFunc 应返回错误")
	}
	var notifier lifecycle.Notifier = lifecycle.NotifierFunc(nil)
	if err := notifier.Notify(context.Background(), lifecycle.LifecycleEvent{}); err == nil {
		t.Fatal("nil NotifierFunc 应返回错误")
	}
	var _ lifecycle.Runner = runnerStub{}
	var _ lifecycle.Factory = func(lifecycle.Options) (lifecycle.Runner, error) { return runnerStub{}, nil }
}

type runnerStub struct{}

func (runnerStub) Start(context.Context) error { return nil }
func (runnerStub) Close(context.Context) error { return nil }
