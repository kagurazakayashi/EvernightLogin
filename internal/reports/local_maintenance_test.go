package reports

// 步骤 291 本地维护报告生成窄方法定向测试（替身依赖：任务入队成功路径；
// 未启用任务运行时的明确不可用由生产装配冒烟覆盖）。

import (
	"context"
	"errors"
	"testing"
)

func TestLocalMaintenanceStartReport(t *testing.T) {
	env := newTestEnv(t)
	caller, err := NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	request := env.startRequest(t)
	view, err := env.service.LocalMaintenanceStart(context.Background(), caller, request)
	if err != nil {
		t.Fatalf("本地维护生成报告: %v", err)
	}
	if view.ID == "" || view.TaskID == "" || len(view.Formats) == 0 {
		t.Fatalf("报告视图异常: %+v", view)
	}
	bad := request
	bad.ScopeID = "bad-scope"
	if _, err := env.service.LocalMaintenanceStart(context.Background(), caller, bad); err == nil {
		t.Fatal("非法作用范围必须拒绝")
	}
	if _, err := env.service.LocalMaintenanceStart(context.Background(),
		LocalMaintenanceCaller{}, request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := NewLocalMaintenanceCaller(""); err == nil {
		t.Fatal("空操作者标识应构造失败")
	}
}
