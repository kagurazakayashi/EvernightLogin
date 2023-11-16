package serverapp

// 步骤 230 随附修复：任务运行前权限复验映射的定向单元测试。

import (
	"context"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestTaskRunPermissionKeyMappings(t *testing.T) {
	cases := []struct {
		kind string
		want string
		ok   bool
	}{
		{auditops.TaskKindAuditExport, auditops.PermissionExport, true},
		{auditops.TaskKindAuditPurge, auditops.PermissionPurge, true},
		{backupadmin.KindBackupCreate, backupadmin.PermissionCreate, true},
		{backupadmin.KindBackupCleanup, backupadmin.PermissionCleanup, true},
		{"test.unmapped", "", false},
		{"", "", false},
	}
	for _, testCase := range cases {
		got, ok := taskRunPermissionKey(testCase.kind)
		if got != testCase.want || ok != testCase.ok {
			t.Fatalf("taskRunPermissionKey(%q) = (%q,%v)，期望 (%q,%v)",
				testCase.kind, got, ok, testCase.want, testCase.ok)
		}
	}
}

func TestCheckTaskPermissionFailClosed(t *testing.T) {
	var nilRuntime *TaskRuntime
	if err := nilRuntime.checkTaskPermission(context.Background(),
		task.PermissionRequest{}); err == nil {
		t.Fatal("nil 运行时必须拒绝运行前权限复验")
	}
	runtime := &TaskRuntime{}
	// 非法发起者。
	if err := runtime.checkTaskPermission(context.Background(),
		task.PermissionRequest{Kind: auditops.TaskKindAuditExport}); err == nil {
		t.Fatal("非法发起者必须拒绝")
	}
	// 不允许的发起者类型。
	if err := runtime.checkTaskPermission(context.Background(), task.PermissionRequest{
		Kind:  auditops.TaskKindAuditExport,
		Actor: audit.Actor{Type: audit.ActorKind("oauth_client"), ID: "client_1"}}); err == nil {
		t.Fatal("不允许的发起者类型必须拒绝")
	}
	// 受信宿主主体放行（权限复验本身不额外拒绝）。
	if err := runtime.checkTaskPermission(context.Background(), task.PermissionRequest{
		Kind:  auditops.TaskKindAuditExport,
		Actor: audit.Actor{Type: audit.ActorLocalAdmin, ID: "host-operator"}}); err != nil {
		t.Fatalf("本机受信主体应放行: %v", err)
	}
	if err := runtime.checkTaskPermission(context.Background(), task.PermissionRequest{
		Kind:  backupadmin.KindBackupCreate,
		Actor: audit.Actor{Type: audit.ActorSystem, ID: "system_worker"}}); err != nil {
		t.Fatalf("系统主体应放行: %v", err)
	}
	// 普通用户 + 未映射类型：在访问权限引擎前就 fail-closed。
	if err := runtime.checkTaskPermission(context.Background(), task.PermissionRequest{
		Kind:  "test.unmapped",
		Actor: audit.Actor{Type: audit.ActorUser, ID: "usr_000000000000000000000000000000a1"}}); err == nil {
		t.Fatal("未映射任务类型必须拒绝")
	}
}
