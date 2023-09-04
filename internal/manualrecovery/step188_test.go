package manualrecovery_test

// 步骤 188 领域测试：待审批/待执行列表逐条判权、Q1 三权分离、Q6 脱敏字段。

import (
	"testing"
	"time"

	. "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
)

// TestStep188ListAndThreeWaySeparation 验证待办列表与执行人分离。
func TestStep188ListAndThreeWaySeparation(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	// 发起者列表：命中自己的申请，目标脱敏且不含完整目标 ID。
	initiated, err := env.service.ListForPage(env.ctx, env.caller(initiator), ListRequest{
		Mode: ListModeInitiated, Limit: 20})
	if err != nil {
		t.Fatalf("发起者列表: %v", err)
	}
	if len(initiated.Items) != 1 || initiated.Items[0].RequestID != record.ID {
		t.Fatalf("发起者列表不符: %+v", initiated.Items)
	}
	if initiated.Items[0].TargetMasked == target || initiated.Items[0].MyRelation != "initiator" {
		t.Fatalf("列表脱敏/关系不符: %+v", initiated.Items[0])
	}
	// 候选审批人列表：逐条按当前资格放行；发起者不能以审批人身份看到自己申请。
	pending, err := env.service.ListForPage(env.ctx, env.caller(approver), ListRequest{
		Mode: ListModePendingApproval, Limit: 20})
	if err != nil {
		t.Fatalf("候选审批人列表: %v", err)
	}
	if len(pending.Items) != 1 || pending.Items[0].MyRelation != "candidate_approver" {
		t.Fatalf("待审批列表不符: %+v", pending.Items)
	}
	initiatorPending, err := env.service.ListForPage(env.ctx, env.caller(initiator), ListRequest{
		Mode: ListModePendingApproval, Limit: 20})
	if err != nil {
		t.Fatalf("发起者待审批列表: %v", err)
	}
	if len(initiatorPending.Items) != 0 {
		t.Fatalf("发起者不应在待审批列表看到自己的申请: %+v", initiatorPending.Items)
	}
	// 批准后等待期未到：执行列表为空；推进时间后可执行。
	if _, err := env.service.Approve(env.ctx, env.caller(approver), ApproveRequest{
		RequestID: record.ID, Note: "独立核验", TraceID: "trace-188-approve"}); err != nil {
		t.Fatalf("审批: %v", err)
	}
	executable, err := env.service.ListForPage(env.ctx, env.caller(executor), ListRequest{
		Mode: ListModeExecutable, Limit: 20})
	if err != nil {
		t.Fatalf("执行列表: %v", err)
	}
	if len(executable.Items) != 0 {
		t.Fatalf("等待期未到不应可执行: %+v", executable.Items)
	}
	env.now = env.now.Add(2 * time.Hour)
	executable, err = env.service.ListForPage(env.ctx, env.caller(executor), ListRequest{
		Mode: ListModeExecutable, Limit: 20})
	if err != nil {
		t.Fatalf("执行列表(已到等待期): %v", err)
	}
	if len(executable.Items) != 1 || executable.Items[0].MyRelation != "candidate_executor" {
		t.Fatalf("待执行列表不符: %+v", executable.Items)
	}

	// Q1：审批人本人执行被拒绝并留痕（即使其具备执行权限键）。
	env.staff.execute[approver] = true
	if _, err := env.service.Execute(env.ctx, env.caller(approver), ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-188-exec-approver"}); err == nil {
		t.Fatal("审批人执行应被拒绝")
	}
	if env.executor.calls != 0 {
		t.Fatalf("被拒绝时执行器不应被调用: %d", env.executor.calls)
	}
	// 发起者执行同样拒绝。
	env.staff.execute[initiator] = true
	if _, err := env.service.Execute(env.ctx, env.caller(initiator), ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-188-exec-initiator"}); err == nil {
		t.Fatal("发起者执行应被拒绝")
	}
	// 独立执行人成功一次；重复执行冲突。
	if _, err := env.service.Execute(env.ctx, env.caller(executor), ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-188-exec-ok"}); err != nil {
		t.Fatalf("独立执行人执行失败: %v", err)
	}
	if _, err := env.service.Execute(env.ctx, env.caller(executor), ExecuteRequest{
		RequestID: record.ID, TraceID: "trace-188-exec-again"}); err == nil {
		t.Fatal("重复执行应被拒绝")
	}
}
