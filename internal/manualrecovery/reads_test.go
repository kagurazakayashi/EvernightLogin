package manualrecovery_test

// 步骤 71 受控只读投影的回归测试：候选审批人读取待审批申请、自批/非待审批拒绝、
// 参与人读取批准与执行记录、制度摘要与内容绑定判定。

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
)

// TestPolicySummaryAndContentConsistent 验证制度摘要返回真实解析值与内容绑定判定。
func TestPolicySummaryAndContentConsistent(t *testing.T) {
	env := newTestEnv(t, nil)
	summary := env.service.PolicySummary()
	if !summary.Enabled || !summary.RequireIndependentApproval {
		t.Fatalf("制度摘要应显示已启用且要求独立审批: %+v", summary)
	}
	if summary.WaitPeriod != time.Hour || summary.ApprovalTTL != 12*time.Hour ||
		summary.RequestTTL != 24*time.Hour {
		t.Fatalf("制度摘要时间窗口不真实: %+v", summary)
	}
	if len(summary.VerificationBases) != 1 || summary.VerificationBases[0] != manualrecovery.BasisInPersonIdentityDocument {
		t.Fatalf("制度摘要核验依据异常: %+v", summary.VerificationBases)
	}
	record := env.create()
	if !manualrecovery.ContentConsistent(record) {
		t.Fatal("刚创建的申请内容摘要应一致")
	}
	record.Reason = "被篡改的原因"
	if manualrecovery.ContentConsistent(record) {
		t.Fatal("原因变化后内容摘要应判定不一致")
	}
}

// TestGetRequestForApprovalContract 验证候选审批人读取只对当前待审批申请开放，
// 且拒绝发起者/目标本人与无资格人员。
func TestGetRequestForApprovalContract(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()

	// 候选审批人可读取待审批申请（不通过、不创建批准）。
	view, err := env.service.GetRequestForApproval(env.ctx, env.caller(approver), record.ID)
	if err != nil {
		t.Fatalf("候选审批人读取待审批申请失败: %v", err)
	}
	if view.ID != record.ID || view.TargetUserID != target || view.Status != manualrecovery.StatusPendingApproval {
		t.Fatalf("读取投影异常: %+v", view)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_approvals`) != 0 {
		t.Fatal("读取不得创建批准记录")
	}

	// 发起者不能走候选审批人读取入口（自我审批语义）。
	if _, err := env.service.GetRequestForApproval(env.ctx, env.caller(initiator), record.ID); !errors.Is(err, manualrecovery.ErrSelfApproval) {
		t.Fatalf("发起者读取应返回 ErrSelfApproval，得到 %v", err)
	}
	// 无审批资格的工作人员被拒绝。
	if _, err := env.service.GetRequestForApproval(env.ctx, env.caller(executor), record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("无资格读取应返回 ErrAccessDenied，得到 %v", err)
	}
	// 非法 ID 与不存在申请被拒绝。
	if _, err := env.service.GetRequestForApproval(env.ctx, env.caller(approver), "bad-id"); !errors.Is(err, manualrecovery.ErrInvalidRequest) {
		t.Fatalf("非法 ID 应返回 ErrInvalidRequest，得到 %v", err)
	}
	missing := "mrr_00000000000000000000000000000000"
	if _, err := env.service.GetRequestForApproval(env.ctx, env.caller(approver), missing); !errors.Is(err, manualrecovery.ErrRequestNotFound) {
		t.Fatalf("不存在申请应返回 ErrRequestNotFound，得到 %v", err)
	}
	// 已批准后候选审批人不再获得读取权；原审批人仍可通过参与人通道读取。
	approval := env.approve(record.ID)
	if _, err := env.service.GetRequestForApproval(env.ctx, env.caller(executor), record.ID); !errors.Is(err, manualrecovery.ErrRequestClosed) {
		t.Fatalf("离开待审批状态应返回 ErrRequestClosed，得到 %v", err)
	}
	latest, found, err := env.service.GetApproval(env.ctx, env.caller(approver), record.ID)
	if err != nil || !found {
		t.Fatalf("审批人应可读取批准: found=%v err=%v", found, err)
	}
	if latest.ID != approval.ID || latest.Status != manualrecovery.ApprovalActive ||
		latest.ApproverUserID != approver || latest.NotBefore.Sub(latest.ApprovedAt) != time.Hour {
		t.Fatalf("批准投影异常: %+v", latest)
	}
	// 发起者可读取批准；无关人员被拒绝。
	if _, _, err := env.service.GetApproval(env.ctx, env.caller(initiator), record.ID); err != nil {
		t.Fatalf("发起者读取批准失败: %v", err)
	}
	// 真实执行人在已批准阶段可读取批准时间窗口（执行确认页需要）；无任何资格者仍拒绝。
	if _, _, err := env.service.GetApproval(env.ctx, env.caller(executor), record.ID); err != nil {
		t.Fatalf("具备执行资格者读取批准时间窗口失败: %v", err)
	}
	if _, _, err := env.service.GetApproval(env.ctx, env.caller(rootUser), record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("无关人员读取批准应被拒绝，得到 %v", err)
	}
}

// TestGetExecutionProjection 验证执行记录的参与人授权与真实结果投影。
func TestGetExecutionProjection(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	env.approve(record.ID)
	// 等待期未满时执行被拒绝，此时没有执行记录。
	if _, err := env.service.Execute(env.ctx, env.caller(executor),
		manualrecovery.ExecuteRequest{RequestID: record.ID, TraceID: "req-exec-early"}); !errors.Is(err, manualrecovery.ErrApprovalNotYetValid) {
		t.Fatalf("等待期未满应拒绝执行，得到 %v", err)
	}
	if _, found, err := env.service.GetExecution(env.ctx, env.caller(approver), record.ID); err != nil || found {
		t.Fatalf("未执行时不应有执行记录: found=%v err=%v", found, err)
	}
	// 推进到等待期之后执行成功。
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor),
		manualrecovery.ExecuteRequest{RequestID: record.ID, TraceID: "req-exec-late"}); err != nil {
		t.Fatalf("等待期后执行失败: %v", err)
	}
	execution, found, err := env.service.GetExecution(env.ctx, env.caller(initiator), record.ID)
	if err != nil || !found {
		t.Fatalf("发起者应可读取执行记录: found=%v err=%v", found, err)
	}
	if execution.Status != "succeeded" || execution.ExecutorUserID != executor ||
		execution.Operation != manualrecovery.OperationPasswordReset || execution.SessionsRevoked != 3 {
		t.Fatalf("执行记录投影异常: %+v", execution)
	}
	if _, _, err := env.service.GetExecution(env.ctx, env.caller(approver), record.ID); err != nil {
		t.Fatalf("审批人读取执行记录失败: %v", err)
	}
	if _, _, err := env.service.GetExecution(env.ctx, env.caller(highUser), record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("无关人员读取执行记录应被拒绝，得到 %v", err)
	}
}

// TestGetRequestForPageProjection 验证统一页面读取：候选审批人读取不产生误导性
// “参与人读取被拒”审计，发起者/执行人可读，无关人员被拒绝并留痕。
func TestGetRequestForPageProjection(t *testing.T) {
	env := newTestEnv(t, nil)
	record := env.create()
	deniedBefore := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='manual_recovery.denied'`)
	view, err := env.service.GetRequestForPage(env.ctx, env.caller(approver), record.ID)
	if err != nil || view.ID != record.ID {
		t.Fatalf("候选审批人页面读取失败: %v", err)
	}
	deniedAfter := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='manual_recovery.denied'`)
	if deniedAfter != deniedBefore {
		t.Fatalf("候选审批人正常读取不应写拒绝审计: before=%d after=%d", deniedBefore, deniedAfter)
	}
	if _, err := env.service.GetRequestForPage(env.ctx, env.caller(initiator), record.ID); err != nil {
		t.Fatalf("发起者页面读取失败: %v", err)
	}
	if _, err := env.service.GetRequestForPage(env.ctx, env.caller(executor), record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("未参与且无审批资格应拒绝，得到 %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='manual_recovery.denied'`) <= deniedAfter {
		t.Fatal("无关人员读取应写失败审计")
	}
	// 执行后执行人可读取页面投影。
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor),
		manualrecovery.ExecuteRequest{RequestID: record.ID, TraceID: "req-exec-page"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if _, err := env.service.GetRequestForPage(env.ctx, env.caller(executor), record.ID); err != nil {
		t.Fatalf("执行人页面读取失败: %v", err)
	}
}
