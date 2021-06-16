package support_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// TestTransitionToSentRejected 验证 46 遗留修复：人工状态迁移不得伪造 sent
// （sent 只能由 SendReset 在真实投递成功后内部写入）。
func TestTransitionToSentRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	view := env.createCase(t, staffOne, targetA, "求助")
	if _, err := env.svc.TransitionCase(env.ctx, env.caller(t, staffOne), support.TransitionRequest{
		CaseID: view.ID, ToStatus: support.StatusSent, RequestID: "req-manual-sent"}); !errors.Is(err, support.ErrInvalidRequest) {
		t.Fatalf("人工迁移到 sent 应拒绝，得到 %v", err)
	}
	updated, err := env.svc.GetCase(env.ctx, env.caller(t, staffOne), view.ID)
	if err != nil || updated.Status != support.StatusPendingVerification {
		t.Fatalf("拒绝后状态异常: %v %+v", err, updated)
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='support.case.denied' AND reason_code='manual_sent_forbidden'`) != 1 {
		t.Fatal("人工 sent 拒绝缺少失败审计")
	}
	// 真实发送路径仍可写入 sent。
	result, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: view.ID, RequestID: "req-real-send"})
	if err != nil || !result.Sent || result.Status != support.StatusSent {
		t.Fatalf("真实发送失败: %v %+v", err, result)
	}
}

// TestSendResetStaffRateLimited 验证客服账户维度限流：超过窗口内次数返回
// RATE_LIMITED、状态不变、写失败审计。
func TestSendResetStaffRateLimited(t *testing.T) {
	env := newTestEnv(t, func(options *support.Options) {
		options.SendRate = support.SendRatePolicy{
			StaffLimit: 2, StaffWindow: 10 * time.Minute,
			GlobalLimit: 100, GlobalWindow: time.Hour,
		}
	})
	view := env.createCase(t, staffOne, targetA, "求助")
	for index := 0; index < 2; index++ {
		if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
			CaseID: view.ID, RequestID: "req-send-ok"}); err != nil {
			t.Fatalf("第 %d 次发送应成功: %v", index+1, err)
		}
	}
	before := env.sender.calls
	if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: view.ID, RequestID: "req-send-limit"}); !errors.Is(err, support.ErrRateLimited) {
		t.Fatalf("超过单客服限流应拒绝，得到 %v", err)
	}
	if env.sender.calls != before {
		t.Fatal("限流拒绝不应触发找回发送")
	}
	if !strings.Contains(env.auditDump(), "send_rate_limited_staff") {
		t.Fatal("单客服限流拒绝缺少失败审计")
	}
}

// TestSendResetGlobalBudget 验证全局发起预算：跨客服累计超过预算时拒绝。
func TestSendResetGlobalBudget(t *testing.T) {
	env := newTestEnv(t, func(options *support.Options) {
		options.SendRate = support.SendRatePolicy{
			StaffLimit: 10, StaffWindow: 10 * time.Minute,
			GlobalLimit: 2, GlobalWindow: time.Hour,
		}
	})
	env.grantStaff(staffTwo, targetA)
	viewA := env.createCase(t, staffOne, targetA, "求助A")
	viewB := env.createCase(t, staffTwo, targetA, "求助B")
	if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: viewA.ID, RequestID: "req-global-1"}); err != nil {
		t.Fatalf("第一次全局发送: %v", err)
	}
	if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffTwo), support.SendRequest{
		CaseID: viewB.ID, RequestID: "req-global-2"}); err != nil {
		t.Fatalf("第二次全局发送: %v", err)
	}
	if _, err := env.svc.SendReset(env.ctx, env.caller(t, staffOne), support.SendRequest{
		CaseID: viewA.ID, RequestID: "req-global-3"}); !errors.Is(err, support.ErrRateLimited) {
		t.Fatalf("超过全局预算应拒绝，得到 %v", err)
	}
	if !strings.Contains(env.auditDump(), "send_rate_limited_global") {
		t.Fatal("全局限流拒绝缺少失败审计")
	}
}

// auditDump 拼接审计动作/原因码供断言。
func (e *testEnv) auditDump() string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx,
		`SELECT action||'|'||COALESCE(reason_code,'') FROM audit_events`)
	if err != nil {
		e.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			e.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(line + "\n")
	}
	return builder.String()
}
