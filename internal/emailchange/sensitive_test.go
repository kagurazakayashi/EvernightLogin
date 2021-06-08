package emailchange_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// strictRunner 模拟已接线的敏感操作收敛入口：按设置拒绝或放行并记录调用。
type strictRunner struct {
	authorizeCalls int
	notifyCalls    int
	denyErr        error
	lastRequest    reauth.Request
}

func (r *strictRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.authorizeCalls++
	r.lastRequest = request
	if r.denyErr != nil {
		return reauth.Result{}, r.denyErr
	}
	return reauth.Result{
		OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID,
		Decision: policy.Decision{Sensitive: true, NotificationRequired: true},
	}, nil
}

func (r *strictRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	r.notifyCalls++
	return nil
}

// TestRequestChangeSensitivePolicy 验证邮箱变更申请接入敏感策略：拒绝时 fail-closed
// 且不产生申请，通过时继续既有流程并产生成功告知。
func TestRequestChangeSensitivePolicy(t *testing.T) {
	const userID = "usr_00000000000000000000000000000001"
	runner := &strictRunner{denyErr: reauth.ErrReauthRequired}
	env := newTestEnv(t, true, func(options *emailchange.Options) { options.Sensitive = runner })
	env.seedUser(t, userID, "alice")

	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new@example.test", "req-denied"); !errors.Is(err, emailchange.ErrReauthRequired) {
		t.Fatalf("敏感策略拒绝时申请错误 = %v，期望 ErrReauthRequired", err)
	}
	if runner.authorizeCalls != 1 {
		t.Errorf("执行前判定调用数 = %d，期望 1", runner.authorizeCalls)
	}
	if runner.lastRequest.OperationID != "email.change.request" ||
		runner.lastRequest.TargetID != userID {
		t.Errorf("绑定操作/目标异常: %+v", runner.lastRequest)
	}
	if runner.lastRequest.Params["new_email"] == "" || runner.lastRequest.Params["request_id"] != "req-denied" {
		t.Errorf("批准参数摘要缺少新邮箱/请求绑定: %+v", runner.lastRequest.Params)
	}
	var requests int
	if err := env.storage.DB().QueryRowContext(env.ctx, `SELECT COUNT(*) FROM email_change_requests`).Scan(&requests); err != nil {
		t.Fatalf("计数: %v", err)
	}
	if requests != 0 {
		t.Errorf("被拒绝后申请数 = %d，期望 0", requests)
	}

	runner.denyErr = nil
	result, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "ok@example.test", "req-allowed")
	if err != nil {
		t.Fatalf("策略通过后的申请: %v", err)
	}
	if !result.VerificationSent {
		t.Errorf("策略通过后应继续发送验证邮件: %+v", result)
	}
	if runner.notifyCalls != 1 {
		t.Errorf("成功告知调用数 = %d，期望 1", runner.notifyCalls)
	}
}

// TestRequestChangeFailsClosedWithoutSensitiveRunner 验证未注入敏感策略且未显式
// 允许旧语义时，敏感邮箱变更默认拒绝（fail-closed）。
func TestRequestChangeFailsClosedWithoutSensitiveRunner(t *testing.T) {
	const userID = "usr_00000000000000000000000000000002"
	env := newTestEnv(t, true, func(options *emailchange.Options) {
		options.AllowLegacyWithoutSensitive = false
	})
	env.seedUser(t, userID, "bob")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "deny@example.test", "req-failclosed"); !errors.Is(err, emailchange.ErrAccessDenied) {
		t.Fatalf("未接线敏感策略时申请错误 = %v，期望 ErrAccessDenied", err)
	}
	var requests int
	if err := env.storage.DB().QueryRowContext(env.ctx, `SELECT COUNT(*) FROM email_change_requests`).Scan(&requests); err != nil {
		t.Fatalf("计数: %v", err)
	}
	if requests != 0 {
		t.Errorf("fail-closed 后申请数 = %d，期望 0", requests)
	}
}
