package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// authnAllowRunner 记录调用并允许执行。
type authnAllowRunner struct {
	calls       int
	notifyCalls int
	operationID string
}

func (r *authnAllowRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	r.operationID = request.OperationID
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID}, nil
}

func (r *authnAllowRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	r.notifyCalls++
	return nil
}

// TestSetPasswordFailsClosedWithoutSensitiveRunner 验证未接线敏感策略时设置密码拒绝。
func TestSetPasswordFailsClosedWithoutSensitiveRunner(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("closed", account.StatusActive, false)
	service := env.newService(func(options *authn.Options) { options.AllowLegacyWithoutSensitive = false })
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: "StrongPass!2026", RequestID: "req-closed"}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("未接线时设置密码错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestSetPasswordSensitivePolicyAndNotify 验证设置密码接入敏感策略并成功告知。
func TestSetPasswordSensitivePolicyAndNotify(t *testing.T) {
	env := newTestEnv(t)
	runner := &authnAllowRunner{}
	userID := env.insertUser("wired", account.StatusActive, false)
	service := env.newService(func(options *authn.Options) { options.Sensitive = runner })
	result, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: "StrongPass!2027", RequestID: "req-wired"})
	if err != nil {
		t.Fatalf("接线后设置密码: %v", err)
	}
	if result.SecurityVersion < 1 || runner.calls != 1 || runner.notifyCalls != 1 {
		t.Errorf("结果/判定/告知 = %+v calls=%d notify=%d", result, runner.calls, runner.notifyCalls)
	}
	if runner.operationID != "password.admin_reset" {
		t.Errorf("系统通道设置密码操作 ID = %q，期望 password.admin_reset", runner.operationID)
	}
}
