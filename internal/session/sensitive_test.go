package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// denyingManagementRunner 模拟敏感策略拒绝的管理访问收敛入口。
type denyingManagementRunner struct{ calls int }

func (r *denyingManagementRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	if request.OperationID != "session.management.access" {
		return reauth.Result{}, reauth.ErrInvalidRequest
	}
	return reauth.Result{}, reauth.ErrMFARequired
}

func (r *denyingManagementRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

// TestAdminRevokeRequiresSensitivePolicy 验证管理强制下线接入敏感策略：策略拒绝时
// 拒绝且不撤销目标会话；既有强认证闸门保持 fail-closed。
func TestAdminRevokeRequiresSensitivePolicy(t *testing.T) {
	env := newTestEnv(t)
	const adminID = "usr_00000000000000000000000000000071"
	const targetID = "usr_00000000000000000000000000000072"
	env.insertUser(adminID, "admin", account.StatusActive, 1)
	env.insertUser(targetID, "target", account.StatusActive, 1)
	runner := &denyingManagementRunner{}
	service := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = &stubAuthorizer{allow: map[string]bool{adminID + "|": true}}
		options.Sensitive = runner
	})
	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	env.markStrongAuth(adminSession.Session.ID)
	targetSession := env.loginWith(service, targetID, "", false, session.ClientInfo{})
	if _, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: targetSession.Session.ID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("策略拒绝后管理下线错误 = %v，期望 ErrAccessDenied", err)
	}
	if runner.calls != 1 {
		t.Errorf("敏感策略调用数 = %d，期望 1", runner.calls)
	}
	if _, err := service.Validate(env.ctx, targetSession.Secret.Reveal()); err != nil {
		t.Errorf("被拒绝后目标会话不应被撤销: %v", err)
	}
}

// TestAdminRevokeFailsClosedWithoutSensitiveRunner 验证未接线且未显式允许旧语义时
// 管理强制下线默认拒绝（既有强认证闸门通过也不放行）。
func TestAdminRevokeFailsClosedWithoutSensitiveRunner(t *testing.T) {
	env := newTestEnv(t)
	const adminID = "usr_00000000000000000000000000000073"
	const targetID = "usr_00000000000000000000000000000074"
	env.insertUser(adminID, "admin2", account.StatusActive, 1)
	env.insertUser(targetID, "target2", account.StatusActive, 1)
	service := env.newServiceWith(func(options *session.Options) {
		options.Authorizer = &stubAuthorizer{allow: map[string]bool{adminID + "|": true}}
		options.AllowLegacyWithoutSensitive = false
	})
	adminSession := env.loginWith(service, adminID, "", false, session.ClientInfo{})
	env.markStrongAuth(adminSession.Session.ID)
	targetSession := env.loginWith(service, targetID, "", false, session.ClientInfo{})
	if _, err := service.AdminRevoke(env.ctx, adminSession.Secret.Reveal(), session.AdminRevokeRequest{
		TargetSessionID: targetSession.Session.ID,
	}); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("未接线时管理下线错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := service.Validate(env.ctx, targetSession.Secret.Reveal()); err != nil {
		t.Errorf("fail-closed 后目标会话不应被撤销: %v", err)
	}
}
