package mfa_test

// 步骤 288 本地维护邮件第二因素列举/删除定向测试。
//
// 覆盖：启用邮件因素后本地维护可列举与删除（无本人验证码/再次认证）、删除后
// 因素不再存在、重复删除 ErrFactorNotFound、非法目标/空身份拒绝。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
)

// TestLocalMaintenanceEmailFactor 覆盖本地维护邮件因素列举与删除。
func TestLocalMaintenanceEmailFactor(t *testing.T) {
	env := newTestEnv(t, nil)
	env.enableEmailFactor()
	localCaller, err := mfa.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	factors, err := env.service.LocalMaintenanceFactors(env.ctx, localCaller, userID)
	if err != nil {
		t.Fatalf("列举因素: %v", err)
	}
	foundEmail := false
	for _, factor := range factors {
		if factor.Type == mfa.FactorEmail {
			foundEmail = true
		}
	}
	if !foundEmail {
		t.Fatalf("应列出邮件因素: %+v", factors)
	}
	if err := env.service.LocalMaintenanceRemoveEmailFactor(env.ctx, localCaller,
		userID, "req-local-mfa-remove"); err != nil {
		t.Fatalf("本地下线邮件因素: %v", err)
	}
	factors, err = env.service.LocalMaintenanceFactors(env.ctx, localCaller, userID)
	if err != nil {
		t.Fatalf("删除后列举: %v", err)
	}
	for _, factor := range factors {
		if factor.Type == mfa.FactorEmail {
			t.Fatalf("邮件因素应已删除: %+v", factors)
		}
	}
	if err := env.service.LocalMaintenanceRemoveEmailFactor(env.ctx, localCaller,
		userID, "req-local-mfa-remove-again"); !errors.Is(err, mfa.ErrFactorNotFound) {
		t.Fatalf("重复删除错误 = %v，期望 ErrFactorNotFound", err)
	}
	if _, err := env.service.LocalMaintenanceFactors(env.ctx, localCaller,
		"bad-id"); !errors.Is(err, mfa.ErrInvalidRequest) {
		t.Fatalf("非法目标错误 = %v，期望 ErrInvalidRequest", err)
	}
	if err := env.service.LocalMaintenanceRemoveEmailFactor(env.ctx,
		mfa.LocalMaintenanceCaller{}, userID, "req-x"); !errors.Is(err, mfa.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
}
