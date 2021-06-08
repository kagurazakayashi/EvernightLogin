package profile_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

// TestChangeUsernameFailsClosedWithoutSensitiveRunner 验证未注入敏感策略且未显式
// 允许旧语义时，受控更名默认拒绝（fail-closed）。
func TestChangeUsernameFailsClosedWithoutSensitiveRunner(t *testing.T) {
	const userID = "usr_00000000000000000000000000000051"
	env := newTestEnv(t, func(options *profile.Options) {
		options.ReauthVerifier = profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil })
		options.AllowLegacyWithoutSensitive = false
	})
	env.seedUser(t, userID, "target")
	caller := env.userCaller(t, userID)
	if _, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "renamed", ExpectedRowVersion: 1, RequestID: "req-closed"}); !errors.Is(err, profile.ErrRenameReauthRequired) {
		t.Fatalf("未接线敏感策略时更名错误 = %v，期望 ErrRenameReauthRequired", err)
	}
	updated, err := env.service.GetProfile(env.ctx, caller, userID)
	if err != nil || updated.Username != "target" {
		t.Fatalf("fail-closed 后用户名应保持 target: %+v err=%v", updated, err)
	}
}
