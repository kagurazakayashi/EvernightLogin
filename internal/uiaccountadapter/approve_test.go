package uiaccountadapter

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// fakeChallenger 是 reauth 挑战的测试替身：可控制 Required 与验证结果。
type fakeChallenger struct {
	required    bool
	verifyCalls int
	verifyErr   error
}

func (f *fakeChallenger) BeginChallenge(context.Context, reauth.Caller,
	reauth.ChallengeRequest) (reauth.Challenge, error) {
	return reauth.Challenge{ID: "chl_test", Required: f.required,
		RequiredStrength: "password"}, nil
}

func (f *fakeChallenger) VerifyChallenge(_ context.Context, _ reauth.Caller,
	_ reauth.VerifyChallengeRequest) (reauth.ApprovalGrant, error) {
	f.verifyCalls++
	if f.verifyErr != nil {
		return reauth.ApprovalGrant{}, f.verifyErr
	}
	return reauth.ApprovalGrant{Token: "approval-token"}, nil
}

func (f *fakeChallenger) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

func TestApproveSynthesizesSignalsOnlyAfterVerification(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC) }
	adapter := &Adapter{opts: Options{Reauth: &fakeChallenger{required: true}, Now: now}}
	ctx, result, err := adapter.approve(context.Background(), "usr_test", "profile.username.change",
		map[string]string{"new_username": "alice2"}, "current-password", "req", "修改用户名")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	signals := reauth.SignalsFromContext(ctx)
	if signals.ApprovalToken == "" || signals.VerifiedAt.IsZero() ||
		!signals.Complete || !signals.Confirmed {
		t.Fatalf("验证成功后应有可信批准信号: %+v", signals)
	}
	if result.OperationID != "profile.username.change" {
		t.Fatalf("结果操作标识异常: %+v", result)
	}
	// 下游校验器（同一信任链）接受该信号。
	if err := (ProfileSignalReauthVerifier{Now: now}).VerifyReauth(ctx,
		profile.Caller{}, "usr_test"); err != nil {
		t.Fatalf("验证后信号应满足 profile 校验: %v", err)
	}
}

func TestApproveDoesNotFakeSignalsWhenNotRequired(t *testing.T) {
	fake := &fakeChallenger{required: false}
	now := func() time.Time { return time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC) }
	adapter := &Adapter{opts: Options{Reauth: fake, Now: now}}
	ctx, _, err := adapter.approve(context.Background(), "usr_test", "email.change.verify",
		map[string]string{"request_id": "req"}, "current-password", "req", "确认邮箱变更")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if fake.verifyCalls != 0 {
		t.Fatal("未要求再认证时不应调用密码验证")
	}
	if signals := reauth.SignalsFromContext(ctx); signals != (reauth.Signals{}) {
		t.Fatalf("未要求再认证时不得伪造可信信号: %+v", signals)
	}
	// 下游 profile 校验器在缺少信号时 fail-closed（要求宿主配置放宽时显式关闭）。
	if err := (ProfileSignalReauthVerifier{Now: now}).VerifyReauth(ctx,
		profile.Caller{}, "usr_test"); err == nil {
		t.Fatal("缺少信号时 profile 校验应 fail-closed")
	}
}
