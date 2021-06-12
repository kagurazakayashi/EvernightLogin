package authfact_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
)

var testNow = time.Now().UTC()

func fact(method authfact.Method) authfact.Fact {
	return authfact.Fact{Method: method, VerifiedAt: testNow}
}

// TestStrengthCombination 验证强度组合语义：单因素/MFA/强认证，邮件不构成强认证，
// 同一因素重复验证不增加独立因素。
func TestStrengthCombination(t *testing.T) {
	empty := authfact.MustSet()
	if empty.Strength() != authfact.StrengthNone || empty.DistinctFactors() != 0 {
		t.Fatalf("空集合强度异常: %v", empty.Strength())
	}
	password := authfact.MustSet(fact(authfact.MethodPassword))
	if password.Strength() != authfact.StrengthSingle {
		t.Fatalf("仅密码应为单因素: %v", password.Strength())
	}
	withEmail := authfact.MustSet(fact(authfact.MethodPassword), fact(authfact.MethodEmailOTP))
	if withEmail.Strength() != authfact.StrengthMFA {
		t.Fatalf("密码+邮件应为 MFA: %v", withEmail.Strength())
	}
	withTOTP := authfact.MustSet(fact(authfact.MethodPassword), fact(authfact.MethodTOTP))
	if withTOTP.Strength() != authfact.StrengthStrong {
		t.Fatalf("密码+TOTP 应为受控强认证: %v", withTOTP.Strength())
	}
	passkeyUV := authfact.MustSet(authfact.Fact{Method: authfact.MethodPasskey,
		VerifiedAt: testNow, UserVerified: true, AuthenticatorID: "ref-1"})
	if passkeyUV.Strength() != authfact.StrengthStrong {
		t.Fatalf("Passkey UV 应为强认证: %v", passkeyUV.Strength())
	}
	passkeyNoUV := authfact.MustSet(authfact.Fact{Method: authfact.MethodPasskey,
		VerifiedAt: testNow, AuthenticatorID: "ref-1"})
	if passkeyNoUV.Strength() != authfact.StrengthSingle {
		t.Fatalf("未 UV 的 Passkey 不应自行构成强认证: %v", passkeyNoUV.Strength())
	}
	// 同一因素验证两遍：独立因素仍为 1，不因重复而升级强度。
	repeated := authfact.MustSet(fact(authfact.MethodTOTP), fact(authfact.MethodTOTP))
	if repeated.DistinctFactors() != 1 || repeated.Strength() != authfact.StrengthSingle {
		t.Fatalf("同一因素重复不应增加因素数量: factors=%d strength=%v",
			repeated.DistinctFactors(), repeated.Strength())
	}
	// 同一认证器两次断言仍是一个因素。
	sameKey := authfact.MustSet(
		authfact.Fact{Method: authfact.MethodPasskey, VerifiedAt: testNow, UserVerified: true, AuthenticatorID: "ref-1"},
		authfact.Fact{Method: authfact.MethodPasskey, VerifiedAt: testNow.Add(time.Second), UserVerified: true, AuthenticatorID: "ref-1"},
	)
	if sameKey.DistinctFactors() != 1 {
		t.Fatalf("同一认证器重复断言应计 1 个因素: %d", sameKey.DistinctFactors())
	}
}

// TestSatisfies 验证策略要求与 UV/邮件降级规则。
func TestSatisfies(t *testing.T) {
	password := authfact.MustSet(fact(authfact.MethodPassword))
	passwordEmail := authfact.MustSet(fact(authfact.MethodPassword), fact(authfact.MethodEmailOTP))
	passwordTOTP := authfact.MustSet(fact(authfact.MethodPassword), fact(authfact.MethodTOTP))
	passkeyUV := authfact.MustSet(authfact.Fact{Method: authfact.MethodSecurityKey,
		VerifiedAt: testNow, UserVerified: true, AuthenticatorID: "key-1"})
	cases := []struct {
		name string
		set  authfact.Set
		req  authfact.Requirement
		want bool
	}{
		{"密码满足单因素", password, authfact.Requirement{Minimum: authfact.StrengthSingle}, true},
		{"密码不满足 MFA", password, authfact.Requirement{Minimum: authfact.StrengthMFA}, false},
		{"密码+邮件满足 MFA", passwordEmail, authfact.Requirement{Minimum: authfact.StrengthMFA}, true},
		{"密码+邮件不满足强认证", passwordEmail, authfact.Requirement{Minimum: authfact.StrengthStrong}, false},
		{"密码+TOTP 满足强认证", passwordTOTP, authfact.Requirement{Minimum: authfact.StrengthStrong}, true},
		{"安全密钥 UV 满足要求 UV 的强认证", passkeyUV,
			authfact.Requirement{Minimum: authfact.StrengthStrong, RequireUserVerification: true}, true},
		{"密码+TOTP 不满足显式 UV 要求", passwordTOTP,
			authfact.Requirement{Minimum: authfact.StrengthStrong, RequireUserVerification: true}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := test.set.Satisfies(test.req); got != test.want {
				t.Fatalf("Satisfies = %v，期望 %v", got, test.want)
			}
		})
	}
}

// TestSelectOnlyEnabledAndPolicySatisfying 验证选择器只返回实际启用且满足策略的
// 方式，且强认证不会降级到邮件。
func TestSelectOnlyEnabledAndPolicySatisfying(t *testing.T) {
	password := authfact.MustSet(fact(authfact.MethodPassword))
	available := []authfact.Available{
		{Method: authfact.MethodEmailOTP, Enabled: true},
		{Method: authfact.MethodTOTP, Enabled: false},
		{Method: authfact.MethodPasskey, Enabled: true, SupportsUserVerification: true, Reference: "cred-1"},
	}
	// 强认证：跳过未启用的 TOTP 与不合格的邮件，选到 Passkey。
	chosen, err := authfact.Select(password, available,
		authfact.Requirement{Minimum: authfact.StrengthStrong})
	if err != nil || chosen.Method != authfact.MethodPasskey {
		t.Fatalf("强认证选择结果 = %v err=%v", chosen.Method, err)
	}
	// 只有邮件可用时不满足强认证，明确报无可用方式（不降级）。
	onlyEmail := []authfact.Available{{Method: authfact.MethodEmailOTP, Enabled: true}}
	if _, err := authfact.Select(password, onlyEmail,
		authfact.Requirement{Minimum: authfact.StrengthStrong}); !errors.Is(err, authfact.ErrNoAvailableMethod) {
		t.Fatalf("只有邮件时应明确拒绝强认证: %v", err)
	}
	// 未启用方式不能被选中。
	if _, err := authfact.Select(password, []authfact.Available{
		{Method: authfact.MethodPasskey, Enabled: false, SupportsUserVerification: true},
	}, authfact.Requirement{Minimum: authfact.StrengthStrong}); !errors.Is(err, authfact.ErrNoAvailableMethod) {
		t.Fatalf("未启用方式不应被选中: %v", err)
	}
	// 要求 UV 时不能选未提供 UV 的 Passkey。
	if _, err := authfact.Select(password, []authfact.Available{
		{Method: authfact.MethodPasskey, Enabled: true, SupportsUserVerification: false},
	}, authfact.Requirement{Minimum: authfact.StrengthStrong, RequireUserVerification: true}); !errors.Is(err, authfact.ErrNoAvailableMethod) {
		t.Fatalf("要求 UV 时未提供 UV 的方式应拒绝: %v", err)
	}
	// 恢复代码标识未实现，选择器不假装可用。
	if _, err := authfact.Select(authfact.MustSet(), []authfact.Available{
		{Method: authfact.MethodRecoveryCode, Enabled: true},
	}, authfact.Requirement{Minimum: authfact.StrengthSingle}); !errors.Is(err, authfact.ErrNoAvailableMethod) {
		t.Fatalf("恢复代码不应被选择器当作可用: %v", err)
	}
}

// TestAMRAndACRMapping 验证 amr/acr 映射与非法方法解析。
func TestAMRAndACRMapping(t *testing.T) {
	passwordTOTP := authfact.MustSet(fact(authfact.MethodPassword), fact(authfact.MethodTOTP))
	amr := authfact.AMR(passwordTOTP)
	joined := ""
	for _, value := range amr {
		joined += value + ","
	}
	for _, want := range []string{"pwd,", "otp,", "totp,", "mfa,"} {
		if !contains(joined, want) {
			t.Errorf("AMR 缺少 %q: %v", want, amr)
		}
	}
	if authfact.ACR(passwordTOTP) != "urn:evernight:acr:strong" {
		t.Errorf("ACR 映射错误: %q", authfact.ACR(passwordTOTP))
	}
	passkeyUV := authfact.MustSet(authfact.Fact{Method: authfact.MethodPasskey,
		VerifiedAt: testNow, UserVerified: true, AuthenticatorID: "cred-1"})
	passkeyAMR := authfact.AMR(passkeyUV)
	if !contains(joinValues(passkeyAMR), "swk,") || !contains(joinValues(passkeyAMR), "user,") {
		t.Errorf("Passkey AMR 应包含 swk/user: %v", passkeyAMR)
	}
	if _, err := authfact.ParseMethod("bogus"); !errors.Is(err, authfact.ErrUnsupportedMethod) {
		t.Errorf("未知方法应拒绝: %v", err)
	}
	if _, err := authfact.NewSet(authfact.Fact{Method: authfact.MethodPassword}); !errors.Is(err, authfact.ErrInvalidFact) {
		t.Errorf("缺少完成时间的事实应拒绝: %v", err)
	}
}

func contains(values, want string) bool {
	for i := 0; i+len(want) <= len(values); i++ {
		if values[i:i+len(want)] == want {
			return true
		}
	}
	return false
}

func joinValues(values []string) string {
	result := ""
	for _, value := range values {
		result += value + ","
	}
	return result
}

// TestEligibleFiltersByPolicy 验证列表选择器只返回启用且不降级的方式。
func TestEligibleFiltersByPolicy(t *testing.T) {
	password := authfact.MustSet(fact(authfact.MethodPassword))
	available := []authfact.Available{
		{Method: authfact.MethodSecurityKey, Enabled: true, SupportsUserVerification: true},
		{Method: authfact.MethodTOTP, Enabled: true},
		{Method: authfact.MethodEmailOTP, Enabled: true},
		{Method: authfact.MethodPasskey, Enabled: false, SupportsUserVerification: true},
	}
	strong := authfact.Eligible(password, available, authfact.Requirement{Minimum: authfact.StrengthStrong})
	if len(strong) != 2 || strong[0].Method != authfact.MethodSecurityKey || strong[1].Method != authfact.MethodTOTP {
		t.Fatalf("强认证要求下可用方式应只有安全密钥与 TOTP: %+v", strong)
	}
	all := authfact.Eligible(password, available, authfact.Requirement{Minimum: authfact.StrengthMFA})
	if len(all) != 3 {
		t.Fatalf("MFA 要求下应包含三个启用方式: %+v", all)
	}
}
