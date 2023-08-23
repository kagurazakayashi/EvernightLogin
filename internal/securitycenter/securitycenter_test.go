package securitycenter

import (
	"context"
	"errors"
	"testing"
)

// fakeRequirement 是强认证要求来源替身（只用于测试适配器契约）。
type fakeRequirement struct {
	required bool
	err      error
}

// StrongAuthRequired 实现 StrongAuthRequirement。
func (f fakeRequirement) StrongAuthRequired(context.Context, string) (bool, error) {
	return f.required, f.err
}

// fakeTOTP 是 TOTP 存在性来源替身。
type fakeTOTP struct {
	active bool
	err    error
}

// HasActive 实现 TOTPPresence。
func (f fakeTOTP) HasActive(context.Context, string) (bool, error) { return f.active, f.err }

// fakePasskey 是 Passkey 存在性来源替身。
type fakePasskey struct {
	active bool
	err    error
}

// HasSecondFactor 实现 PasskeyPresence。
func (f fakePasskey) HasSecondFactor(context.Context, string) (bool, error) {
	return f.active, f.err
}

// TestMFAPolicyProjection 验证强制策略投影与 fail-closed 语义。
func TestMFAPolicyProjection(t *testing.T) {
	if _, err := NewMFAPolicy(nil); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("nil 来源应拒绝构造: %v", err)
	}
	var typedNil *fakeRequirement
	if _, err := NewMFAPolicy(typedNil); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("typed-nil 来源应拒绝构造: %v", err)
	}
	cases := []struct {
		name     string
		required bool
		err      error
	}{
		{name: "强制", required: true},
		{name: "未强制", required: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewMFAPolicy(fakeRequirement{required: test.required})
			if err != nil {
				t.Fatalf("构造失败: %v", err)
			}
			required, err := policy.MFARequired(context.Background(), "usr_x")
			if err != nil || required != test.required {
				t.Fatalf("MFARequired = %v, %v", required, err)
			}
		})
	}
	// 来源读取失败必须返回错误（领域服务据此拒绝移除），不能解释成“未强制”。
	failing, err := NewMFAPolicy(fakeRequirement{err: errors.New("store down")})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if required, err := failing.MFARequired(context.Background(), "usr_x"); err == nil || required {
		t.Fatalf("来源故障应返回错误而非 false: required=%v err=%v", required, err)
	}
	// 未接线（零值）也 fail-closed。
	var zeroValue MFAPolicy
	if _, err := zeroValue.MFARequired(context.Background(), "usr_x"); err == nil {
		t.Fatal("零值适配器必须 fail-closed")
	}
}

// TestTOTPOtherStrongFactorLateWiringThroughInterface 是步骤 194 审计 F1 的回归：
// 适配器以接口形式注入 Passkey 服务后再 SetTOTP，必须对**同一接口实例**可见。
// 若构造函数返回值类型/值接收者，接口会持有副本，SetTOTP 永远改不到 Passkey 看到
// 的实例（生产表现为“仍有 TOTP 却误拒删除最后一个 Passkey”）。
func TestTOTPOtherStrongFactorLateWiringThroughInterface(t *testing.T) {
	adapter := NewTOTPOtherStrongFactor(nil)
	// 按生产装配方式装箱进接口（passkey.Options.OtherStrongFactors 为接口）。
	var injected interface {
		HasOtherStrongFactor(ctx context.Context, userID string) (bool, error)
	} = adapter
	got, err := injected.HasOtherStrongFactor(context.Background(), "usr_x")
	if err != nil || got {
		t.Fatalf("接线前应为“没有其他强因素”: %v, %v", got, err)
	}
	adapter.SetTOTP(fakeTOTP{active: true})
	got, err = injected.HasOtherStrongFactor(context.Background(), "usr_x")
	if err != nil || !got {
		t.Fatalf("SetTOTP 后接口实例必须看到 TOTP: %v, %v", got, err)
	}
}

// TestOtherStrongFactorAdapters 验证“其他强因素”适配器：存在/不存在/未启用/故障。
func TestOtherStrongFactorAdapters(t *testing.T) {
	totpCases := []struct {
		name string
		totp TOTPPresence
		want bool
	}{
		{name: "无 TOTP（Passkey 关闭时）", totp: nil, want: false},
		{name: "有 TOTP", totp: fakeTOTP{active: true}, want: true},
		{name: "无活动 TOTP", totp: fakeTOTP{active: false}, want: false},
	}
	for _, test := range totpCases {
		t.Run(test.name, func(t *testing.T) {
			adapter := NewTOTPOtherStrongFactor(test.totp)
			got, err := adapter.HasOtherStrongFactor(context.Background(), "usr_x")
			if err != nil || got != test.want {
				t.Fatalf("HasOtherStrongFactor = %v, %v", got, err)
			}
		})
	}
	// 查询故障必须返回错误，领域服务按策略不可用拒绝删除。
	failing := NewTOTPOtherStrongFactor(fakeTOTP{err: errors.New("store down")})
	if _, err := failing.HasOtherStrongFactor(context.Background(), "usr_x"); err == nil {
		t.Fatal("TOTP 查询故障应返回错误")
	}
	// TOTP 方向：Passkey 未启用如实返回“没有其他强因素”。
	passkeyCases := []struct {
		name     string
		passkeys PasskeyPresence
		want     bool
	}{
		{name: "Passkey 未启用", passkeys: nil, want: false},
		{name: "有 Passkey", passkeys: fakePasskey{active: true}, want: true},
		{name: "无活动 Passkey", passkeys: fakePasskey{active: false}, want: false},
	}
	for _, test := range passkeyCases {
		t.Run(test.name, func(t *testing.T) {
			adapter := NewPasskeyOtherStrongFactor(test.passkeys)
			got, err := adapter.HasOtherStrongFactor(context.Background(), "usr_x")
			if err != nil || got != test.want {
				t.Fatalf("HasOtherStrongFactor = %v, %v", got, err)
			}
		})
	}
	passkeyFailing := NewPasskeyOtherStrongFactor(fakePasskey{err: errors.New("store down")})
	if _, err := passkeyFailing.HasOtherStrongFactor(context.Background(), "usr_x"); err == nil {
		t.Fatal("Passkey 查询故障应返回错误")
	}
}
