package policy_test

// 步骤 72 只读访问器测试：Operation/AvailableStrengths/ValidatePolicy 供管理页面
// 读取目录定义、能力集合与联动校验，不改变任何策略或授权语义。

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

func TestServiceOperationAndAvailableStrengths(t *testing.T) {
	env := newTestEnv(t, nil)
	operation, ok := env.service.Operation(policy.OperationPolicyChange)
	if !ok {
		t.Fatal("缺少 security.policy.change 目录定义")
	}
	if !operation.RootOnly || !operation.ImmutableSensitive || !operation.Implemented {
		t.Fatalf("自身保护定义 = %+v", operation)
	}
	if _, found := env.service.Operation("not.registered.operation"); found {
		t.Fatal("未登记操作不应返回定义")
	}
	strengths := env.service.AvailableStrengths()
	if len(strengths) != 2 || strengths[0] != policy.StrengthNone ||
		strengths[1] != policy.StrengthPassword {
		t.Fatalf("可用强度 = %v", strengths)
	}
}

func TestValidatePolicyCombinations(t *testing.T) {
	valid := policy.Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: policy.StrengthPassword, ConfirmationRequired: true,
		NotificationRequired: true}
	if err := policy.ValidatePolicy(valid); err != nil {
		t.Fatalf("合法策略被拒绝: %v", err)
	}
	invalid := valid
	invalid.MaxAuthAgeSeconds = 10
	if err := policy.ValidatePolicy(invalid); err == nil {
		t.Fatal("低于最小新鲜度应拒绝")
	}
	nonSensitive := policy.Policy{Sensitive: false, ReauthRequired: true, MaxAuthAgeSeconds: 300,
		Strength: policy.StrengthPassword}
	if err := policy.ValidatePolicy(nonSensitive); err == nil {
		t.Fatal("非敏感操作仍要求额外验证应拒绝")
	}
}
