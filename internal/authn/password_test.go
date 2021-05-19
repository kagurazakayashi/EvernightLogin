package authn

import (
	"errors"
	"strings"
	"testing"
)

// testParams 是测试用低成本 Argon2id 参数（等于工具下限），避免单元测试耗时。
func testParams() Params {
	return Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// TestParamsValidate 验证 Argon2id 参数的上下界：默认值合法，低于下限、超过
// 上限、违反库硬性要求或盐/摘要长度越界都拒绝。
func TestParamsValidate(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatalf("默认参数应合法: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Params)
	}{
		{"内存低于下限", func(p *Params) { p.MemoryKiB = MinMemoryKiB - 1 }},
		{"内存超过上限", func(p *Params) { p.MemoryKiB = MaxMemoryKiB + 1 }},
		{"迭代为零", func(p *Params) { p.Iterations = 0 }},
		{"迭代超过上限", func(p *Params) { p.Iterations = MaxIterations + 1 }},
		{"并行度为零", func(p *Params) { p.Parallelism = 0 }},
		{"并行度超过上限", func(p *Params) { p.Parallelism = MaxParallelism + 1 }},
		{"内存低于并行度硬性要求", func(p *Params) { p.MemoryKiB = 8; p.Parallelism = 2 }},
		{"盐过短", func(p *Params) { p.SaltLength = MinSaltBytes - 1 }},
		{"盐过长", func(p *Params) { p.SaltLength = MaxSaltBytes + 1 }},
		{"摘要过短", func(p *Params) { p.KeyLength = MinKeyBytes - 1 }},
		{"摘要过长", func(p *Params) { p.KeyLength = MaxKeyBytes + 1 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			params := testParams()
			test.mutate(&params)
			if err := params.Validate(); !errors.Is(err, ErrOptionsInvalid) {
				t.Fatalf("参数 = %+v 错误 = %v，期望 ErrOptionsInvalid", params, err)
			}
		})
	}
}

// TestHashAndVerifyPassword 验证 PHC 编码往返、错误密码不放行、每次盐不同、
// 参数摘要不含秘密，以及升级判断。
func TestHashAndVerifyPassword(t *testing.T) {
	params := testParams()
	const password = "Correct-Horse-9-Battery"
	encoded, err := HashPassword(password, params, nil)
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("PHC 编码格式不符合预期: %q", encoded)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("PHC 编码包含明文密码")
	}
	second, err := HashPassword(password, params, nil)
	if err != nil {
		t.Fatalf("HashPassword 第二次失败: %v", err)
	}
	if encoded == second {
		t.Fatal("两次哈希相同：盐没有随机化")
	}
	verified, err := VerifyPassword(encoded, password)
	if err != nil {
		t.Fatalf("VerifyPassword 失败: %v", err)
	}
	if !verified.Matched {
		t.Fatal("正确密码未通过验证")
	}
	if verified.Params != params {
		t.Fatalf("解析参数 = %+v，期望 %+v", verified.Params, params)
	}
	rejected, err := VerifyPassword(encoded, "Correct-Horse-9-Battery!")
	if err != nil {
		t.Fatalf("VerifyPassword 错误密码返回错误: %v", err)
	}
	if rejected.Matched {
		t.Fatal("错误密码被接受")
	}
	if !params.WeakerThan(DefaultParams()) {
		t.Fatal("低成本参数应被判定为需要升级")
	}
	if DefaultParams().WeakerThan(params) {
		t.Fatal("高成本参数不应被判定为需要升级")
	}
}

// TestHashPasswordRejectsOversizeAndBadParams 验证超大输入与非法参数被拒绝。
func TestHashPasswordRejectsOversizeAndBadParams(t *testing.T) {
	oversize := strings.Repeat("a", MaxPasswordBytes+1)
	if _, err := HashPassword(oversize, testParams(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超大输入错误 = %v，期望 ErrInvalidRequest", err)
	}
	bad := testParams()
	bad.Iterations = 0
	if _, err := HashPassword("Some-Long-Password-1", bad, nil); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("非法参数错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestVerifyPasswordRejectsMalformedHash 验证畸形/越界哈希一律拒绝，绝不放行。
func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"plaintext-password",
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=16$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=999999999,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=8192,t=999,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=8192,t=1,p=0$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=8192,t=1,p=1$%%%$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$",
	}
	for _, encoded := range cases {
		if _, err := VerifyPassword(encoded, "Correct-Horse-9-Battery"); !errors.Is(err, ErrPasswordHashInvalid) {
			t.Errorf("VerifyPassword(%q) 错误 = %v，期望 ErrPasswordHashInvalid", encoded, err)
		}
	}
}

// TestPasswordPolicy 验证长度、弱密码、标识包含与输入边界规则。
func TestPasswordPolicy(t *testing.T) {
	policy := DefaultPasswordPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("默认策略应合法: %v", err)
	}
	if err := policy.Check("Correct-Horse-9-Battery", []string{"alice", "Alice"}); err != nil {
		t.Fatalf("强密码被拒绝: %v", err)
	}
	weak := []struct {
		name     string
		password string
		tokens   []string
		want     error
	}{
		{"过短", "Short1!", nil, ErrWeakPassword},
		{"空密码", "", nil, ErrWeakPassword},
		{"全空白", "            ", nil, ErrWeakPassword},
		{"常见弱密码", "password123", nil, ErrWeakPassword},
		{"中文常见弱密码", "密码123456", nil, ErrWeakPassword},
		{"单一字符重复", "aaaaaaaaaaaa", nil, ErrWeakPassword},
		{"连续数字", "012345678901", nil, ErrWeakPassword},
		{"键盘序列", "zxcvbnmzxcvbnm", nil, ErrWeakPassword},
		{"包含用户名", "alice-Correct-Horse-9", []string{"alice"}, ErrWeakPassword},
		{"包含昵称", "MyNickname-Horse-9", []string{"MyNickname"}, ErrWeakPassword},
	}
	for _, test := range weak {
		t.Run(test.name, func(t *testing.T) {
			err := policy.Check(test.password, test.tokens)
			if !errors.Is(err, test.want) {
				t.Fatalf("密码 %q 错误 = %v，期望 %v", test.password, err, test.want)
			}
			if err != nil && test.password != "" && strings.Contains(err.Error(), test.password) {
				t.Error("策略错误信息回显了密码")
			}
		})
	}
	// 控制字符不属于“弱”，而是输入非法。
	if err := policy.Check("Correct-Horse-9\x00Battery", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("控制字符错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 超过上限的输入拒绝。
	if err := policy.Check(strings.Repeat("A", MaxPasswordBytes+1), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超大输入错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 策略参数越界。
	bad := PasswordPolicy{MinRunes: MinPasswordRunes - 1}
	if err := bad.Validate(); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("非法最短长度错误 = %v", err)
	}
	if err := (PasswordPolicy{MinRunes: 16, MaxRunes: 12}).Validate(); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("最长小于最短错误 = %v", err)
	}
	if err := (PasswordPolicy{HistoryLimit: MaxPasswordHistoryLimit + 1}).Validate(); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("历史条数越界错误 = %v", err)
	}
	// 部署追加词表生效。
	extra := DefaultPasswordPolicy()
	extra.WeakExtraWords = []string{"companyname"}
	if err := extra.Check("CompanyName", nil); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("追加弱密码词未生效: %v", err)
	}
}
