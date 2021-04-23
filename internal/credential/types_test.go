package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestNormalizeIssueRequest 校验签发参数默认值、上下界与格式拒绝。
func TestNormalizeIssueRequest(t *testing.T) {
	valid := IssueRequest{Purpose: "email.verify", Target: "user-1", Kind: KindToken}
	normalized, err := normalizeIssueRequest(valid)
	if err != nil {
		t.Fatalf("合法令牌请求失败: %v", err)
	}
	if normalized.TTL != DefaultTokenTTL {
		t.Fatalf("令牌默认 TTL = %s，期望 %s", normalized.TTL, DefaultTokenTTL)
	}
	if normalized.MaxAttempts != DefaultMaxAttempts {
		t.Fatalf("默认尝试上限 = %d，期望 %d", normalized.MaxAttempts, DefaultMaxAttempts)
	}
	code := IssueRequest{Purpose: "password.reset", Target: "user-2", Kind: KindCode}
	normalizedCode, err := normalizeIssueRequest(code)
	if err != nil {
		t.Fatalf("合法验证码请求失败: %v", err)
	}
	if normalizedCode.TTL != DefaultCodeTTL {
		t.Fatalf("验证码默认 TTL = %s，期望 %s", normalizedCode.TTL, DefaultCodeTTL)
	}

	cases := []struct {
		name    string
		request IssueRequest
	}{
		{name: "未知形态", request: IssueRequest{Purpose: "p", Target: "t", Kind: "otp"}},
		{name: "用途为空", request: IssueRequest{Purpose: "", Target: "t", Kind: KindToken}},
		{name: "目标为空", request: IssueRequest{Purpose: "p", Target: "", Kind: KindToken}},
		{name: "用途含空格", request: IssueRequest{Purpose: "email verify", Target: "t", Kind: KindToken}},
		{name: "目标含换行", request: IssueRequest{Purpose: "p", Target: "t\nx", Kind: KindToken}},
		{name: "用途含中文", request: IssueRequest{Purpose: "邮件验证", Target: "t", Kind: KindToken}},
		{name: "应用 ID 含空格", request: IssueRequest{Purpose: "p", Target: "t", AppID: "app 1", Kind: KindToken}},
		{name: "有效期过短", request: IssueRequest{Purpose: "p", Target: "t", Kind: KindToken, TTL: MinTTL - time.Millisecond}},
		{name: "有效期过长", request: IssueRequest{Purpose: "p", Target: "t", Kind: KindToken, TTL: MaxTTL + time.Millisecond}},
		{name: "尝试上限过大", request: IssueRequest{Purpose: "p", Target: "t", Kind: KindCode, MaxAttempts: MaxMaxAttempts + 1}},
		{name: "尝试上限为负", request: IssueRequest{Purpose: "p", Target: "t", Kind: KindCode, MaxAttempts: -1}},
		{name: "用途过长", request: IssueRequest{Purpose: strings.Repeat("p", maxPurposeBytes+1), Target: "t", Kind: KindToken}},
		{name: "目标过长", request: IssueRequest{Purpose: "p", Target: strings.Repeat("t", maxTargetBytes+1), Kind: KindToken}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := normalizeIssueRequest(testCase.request); !errors.Is(err, ErrRequestInvalid) {
				t.Fatalf("错误 = %v，期望 ErrRequestInvalid", err)
			}
		})
	}

	// 边界值应被接受。
	accepted := []IssueRequest{
		{Purpose: "p", Target: "t", Kind: KindToken, TTL: MinTTL, MaxAttempts: MinMaxAttempts},
		{Purpose: "p", Target: "t", Kind: KindToken, TTL: MaxTTL, MaxAttempts: MaxMaxAttempts},
		{Purpose: "p", Target: "t", Kind: KindCode, AppID: "app_1"},
	}
	for _, request := range accepted {
		if _, err := normalizeIssueRequest(request); err != nil {
			t.Fatalf("边界请求被拒绝: %v", err)
		}
	}
}

// TestValidateCredentialID 校验凭证 ID 的固定格式。
func TestValidateCredentialID(t *testing.T) {
	if err := validateCredentialID("otc_0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("合法 ID 被拒绝: %v", err)
	}
	for _, invalid := range []string{
		"",
		"otc_",
		"otc_0123",
		"OTC_0123456789abcdef0123456789abcdef",
		"otc_0123456789ABCDEF0123456789abcdef",
		"otc_0123456789abcdef0123456789abcde/",
		"otc_0123456789abcdef0123456789abcdef0",
	} {
		if err := validateCredentialID(invalid); !errors.Is(err, ErrRequestInvalid) {
			t.Fatalf("ID %q 错误 = %v，期望 ErrRequestInvalid", invalid, err)
		}
	}
}

// TestSecretRedaction 验证令牌/验证码的格式化、JSON 与日志脱敏，以及 Reveal 才
// 能取得明文。
func TestSecretRedaction(t *testing.T) {
	const plaintext = "87654321"
	secret := newSecret(plaintext)
	if !secret.IsSet() {
		t.Fatal("已设置秘密 IsSet = false")
	}
	if secret.Reveal() != plaintext {
		t.Fatal("Reveal 未返回原值")
	}
	formatted := []string{
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%q", secret),
		fmt.Sprintf("%x", secret),
	}
	for _, text := range formatted {
		if strings.Contains(text, plaintext) {
			t.Fatalf("格式化输出泄露秘密: %q", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Fatalf("格式化输出缺少脱敏标记: %q", text)
		}
	}
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("JSON 序列化失败: %v", err)
	}
	if strings.Contains(string(encoded), plaintext) || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("JSON 序列化泄露或缺少脱敏: %s", encoded)
	}

	var logBuffer strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("测试脱敏", "secret", secret)
	if strings.Contains(logBuffer.String(), plaintext) {
		t.Fatal("结构化日志泄露秘密")
	}
	if !strings.Contains(logBuffer.String(), "[REDACTED]") {
		t.Fatalf("结构化日志缺少脱敏标记: %s", logBuffer.String())
	}

	// 签发结果整体格式化时同样不能泄露秘密。
	issued := IssuedCredential{
		ID:        "otc_0123456789abcdef0123456789abcdef",
		Kind:      KindCode,
		Purpose:   "email.verify",
		Target:    "user-1",
		ExpiresAt: time.Now(),
		Secret:    secret,
	}
	for _, text := range []string{
		fmt.Sprintf("%v", issued),
		fmt.Sprintf("%+v", issued),
		fmt.Sprintf("%#v", issued),
	} {
		if strings.Contains(text, plaintext) {
			t.Fatalf("签发结果格式化泄露秘密: %q", text)
		}
	}
	issuedJSON, err := json.Marshal(issued)
	if err != nil {
		t.Fatalf("签发结果 JSON 序列化失败: %v", err)
	}
	if strings.Contains(string(issuedJSON), plaintext) {
		t.Fatal("签发结果 JSON 泄露秘密")
	}

	if (Secret{}).String() != "[UNSET]" || (Secret{}).IsSet() {
		t.Fatal("零值 Secret 行为错误")
	}
}

// TestVerifyRequestValidate 校验验证参数格式。
func TestVerifyRequestValidate(t *testing.T) {
	const id = "otc_0123456789abcdef0123456789abcdef"
	validToken := VerifyRequest{Kind: KindToken, ID: id, Purpose: "email.verify", Target: "user-1", Secret: "abcDEF0123-_"}
	if err := validToken.validate(); err != nil {
		t.Fatalf("合法令牌请求被拒绝: %v", err)
	}
	validCode := VerifyRequest{Kind: KindCode, ID: id, Purpose: "email.verify", Target: "user-1", Secret: "01234567"}
	if err := validCode.validate(); err != nil {
		t.Fatalf("合法验证码请求被拒绝: %v", err)
	}
	cases := []struct {
		name    string
		request VerifyRequest
	}{
		{name: "未知形态", request: VerifyRequest{Kind: "otp", ID: id, Purpose: "p", Target: "t", Secret: "x"}},
		{name: "ID 格式错误", request: VerifyRequest{Kind: KindToken, ID: "bad", Purpose: "p", Target: "t", Secret: "x"}},
		{name: "用途为空", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "", Target: "t", Secret: "x"}},
		{name: "目标为空", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "p", Target: "", Secret: "x"}},
		{name: "应用含空格", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "p", Target: "t", AppID: "a b", Secret: "x"}},
		{name: "令牌为空", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "p", Target: "t", Secret: ""}},
		{name: "令牌含空格", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "p", Target: "t", Secret: "a b"}},
		{name: "令牌过长", request: VerifyRequest{Kind: KindToken, ID: id, Purpose: "p", Target: "t", Secret: strings.Repeat("a", maxTokenInputBytes+1)}},
		{name: "验证码含字母", request: VerifyRequest{Kind: KindCode, ID: id, Purpose: "p", Target: "t", Secret: "12a45678"}},
		{name: "验证码含空格", request: VerifyRequest{Kind: KindCode, ID: id, Purpose: "p", Target: "t", Secret: "1234 678"}},
		{name: "验证码为空", request: VerifyRequest{Kind: KindCode, ID: id, Purpose: "p", Target: "t", Secret: ""}},
		{name: "验证码过长", request: VerifyRequest{Kind: KindCode, ID: id, Purpose: "p", Target: "t", Secret: strings.Repeat("1", maxCodeInputBytes+1)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.request.validate(); !errors.Is(err, ErrRequestInvalid) {
				t.Fatalf("错误 = %v，期望 ErrRequestInvalid", err)
			}
		})
	}
}

// TestCancelRequestValidate 校验取消请求格式。
func TestCancelRequestValidate(t *testing.T) {
	const id = "otc_0123456789abcdef0123456789abcdef"
	valid := CancelRequest{ID: id, Purpose: "email.verify", Target: "user-1"}
	if err := valid.validate(); err != nil {
		t.Fatalf("合法取消请求被拒绝: %v", err)
	}
	for _, invalid := range []CancelRequest{
		{ID: "", Purpose: "p", Target: "t"},
		{ID: "bad", Purpose: "p", Target: "t"},
		{ID: id, Purpose: "p", Target: ""},
	} {
		if err := invalid.validate(); !errors.Is(err, ErrRequestInvalid) {
			t.Fatalf("非法取消请求 %+v 错误 = %v", invalid, err)
		}
	}
}

// TestContextJSONContainsNoSecret 验证 context_json 只保存诊断元数据。
func TestContextJSONContainsNoSecret(t *testing.T) {
	for _, kind := range []Kind{KindToken, KindCode} {
		text := contextJSON(kind)
		if !strings.Contains(text, string(kind)) {
			t.Fatalf("contextJSON(%s) = %s，缺少形态", kind, text)
		}
		if strings.Contains(text, "secret") || strings.Contains(text, "hash") {
			t.Fatalf("contextJSON(%s) 含敏感字段: %s", kind, text)
		}
	}
}

// TestKindValid 校验形态枚举。
func TestKindValid(t *testing.T) {
	for _, kind := range []Kind{KindToken, KindCode} {
		if !kind.valid() {
			t.Fatalf("%q 应为合法形态", kind)
		}
	}
	for _, kind := range []Kind{"", "otp", "TOKEN"} {
		if kind.valid() {
			t.Fatalf("%q 不应为合法形态", kind)
		}
	}
}
