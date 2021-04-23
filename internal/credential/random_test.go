package credential

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// failingReader 模拟安全随机源失败。
type failingReader struct {
	err error
}

// Read 实现 io.Reader，始终返回错误。
func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

// TestNewCredentialIDFormat 验证凭证 ID 前缀、长度、字符集与随机性。
func TestNewCredentialIDFormat(t *testing.T) {
	first, err := newCredentialID(rand.Reader)
	if err != nil {
		t.Fatalf("生成凭证 ID 失败: %v", err)
	}
	if err := validateCredentialID(first); err != nil {
		t.Fatalf("生成的凭证 ID 不合格式: %v", err)
	}
	second, err := newCredentialID(rand.Reader)
	if err != nil {
		t.Fatalf("生成凭证 ID 失败: %v", err)
	}
	if first == second {
		t.Fatal("两次生成的凭证 ID 相同")
	}
	if _, err := newCredentialID(failingReader{err: errors.New("熵源不可用")}); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("随机源失败错误 = %v，期望 ErrRandomSource", err)
	}
}

// TestNewTokenSecretFormat 验证高熵令牌长度、编码与随机性。
func TestNewTokenSecretFormat(t *testing.T) {
	first, err := newTokenSecret(rand.Reader)
	if err != nil {
		t.Fatalf("生成令牌失败: %v", err)
	}
	if len(first) != TokenSecretLength {
		t.Fatalf("令牌长度 = %d，期望 %d", len(first), TokenSecretLength)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("令牌不是合法 base64url: %v", err)
	}
	if len(decoded) != TokenSize {
		t.Fatalf("令牌字节数 = %d，期望 %d", len(decoded), TokenSize)
	}
	second, err := newTokenSecret(rand.Reader)
	if err != nil {
		t.Fatalf("生成令牌失败: %v", err)
	}
	if first == second {
		t.Fatal("两次生成的令牌相同")
	}
	if _, err := newTokenSecret(failingReader{err: errors.New("熵源不可用")}); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("随机源失败错误 = %v，期望 ErrRandomSource", err)
	}
}

// TestNewCodeSecretFormat 验证验证码为固定长度十进制数字，并验证拒绝采样行为。
func TestNewCodeSecretFormat(t *testing.T) {
	code, err := newCodeSecret(rand.Reader)
	if err != nil {
		t.Fatalf("生成验证码失败: %v", err)
	}
	if len(code) != CodeLength {
		t.Fatalf("验证码长度 = %d，期望 %d", len(code), CodeLength)
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			t.Fatalf("验证码包含非数字字符: %q", code)
		}
	}
	// 250 被拒绝（避免取模偏差），随后 0～7 被接受，得到 "01234567"。
	fixed := bytes.NewReader([]byte{250, 0, 1, 2, 3, 4, 5, 6, 7})
	deterministic, err := newCodeSecret(fixed)
	if err != nil {
		t.Fatalf("固定随机源生成验证码失败: %v", err)
	}
	if deterministic != "01234567" {
		t.Fatalf("拒绝采样结果 = %q，期望 01234567", deterministic)
	}
	if _, err := newCodeSecret(failingReader{err: errors.New("熵源不可用")}); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("随机源失败错误 = %v，期望 ErrRandomSource", err)
	}
}

// TestRandomDigitRejectsNonUniformStream 验证持续返回 250 以上字节的随机源最终
// 明确失败，而不是无限重试。
func TestRandomDigitRejectsNonUniformStream(t *testing.T) {
	stream := bytes.NewReader(bytes.Repeat([]byte{255}, credentialMaxRandomRetries+10))
	if _, err := randomDigit(stream); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("异常随机源错误 = %v，期望 ErrRandomSource", err)
	}
}

// TestShortRandomReadsFail 验证短读也必须失败，不能补零或复用随机值。
func TestShortRandomReadsFail(t *testing.T) {
	stream := bytes.NewReader([]byte{1, 2, 3})
	if _, err := newTokenSecret(stream); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("短读错误 = %v，期望 ErrRandomSource", err)
	}
}

// TestDefaultRandomReaderIsSafe 确认生产默认随机源不是空实现。
func TestDefaultRandomReaderIsSafe(t *testing.T) {
	reader := defaultRandomReader()
	if reader == nil {
		t.Fatal("默认随机源为空")
	}
	buffer := make([]byte, 8)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatalf("默认随机源读取失败: %v", err)
	}
	if strings.TrimSpace(string(buffer)) == "" {
		t.Fatal("默认随机源读取结果异常")
	}
}
