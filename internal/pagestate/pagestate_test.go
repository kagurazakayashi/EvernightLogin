package pagestate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

type payload struct {
	ChallengeID string `json:"challenge_id"`
	Attempts    int    `json:"attempts"`
}

// testCodec 构造带可控时钟的编解码器。
func testCodec(t *testing.T, now *time.Time) *pagestate.Codec {
	t.Helper()
	keyring, err := secrets.GenerateKeyring("k1", *now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	codec, err := pagestate.New(pagestate.Options{Keyring: keyring, TTL: 10 * time.Minute,
		Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatalf("构造 Codec: %v", err)
	}
	return codec
}

// TestSealOpenRoundTrip 验证正常往返、用途绑定、篡改与过期拒绝。
func TestSealOpenRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 0, 0, 0, time.UTC)
	codec := testCodec(t, &now)
	token, err := codec.Seal("mfa.second_factor", payload{ChallengeID: "chal_1", Attempts: 2})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var opened payload
	if err := codec.Open("mfa.second_factor", token, &opened); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.ChallengeID != "chal_1" || opened.Attempts != 2 {
		t.Fatalf("往返内容不一致: %+v", opened)
	}
	// 用途不符拒绝。
	if err := codec.Open("mfa.strong_setup", token, &opened); !errors.Is(err, pagestate.ErrStateInvalid) {
		t.Fatalf("错误用途应拒绝，实际 %v", err)
	}
	// 篡改载荷/签名拒绝。
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatalf("令牌格式异常: %s", token)
	}
	tampered := parts[0] + "." + parts[1] + "." + parts[2] + "x." + parts[3]
	if err := codec.Open("mfa.second_factor", tampered, &opened); !errors.Is(err, pagestate.ErrStateInvalid) {
		t.Fatalf("篡改载荷应拒绝，实际 %v", err)
	}
	// 过期拒绝。
	now = now.Add(11 * time.Minute)
	if err := codec.Open("mfa.second_factor", token, &opened); !errors.Is(err, pagestate.ErrStateInvalid) {
		t.Fatalf("过期状态应拒绝，实际 %v", err)
	}
}

// TestCodecOptionsValidation 验证 TTL/用途域/密钥环边界。
func TestCodecOptionsValidation(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 0, 0, 0, time.UTC)
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	if _, err := pagestate.New(pagestate.Options{TTL: time.Minute}); err == nil {
		t.Fatal("缺少密钥环应拒绝")
	}
	if _, err := pagestate.New(pagestate.Options{Keyring: keyring, TTL: time.Second}); err == nil {
		t.Fatal("过短 TTL 应拒绝")
	}
	codec, err := pagestate.New(pagestate.Options{Keyring: keyring, TTL: 10 * time.Minute,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("构造 Codec: %v", err)
	}
	if _, err := codec.Seal("bad purpose!", payload{}); err == nil {
		t.Fatal("非法用途域应拒绝")
	}
	if _, err := codec.Seal("ok.purpose", strings.Repeat("x", 10000)); err == nil {
		t.Fatal("过大状态应拒绝")
	}
}
