// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package uisecurityadapter

import (
	"context"
	"errors"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// TestNewRequiresCoreOnly 验证适配器构造只强制核心服务；Passkey/OAuth 可选。
func TestNewRequiresCoreOnly(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("缺少核心服务时必须拒绝构造")
	}
	if _, err := New(Options{MFA: nil, TOTP: nil, Recovery: nil, Sessions: nil, Reauth: nil}); err == nil {
		t.Fatal("缺少全部核心服务时必须拒绝构造")
	}
}

// TestOptionalCapabilityMethodsFailClosed 验证可选服务 nil 时方法返回稳定
// FEATURE_NOT_ENABLED，不 panic、不伪造空列表（页面据此返回 403）。
func TestOptionalCapabilityMethodsFailClosed(t *testing.T) {
	adapter := &Adapter{}
	ctx := context.Background()
	if _, err := adapter.ListPasskeys(ctx, "usr_11111111111111111111111111111111"); err == nil {
		t.Fatal("Passkey 未启用时 ListPasskeys 必须失败")
	} else {
		var publicErr *login.UIAccountError
		if !errors.As(err, &publicErr) || publicErr.Code != "FEATURE_NOT_ENABLED" {
			t.Fatalf("错误码 = %v，期望 FEATURE_NOT_ENABLED", err)
		}
	}
	if _, err := adapter.BeginPasskeyRegistration(ctx, "usr_11111111111111111111111111111111", "req"); err == nil {
		t.Fatal("Passkey 未启用时注册必须失败")
	}
	if err := adapter.RemovePasskey(ctx, "usr_11111111111111111111111111111111",
		"cred", "password", "req"); err == nil {
		t.Fatal("Passkey 未启用时撤销必须失败")
	}
	if _, err := adapter.ListGrants(ctx, nil, 1, 20); err == nil {
		t.Fatal("OAuth 未启用时授权列表必须失败")
	} else {
		var publicErr *login.UIAccountError
		if !errors.As(err, &publicErr) || publicErr.Code != "FEATURE_NOT_ENABLED" {
			t.Fatalf("OAuth 错误码 = %v，期望 FEATURE_NOT_ENABLED", err)
		}
	}
	if _, err := adapter.RevokeGrant(ctx, nil, "aur_x", "password", "req"); err == nil {
		t.Fatal("OAuth 未启用时撤回授权必须失败")
	}
}
