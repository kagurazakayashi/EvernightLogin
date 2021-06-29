package oauthclient_test

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// TestDeviceOnlyClientWithoutRedirectURI 验证纯设备码客户端（电视/CLI）按 RFC 8628
// 不使用回调地址，允许不登记回调；含授权码模式时仍必须至少登记一个回调。
func TestDeviceOnlyClientWithoutRedirectURI(t *testing.T) {
	env := newTestEnv(t, nil)
	deviceOnly := validPublicRegister()
	deviceOnly.RedirectURIs = nil
	deviceOnly.GrantTypes = []string{
		"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), deviceOnly); err != nil {
		t.Fatalf("登记纯设备码公开客户端失败：%v", err)
	}
	authorizationCode := validPublicRegister()
	authorizationCode.RedirectURIs = nil
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), authorizationCode); !errors.Is(err,
		oauthclient.ErrInvalidRequest) {
		t.Fatalf("缺回调的授权码客户端登记 error = %v，期望 ErrInvalidRequest", err)
	}
}
