package oidc_test

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
)

// TestUserInfoRejectsRevokedAccessToken 验证步骤 55：UserInfo 在校验 Access Token
// 后接入在线撤销检查，撤回授权/退出应用后的未过期令牌不能继续访问用户信息。
func TestUserInfoRejectsRevokedAccessToken(t *testing.T) {
	env := newTestEnv(t)
	accessToken := env.issueAccessToken(testClient, testUser,
		[]string{"openid", "email"}, []string{testIssuer})
	if _, err := env.service.UserInfo(env.ctx, accessToken); err != nil {
		t.Fatalf("未撤销时 UserInfo 应成功: %v", err)
	}
	env.checker.revoked = true
	if _, err := env.service.UserInfo(env.ctx, accessToken); oidc.CodeOf(err) != oidc.CodeTokenInvalid {
		t.Fatalf("已撤销 Access Token 的 UserInfo 应 TOKEN_INVALID，实际 %v", err)
	}
}
