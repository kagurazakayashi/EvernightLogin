package token_test

import (
	"testing"

	. "github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// TestIssueAccessTokenForDeviceCode 验证设备码授权类型使用 RFC 8628 的 URN 常量，
// 与 OAuth 客户端登记值一致后可签发用户主体 Access Token（步骤 57 依赖）。
func TestIssueAccessTokenForDeviceCode(t *testing.T) {
	if string(GrantDeviceCode) != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Fatalf("GrantDeviceCode = %q，期望 RFC 8628 URN", GrantDeviceCode)
	}
	env := newTestEnv(t, nil)
	request := accessRequest()
	request.GrantType = GrantDeviceCode
	issued, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), request)
	if err != nil {
		t.Fatalf("设备码授权类型签发 Access Token 失败：%v", err)
	}
	claims, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证设备码 Access Token 失败：%v", err)
	}
	if claims.Subject != testUserA || claims.SubjectType != TokenSubjectTypeUser {
		t.Fatalf("设备码令牌主体 = %q/%q，期望用户主体", claims.Subject, claims.SubjectType)
	}
}
