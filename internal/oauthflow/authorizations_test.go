package oauthflow_test

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// TestListUserAuthorizations 验证仅返回本人已批准、未撤销的授权摘要，分页有上限，
// 不含秘密；撤回后从列表移除。
func TestListUserAuthorizations(t *testing.T) {
	env := newTestEnv(t, "public")
	prompt := env.begin()
	result := env.approve(prompt)
	if !result.Approved {
		t.Fatal("授权批准失败")
	}
	page, err := env.flow.ListUserAuthorizations(env.ctx, env.sessionSecret,
		oauthflow.AuthorizationListOptions{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("已授权列表失败: %v", err)
	}
	if len(page.Authorizations) != 1 || page.Authorizations[0].AuthorizationID != prompt.RequestID {
		t.Fatalf("列表应包含本人授权: %+v", page.Authorizations)
	}
	summary := page.Authorizations[0]
	if summary.ClientID != env.appID || len(summary.Scopes) == 0 ||
		len(summary.Audiences) == 0 || summary.ApprovedAt.IsZero() {
		t.Fatalf("授权摘要字段不正确: %+v", summary)
	}
	// 分页上限拒绝（不静默截断）。
	if _, err := env.flow.ListUserAuthorizations(env.ctx, env.sessionSecret,
		oauthflow.AuthorizationListOptions{Page: 1, PageSize: 51}); err == nil {
		t.Fatal("超过分页上限应拒绝")
	}
	// 无效会话拒绝。
	if _, err := env.flow.ListUserAuthorizations(env.ctx, "invalid-session", oauthflow.AuthorizationListOptions{}); err == nil {
		t.Fatal("无效会话应拒绝")
	}
	// 撤回后不再出现在已授权列表。
	if _, err := env.flow.RevokeAuthorization(env.ctx, oauthflow.RevokeAuthorizationRequest{
		SessionSecret: env.sessionSecret, AuthorizationID: prompt.RequestID,
		RequestID: "req-revoke-list"}); err != nil {
		t.Fatalf("撤回授权失败: %v", err)
	}
	page, err = env.flow.ListUserAuthorizations(env.ctx, env.sessionSecret,
		oauthflow.AuthorizationListOptions{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("撤回后列表失败: %v", err)
	}
	if len(page.Authorizations) != 0 {
		t.Fatalf("已撤销授权不应出现在列表: %+v", page.Authorizations)
	}
	// 他人授权不可见：用户身份只来自服务端会话，不接受客户端自报 userID。
}
