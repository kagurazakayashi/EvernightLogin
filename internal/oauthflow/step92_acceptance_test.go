package oauthflow_test

// 步骤 92 验收探针：OAuth 2.0 / Device Authorization 协议层负向与类型隔离验收。
// 本文件复用既有测试环境（真实临时 SQLite、迁移、真实令牌/会话/审计服务），补充
// 步骤 92 能力矩阵中要求的：PKCE 降级/错误校验、授权码重放、授权码与设备码互用、
// 设备码轮询 pending/slow_down/过期、Access/Refresh Token 与授权码类型混用。
//
// 边界：这是进程内真实服务的协议语义验收，不是部署后的 HTTP 端点，也不是标准
// OAuth 客户端/真机实测；HTTP 层端点装配仍缺失（见验收记录未测项）。

import (
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// TestStep92PKCEDowngradeAndReplay 覆盖 PKCE 强制 S256、错误 verifier 不消费授权码、
// 授权码一次性与重复兑换拒绝。
func TestStep92PKCEDowngradeAndReplay(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	t.Run("禁止 PKCE plain", func(t *testing.T) {
		request := env.authorizeRequest()
		request.CodeChallengeMethod = "plain"
		if _, err := env.flow.BeginAuthorization(env.ctx, env.sessionSecret, request); !isOAuthCode(err, "invalid_request") {
			t.Fatalf("plain 降级应 invalid_request，实际 %v", err)
		}
	})
	t.Run("禁止缺少 PKCE", func(t *testing.T) {
		request := env.authorizeRequest()
		request.CodeChallenge = ""
		request.CodeChallengeMethod = ""
		if _, err := env.flow.BeginAuthorization(env.ctx, env.sessionSecret, request); !isOAuthCode(err, "invalid_request") {
			t.Fatalf("缺少 PKCE 应 invalid_request，实际 %v", err)
		}
	})
	prompt := env.begin()
	result := env.approve(prompt)
	t.Run("错误 verifier 不消费授权码", func(t *testing.T) {
		_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
			GrantType: "authorization_code", Code: result.Code.Reveal(), RedirectURI: testRedirect,
			ClientID: testAppID, CodeVerifier: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			RequestID: "req_92_bad_verifier"})
		if !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("错误 verifier 应 invalid_grant，实际 %v", err)
		}
		if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE consumed_at_ms IS NULL`); got != 1 {
			t.Fatalf("PKCE 失败不应消费授权码，可用码 = %d", got)
		}
	})
	response, err := env.exchangeAccess(result.Code.Reveal())
	if err != nil {
		t.Fatalf("正确 PKCE 兑换失败: %v", err)
	}
	if _, err := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(), testAudience); err != nil {
		t.Fatalf("兑换得到的 Access Token 验证失败: %v", err)
	}
	if _, err := env.exchangeAccess(result.Code.Reveal()); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("授权码重复兑换应 invalid_grant，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE replayed_at_ms IS NOT NULL`); got != 1 {
		t.Fatalf("重复兑换未记录重放，replayed 记录 = %d", got)
	}
}

// TestStep92DeviceCodeMixupsAndPolling 覆盖设备码轮询状态与授权码/设备码互用拒绝。
func TestStep92DeviceCodeMixupsAndPolling(t *testing.T) {
	t.Run("轮询 pending/slow_down/过期", func(t *testing.T) {
		env := newDeviceEnv(t, oauthclient.ClientTypePublic)
		start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
		_, err := env.pollDevice(t, start)
		if code := deviceProtocolCode(t, err); code != "authorization_pending" {
			t.Fatalf("首次轮询应 authorization_pending，实际 %q", code)
		}
		_, err = env.pollDevice(t, start)
		if code := deviceProtocolCode(t, err); code != "slow_down" {
			t.Fatalf("过快轮询应 slow_down，实际 %q", code)
		}
		env.now = env.now.Add(11 * time.Minute)
		_, err = env.pollDevice(t, start)
		if code := deviceProtocolCode(t, err); code != "expired_token" {
			t.Fatalf("过期设备码应 expired_token，实际 %q", code)
		}
	})
	t.Run("授权码与设备码不能互用", func(t *testing.T) {
		env := newDeviceEnv(t, oauthclient.ClientTypePublic)
		prompt := env.begin()
		approved := env.approve(prompt)
		deviceStart := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
		// 设备码冒充授权码。
		_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
			GrantType: "authorization_code", Code: deviceStart.DeviceCode.Reveal(),
			RedirectURI: testRedirect, ClientID: testAppID, CodeVerifier: pkceVerifier,
			RequestID: "req_92_mix_1"})
		if !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("设备码冒充授权码应 invalid_grant，实际 %v", err)
		}
		// 授权码冒充设备码。
		_, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
			GrantType:  oauthflow.AccessTokenGrantDeviceCode,
			DeviceCode: approved.Code.Reveal(), ClientID: testAppID,
			RequestID: "req_92_mix_2"})
		if !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("授权码冒充设备码应 invalid_grant，实际 %v", err)
		}
		// 授权码本身仍可用（互用失败不破坏原授权）。
		if _, err := env.exchangeAccess(approved.Code.Reveal()); err != nil {
			t.Fatalf("互用失败后原授权码仍应可兑换: %v", err)
		}
	})
}

// TestStep92TokenKindMixups 覆盖 Access/Refresh Token 与授权码/刷新授权字段的类型混用。
func TestStep92TokenKindMixups(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	accessToken := first.AccessToken.Reveal()
	if !first.RefreshToken.IsSet() {
		t.Fatal("应签发 Refresh Token")
	}
	refreshToken := first.RefreshToken.Reveal()

	t.Run("Access Token 冒充 Refresh Token", func(t *testing.T) {
		if _, err := env.refresh(accessToken, "req_92_mix_refresh", nil, nil); !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("Access Token 冒充刷新令牌应 invalid_grant，实际 %v", err)
		}
	})
	t.Run("Access Token 冒充授权码", func(t *testing.T) {
		_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
			GrantType: "authorization_code", Code: accessToken, RedirectURI: testRedirect,
			ClientID: testAppID, CodeVerifier: pkceVerifier, RequestID: "req_92_mix_code_1"})
		// 访问令牌是长 JWT，会先命中授权码参数长度校验（invalid_request）；
		// 两种标准错误都表示拒绝，关键是不得兑换成功。
		if !isOAuthCode(err, "invalid_grant") && !isOAuthCode(err, "invalid_request") {
			t.Fatalf("Access Token 冒充授权码应被拒绝，实际 %v", err)
		}
	})
	t.Run("Refresh Token 冒充授权码", func(t *testing.T) {
		_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
			GrantType: "authorization_code", Code: refreshToken, RedirectURI: testRedirect,
			ClientID: testAppID, CodeVerifier: pkceVerifier, RequestID: "req_92_mix_code_2"})
		if !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("Refresh Token 冒充授权码应 invalid_grant，实际 %v", err)
		}
	})
	t.Run("刷新轮换与旧值重放", func(t *testing.T) {
		rotated, err := env.refresh(refreshToken, "req_92_rotate", nil, nil)
		if err != nil {
			t.Fatalf("刷新轮换失败: %v", err)
		}
		if !rotated.RefreshToken.IsSet() || rotated.RefreshToken.Reveal() == refreshToken {
			t.Fatal("轮换必须返回新的 Refresh Token")
		}
		if _, err := env.refresh(refreshToken, "req_92_replay", nil, nil); !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("旧刷新令牌重放应 invalid_grant，实际 %v", err)
		}
		if got := env.queryInt(`SELECT COUNT(*) FROM refresh_token_families WHERE revoked_at_ms IS NOT NULL`); got != 1 {
			t.Fatalf("重放后令牌族应撤销，实际撤销族 = %d", got)
		}
		if _, err := env.refresh(rotated.RefreshToken.Reveal(), "req_92_after_replay", nil, nil); !isOAuthCode(err, "invalid_grant") {
			t.Fatalf("族撤销后新刷新令牌应失效，实际 %v", err)
		}
	})
}
