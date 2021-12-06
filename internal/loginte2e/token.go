package loginte2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// TokenResponse 是令牌端点的成功响应投影。字段都是秘密：只在内存使用，绝不写入
// 日志或报告。
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	Scope        string
	RefreshToken string
	IDToken      string
}

// tokenForm 提交令牌端点表单（只放请求体，绝不放 URL 查询串）。
func (c *Client) tokenForm(ctx context.Context, values url.Values) (*httpResult, error) {
	return c.do(ctx, "POST", pathToken, requestOptions{form: values})
}

// clientAuthFields 按配置把客户端身份写入表单：公开客户端只带 client_id，
// 保密客户端使用 client_secret_post（--client-secret-file）。
func (c *Client) clientAuthFields(values url.Values) url.Values {
	values.Set("client_id", c.cfg.ClientID)
	if c.cfg.ClientSecret != "" {
		values.Set("client_secret", c.cfg.ClientSecret)
	}
	return values
}

// parseTokenResponse 解析成功的令牌响应；错误响应返回 *HTTPError。
func parseTokenResponse(result *httpResult) (*TokenResponse, error) {
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("令牌端点返回意外状态 HTTP %d", result.Status)
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	if payload.AccessToken == "" {
		return nil, fmt.Errorf("令牌响应缺少 access_token")
	}
	return &TokenResponse{AccessToken: payload.AccessToken, TokenType: payload.TokenType,
		ExpiresIn: payload.ExpiresIn, Scope: payload.Scope,
		RefreshToken: payload.RefreshToken, IDToken: payload.IDToken}, nil
}

// exchangeAuthorizationCode 用授权码 + PKCE verifier 兑换令牌。
func (c *Client) exchangeAuthorizationCode(ctx context.Context,
	code, verifier string) (*TokenResponse, error) {
	form := c.clientAuthFields(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
		"code_verifier": {verifier},
	})
	result, err := c.tokenForm(ctx, form)
	if err != nil {
		return nil, err
	}
	return parseTokenResponse(result)
}

// exchangeRefreshToken 用刷新令牌换新令牌（轮换语义由服务端实现）。
func (c *Client) exchangeRefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := c.clientAuthFields(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	result, err := c.tokenForm(ctx, form)
	if err != nil {
		return nil, err
	}
	return parseTokenResponse(result)
}

// userInfo 用访问令牌读取 UserInfo（只允许 Authorization: Bearer）。
func (c *Client) userInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	result, err := c.do(ctx, "GET", pathUserInfo, requestOptions{bearer: accessToken})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("UserInfo 返回意外状态 HTTP %d", result.Status)
	}
	var payload map[string]any
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// revokeToken 撤销令牌（RFC 7009）。成功响应为空正文。
func (c *Client) revokeToken(ctx context.Context, token, hint string) error {
	form := c.clientAuthFields(url.Values{"token": {token}})
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	result, err := c.do(ctx, "POST", pathRevoke, requestOptions{form: form})
	if err != nil {
		return err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return problem
		}
		return fmt.Errorf("撤销端点返回意外状态 HTTP %d", result.Status)
	}
	return nil
}

// introspectToken 查询令牌状态（RFC 7662）。必须完成客户端认证。
func (c *Client) introspectToken(ctx context.Context, token string) (map[string]any, error) {
	form := c.clientAuthFields(url.Values{"token": {token}})
	result, err := c.do(ctx, "POST", pathIntrospect, requestOptions{form: form})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("状态查询端点返回意外状态 HTTP %d", result.Status)
	}
	var payload map[string]any
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// runTokenSuite 验证令牌端点生命周期与负例。
func (r *Runner) runTokenSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireClient(); err != nil {
		r.skipSuite("缺少 --client-id：" + safeDetail(err))
		return nil
	}

	// 不需要授权码的负例。
	r.run("token_missing_grant_type_rejected", func() error {
		form := r.client.clientAuthFields(url.Values{})
		result, err := r.client.tokenForm(ctx, form)
		if err != nil {
			return err
		}
		_, problemErr := result.expectProblem(400, "invalid_request", "REQ_INVALID",
			"invalid_client", "CLIENT_AUTH_FAILED")
		return problemErr
	})

	r.run("token_unknown_grant_rejected", func() error {
		form := r.client.clientAuthFields(url.Values{
			"grant_type": {"urn:example:loginte2e:unknown-grant"}})
		result, err := r.client.tokenForm(ctx, form)
		if err != nil {
			return err
		}
		if result.isSuccess() {
			return fmt.Errorf("未知 grant_type 不应成功")
		}
		problem, ok := result.problem().(*HTTPError)
		if !ok || problem.Code == "" {
			return fmt.Errorf("拒绝响应缺少稳定错误码")
		}
		if problem.Code != "unsupported_grant_type" {
			return fmt.Errorf("期望 unsupported_grant_type，实际 %v", problem)
		}
		return nil
	})

	if err := r.requireRedirect(); err != nil {
		r.skipSuite("缺少 --client-id/--redirect-uri：" + safeDetail(err))
		return nil
	}
	if err := r.requireSession(); err != nil {
		r.skipSuite("缺少已登录会话：" + safeDetail(err))
		return nil
	}

	// 授权码兑换与后续用例共享的令牌状态。某一步失败后，依赖它的用例如实 skip，
	// 不把“没拿到令牌”误报成第二个失败。
	var (
		tokens *TokenResponse
		flow   *authorizationCode
	)

	r.run("authorization_code_exchange", func() error {
		obtained, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		flow = obtained
		issued, err := r.client.exchangeAuthorizationCode(ctx, obtained.Code, obtained.Verifier)
		if err != nil {
			return err
		}
		if issued.TokenType != "Bearer" {
			return fmt.Errorf("token_type 应为 Bearer，实际 %q", issued.TokenType)
		}
		if issued.ExpiresIn <= 0 {
			return fmt.Errorf("expires_in 必须为正数")
		}
		if issued.IDToken == "" {
			return fmt.Errorf("申请了 openid scope 但响应缺少 id_token")
		}
		if issued.RefreshToken == "" {
			return fmt.Errorf("申请了 offline_access 但响应缺少 refresh_token")
		}
		tokens = issued
		return nil
	})

	r.run("code_replay_rejected", func() error {
		if flow == nil {
			return skipf("前置用例未取得授权码")
		}
		_, err := r.client.exchangeAuthorizationCode(ctx, flow.Code, flow.Verifier)
		if err == nil {
			return fmt.Errorf("授权码重复兑换不应成功")
		}
		problem, ok := err.(*HTTPError)
		if !ok || problem.Code != "invalid_grant" {
			return fmt.Errorf("授权码重放期望 invalid_grant，实际 %v", err)
		}
		return nil
	})

	r.run("wrong_pkce_verifier_rejected", func() error {
		obtained, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		wrong, err := randomURLSafe(pkceVerifierBytes)
		if err != nil {
			return err
		}
		_, exchangeErr := r.client.exchangeAuthorizationCode(ctx, obtained.Code, wrong)
		if exchangeErr == nil {
			return fmt.Errorf("错误 PKCE verifier 不应兑换成功")
		}
		problem, ok := exchangeErr.(*HTTPError)
		if !ok || problem.Code != "invalid_grant" {
			return fmt.Errorf("错误 PKCE verifier 期望 invalid_grant，实际 %v", exchangeErr)
		}
		return nil
	})

	r.run("userinfo_returns_subject", func() error {
		if tokens == nil {
			return skipf("前置用例未取得访问令牌")
		}
		info, err := r.client.userInfo(ctx, tokens.AccessToken)
		if err != nil {
			return err
		}
		subject, _ := info["sub"].(string)
		if strings.TrimSpace(subject) == "" {
			return fmt.Errorf("UserInfo 缺少 sub")
		}
		return nil
	})

	r.run("refresh_rotates_and_replay_rejected", func() error {
		if tokens == nil || tokens.RefreshToken == "" {
			return skipf("前置用例未取得刷新令牌")
		}
		refreshed, err := r.client.exchangeRefreshToken(ctx, tokens.RefreshToken)
		if err != nil {
			return err
		}
		if refreshed.AccessToken == "" {
			return fmt.Errorf("刷新响应缺少访问令牌")
		}
		if refreshed.RefreshToken == "" {
			return fmt.Errorf("刷新响应缺少轮换后的刷新令牌")
		}
		if refreshed.RefreshToken == tokens.RefreshToken {
			return fmt.Errorf("刷新令牌未轮换（新旧相同）")
		}
		// 旧刷新令牌重放必须被拒绝。
		if _, replayErr := r.client.exchangeRefreshToken(ctx, tokens.RefreshToken); replayErr == nil {
			return fmt.Errorf("旧刷新令牌重放不应成功")
		}
		return nil
	})

	r.run("revoke_invalidates_access_token", func() error {
		obtained, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		issued, err := r.client.exchangeAuthorizationCode(ctx, obtained.Code, obtained.Verifier)
		if err != nil {
			return err
		}
		if err := r.client.revokeToken(ctx, issued.AccessToken, "access_token"); err != nil {
			return err
		}
		if _, infoErr := r.client.userInfo(ctx, issued.AccessToken); infoErr == nil {
			return fmt.Errorf("撤销后的访问令牌仍可访问 UserInfo")
		}
		return nil
	})

	// 状态查询：未声明端点时 404；声明了则未认证请求必须被拒绝（401/403）。
	r.run("introspect_requires_client_auth", func() error {
		document, err := r.document(ctx)
		if err != nil {
			return err
		}
		if document.IntrospectionEndpoint == "" {
			result, err := r.client.do(ctx, "POST", pathIntrospect,
				requestOptions{form: url.Values{"token": {"test-only-placeholder"}}})
			if err != nil {
				return err
			}
			if result.Status != 404 {
				return fmt.Errorf("未声明状态查询能力时端点应 404，实际 HTTP %d", result.Status)
			}
			return nil
		}
		result, err := r.client.do(ctx, "POST", pathIntrospect,
			requestOptions{form: url.Values{"token": {"test-only-placeholder"}}})
		if err != nil {
			return err
		}
		if _, problemErr := result.expectProblem(0, "invalid_client", "CLIENT_AUTH_FAILED",
			"REQ_INVALID"); problemErr != nil {
			return problemErr
		}
		return nil
	})

	r.run("introspect_active_token", func() error {
		document, err := r.document(ctx)
		if err != nil {
			return err
		}
		if document.IntrospectionEndpoint == "" {
			return skipf("服务未声明 introspection_endpoint")
		}
		if r.client.cfg.ClientSecret == "" {
			return skipf("状态查询需要保密客户端：用 --client-secret-file 提供密钥")
		}
		obtained, err := r.obtainAuthorizationCode(ctx)
		if err != nil {
			return err
		}
		issued, err := r.client.exchangeAuthorizationCode(ctx, obtained.Code, obtained.Verifier)
		if err != nil {
			return err
		}
		info, err := r.client.introspectToken(ctx, issued.AccessToken)
		if err != nil {
			return err
		}
		if active, ok := info["active"].(bool); !ok || !active {
			return fmt.Errorf("刚签发的访问令牌状态查询应为 active=true")
		}
		return nil
	})
	return nil
}
