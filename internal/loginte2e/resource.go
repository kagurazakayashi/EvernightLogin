package loginte2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// pathTokenAuthorize 是宿主扩展端点（非标准 OAuth；只有注入处理器时存在）。
const pathTokenAuthorize = "/oauth/token/authorize"

// basicRequest 执行带 HTTP Basic 的固定路径请求（资源服务身份）。
func (c *Client) basicRequest(ctx context.Context, method, path, clientID, secret string,
	contentType string, body io.Reader) (*httpResult, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求失败", ErrConfigInvalid)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "login-loginte2e/1 (test-only)")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if clientID != "" || secret != "" {
		request.SetBasicAuth(clientID, secret)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: 请求失败", ErrUnavailable)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败")
	}
	return &httpResult{Method: method, Path: path, Status: response.StatusCode,
		Header: response.Header.Clone(), Body: data}, nil
}

// resourceClient 检查资源服务套件前置条件。
func (r *Runner) requireResourceClient() error {
	if strings.TrimSpace(r.client.cfg.ResourceClientID) == "" ||
		strings.TrimSpace(r.client.cfg.ResourceClientSecret) == "" {
		return skipf("缺少 --resource-client-id/--resource-client-secret-file")
	}
	if strings.TrimSpace(r.client.cfg.Audience) == "" {
		return skipf("缺少 --audience（预期资源 audience）")
	}
	return nil
}

// obtainAccessTokenForResource 用授权码流程取得真实 access token（复用浏览器会话）。
func (r *Runner) obtainAccessTokenForResource(ctx context.Context) (*TokenResponse, error) {
	if err := r.requireRedirect(); err != nil {
		return nil, err
	}
	if err := r.requireSession(); err != nil {
		return nil, err
	}
	code, err := r.obtainAuthorizationCode(ctx)
	if err != nil {
		return nil, err
	}
	return r.client.exchangeAuthorizationCode(ctx, code.Code, code.Verifier)
}

// runTokenAuthzSuite 验证扩展联合判定端点：认证、错误、跨 audience、ID Token 混用。
func (r *Runner) runTokenAuthzSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireResourceClient(); err != nil {
		r.skipSuite("缺少资源服务前置条件：" + safeDetail(err))
		return nil
	}
	tokens, tokenErr := r.obtainAccessTokenForResource(ctx)
	if tokenErr != nil {
		r.run("obtain_access_token", func() error { return tokenErr })
		return nil
	}
	audience := r.client.cfg.Audience
	postJSON := func(clientID, secret string, payload map[string]any) (*httpResult, error) {
		data, _ := json.Marshal(payload)
		return r.client.basicRequest(ctx, http.MethodPost, pathTokenAuthorize,
			clientID, secret, "application/json", bytes.NewReader(data))
	}

	r.run("tokenauthz_missing_auth_rejected", func() error {
		result, err := postJSON("", "", map[string]any{
			"access_token": tokens.AccessToken, "permissions": []string{"authorization.check"},
			"audience": audience})
		if err != nil {
			return err
		}
		if result.Status != http.StatusUnauthorized {
			return fmt.Errorf("缺认证应为 401，实际 %d", result.Status)
		}
		return nil
	})
	r.run("tokenauthz_wrong_auth_rejected", func() error {
		result, err := postJSON(r.client.cfg.ResourceClientID, "wrong-secret",
			map[string]any{"access_token": tokens.AccessToken,
				"permissions": []string{"authorization.check"}, "audience": audience})
		if err != nil {
			return err
		}
		if result.Status != http.StatusUnauthorized {
			return fmt.Errorf("错误认证应为 401，实际 %d", result.Status)
		}
		return nil
	})
	r.run("tokenauthz_authenticated_decision", func() error {
		result, err := postJSON(r.client.cfg.ResourceClientID, r.client.cfg.ResourceClientSecret,
			map[string]any{"access_token": tokens.AccessToken,
				"permissions": []string{"authorization.check"}, "audience": audience})
		if err != nil {
			return err
		}
		if result.Status != http.StatusOK {
			return fmt.Errorf("已认证请求应返回 200，实际 %d", result.Status)
		}
		var decision struct {
			Allow     bool   `json:"allow"`
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		}
		if err := result.decodeJSON(&decision); err != nil {
			return err
		}
		if !decision.Allow && decision.Code == "" {
			return fmt.Errorf("业务拒绝缺少稳定 code")
		}
		if decision.RequestID == "" {
			return fmt.Errorf("响应缺少 request_id")
		}
		return nil
	})
	r.run("tokenauthz_cross_audience_rejected", func() error {
		result, err := postJSON(r.client.cfg.ResourceClientID, r.client.cfg.ResourceClientSecret,
			map[string]any{"access_token": tokens.AccessToken,
				"permissions": []string{"authorization.check"},
				"audience":    "https://loginte2e.invalid/api"})
		if err != nil {
			return err
		}
		if result.Status != http.StatusForbidden {
			return fmt.Errorf("跨 audience 应为 403，实际 %d", result.Status)
		}
		return nil
	})
	r.run("tokenauthz_unknown_field_rejected", func() error {
		result, err := postJSON(r.client.cfg.ResourceClientID, r.client.cfg.ResourceClientSecret,
			map[string]any{"access_token": tokens.AccessToken,
				"permissions": []string{"authorization.check"}, "audience": audience,
				"app_id": "spoofed-app"})
		if err != nil {
			return err
		}
		if result.Status != http.StatusBadRequest {
			return fmt.Errorf("未知字段应为 400，实际 %d", result.Status)
		}
		return nil
	})
	r.run("tokenauthz_id_token_rejected", func() error {
		if tokens.IDToken == "" {
			return skipf("授权响应未返回 id_token")
		}
		result, err := postJSON(r.client.cfg.ResourceClientID, r.client.cfg.ResourceClientSecret,
			map[string]any{"access_token": tokens.IDToken,
				"permissions": []string{"authorization.check"}, "audience": audience})
		if err != nil {
			return err
		}
		if result.Status != http.StatusOK {
			return fmt.Errorf("ID Token 混用应作为业务拒绝返回 200，实际 %d", result.Status)
		}
		var decision struct {
			Allow bool `json:"allow"`
		}
		if err := result.decodeJSON(&decision); err != nil {
			return err
		}
		if decision.Allow {
			return fmt.Errorf("ID Token 不能作为 access token 通过")
		}
		return nil
	})
	return nil
}

// runIntrospectSuite 验证标准 RFC 7662 状态查询契约。
func (r *Runner) runIntrospectSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireResourceClient(); err != nil {
		r.skipSuite("缺少资源服务前置条件：" + safeDetail(err))
		return nil
	}
	tokens, tokenErr := r.obtainAccessTokenForResource(ctx)
	if tokenErr != nil {
		r.run("obtain_access_token", func() error { return tokenErr })
		return nil
	}
	audience := r.client.cfg.Audience
	introspect := func(secret, token, aud string) (*httpResult, error) {
		form := url.Values{"token": {token}}
		if aud != "" {
			form.Set("audience", aud)
		}
		return r.client.basicRequest(ctx, http.MethodPost, pathIntrospect,
			r.client.cfg.ResourceClientID, secret, "application/x-www-form-urlencoded",
			strings.NewReader(form.Encode()))
	}
	decode := func(result *httpResult) (map[string]any, error) {
		payload := map[string]any{}
		if err := result.decodeJSON(&payload); err != nil {
			return nil, err
		}
		return payload, nil
	}

	r.run("introspect_active_own_audience", func() error {
		result, err := introspect(r.client.cfg.ResourceClientSecret, tokens.AccessToken, audience)
		if err != nil {
			return err
		}
		if result.Status != http.StatusOK {
			return fmt.Errorf("introspect 应 200，实际 %d", result.Status)
		}
		payload, err := decode(result)
		if err != nil {
			return err
		}
		if payload["active"] != true {
			return fmt.Errorf("有效令牌应 active")
		}
		if payload["sub"] != nil {
			return fmt.Errorf("跨资源不应返回 sub")
		}
		return nil
	})
	r.run("introspect_wrong_auth_rejected", func() error {
		result, err := introspect("wrong-secret", tokens.AccessToken, audience)
		if err != nil {
			return err
		}
		if result.Status != http.StatusUnauthorized {
			return fmt.Errorf("错误认证应为 401，实际 %d", result.Status)
		}
		return nil
	})
	r.run("introspect_unknown_token_inactive", func() error {
		result, err := introspect(r.client.cfg.ResourceClientSecret, "not-a-real-token", audience)
		if err != nil {
			return err
		}
		if result.Status != http.StatusOK {
			return fmt.Errorf("未知令牌应 200，实际 %d", result.Status)
		}
		payload, err := decode(result)
		if err != nil {
			return err
		}
		if payload["active"] != false {
			return fmt.Errorf("未知令牌必须 inactive")
		}
		return nil
	})
	r.run("introspect_cross_audience_not_active", func() error {
		result, err := introspect(r.client.cfg.ResourceClientSecret, tokens.AccessToken,
			"https://loginte2e.invalid/api")
		if err != nil {
			return err
		}
		if result.Status == http.StatusOK {
			payload, err := decode(result)
			if err != nil {
				return err
			}
			if payload["active"] == true {
				return fmt.Errorf("跨 audience 不应 active")
			}
			return nil
		}
		if result.Status != http.StatusForbidden && result.Status != http.StatusUnauthorized {
			return fmt.Errorf("跨 audience 拒绝状态异常: %d", result.Status)
		}
		return nil
	})
	r.run("introspect_id_token_not_active", func() error {
		if tokens.IDToken == "" {
			return skipf("授权响应未返回 id_token")
		}
		result, err := introspect(r.client.cfg.ResourceClientSecret, tokens.IDToken, audience)
		if err != nil {
			return err
		}
		if result.Status != http.StatusOK {
			return fmt.Errorf("ID Token 状态查询应 200，实际 %d", result.Status)
		}
		payload, err := decode(result)
		if err != nil {
			return err
		}
		if payload["active"] == true {
			return fmt.Errorf("ID Token 不应 active")
		}
		return nil
	})
	return nil
}
