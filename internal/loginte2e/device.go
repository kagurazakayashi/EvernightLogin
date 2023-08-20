package loginte2e

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DeviceConfirmFunc 注入“已登录用户确认设备码”的能力。协议包不提供确认页 HTTP
// 端点（确认页由宿主页面层实现），因此：
//   - 库使用者（集成测试）可以直接调用真实 oauthflow.Service.DecideDeviceAuthorization；
//   - 命令行在显式给出 --device-confirm-url 时使用通用 HTML 表单驱动；
//   - 两者都没有时，设备码套件如实 skip 确认与领令牌步骤，不伪造成功。
type DeviceConfirmFunc func(ctx context.Context, userCode string) error

// deviceAuthorization 是设备授权申请响应投影。device_code/user_code 是秘密/敏感
// 值，只放内存。
type deviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int64
	Interval                int64
}

// beginDeviceAuthorization 申请设备授权。scope 为空时不发送 scope 参数。
func (c *Client) beginDeviceAuthorization(ctx context.Context, scope string) (*deviceAuthorization, error) {
	form := c.clientAuthFields(url.Values{})
	if strings.TrimSpace(scope) != "" {
		form.Set("scope", scope)
	}
	result, err := c.do(ctx, "POST", pathDeviceAuthorization, requestOptions{form: form})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("设备授权申请返回意外状态 HTTP %d", result.Status)
	}
	var payload struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	if payload.DeviceCode == "" || payload.UserCode == "" {
		return nil, fmt.Errorf("设备授权响应缺少 device_code/user_code")
	}
	if payload.VerificationURI == "" {
		return nil, fmt.Errorf("设备授权响应缺少 verification_uri")
	}
	if payload.ExpiresIn <= 0 || payload.Interval <= 0 {
		return nil, fmt.Errorf("设备授权响应的 expires_in/interval 必须为正数")
	}
	return &deviceAuthorization{DeviceCode: payload.DeviceCode, UserCode: payload.UserCode,
		VerificationURI:         payload.VerificationURI,
		VerificationURIComplete: payload.VerificationURIComplete,
		ExpiresIn:               payload.ExpiresIn, Interval: payload.Interval}, nil
}

// deviceTokenOnce 轮询一次设备码令牌端点。返回 (令牌, 建议等待, 错误)：
// authorization_pending/slow_down 通过错误码表达，调用方决定是否继续轮询。
func (c *Client) deviceTokenOnce(ctx context.Context, deviceCode string) (*TokenResponse,
	time.Duration, error) {
	form := c.clientAuthFields(url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	result, err := c.tokenForm(ctx, form)
	if err != nil {
		return nil, 0, err
	}
	if result.Status == 200 {
		tokens, parseErr := parseTokenResponse(result)
		return tokens, 0, parseErr
	}
	retry := retryAfterDuration(result)
	if problem, ok := result.problem().(*HTTPError); ok {
		return nil, retry, problem
	}
	return nil, retry, fmt.Errorf("设备码轮询返回意外状态 HTTP %d", result.Status)
}

// cancelDeviceAuthorization 取消仍在等待的设备授权（本包扩展端点）。
func (c *Client) cancelDeviceAuthorization(ctx context.Context, deviceCode string) error {
	form := c.clientAuthFields(url.Values{"device_code": {deviceCode}})
	result, err := c.do(ctx, "POST", pathDeviceCancel, requestOptions{form: form})
	if err != nil {
		return err
	}
	if result.Status != 204 {
		if problem := result.problem(); problem != nil {
			return problem
		}
		return fmt.Errorf("设备取消端点返回意外状态 HTTP %d", result.Status)
	}
	return nil
}

// retryAfterDuration 读取 Retry-After 秒数（缺失或非法返回 0）。
func retryAfterDuration(result *httpResult) time.Duration {
	raw := strings.TrimSpace(result.Header.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 || seconds > 3600 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// deviceOAuthCode 返回错误里的 OAuth 错误码（非 OAuth 错误返回空串）。
func deviceOAuthCode(err error) string {
	var problem *HTTPError
	if errors.As(err, &problem) {
		return problem.Code
	}
	return ""
}

// pollDeviceTokens 按服务端 interval/slow_down 规则轮询直到拿到令牌或超时。
func (r *Runner) pollDeviceTokens(ctx context.Context, deviceCode string,
	initialInterval time.Duration) (*TokenResponse, error) {
	if initialInterval <= 0 {
		initialInterval = 5 * time.Second
	}
	interval := initialInterval
	deadline := time.Now().Add(r.client.cfg.PollTimeout)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("设备码轮询超过 %s 仍未取得令牌", r.client.cfg.PollTimeout)
		}
		tokens, retry, err := r.client.deviceTokenOnce(ctx, deviceCode)
		if err == nil {
			return tokens, nil
		}
		switch deviceOAuthCode(err) {
		case "authorization_pending":
			wait := interval
			if retry > wait {
				wait = retry
			}
			if sleepErr := sleepContext(ctx, wait); sleepErr != nil {
				return nil, sleepErr
			}
		case "slow_down":
			if retry > 0 {
				interval = retry
			} else {
				interval += 5 * time.Second
			}
			if sleepErr := sleepContext(ctx, interval); sleepErr != nil {
				return nil, sleepErr
			}
		default:
			return nil, err
		}
	}
}

// beginDeviceAuthorizationScoped 申请设备授权：先用配置 scope，若被 invalid_scope
// 拒绝则退回最小 profile（设备客户端登记 scope 可能与 OIDC 客户端不同）。
func (r *Runner) beginDeviceAuthorizationScoped(ctx context.Context) (*deviceAuthorization, error) {
	authorization, err := r.client.beginDeviceAuthorization(ctx,
		strings.Join(r.client.cfg.Scopes, " "))
	if err == nil {
		return authorization, nil
	}
	if deviceOAuthCode(err) != "invalid_scope" {
		return nil, err
	}
	return r.client.beginDeviceAuthorization(ctx, "profile")
}

// deviceScopeCandidates 返回设备授权申请要尝试的 scope：先用户配置值，若被
// invalid_scope 拒绝再退到最小集（设备客户端登记 scope 可能与 OIDC 客户端不同）。
func (r *Runner) deviceScopeCandidates() []string {
	configured := strings.TrimSpace(strings.Join(r.client.cfg.Scopes, " "))
	candidates := []string{configured}
	if configured != "profile" {
		candidates = append(candidates, "profile")
	}
	return candidates
}

// runDeviceSuite 验证 RFC 8628 设备码流程。
func (r *Runner) runDeviceSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireClient(); err != nil {
		r.skipSuite("缺少 --client-id：" + safeDetail(err))
		return nil
	}

	var (
		authorization *deviceAuthorization
		issued        *TokenResponse
	)

	r.run("device_authorization_begin", func() error {
		var lastErr error
		for _, scope := range r.deviceScopeCandidates() {
			authorization, lastErr = r.client.beginDeviceAuthorization(ctx, scope)
			if lastErr == nil {
				break
			}
			if deviceOAuthCode(lastErr) != "invalid_scope" {
				break
			}
			authorization = nil
		}
		if lastErr != nil {
			return lastErr
		}
		if authorization.VerificationURIComplete != "" &&
			!strings.Contains(authorization.VerificationURIComplete, "user_code=") {
			return fmt.Errorf("verification_uri_complete 未携带 user_code")
		}
		return nil
	})

	r.run("device_poll_authorization_pending", func() error {
		if authorization == nil {
			return skipf("前置用例未取得设备码")
		}
		tokens, _, err := r.client.deviceTokenOnce(ctx, authorization.DeviceCode)
		if err == nil || tokens != nil {
			return fmt.Errorf("未确认前轮询不应取得令牌")
		}
		code := deviceOAuthCode(err)
		if code != "authorization_pending" && code != "slow_down" {
			return fmt.Errorf("未确认前轮询期望 authorization_pending/slow_down，实际 %v", err)
		}
		return nil
	})

	confirmer := r.deviceConfirmer()
	if confirmer == nil {
		r.run("device_confirm_and_token", func() error {
			return skipf("协议包不提供设备确认页端点：需注入 DeviceConfirmFunc（库测试）或用 --device-confirm-url 驱动宿主确认页")
		})
	} else {
		r.run("device_confirm_and_token", func() error {
			if authorization == nil {
				return skipf("前置用例未取得设备码")
			}
			if err := confirmer(ctx, authorization.UserCode); err != nil {
				return err
			}
			tokens, err := r.pollDeviceTokens(ctx, authorization.DeviceCode,
				time.Duration(authorization.Interval)*time.Second)
			if err != nil {
				return err
			}
			if tokens.TokenType != "Bearer" || tokens.AccessToken == "" {
				return fmt.Errorf("设备码令牌响应异常")
			}
			issued = tokens
			return nil
		})
	}

	r.run("device_code_replay_rejected", func() error {
		if issued == nil {
			return skipf("前置用例未取得设备码令牌")
		}
		_, _, err := r.client.deviceTokenOnce(ctx, authorization.DeviceCode)
		if err == nil {
			return fmt.Errorf("已领令牌的设备码重复轮询不应成功")
		}
		code := deviceOAuthCode(err)
		if code != "invalid_grant" && code != "expired_token" {
			return fmt.Errorf("设备码重放期望 invalid_grant，实际 %v", err)
		}
		return nil
	})

	r.run("device_cancel_flow", func() error {
		second, err := r.client.beginDeviceAuthorization(ctx,
			strings.Join(r.client.cfg.Scopes, " "))
		if err != nil {
			if deviceOAuthCode(err) != "invalid_scope" {
				return err
			}
			second, err = r.client.beginDeviceAuthorization(ctx, "profile")
			if err != nil {
				return err
			}
		}
		if err := r.client.cancelDeviceAuthorization(ctx, second.DeviceCode); err != nil {
			return err
		}
		if _, _, pollErr := r.client.deviceTokenOnce(ctx, second.DeviceCode); pollErr == nil {
			return fmt.Errorf("已取消的设备授权仍能取得令牌")
		}
		return nil
	})

	r.run("device_poll_slow_down", func() error {
		pending, err := r.beginDeviceAuthorizationScoped(ctx)
		if err != nil {
			return err
		}
		// 第一次轮询占用轮询槽位：用户尚未确认 → authorization_pending。
		if _, _, pollErr := r.client.deviceTokenOnce(ctx, pending.DeviceCode); deviceOAuthCode(pollErr) != "authorization_pending" {
			return fmt.Errorf("首次轮询期望 authorization_pending，实际 %v", pollErr)
		}
		// 紧接着再次轮询：服务端强制间隔生效 → slow_down，并提示客户端增大间隔。
		_, retry, slowErr := r.client.deviceTokenOnce(ctx, pending.DeviceCode)
		if deviceOAuthCode(slowErr) != "slow_down" {
			return fmt.Errorf("过快轮询期望 slow_down，实际 %v", slowErr)
		}
		if retry <= 0 {
			return fmt.Errorf("slow_down 响应缺少合法 Retry-After")
		}
		// 清理本次等待中的请求（取消只影响该请求，不影响其他授权）。
		return r.client.cancelDeviceAuthorization(ctx, pending.DeviceCode)
	})

	r.run("device_begin_requires_client", func() error {
		result, err := r.client.do(ctx, "POST", pathDeviceAuthorization, requestOptions{
			form: url.Values{}})
		if err != nil {
			return err
		}
		if result.isSuccess() {
			return fmt.Errorf("缺少 client_id 的设备授权申请不应成功")
		}
		if _, problemErr := result.expectProblem(0, "invalid_client", "CLIENT_AUTH_FAILED",
			"REQ_INVALID"); problemErr != nil {
			return problemErr
		}
		return nil
	})
	return nil
}

// deviceConfirmer 返回可用的设备确认能力：优先库使用者注入的函数，其次显式配置
// 的宿主确认页驱动。都没有返回 nil（调用方按 skip 处理）。
func (r *Runner) deviceConfirmer() DeviceConfirmFunc {
	if r.client.cfg.DeviceConfirm != nil {
		return r.client.cfg.DeviceConfirm
	}
	if strings.TrimSpace(r.client.cfg.DeviceConfirmURL) != "" {
		return r.client.pageDeviceConfirmer()
	}
	return nil
}

// hiddenInputPattern 匹配 HTML 隐藏字段；契约页面由宿主实现，这里只做通用驱动。
var (
	formActionPattern  = regexp.MustCompile(`(?is)<form[^>]*action="([^"]+)"`)
	hiddenInputPattern = regexp.MustCompile(`(?is)<input[^>]*>`)
	inputNamePattern   = regexp.MustCompile(`(?is)name="([^"]+)"`)
	inputValuePattern  = regexp.MustCompile(`(?is)value="([^"]*)"`)
	inputTypePattern   = regexp.MustCompile(`(?is)type="([^"]+)"`)
)

// pageDeviceConfirmer 构造一个“驱动宿主设备确认页”的确认函数（实验性）：
// 读取确认页 → 收集隐藏字段 → 带上 user_code 与决定值提交。宿主确认页必须自行
// 校验真实会话/CSRF/同源；工具不绕过这些检查，失败即如实报告。
func (c *Client) pageDeviceConfirmer() DeviceConfirmFunc {
	return func(ctx context.Context, userCode string) error {
		if c.cfg.SessionSecret == "" {
			return skipf("驱动设备确认页需要 --session-cookie-file：确认页要求真实登录会话")
		}
		pagePath := strings.ReplaceAll(c.cfg.DeviceConfirmURL, "{code}", url.QueryEscape(userCode))
		if !strings.Contains(c.cfg.DeviceConfirmURL, "{code}") {
			separator := "?"
			if strings.Contains(pagePath, "?") {
				separator = "&"
			}
			pagePath += separator + "user_code=" + url.QueryEscape(userCode)
		}
		requestURL := pagePath
		if strings.HasPrefix(pagePath, "/") {
			requestURL = c.baseText + pagePath
		}
		result, err := c.doAbsolute(ctx, "GET", requestURL, requestOptions{
			bearer: c.cfg.SessionSecret})
		if err != nil {
			return err
		}
		if result.Status != 200 {
			if problem := result.problem(); problem != nil {
				return problem
			}
			return fmt.Errorf("设备确认页返回 HTTP %d", result.Status)
		}
		action, values, found := parseHTMLForm(result.Body)
		if !found {
			return fmt.Errorf("设备确认页未找到可提交的表单")
		}
		if values.Get("user_code") == "" {
			values.Set("user_code", userCode)
		}
		if values.Has("decision") {
			values.Set("decision", c.cfg.DeviceConfirmDecision)
		} else if values.Has("approve") {
			values.Set("approve", "true")
		} else {
			values.Set("decision", c.cfg.DeviceConfirmDecision)
		}
		postURL := action
		if strings.HasPrefix(action, "/") {
			postURL = c.baseText + action
		} else if !strings.HasPrefix(action, "http://") && !strings.HasPrefix(action, "https://") {
			postURL = requestURL + "/" + action
		}
		posted, err := c.doAbsolute(ctx, "POST", postURL, requestOptions{
			bearer: c.cfg.SessionSecret, form: values, originIssuer: true})
		if err != nil {
			return err
		}
		if posted.Status >= 400 {
			if problem := posted.problem(); problem != nil {
				return problem
			}
			return fmt.Errorf("设备确认提交返回 HTTP %d", posted.Status)
		}
		return nil
	}
}

// parseHTMLForm 从页面解析第一个表单的 action 与全部隐藏字段值。
func parseHTMLForm(body []byte) (string, url.Values, bool) {
	actionMatch := formActionPattern.FindSubmatch(body)
	if len(actionMatch) < 2 {
		return "", nil, false
	}
	values := url.Values{}
	for _, tag := range hiddenInputPattern.FindAll(body, -1) {
		typeMatch := inputTypePattern.FindSubmatch(tag)
		if len(typeMatch) < 2 || !strings.EqualFold(string(typeMatch[1]), "hidden") {
			continue
		}
		nameMatch := inputNamePattern.FindSubmatch(tag)
		if len(nameMatch) < 2 {
			continue
		}
		value := ""
		if valueMatch := inputValuePattern.FindSubmatch(tag); len(valueMatch) >= 2 {
			value = string(valueMatch[1])
		}
		values.Set(string(nameMatch[1]), value)
	}
	return string(actionMatch[1]), values, true
}
