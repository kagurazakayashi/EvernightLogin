package loginte2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// 扫码登录端点使用项目统一错误信封 {code,message,request_id}；确认端使用真实
// 完整会话（Bearer 会话秘密时无浏览器环境凭据，不需要 CSRF 头，但状态修改端点
// 仍必须带同源 Origin）。

// qrBegin 是创建扫码请求的响应投影。ClaimSecret 是领取绑定（一次性秘密），
// QRPayload 只应包含一次性 request_id。
type qrBegin struct {
	RequestID           string `json:"request_id"`
	QRPayload           string `json:"qr_payload"`
	ClaimSecret         string `json:"claim_secret"`
	ExpiresAt           string `json:"expires_at"`
	Version             int64  `json:"version"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

// qrStatus 是扫码状态轮询响应投影。
type qrStatus struct {
	RequestID         string `json:"request_id"`
	Status            string `json:"status"`
	ExpiresAt         string `json:"expires_at"`
	Version           int64  `json:"version"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// qrPrompt 是确认端只读上下文投影（不含任何秘密）。
type qrPrompt struct {
	RequestID   string   `json:"request_id"`
	ClientID    string   `json:"client_id"`
	Status      string   `json:"status"`
	Scopes      []string `json:"scopes"`
	Version     int64    `json:"version"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at"`
	RequesterUA string   `json:"requester_user_agent"`
	Warning     string   `json:"warning"`
}

// qrClaimResult 是领取结果投影（只含会话标识，不含会话秘密或 Token）。
type qrClaimResult struct {
	Status    string `json:"status"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	AppID     string `json:"app_id"`
	ExpiresAt string `json:"expires_at"`
}

// qrBeginRequest 创建一次扫码登录请求。
func (c *Client) qrRequest(ctx context.Context) (*qrBegin, error) {
	result, err := c.do(ctx, "POST", pathQRRequest, requestOptions{
		jsonBody: map[string]any{"client_id": c.cfg.ClientID}})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("扫码创建返回意外状态 HTTP %d", result.Status)
	}
	var payload qrBegin
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	if payload.RequestID == "" || payload.ClaimSecret == "" || payload.QRPayload == "" {
		return nil, fmt.Errorf("扫码创建响应缺少请求标识/领取绑定/二维码载荷")
	}
	return &payload, nil
}

// qrStatusQuery 查询扫码请求状态。
func (c *Client) qrStatusQuery(ctx context.Context, requestID, claimSecret string) (*qrStatus, error) {
	result, err := c.do(ctx, "POST", pathQRStatus, requestOptions{
		jsonBody: map[string]any{"request_id": requestID, "claim_secret": claimSecret}})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("扫码状态查询返回意外状态 HTTP %d", result.Status)
	}
	var payload qrStatus
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// qrPromptQuery 用已登录会话读取确认端上下文。
func (c *Client) qrPromptQuery(ctx context.Context, requestID string) (*qrPrompt, error) {
	result, err := c.do(ctx, "GET", pathQRPrompt+"?"+url.Values{"request_id": {requestID}}.Encode(),
		requestOptions{bearer: c.cfg.SessionSecret})
	if err != nil {
		return nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, problem
		}
		return nil, fmt.Errorf("扫码确认上下文返回意外状态 HTTP %d", result.Status)
	}
	var payload qrPrompt
	if err := result.decodeJSON(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// qrDecide 以已登录会话批准/拒绝扫码请求。
func (c *Client) qrDecide(ctx context.Context, requestID string, version int64, approve bool) error {
	result, err := c.do(ctx, "POST", pathQRDecision, requestOptions{
		bearer: c.cfg.SessionSecret,
		jsonBody: map[string]any{"request_id": requestID, "expected_version": version,
			"approve": approve},
		originIssuer: true,
	})
	if err != nil {
		return err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return problem
		}
		return fmt.Errorf("扫码决定返回意外状态 HTTP %d", result.Status)
	}
	return nil
}

// qrClaimRequest 领取扫码结果；返回响应中的会话 Cookie（值不写入报告）。
func (c *Client) qrClaim(ctx context.Context, requestID, claimSecret string) (*qrClaimResult,
	*http.Cookie, error) {
	result, err := c.do(ctx, "POST", pathQRClaim, requestOptions{
		jsonBody: map[string]any{"request_id": requestID, "claim_secret": claimSecret}})
	if err != nil {
		return nil, nil, err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return nil, nil, problem
		}
		return nil, nil, fmt.Errorf("扫码领取返回意外状态 HTTP %d", result.Status)
	}
	var payload qrClaimResult
	if err := result.decodeJSON(&payload); err != nil {
		return nil, nil, err
	}
	for _, cookie := range (&http.Response{Header: result.Header}).Cookies() {
		if cookie != nil && cookie.Value != "" {
			return &payload, cookie, nil
		}
	}
	return &payload, nil, nil
}

// qrCancelRequest 取消仍未领取的扫码请求。
func (c *Client) qrCancelRequest(ctx context.Context, requestID, claimSecret string) error {
	result, err := c.do(ctx, "POST", pathQRCancel, requestOptions{
		jsonBody: map[string]any{"request_id": requestID, "claim_secret": claimSecret}})
	if err != nil {
		return err
	}
	if result.Status != 200 {
		if problem := result.problem(); problem != nil {
			return problem
		}
		return fmt.Errorf("扫码取消返回意外状态 HTTP %d", result.Status)
	}
	return nil
}

// pollQRStatus 按服务端 retry_after_seconds 轮询直到状态达到期望值或超时。
func (r *Runner) pollQRStatus(ctx context.Context, requestID, claimSecret,
	want string) (*qrStatus, error) {
	deadline := time.Now().Add(r.client.cfg.PollTimeout)
	lastStatus := ""
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("扫码状态在 %s 内未变为 %s（最后状态 %q）",
				r.client.cfg.PollTimeout, want, lastStatus)
		}
		status, err := r.client.qrStatusQuery(ctx, requestID, claimSecret)
		if err != nil {
			if problem, ok := err.(*HTTPError); ok && problem.Code == "RATE_LIMITED" {
				if sleepErr := sleepContext(ctx, time.Second); sleepErr != nil {
					return nil, sleepErr
				}
				continue
			}
			return nil, err
		}
		if status.Status == want {
			return status, nil
		}
		lastStatus = status.Status
		wait := time.Duration(status.RetryAfterSeconds) * time.Second
		if wait <= 0 {
			wait = time.Second
		}
		if wait > 15*time.Second {
			wait = 15 * time.Second
		}
		if sleepErr := sleepContext(ctx, wait); sleepErr != nil {
			return nil, sleepErr
		}
	}
}

// runQRSuite 验证扫码登录全流程与安全负例。
func (r *Runner) runQRSuite(ctx context.Context) error {
	if _, err := r.document(ctx); err != nil {
		return err
	}
	if err := r.requireClient(); err != nil {
		r.skipSuite("缺少 --client-id：" + safeDetail(err))
		return nil
	}

	var created *qrBegin
	r.run("qr_request_created", func() error {
		request, err := r.client.qrRequest(ctx)
		if err != nil {
			return err
		}
		if request.PollIntervalSeconds <= 0 {
			created = request
			return fmt.Errorf("poll_interval_seconds 必须为正数")
		}
		created = request
		return nil
	})
	// 未领取的请求在套件结束时尽量取消，避免留下悬挂记录（best effort）。
	defer func() {
		if created != nil {
			_ = r.client.qrCancelRequest(context.WithoutCancel(ctx), created.RequestID,
				created.ClaimSecret)
		}
	}()

	r.run("qr_payload_has_no_secrets", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		if created.ClaimSecret == "" {
			return fmt.Errorf("创建响应缺少领取绑定")
		}
		if len(created.QRPayload) > 4096 {
			return fmt.Errorf("二维码载荷异常过长")
		}
		// 二维码/状态对象里绝不能出现领取绑定或令牌。
		for _, forbidden := range []string{created.ClaimSecret, "access_token", "refresh_token",
			"id_token", "claim_secret"} {
			if forbidden != "" && containsStringFold(created.QRPayload, forbidden) {
				return fmt.Errorf("二维码载荷包含不应出现的内容（秘密或令牌字段）")
			}
		}
		if !containsStringFold(created.QRPayload, created.RequestID) {
			return fmt.Errorf("二维码载荷未包含一次性请求标识")
		}
		return nil
	})

	r.run("qr_wrong_claim_secret_rejected", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		wrong := "invalid-claim-secret-for-negative-test"
		if _, err := r.client.qrStatusQuery(ctx, created.RequestID, wrong); err == nil {
			return fmt.Errorf("错误领取绑定仍能查询状态")
		}
		return nil
	})

	r.run("qr_status_pending", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		status, err := r.client.qrStatusQuery(ctx, created.RequestID, created.ClaimSecret)
		if err != nil {
			return err
		}
		if status.Status != "pending" {
			return fmt.Errorf("新请求状态应为 pending，实际 %q", status.Status)
		}
		if status.Version < created.Version {
			return fmt.Errorf("状态版本不应小于创建版本")
		}
		return nil
	})

	r.run("qr_prompt_requires_session", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		// 不带会话访问确认端上下文必须被拒绝（401），不能泄露请求详情。
		result, err := r.client.do(ctx, "GET",
			pathQRPrompt+"?"+url.Values{"request_id": {created.RequestID}}.Encode(),
			requestOptions{})
		if err != nil {
			return err
		}
		if result.Status != 401 {
			return fmt.Errorf("匿名读取确认上下文应为 401，实际 HTTP %d", result.Status)
		}
		return nil
	})

	if err := r.requireSession(); err != nil {
		for _, name := range []string{"qr_prompt_context", "qr_decision_approve",
			"qr_status_approved", "qr_claim_issues_session", "qr_claim_replay_rejected",
			"qr_cross_user_claim_requires_binding"} {
			r.run(name, func() error { return err })
		}
		r.run("qr_cancel_flow", func() error { return r.cancelFlow(ctx) })
		return nil
	}

	var (
		prompt   *qrPrompt
		claimed  bool
		sessionC *http.Cookie
	)
	r.run("qr_prompt_context", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		contextInfo, err := r.client.qrPromptQuery(ctx, created.RequestID)
		if err != nil {
			return err
		}
		if contextInfo.ClientID != r.client.cfg.ClientID {
			return fmt.Errorf("确认上下文 client_id 与请求不一致")
		}
		if contextInfo.Status != "pending" {
			return fmt.Errorf("确认上下文状态应为 pending，实际 %q", contextInfo.Status)
		}
		if contextInfo.Version <= 0 {
			return fmt.Errorf("确认上下文缺少版本号")
		}
		prompt = contextInfo
		return nil
	})

	r.run("qr_decision_approve", func() error {
		if prompt == nil {
			return skipf("前置用例未取得确认上下文")
		}
		return r.client.qrDecide(ctx, created.RequestID, prompt.Version, true)
	})

	r.run("qr_status_approved", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		status, err := r.pollQRStatus(ctx, created.RequestID, created.ClaimSecret, "approved")
		if err != nil {
			return err
		}
		if status.Version < prompt.Version {
			return fmt.Errorf("批准后状态版本不应回退")
		}
		return nil
	})

	r.run("qr_claim_issues_session", func() error {
		if created == nil {
			return skipf("前置用例未创建扫码请求")
		}
		result, cookie, err := r.client.qrClaim(ctx, created.RequestID, created.ClaimSecret)
		if err != nil {
			return err
		}
		if cookie == nil {
			return fmt.Errorf("领取成功必须写入目标应用会话 Cookie")
		}
		if result.UserID == "" || result.SessionID == "" {
			return fmt.Errorf("领取结果缺少用户/会话标识")
		}
		if result.AppID != "" && result.AppID != r.client.cfg.ClientID {
			return fmt.Errorf("领取结果的应用与请求不一致")
		}
		claimed = true
		sessionC = cookie
		return nil
	})

	r.run("qr_claim_replay_rejected", func() error {
		if !claimed {
			return skipf("前置用例未成功领取")
		}
		_, _, err := r.client.qrClaim(ctx, created.RequestID, created.ClaimSecret)
		if err == nil {
			return fmt.Errorf("同一领取绑定第二次领取不应成功")
		}
		problem, ok := err.(*HTTPError)
		if !ok {
			return fmt.Errorf("重复领取期望稳定错误码，实际 %v", err)
		}
		if problem.Code != "CHALLENGE_INVALID" && problem.Code != "ACCESS_DENIED" &&
			problem.Code != "CONFLICT" {
			return fmt.Errorf("重复领取错误码不符合预期：%v", problem)
		}
		return nil
	})

	r.run("qr_cross_user_claim_requires_binding", func() error {
		if !claimed || sessionC == nil {
			return skipf("前置用例未成功领取")
		}
		// 领取绑定缺失时，即使知道 request_id 也不能领取（410/401）。
		result, err := r.client.do(ctx, "POST", pathQRClaim, requestOptions{
			jsonBody: map[string]any{"request_id": created.RequestID,
				"claim_secret": "invalid-claim-secret-for-negative-test"}})
		if err != nil {
			return err
		}
		if result.isSuccess() {
			return fmt.Errorf("错误领取绑定仍能领取会话")
		}
		return nil
	})

	r.run("qr_cancel_flow", func() error { return r.cancelFlow(ctx) })
	return nil
}

// cancelFlow 验证取消语义：创建 → 取消 → 状态为 cancelled → 领取被拒绝。
func (r *Runner) cancelFlow(ctx context.Context) error {
	request, err := r.client.qrRequest(ctx)
	if err != nil {
		return err
	}
	if err := r.client.qrCancelRequest(ctx, request.RequestID, request.ClaimSecret); err != nil {
		return err
	}
	status, err := r.client.qrStatusQuery(ctx, request.RequestID, request.ClaimSecret)
	if err != nil {
		return err
	}
	if status.Status != "cancelled" {
		return fmt.Errorf("取消后状态应为 cancelled，实际 %q", status.Status)
	}
	if _, _, claimErr := r.client.qrClaim(ctx, request.RequestID, request.ClaimSecret); claimErr == nil {
		return fmt.Errorf("已取消的扫码请求仍能领取会话")
	}
	return nil
}

// containsStringFold 判断 haystack 是否包含 needle（大小写不敏感）。
func containsStringFold(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	if len(needle) > len(haystack) {
		return false
	}
	lowerHaystack := []byte(haystack)
	for index := range lowerHaystack {
		if lowerHaystack[index] >= 'A' && lowerHaystack[index] <= 'Z' {
			lowerHaystack[index] += 'a' - 'A'
		}
	}
	lowerNeedle := []byte(needle)
	for index := range lowerNeedle {
		if lowerNeedle[index] >= 'A' && lowerNeedle[index] <= 'Z' {
			lowerNeedle[index] += 'a' - 'A'
		}
	}
	for start := 0; start+len(lowerNeedle) <= len(lowerHaystack); start++ {
		matched := true
		for offset := range lowerNeedle {
			if lowerHaystack[start+offset] != lowerNeedle[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
