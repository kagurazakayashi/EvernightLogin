package loginte2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// 管理 JSON API 的统一响应信封：成功 {ok:true,request_id,data}，失败
// {ok:false,code,message,request_id}。本套件只调用只读端点与稳定的拒绝路径，
// 不执行任何管理写操作（写操作需要 confirm/原因/敏感策略，测试工具不应产生副作用）。

// adminEnvelope 是管理 API 响应信封的通用投影。
type adminEnvelope struct {
	OK        bool            `json:"ok"`
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data"`
}

// adminURLPath 返回管理 API 的站内相对路径（挂在 server 基础地址之后）。
func (c *Client) adminURLPath(suffix string) string {
	base := "/" + strings.Trim(c.cfg.AdminBasePath, "/")
	if suffix == "" {
		return base
	}
	return base + suffix
}

// adminGet 以管理会话 Bearer 秘密发起 GET；bearer 为空表示匿名（负例）。
func (c *Client) adminGet(ctx context.Context, suffix string, query url.Values,
	bearer string) (*httpResult, error) {
	path := c.adminURLPath(suffix)
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return c.do(ctx, "GET", path, requestOptions{bearer: bearer})
}

// adminMethod 以管理会话 Bearer 秘密发起任意方法（本工具只用 GET 与负例 POST）。
func (c *Client) adminMethod(ctx context.Context, method, suffix string, bearer string) (*httpResult, error) {
	return c.do(ctx, method, c.adminURLPath(suffix), requestOptions{bearer: bearer})
}

// decodeAdmin 解码管理 API 信封。
func decodeAdmin(result *httpResult) (*adminEnvelope, error) {
	var envelope adminEnvelope
	if err := result.decodeJSON(&envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// adminError 断言失败响应是 ok:false 的管理错误信封，并返回错误码。
func adminError(result *httpResult) (*adminEnvelope, error) {
	if result.isSuccess() {
		return nil, fmt.Errorf("期望被拒绝，实际 HTTP %d", result.Status)
	}
	envelope, err := decodeAdmin(result)
	if err != nil {
		return nil, err
	}
	if envelope.OK {
		return nil, fmt.Errorf("失败响应不应标记 ok=true")
	}
	if envelope.Code == "" {
		return nil, fmt.Errorf("失败响应缺少稳定错误码")
	}
	return envelope, nil
}

// describeCode 把稳定错误码格式化为便于阅读的后缀。
func describeCode(code string) string {
	if code == "" {
		return ""
	}
	return "（" + code + "）"
}

// itoa 是稳定的整数格式化（避免为此引入额外依赖语义）。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	if negative {
		digits = append(digits, '-')
	}
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}
	return string(digits)
}

// runAdminSuite 验证管理 JSON API 的只读契约与拒绝路径。
func (r *Runner) runAdminSuite(ctx context.Context) error {
	// 管理 API 不依赖 OIDC Discovery：独立服务可能只挂管理 API 而未挂协议端点。
	// 可达性由第一个管理端点请求自行证明。
	if err := r.requireAdminSession(); err != nil {
		r.skipSuite("缺少管理会话：" + safeDetail(err))
		return nil
	}
	secret := r.client.cfg.AdminSessionSecret

	// 先探测管理 API 是否挂载、提供的管理会话是否被服务端接受。未挂载/会话被拒
	// 属于前置条件问题：整个套件如实 skip（不影响 host 的权限策略是否合理）。
	probe, probeErr := r.client.adminGet(ctx, "/meta", nil, secret)
	if probeErr != nil {
		if isUnavailable(probeErr) {
			return probeErr
		}
		r.skipSuite("管理 API 探测失败：" + safeDetail(probeErr))
		return nil
	}
	switch {
	case probe.Status == 404:
		r.skipSuite("管理 API 未挂载（404）：请确认服务端 --enable-admin-api 与实际前缀")
		return nil
	case probe.Status == 401 || probe.Status == 403:
		code := ""
		if envelope, decodeErr := decodeAdmin(probe); decodeErr == nil {
			code = envelope.Code
		}
		r.skipSuite("管理会话被服务端拒绝" + describeCode(code) +
			"：需要已完成强认证且在新鲜期内的管理会话")
		return nil
	case probe.Status != 200:
		r.skipSuite("管理 API 返回意外状态 HTTP " + itoa(probe.Status))
		return nil
	}

	r.run("admin_meta", func() error {
		result, err := r.client.adminGet(ctx, "/meta", nil, secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return fmt.Errorf("管理 API 未挂载（404）：请确认服务端 --enable-admin-api 与实际前缀")
		}
		if err := result.expectStatus(200); err != nil {
			return err
		}
		envelope, err := decodeAdmin(result)
		if err != nil {
			return err
		}
		if !envelope.OK {
			return fmt.Errorf("成功响应缺少 ok=true")
		}
		var data struct {
			APIVersion string `json:"api_version"`
			BasePath   string `json:"base_path"`
			Auth       struct {
				StrongAuthRequired bool `json:"strong_auth_required"`
				PerRequestReauth   bool `json:"per_request_reauth"`
			} `json:"authentication"`
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			return fmt.Errorf("meta data 不是预期结构")
		}
		if data.APIVersion == "" {
			return fmt.Errorf("meta 缺少 api_version")
		}
		if data.BasePath != "/"+strings.Trim(r.client.cfg.AdminBasePath, "/") {
			return fmt.Errorf("meta base_path 与实际挂载前缀不一致")
		}
		if !data.Auth.StrongAuthRequired || !data.Auth.PerRequestReauth {
			return fmt.Errorf("meta 未声明强认证/每请求重新鉴权契约")
		}
		return nil
	})

	r.run("admin_error_codes", func() error {
		result, err := r.client.adminGet(ctx, "/error-codes", nil, secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if err := result.expectStatus(200); err != nil {
			return err
		}
		envelope, err := decodeAdmin(result)
		if err != nil {
			return err
		}
		var data struct {
			ErrorCodes []struct {
				Code       string `json:"code"`
				Message    string `json:"message"`
				HTTPStatus int    `json:"http_status"`
			} `json:"error_codes"`
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			return fmt.Errorf("error-codes data 不是预期结构")
		}
		if len(data.ErrorCodes) == 0 {
			return fmt.Errorf("错误码投影为空")
		}
		for _, item := range data.ErrorCodes {
			if item.Code == "" || item.Message == "" || item.HTTPStatus < 400 ||
				item.HTTPStatus > 599 {
				return fmt.Errorf("错误码条目字段不完整或状态码非法")
			}
		}
		required := []string{"REQ_INVALID", "AUTH_FAILED"}
		for _, code := range required {
			found := false
			for _, item := range data.ErrorCodes {
				if item.Code == code {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("错误码投影缺少根包已登记码 %s", code)
			}
		}
		return nil
	})

	r.run("admin_error_codes_filter", func() error {
		result, err := r.client.adminGet(ctx, "/error-codes",
			url.Values{"code": {"AUTH_FAILED"}}, secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if err := result.expectStatus(200); err != nil {
			return err
		}
		envelope, err := decodeAdmin(result)
		if err != nil {
			return err
		}
		var data struct {
			ErrorCodes []struct {
				Code string `json:"code"`
			} `json:"error_codes"`
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			return fmt.Errorf("过滤结果不是预期结构")
		}
		if len(data.ErrorCodes) != 1 || data.ErrorCodes[0].Code != "AUTH_FAILED" {
			return fmt.Errorf("错误码过滤未生效（期望恰好 1 条 AUTH_FAILED）")
		}
		return nil
	})

	r.run("admin_unauthenticated_rejected", func() error {
		result, err := r.client.adminGet(ctx, "/meta", nil, "")
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if result.Status != 401 {
			return fmt.Errorf("匿名访问管理 API 应为 401，实际 HTTP %d", result.Status)
		}
		envelope, err := adminError(result)
		if err != nil {
			return err
		}
		if envelope.Code != "AUTH_FAILED" && envelope.Code != "REQ_INVALID" {
			return fmt.Errorf("匿名访问错误码不符合预期：%s", envelope.Code)
		}
		return nil
	})

	r.run("admin_invalid_session_rejected", func() error {
		result, err := r.client.adminGet(ctx, "/meta", nil,
			"invalid-management-session-for-negative-test")
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if result.Status != 401 && result.Status != 403 {
			return fmt.Errorf("无效管理会话应为 401/403，实际 HTTP %d", result.Status)
		}
		if _, err := adminError(result); err != nil {
			return err
		}
		return nil
	})

	r.run("admin_unknown_path_404", func() error {
		result, err := r.client.adminGet(ctx, "/loginte2e-not-found", nil, secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return nil
		}
		// 挂在别的路径时同样应表现为“资源不存在”，而不是 200。
		if result.Status == 401 || result.Status == 403 {
			return nil
		}
		return fmt.Errorf("未知管理路径应 404，实际 HTTP %d", result.Status)
	})

	r.run("admin_method_not_allowed", func() error {
		result, err := r.client.adminMethod(ctx, "POST", "/meta", secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if result.Status != 405 {
			return fmt.Errorf("POST /meta 应为 405，实际 HTTP %d", result.Status)
		}
		if allow := result.Header.Get("Allow"); !strings.Contains(allow, "GET") {
			return fmt.Errorf("405 响应缺少 Allow: GET")
		}
		return nil
	})

	r.run("admin_invalid_query_rejected", func() error {
		result, err := r.client.adminGet(ctx, "/error-codes",
			url.Values{"code": {"AUTH_FAILED", "REQ_INVALID"}}, secret)
		if err != nil {
			return err
		}
		if result.Status == 404 {
			return skipf("管理 API 未挂载（404）")
		}
		if result.Status != 400 {
			return fmt.Errorf("重复查询参数应为 400，实际 HTTP %d", result.Status)
		}
		if _, err := adminError(result); err != nil {
			return err
		}
		return nil
	})

	r.run("admin_readonly_endpoint_contract", func() error {
		// 只读端点是否装配取决于宿主：200（有权限）/403（权限拒绝）/404（未装配）
		// 都是可接受的真实状态；只要不是 5xx 或匿名可读就算通过，并如实记录。
		result, err := r.client.adminGet(ctx, "/audit/events", nil, secret)
		if err != nil {
			return err
		}
		switch result.Status {
		case 200, 403, 404:
			if result.Status >= 400 {
				if _, err := adminError(result); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("只读端点返回意外状态 HTTP %d", result.Status)
		}
	})

	r.run("admin_responses_have_no_secret", func() error {
		// 管理 API 响应不得回显会话秘密（即使请求使用 Bearer）。
		for _, suffix := range []string{"/meta", "/error-codes"} {
			result, err := r.client.adminGet(ctx, suffix, nil, secret)
			if err != nil {
				return err
			}
			if result.Status >= 500 {
				return fmt.Errorf("%s 返回 HTTP %d", suffix, result.Status)
			}
			if containsStringFold(string(result.Body), secret) {
				return fmt.Errorf("%s 响应回显了管理会话秘密", suffix)
			}
		}
		return nil
	})
	return nil
}
