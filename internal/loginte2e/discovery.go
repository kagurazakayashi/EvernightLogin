package loginte2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// DiscoveryDocument 是 OIDC Discovery 文档的只读投影（字段与 internal/protocolapi
// 的声明一致；多出的字段忽略，缺失字段按空值处理）。
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
}

// fetchDiscovery 拉取并解析 Discovery 文档；校验期望 issuer（如果配置）并缓存
// issuer 供后续同源请求使用。不可达返回 ErrUnavailable。
func (c *Client) fetchDiscovery(ctx context.Context) (*DiscoveryDocument, error) {
	result, err := c.do(ctx, "GET", pathDiscovery, requestOptions{})
	if err != nil {
		return nil, err
	}
	// 只有“连接/TLS 失败”才用 ErrUnavailable（退出码 3）；HTTP 响应错误是真实
	// 测试失败（例如服务未启用协议端点），按普通错误返回（退出码 1）。
	if err := result.expectStatus(200); err != nil {
		return nil, fmt.Errorf("Discovery 端点不可用：%v", err)
	}
	var document DiscoveryDocument
	if err := result.decodeJSON(&document); err != nil {
		return nil, err
	}
	if strings.TrimSpace(document.Issuer) == "" {
		return nil, fmt.Errorf("Discovery 文档缺少 issuer")
	}
	if expected := strings.TrimSpace(c.cfg.ExpectedIssuer); expected != "" &&
		expected != document.Issuer {
		return nil, fmt.Errorf("Discovery issuer %q 与 --issuer %q 不一致",
			document.Issuer, expected)
	}
	c.issuerCache = document.Issuer
	return &document, nil
}

// jwks 拉取 JWKS 原文（公开数据），供验签使用。
func (c *Client) jwks(ctx context.Context) ([]byte, error) {
	result, err := c.do(ctx, "GET", pathJWKS, requestOptions{})
	if err != nil {
		return nil, err
	}
	if err := result.expectStatus(200); err != nil {
		return nil, fmt.Errorf("JWKS 端点不可用（HTTP %d）", result.Status)
	}
	if len(result.Body) == 0 {
		return nil, fmt.Errorf("JWKS 响应正文为空")
	}
	c.jwksCache = append([]byte(nil), result.Body...)
	return c.jwksCache, nil
}

// issuerOrigin 返回 issuer 的 scheme://host；issuer 非法时返回错误。
func issuerOrigin(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return "", fmt.Errorf("issuer 不是合法绝对地址")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// issuerPath 返回 issuer 的路径部分（去掉尾斜杠）。
func issuerPath(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Path, "/")
}

// serverPath 返回被测服务基础地址的路径前缀（去掉尾斜杠）。
func (c *Client) serverPath() string {
	return strings.TrimRight(c.base.Path, "/")
}

// runDiscoverySuite 核对 Discovery 声明与真实端点。
func (r *Runner) runDiscoverySuite(ctx context.Context) error {
	var (
		document    *DiscoveryDocument
		documentErr error
	)
	r.run("discovery_document", func() error {
		result, err := r.client.do(ctx, "GET", pathDiscovery, requestOptions{})
		if err != nil {
			documentErr = err
			return err
		}
		if err := result.expectStatus(200); err != nil {
			documentErr = err
			return err
		}
		if contentType := result.Header.Get("Content-Type"); !strings.HasPrefix(contentType,
			"application/json") {
			documentErr = fmt.Errorf("Discovery Content-Type 应为 JSON，实际 %q", contentType)
			return documentErr
		}
		decoded, decodeErr := r.document(ctx)
		if decodeErr != nil {
			documentErr = decodeErr
			return decodeErr
		}
		document = decoded
		return nil
	})
	if document == nil {
		// 文档拿不到时后续核对没有意义；连接/TLS 失败属于“目标不可达”，向上返回。
		if documentErr != nil && isUnavailable(documentErr) {
			return documentErr
		}
		return nil
	}

	r.run("issuer", func() error {
		issuer := document.Issuer
		parsed, err := url.Parse(issuer)
		if err != nil || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("issuer 不是合法绝对地址")
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
			return fmt.Errorf("issuer 必须是 https（回环地址允许 http），实际 %q", parsed.Scheme)
		}
		if issuerPath(issuer) != r.client.serverPath() {
			return fmt.Errorf("issuer 路径 %q 与 --server 路径 %q 不一致：请把 --server 改成含部署路径前缀的地址",
				issuerPath(issuer), r.client.serverPath())
		}
		return nil
	})

	r.run("endpoint_urls", func() error {
		issuer := document.Issuer
		expected := map[string]string{
			"authorization_endpoint": issuer + pathAuthorize,
			"token_endpoint":         issuer + pathToken,
			"userinfo_endpoint":      issuer + pathUserInfo,
			"jwks_uri":               issuer + pathJWKS,
			"revocation_endpoint":    issuer + pathRevoke,
		}
		actual := map[string]string{
			"authorization_endpoint": document.AuthorizationEndpoint,
			"token_endpoint":         document.TokenEndpoint,
			"userinfo_endpoint":      document.UserInfoEndpoint,
			"jwks_uri":               document.JWKSURI,
			"revocation_endpoint":    document.RevocationEndpoint,
		}
		for name, want := range expected {
			if actual[name] != want {
				return fmt.Errorf("%s 声明为 %q，期望 %q", name, actual[name], want)
			}
		}
		if document.DeviceAuthorizationEndpoint != "" &&
			document.DeviceAuthorizationEndpoint != issuer+pathDeviceAuthorization {
			return fmt.Errorf("device_authorization_endpoint 与挂载路径不一致")
		}
		if document.IntrospectionEndpoint != "" &&
			document.IntrospectionEndpoint != issuer+pathIntrospect {
			return fmt.Errorf("introspection_endpoint 与挂载路径不一致")
		}
		return nil
	})

	r.run("capabilities", func() error {
		if !containsString(document.ResponseTypesSupported, "code") {
			return fmt.Errorf("response_types_supported 缺少 code")
		}
		if !containsString(document.ResponseModesSupported, "query") {
			return fmt.Errorf("response_modes_supported 缺少 query")
		}
		if document.ClaimsParameterSupported || document.RequestParameterSupported ||
			document.RequestURIParameterSupported {
			return fmt.Errorf("声明了未实现的能力（claims/request/request_uri 必须为 false）")
		}
		for _, grant := range []string{"authorization_code", "refresh_token", "client_credentials"} {
			if !containsString(document.GrantTypesSupported, grant) {
				return fmt.Errorf("grant_types_supported 缺少 %s", grant)
			}
		}
		if len(document.CodeChallengeMethodsSupported) != 1 ||
			document.CodeChallengeMethodsSupported[0] != PKCEMethodS256 {
			return fmt.Errorf("code_challenge_methods_supported 必须只有 S256，实际 %v",
				document.CodeChallengeMethodsSupported)
		}
		if !containsString(document.IDTokenSigningAlgValuesSupported, "ES256") {
			return fmt.Errorf("id_token_signing_alg_values_supported 缺少 ES256")
		}
		if !containsString(document.SubjectTypesSupported, "pairwise") {
			return fmt.Errorf("subject_types_supported 缺少 pairwise")
		}
		if !containsString(document.ScopesSupported, "openid") {
			return fmt.Errorf("scopes_supported 缺少 openid")
		}
		if len(document.TokenEndpointAuthMethodsSupported) == 0 {
			return fmt.Errorf("token_endpoint_auth_methods_supported 不能为空")
		}
		return nil
	})

	r.run("jwks_reachable", func() error {
		payload, err := r.client.jwks(ctx)
		if err != nil {
			return err
		}
		if _, parseErr := parseJWKS(payload); parseErr != nil {
			return parseErr
		}
		return nil
	})

	r.run("authorize_requires_login", func() error {
		result, err := r.client.do(ctx, "GET", pathAuthorize, requestOptions{})
		if err != nil {
			return err
		}
		switch result.Status {
		case 200:
			return fmt.Errorf("未登录访问授权端点返回 200（不应自动展示同意页）")
		case 303, 401:
			return nil
		default:
			return fmt.Errorf("未登录访问授权端点返回意外状态 HTTP %d", result.Status)
		}
	})

	r.run("token_rejects_get", func() error {
		result, err := r.client.do(ctx, "GET", pathToken, requestOptions{})
		if err != nil {
			return err
		}
		if result.Status != 405 {
			return fmt.Errorf("GET 令牌端点应为 405，实际 HTTP %d", result.Status)
		}
		if allow := result.Header.Get("Allow"); !strings.Contains(allow, "POST") {
			return fmt.Errorf("405 响应缺少 Allow: POST")
		}
		if _, problemErr := result.expectProblem(405); problemErr != nil {
			return problemErr
		}
		return nil
	})

	r.run("userinfo_requires_bearer", func() error {
		result, err := r.client.do(ctx, "GET", pathUserInfo, requestOptions{})
		if err != nil {
			return err
		}
		if result.Status != 401 {
			return fmt.Errorf("无 Bearer 访问 UserInfo 应为 401，实际 HTTP %d", result.Status)
		}
		challenge := result.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(challenge, "Bearer") {
			return fmt.Errorf("401 响应缺少 Bearer 认证挑战")
		}
		return nil
	})

	r.run("revoke_rejects_anonymous", func() error {
		result, err := r.client.do(ctx, "POST", pathRevoke, requestOptions{
			form: url.Values{"token": {"test-only-placeholder"}}})
		if err != nil {
			return err
		}
		if result.isSuccess() {
			return fmt.Errorf("匿名撤销请求不应成功")
		}
		problem, ok := result.problem().(*HTTPError)
		if !ok || problem.Code == "" {
			return fmt.Errorf("撤销端点未返回稳定错误码")
		}
		return nil
	})

	r.run("device_capability", func() error {
		declared := document.DeviceAuthorizationEndpoint != ""
		result, err := r.client.do(ctx, "POST", pathDeviceAuthorization, requestOptions{
			form: url.Values{"client_id": {"app_00000000000000000000000000000000"}}})
		if err != nil {
			return err
		}
		if !declared {
			if result.Status != 404 {
				return fmt.Errorf("未声明设备码能力时端点应 404，实际 HTTP %d", result.Status)
			}
			return nil
		}
		// 已声明：未登记客户端必须被拒绝（400/401），不能是 404/200。
		if _, problemErr := result.expectProblem(0, "invalid_client", "CLIENT_AUTH_FAILED",
			"REQ_INVALID"); problemErr != nil {
			return problemErr
		}
		return nil
	})

	r.run("introspection_capability", func() error {
		declared := document.IntrospectionEndpoint != ""
		result, err := r.client.do(ctx, "POST", pathIntrospect, requestOptions{
			form: url.Values{"token": {"test-only-placeholder"}}})
		if err != nil {
			return err
		}
		if !declared {
			if result.Status != 404 {
				return fmt.Errorf("未声明状态查询能力时端点应 404，实际 HTTP %d", result.Status)
			}
			return nil
		}
		if _, problemErr := result.expectProblem(0, "invalid_client", "CLIENT_AUTH_FAILED",
			"REQ_INVALID"); problemErr != nil {
			return problemErr
		}
		return nil
	})

	r.run("qr_endpoints_probe", func() error {
		// 扫码登录不在 Discovery 中声明（属于宿主页面/应用能力），这里探测存在性：
		// 200/400/403/401 说明端点存在；404 说明未挂载。两种都算通过（如实记录）。
		result, err := r.client.do(ctx, "POST", pathQRRequest, requestOptions{
			jsonBody: map[string]any{}})
		if err != nil {
			return err
		}
		switch {
		case result.Status == 404:
			return nil
		case result.isSuccess():
			// 探测创建了真实待确认请求：用响应里的领取绑定立即取消，避免留下悬挂请求。
			var created struct {
				RequestID   string `json:"request_id"`
				ClaimSecret string `json:"claim_secret"`
			}
			if decodeErr := result.decodeJSON(&created); decodeErr != nil {
				return decodeErr
			}
			if created.RequestID != "" && created.ClaimSecret != "" {
				_, _ = r.client.do(ctx, "POST", pathQRCancel, requestOptions{
					jsonBody: map[string]any{"request_id": created.RequestID,
						"claim_secret": created.ClaimSecret}})
			}
			return nil
		default:
			if problem, ok := result.problem().(*HTTPError); ok && problem.Code != "" {
				return nil
			}
			return fmt.Errorf("扫码端点探测返回意外状态 HTTP %d", result.Status)
		}
	})
	return nil
}

// isLoopbackHost 判断主机是否回环地址（与 protocolapi 的 issuer 校验口径一致）。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	trimmed := strings.Trim(host, "[]")
	return trimmed == "127.0.0.1" || trimmed == "::1"
}
