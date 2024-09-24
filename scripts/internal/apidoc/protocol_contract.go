package apidoc

// 步骤 271：OAuth 2.0 / OIDC 协议端点契约（第一段）。
//
// 本文件把 internal/protocolapi 的真实 HTTP 协议端点纳入统一参考索引与适用
// OpenAPI 描述：
//   - 端点集合来自 AST 扫描（doc.go 端点表），本文件的契约表必须与扫描结果双向
//     完全一致；多一条/少一条都会让 -write/-check 失败；
//   - 区分浏览器重定向（授权端点）与 JSON 响应（令牌/UserInfo/内省/撤销/设备码）,
//     以及自定义扫码端点的项目统一错误信封；
//   - 保留协议标准参数/错误（RFC 6749/6750/7009/7662/8628），不把它们改写成项目
//     业务错误码；
//   - 协议例外（条件注册端点、自定义信封、标准错误格式、默认关闭 404、宿主中间件
//     责任、Discovery 不声明未实现能力）显式登记并核验证据，不能以“特殊端点”整体
//     逃避契约；
//   - Discovery 只声明真实启用能力，本文件不把未实现能力写进 OpenAPI。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProtocolField 是协议请求/响应字段的文档视图。
type ProtocolField struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query|form|json|header|body
	Required bool   `json:"required"`
	Secret   bool   `json:"secret,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// ProtocolContract 是一条协议端点的 HTTP 契约（方法 + 路径唯一）。
type ProtocolContract struct {
	Method              string          `json:"method"`
	Path                string          `json:"path"`
	Summary             string          `json:"summary"`
	Registration        string          `json:"registration"`
	EnabledWhen         string          `json:"enabled_when"`
	TransportKind       string          `json:"transport_kind"`
	RequestContentType  string          `json:"request_content_type,omitempty"`
	ResponseContentType string          `json:"response_content_type"`
	ClientAuth          string          `json:"client_auth"`
	SessionAuth         string          `json:"session_auth"`
	Audience            string          `json:"audience,omitempty"`
	RequestFields       []ProtocolField `json:"request_fields,omitempty"`
	ResponseFields      []ProtocolField `json:"response_fields,omitempty"`
	SuccessStatuses     []int           `json:"success_statuses"`
	StandardErrors      []string        `json:"standard_errors,omitempty"`
	ProjectErrorCodes   []string        `json:"project_error_codes,omitempty"`
	DiscoveryDeclared   string          `json:"discovery_declared"`
	Notes               []string        `json:"notes,omitempty"`
	Evidence            []string        `json:"evidence,omitempty"`
}

// ProtocolException 是协议例外登记：Kind 取 standard-error-envelope、project-envelope、
// conditional-registration、browser-redirect、disabled-404、host-middleware、
// discovery-limit、root-router；每个例外必须有可核验证据，且覆盖对应端点。
type ProtocolException struct {
	Code      string   `json:"code"`
	Kind      string   `json:"kind"`
	Endpoints []string `json:"endpoints,omitempty"`
	Reason    string   `json:"reason"`
	Evidence  []string `json:"evidence"`
}

// ProtocolContractArtifact 是协议契约生成结果与自检问题。
type ProtocolContractArtifact struct {
	Contracts  []ProtocolContract
	Exceptions []ProtocolException
	// JSON 是确定性 OpenAPI 文档（只含协议端点；不影响运行期 /openapi.json）。
	JSON []byte
	// Issues 非空时 -write/-check 失败。
	Issues []string
}

// protocolRegistrationTokens 把注册条件映射到 routes.go 必须出现的源码标记。
var protocolRegistrationTokens = map[string]string{
	"always":               "",
	"introspection":        "enabledInspect",
	"device":               "enabledDevice",
	"qr":                   "QRLogin != nil",
	"token-authorize-hook": "TokenAuthorize != nil",
}

// checkTokenEvidence 校验 "文件:标记文本" 形式的契约证据：文件存在且包含该文本。
// 证据只证明“源码中确有该事实”，不替代运行时测试。
func checkTokenEvidence(root, ref string) (file, token string, found bool) {
	index := strings.Index(ref, ":")
	if index <= 0 || index == len(ref)-1 {
		return ref, "", false
	}
	file, token = ref[:index], ref[index+1:]
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return file, token, false
	}
	return file, token, strings.Contains(string(raw), token)
}

// protocolContractTable 返回协议端点契约表；顺序按方法+路径稳定排序。
func protocolContractTable() []ProtocolContract {
	contracts := []ProtocolContract{
		{
			Method: "GET", Path: "/.well-known/openid-configuration",
			Summary:      "OIDC Discovery：只声明真实启用的能力",
			Registration: "always", EnabledWhen: "protocol.enabled=true（默认 false，关闭时协议命名空间 404）",
			TransportKind: "json-standard", ResponseContentType: "application/json",
			ClientAuth: "无（公开只读）", SessionAuth: "无", Audience: "issuer（部署公开基址）",
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"404（协议未启用）", "405（非 GET）"},
			DiscoveryDeclared: "是（文档自身）",
			Notes:             []string{"只声明已启用端点与能力；不声明 end_session/PAR/动态注册/CIBA/token exchange 等未实现项。", "缓存由宿主中间件决定；本包不设置 CORS。"},
			Evidence:          []string{"internal/protocolapi/discovery.go:只声明", "internal/protocolapi/doc.go:未实现 OIDC 会话管理"},
		},
		{
			Method: "GET", Path: "/jwks",
			Summary:      "JWT 签名公钥（JWKS）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "json-standard", ResponseContentType: "application/json",
			ClientAuth: "无（公开只读）", SessionAuth: "无", Audience: "issuer",
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"404（协议未启用）", "405（非 GET）"},
			DiscoveryDeclared: "是（jwks_uri）",
			Notes:             []string{"只含公钥与 kid/alg（ES256）；不含私钥材料。"},
			Evidence:          []string{"internal/protocolapi/protocolapi.go:PathJWKS"},
		},
		{
			Method: "GET", Path: "/oauth/authorize",
			Summary:      "授权端点：Cookie 会话 → 最小同意页（浏览器流程）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "browser-redirect", ResponseContentType: "text/html（同意页）或 303 Location",
			ClientAuth:  "公开/保密客户端均可（PKCE 必填；不支持 implicit/password）",
			SessionAuth: "真实浏览器会话 Cookie（或 Bearer 会话）；未登录 303 到宿主登录页/受控错误",
			Audience:    "token 响应中的 audience 由授权请求/应用配置决定",
			RequestFields: []ProtocolField{
				{Name: "response_type", In: "query", Required: true, Summary: "固定 code（仅授权码流程）"},
				{Name: "client_id", In: "query", Required: true},
				{Name: "redirect_uri", In: "query", Required: true, Summary: "必须已登记且逐字节匹配"},
				{Name: "scope", In: "query", Required: false},
				{Name: "state", In: "query", Required: false},
				{Name: "code_challenge", In: "query", Required: true, Summary: "S256 PKCE；plain 被拒绝"},
				{Name: "code_challenge_method", In: "query", Required: true, Summary: "S256"},
				{Name: "login_path", In: "query", Required: false, Secret: false, Summary: "未登录时宿主登录页（只能站内相对路径）"},
			},
			ResponseFields:    []ProtocolField{{Name: "state", In: "body"}, {Name: "code", In: "body", Secret: true}, {Name: "error", In: "body"}, {Name: "error_description", In: "body"}},
			SuccessStatuses:   []int{200, 303},
			StandardErrors:    []string{"invalid_request", "unauthorized_client", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable", "access_denied"},
			DiscoveryDeclared: "是（authorization_endpoint）",
			Notes:             []string{"无效 client_id/redirect_uri 不重定向，返回 JSON 错误（不得开放重定向）；其余错误只在已登记回调上用 error 参数 303 重定向。", "同意页是内置窄 HTML；GET 只创建待确认请求，绝不自动批准。"},
			Evidence:          []string{"internal/protocolapi/authorize.go:handleAuthorizeGet", "internal/protocolapi/doc.go:无效 client_id/redirect_uri 不重定向"},
		},
		{
			Method: "POST", Path: "/oauth/authorize",
			Summary:      "同意/拒绝决定（浏览器表单 + 会话 + CSRF）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "browser-redirect", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "303 Location 或 application/json（错误）",
			ClientAuth:          "沿用授权请求的客户端登记", SessionAuth: "同一浏览器会话 + 会话绑定 CSRF 令牌 +（携带时）同源 Origin",
			Audience: "同授权请求", RequestFields: []ProtocolField{
				{Name: "request_id", In: "form", Required: true, Summary: "授权请求确认编号"},
				{Name: "decision", In: "form", Required: true, Summary: "approve|deny"},
				{Name: "csrf_token", In: "form", Required: true, Secret: true},
			},
			SuccessStatuses:   []int{303},
			StandardErrors:    []string{"invalid_request", "access_denied", "server_error"},
			DiscoveryDeclared: "-",
			Notes:             []string{"批准/拒绝是显式决定；CSRF 与 Origin 两类校验不可互相替代。"},
			Evidence:          []string{"internal/protocolapi/authorize.go:handleAuthorizeDecision"},
		},
		{
			Method: "POST", Path: "/oauth/token",
			Summary:      "令牌端点：授权码/刷新令牌/客户端凭证/设备码（标准 JSON，表单请求）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "application/json",
			ClientAuth:          "保密客户端：client_secret_basic / client_secret_post / 已验证 TLS 客户端证书（三选一）；公开客户端 PKCE",
			SessionAuth:         "无", Audience: "由 grant/授权请求与 resource/audience 参数决定；不发无 audience 的万能令牌",
			RequestFields: []ProtocolField{
				{Name: "grant_type", In: "form", Required: true, Summary: "authorization_code|refresh_token|client_credentials|urn:ietf:params:oauth:grant-type:device_code"},
				{Name: "code", In: "form", Required: false, Secret: true},
				{Name: "redirect_uri", In: "form", Required: false},
				{Name: "code_verifier", In: "form", Required: false, Secret: true, Summary: "PKCE S256"},
				{Name: "refresh_token", In: "form", Required: false, Secret: true},
				{Name: "device_code", In: "form", Required: false, Secret: true},
				{Name: "scope", In: "form", Required: false},
			},
			ResponseFields:    []ProtocolField{{Name: "access_token", In: "body", Secret: true}, {Name: "token_type", In: "body"}, {Name: "expires_in", In: "body"}, {Name: "refresh_token", In: "body", Secret: true}, {Name: "id_token", In: "body", Secret: true}, {Name: "scope", In: "body"}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "authorization_pending", "slow_down", "access_denied", "expired_token", "temporarily_unavailable"},
			DiscoveryDeclared: "是（token_endpoint；grant_types_supported 只列真实支持项）",
			Notes:             []string{"一次请求只能使用一种客户端认证方式；重复参数/未知参数按 invalid_request 拒绝。", "响应 no-store；成功=签发事实，审计不可用时返回 temporarily_unavailable。"},
			Evidence:          []string{"internal/protocolapi/token.go:handleToken", "internal/protocolapi/doc.go:client_secret_basic/post"},
		},
		{
			Method: "POST", Path: "/oauth/token/authorize",
			Summary:      "宿主注入的一次性授权处理器（仅 TokenAuthorize 非空时挂载）",
			Registration: "token-authorize-hook", EnabledWhen: "protocol.enabled=true 且宿主注入 TokenAuthorize 处理器（本包不内置实现）",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "application/json 或宿主定义（取决于注入处理器）",
			ClientAuth:          "由注入处理器与真实服务判定（不得自行信任请求参数）", SessionAuth: "由注入处理器判定",
			Audience:          "本包只负责路由与请求边界；授权/audience/审计由宿主处理器负责",
			SuccessStatuses:   []int{200},
			DiscoveryDeclared: "否（宿主扩展，不写入 Discovery）",
			Notes:             []string{"该端点只登记路径常量与条件注册：没有注入处理器时不会挂载（404），不能按“存在路径常量”认为可用。", "处理器由宿主装配，契约字段/响应以宿主实现为准；本包不伪造成功。"},
			Evidence:          []string{"internal/protocolapi/routes.go:TokenAuthorize != nil"},
		},
		{
			Method: "GET", Path: "/oauth/userinfo",
			Summary:      "OIDC UserInfo（Authorization: Bearer）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "json-standard", ResponseContentType: "application/json",
			ClientAuth: "Access Token 的客户端/audience 校验由令牌与授权服务判定", SessionAuth: "无；只接受 Authorization: Bearer",
			Audience:          "access token 的 aud 必须覆盖 UserInfo 资源服务",
			RequestFields:     []ProtocolField{{Name: "Authorization", In: "header", Required: true, Secret: true, Summary: "Bearer <access_token>"}},
			ResponseFields:    []ProtocolField{{Name: "sub", In: "body"}, {Name: "name", In: "body"}, {Name: "preferred_username", In: "body"}, {Name: "email", In: "body", Secret: true}, {Name: "email_verified", In: "body"}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_token", "insufficient_scope"},
			DiscoveryDeclared: "是（userinfo_endpoint）",
			Notes:             []string{"查询串/请求体里的令牌被拒绝（避免进 URL/日志）；ID Token 不能冒充 Access Token。", "错误响应带 RFC 6750 WWW-Authenticate 挑战。"},
			Evidence:          []string{"internal/protocolapi/token.go:handleUserInfo", "internal/protocolapi/token.go:只从 Authorization: Bearer 读取"},
		},
		{
			Method: "POST", Path: "/oauth/userinfo",
			Summary:      "OIDC UserInfo（POST 兼容）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "json-standard", ResponseContentType: "application/json",
			ClientAuth: "同 GET /oauth/userinfo", SessionAuth: "无；只接受 Authorization: Bearer",
			Audience:          "同 GET /oauth/userinfo",
			RequestFields:     []ProtocolField{{Name: "Authorization", In: "header", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "sub", In: "body"}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_token", "insufficient_scope"},
			DiscoveryDeclared: "是（userinfo_endpoint；GET/POST 均支持）",
			Notes:             []string{"POST 不把令牌放进请求体；请求体参数被忽略/拒绝。"},
			Evidence:          []string{"internal/protocolapi/token.go:MethodPost"},
		},
		{
			Method: "POST", Path: "/oauth/revoke",
			Summary:      "令牌撤销（RFC 7009）",
			Registration: "always", EnabledWhen: "protocol.enabled=true",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "application/json（通常 200 空体）",
			ClientAuth:          "与令牌端点相同的客户端认证", SessionAuth: "无", Audience: "遍历 access/refresh token 的撤销状态由 oauthflow 判定",
			RequestFields:     []ProtocolField{{Name: "token", In: "form", Required: true, Secret: true}, {Name: "token_type_hint", In: "form", Required: false}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_client", "unsupported_token_type"},
			DiscoveryDeclared: "是（revocation_endpoint）",
			Notes:             []string{"撤销是幂等语义；未知 token 不披露存在性（200）。"},
			Evidence:          []string{"internal/protocolapi/token.go:handleRevoke"},
		},
		{
			Method: "POST", Path: "/oauth/introspect",
			Summary:      "令牌状态查询（RFC 7662，显式启用）",
			Registration: "introspection", EnabledWhen: "protocol.enabled=true 且 EnableIntrospection=true（依赖 InspectAuthorizer/InspectClientAuthorizer）",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "application/json",
			ClientAuth:          "资源服务器客户端认证（client_secret_basic/post 或已验证 TLS 证书）", SessionAuth: "无",
			Audience:          "由请求 audience/resource 声明，披露裁剪由注入 Authorizer 判定",
			RequestFields:     []ProtocolField{{Name: "token", In: "form", Required: true, Secret: true}, {Name: "token_type_hint", In: "form", Required: false}, {Name: "audience", In: "form", Required: false}, {Name: "resource", In: "form", Required: false}},
			ResponseFields:    []ProtocolField{{Name: "active", In: "body"}, {Name: "scope", In: "body"}, {Name: "client_id", In: "body"}, {Name: "sub", In: "body"}, {Name: "aud", In: "body"}, {Name: "exp", In: "body"}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_client", "invalid_token", "temporarily_unavailable"},
			DiscoveryDeclared: "是（introspection_endpoint，仅启用时）",
			Notes:             []string{"ResourceServerClientID 只来自真实客户端认证结果，不来自请求自报。", "未启用时端点不注册（404），Discovery 不声明。"},
			Evidence:          []string{"internal/protocolapi/routes.go:enabledInspect", "internal/protocolapi/token.go:handleIntrospect"},
		},
		{
			Method: "POST", Path: "/oauth/device_authorization",
			Summary:      "设备授权申请（RFC 8628，显式启用）",
			Registration: "device", EnabledWhen: "protocol.enabled=true 且 EnableDeviceFlow=true（需 DeviceVerificationURI）",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "application/json",
			ClientAuth:          "客户端认证（设备为公开客户端时可仅 client_id）", SessionAuth: "无", Audience: "设备码最终签发令牌的 audience 由授权请求决定",
			RequestFields:     []ProtocolField{{Name: "client_id", In: "form", Required: false}, {Name: "scope", In: "form", Required: false}},
			ResponseFields:    []ProtocolField{{Name: "device_code", In: "body", Secret: true}, {Name: "user_code", In: "body", Secret: true}, {Name: "verification_uri", In: "body"}, {Name: "expires_in", In: "body"}, {Name: "interval", In: "body"}},
			SuccessStatuses:   []int{200},
			StandardErrors:    []string{"invalid_request", "invalid_client", "unsupported_grant_type", "temporarily_unavailable"},
			DiscoveryDeclared: "是（device_authorization_endpoint，仅启用时）",
			Notes:             []string{"device_code/短码只在申请响应出现一次；短码只存 keyed HMAC 摘要。", "轮询由 /oauth/token 的 device_code grant 完成，服务端强制 interval/slow_down。"},
			Evidence:          []string{"internal/protocolapi/routes.go:enabledDevice", "internal/protocolapi/device.go:handleDeviceAuthorization"},
		},
		{
			Method: "POST", Path: "/oauth/device/cancel",
			Summary:      "设备授权取消（本包扩展，显式启用）",
			Registration: "device", EnabledWhen: "protocol.enabled=true 且 EnableDeviceFlow=true",
			TransportKind: "json-standard", RequestContentType: "application/x-www-form-urlencoded",
			ResponseContentType: "无（204 No Content）",
			ClientAuth:          "必须绑定申请时的同一 client_id；保密客户端还需客户端认证", SessionAuth: "无",
			Audience:          "不改变用户已授予的授权",
			RequestFields:     []ProtocolField{{Name: "device_code", In: "form", Required: true, Secret: true}},
			SuccessStatuses:   []int{204},
			StandardErrors:    []string{"invalid_request", "invalid_client", "access_denied"},
			DiscoveryDeclared: "否（本包扩展，不在 OIDC 标准 Discovery 字段中）",
			Notes:             []string{"扩展端点只在 Discovery 说明或部署文档中出现，不伪造标准字段。"},
			Evidence:          []string{"internal/protocolapi/device.go:handleDeviceCancel"},
		},
		{
			Method: "POST", Path: "/oauth/qr/request",
			Summary:      "扫码登录：匿名发起端创建请求（一次性领取绑定）",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth:          "仅允许登记/允许的 QRClientID（可请求体声明，服务端复核）", SessionAuth: "无（匿名）",
			Audience:          "扫码成功后签发目标应用会话 Cookie，不签发 OAuth Token",
			RequestFields:     []ProtocolField{{Name: "client_id", In: "json", Required: false}, {Name: "scopes", In: "json", Required: false}},
			ResponseFields:    []ProtocolField{{Name: "request_id", In: "body"}, {Name: "qr_payload", In: "body"}, {Name: "claim_secret", In: "body", Secret: true}, {Name: "expires_at", In: "body"}, {Name: "poll_interval_seconds", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"REQ_INVALID", "ACCESS_DENIED", "RATE_LIMITED", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否（项目扩展；Discovery 不声明扫码端点）",
			Notes:             []string{"二维码载荷只含 request_id，不含令牌/会话秘密/领取绑定。", "claim_secret 只出现一次；共享缓存/日志不得记录响应正文。"},
			Evidence:          []string{"internal/protocolapi/qr.go:handleQRRequest", "internal/protocolapi/routes.go:QRLogin != nil"},
		},
		{
			Method: "POST", Path: "/oauth/qr/status",
			Summary:      "扫码登录：原发起端轮询状态（需 request_id + claim_secret）",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth:          "持有一次性领取绑定的原发起端（无客户端密钥）", SessionAuth: "无",
			Audience:          "状态含 retry_after_seconds；服务端强制最小查询间隔",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "json", Required: true}, {Name: "claim_secret", In: "json", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "request_id", In: "body"}, {Name: "status", In: "body"}, {Name: "retry_after_seconds", In: "body"}, {Name: "expires_at", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"REQ_INVALID", "ACCESS_DENIED", "RESOURCE_FORBIDDEN", "CONFLICT", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否", Notes: []string{"不存在的请求与无绑定请求使用同一受控错误，避免探测他人请求。"},
			Evidence: []string{"internal/protocolapi/qr.go:handleQRStatus"},
		},
		{
			Method: "POST", Path: "/oauth/qr/claim",
			Summary:      "扫码登录：原发起端领取目标应用会话",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封；会话 Cookie）",
			ClientAuth:          "持有正确领取绑定且请求已批准/未过期的原发起端", SessionAuth: "无（领取后写入目标应用会话 Cookie）",
			Audience:          "只签发目标应用会话，不是发起者长期 Token",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "json", Required: true}, {Name: "claim_secret", In: "json", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "status", In: "body"}, {Name: "user_id", In: "body"}, {Name: "session_id", In: "body", Secret: true}, {Name: "app_id", In: "body"}, {Name: "expires_at", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"REQ_INVALID", "ACCESS_DENIED", "RESOURCE_FORBIDDEN", "CONFLICT", "GONE", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否", Notes: []string{"领取只能成功一次；跨用户/无绑定 410；正文绝不返回会话秘密或 Token。"},
			Evidence: []string{"internal/protocolapi/qr.go:handleQRClaim"},
		},
		{
			Method: "POST", Path: "/oauth/qr/cancel",
			Summary:      "扫码登录：原发起端取消",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth:          "持有一次性领取绑定的原发起端", SessionAuth: "无",
			Audience:          "只取消该请求，不影响已领取会话",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "json", Required: true}, {Name: "claim_secret", In: "json", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "status", In: "body"}, {Name: "expires_at", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"REQ_INVALID", "ACCESS_DENIED", "CONFLICT", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否", Evidence: []string{"internal/protocolapi/qr.go:handleQRCancel"},
		},
		{
			Method: "POST", Path: "/oauth/qr/regenerate",
			Summary:      "扫码登录：重新生成二维码（旧绑定立即失效）",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth:          "持有一次性领取绑定的原发起端", SessionAuth: "无",
			Audience:          "同一事务内取消旧请求并创建新请求",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "json", Required: true}, {Name: "claim_secret", In: "json", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "request_id", In: "body"}, {Name: "qr_payload", In: "body"}, {Name: "claim_secret", In: "body", Secret: true}, {Name: "expires_at", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"REQ_INVALID", "ACCESS_DENIED", "RESOURCE_FORBIDDEN", "CONFLICT", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否", Evidence: []string{"internal/protocolapi/qr.go:handleQRRegenerate"},
		},
		{
			Method: "GET", Path: "/oauth/qr/prompt",
			Summary:      "扫码登录：确认端读取受控上下文（会话）",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth: "无", SessionAuth: "真实完整会话（Cookie/Bearer）", Audience: "只读受控上下文，不返回秘密、不构成批准",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "query", Required: true}},
			ResponseFields:    []ProtocolField{{Name: "request_id", In: "body"}, {Name: "client_id", In: "body"}, {Name: "application_name", In: "body"}, {Name: "scopes", In: "body"}, {Name: "status", In: "body"}, {Name: "warning", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"AUTH_FAILED", "REQ_INVALID", "ACCESS_DENIED", "RESOURCE_FORBIDDEN", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否",
			Notes:             []string{"不存在/无权限统一错误，避免探测他人请求；不返回 claim_secret。"},
			Evidence:          []string{"internal/protocolapi/qr.go:handleQRPrompt"},
		},
		{
			Method: "POST", Path: "/oauth/qr/decision",
			Summary:      "扫码登录：确认端批准/拒绝（会话 + CSRF + Origin）",
			Registration: "qr", EnabledWhen: "protocol.enabled=true 且注入 QRLogin 服务",
			TransportKind: "json-project-envelope", RequestContentType: "application/json",
			ResponseContentType: "application/json（成功 data；错误项目统一信封）",
			ClientAuth:          "无", SessionAuth: "真实完整会话 + 会话绑定 CSRF（Cookie 会话）；Origin/Referer 至少一个存在并与 issuer 同源",
			Audience:          "批准绑定用户+会话+安全版本快照；批准前按敏感策略要求近期认证",
			RequestFields:     []ProtocolField{{Name: "request_id", In: "json", Required: true}, {Name: "decision", In: "json", Required: true, Summary: "approve|deny"}, {Name: "csrf_token", In: "json", Required: true, Secret: true}},
			ResponseFields:    []ProtocolField{{Name: "status", In: "body"}, {Name: "request_id", In: "body"}},
			SuccessStatuses:   []int{200},
			ProjectErrorCodes: []string{"AUTH_FAILED", "REQ_INVALID", "ACCESS_DENIED", "RESOURCE_FORBIDDEN", "REAUTH_REQUIRED", "INTERNAL_ERROR"},
			DiscoveryDeclared: "否",
			Notes:             []string{"缺少 Origin/Referer 直接 403（纵深防御）；批准页由宿主页面层实现，本端点不提供页面。"},
			Evidence:          []string{"internal/protocolapi/qr.go:handleQRDecision"},
		},
	}
	sort.Slice(contracts, func(left, right int) bool {
		if contracts[left].Path != contracts[right].Path {
			return contracts[left].Path < contracts[right].Path
		}
		return contracts[left].Method < contracts[right].Method
	})
	return contracts
}

// protocolExceptionTable 返回协议例外登记表。
func protocolExceptionTable() []ProtocolException {
	return []ProtocolException{
		{Code: "STD-OAUTH-ERROR", Kind: "standard-error-envelope",
			Endpoints: []string{"POST /oauth/token", "GET /oauth/userinfo", "POST /oauth/userinfo", "POST /oauth/revoke", "POST /oauth/introspect", "POST /oauth/device_authorization", "POST /oauth/device/cancel", "GET /oauth/authorize"},
			Reason:    "标准协议端点错误使用 RFC 6749/6750/7009/7662/8628 的 error/error_description（UserInfo 带 WWW-Authenticate），不得改写为项目 {code,message,request_id} 信封",
			Evidence:  []string{"internal/protocolapi/doc.go:标准端点错误使用 RFC"}},
		{Code: "QR-PROJECT-ENVELOPE", Kind: "project-envelope",
			Endpoints: []string{"POST /oauth/qr/request", "POST /oauth/qr/status", "POST /oauth/qr/claim", "POST /oauth/qr/cancel", "POST /oauth/qr/regenerate", "GET /oauth/qr/prompt", "POST /oauth/qr/decision"},
			Reason:    "自定义扫码端点使用项目统一错误信封 {code,message,request_id}（与业务 API 一致），成功响应为 data",
			Evidence:  []string{"internal/protocolapi/doc.go:自定义扫码端点使用项目统一错误信封"}},
		{Code: "CONDITIONAL-INTROSPECTION", Kind: "conditional-registration",
			Endpoints: []string{"POST /oauth/introspect"},
			Reason:    "只有宿主显式 EnableIntrospection 且注入真实 Authorizer 才注册；未启用时 404，Discovery 不声明",
			Evidence:  []string{"internal/protocolapi/routes.go:enabledInspect"}},
		{Code: "CONDITIONAL-DEVICE", Kind: "conditional-registration",
			Endpoints: []string{"POST /oauth/device_authorization", "POST /oauth/device/cancel"},
			Reason:    "只有 EnableDeviceFlow=true（且配置设备确认页）才注册；未启用时 404，Discovery 不声明",
			Evidence:  []string{"internal/protocolapi/routes.go:enabledDevice"}},
		{Code: "CONDITIONAL-QR", Kind: "conditional-registration",
			Endpoints: []string{"POST /oauth/qr/request", "POST /oauth/qr/status", "POST /oauth/qr/claim", "POST /oauth/qr/cancel", "POST /oauth/qr/regenerate", "GET /oauth/qr/prompt", "POST /oauth/qr/decision"},
			Reason:    "只有注入 QRLogin 服务才注册；未注入时 404。Discovery 不声明扫码扩展端点",
			Evidence:  []string{"internal/protocolapi/routes.go:QRLogin != nil"}},
		{Code: "CONDITIONAL-TOKEN-AUTHORIZE", Kind: "conditional-registration",
			Endpoints: []string{"POST /oauth/token/authorize"},
			Reason:    "POST /oauth/token/authorize 只有在宿主注入 TokenAuthorize 处理器时才存在；本包不内置该端点实现，契约索引只登记路径常量",
			Evidence:  []string{"internal/protocolapi/routes.go:TokenAuthorize != nil"}},
		{Code: "BROWSER-REDIRECT", Kind: "browser-redirect",
			Endpoints: []string{"GET /oauth/authorize", "POST /oauth/authorize"},
			Reason:    "授权端点是浏览器流程：成功/协议错误可能是 303 重定向到已登记回调，而不是 JSON 响应；无效 client_id/redirect_uri 仍是 JSON 错误（防开放重定向）",
			Evidence:  []string{"internal/protocolapi/doc.go:无效 client_id/redirect_uri 不重定向"}},
		{Code: "DISABLED-404", Kind: "disabled-404",
			Endpoints: []string{},
			Reason:    "protocol.enabled=false（默认）时整个协议命名空间不挂载，所有协议路径 404；不要把它当作“端点存在但未授权”",
			Evidence:  []string{"internal/protocolapi/protocolapi.go:最终开关（默认关闭）"}},
		{Code: "DISCOVERY-LIMIT", Kind: "discovery-limit",
			Endpoints: []string{"GET /.well-known/openid-configuration"},
			Reason:    "Discovery 只声明真实启用的能力；end_session/PAR/动态注册/request_uri/CIBA/token exchange 未实现且不声明",
			Evidence:  []string{"internal/protocolapi/doc.go:未实现 OIDC 会话管理"}},
		{Code: "HOST-MIDDLEWARE", Kind: "host-middleware",
			Endpoints: []string{},
			Reason:    "TLS/HSTS、请求体总量、限流、访问日志、可信客户端地址与反向代理前缀由宿主负责；协议包只做单请求上限与协议语义",
			Evidence:  []string{"internal/protocolapi/doc.go:宿主必须提供的前置防护"}},
		{Code: "ROOT-ROUTER-ENVELOPE", Kind: "root-router",
			Endpoints: []string{},
			Reason:    "协议命名空间未匹配路径/panic 恢复返回项目统一 404/500 信封（不是 OAuth 标准错误）；这是路由边界而不是协议端点契约",
			Evidence:  []string{"internal/protocolapi/doc.go:最外层 router 是统一错误边界"}},
		{Code: "HOST-CONFIRM-PAGES", Kind: "host-middleware",
			Endpoints: []string{},
			Reason:    "设备码/扫码“用户确认页”由宿主页面层实现，本包只提供协议端点；确认页接线未验收，不得宣传为已交付",
			Evidence:  []string{"internal/protocolapi/doc.go:未实现设备码/扫码登录的“用户确认页”端点"}},
	}
}

// buildProtocolContract 构建协议契约与 OpenAPI，并核验扫描/证据/例外覆盖。
func buildProtocolContract(root string, paths []ProtocolPath, endpoints []ProtocolEndpoint) (*ProtocolContractArtifact, error) {
	artifact := &ProtocolContractArtifact{}
	contracts := protocolContractTable()
	artifact.Contracts = contracts
	artifact.Exceptions = protocolExceptionTable()

	// 1) 端点表与契约表双向完全一致。
	scanned := map[string]bool{}
	for _, endpoint := range endpoints {
		scanned[endpoint.Method+" "+endpoint.Path] = true
	}
	contracted := map[string]bool{}
	for _, contract := range contracts {
		key := contract.Method + " " + contract.Path
		if contracted[key] {
			artifact.Issues = append(artifact.Issues, "协议契约重复登记："+key)
		}
		contracted[key] = true
		if !scanned[key] {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("协议契约 %s 没有对应的真实端点（doc.go 端点表/路由未注册）：请修正契约或实现", key))
		}
	}
	for key := range scanned {
		if !contracted[key] {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("真实协议端点 %s 缺少 HTTP 契约：请在 protocol_contract.go 登记（方法/传输/认证/错误/开关）", key))
		}
	}

	// 2) 路径常量必须被契约覆盖，契约路径必须是真实 Path 常量。
	pathNames := map[string]bool{}
	for _, path := range paths {
		pathNames[path.Path] = true
	}
	usedPaths := map[string]bool{}
	for _, contract := range contracts {
		if !pathNames[contract.Path] {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("协议契约路径 %s 不在 protocolapi Path* 常量中", contract.Path))
		}
		usedPaths[contract.Path] = true
	}
	for _, path := range paths {
		if !usedPaths[path.Path] {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("协议路径常量 %s（%s）没有被任何 HTTP 契约使用", path.Name, path.Path))
		}
	}

	// 3) 条件注册的源码标记必须真实存在（routes.go），防止契约写“条件”但代码没有开关。
	routesPath := filepath.Join(root, "internal", "protocolapi", "routes.go")
	routesRaw, readErr := os.ReadFile(routesPath)
	if readErr != nil {
		return nil, fmt.Errorf("读取协议路由文件失败：%w", readErr)
	}
	routesText := string(routesRaw)
	for _, contract := range contracts {
		if token, ok := protocolRegistrationTokens[contract.Registration]; !ok {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("协议契约 %s %s 的 registration=%q 未定义", contract.Method, contract.Path, contract.Registration))
		} else if token != "" && !strings.Contains(routesText, token) {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("协议契约 %s %s 声明条件注册 %q，但 routes.go 未出现标记 %q",
					contract.Method, contract.Path, contract.Registration, token))
		}
	}

	// 4) 每条契约的证据必须可核验（文件+标记）。
	for _, contract := range contracts {
		for _, ref := range contract.Evidence {
			if _, token, found := checkTokenEvidence(root, ref); !found {
				artifact.Issues = append(artifact.Issues,
					fmt.Sprintf("协议契约 %s %s 的证据不可核验：%s（缺少 %q）",
						contract.Method, contract.Path, ref, token))
			}
		}
	}

	// 5) 例外必须覆盖：所有条件注册端点、所有自定义信封端点、浏览器重定向端点。
	conditional := map[string]bool{}
	envelope := map[string]bool{}
	for _, contract := range contracts {
		key := contract.Method + " " + contract.Path
		if contract.Registration != "always" {
			conditional[key] = true
		}
		if contract.TransportKind == "json-project-envelope" {
			envelope[key] = true
		}
	}
	for _, exception := range artifact.Exceptions {
		for _, ref := range exception.Evidence {
			if _, token, found := checkTokenEvidence(root, ref); !found {
				artifact.Issues = append(artifact.Issues,
					fmt.Sprintf("协议例外 %s 的证据不可核验：%s（缺少 %q）", exception.Code, ref, token))
			}
		}
		switch exception.Kind {
		case "conditional-registration":
			for _, endpoint := range exception.Endpoints {
				if !conditional[endpoint] {
					artifact.Issues = append(artifact.Issues,
						fmt.Sprintf("协议例外 %s 声明条件端点 %s，但契约未标记条件注册", exception.Code, endpoint))
				}
				delete(conditional, endpoint)
			}
		case "project-envelope":
			for _, endpoint := range exception.Endpoints {
				if !envelope[endpoint] {
					artifact.Issues = append(artifact.Issues,
						fmt.Sprintf("协议例外 %s 声明项目信封端点 %s，但契约未标记自定义信封", exception.Code, endpoint))
				}
				delete(envelope, endpoint)
			}
		}
	}
	for endpoint := range conditional {
		artifact.Issues = append(artifact.Issues,
			"条件注册端点未登记协议例外："+endpoint)
	}
	for endpoint := range envelope {
		artifact.Issues = append(artifact.Issues,
			"自定义错误信封端点未登记协议例外："+endpoint)
	}

	// 6) 生成适用 OpenAPI（协议端点独立文档，不影响运行期 /openapi.json）。
	openAPI := buildProtocolOpenAPI(contracts, artifact.Exceptions)
	artifact.JSON = openAPI
	validationIssues := validateProtocolOpenAPI(openAPI, contracts)
	artifact.Issues = append(artifact.Issues, validationIssues...)
	sort.Strings(artifact.Issues)
	return artifact, nil
}

// buildProtocolOpenAPI 由同一份契约表生成确定性 OpenAPI 3 文档。
func buildProtocolOpenAPI(contracts []ProtocolContract, exceptions []ProtocolException) []byte {
	paths := map[string]any{}
	for _, contract := range contracts {
		operation := map[string]any{
			"summary":     contract.Summary,
			"description": protocolOperationDescription(contract),
			"tags":        []string{"protocol", protocolTransportTag(contract.TransportKind)},
			"responses":   protocolOperationResponses(contract),
		}
		if contract.RequestContentType != "" || len(contract.RequestFields) > 0 {
			operation["requestBody"] = protocolRequestBody(contract)
		}
		if parameters := protocolParameters(contract.RequestFields); len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		pathItem, _ := paths[contract.Path].(map[string]any)
		if pathItem == nil {
			pathItem = map[string]any{}
			paths[contract.Path] = pathItem
		}
		pathItem[strings.ToLower(contract.Method)] = operation
	}
	exceptionRows := make([]map[string]any, 0, len(exceptions))
	for _, exception := range exceptions {
		exceptionRows = append(exceptionRows, map[string]any{
			"code": exception.Code, "kind": exception.Kind,
			"endpoints": exception.Endpoints, "reason": exception.Reason,
		})
	}
	document := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "EvernightLogin OAuth 2.0 / OIDC 协议端点（离线参考）",
			"version": "devel",
			"description": "由 scripts/reference 从 protocolapi 端点表与协议契约生成；" +
				"描述默认关闭默认、标准错误格式、浏览器重定向与 JSON 响应区别。运行期 /openapi.json 仍是宿主最小文档，不含本段。",
		},
		"tags": []map[string]any{
			{"name": "protocol", "description": "OAuth 2.0 / OIDC 协议端点"},
			{"name": "protocol-json", "description": "JSON 响应协议端点"},
			{"name": "protocol-browser", "description": "浏览器重定向授权流程"},
			{"name": "protocol-project-envelope", "description": "项目统一错误信封的扩展端点"},
		},
		"x-login-protocol-mode":       "协议端点由 protocol.enabled 显式启用（默认 false）；关闭时协议命名空间 404。",
		"x-login-protocol-exceptions": exceptionRows,
		"x-login-examples-policy":     "所有示例均为明确合成值（example-*、000000 等），不包含可用密码、令牌、恢复码、私钥或真实用户数据。",
		"paths":                       paths,
		"components": map[string]any{
			"schemas": protocolSchemas(),
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
			},
		},
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		// 文档由本包可控结构组成；序列化失败属于内部错误。
		panic("apidoc: 协议 OpenAPI 序列化失败: " + err.Error())
	}
	return append(raw, '\n')
}

// protocolOperationDescription 生成端点描述（含开关/认证/会话/错误格式）。
func protocolOperationDescription(contract ProtocolContract) string {
	lines := []string{
		"注册条件：" + contract.EnabledWhen,
		"传输：" + contract.TransportKind + "；请求 Content-Type：" + contract.RequestContentType + "；成功响应 Content-Type：" + contract.ResponseContentType,
		"客户端认证：" + contract.ClientAuth,
		"会话：" + contract.SessionAuth,
	}
	if contract.Audience != "" {
		lines = append(lines, "audience/绑定："+contract.Audience)
	}
	if len(contract.StandardErrors) > 0 {
		lines = append(lines, "标准协议错误（不是项目错误信封）："+strings.Join(contract.StandardErrors, "、"))
	}
	if len(contract.ProjectErrorCodes) > 0 {
		lines = append(lines, "项目错误码（统一信封）："+strings.Join(contract.ProjectErrorCodes, "、"))
	}
	lines = append(lines, contract.Notes...)
	return strings.Join(lines, "\n")
}

// protocolTransportTag 把传输类别映射为 OpenAPI tag。
func protocolTransportTag(kind string) string {
	switch kind {
	case "browser-redirect":
		return "protocol-browser"
	case "json-project-envelope":
		return "protocol-project-envelope"
	default:
		return "protocol-json"
	}
}

// protocolParameters 把 query/header 字段转换为 OpenAPI 参数。
func protocolParameters(fields []ProtocolField) []map[string]any {
	var parameters []map[string]any
	for _, field := range fields {
		switch field.In {
		case "query", "header":
			parameter := map[string]any{
				"name": field.Name, "in": field.In,
				"required": field.Required, "description": field.Summary,
				"schema": map[string]any{"type": "string"},
			}
			if field.Secret {
				parameter["x-login-secret"] = true
			}
			parameters = append(parameters, parameter)
		}
	}
	return parameters
}

// protocolRequestBody 生成请求体（form 或 JSON）。
func protocolRequestBody(contract ProtocolContract) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, field := range contract.RequestFields {
		if field.In != "form" && field.In != "json" && field.In != "body" {
			continue
		}
		property := map[string]any{"type": "string", "description": field.Summary}
		if field.Secret {
			property["writeOnly"] = true
		}
		properties[field.Name] = property
		if field.Required {
			required = append(required, field.Name)
		}
	}
	sort.Strings(required)
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	contentType := contract.RequestContentType
	if contentType == "" {
		contentType = "application/json"
	}
	return map[string]any{
		"required": true,
		"content":  map[string]any{contentType: map[string]any{"schema": schema}},
	}
}

// protocolOperationResponses 生成成功与错误响应。
func protocolOperationResponses(contract ProtocolContract) map[string]any {
	responses := map[string]any{}
	for _, status := range contract.SuccessStatuses {
		key := fmt.Sprintf("%d", status)
		switch {
		case status == 204:
			responses[key] = map[string]any{"description": "成功（无响应体）"}
		case status == 303:
			responses[key] = map[string]any{
				"description": "浏览器重定向（授权码/错误参数在 Location 中）",
				"headers": map[string]any{"Location": map[string]any{
					"description": "已登记回调地址；不得使用未登记/可开放重定向的地址", "schema": map[string]any{"type": "string"}}},
			}
		case strings.Contains(contract.ResponseContentType, "text/html"):
			responses[key] = map[string]any{
				"description": "内置最小同意页（HTML；不含脚本/主题/多语言）",
				"content":     map[string]any{"text/html": map[string]any{"schema": map[string]any{"type": "string"}}},
			}
		default:
			responses[key] = map[string]any{
				"description": "成功（JSON）",
				"content": map[string]any{"application/json": map[string]any{
					"schema":  protocolResponseSchema(contract),
					"example": protocolResponseExample(contract),
				}},
			}
		}
	}
	if len(contract.StandardErrors) > 0 {
		examples := map[string]any{}
		for _, code := range contract.StandardErrors {
			examples[code] = map[string]any{"value": map[string]any{
				"error": protocolErrorCode(code), "error_description": "示例说明（合成值）",
			}}
		}
		responses["400"] = map[string]any{
			"description": "协议标准错误（RFC 6749/6750/7009/7662/8628；UserInfo 同时带 WWW-Authenticate 挑战）",
			"content": map[string]any{"application/json": map[string]any{
				"schema":   map[string]any{"$ref": "#/components/schemas/OAuthError"},
				"examples": examples,
			}},
		}
	}
	if len(contract.ProjectErrorCodes) > 0 {
		examples := map[string]any{}
		for _, code := range contract.ProjectErrorCodes {
			examples[code] = map[string]any{"value": map[string]any{
				"ok": false, "code": code, "message": "示例说明（合成值）", "request_id": "req_example_000000",
			}}
		}
		responses["400"] = map[string]any{
			"description": "项目统一错误信封（自定义扫码端点例外；与业务 API 一致）",
			"content": map[string]any{"application/json": map[string]any{
				"schema":   map[string]any{"$ref": "#/components/schemas/ProjectError"},
				"examples": examples,
			}},
		}
	}
	return responses
}

// protocolResponseSchema 用响应字段生成宽松对象 schema（不伪造必填/类型细节）。
func protocolResponseSchema(contract ProtocolContract) map[string]any {
	if len(contract.ResponseFields) == 0 {
		return map[string]any{"type": "object", "description": "OAuth/OIDC 标准 JSON 响应"}
	}
	properties := map[string]any{}
	for _, field := range contract.ResponseFields {
		property := map[string]any{"type": "string", "description": field.Summary}
		if field.Secret {
			property["writeOnly"] = true
		}
		properties[field.Name] = property
	}
	return map[string]any{"type": "object", "properties": properties}
}

// protocolResponseExample 生成合成成功示例（不含真实凭据）。
func protocolResponseExample(contract ProtocolContract) map[string]any {
	example := map[string]any{}
	for _, field := range contract.ResponseFields {
		switch {
		case field.Secret:
			example[field.Name] = "example-" + field.Name
		case field.Name == "expires_in" || field.Name == "poll_interval_seconds" || field.Name == "retry_after_seconds":
			example[field.Name] = 600
		case field.Name == "active" || field.Name == "email_verified":
			example[field.Name] = true
		default:
			example[field.Name] = "example-" + field.Name
		}
	}
	return example
}

// protocolErrorCode 把标准错误说明条目转换为 RFC 错误码（去掉括号说明）。
func protocolErrorCode(description string) string {
	if index := strings.Index(description, "（"); index > 0 {
		return description[:index]
	}
	return description
}

// protocolSchemas 返回协议 OpenAPI 共用 schema。
func protocolSchemas() map[string]any {
	return map[string]any{
		"OAuthError": map[string]any{
			"type": "object", "additionalProperties": false,
			"required": []string{"error"},
			"properties": map[string]any{
				"error":             map[string]any{"type": "string", "description": "RFC 6749/6750/7009/7662/8628 标准错误码"},
				"error_description": map[string]any{"type": "string", "description": "人类可读说明；不回显内部错误文本"},
				"error_uri":         map[string]any{"type": "string", "description": "错误说明地址（如提供）"},
			},
		},
		"ProjectError": map[string]any{
			"type": "object", "additionalProperties": false,
			"required": []string{"ok", "code", "message", "request_id"},
			"properties": map[string]any{
				"ok":         map[string]any{"type": "boolean", "enum": []bool{false}},
				"code":       map[string]any{"type": "string"},
				"message":    map[string]any{"type": "string"},
				"request_id": map[string]any{"type": "string"},
			},
		},
	}
}

// validateProtocolOpenAPI 校验协议 OpenAPI：操作集合与契约一致、$ref 可解析、
// 示例是合法 JSON 且不含真实凭据模式。
func validateProtocolOpenAPI(raw []byte, contracts []ProtocolContract) []string {
	var issues []string
	if !json.Valid(raw) {
		return []string{"协议 OpenAPI 不是合法 JSON"}
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return []string{"协议 OpenAPI 无法解析：" + err.Error()}
	}
	paths, _ := document["paths"].(map[string]any)
	documented := map[string]bool{}
	for path, value := range paths {
		pathItem, ok := value.(map[string]any)
		if !ok {
			issues = append(issues, "协议 OpenAPI paths 项不是对象："+path)
			continue
		}
		for method := range pathItem {
			switch strings.ToLower(method) {
			case "get", "post", "put", "delete", "patch":
				documented[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	for _, contract := range contracts {
		key := contract.Method + " " + contract.Path
		if !documented[key] {
			issues = append(issues, "协议 OpenAPI 缺少操作："+key)
		}
	}
	for key := range documented {
		found := false
		for _, contract := range contracts {
			if contract.Method+" "+contract.Path == key {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, "协议 OpenAPI 存在契约表之外的操作："+key)
		}
	}
	issues = append(issues, validateOpenAPIReferences(document)...)
	issues = append(issues, validateOpenAPIExamples(document)...)
	return issues
}

// validateOpenAPIReferences 校验文档内 $ref 目标存在，并检查 operationId 唯一。
// 支持任意本地 JSON Pointer（#/components/...），不限于 schemas；外部 URL（http、
// 非 #/ 开头）需人工确认，直接作为问题暴露。
func validateOpenAPIReferences(document map[string]any) []string {
	var issues []string
	operationIDs := map[string]bool{}
	var walk func(value any, context string)
	walk = func(value any, context string) {
		switch typed := value.(type) {
		case map[string]any:
			if ref, ok := typed["$ref"].(string); ok {
				if strings.HasPrefix(ref, "#/") {
					if !jsonPointerExists(document, ref) {
						issues = append(issues, fmt.Sprintf("%s 的 $ref 指向不存在的目标：%s", context, ref))
					}
				} else {
					issues = append(issues, fmt.Sprintf("%s 的 $ref 不是本地 JSON Pointer（需人工确认）：%s", context, ref))
				}
			}
			if id, ok := typed["operationId"].(string); ok && id != "" {
				if operationIDs[id] {
					issues = append(issues, "OpenAPI operationId 重复："+id)
				}
				operationIDs[id] = true
			}
			for key, child := range typed {
				walk(child, context+"/"+key)
			}
		case []any:
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s[%d]", context, index))
			}
		}
	}
	walk(document, "$")
	return issues
}

// jsonPointerExists 解析 #/a/b/c 形式的 JSON Pointer 是否指向真实节点。
func jsonPointerExists(document map[string]any, ref string) bool {
	pointer := strings.TrimPrefix(ref, "#/")
	if pointer == "" {
		return true
	}
	var current any = document
	for _, rawToken := range strings.Split(pointer, "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[token]
			if !ok {
				return false
			}
			current = next
		case []any:
			index := -1
			if _, err := fmt.Sscanf(token, "%d", &index); err != nil ||
				index < 0 || index >= len(typed) {
				return false
			}
			current = typed[index]
		default:
			return false
		}
	}
	return true
}

var protocolSecretPatterns = []string{
	"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY",
	"PRIVATE KEY-----", "password=", "client_secret=",
}

// validateOpenAPIExamples 校验所有示例：JSON 可序列化、不含真实凭据模式；
// 对明显真实凭据特征（长 base64/JWT）也拒绝。
func validateOpenAPIExamples(document map[string]any) []string {
	var issues []string
	var walk func(value any, context string)
	walk = func(value any, context string) {
		switch typed := value.(type) {
		case map[string]any:
			for _, key := range []string{"example", "examples"} {
				if example, ok := typed[key]; ok {
					issues = append(issues, validateExampleValue(example, context+"/"+key)...)
				}
			}
			for key, child := range typed {
				walk(child, context+"/"+key)
			}
		case []any:
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s[%d]", context, index))
			}
		}
	}
	walk(document, "$")
	return issues
}

// validateExampleValue 校验单个示例值（递归检查字符串）。
func validateExampleValue(value any, context string) []string {
	var issues []string
	if _, err := json.Marshal(value); err != nil {
		issues = append(issues, "OpenAPI 示例无法序列化："+context)
		return issues
	}
	var walkStrings func(value any, context string)
	walkStrings = func(value any, context string) {
		switch typed := value.(type) {
		case string:
			for _, pattern := range protocolSecretPatterns {
				if strings.Contains(strings.ToUpper(typed), strings.ToUpper(pattern)) {
					issues = append(issues, fmt.Sprintf("OpenAPI 示例疑似真实凭据（%s）：%s", pattern, context))
				}
			}
			if looksLikeRealToken(typed) {
				issues = append(issues, "OpenAPI 示例疑似真实令牌/密钥（长 base64/JWT）："+context)
			}
		case map[string]any:
			for key, child := range typed {
				walkStrings(child, context+"/"+key)
			}
		case []any:
			for index, child := range typed {
				walkStrings(child, fmt.Sprintf("%s[%d]", context, index))
			}
		}
	}
	walkStrings(value, context)
	return issues
}

// looksLikeRealToken 识别 JWT/长 base64/长 hex 等真实凭据特征（合成示例使用 example-*）。
func looksLikeRealToken(value string) bool {
	if strings.HasPrefix(value, "example-") || len(value) < 32 {
		return false
	}
	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
		return true
	}
	hexish := true
	for _, char := range value {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') &&
			!(char >= 'A' && char <= 'F') {
			hexish = false
			break
		}
	}
	return hexish
}
