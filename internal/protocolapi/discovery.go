package protocolapi

import "net/http"

// DiscoveryDocument 是本包对外声明的 OpenID Connect Discovery 文档。字段只包含
// 实际实现的能力：New 依据挂载的端点与 OIDC 服务配置生成，不声明未实现能力。
//
// 与 internal/oidc.DiscoveryDocument 的关系：oidc 服务只声明授权码模式；本包在
// 其上追加真实挂载的撤销/状态查询/设备码端点与对应 grant_type，属于传输层对
// “本进程实际能力”的如实汇总，不修改 oidc 服务的声明。
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// RevocationEndpoint 是 RFC 7009 撤销端点；始终实现。
	RevocationEndpoint string `json:"revocation_endpoint"`
	// IntrospectionEndpoint 是 RFC 7662 状态查询端点；只在显式启用时出现。
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	// DeviceAuthorizationEndpoint 是 RFC 8628 设备授权端点；只在显式启用时出现。
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	ScopesSupported                           []string `json:"scopes_supported"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	ClaimsParameterSupported                  bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported              bool     `json:"request_uri_parameter_supported"`
}

// clone 返回深拷贝，避免调用方修改 Server 内部发现文档。
func (d DiscoveryDocument) clone() DiscoveryDocument {
	return DiscoveryDocument{
		Issuer:                                    d.Issuer,
		AuthorizationEndpoint:                     d.AuthorizationEndpoint,
		TokenEndpoint:                             d.TokenEndpoint,
		UserInfoEndpoint:                          d.UserInfoEndpoint,
		JWKSURI:                                   d.JWKSURI,
		RevocationEndpoint:                        d.RevocationEndpoint,
		IntrospectionEndpoint:                     d.IntrospectionEndpoint,
		DeviceAuthorizationEndpoint:               d.DeviceAuthorizationEndpoint,
		ScopesSupported:                           append([]string(nil), d.ScopesSupported...),
		ResponseTypesSupported:                    append([]string(nil), d.ResponseTypesSupported...),
		ResponseModesSupported:                    append([]string(nil), d.ResponseModesSupported...),
		GrantTypesSupported:                       append([]string(nil), d.GrantTypesSupported...),
		SubjectTypesSupported:                     append([]string(nil), d.SubjectTypesSupported...),
		IDTokenSigningAlgValuesSupported:          append([]string(nil), d.IDTokenSigningAlgValuesSupported...),
		TokenEndpointAuthMethodsSupported:         append([]string(nil), d.TokenEndpointAuthMethodsSupported...),
		RevocationEndpointAuthMethodsSupported:    append([]string(nil), d.RevocationEndpointAuthMethodsSupported...),
		IntrospectionEndpointAuthMethodsSupported: append([]string(nil), d.IntrospectionEndpointAuthMethodsSupported...),
		CodeChallengeMethodsSupported:             append([]string(nil), d.CodeChallengeMethodsSupported...),
		ClaimsSupported:                           append([]string(nil), d.ClaimsSupported...),
		ClaimsParameterSupported:                  d.ClaimsParameterSupported,
		RequestParameterSupported:                 d.RequestParameterSupported,
		RequestURIParameterSupported:              d.RequestURIParameterSupported,
	}
}

// buildDiscovery 汇总本进程实际实现的能力。调用前 New 已校验 oidc 端点与本包
// 挂载路径一致；这里只补充撤销/状态查询/设备码等本包挂载的附加端点。
func (s *Server) buildDiscovery() DiscoveryDocument {
	base := s.opts.OIDC.Discovery()
	authMethods := normalizedList(base.TokenEndpointAuthMethodsSupported)
	document := DiscoveryDocument{
		Issuer:                                 s.issuer,
		AuthorizationEndpoint:                  s.endpoint(PathAuthorize),
		TokenEndpoint:                          s.endpoint(PathToken),
		UserInfoEndpoint:                       s.endpoint(PathUserInfo),
		JWKSURI:                                s.endpoint(PathJWKS),
		RevocationEndpoint:                     s.endpoint(PathRevoke),
		ScopesSupported:                        appendScope(normalizedList(base.ScopesSupported), ScopeOfflineAccess),
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:                  []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:       []string{"ES256"},
		TokenEndpointAuthMethodsSupported:      authMethods,
		RevocationEndpointAuthMethodsSupported: append([]string(nil), authMethods...),
		CodeChallengeMethodsSupported:          []string{"S256"},
		ClaimsSupported:                        append([]string(nil), base.ClaimsSupported...),
		// 请求对象/claims 请求/request_uri 未实现：显式声明为 false，不夸大。
		ClaimsParameterSupported:     false,
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}
	if s.enabledDevice {
		document.DeviceAuthorizationEndpoint = s.endpoint(PathDeviceAuthorization)
		document.GrantTypesSupported = append(document.GrantTypesSupported, DeviceCodeGrantType)
	}
	if s.enabledInspect {
		document.IntrospectionEndpoint = s.endpoint(PathIntrospect)
		document.IntrospectionEndpointAuthMethodsSupported = append([]string(nil), authMethods...)
	}
	return document
}

// normalizedList 返回去重并保序的字符串副本（空输入返回空切片而非 nil，保证 JSON
// 输出稳定为 []）。
func normalizedList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// appendScope 追加一个 scope（已存在则原样返回）。
func appendScope(scopes []string, scope string) []string {
	for _, existing := range scopes {
		if existing == scope {
			return scopes
		}
	}
	return append(scopes, scope)
}

// handleDiscovery 处理 GET /.well-known/openid-configuration。
func (s *Server) handleDiscovery(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set(headerAllow, "GET, HEAD")
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	writeJSON(writer, http.StatusOK, requestID, s.discovery)
}

// handleJWKS 处理 GET /jwks：发布签名公钥集合（公开数据，可被客户端缓存）。
func (s *Server) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	requestID := s.requestID(request)
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set(headerAllow, "GET, HEAD")
		writeProblem(writer, request, http.StatusMethodNotAllowed, codeReqInvalid, requestID, "")
		return
	}
	document, err := s.opts.Tokens.PublishedJWKS(request.Context())
	if err != nil || len(document) == 0 {
		s.logFailure(request, requestID, "jwks_unavailable")
		writeProblem(writer, request, http.StatusServiceUnavailable, codeDBUnavailable,
			requestID, "")
		return
	}
	header := writer.Header()
	header.Set(headerContentType, headerContentJSON)
	// 公钥是公开数据；允许短期缓存以便客户端按 kid 缓存，吊销/轮换后最迟 5 分钟生效。
	header.Set(headerCacheControl, "public, max-age=300")
	header.Set(headerNosniff, "nosniff")
	if requestID != "" {
		header.Set(headerRequestID, requestID)
	}
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(document)
	}
}
