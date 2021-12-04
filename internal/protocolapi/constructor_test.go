package protocolapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
)

// TestNewRequiresDependencies 验证缺依赖/参数非法时拒绝构造（fail-closed）。
func TestNewRequiresDependencies(t *testing.T) {
	env := newTestEnv(t, nil)
	base := func() protocolapi.Options {
		return protocolapi.Options{
			OAuth: env.flow, OIDC: env.oidc, Tokens: env.tokens,
			Sessions: env.sessions, ClientAuth: env.clientAuth, QRLogin: env.qr,
			QRClientID: testClientPublic, QRScopes: []string{"profile"},
			EnableDeviceFlow: true, EnableIntrospection: true,
		}
	}
	cases := []struct {
		name   string
		mutate func(*protocolapi.Options)
	}{
		{"缺少 OAuth", func(o *protocolapi.Options) { o.OAuth = nil }},
		{"缺少 OIDC", func(o *protocolapi.Options) { o.OIDC = nil }},
		{"缺少令牌发布", func(o *protocolapi.Options) { o.Tokens = nil }},
		{"缺少会话", func(o *protocolapi.Options) { o.Sessions = nil }},
		{"状态查询缺客户端认证", func(o *protocolapi.Options) { o.ClientAuth = nil }},
		{"BasePath 非法", func(o *protocolapi.Options) { o.BasePath = "/login/" }},
		{"BasePath 与 issuer 不一致", func(o *protocolapi.Options) { o.BasePath = "/login" }},
		{"请求体上限过小", func(o *protocolapi.Options) { o.MaxBodyBytes = 16 }},
		{"请求体上限过大", func(o *protocolapi.Options) { o.MaxBodyBytes = 8 << 20 }},
		{"非法 QRClientID", func(o *protocolapi.Options) { o.QRClientID = "app_bad" }},
		{"非法 LoginPath", func(o *protocolapi.Options) { o.LoginPath = "login" }},
		{"非法会话 Cookie 名", func(o *protocolapi.Options) { o.SessionCookieName = "bad name" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := base()
			test.mutate(&options)
			if _, err := protocolapi.New(options); !errors.Is(err, protocolapi.ErrOptionsInvalid) {
				t.Fatalf("期望 ErrOptionsInvalid，实际 %v", err)
			}
		})
	}
}

// staticUsers 是 OIDC 用户资料来源的边界替身（本测试只验证端点一致性，不验证
// UserInfo 语义，UserInfo 语义由真实服务在 oauth_test 中覆盖）。
type staticUsers struct{}

func (staticUsers) LoadUserInfo(context.Context, string) (oidc.UserInfoRecord, bool, error) {
	return oidc.UserInfoRecord{}, false, nil
}

// TestNewRejectsIssuerEndpointMismatch 用真实 oidc 服务验证端点一致性检查：oidc
// 服务允许的端点形式与 protocolapi 常量不同，协议端点必须拒绝构造。
func TestNewRejectsIssuerEndpointMismatch(t *testing.T) {
	env := newTestEnv(t, nil)
	// 复用 oidc 服务的内部配置无法直接修改，这里直接构造一个端点路径不同的服务：
	// oidc.New 只要求端点与 issuer 同源同前缀，不要求具体路径。
	alternate, err := oidc.New(oidc.Options{
		Issuer:                testIssuer,
		AuthorizationEndpoint: testIssuer + "/oauth/authorize",
		TokenEndpoint:         testIssuer + "/oauth/token",
		UserInfoEndpoint:      testIssuer + "/oidc/userinfo",
		JWKSURI:               testIssuer + "/oidc/jwks",
		Tokens:                env.tokens,
		Users:                 staticUsers{},
		RevocationChecker:     &revocationLinker{},
		SubjectSecret:         []byte("protocolapi-test-subject-secret-32b"),
	})
	if err != nil {
		t.Fatalf("备用 OIDC 服务构造失败: %v", err)
	}
	_, err = protocolapi.New(protocolapi.Options{
		OAuth: env.flow, OIDC: alternate, Tokens: env.tokens,
		Sessions: env.sessions, ClientAuth: env.clientAuth,
	})
	if !errors.Is(err, protocolapi.ErrOptionsInvalid) {
		t.Fatalf("OIDC 端点与挂载路径不一致应拒绝构造，实际 %v", err)
	}
}

// TestDiscoveryOnlyDeclaresImplementedCapabilities 验证 Discovery 只声明真实
// 挂载的能力，且不出现未实现字段。
func TestDiscoveryOnlyDeclaresImplementedCapabilities(t *testing.T) {
	env := newTestEnv(t, nil)
	response, body := env.doRequest(http.MethodGet, protocolapi.PathDiscovery, requestOptions{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Discovery 状态 = %d: %s", response.StatusCode, body)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("Discovery Content-Type = %q", contentType)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("Discovery 不是合法 JSON: %v", err)
	}
	// 未实现能力绝不能出现。
	for _, forbidden := range []string{"end_session_endpoint", "registration_endpoint",
		"pushed_authorization_request_endpoint", "request_object_signing_alg_values_supported"} {
		if _, exists := document[forbidden]; exists {
			t.Fatalf("Discovery 声明了未实现能力 %q", forbidden)
		}
	}
	if document["issuer"] != testIssuer {
		t.Fatalf("issuer = %v", document["issuer"])
	}
	expected := map[string]string{
		"authorization_endpoint":        testIssuer + protocolapi.PathAuthorize,
		"token_endpoint":                testIssuer + protocolapi.PathToken,
		"userinfo_endpoint":             testIssuer + protocolapi.PathUserInfo,
		"jwks_uri":                      testIssuer + protocolapi.PathJWKS,
		"revocation_endpoint":           testIssuer + protocolapi.PathRevoke,
		"introspection_endpoint":        testIssuer + protocolapi.PathIntrospect,
		"device_authorization_endpoint": testIssuer + protocolapi.PathDeviceAuthorization,
	}
	for field, want := range expected {
		if document[field] != want {
			t.Fatalf("%s = %v，期望 %s", field, document[field], want)
		}
	}
	grantTypes := stringList(t, document["grant_types_supported"])
	for _, want := range []string{"authorization_code", "refresh_token", "client_credentials",
		protocolapi.DeviceCodeGrantType} {
		if !contains(grantTypes, want) {
			t.Fatalf("grant_types_supported 缺少 %q: %v", want, grantTypes)
		}
	}
	authMethods := stringList(t, document["token_endpoint_auth_methods_supported"])
	for _, want := range []string{"client_secret_basic", "client_secret_post", "tls_client_auth"} {
		if !contains(authMethods, want) {
			t.Fatalf("token_endpoint_auth_methods_supported 缺少 %q: %v", want, authMethods)
		}
	}
	if methods := stringList(t, document["code_challenge_methods_supported"]); len(methods) != 1 ||
		methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", methods)
	}
	scopes := stringList(t, document["scopes_supported"])
	if !contains(scopes, "openid") || !contains(scopes, "offline_access") {
		t.Fatalf("scopes_supported = %v", scopes)
	}
	if document["claims_parameter_supported"] != false ||
		document["request_parameter_supported"] != false ||
		document["request_uri_parameter_supported"] != false {
		t.Fatal("未实现的请求参数能力必须声明为 false")
	}
}

// TestDiscoveryOmitsDisabledCapabilities 验证显式关闭设备码/状态查询时发现文档与
// 路由同步收缩，不夸大能力。
func TestDiscoveryOmitsDisabledCapabilities(t *testing.T) {
	env := newTestEnv(t, func(options *protocolapi.Options) {
		options.EnableDeviceFlow = false
		options.EnableIntrospection = false
	})
	response, body := env.doRequest(http.MethodGet, protocolapi.PathDiscovery, requestOptions{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Discovery 状态 = %d: %s", response.StatusCode, body)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("Discovery 不是合法 JSON: %v", err)
	}
	if _, exists := document["device_authorization_endpoint"]; exists {
		t.Fatal("未启用设备码却声明了 device_authorization_endpoint")
	}
	if _, exists := document["introspection_endpoint"]; exists {
		t.Fatal("未启用状态查询却声明了 introspection_endpoint")
	}
	if grantTypes := stringList(t, document["grant_types_supported"]); contains(grantTypes,
		protocolapi.DeviceCodeGrantType) {
		t.Fatal("未启用设备码却声明了设备码 grant")
	}
	for _, path := range []string{protocolapi.PathDeviceAuthorization,
		protocolapi.PathIntrospect} {
		response, _ := env.doRequest(http.MethodPost, path, requestOptions{form: map[string][]string{}})
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 未挂载时应 404，实际 %d", path, response.StatusCode)
		}
	}
}

// TestJWKSPublishesVerifiablePublicKeys 验证 /jwks 返回已发布的 ES256 公钥，且
// 不包含私钥字段。
func TestJWKSPublishesVerifiablePublicKeys(t *testing.T) {
	env := newTestEnv(t, nil)
	// 触发一次真实签发以生成 active 签名密钥（JWKS 只发布已生成的公钥）。
	_ = env.issueDirectToken([]string{"profile"})
	response, body := env.doRequest(http.MethodGet, protocolapi.PathJWKS, requestOptions{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS 状态 = %d: %s", response.StatusCode, body)
	}
	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("JWKS 不是合法 JSON: %v", err)
	}
	if len(document.Keys) == 0 {
		t.Fatal("JWKS 没有任何公钥")
	}
	key := document.Keys[0]
	if key["kty"] != "EC" || key["crv"] != "P-256" {
		t.Fatalf("JWKS 公钥类型异常: %v", key)
	}
	for _, secretField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, exists := key[secretField]; exists {
			t.Fatalf("JWKS 泄露私钥字段 %q", secretField)
		}
	}
	if key["kid"] == "" || key["kid"] == nil {
		t.Fatal("JWKS 公钥缺少 kid")
	}
	if cache := response.Header.Get("Cache-Control"); !strings.Contains(cache, "max-age") {
		t.Fatalf("JWKS Cache-Control = %q", cache)
	}
}

// TestHandlerAndMount 验证 Handler 独立可用、Mount 成功挂载、冲突检测生效。
func TestHandlerAndMount(t *testing.T) {
	env := newTestEnv(t, nil)
	// Handler 直接可用。
	response, _ := env.doRequest(http.MethodGet, protocolapi.PathDiscovery, requestOptions{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Handler 直连 Discovery 状态 = %d", response.StatusCode)
	}
	// 未知路径 404：与已实现错误一致，同时带 X-Request-ID 头与 JSON request_id。
	unknown, unknownBody := env.doRequest(http.MethodGet, "/oauth/unknown", requestOptions{})
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("未知路径状态 = %d", unknown.StatusCode)
	}
	unknownRequestID := unknown.Header.Get("X-Request-ID")
	if unknownRequestID == "" {
		t.Fatal("未知路径响应缺少 X-Request-ID 头")
	}
	if payloadRequestID, _ := env.decodeJSON(unknownBody)["request_id"].(string); payloadRequestID != unknownRequestID {
		t.Fatalf("未知路径 request_id 不一致: body=%q header=%q",
			payloadRequestID, unknownRequestID)
	}
	// 冲突检测：宿主已注册同一路径。
	conflictMux := http.NewServeMux()
	conflictMux.HandleFunc(protocolapi.PathToken, func(http.ResponseWriter, *http.Request) {})
	if err := env.server.Mount(conflictMux); !errors.Is(err, protocolapi.ErrMountConflict) {
		t.Fatalf("路径冲突应返回 ErrMountConflict，实际 %v", err)
	}
	// 失败挂载不得留下半挂载状态。
	if _, pattern := conflictMux.Handler(httptest.NewRequest(http.MethodGet,
		protocolapi.PathDiscovery, nil)); pattern != "" {
		t.Fatalf("冲突失败后不应注册任何路由，实际 pattern=%q", pattern)
	}
	// 正常挂载并端到端可用。
	mux := http.NewServeMux()
	if err := env.server.Mount(mux); err != nil {
		t.Fatalf("Mount 失败: %v", err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	discovery, err := server.Client().Get(server.URL + protocolapi.PathDiscovery)
	if err != nil {
		t.Fatalf("挂载后请求 Discovery 失败: %v", err)
	}
	defer discovery.Body.Close()
	if discovery.StatusCode != http.StatusOK {
		t.Fatalf("挂载后 Discovery 状态 = %d", discovery.StatusCode)
	}
	// 方法错误返回 405 且带 Allow。
	method, _ := env.doRequest(http.MethodPut, protocolapi.PathToken,
		requestOptions{form: map[string][]string{"grant_type": {"authorization_code"}}})
	if method.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("PUT token 状态 = %d", method.StatusCode)
	}
	if allow := method.Header.Get("Allow"); allow != http.MethodPost {
		t.Fatalf("Allow = %q", allow)
	}
}

// TestPathsArePassedThrough 验证 Paths 返回含 BasePath 的完整挂载清单。
func TestPathsArePassedThrough(t *testing.T) {
	env := newTestEnv(t, nil)
	paths := env.server.Paths()
	if len(paths) < 10 {
		t.Fatalf("挂载路径过少: %v", paths)
	}
	for _, path := range []string{protocolapi.PathDiscovery, protocolapi.PathToken,
		protocolapi.PathQRClaim, protocolapi.PathDeviceAuthorization,
		protocolapi.PathIntrospect, protocolapi.PathRevoke, protocolapi.PathUserInfo} {
		if !contains(paths, path) {
			t.Fatalf("Paths 缺少 %s: %v", path, paths)
		}
	}
}

// TestPathPrefixHandlerForComposedMounts 验证宿主按命名空间挂载时的可组合处理器
// （模拟 internal/serverapp.ComposeHandler “先剥离前缀再交给子处理器”的语义）。
func TestPathPrefixHandlerForComposedMounts(t *testing.T) {
	env := newTestEnv(t, nil)
	oauthHandler, err := env.server.PathPrefixHandler("/oauth")
	if err != nil {
		t.Fatalf("构造 /oauth 命名空间处理器失败: %v", err)
	}
	wellKnownHandler, err := env.server.PathPrefixHandler("/.well-known")
	if err != nil {
		t.Fatalf("构造 /.well-known 命名空间处理器失败: %v", err)
	}
	jwksHandler, err := env.server.PathPrefixHandler("/jwks")
	if err != nil {
		t.Fatalf("构造 /jwks 命名空间处理器失败: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/oauth/", http.StripPrefix("/oauth", oauthHandler))
	mux.Handle("/.well-known/", http.StripPrefix("/.well-known", wellKnownHandler))
	mux.Handle("/jwks", http.StripPrefix("/jwks", jwksHandler))
	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()

	discovery, err := client.Get(server.URL + protocolapi.PathDiscovery)
	if err != nil || discovery.StatusCode != http.StatusOK {
		t.Fatalf("命名空间 Discovery 请求失败: %v %v", err, discovery)
	}
	discovery.Body.Close()
	jwks, err := client.Get(server.URL + protocolapi.PathJWKS)
	if err != nil || jwks.StatusCode != http.StatusOK {
		t.Fatalf("命名空间 JWKS 请求失败: %v %v", err, jwks)
	}
	jwks.Body.Close()
	// /oauth/token 方法错误应到达协议处理器并返回 405（证明前缀重建正确）。
	request, _ := http.NewRequest(http.MethodGet, server.URL+protocolapi.PathToken, nil)
	tokenResponse, err := client.Do(request)
	if err != nil {
		t.Fatalf("命名空间令牌端点请求失败: %v", err)
	}
	tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("命名空间令牌端点状态 = %d", tokenResponse.StatusCode)
	}
	// 非命名空间前缀拒绝构造。
	if _, err := env.server.PathPrefixHandler("/not-mounted"); err == nil {
		t.Fatal("非路由前缀应拒绝构造命名空间处理器")
	}
	if _, err := env.server.PathPrefixHandler(""); err == nil {
		t.Fatal("空前缀应拒绝构造命名空间处理器")
	}
}

// stringList 把 JSON 数组转换为字符串列表。
func stringList(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("期望 JSON 数组，实际 %T: %v", value, value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("数组元素不是字符串: %v", item)
		}
		result = append(result, text)
	}
	return result
}

// contains 判断字符串列表是否包含指定值。
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
