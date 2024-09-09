package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// samplePageRoutes 返回覆盖公开/登录后/管理三种访问级别的页面路由样本。
func samplePageRoutes() []PageRoute {
	return []PageRoute{
		{Name: "auth.login", Method: http.MethodGet, Path: "/login", Access: "public"},
		{Name: "auth.login.submit", Method: http.MethodPost, Path: "/login", Access: "public"},
		{Name: "account.password.submit", Method: http.MethodPost, Path: "/account/password", Access: "user"},
		{Name: "support.recovery_execute.submit", Method: http.MethodPost,
			Path: "/support/recovery/execute", Access: "management"},
	}
}

// decodeOpenAPI 解析生成的文档。
func decodeOpenAPI(t *testing.T, document []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("OpenAPI 不是合法 JSON: %v", err)
	}
	return decoded
}

// lookupOperation 从文档中取出指定方法/路径的操作对象。
func lookupOperation(t *testing.T, document map[string]any, method, path string) map[string]any {
	t.Helper()
	paths, _ := document["paths"].(map[string]any)
	item, ok := paths[path].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI 缺少路径 %s", path)
	}
	operation, ok := item[strings.ToLower(method)].(map[string]any)
	if !ok {
		t.Fatalf("路径 %s 缺少 %s 操作", path, method)
	}
	return operation
}

// resolvePageResponse 解析响应的 #/components/responses 引用；无引用时原样返回。
func resolvePageResponse(t *testing.T, document, responses map[string]any,
	status string) map[string]any {
	t.Helper()
	entry, ok := responses[status].(map[string]any)
	if !ok {
		t.Fatalf("响应 %s 结构无效", status)
	}
	ref, _ := entry["$ref"].(string)
	if ref == "" {
		return entry
	}
	components, _ := document["components"].(map[string]any)
	componentResponses, _ := components["responses"].(map[string]any)
	name := strings.TrimPrefix(ref, "#/components/responses/")
	resolved, ok := componentResponses[name].(map[string]any)
	if !ok {
		t.Fatalf("响应 %s 引用的组件 %q 不存在", status, ref)
	}
	return resolved
}

// TestOpenAPIDocumentsPageOperations 验证页面/表单操作被完整投影，并与 JSON API
// 语义分开标识。
func TestOpenAPIDocumentsPageOperations(t *testing.T) {
	document, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "v-test", samplePageRoutes())
	if err != nil {
		t.Fatalf("生成 OpenAPI 失败: %v", err)
	}
	if err := validateOpenAPIDocument(document); err != nil {
		t.Fatalf("生成文档自检失败: %v", err)
	}
	decoded := decodeOpenAPI(t, document)

	// JSON API 与页面/表单必须分别标识。
	health := lookupOperation(t, decoded, http.MethodGet, "/api/healthz")
	if tags := stringSlice(health["tags"]); len(tags) != 1 || tags[0] != pageJSONTag {
		t.Fatalf("健康检查 tags = %v，期望 [json-api]", health["tags"])
	}
	if kind := health["x-login-route-kind"]; kind != "json-api" {
		t.Fatalf("健康检查 route-kind = %v", kind)
	}

	loginGET := lookupOperation(t, decoded, http.MethodGet, "/api/login")
	if tags := stringSlice(loginGET["tags"]); len(tags) != 1 || tags[0] != pageHTMLTag {
		t.Fatalf("登录页 tags = %v，期望 [page-html]", loginGET["tags"])
	}
	if name := loginGET["x-login-route-name"]; name != "auth.login" {
		t.Fatalf("登录页命名路由 = %v", name)
	}
	if _, isGETWithBody := loginGET["requestBody"]; isGETWithBody {
		t.Fatal("GET 页面操作不应有 requestBody")
	}
	parameters, ok := loginGET["parameters"].([]any)
	if !ok || len(parameters) != 1 {
		t.Fatalf("登录页查询参数 = %v，期望 return 一条", loginGET["parameters"])
	}
	if _, exists := loginGET["security"]; exists {
		t.Fatal("公开页面不应声明会话 Cookie 安全方案")
	}

	loginPOST := lookupOperation(t, decoded, http.MethodPost, "/api/login")
	body, ok := loginPOST["requestBody"].(map[string]any)
	if !ok {
		t.Fatal("登录提交缺少 requestBody")
	}
	content, _ := body["content"].(map[string]any)
	form, ok := content["application/x-www-form-urlencoded"].(map[string]any)
	if !ok {
		t.Fatalf("登录提交内容类型 = %v", content)
	}
	schema, _ := form["schema"].(map[string]any)
	required := stringSlice(schema["required"])
	for _, want := range []string{"csrf_token", "identifier", "password"} {
		if !contains(required, want) {
			t.Fatalf("登录提交必填字段缺少 %s：%v", want, required)
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	passwordSchema, _ := properties["password"].(map[string]any)
	if passwordSchema["writeOnly"] != true {
		t.Fatal("密码字段必须 writeOnly")
	}
	if example, _ := passwordSchema["example"].(string); !strings.Contains(example, "example-") {
		t.Fatalf("密码示例不是明确合成值：%q", example)
	}
	csrfSchema, _ := properties["csrf_token"].(map[string]any)
	if csrfSchema["writeOnly"] != true {
		t.Fatal("CSRF 令牌字段必须 writeOnly")
	}
	csrfDescription, _ := csrfSchema["description"].(string)
	if !strings.Contains(csrfDescription, "匿名公开表单") {
		t.Fatalf("公开表单 CSRF 说明不符合预期：%q", csrfDescription)
	}
	exampleMap, _ := form["example"].(map[string]any)
	passwordExample, _ := exampleMap["password"].(string)
	if passwordExample == "" || !strings.Contains(passwordExample, "synthetic") {
		t.Fatalf("请求示例密码不是合成值：%q", passwordExample)
	}

	responses, _ := loginPOST["responses"].(map[string]any)
	for _, status := range []string{"200", "303", "400", "403", "429"} {
		if _, ok := responses[status]; !ok {
			t.Fatalf("登录提交缺少响应 %s", status)
		}
	}
	redirect := resolvePageResponse(t, decoded, responses, "303")
	headers, _ := redirect["headers"].(map[string]any)
	if _, ok := headers["Location"]; !ok {
		t.Fatal("303 响应缺少 Location 头说明")
	}
	if _, hasJSONContent := redirect["content"]; hasJSONContent {
		t.Fatal("303 跳转不应声明响应体内容")
	}
	// 页面错误必须如实声明两种形态：页面处理器 HTML 错误页 + 传输层前置拒绝的
	// application/json 统一错误信封；不得声明产品从未设置的额外错误码头。
	forbidden := resolvePageResponse(t, decoded, responses, "403")
	errorContent, _ := forbidden["content"].(map[string]any)
	if _, ok := errorContent["text/html; charset=utf-8"]; !ok {
		t.Fatalf("页面错误缺少 HTML 错误页声明：%v", errorContent)
	}
	jsonError, ok := errorContent["application/json"].(map[string]any)
	if !ok {
		t.Fatalf("页面错误缺少传输层 JSON 错误信封声明：%v", errorContent)
	}
	jsonSchema, _ := jsonError["schema"].(map[string]any)
	if jsonSchema["$ref"] != "#/components/schemas/Error" {
		t.Fatalf("页面 JSON 错误信封应引用 Error schema：%v", jsonSchema)
	}
	if bytes.Contains(document, []byte("X-Login-Error-Code")) {
		t.Fatal("文档不得声明产品代码从未设置的 X-Login-Error-Code 头")
	}
	pageTransport, _ := decoded["x-login-page-transport"].(map[string]any)
	if format, _ := pageTransport["response_format"].(string); !strings.Contains(format, "application/json") {
		t.Fatalf("页面传输语义未说明传输层前置拒绝返回 JSON 信封：%v", pageTransport["response_format"])
	}

	// 登录后页面声明会话 Cookie 安全方案。
	password := lookupOperation(t, decoded, http.MethodPost, "/api/account/password")
	security, _ := password["security"].([]any)
	if len(security) != 1 {
		t.Fatalf("登录后页面 security = %v", password["security"])
	}
	access := password["x-login-page-access"]
	if access != "user" {
		t.Fatalf("改密页访问级别 = %v", access)
	}

	// 文档级扩展：契约计数、协议开关说明、示例策略、来源与离线校验。
	contract, _ := decoded["x-login-page-contract"].(map[string]any)
	if contract["version"] != "ui.v1" {
		t.Fatalf("页面契约版本 = %v", contract["version"])
	}
	if documented, _ := contract["documented"].(float64); int(documented) != len(samplePageRoutes()) {
		t.Fatalf("已登记页面操作数 = %v，期望 %d", contract["documented"], len(samplePageRoutes()))
	}
	protocolMode, _ := decoded["x-login-protocol-mode"].(map[string]any)
	if enabledBy, _ := protocolMode["enabled_by"].(string); !strings.Contains(enabledBy, "protocol.enabled") {
		t.Fatalf("协议模式启用条件缺失：%v", protocolMode)
	}
	if _, ok := decoded["x-login-examples-policy"].(string); !ok {
		t.Fatal("缺少示例合成值策略说明")
	}
	if _, ok := decoded["x-login-offline-check"].(string); !ok {
		t.Fatal("缺少离线校验说明")
	}
	transportExtension, _ := decoded["x-login-page-transport"].(map[string]any)
	if _, ok := transportExtension["rate_limit"].(map[string]any); !ok {
		t.Fatal("缺少页面传输/限流说明")
	}
	components, _ := decoded["components"].(map[string]any)
	schemes, _ := components["securitySchemes"].(map[string]any)
	cookie, _ := schemes["sessionCookie"].(map[string]any)
	if cookie["in"] != "cookie" {
		t.Fatalf("会话安全方案 = %v", cookie)
	}
}

// TestOpenAPIPageContractDriftFails 验证实际路由与契约不一致时构造失败。
func TestOpenAPIPageContractDriftFails(t *testing.T) {
	cases := []struct {
		name   string
		routes []PageRoute
	}{
		{"路径漂移", []PageRoute{{Name: "auth.login", Method: http.MethodGet,
			Path: "/signin", Access: "public"}}},
		{"方法漂移", []PageRoute{{Name: "auth.login", Method: http.MethodPost,
			Path: "/login", Access: "public"}}},
		{"命名重复", []PageRoute{
			{Name: "auth.login", Method: http.MethodGet, Path: "/login", Access: "public"},
			{Name: "auth.login", Method: http.MethodGet, Path: "/login2", Access: "public"}}},
		{"方法路径重复", []PageRoute{
			{Name: "auth.login", Method: http.MethodGet, Path: "/login", Access: "public"},
			{Name: "auth.landing", Method: http.MethodGet, Path: "/login", Access: "public"}}},
		{"非法路径", []PageRoute{{Name: "auth.login", Method: http.MethodGet,
			Path: "/login/../x", Access: "public"}}},
		{"缺少命名", []PageRoute{{Name: "", Method: http.MethodGet, Path: "/login"}}},
	}
	for _, testCase := range cases {
		if _, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "test",
			testCase.routes); err == nil {
			t.Fatalf("%s：应拒绝生成文档", testCase.name)
		}
	}
}

// TestOpenAPISkipsUnregisteredPageRoutes 验证未登记契约的页面路由不进入本步文档，
// 只计入未登记数量，避免把未定义模式伪装成完整契约。
func TestOpenAPISkipsUnregisteredPageRoutes(t *testing.T) {
	routes := append(samplePageRoutes(), PageRoute{
		Name: "admin.dashboard", Method: http.MethodGet, Path: "/admin", Access: "management",
	})
	document, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "test", routes)
	if err != nil {
		t.Fatalf("生成 OpenAPI 失败: %v", err)
	}
	decoded := decodeOpenAPI(t, document)
	paths, _ := decoded["paths"].(map[string]any)
	if _, exists := paths["/api/admin"]; exists {
		t.Fatal("未登记契约的页面路由不应写入页面操作文档")
	}
	contract, _ := decoded["x-login-page-contract"].(map[string]any)
	if unregistered, _ := contract["unregistered"].(float64); int(unregistered) != 1 {
		t.Fatalf("未登记页面路由数 = %v，期望 1", contract["unregistered"])
	}
}

// TestOpenAPIPageDocumentDeterministic 验证同一输入生成逐字节相同的文档。
func TestOpenAPIPageDocumentDeterministic(t *testing.T) {
	first, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "v", samplePageRoutes())
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	second, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "v", samplePageRoutes())
	if err != nil {
		t.Fatalf("再次生成失败: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("页面 OpenAPI 输出不确定")
	}
}

// TestOpenAPIPageRoutesServedByHandler 验证服务端输出包含注入的页面路由文档。
func TestOpenAPIPageRoutesServedByHandler(t *testing.T) {
	options := testOptions(nil)
	options.Prefix = "/api"
	options.PageRoutes = samplePageRoutes()
	handler := buildHandler(t, options)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("OpenAPI 端点状态 = %d", recorder.Code)
	}
	generated, err := OpenAPIDocumentWithPageRoutes("/api", testErrorCodes, "test",
		samplePageRoutes())
	if err != nil {
		t.Fatalf("生成文档失败: %v", err)
	}
	if !bytes.Equal(recorder.Body.Bytes(), generated) {
		t.Fatal("服务端 OpenAPI 与生成函数输出不一致")
	}
	decoded := decodeOpenAPI(t, recorder.Body.Bytes())
	lookupOperation(t, decoded, http.MethodPost, "/api/login")
}

// TestPageOperationContractsComplete 验证契约表自身完整：方法/路径合法、页面写
// 操作声明 CSRF、秘密字段 writeOnly、GET 不带表单字段、摘要与状态转移非空。
func TestPageOperationContractsComplete(t *testing.T) {
	operations := PageOperations()
	if len(operations) == 0 {
		t.Fatal("页面操作契约表为空")
	}
	seen := map[string]bool{}
	secretNames := []string{"password", "current_password", "new_password", "password_confirm",
		"confirm_password", "token", "attempt_token", "code", "totp_code", "passkey_response",
		"response", "secret_password"}
	for _, item := range operations {
		if seen[item.Name] {
			t.Fatalf("契约重复：%s", item.Name)
		}
		seen[item.Name] = true
		if item.Method != http.MethodGet && item.Method != http.MethodPost {
			t.Fatalf("%s 方法非法：%q", item.Name, item.Method)
		}
		if problem := validPagePath(item.Path); problem != "" {
			t.Fatalf("%s 路径非法：%s", item.Name, problem)
		}
		if strings.TrimSpace(item.Summary) == "" || strings.TrimSpace(item.Description) == "" {
			t.Fatalf("%s 缺少摘要或说明", item.Name)
		}
		if len(item.StateTransitions) == 0 {
			t.Fatalf("%s 缺少状态转移说明", item.Name)
		}
		if item.Module == "" {
			t.Fatalf("%s 缺少页面模块", item.Name)
		}
		if pageModuleEnabledWhen[item.Module] == "" {
			t.Fatalf("%s 的页面模块 %q 未登记启用条件", item.Name, item.Module)
		}
		if item.Method == http.MethodPost && item.CSRF != pageCSRFAnonymous &&
			item.CSRF != pageCSRFSession {
			t.Fatalf("%s 作写操作但 CSRF 模式无效：%q", item.Name, item.CSRF)
		}
		if item.Method == http.MethodGet && (len(item.Fields) > 0 || item.CSRF != "") {
			t.Fatalf("%s 是 GET 操作，不应有表单字段或 CSRF 模式", item.Name)
		}
		for _, field := range item.Fields {
			if err := validatePageField(field); err != nil {
				t.Fatalf("%s 字段非法：%v", item.Name, err)
			}
			if field.Name == pageCSRFFieldName {
				t.Fatalf("%s 重复声明保留的 CSRF 字段", item.Name)
			}
			if contains(secretNames, field.Name) && !field.WriteOnly {
				t.Fatalf("%s 的秘密字段 %s 未标记 writeOnly", item.Name, field.Name)
			}
			if !field.WriteOnly && field.Kind == PageFieldString &&
				!strings.Contains(pageFieldExample(field), "example") && len(field.Enum) == 0 {
				t.Fatalf("%s 字段 %s 的示例不是明确合成值", item.Name, field.Name)
			}
		}
	}
	// 文档字符串不得包含真实凭据形态（Bearer + 长串、sk- 前缀等）。
	for _, item := range operations {
		for _, text := range append(append([]string{item.Summary, item.Description},
			item.Notes...), item.StateTransitions...) {
			if looksLikeRealSecret(text) {
				t.Fatalf("%s 的文档文本疑似包含真实秘密：%q", item.Name, text)
			}
		}
	}
}

// TestOpenAPIPageDocumentFitsResponseBuffer 验证全部页面契约生成的文档不超过传输层
// 响应超时保护的缓冲上限（1 MiB）。超过时真实 serve 的 /openapi.json 会因缓冲
// 溢出返回 500，因此该断言是重要回归护栏。
func TestOpenAPIPageDocumentFitsResponseBuffer(t *testing.T) {
	routes := make([]PageRoute, 0, 128)
	for _, operation := range PageOperations() {
		routes = append(routes, PageRoute{
			Name: operation.Name, Method: operation.Method,
			Path: operation.Path, Access: "public",
		})
	}
	document, err := OpenAPIDocumentWithPageRoutes("", testErrorCodes, "test", routes)
	if err != nil {
		t.Fatalf("生成文档失败: %v", err)
	}
	if int64(len(document)) >= maxBufferedResponseBytes {
		t.Fatalf("OpenAPI 文档 %d 字节超过响应缓冲上限 %d 字节："+
			"真实 serve 的 /openapi.json 会返回 500；请压缩契约或改用流式响应路径",
			len(document), maxBufferedResponseBytes)
	}
}

// TestValidateOpenAPIDocumentRejectsBrokenDocument 验证构造期自检会拒绝坏文档。
func TestValidateOpenAPIDocumentRejectsBrokenDocument(t *testing.T) {
	cases := []string{
		`{"openapi":"3.0.3"}`,
		`{"openapi":"2.0","paths":{"/a":{"get":{}}}}`,
		`{"openapi":"3.0.3","paths":{"/a":{"get":{"operationId":"x","responses":{}}}}}`,
		`{"openapi":"3.0.3","paths":{"/a":{"get":{"operationId":"x","responses":{"200":{}},"x-login-route-kind":"html-page"}}}}`,
	}
	for _, document := range cases {
		if err := validateOpenAPIDocument([]byte(document)); err == nil {
			t.Fatalf("坏文档应被拒绝：%s", document)
		}
	}
}

// looksLikeRealSecret 粗略检测文档文本是否包含真实凭据形态。
func looksLikeRealSecret(text string) bool {
	lower := strings.ToLower(text)
	for _, forbidden := range []string{"bearer ey", "sk-live", "sk_test", "-----begin"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}

// stringSlice 把 JSON 数组转为字符串切片。
func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

// contains 报告切片是否包含目标字符串。
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
