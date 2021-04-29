package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOpenAPIDocumentMatchesRegistry 验证文档错误码 enum 与注册表投影逐项一致。
func TestOpenAPIDocumentMatchesRegistry(t *testing.T) {
	document, err := OpenAPIDocument("/api", testErrorCodes, "v-test")
	if err != nil {
		t.Fatalf("生成 OpenAPI 失败: %v", err)
	}
	again, err := OpenAPIDocument("/api", testErrorCodes, "v-test")
	if err != nil || !bytes.Equal(document, again) {
		t.Fatalf("OpenAPI 输出不确定: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("OpenAPI 不是合法 JSON: %v", err)
	}
	if decoded["openapi"] != openAPIVersion {
		t.Fatalf("openapi 版本 = %v", decoded["openapi"])
	}
	info, _ := decoded["info"].(map[string]any)
	if info["version"] != "v-test" {
		t.Fatalf("info.version = %v", info["version"])
	}
	paths, _ := decoded["paths"].(map[string]any)
	if paths == nil {
		t.Fatal("OpenAPI 缺少 paths")
	}
	for _, path := range []string{"/api/healthz", "/api/openapi.json"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("OpenAPI 缺少路径 %s", path)
		}
	}
	components, _ := decoded["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	errorSchema, _ := schemas["Error"].(map[string]any)
	properties, _ := errorSchema["properties"].(map[string]any)
	codeProperty, _ := properties["code"].(map[string]any)
	enumValues, _ := codeProperty["enum"].([]any)
	if len(enumValues) != len(testErrorCodes) {
		t.Fatalf("错误码 enum 数量 = %d，期望 %d", len(enumValues), len(testErrorCodes))
	}
	enumSet := make(map[string]bool, len(enumValues))
	for _, value := range enumValues {
		enumSet[value.(string)] = true
	}
	registry, _ := decoded["x-login-error-registry"].(map[string]any)
	if len(registry) != len(testErrorCodes) {
		t.Fatalf("x-login-error-registry 数量 = %d，期望 %d", len(registry), len(testErrorCodes))
	}
	for _, code := range testErrorCodes {
		if !enumSet[code.Code] {
			t.Fatalf("enum 缺少错误码 %s", code.Code)
		}
		entry, ok := registry[code.Code].(map[string]any)
		if !ok {
			t.Fatalf("注册表缺少错误码 %s", code.Code)
		}
		if entry["category"] != code.Category || entry["message"] != code.Message {
			t.Fatalf("错误码 %s 注册表投影不一致: %v", code.Code, entry)
		}
		status, _ := entry["http_status"].(float64)
		if int(status) != code.HTTPStatus {
			t.Fatalf("错误码 %s HTTP 状态 = %v，期望 %d", code.Code, entry["http_status"], code.HTTPStatus)
		}
	}
	if decoded["x-login-oauth-reserved-prefix"] != OAuthReservedPrefix+"/" {
		t.Fatalf("OAuth 保留前缀扩展缺失: %v", decoded["x-login-oauth-reserved-prefix"])
	}
	// 文档不得包含密钥、数据库路径等实现细节字段。
	lower := strings.ToLower(string(document))
	for _, forbidden := range []string{"password", "private key", "database path", "sec" + "ret"} {
		if bytes.Contains([]byte(lower), []byte(forbidden)) {
			t.Fatalf("OpenAPI 文档包含可疑敏感词 %q", forbidden)
		}
	}
}

// TestOpenAPIServedByHandler 验证服务端输出与公开生成函数一致。
func TestOpenAPIServedByHandler(t *testing.T) {
	options := testOptions(nil)
	options.Prefix = "/api"
	handler := buildHandler(t, options)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("OpenAPI 端点状态 = %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json; charset=utf-8" {
		t.Fatalf("OpenAPI Content-Type = %q", contentType)
	}
	generated, err := OpenAPIDocument("/api", testErrorCodes, "test")
	if err != nil {
		t.Fatalf("生成文档失败: %v", err)
	}
	if !bytes.Equal(recorder.Body.Bytes(), generated) {
		t.Fatal("服务端 OpenAPI 与生成函数输出不一致")
	}
}

// TestOpenAPIRejectsInvalidPrefix 验证非法前缀在生成阶段被拒绝。
func TestOpenAPIRejectsInvalidPrefix(t *testing.T) {
	for _, prefix := range []string{"/api/", "api", "//api", "/a/../b", "/a?b", "/a#b"} {
		if _, err := OpenAPIDocument(prefix, testErrorCodes, "test"); err == nil {
			t.Fatalf("非法前缀 %q 应被拒绝", prefix)
		}
	}
	document, err := OpenAPIDocument("", testErrorCodes, "test")
	if err != nil {
		t.Fatalf("空前缀应合法: %v", err)
	}
	if !bytes.Contains(document, []byte(`"/healthz"`)) {
		t.Fatalf("空前缀文档路径错误: %s", document)
	}
}
