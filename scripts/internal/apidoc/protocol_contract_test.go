package apidoc

// 步骤 271：协议端点契约/例外/OpenAPI 离线校验的定向测试。
// 覆盖：契约表与真实端点双向一致、例外覆盖条件注册与项目信封、OpenAPI $ref/示例
// 校验能发现失效引用与疑似真实凭据；避免“特殊端点整体豁免”。

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtocolContractMatchesScannedEndpoints 在真实仓库上核对契约表与扫描端点。
func TestProtocolContractMatchesScannedEndpoints(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("仓库根: %v", err)
	}
	paths, endpoints, err := scanProtocol(root)
	if err != nil {
		t.Fatalf("扫描协议端点失败: %v", err)
	}
	artifact, err := buildProtocolContract(root, paths, endpoints)
	if err != nil {
		t.Fatalf("构建协议契约失败: %v", err)
	}
	if len(artifact.Issues) > 0 {
		t.Fatalf("协议契约自检未通过: %v", artifact.Issues)
	}
	if len(artifact.Contracts) != len(endpoints) {
		t.Fatalf("契约 %d 条，扫描端点 %d 条，应双向一致",
			len(artifact.Contracts), len(endpoints))
	}
	if len(artifact.Exceptions) == 0 {
		t.Fatal("协议例外登记为空（条件注册/自定义信封必须显式登记）")
	}
	// OpenAPI 操作应与契约一一对应。
	var document map[string]any
	if err := json.Unmarshal(artifact.JSON, &document); err != nil {
		t.Fatalf("协议 OpenAPI 不是合法 JSON: %v", err)
	}
	openapiPaths, _ := document["paths"].(map[string]any)
	operations := 0
	for _, value := range openapiPaths {
		if item, ok := value.(map[string]any); ok {
			for method := range item {
				if isHTTPMethod(strings.ToUpper(method)) {
					operations++
				}
			}
		}
	}
	if operations != len(artifact.Contracts) {
		t.Fatalf("OpenAPI 操作 %d，契约 %d，应一致", operations, len(artifact.Contracts))
	}
}

// TestValidateProtocolOpenAPIDetectsProblems 验证离线校验能发现缺失操作、失效
// $ref 与疑似真实凭据示例，而不是只看 JSON 语法。
func TestValidateProtocolOpenAPIDetectsProblems(t *testing.T) {
	contracts := protocolContractTable()
	raw, err := json.Marshal(map[string]any{
		"openapi": "3.0.3",
		"paths":   map[string]any{},
		"components": map[string]any{
			"schemas": map[string]any{"OAuthError": map[string]any{"type": "object"}},
		},
	})
	if err != nil {
		t.Fatalf("构造测试文档: %v", err)
	}
	issues := validateProtocolOpenAPI(raw, contracts)
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "缺少操作") {
		t.Fatalf("缺失操作未被发现: %v", issues)
	}

	broken := map[string]any{
		"openapi": "3.0.3",
		"paths": map[string]any{
			"/oauth/token": map[string]any{
				"post": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"$ref": "#/components/schemas/MissingSchema"},
					},
					"example": map[string]any{
						"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.example-signature",
						"note":         "BEGIN PRIVATE KEY",
					},
				},
			},
		},
	}
	brokenRaw, err := json.Marshal(broken)
	if err != nil {
		t.Fatalf("构造问题文档: %v", err)
	}
	issues = validateOpenAPIReferencesAny(broken)
	if len(issues) == 0 {
		t.Fatalf("失效 $ref 未被发现")
	}
	issues = validateOpenAPIExamplesAny(broken)
	joined = strings.Join(issues, "\n")
	if !strings.Contains(joined, "疑似真实凭据") {
		t.Fatalf("疑似真实凭据示例未被发现: %v", issues)
	}
	if len(brokenRaw) == 0 {
		t.Fatal("测试文档为空")
	}
}
