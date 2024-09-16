package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// 本文件验证管理 OpenAPI 的认证契约：文档级 security 必须声明且引用已定义的
// securitySchemes；任何操作不得把 security 置空（审计 M1：此前 78/78 操作无
// security、scheme 未被引用，且 ticket-redeem 残留 security=nil）。

// TestBuildOpenAPIDocumentDeclaresSecurity 验证生成的文档带文档级 security、
// 引用的 scheme 都已定义，且没有任何操作关闭认证。
func TestBuildOpenAPIDocumentDeclaresSecurity(t *testing.T) {
	operations := transport.AdminOperations()
	raw, err := buildOpenAPIDocument(operations)
	if err != nil {
		t.Fatalf("生成管理 OpenAPI 失败：%v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("管理 OpenAPI 不是合法 JSON：%v", err)
	}
	components, _ := document["components"].(map[string]any)
	schemesRaw, _ := components["securitySchemes"].(map[string]any)
	schemes := map[string]bool{}
	for name := range schemesRaw {
		schemes[name] = true
	}
	for _, want := range []string{"managementSessionCookie", "managementSessionBearer"} {
		if !schemes[want] {
			t.Fatalf("缺少 securityScheme %s", want)
		}
	}
	documentSecurity, ok := document["security"].([]any)
	if !ok || len(documentSecurity) < 2 {
		t.Fatalf("文档级 security 缺失或不足（%v）：管理 API 必须声明 Cookie/Bearer", document["security"])
	}
	referenced := map[string]bool{}
	for _, rawRequirement := range documentSecurity {
		requirement, _ := rawRequirement.(map[string]any)
		if len(requirement) == 0 {
			t.Fatal("文档级 security requirement 为空")
		}
		for schemeName := range requirement {
			referenced[schemeName] = true
			if !schemes[schemeName] {
				t.Fatalf("文档级 security 引用未定义 scheme %s", schemeName)
			}
		}
	}
	for _, want := range []string{"managementSessionCookie", "managementSessionBearer"} {
		if !referenced[want] {
			t.Fatalf("文档级 security 未引用 %s", want)
		}
	}
	// 每个操作：不得把 security 置空；若覆盖则必须非空且引用已定义 scheme。
	ticketRedeems := 0
	paths, _ := document["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for method, rawOperation := range item {
			operation, _ := rawOperation.(map[string]any)
			rawSecurity, hasSecurity := operation["security"]
			if hasSecurity {
				requirements, ok := rawSecurity.([]any)
				if !ok || len(requirements) == 0 {
					t.Fatalf("%s %s 把 security 置空（不允许关闭认证）", method, path)
				}
				for _, rawRequirement := range requirements {
					requirement, _ := rawRequirement.(map[string]any)
					for schemeName := range requirement {
						if !schemes[schemeName] {
							t.Fatalf("%s %s security 引用未定义 scheme %s", method, path, schemeName)
						}
					}
				}
			}
			if operation["x-login-download"] == "ticket-redeem" {
				ticketRedeems++
				if hasSecurity {
					t.Fatalf("%s %s 票据兑换不应覆盖文档级认证要求（应先走管理会话）", method, path)
				}
			}
		}
	}
	if ticketRedeems < 2 {
		t.Fatalf("票据兑换操作数异常：%d（期望报告与备份各一个）", ticketRedeems)
	}
	if len(paths) < 60 {
		t.Fatalf("唯一路径仅 %d 条，管理 API 契约疑似缺失", len(paths))
	}
}

// TestValidateGeneratedRequiresSecurity 验证结构自检会拒绝缺少文档级 security 或
// 引用未定义 scheme 的文档。
func TestValidateGeneratedRequiresSecurity(t *testing.T) {
	raw, err := buildOpenAPIDocument(transport.AdminOperations())
	if err != nil {
		t.Fatalf("生成管理 OpenAPI 失败：%v", err)
	}
	markdown := renderMarkdown(transport.AdminOperations())
	if issues := validateGenerated(raw, markdown); len(issues) > 0 {
		t.Fatalf("合法生成物自检失败：%v", issues)
	}
	// 1) 删除文档级 security：必须被自检拒绝。
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("解析生成物失败：%v", err)
	}
	delete(document, "security")
	broken, _ := json.Marshal(document)
	issues := validateGenerated(broken, markdown)
	if !containsIssue(issues, "security") {
		t.Fatalf("缺少安全声明未被拒绝：%v", issues)
	}
	// 2) security 引用未定义 scheme：必须被自检拒绝。
	document["security"] = []any{map[string]any{"notDefinedScheme": []string{}}}
	broken, _ = json.Marshal(document)
	issues = validateGenerated(broken, markdown)
	if !containsIssue(issues, "notDefinedScheme") {
		t.Fatalf("未定义 scheme 未被拒绝：%v", issues)
	}
}

// containsIssue 报告问题清单中是否有包含目标片段的问题。
func containsIssue(issues []string, fragment string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, fragment) {
			return true
		}
	}
	return false
}
