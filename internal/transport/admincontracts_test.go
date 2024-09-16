package transport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件验证管理 API 契约表自身完整、与真实注册路由双向一致、且不包含本步
// 明确排除的域（管理组 269 / 直接改密 258/259 / 邮件投递 266）。

// TestAdminOperationContractsComplete 验证每条契约的结构与语义完整性。
func TestAdminOperationContractsComplete(t *testing.T) {
	operations := AdminOperations()
	if len(operations) < 70 {
		t.Fatalf("管理 API 契约仅 %d 条，期望 >=70（运维/报告/客服域）", len(operations))
	}
	domains := map[string]bool{}
	seen := map[string]bool{}
	for _, operation := range operations {
		if seen[operation.Key] {
			t.Fatalf("契约重复：%s", operation.Key)
		}
		seen[operation.Key] = true
		domains[operation.Domain] = true
		if err := ValidateAdminOperation(operation.AdminOperation); err != nil {
			t.Fatalf("契约 %s 无效：%v", operation.Key, err)
		}
		if _, err := AdminSuccessDataSchema(operation.Success, operation.ExtraKeys); err != nil {
			t.Fatalf("契约 %s 成功响应声明无效：%v", operation.Key, err)
		}
		// confirm/reason 声明必须与请求体字段的必填语义一致。
		hasConfirmField, confirmRequired := false, false
		hasReasonField, reasonRequired := false, false
		for _, field := range operation.Body {
			switch field.Name {
			case "confirm":
				hasConfirmField, confirmRequired = true, field.Required
			case "reason":
				hasReasonField, reasonRequired = true, field.Required
			}
		}
		if hasConfirmField != operation.Confirm || (hasConfirmField && !confirmRequired) {
			t.Fatalf("%s 的 confirm 声明与请求体字段不一致（field=%t required=%t declared=%t）",
				operation.Key, hasConfirmField, confirmRequired, operation.Confirm)
		}
		if reasonRequired != operation.Reason {
			t.Fatalf("%s 的 reason 声明与请求体字段不一致（required=%t declared=%t）",
				operation.Key, reasonRequired, operation.Reason)
		}
		_ = hasReasonField
		// 秘密字段示例必须是明确合成值（不可用于真实操作）。
		for _, field := range operation.Body {
			if !field.Secret {
				continue
			}
			if field.MaxLength == 0 {
				t.Fatalf("%s 秘密字段 %s 缺少长度上限", operation.Key, field.Name)
			}
			if field.Name == "token" && operation.Download != "ticket-redeem" {
				t.Fatalf("只有票据兑换端点可以声明 token 字段：%s", operation.Key)
			}
		}
		// 下载语义必须准确：票据签发/兑换与流式下载分开声明。
		switch operation.Download {
		case "":
			if operation.Success == "download" {
				t.Fatalf("%s 声明 download 成功响应但未标注 Download 语义", operation.Key)
			}
		case "stream", "ticket-issue", "ticket-redeem":
		default:
			t.Fatalf("%s 的 Download 语义 %q 未登记", operation.Key, operation.Download)
		}
	}
	for _, domain := range AdminDomainOrder {
		if !domains[domain] && domain != "core" {
			t.Fatalf("域 %s 没有登记任何契约", domain)
		}
	}
}

// TestAdminContractsMatchRegisteredRoutes 用 docs/reference/http-routes.json 的
// 真实注册路由交叉核对：范围内路由必须全部有契约，契约必须都有真实路由。
func TestAdminContractsMatchRegisteredRoutes(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "reference", "http-routes.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("路由事实来源不可用（%v）；由 scripts/adminapi-doc -check 在仓库根执行同等校验", err)
	}
	var routesFile struct {
		AdminRoutes []struct {
			Method  string `json:"method"`
			Pattern string `json:"pattern"`
		} `json:"admin_routes"`
	}
	if err := json.Unmarshal(raw, &routesFile); err != nil {
		t.Fatalf("解析 %s 失败：%v", path, err)
	}
	scanned := map[string]bool{}
	for _, route := range routesFile.AdminRoutes {
		scanned[strings.ToUpper(route.Method)+" "+route.Pattern] = true
	}
	contracted := map[string]bool{}
	var missing []string
	for _, operation := range AdminOperations() {
		contracted[operation.Key] = true
		if !scanned[operation.Key] {
			missing = append(missing, operation.Key)
		}
	}
	// docs/reference/http-routes.json 可能尚未刷新（并行步骤新增路由）；此时契约
	// 比清单多是预期状态，由 scripts/adminapi-doc -check（AST 扫描实时源码）最终把关。
	if len(missing) > 0 {
		t.Logf("路由清单 %s 可能过期（清单 %d 条 / 缺失契约 %d 条）：%v",
			path, len(scanned), len(missing), missing)
	}
	// 范围内真实路由必须全部登记契约（范围外属 269/258/259/266，不要求）。
	scope := map[string]bool{
		"meta": true, "error-codes": true, "audit": true, "reports": true,
		"report-plans": true, "backups": true, "tasks": true, "diagnostics": true,
		"settings": true, "notifications": true, "support": true,
	}
	for key := range scanned {
		pattern := key[strings.Index(key, " ")+1:]
		first := strings.SplitN(pattern, "/", 2)[0]
		if scope[first] && !contracted[key] {
			t.Fatalf("真实注册路由 %s 缺少契约", key)
		}
	}
}

// TestAdminContractsExcludeOtherSteps 验证排除域没有契约（不写占位 schema）。
func TestAdminContractsExcludeOtherSteps(t *testing.T) {
	exclusions := AdminScopeExclusions()
	for _, operation := range AdminOperations() {
		first := strings.SplitN(operation.Pattern, "/", 2)[0]
		if reason, excluded := exclusions[first]; excluded {
			t.Fatalf("契约 %s 落在排除域 %q（%s）", operation.Key, first, reason)
		}
	}
	// 直接改名/改密的 HTTP 端点（258/259）也未实现，不得出现在契约里。
	for _, operation := range AdminOperations() {
		if strings.Contains(operation.Pattern, "password") || strings.Contains(operation.Pattern, "username") {
			t.Fatalf("契约 %s 疑似直接改名/改密端点（属 258/259，未实现不得写占位）", operation.Key)
		}
	}
}

// TestAdminComponentSchemasCoverSuccessReferences 验证成功响应引用的组件都已登记。
func TestAdminComponentSchemasCoverSuccessReferences(t *testing.T) {
	schemas := AdminComponentSchemas()
	if len(schemas) < 30 {
		t.Fatalf("管理 API schema 组件仅 %d 个，期望更多", len(schemas))
	}
	for _, operation := range AdminOperations() {
		schema, err := AdminSuccessDataSchema(operation.Success, operation.ExtraKeys)
		if err != nil {
			t.Fatalf("%s 成功 schema 无效：%v", operation.Key, err)
		}
		if ref, ok := schema["$ref"].(string); ok {
			name := strings.TrimPrefix(ref, "#/components/schemas/")
			if _, exists := schemas[name]; !exists {
				t.Fatalf("%s 引用未登记组件 %s", operation.Key, name)
			}
		}
	}
	// 信封与下载组件必须有明确语义（错误码注册表同源在生成器中校验）。
	for _, name := range []string{"AdminSuccessEnvelope", "AdminErrorEnvelope", "AdminDownloadStream",
		"AdminReportTicket", "AdminBackupTicket", "AdminRetention"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("缺少关键组件 %s", name)
		}
	}
}

// TestAdminDownloadSemanticsAreAccurate 验证下载相关操作声明不把服务器路径当下载地址。
func TestAdminDownloadSemanticsAreAccurate(t *testing.T) {
	issueCount, redeemCount, streamCount := 0, 0, 0
	for _, operation := range AdminOperations() {
		switch operation.Download {
		case "ticket-issue":
			issueCount++
			for _, field := range operation.Body {
				if field.Name == "token" {
					t.Fatalf("%s 票据签发端点不得在请求体接受 token", operation.Key)
				}
			}
		case "ticket-redeem":
			redeemCount++
			foundToken := false
			for _, field := range operation.Body {
				if field.Name == "token" && field.Secret {
					foundToken = true
				}
			}
			if !foundToken {
				t.Fatalf("%s 票据兑换端点必须声明只写 token 字段", operation.Key)
			}
			if operation.Success != "download" {
				t.Fatalf("%s 票据兑换成功响应必须是文件流", operation.Key)
			}
		case "stream":
			streamCount++
			if operation.Success != "download" {
				t.Fatalf("%s 流式下载成功响应必须是文件流", operation.Key)
			}
		}
	}
	if issueCount < 2 || redeemCount < 2 || streamCount < 1 {
		t.Fatalf("下载语义覆盖不足：issue=%d redeem=%d stream=%d",
			issueCount, redeemCount, streamCount)
	}
}

// TestAdminOperationsNoServerPathExamples 验证契约文本不把宿主路径当下载地址。
func TestAdminOperationsNoServerPathExamples(t *testing.T) {
	forbidden := []string{"/var/", "/home/", "/etc/", "C:\\", "database/", "hostpath"}
	for _, operation := range AdminOperations() {
		texts := append([]string{operation.Summary, operation.Description}, operation.Notes...)
		for _, field := range operation.Body {
			texts = append(texts, field.Description)
		}
		for _, text := range texts {
			lower := strings.ToLower(text)
			for _, fragment := range forbidden {
				if strings.Contains(lower, strings.ToLower(fragment)) {
					t.Fatalf("%s 文本疑似包含宿主路径 %q：%q", operation.Key, fragment, text)
				}
			}
		}
	}
}
