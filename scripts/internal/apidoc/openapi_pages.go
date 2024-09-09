package apidoc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// 本文件生成「页面/表单操作」的 OpenAPI 参考物（docs/reference/http-openapi.json），
// 并用 AST 扫描到的真实页面命名路由核对页面操作契约。
//
// 分工：
//   - 契约本身（字段/响应/状态转移/限流说明）来自 internal/transport 的
//     pagecontracts_*.go，与运行期文档同一来源；
//   - 方法/路径来自 ui/ 中 UIRoute 字面量的 AST 扫描（不是手写清单）；
//   - 两者不一致、或范围内的页面路由缺少契约时，-check 直接失败；
//   - 未登记契约的页面路由（管理/审计/报告/备份/OAuth 页面等）不写入本步文档，
//     只计入数量并在 http-routes.json / http-api.md 里保留完整路由清单。

// pageOperationScopePrefixes 是本步已定义 OpenAPI 模式的页面命名路由前缀。
// 管理组（admin.*）由后续步骤统一定义，不在此范围。
var pageOperationScopePrefixes = []string{"auth.", "account.", "support."}

// pageOpenAPIVersion 是生成物中 info.version 的稳定值（发布版本由运行期文档给出）。
const pageOpenAPIVersion = "devel"

// PageFieldView 是文档表格使用的字段视图。
type PageFieldView struct {
	Name     string
	Location string
	Required bool
	Secret   bool
	Summary  string
}

// PageOperationView 是页面操作契约的文档视图。
type PageOperationView struct {
	Name             string
	Method           string
	Path             string
	Access           string
	Module           string
	Summary          string
	CSRF             string
	Fields           []PageFieldView
	Responses        []string
	StateTransitions []string
	EnabledWhen      string
	Notes            []string
}

// PageOpenAPIArtifact 是本步页面 OpenAPI 的生成结果与自检问题。
type PageOpenAPIArtifact struct {
	// JSON 是确定性 OpenAPI 文档（空前缀，页面路径相对站内前缀）。
	JSON []byte
	// Operations 是已登记契约的文档视图（按命名路由排序）。
	Operations []PageOperationView
	// Issues 是契约与真实路由的不一致问题；非空时 -write/-check 失败。
	Issues []string
	// Documented/Unregistered 是写入文档/未登记契约的页面路由数量。
	Documented   int
	Unregistered int
}

// buildPageOpenAPI 从 AST 扫描到的页面路由构建页面 OpenAPI 参考物。
func buildPageOpenAPI(pages []PageRoute) (*PageOpenAPIArtifact, error) {
	artifact := &PageOpenAPIArtifact{}
	scanned := make(map[string]PageRoute, len(pages))
	routes := make([]transport.PageRoute, 0, len(pages))
	for _, page := range pages {
		access, problem := pageAccessFromScan(page.Access)
		if problem != "" {
			artifact.Issues = append(artifact.Issues,
				fmt.Sprintf("页面路由 %s 的访问级别无法识别：%s", page.Name, problem))
			access = "public"
		}
		scanned[page.Name] = page
		routes = append(routes, transport.PageRoute{
			Name: page.Name, Method: page.Method, Path: page.Path, Access: access,
		})
	}

	// 1) 范围内的真实页面路由必须有契约，且方法/路径一致。
	for _, page := range pages {
		if !pageOperationInScope(page.Name) {
			continue
		}
		contract, ok := transport.PageOperationContract(page.Name)
		if !ok {
			artifact.Issues = append(artifact.Issues, fmt.Sprintf(
				"页面路由 %s（%s %s）缺少 OpenAPI 页面契约：请在 internal/transport/pagecontracts_*.go "+
					"登记字段/响应/状态转移", page.Name, page.Method, page.Path))
			continue
		}
		if contract.Method != page.Method || contract.Path != page.Path {
			artifact.Issues = append(artifact.Issues, fmt.Sprintf(
				"页面路由 %s 与契约不一致：实际 %s %s，契约 %s %s；请同步 ui 路由与契约表",
				page.Name, page.Method, page.Path, contract.Method, contract.Path))
		}
	}

	// 2) 契约表中的每条都必须对应真实注册的页面路由（不能凭空编造接口）。
	for _, operation := range transport.PageOperations() {
		if _, ok := scanned[operation.Name]; !ok {
			artifact.Issues = append(artifact.Issues, fmt.Sprintf(
				"页面操作契约 %s（%s %s）没有对应的实际页面路由：请删除过期契约或修正路由名",
				operation.Name, operation.Method, operation.Path))
			continue
		}
		view := pageOperationView(operation, scanned[operation.Name])
		artifact.Operations = append(artifact.Operations, view)
	}
	sort.Slice(artifact.Operations, func(left, right int) bool {
		return artifact.Operations[left].Name < artifact.Operations[right].Name
	})
	artifact.Documented = len(artifact.Operations)

	// 3) 用同一契约表与扫描路由生成确定性 OpenAPI 文档。
	codes := make([]transport.ErrorCodeInfo, 0, len(errs.RegisteredErrorCodes()))
	for _, definition := range errs.RegisteredErrorCodes() {
		codes = append(codes, transport.ErrorCodeInfo{
			Code: string(definition.Code), Category: string(definition.Category),
			Message: definition.DefaultMessage, HTTPStatus: definition.HTTPStatus,
		})
	}
	document, err := transport.OpenAPIDocumentWithPageRoutes("", codes,
		pageOpenAPIVersion, routes)
	if err != nil {
		return nil, fmt.Errorf("生成页面 OpenAPI 文档失败：%w", err)
	}
	if !json.Valid(document) {
		return nil, fmt.Errorf("生成的页面 OpenAPI 文档不是合法 JSON")
	}
	// 4) 文档自检：已登记操作必须都出现在 paths 中，且页面/JSON 语义分开标识。
	problems, unregistered := validatePageOpenAPIDocument(document, artifact.Documented)
	artifact.Issues = append(artifact.Issues, problems...)
	artifact.Unregistered = unregistered
	artifact.JSON = document
	return artifact, nil
}

// pageOperationInScope 报告命名路由是否属于本步已定义模式的范围。
func pageOperationInScope(name string) bool {
	for _, prefix := range pageOperationScopePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// pageAccessFromScan 把 UIRoute 字面量中的访问级别常量转换为文档口径。
func pageAccessFromScan(raw string) (string, string) {
	switch strings.TrimSpace(raw) {
	case "UIAccessPublic":
		return "public", ""
	case "UIAccessUser":
		return "user", ""
	case "UIAccessManagement":
		return "management", ""
	case "":
		return "public", "缺少 Access 字段"
	default:
		return "public", raw
	}
}

// pageOperationView 构造单条操作的文档视图。
func pageOperationView(operation transport.NamedPageOperation,
	page PageRoute) PageOperationView {
	access, _ := pageAccessFromScan(page.Access)
	view := PageOperationView{
		Name:             operation.Name,
		Method:           operation.Method,
		Path:             operation.Path,
		Access:           access,
		Module:           operation.Module,
		Summary:          operation.Summary,
		CSRF:             operation.CSRF,
		Responses:        transport.PageResponseStatuses(operation.Method, access),
		StateTransitions: append([]string(nil), operation.StateTransitions...),
		Notes:            append([]string(nil), operation.Notes...),
	}
	if operation.Method == "POST" {
		view.Fields = append(view.Fields, PageFieldView{
			Name: transport.DefaultCSRFFormField, Location: "form", Required: true, Secret: true,
			Summary: "CSRF 令牌（隐藏字段）",
		})
	}
	for _, field := range operation.Fields {
		view.Fields = append(view.Fields, PageFieldView{
			Name: field.Name, Location: "form", Required: field.Required,
			Secret: field.WriteOnly, Summary: field.Description,
		})
	}
	for _, field := range operation.Query {
		view.Fields = append(view.Fields, PageFieldView{
			Name: field.Name, Location: "query", Required: field.Required,
			Secret: field.WriteOnly, Summary: field.Description,
		})
	}
	sort.Slice(view.Fields, func(left, right int) bool {
		return view.Fields[left].Name < view.Fields[right].Name
	})
	return view
}

// validatePageOpenAPIDocument 校验生成文档的结构与语义标识，返回问题清单与未登记数。
func validatePageOpenAPIDocument(document []byte, wantDocumented int) ([]string, int) {
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return []string{fmt.Sprintf("页面 OpenAPI 文档不是合法 JSON：%v", err)}, 0
	}
	var issues []string
	paths, ok := decoded["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return []string{"页面 OpenAPI 文档缺少 paths"}, 0
	}
	documented := 0
	operationIDs := map[string]bool{}
	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			issues = append(issues, fmt.Sprintf("路径 %s 结构无效", path))
			continue
		}
		for method, rawOperation := range item {
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				issues = append(issues, fmt.Sprintf("%s %s 操作结构无效", method, path))
				continue
			}
			operationID, _ := operation["operationId"].(string)
			if operationID == "" {
				issues = append(issues, fmt.Sprintf("%s %s 缺少 operationId", method, path))
			} else if operationIDs[operationID] {
				issues = append(issues, fmt.Sprintf("operationId 重复：%s", operationID))
			} else {
				operationIDs[operationID] = true
			}
			kind, _ := operation["x-login-route-kind"].(string)
			switch kind {
			case "html-page":
				documented++
				if name, _ := operation["x-login-route-name"].(string); name == "" {
					issues = append(issues, fmt.Sprintf("%s %s 缺少命名路由", method, path))
				}
				if responses, _ := operation["responses"].(map[string]any); len(responses) == 0 {
					issues = append(issues, fmt.Sprintf("%s %s 缺少 responses", method, path))
				}
			case "json-api":
				// JSON API 只为健康/文档端点，数量固定；这里只确认标识存在。
			default:
				issues = append(issues, fmt.Sprintf("%s %s 缺少 x-login-route-kind", method, path))
			}
		}
	}
	if wantDocumented > 0 && documented != wantDocumented {
		issues = append(issues, fmt.Sprintf(
			"页面 OpenAPI 文档操作数 %d 与已登记契约数 %d 不一致", documented, wantDocumented))
	}
	contract, _ := decoded["x-login-page-contract"].(map[string]any)
	unregistered := 0
	if raw, ok := contract["unregistered"].(float64); ok {
		unregistered = int(raw)
	} else {
		issues = append(issues, "页面 OpenAPI 文档缺少未登记页面路由计数")
	}
	sort.Strings(issues)
	return issues, unregistered
}

// pageOperationTableRows 生成 Markdown 表格行。
func (artifact *PageOpenAPIArtifact) pageOperationTableRows() [][]string {
	rows := make([][]string, 0, len(artifact.Operations))
	for _, operation := range artifact.Operations {
		rows = append(rows, []string{
			"`" + operation.Name + "`", operation.Method, "`" + operation.Path + "`",
			operation.Access, operation.Module, formatPageFields(operation.Fields),
			strings.Join(operation.Responses, ", "),
			summarizeTransitions(operation.StateTransitions),
		})
	}
	return rows
}

// formatPageFields 把字段视图格式化为表格单元格文本。
func formatPageFields(fields []PageFieldView) string {
	if len(fields) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		label := field.Name
		if field.Location == "query" {
			label = "query:" + label
		}
		if field.Required {
			label += "（必填）"
		}
		if field.Secret {
			label += "[只写]"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "、")
}

// summarizeTransitions 压缩状态转移文本，避免表格过长。
func summarizeTransitions(transitions []string) string {
	if len(transitions) == 0 {
		return "-"
	}
	limit := len(transitions)
	if limit > 2 {
		limit = 2
	}
	summary := strings.Join(transitions[:limit], "；")
	if len(transitions) > limit {
		summary += " 等"
	}
	return summary
}
