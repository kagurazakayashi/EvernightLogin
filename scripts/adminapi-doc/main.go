// Command adminapi-doc 生成并校验管理 JSON API（运维/报告/客服域）的机器与人类契约。
//
// 用法（仓库根目录）：
//
//	go run ./scripts/adminapi-doc -write   # 生成 docs/reference/http-admin-api.md 与 http-openapi-admin.json
//	go run ./scripts/adminapi-doc -check   # 只读校验：契约↔真实路由一致、生成物逐字节一致（失败非零退出）
//	go run ./scripts/adminapi-doc -list    # 列出将生成的文件（不写文件）
//
// 设计边界：
//   - 路由事实来源：docs/reference/http-routes.json（由 scripts/reference 通过 AST 扫描
//     adminapi/serverapp 真实注册得到）；本工具不手写第二份端点清单；
//   - 契约来源：internal/transport 的 AdminOperations（与运行期 HTTP 契约层同包）；
//   - 本工具只读源码/生成物，不访问网络、数据库或运行中的服务；
//   - 管理组与直接改名/改密（258/259）属步骤 269、邮件投递
//     记录属后续步骤（266）：这些前缀既不允许出现契约，也不生成占位 schema；
//   - 步骤 268 已登记的 docs/reference/http-api.md 与 http-openapi.json 本工具不改写，
//     避免与页面契约生成器和 268 审计冻结冲突。
//
// 退出码：0=通过；1=校验失败/生成拒绝；2=用法或环境错误。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	"github.com/kagurazakayashi/EvernightLogin/scripts/internal/apidoc"
)

// referenceHTTPRoutesJSON 是路由事实来源（相对仓库根）。
const referenceHTTPRoutesJSON = "docs/reference/http-routes.json"

// 生成物相对路径。
const (
	outputJSON = "docs/reference/http-openapi-admin.json"
	outputMD   = "docs/reference/http-admin-api.md"
)

// schemaVersion 是本生成物的格式版本。
const schemaVersion = "evernight.reference/v1/http-openapi-admin"

// adminScopePrefixes 是本步登记契约的管理路由一级前缀（相对管理 API 前缀）。
var adminScopePrefixes = []string{
	"meta", "error-codes", "users", "roles", "groups", "permissions",
	"applications", "sessions", "audit", "reports", "report-plans", "backups",
	"tasks", "diagnostics", "settings", "notifications", "deliveries", "support",
}

func main() {
	os.Exit(run(os.Args[1:]))
}

// run 执行命令并返回进程退出码。
func run(args []string) int {
	flags := flag.NewFlagSet("adminapi-doc", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	writeMode := flags.Bool("write", false, "生成管理 API 参考文件（原子写入）")
	checkMode := flags.Bool("check", false, "只读校验契约与生成物（失败非零退出）")
	listMode := flags.Bool("list", false, "列出将生成的文件")
	rootFlag := flags.String("root", "", "仓库根目录（默认当前目录）")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "adminapi-doc: 不接受位置参数")
		return 2
	}
	root := *rootFlag
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "adminapi-doc: 解析仓库根目录失败：", err)
		return 2
	}
	artifact, err := generate(absolute)
	if err != nil {
		fmt.Fprintln(os.Stderr, "adminapi-doc:", err)
		return 1
	}
	for _, warning := range artifact.Warnings {
		fmt.Fprintln(os.Stderr, "WARN:", warning)
	}
	for _, issue := range artifact.Issues {
		fmt.Fprintln(os.Stderr, "FAIL:", issue)
	}
	switch {
	case *listMode:
		fmt.Println(outputJSON)
		fmt.Println(outputMD)
		return 0
	case *writeMode:
		if len(artifact.Issues) > 0 {
			fmt.Fprintf(os.Stderr, "adminapi-doc: 契约存在 %d 个问题，拒绝生成文档\n", len(artifact.Issues))
			return 1
		}
		for path, content := range artifact.Files {
			full := filepath.Join(absolute, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				fmt.Fprintln(os.Stderr, "adminapi-doc: 创建目录失败：", err)
				return 1
			}
			if err := os.WriteFile(full, content, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "adminapi-doc: 写入失败：", err)
				return 1
			}
			fmt.Println("WROTE:", path)
		}
		fmt.Printf("ADMINAPI DOC WRITE: PASS files=%d operations=%d\n",
			len(artifact.Files), artifact.OperationCount)
		return 0
	case *checkMode:
		if len(artifact.Issues) > 0 {
			fmt.Printf("ADMINAPI DOC CHECK: FAIL issues=%d\n", len(artifact.Issues))
			return 1
		}
		for path, content := range artifact.Files {
			full := filepath.Join(absolute, filepath.FromSlash(path))
			existing, readErr := os.ReadFile(full)
			if readErr != nil {
				fmt.Fprintln(os.Stderr, "FAIL: 缺少生成物 ", path, "：", readErr)
				fmt.Println("ADMINAPI DOC CHECK: FAIL")
				return 1
			}
			if string(existing) != string(content) {
				fmt.Fprintf(os.Stderr,
					"FAIL: %s 与契约不一致；请运行 go run ./scripts/adminapi-doc -write\n", path)
				fmt.Println("ADMINAPI DOC CHECK: FAIL")
				return 1
			}
		}
		fmt.Printf("ADMINAPI DOC CHECK: PASS files=%d operations=%d\n",
			len(artifact.Files), artifact.OperationCount)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "adminapi-doc: 需要 -write、-check 或 -list 之一")
		flags.Usage()
		return 2
	}
}

// artifact 是一次生成结果。
type artifact struct {
	Files          map[string][]byte
	Issues         []string
	Warnings       []string
	OperationCount int
}

// scannedRoute 是 http-routes.json 中的管理路由条目。
type scannedRoute struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
}

// routesFile 是 docs/reference/http-routes.json 的只读子集。
type routesFile struct {
	AdminRoutes []scannedRoute `json:"admin_routes"`
}

// generate 读取真实注册路由与契约，校验并生成文件内容（不写磁盘）。
//
// 路由事实优先来自 AST 扫描（scripts/internal/apidoc.ScanAdminRoutes，与
// docs/reference/http-routes.json 同一扫描器），这样并行步骤新增路由（尚未刷新
// 参考生成物时）也能立即参与契约校验；扫描失败时回退到已生成的 http-routes.json。
func generate(root string) (artifact, error) {
	operations := transport.AdminOperations()
	if len(operations) == 0 {
		return artifact{}, fmt.Errorf("管理 API 契约表为空")
	}
	routes, warnings := loadAdminRoutes(root)
	if len(routes) == 0 {
		return artifact{}, fmt.Errorf("未能获取管理路由事实（AST 扫描与 %s 都不可用）",
			referenceHTTPRoutesJSON)
	}
	issues := validateContracts(operations, routes)
	if len(issues) > 0 {
		sort.Strings(issues)
		return artifact{Issues: issues, Warnings: warnings, OperationCount: len(operations)}, nil
	}
	document, err := buildOpenAPIDocument(operations)
	if err != nil {
		return artifact{}, err
	}
	markdown := renderMarkdown(operations)
	// 生成物自检：JSON 可解析、秘密/路径样例安全、排除域无残留。
	issues = append(issues, validateGenerated(document, markdown)...)
	files := map[string][]byte{
		outputJSON: document,
		outputMD:   markdown,
	}
	sort.Strings(issues)
	return artifact{Files: files, Issues: issues, Warnings: warnings,
		OperationCount: len(operations)}, nil
}

// loadAdminRoutes 优先用 AST 扫描真实注册路由，失败时回退到生成的 JSON 清单；
// 并比较两者，清单过期只告警（由 scripts/reference -write 负责刷新）。
func loadAdminRoutes(root string) ([]scannedRoute, []string) {
	var warnings []string
	var routes []scannedRoute
	scanned, err := apidoc.ScanAdminRoutes(root)
	if err != nil {
		warnings = append(warnings, "AST 扫描管理路由失败，回退到 "+referenceHTTPRoutesJSON+"："+err.Error())
	} else {
		routes = make([]scannedRoute, 0, len(scanned))
		for _, route := range scanned {
			routes = append(routes, scannedRoute{Method: route.Method,
				Pattern: route.Pattern, Source: route.Source})
		}
	}
	raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(referenceHTTPRoutesJSON)))
	if readErr != nil {
		if len(routes) == 0 {
			return nil, append(warnings, "读取 "+referenceHTTPRoutesJSON+" 失败："+readErr.Error())
		}
		return routes, warnings
	}
	var file routesFile
	if unmarshalErr := json.Unmarshal(raw, &file); unmarshalErr != nil {
		if len(routes) == 0 {
			return nil, append(warnings, "解析 "+referenceHTTPRoutesJSON+" 失败："+unmarshalErr.Error())
		}
		return routes, warnings
	}
	if len(routes) == 0 {
		return file.AdminRoutes, warnings
	}
	// 清单与 AST 不一致说明参考生成物尚未刷新，只告警（避免本工具写别家的生成物）。
	current := make(map[string]bool, len(routes))
	for _, route := range routes {
		current[strings.ToUpper(route.Method)+" "+route.Pattern] = true
	}
	listed := make(map[string]bool, len(file.AdminRoutes))
	for _, route := range file.AdminRoutes {
		listed[strings.ToUpper(route.Method)+" "+route.Pattern] = true
	}
	stale := 0
	for key := range current {
		if !listed[key] {
			stale++
		}
	}
	if stale > 0 || len(current) != len(listed) {
		warnings = append(warnings, fmt.Sprintf(
			"%s 与当前源码不一致（源码 %d 条 / 清单 %d 条），可能含并行步骤尚未提交的路由；"+
				"最终由 scripts/reference -write 与 271/273 统一刷新", referenceHTTPRoutesJSON,
			len(current), len(listed)))
	}
	return routes, warnings
}

// validateContracts 校验契约表与真实路由的双向一致、排除域无契约、单条契约合法。
func validateContracts(operations []transport.NamedAdminOperation,
	routes []scannedRoute) []string {
	var issues []string
	scanned := make(map[string]scannedRoute, len(routes))
	for _, route := range routes {
		scanned[strings.ToUpper(route.Method)+" "+route.Pattern] = route
	}
	contracts := make(map[string]bool, len(operations))
	for _, operation := range operations {
		key := strings.ToUpper(operation.Method) + " " + operation.Pattern
		if contracts[key] {
			issues = append(issues, "管理 API 契约重复："+key)
			continue
		}
		contracts[key] = true
		if err := transport.ValidateAdminOperation(operation.AdminOperation); err != nil {
			issues = append(issues, fmt.Sprintf("契约 %s 无效：%v", key, err))
		}
		if _, ok := transport.AdminSuccessDataSchema(operation.Success, operation.ExtraKeys); ok != nil {
			issues = append(issues, fmt.Sprintf("契约 %s 成功响应声明无效：%v", key, ok))
		}
		if _, ok := scanned[key]; !ok {
			issues = append(issues, fmt.Sprintf(
				"契约 %s 没有对应的真实注册路由（docs/reference/http-routes.json）：请删除过期契约或修正模式", key))
		}
	}
	// 真实路由必须被契约覆盖：范围内路由缺契约即失败；范围外（269/258/259/266）不要求。
	for _, route := range routes {
		key := strings.ToUpper(route.Method) + " " + route.Pattern
		first := strings.SplitN(route.Pattern, "/", 2)[0]
		if !isAdminScopePrefix(first) {
			continue
		}
		if !contracts[key] {
			issues = append(issues, fmt.Sprintf(
				"真实注册的管理路由 %s 缺少 OpenAPI 契约：请在 internal/transport/admincontracts_*.go 登记", key))
		}
	}
	// 排除域不得出现契约（防止把未开始/未实现端点写成占位）。
	exclusions := transport.AdminScopeExclusions()
	for first, reason := range exclusions {
		for key := range contracts {
			pattern := strings.TrimPrefix(key[strings.Index(key, " ")+1:], "")
			if strings.HasPrefix(pattern, first+"/") || pattern == first {
				issues = append(issues, fmt.Sprintf(
					"契约 %s 落在排除域 %q（%s），不得写占位 schema", key, first, reason))
			}
		}
	}
	sort.Strings(issues)
	return issues
}

// isAdminScopePrefix 报告一级前缀是否属于本步登记范围。
func isAdminScopePrefix(first string) bool {
	for _, prefix := range adminScopePrefixes {
		if first == prefix {
			return true
		}
	}
	return false
}

// buildOpenAPIDocument 生成管理 API 的 OpenAPI 3 文档。
func buildOpenAPIDocument(operations []transport.NamedAdminOperation) ([]byte, error) {
	if err := validateGeneratedEnvelopes(); err != nil {
		return nil, err
	}
	tags := make([]any, 0, len(transport.AdminDomainOrder))
	for _, domain := range transport.AdminDomainOrder {
		tags = append(tags, map[string]any{
			"name":        domain,
			"description": transport.AdminDomainTitles[domain],
		})
	}
	paths := make(map[string]any, len(operations))
	errorRegistry := map[string]any{}
	for _, definition := range errs.RegisteredErrorCodes() {
		errorRegistry[string(definition.Code)] = map[string]any{
			"category":    string(definition.Category),
			"message":     definition.DefaultMessage,
			"http_status": definition.HTTPStatus,
		}
	}
	for _, operation := range operations {
		path := "/" + operation.Pattern
		item, ok := paths[path].(map[string]any)
		if !ok {
			item = map[string]any{}
			paths[path] = item
		}
		method := strings.ToLower(operation.Method)
		if _, duplicate := item[method]; duplicate {
			return nil, fmt.Errorf("路径 %s 的 %s 方法重复登记", path, operation.Method)
		}
		openAPIOperation, err := buildOperation(operation)
		if err != nil {
			return nil, err
		}
		item[method] = openAPIOperation
	}
	document := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "login 管理 JSON API（管理组与直接管理 + 运维/报告/客服）",
			"version": "admin.v1",
			"description": "管理 JSON API 的机器契约：审计、通知、邮件投递、报告与报告计划、任务、备份恢复、" +
				"配置诊断、配置管理与客服人工恢复。成功/失败使用统一 JSON 信封（ok/request_id/data 或 " +
				"ok/code/message/request_id），错误码来自根包 errs 注册表；接口按装配条件注册，未装配领域 404。\n" +
				"认证：文档级 security 声明管理会话 Cookie 或 Bearer 会话秘密二选一；Cookie 会话的非安全方法还须 " +
				"X-CSRF-Token。管理组（用户/角色/用户组/权限/应用/成员/会话）与直接改名/直接重置密码" +
				"（一次操作两步验证证明、目标绑定、新口令只写不回显、must_change、旧会话与找回失效）均已覆盖；" +
				"口令/证明不进入响应与日志，root 执行同样需要两步验证与审计。",
		},
		"servers": []any{
			map[string]any{
				"url":         transport.AdminAPIBasePath,
				"description": "管理 API 默认前缀；实际完整路径 = server.path_prefix + 该前缀（可由部署配置覆盖）。",
			},
		},
		"tags": tags,
		"components": map[string]any{
			"schemas": transport.AdminComponentSchemas(),
			"securitySchemes": map[string]any{
				"managementSessionBearer": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "管理会话秘密（Authorization: Bearer <secret>）；每次请求由 session.Service.AuthorizeManagement 重新校验状态、安全版本与强认证新鲜度。",
				},
				"managementSessionCookie": map[string]any{
					"type": "apiKey", "in": "cookie", "name": "__Host-login_session",
					"description": "管理会话 Cookie；Cookie 会话的所有非安全方法必须携带与会话绑定的 X-CSRF-Token 并由服务端校验。",
				},
			},
		},
		"paths": paths,
		// 文档级安全要求：管理会话 Cookie 或 Bearer 会话秘密二选一（OR 语义）。
		// Cookie 会话的非安全方法还必须携带 X-CSRF-Token（见 x-login-admin-api.csrf）；
		// 每个操作都继承本要求，没有任何操作可以关闭认证（票据兑换同样需要会话）。
		"security": []any{
			map[string][]string{"managementSessionCookie": {}},
			map[string][]string{"managementSessionBearer": {}},
		},
		"x-login-admin-api": map[string]any{
			"envelope":         transport.AdminAPIEnvelopeDescription(),
			"auth":             "文档级 security：管理会话 Cookie 或 Bearer 会话秘密二选一（每次请求重新授权）；受限/强认证过期 fail-closed 403 REAUTH_REQUIRED；没有任何操作可关闭认证。",
			"csrf":             "Cookie 会话非安全方法必须携带 X-CSRF-Token；Bearer 会话不受浏览器 CSRF 影响、不要求该头。",
			"pagination":       "列表用 limit（默认 20，最大 100）+ offset（最大 1000000）；部分列表提供稳定 cursor（与 offset 互斥）。",
			"confirm":          "写操作必须 confirm=true（确认不是授权）；取消/清理/保留策略等还要求非空 reason（进入真实审计）。",
			"async":            "提交/受理 ≠ 完成/取消：异步操作返回真实任务/状态，需按任务编号查询终态。",
			"download":         "下载不暴露宿主路径：报告/备份使用一次性短期票据（签发→兑换流式下载）；审计导出每次下载重新授权。",
			"error_registry":   errorRegistry,
			"scope_exclusions": transport.AdminScopeExclusions(),
			"source_of_truth":  "路由：docs/reference/http-routes.json（AST 扫描真实注册）；契约：internal/transport/admincontracts_*.go；校验：go run ./scripts/adminapi-doc -check。",
		},
	}
	return json.MarshalIndent(document, "", "  ")
}

// validateGeneratedEnvelopes 确认信封组件存在。
func validateGeneratedEnvelopes() error {
	schemas := transport.AdminComponentSchemas()
	for _, name := range []string{"AdminSuccessEnvelope", "AdminErrorEnvelope", "AdminDownloadStream"} {
		if _, ok := schemas[name]; !ok {
			return fmt.Errorf("缺少信封/下载组件 %s", name)
		}
	}
	return nil
}

// buildOperation 生成单条 OpenAPI 操作。
func buildOperation(operation transport.NamedAdminOperation) (map[string]any, error) {
	successSchema, err := transport.AdminSuccessDataSchema(operation.Success, operation.ExtraKeys)
	if err != nil {
		return nil, fmt.Errorf("%s %s 成功响应无效：%w", operation.Method, operation.Pattern, err)
	}
	permission := "management-session-baseline"
	if operation.RootOnly {
		permission = "root-only"
	} else if len(operation.Permissions) > 0 {
		permission = strings.Join(operation.Permissions, " | ")
	}
	openAPIOperation := map[string]any{
		"tags":        []string{operation.Domain},
		"summary":     operation.Summary,
		"description": operation.Description,
		"operationId": "admin_" + strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(
			strings.ToLower(operation.Method)+"_"+operation.Pattern),
		"x-login-api-kind":       "admin-json-api",
		"x-login-domain":         operation.Domain,
		"x-login-permission":     permission,
		"x-login-root-only":      operation.RootOnly,
		"x-login-sensitive":      operation.Sensitive,
		"x-login-confirm":        operation.Confirm,
		"x-login-reason":         operation.Reason,
		"x-login-async-task":     operation.Async,
		"x-login-cancelable":     operation.Cancelable,
		"x-login-download":       operation.Download,
		"x-login-error-envelope": "admin-json",
	}
	if len(operation.Notes) > 0 {
		openAPIOperation["x-login-notes"] = append([]string(nil), operation.Notes...)
	}
	// 认证不按操作关闭：票据兑换同样需要管理会话（兑换时还会再次授权）。
	// 统一由文档级 security 声明"Cookie 或 Bearer 二选一"，操作不再覆盖为 nil。
	parameters := make([]any, 0, len(operation.Path)+len(operation.Query))
	for _, param := range operation.Path {
		parameters = append(parameters, buildParameter(param, "path"))
	}
	for _, param := range operation.Query {
		parameters = append(parameters, buildParameter(param, "query"))
	}
	if len(parameters) > 0 {
		openAPIOperation["parameters"] = parameters
	}
	if len(operation.Body) > 0 {
		body, err := buildRequestBody(operation)
		if err != nil {
			return nil, err
		}
		openAPIOperation["requestBody"] = body
	}
	openAPIOperation["responses"] = buildResponses(operation, successSchema)
	return openAPIOperation, nil
}

// buildParameter 构造路径/查询参数。
func buildParameter(param transport.AdminParam, in string) map[string]any {
	schema := map[string]any{"type": param.Type}
	if len(param.Enum) > 0 {
		schema["enum"] = append([]string(nil), param.Enum...)
	}
	if param.Min != 0 || param.Max != 0 {
		if param.Min != 0 {
			schema["minimum"] = param.Min
		}
		if param.Max != 0 {
			schema["maximum"] = param.Max
		}
	}
	if param.Default != "" {
		schema["default"] = param.Default
	}
	return map[string]any{
		"name": param.Name, "in": in, "required": param.Required,
		"description": param.Description, "schema": schema,
	}
}

// buildRequestBody 构造 JSON 请求体（含严格解码与合成示例）。
func buildRequestBody(operation transport.NamedAdminOperation) (map[string]any, error) {
	properties := make(map[string]any, len(operation.Body))
	required := make([]string, 0, len(operation.Body))
	example := make(map[string]any, len(operation.Body))
	for _, field := range operation.Body {
		schema := map[string]any{"type": field.Type, "description": field.Description}
		if len(field.Enum) > 0 {
			schema["enum"] = append([]string(nil), field.Enum...)
		}
		if field.MaxLength > 0 {
			schema["maxLength"] = field.MaxLength
		}
		if field.Secret {
			schema["writeOnly"] = true
			schema["example"] = adminSecretExample(field.Name)
			example[field.Name] = adminSecretExample(field.Name)
		} else {
			value := adminFieldExample(field)
			if value != nil {
				schema["example"] = value
				example[field.Name] = value
			}
		}
		properties[field.Name] = schema
		if field.Required {
			required = append(required, field.Name)
		}
	}
	return map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{
					"type": "object", "properties": properties, "required": required,
					"additionalProperties": false,
					"description":          "严格 JSON 解码：未知字段/重复字段/尾随内容/超限请求体一律拒绝。",
				},
				"example": example,
			},
		},
	}, nil
}

// adminFieldExample 为非秘密字段生成明确合成示例值。
func adminFieldExample(field transport.AdminField) any {
	switch field.Type {
	case "boolean":
		return true
	case "integer":
		return 1
	case "array":
		return []string{"example-format"}
	case "object":
		return map[string]any{"example_field": "example-value"}
	}
	if len(field.Enum) > 0 {
		return field.Enum[0]
	}
	switch field.Name {
	case "target_user_id", "new_assignee_user_id", "case_id", "request_id", "plan_id",
		"schedule_id", "backup_id", "job_id", "report_id", "task_id", "operation_id",
		"scope_id", "verification_reference", "token":
		return "00000000-0000-0000-0000-00000000example"
	case "date_time", "cutoff":
		return "2026-01-01T00:00:00Z"
	case "reason", "note", "name", "description":
		return "example-" + field.Name
	}
	return "example-" + field.Name
}

// adminSecretExample 为秘密字段生成不可用合成值。
func adminSecretExample(fieldName string) string {
	switch fieldName {
	case "totp_code":
		return "000000"
	case "password":
		return "example-password-synthetic-not-real"
	case "token":
		return "example-download-token-synthetic-not-real"
	}
	return "example-" + fieldName + "-synthetic-not-real"
}

// buildResponses 构造成功与典型拒绝响应。
func buildResponses(operation transport.NamedAdminOperation,
	successSchema map[string]any) map[string]any {
	responses := map[string]any{}
	if operation.Download == "stream" || operation.Download == "ticket-redeem" {
		responses["200"] = map[string]any{
			"description": "受控文件流式字节（不暴露宿主路径；使用稳定文件名与 no-store）。",
			"content": map[string]any{
				"application/octet-stream": map[string]any{
					"schema": map[string]any{"type": "string", "format": "binary"},
				},
			},
		}
	} else {
		responses["200"] = map[string]any{
			"description": "成功（统一 JSON 信封；data 见 schema）。",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":     "object",
						"required": []string{"ok", "request_id", "data"},
						"properties": map[string]any{
							"ok":         map[string]any{"type": "boolean", "enum": []bool{true}},
							"request_id": map[string]any{"type": "string"},
							"data":       successSchema,
						},
					},
				},
			},
		}
	}
	responses["400"] = adminErrorResponse("请求参数/格式无效（REQ_INVALID；严格 JSON 解码、分页/筛选/状态校验失败）。")
	responses["401"] = adminErrorResponse("管理会话无效或过期（AUTH_FAILED）。")
	responses["403"] = adminErrorResponse("权限不足、强认证未完成/过期（REAUTH_REQUIRED）、数据范围外或 CSRF 校验失败（ACCESS_DENIED）。")
	responses["404"] = adminErrorResponse("资源不存在、超出数据范围或该领域服务未装配。")
	responses["405"] = adminErrorResponse("方法不受支持。")
	responses["409"] = adminErrorResponse("版本/状态冲突（CONFLICT：行版本过期、异步终态不允许、一次性票据重复兑换等）。")
	responses["413"] = adminErrorResponse("请求体超过允许上限。")
	responses["429"] = adminErrorResponse("限流拒绝（RATE_LIMITED；按 Retry-After 等待）。")
	responses["500"] = adminErrorResponse("未预期内部错误（INTERNAL_ERROR；不泄露内部原因）。")
	responses["503"] = adminErrorResponse("维护模式或依赖不可用（DB/AUDIT/通知等）。")
	return responses
}

// adminErrorResponse 构造管理 API 失败信封响应。
func adminErrorResponse(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/AdminErrorEnvelope"},
			},
		},
	}
}

// renderMarkdown 渲染人类可读的管理 API 参考。
func renderMarkdown(operations []transport.NamedAdminOperation) []byte {
	var builder strings.Builder
	builder.WriteString("# 管理 JSON API 参考（管理组与直接管理 + 运维/报告/客服）\n\n")
	builder.WriteString("> 本文件由 `go run ./scripts/adminapi-doc -write` 从**AST 扫描的真实注册路由**" +
		"（与 `docs/reference/http-routes.json` 同一扫描器）与 `internal/transport/admincontracts_*.go` 契约生成，" +
		"**不要手工编辑**；`-check` 逐字节校验且失败非零退出。管理组（用户/角色/用户组/权限/应用/会话）" +
		"与直接改名/直接重置密码（步骤 258/259）均在本文件；直接操作的一次性证明与新口令不回显。\n\n")

	builder.WriteString("## 1. 基础约定\n\n")
	builder.WriteString(bulletLines([]string{
		"**挂载路径**：默认 `" + transport.AdminAPIBasePath + "`；实际完整路径 = `server.path_prefix` + 该前缀（可配置）。路由按装配条件注册，未装配领域返回 404。",
		"**统一信封**：" + transport.AdminAPIEnvelopeDescription(),
		"**认证**：文档级 security 声明 `managementSessionCookie`（会话 Cookie）与 `managementSessionBearer`（Authorization: Bearer 会话秘密）二选一；每个操作都继承该要求，没有任何操作可关闭认证（含下载票据兑换）。每次请求重新校验会话状态、账户状态、安全版本与强认证新鲜度；受限会话与强认证过期一开始就 403 REAUTH_REQUIRED，不做只读降级。",
		"**CSRF**：Cookie 会话的非安全方法必须携带与会话绑定的 `X-CSRF-Token`；Bearer 会话秘密不随浏览器自动发送，不要求 CSRF 头。",
		"**权限**：端点声明所需权限键（任一满足）；root 按内核语义拥有全部已实现权限，但仍校验认证、两步验证、目标/输入、业务一致性与审计。表内 `root-only` 表示仅真实 root/受信本地主体可调用。",
		"**敏感操作**：`敏感=是` 表示领域服务会按 `internal/policy` 复核再次认证/强认证新鲜度与策略下限；前端确认不能替代。",
		"**确认与原因**：所有写操作必须 `confirm=true`（确认不是授权）；取消/清理/保留策略/启停等还要求非空 `reason`，原因进入真实审计。",
		"**直接管理（改名/重置密码）**：操作者只能来自可信管理会话，并持独立权限 `users.username.change.other` / `users.password.reset.other`；目标用稳定 UserID，不得为 root 或超出可管理范围。每个逻辑操作要求操作者本次合格两步验证（TOTP 或 Passkey/WebAuthn；证明绑定操作者/会话/操作/目标/本次意图，提交即消费）；新口令只写不回显，成功只返回脱敏事实（`must_change`、撤销会话数、旧找回请求/凭证失效数）；root 执行同样需要两步验证与审计，应用内权限不等于全局权限。",
		"**分页与筛选**：列表 `limit` 默认 20、最大 100；`offset` 最大 1000000；部分列表提供稳定 `cursor`（与 offset 互斥，条件变化后旧游标失效）。时间参数使用 RFC3339；有界搜索最多 64 字符，通配符按字面。",
		"**异步语义**：提交/受理 ≠ 完成/取消。异步操作返回真实任务/状态，必须按任务编号查询终态；取消只表示“已受理取消”，终态以任务/状态为准。",
		"**下载与票据**：响应不暴露宿主路径，也不把服务器路径当下载地址。报告/备份使用**一次性短期下载票据**（签发只返回一次 token → 兑换时再次授权并重查产物状态 → 流式返回受控字节，重复兑换/撤权后拒绝）；审计导出每次下载重新授权。",
		"**错误码**：来自根包 `errs` 注册表（HTTP 状态与默认消息同源）；排障见 [errors.md](errors.md)。",
		"**范围**：本文件覆盖步骤 269：管理组（users/roles/groups/permissions/applications/sessions）与直接改名/直接重置密码（direct，一次操作两步验证证明）；以及 270 域（core/audit/reports/plans/backups/tasks/diagnostics/settings/notifications/deliveries/support）。",
	}))

	builder.WriteString("## 2. 操作总览\n\n")
	builder.WriteString("| 域 | 操作数 |\n|---|---|\n")
	counts := map[string]int{}
	for _, operation := range operations {
		counts[operation.Domain]++
	}
	for _, domain := range transport.AdminDomainOrder {
		builder.WriteString(fmt.Sprintf("| %s | %d |\n", transport.AdminDomainTitles[domain], counts[domain]))
	}
	builder.WriteString("\n")

	section := 3
	currentDomain := ""
	for _, operation := range operations {
		if operation.Domain != currentDomain {
			currentDomain = operation.Domain
			builder.WriteString(fmt.Sprintf("## %d. %s（%d 条）\n\n", section,
				transport.AdminDomainTitles[currentDomain], counts[currentDomain]))
			section++
			builder.WriteString("| 方法 | 路径 | 摘要 | 权限 | 敏感 | 确认/原因 | 异步/取消 | 成功 data |\n")
			builder.WriteString("|---|---|---|---|---|---|---|---|\n")
			for _, item := range operations {
				if item.Domain != currentDomain {
					continue
				}
				builder.WriteString("| " + strings.Join([]string{
					item.Method, "`/" + item.Pattern + "`", item.Summary,
					adminPermissionLabel(item.AdminOperation),
					boolLabel(item.Sensitive),
					adminConfirmLabel(item.AdminOperation),
					adminAsyncLabel(item.AdminOperation),
					"`" + adminSuccessLabel(item.Success) + "`",
				}, " | ") + " |\n")
			}
			builder.WriteString("\n")
			// 请求字段与语义细节。
			for _, item := range operations {
				if item.Domain != currentDomain {
					continue
				}
				if len(item.Body) == 0 && len(item.Query) == 0 && len(item.Path) == 0 && len(item.Notes) == 0 {
					continue
				}
				builder.WriteString(fmt.Sprintf("### `%s /%s`\n\n", item.Method, item.Pattern))
				builder.WriteString(item.Description + "\n\n")
				if len(item.Path) > 0 {
					builder.WriteString("路径参数：" + adminParamLines(item.Path) + "\n\n")
				}
				if len(item.Query) > 0 {
					builder.WriteString("查询参数：\n\n")
					for _, param := range item.Query {
						builder.WriteString(fmt.Sprintf("- `%s`（%s%s）：%s\n", param.Name, param.Type,
							requiredSuffix(param.Required), param.Description))
					}
					builder.WriteString("\n")
				}
				if len(item.Body) > 0 {
					builder.WriteString("请求体（application/json，严格解码）：\n\n")
					builder.WriteString("| 字段 | 类型 | 必填 | 说明 |\n|---|---|---|---|\n")
					for _, field := range item.Body {
						builder.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n", field.Name, field.Type,
							boolLabel(field.Required), field.Description))
					}
					builder.WriteString("\n")
					builder.WriteString("请求体示例（合成值，不可用于真实操作）：\n\n")
					builder.WriteString("```json\n" + renderBodyExample(item.Body) + "```\n\n")
				}
				if len(item.Notes) > 0 {
					builder.WriteString("边界与语义：\n\n")
					for _, note := range item.Notes {
						builder.WriteString("- " + note + "\n")
					}
					builder.WriteString("\n")
				}
			}
		}
	}

	builder.WriteString("## 机器可读\n\n")
	builder.WriteString("- [http-openapi-admin.json](http-openapi-admin.json)：本页同源 OpenAPI 3 文档（信封/组件/参数/请求体/响应/扩展）。\n")
	builder.WriteString("- [http-routes.json](http-routes.json)：路由事实来源（AST 扫描真实注册）。\n")
	builder.WriteString("- 生成与校验：`go run ./scripts/adminapi-doc -write` / `-check`（失败非零退出）。\n")
	return []byte(builder.String())
}

// bulletLines 生成 Markdown 列表。
func bulletLines(items []string) string {
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString("- " + item + "\n")
	}
	builder.WriteString("\n")
	return builder.String()
}

// boolLabel 把布尔值渲染为是/否。
func boolLabel(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

// requiredSuffix 返回必填标注。
func requiredSuffix(required bool) string {
	if required {
		return "，必填"
	}
	return "，可选"
}

// adminPermissionLabel 返回权限展示文本。
func adminPermissionLabel(operation transport.AdminOperation) string {
	if operation.RootOnly {
		return "root-only"
	}
	if len(operation.Permissions) == 0 {
		return "管理会话基线"
	}
	labels := make([]string, 0, len(operation.Permissions))
	for _, permission := range operation.Permissions {
		labels = append(labels, "`"+permission+"`")
	}
	return strings.Join(labels, " / ")
}

// adminConfirmLabel 返回确认/原因展示文本。
func adminConfirmLabel(operation transport.AdminOperation) string {
	parts := []string{}
	if operation.Confirm {
		parts = append(parts, "确认")
	}
	if operation.Reason {
		parts = append(parts, "原因")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "+")
}

// adminAsyncLabel 返回异步/取消展示文本。
func adminAsyncLabel(operation transport.AdminOperation) string {
	parts := []string{}
	if operation.Async {
		parts = append(parts, "异步任务")
	}
	if operation.Cancelable {
		parts = append(parts, "可取消")
	}
	if operation.Download != "" {
		parts = append(parts, "下载:"+operation.Download)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "/")
}

// adminSuccessLabel 返回成功 data 摘要。
func adminSuccessLabel(success string) string {
	switch {
	case success == "download":
		return "文件流"
	case success == "object":
		return "对象（见字段/说明）"
	case strings.HasPrefix(success, "list:"):
		return "分页列表 " + strings.Split(strings.TrimPrefix(success, "list:"), ":")[0]
	default:
		return success
	}
}

// adminParamLines 渲染路径参数行。
func adminParamLines(params []transport.AdminParam) string {
	parts := make([]string, 0, len(params))
	for _, param := range params {
		parts = append(parts, fmt.Sprintf("`%s`（%s）：%s", param.Name, param.Type, param.Description))
	}
	return strings.Join(parts, "；")
}

// renderBodyExample 渲染请求体 JSON 示例（4 空格缩进，字段按名称排序）。
func renderBodyExample(fields []transport.AdminField) string {
	example := map[string]any{}
	for _, field := range fields {
		if field.Secret {
			example[field.Name] = adminSecretExample(field.Name)
			continue
		}
		switch field.Type {
		case "boolean":
			if field.Name == "confirm" {
				example[field.Name] = true
			} else {
				example[field.Name] = true
			}
		case "integer":
			example[field.Name] = 1
		case "array":
			example[field.Name] = []string{"example-value"}
		case "object":
			example[field.Name] = map[string]any{"example_field": "example-value"}
		default:
			if len(field.Enum) > 0 {
				example[field.Name] = field.Enum[0]
			} else {
				example[field.Name] = "example-" + field.Name
			}
		}
	}
	data, err := json.MarshalIndent(example, "", "    ")
	if err != nil {
		return "{}\n"
	}
	return string(data) + "\n"
}

// validateGenerated 校验生成物的安全问题与排除域残留。
func validateGenerated(document, markdown []byte) []string {
	var issues []string
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return []string{"生成的 OpenAPI 文档不是合法 JSON：" + err.Error()}
	}
	text := strings.ToLower(string(document) + "\n" + string(markdown))
	// 不得出现宿主路径形态（下载语义明确禁止把服务器路径当下载地址）。
	for _, forbidden := range []string{"/var/", "/home/", "/etc/", "c:\\\\", "database/login", "hostpath"} {
		if strings.Contains(text, forbidden) {
			issues = append(issues, "生成物包含疑似宿主路径片段："+forbidden)
		}
	}
	// 不得出现明显真实凭据形态。
	for _, forbidden := range []string{"bearer ey", "sk-live", "-----begin", "password\":\"real"} {
		if strings.Contains(text, forbidden) {
			issues = append(issues, "生成物包含疑似真实凭据片段："+forbidden)
		}
	}
	// 排除域不得出现路径（防止占位 schema）。
	for _, excluded := range []string{"/mail"} {
		if strings.Contains(text, "\"/"+strings.TrimPrefix(excluded, "/")) {
			issues = append(issues, "生成物出现排除域路径片段："+excluded)
		}
	}
	// 认证契约：文档级 security 必须存在且只引用已定义的 securitySchemes；
	// 任何操作不得把 security 覆盖为 null/空数组（禁止关闭认证，票据兑换同样需要会话）。
	schemes := adminDocSecuritySchemes(decoded)
	documentSecurity, securityOK := decoded["security"].([]any)
	if !securityOK || len(documentSecurity) == 0 {
		issues = append(issues, "文档缺少文档级 security（管理 API 必须声明会话 Cookie/Bearer）")
	} else {
		issues = append(issues, validateSecurityRequirements(documentSecurity, schemes, "文档级")...)
	}
	paths, _ := decoded["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		if len(item) == 0 {
			issues = append(issues, "路径 "+path+" 没有操作")
			continue
		}
		for method, rawOperation := range item {
			operation, _ := rawOperation.(map[string]any)
			if _, ok := operation["responses"].(map[string]any); !ok {
				issues = append(issues, "操作 "+method+" "+path+" 缺少 responses")
			}
			if _, ok := operation["x-login-domain"]; !ok {
				issues = append(issues, "操作 "+method+" "+path+" 缺少域标识")
			}
			if rawSecurity, exists := operation["security"]; exists {
				requirements, ok := rawSecurity.([]any)
				if !ok || len(requirements) == 0 {
					issues = append(issues, "操作 "+method+" "+path+" 把 security 置空（不允许关闭认证）")
					continue
				}
				issues = append(issues,
					validateSecurityRequirements(requirements, schemes, method+" "+path)...)
			}
		}
	}
	return issues
}

// adminDocSecuritySchemes 返回文档 components.securitySchemes 中已定义的方案名集合。
func adminDocSecuritySchemes(decoded map[string]any) map[string]bool {
	schemes := map[string]bool{}
	components, _ := decoded["components"].(map[string]any)
	securitySchemes, _ := components["securitySchemes"].(map[string]any)
	for name := range securitySchemes {
		schemes[name] = true
	}
	return schemes
}

// validateSecurityRequirements 校验 security requirement 数组：每项为非空对象且
// 引用的 scheme 都已定义；返回问题清单。
func validateSecurityRequirements(requirements []any, schemes map[string]bool,
	where string) []string {
	var issues []string
	for _, rawRequirement := range requirements {
		requirement, ok := rawRequirement.(map[string]any)
		if !ok || len(requirement) == 0 {
			issues = append(issues, where+" security requirement 为空或结构无效")
			continue
		}
		for schemeName := range requirement {
			if !schemes[schemeName] {
				issues = append(issues, where+" security 引用未定义的 scheme "+schemeName)
			}
		}
	}
	return issues
}
