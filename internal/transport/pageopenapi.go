package transport

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// 本文件实现「页面/表单操作」的 OpenAPI 契约投影。页面路由与 JSON API 是两种
// 不同的传输语义，文档必须分开标识：
//   - JSON API：统一业务错误信封（Error schema + request_id），如 /healthz、
//     /openapi.json，以及后续步骤定义的管理 API；
//   - HTML 页面：服务端渲染 HTML，错误以页面呈现，不使用统一 JSON 错误信封；
//     成功写操作以 303 跳转流程下一步，表单提交要求同源 + CSRF 令牌。
//
// 路径/方法由页面处理器真实注册的路由投影（PageRoute）提供，本文件只提供按
// 命名路由绑定的请求字段/响应/状态转移契约。二者不一致时构造直接失败，避免
// 文档声称的接口与实际注册漂移；离线一致性由 scripts/reference -check 通过
// AST 扫描 ui/ 路由再核对同一契约表来保证。

// PageRoute 是页面处理器报告的已注册命名路由投影（ui.v1 命名契约的子集）。
type PageRoute struct {
	// Name 是冻结的命名路由名，如 auth.login.submit。
	Name string
	// Method 是 GET 或 POST。
	Method string
	// Path 是相对站内前缀的页面路径，如 /login。
	Path string
	// Access 是页面访问级别：public/user/management。
	Access string
}

// PageFieldKind 是表单字段或查询参数的类型。
type PageFieldKind string

const (
	// PageFieldString 是普通文本字段（表单值本质是字符串）。
	PageFieldString PageFieldKind = "string"
	// PageFieldInteger 是十进制整数字段（如 row_version、分页页码）。
	PageFieldInteger PageFieldKind = "integer"
	// PageFieldBoolean 是布尔语义字段（表单常见 on/1/true）。
	PageFieldBoolean PageFieldKind = "boolean"
	// PageFieldFile 是 multipart 文件字段（如头像上传）。
	PageFieldFile PageFieldKind = "file"
)

// PageField 是一个页面表单字段或查询参数契约。示例值由生成器按合成值规则产生，
// 绝不复用真实凭据；秘密字段使用 writeOnly，不出现在响应与示例凭据中。
type PageField struct {
	// Name 是表单字段名（与服务端白名单一致）。
	Name string
	// Kind 是字段类型。
	Kind PageFieldKind
	// Required 表示服务端要求该字段非空；可选字段允许缺省。
	Required bool
	// WriteOnly 表示只写秘密（密码、令牌、恢复码、WebAuthn 断言等）。
	WriteOnly bool
	// MaxLength 是服务端接受的字节上限；0 表示不单独标注。
	MaxLength int
	// Enum 是固定取值集合（如确认框的 yes/true）；空表示自由文本。
	Enum []string
	// Description 是直白中文说明，解释用途与安全约束。
	Description string
}

// PageOperation 是一条页面路由的完整操作契约。Method/Path 是契约钉住的
// 实际注册值：页面路由改动必须同步本契约，否则构造与离线校验都会失败。
type PageOperation struct {
	// Method/Path 是与 PageRoute 必须一致的注册值（相对站内前缀）。
	Method string
	Path   string
	// Summary 是短摘要；Description 是完整说明。
	Summary     string
	Description string
	// Module 是页面模块（auth/account/support），用于说明启用条件。
	Module string
	// CSRF 是表单 CSRF 模式：anonymous-form-token 或 session-bound-token；
	// GET 操作留空。
	CSRF string
	// Fields 是 POST 表单字段（GET 操作为空）。
	Fields []PageField
	// Query 是 GET 查询参数。
	Query []PageField
	// StateTransitions 是本操作允许的状态转移（直白中文，供实现/测试对照）。
	StateTransitions []string
	// Notes 是补充边界（如不枚举账户、不返回秘密）。
	Notes []string
	// RequestContentType 覆盖 POST 请求体媒体类型；空表示 application/x-www-form-urlencoded。
	RequestContentType string
	// SuccessContentType 覆盖成功响应媒体类型；空表示 text/html。
	SuccessContentType string
	// ExtraResponses 是除通用集合外必须声明的额外状态码。
	ExtraResponses []string
}

// NamedPageOperation 是带命名路由名的操作契约，供文档生成与测试排序遍历。
type NamedPageOperation struct {
	Name string
	PageOperation
}

// pageModuleEnabledWhen 说明各页面模块的启用条件；未挂载时对应路径 404。
var pageModuleEnabledWhen = map[string]string{
	"auth": "宿主装配内置页面且 ui.PageAuth 非 nil（独立服务由 serverapp 装配）；" +
		"注册/Passkey 相关操作还分别要求 registration.enabled / passkey.enabled。",
	"mfa": "宿主装配内置页面且 ui.PageMFA 非 nil；找回密码与第二因素入口还受对应安全策略约束，" +
		"未启用时页面说明不可用而不是伪造成功。",
	"account": "宿主装配内置页面且 ui.PageAccount 非 nil；匿名邮箱变更验证属于公开表单；" +
		"Passkey 页还要求 passkey.enabled。",
	"security": "宿主装配内置页面且 ui.PageSecurity 非 nil；敏感操作按再次认证策略要求本次操作绑定的两步验证，" +
		"策略不满足时拒绝而不是降级为只确认按钮。",
	"support": "宿主装配内置页面且 ui.PageSupport 非 nil；人工恢复默认按配置开关与审批流程生效，" +
		"未启用时页面说明不可用而不是伪造成功。",
}

// pageCSRFAnonymous 是匿名公开表单的 CSRF 模式（短时效、与用途绑定）。
const pageCSRFAnonymous = "anonymous-form-token"

// pageCSRFSession 是会话表单的 CSRF 模式（与会话绑定并校验同源）。
const pageCSRFSession = "session-bound-token"

// pageCSRFFieldName 是页面表单隐藏 CSRF 字段的默认名（与传输层中间件一致）。
var pageCSRFFieldName = DefaultCSRFFormField

// pageSessionCookieName 是会话 Cookie 的公开默认名（与 httpapi 契约一致）。
var pageSessionCookieName = httpapi.DefaultHTTPCSRFCookieName

// pageJSONTag/pageHTMLTag 是文档中区分 JSON API 与 HTML 页面的标签。
const (
	pageJSONTag = "json-api"
	pageHTMLTag = "page-html"
)

// buildPageOpenAPI 把已注册页面路由投影为 OpenAPI paths 片段与跨操作元数据。
// 未登记契约的路由（宿主自定义页面、其他步骤尚未定义模式的页面）不进入本步
// 文档，只计数写入扩展，避免把未定义模式伪装成完整契约。
func buildPageOpenAPI(prefix string, routes []PageRoute) (pageOpenAPI, error) {
	result := pageOpenAPI{
		Paths:              map[string]any{},
		Documented:         []NamedPageOperation{},
		Unregistered:       []string{},
		SecurityScheme:     pageSecurityScheme(),
		ResponseComponents: pageResponseComponents(),
	}
	seenNames := map[string]struct{}{}
	seenRoutes := map[string]string{}
	for _, route := range routes {
		name := strings.TrimSpace(route.Name)
		if name == "" {
			return pageOpenAPI{}, fmt.Errorf("页面路由缺少命名")
		}
		if _, exists := seenNames[name]; exists {
			return pageOpenAPI{}, fmt.Errorf("页面路由命名重复：%s", name)
		}
		seenNames[name] = struct{}{}
		method := strings.ToUpper(strings.TrimSpace(route.Method))
		if method != http.MethodGet && method != http.MethodPost {
			// HEAD 由 GET 自动支持，不单独建档；其他方法不是页面契约。
			continue
		}
		if problem := validPagePath(route.Path); problem != "" {
			return pageOpenAPI{}, fmt.Errorf("页面路由 %s 的路径无效：%s", name, problem)
		}
		routeKey := method + " " + route.Path
		if other, exists := seenRoutes[routeKey]; exists {
			return pageOpenAPI{}, fmt.Errorf("页面路由 %s 与 %s 的方法/路径重复：%s", name, other, routeKey)
		}
		seenRoutes[routeKey] = name
		access := normalizePageAccess(route.Access)
		contract, documented := pageOperationContract(name)
		if !documented {
			result.Unregistered = append(result.Unregistered, name)
			continue
		}
		if contract.Method != method || contract.Path != route.Path {
			return pageOpenAPI{}, fmt.Errorf(
				"页面路由 %s 的方法/路径与 OpenAPI 契约不一致：实际 %s %s，契约 %s %s；"+
					"请同步 ui 路由与 internal/transport/pagecontracts_*.go",
				name, method, route.Path, contract.Method, contract.Path)
		}
		operation, err := buildPageOperation(prefix, name, access, contract)
		if err != nil {
			return pageOpenAPI{}, err
		}
		fullPath := routePath(prefix, route.Path)
		pathItem, ok := result.Paths[fullPath].(map[string]any)
		if !ok {
			pathItem = map[string]any{}
			result.Paths[fullPath] = pathItem
		}
		pathItem[strings.ToLower(method)] = operation
		result.Documented = append(result.Documented, NamedPageOperation{Name: name, PageOperation: contract})
	}
	sort.Slice(result.Documented, func(left, right int) bool {
		return result.Documented[left].Name < result.Documented[right].Name
	})
	sort.Strings(result.Unregistered)
	return result, nil
}

// pageOpenAPI 是一次页面投影结果。
type pageOpenAPI struct {
	// Paths 是完整路径（含前缀）到 path item 的映射。
	Paths map[string]any
	// Documented 是已写入文档的操作契约（按命名排序）。
	Documented []NamedPageOperation
	// Unregistered 是未登记契约、未写入本步文档的页面路由名（按名称排序）。
	Unregistered []string
	// SecurityScheme 是会话 Cookie 的安全方案定义。
	SecurityScheme map[string]any
	// ResponseComponents 是可复用的页面响应组件（#/components/responses）。
	ResponseComponents map[string]any
}

// buildPageOperation 生成单条页面操作对象。重复的传输语义（HTML 错误信封、
// 限流维度、协议开关、模块启用条件）放在文档级扩展与可复用响应组件中，操作本身
// 只保留特有信息，避免文档体积随操作数膨胀（响应超时保护有 1 MiB 缓冲上限）。
func buildPageOperation(prefix, name, access string, contract PageOperation) (map[string]any, error) {
	operation := map[string]any{
		"tags":                      []string{pageHTMLTag},
		"summary":                   contract.Summary,
		"description":               contract.Description,
		"operationId":               pageOperationID(name),
		"x-login-route-name":        name,
		"x-login-route-kind":        "html-page",
		"x-login-page-module":       contract.Module,
		"x-login-page-access":       access,
		"x-login-csrf":              pageCSRFMode(contract),
		"x-login-state-transitions": append([]string(nil), contract.StateTransitions...),
	}
	if len(contract.Notes) > 0 {
		operation["x-login-notes"] = append([]string(nil), contract.Notes...)
	}
	if access != "public" {
		operation["security"] = []map[string][]string{{"sessionCookie": {}}}
	}
	responses, err := buildPageResponses(name, access, contract)
	if err != nil {
		return nil, err
	}
	operation["responses"] = responses
	if contract.Method == http.MethodPost {
		body, err := buildPageRequestBody(contract)
		if err != nil {
			return nil, err
		}
		operation["requestBody"] = body
	}
	if contract.Method == http.MethodGet && len(contract.Query) > 0 {
		parameters := make([]any, 0, len(contract.Query))
		for _, field := range contract.Query {
			parameters = append(parameters, pageQueryParameter(field))
		}
		operation["parameters"] = parameters
	}
	_ = prefix
	return operation, nil
}

// pageOperationID 把命名路由转换为稳定唯一的 operationId。
func pageOperationID(name string) string {
	return "page_" + strings.NewReplacer(".", "_", "-", "_").Replace(name)
}

// pageCSRFMode 返回操作的 CSRF 模式；GET 操作返回 not-required。
func pageCSRFMode(contract PageOperation) string {
	if contract.Method != http.MethodPost {
		return "not-required"
	}
	if contract.CSRF == "" {
		return pageCSRFSession
	}
	return contract.CSRF
}

// buildPageRequestBody 生成 POST 表单请求体（含 CSRF 隐藏字段与合成示例）。
func buildPageRequestBody(contract PageOperation) (map[string]any, error) {
	contentType := "application/x-www-form-urlencoded"
	fields := contract.Fields
	if contract.RequestContentType != "" {
		contentType = contract.RequestContentType
	}
	properties := map[string]any{}
	required := make([]string, 0, len(fields)+1)
	example := map[string]any{}
	csrf := PageField{
		Name:        pageCSRFFieldName,
		Kind:        PageFieldString,
		Required:    true,
		WriteOnly:   true,
		MaxLength:   256,
		Description: pageCSRFDescription(contract.CSRF),
	}
	for _, field := range append([]PageField{csrf}, fields...) {
		if err := validatePageField(field); err != nil {
			return nil, fmt.Errorf("页面操作 %s %s 的字段契约无效：%w", contract.Method, contract.Path, err)
		}
		properties[field.Name] = pageFieldSchema(field)
		if field.Required {
			required = append(required, field.Name)
		}
		example[field.Name] = pageFieldExample(field)
	}
	body := map[string]any{
		"required": true,
		"content": map[string]any{
			contentType: map[string]any{
				"schema": map[string]any{
					"type":       "object",
					"properties": properties,
					"required":   required,
				},
				"example": example,
			},
		},
	}
	return body, nil
}

// pageCSRFDescription 返回 CSRF 字段说明。
func pageCSRFDescription(mode string) string {
	if mode == pageCSRFAnonymous {
		return "匿名公开表单 CSRF 令牌（隐藏字段）：由服务端渲染的登录/注册/找回页签发，" +
			"短期有效并与表单用途绑定；不接受 URL 传参或脚本自造，缺失/过期/跨用途一律拒绝。"
	}
	return "会话绑定的 CSRF 令牌（隐藏字段）：取自当前会话渲染的页面，与会话和精确同源校验绑定；" +
		"不接受 URL 传参、Cookie 外自报身份或其他会话的令牌。"
}

// pageResponseComponentNames 把页面状态码映射为可复用响应组件名；操作响应统一用
// $ref 引用，避免把头部/媒体类型说明在每条操作里重复一遍（响应超时保护缓冲上限 1 MiB）。
var pageResponseComponentNames = map[string]string{
	"200": "PageOK",
	"303": "PageRedirect",
	"400": "PageBadRequest",
	"401": "PageUnauthorized",
	"403": "PageForbidden",
	"404": "PageNotFound",
	"405": "PageMethodNotAllowed",
	"409": "PageConflict",
	"413": "PagePayloadTooLarge",
	"415": "PageUnsupportedMediaType",
	"429": "PageRateLimited",
	"500": "PageInternalError",
	"503": "PageUnavailable",
}

// pageResponseComponents 返回页面操作可复用的响应组件集合。
func pageResponseComponents() map[string]any {
	components := make(map[string]any, len(pageResponseComponentNames))
	for status, name := range pageResponseComponentNames {
		entry, err := pageResponseEntry(status)
		if err != nil {
			// 组件名与状态码表是编译期常量组合，未知状态码属于编程错误。
			panic("transport: 页面响应组件状态码未登记: " + status)
		}
		components[name] = entry
	}
	return components
}

// buildPageResponses 生成页面操作响应集合。页面错误以 HTML 呈现，不使用统一
// JSON 错误信封；成功写操作使用 303 跳转流程下一步。除图片等特殊成功响应外，
// 全部用 #/components/responses 引用。
func buildPageResponses(name, access string, contract PageOperation) (map[string]any, error) {
	responses := map[string]any{}
	statuses := pageResponseStatuses(contract.Method, access)
	for _, status := range contract.ExtraResponses {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	for index, status := range statuses {
		if index > 0 && status == statuses[index-1] {
			continue
		}
		component, ok := pageResponseComponentNames[status]
		if !ok {
			return nil, fmt.Errorf("页面操作 %s 的响应 %s 未登记可复用组件", name, status)
		}
		if status == "200" && contract.SuccessContentType != "" &&
			contract.SuccessContentType != "multipart/form-data" {
			responses[status] = pageBinaryResponse(contract.SuccessContentType)
			continue
		}
		responses[status] = map[string]any{"$ref": "#/components/responses/" + component}
	}
	return responses, nil
}

// pageBinaryResponse 构造二进制成功响应（如图像字节），内联而非组件引用。
func pageBinaryResponse(contentType string) map[string]any {
	return map[string]any{
		"description": pageStatusDescription("200"),
		"headers":     pageResponseHeaders(false),
		"content": map[string]any{
			contentType: map[string]any{
				"schema": map[string]any{"type": "string", "format": "binary"},
			},
		},
	}
}

// PageResponseStatuses 返回页面操作按方法与访问级别确定的通用响应状态码集合
// （排序去重）。文档生成与离线校验共用同一函数，避免第二份状态码清单。
func PageResponseStatuses(method, access string) []string {
	return pageResponseStatuses(method, access)
}

// pageResponseStatuses 返回按方法/访问级别确定的通用状态码集合（已去重排序）。
func pageResponseStatuses(method, access string) []string {
	statuses := []string{"200", "404", "405", "429", "500", "503"}
	if method == http.MethodPost {
		statuses = append(statuses, "303", "400", "403", "409", "413", "415")
	}
	if access != "public" {
		statuses = append(statuses, "401")
	}
	sort.Strings(statuses)
	unique := statuses[:0]
	for index, status := range statuses {
		if index == 0 || status != statuses[index-1] {
			unique = append(unique, status)
		}
	}
	return unique
}

// pageResponseEntry 构造单个状态码的可复用响应对象。
func pageResponseEntry(status string) (map[string]any, error) {
	switch status {
	case "200":
		return map[string]any{
			"description": pageStatusDescription(status),
			"headers":     pageResponseHeaders(false),
			"content": map[string]any{
				"text/html; charset=utf-8": map[string]any{
					"schema": map[string]any{"type": "string"},
				},
			},
		}, nil
	case "303":
		return map[string]any{
			"description": pageStatusDescription(status),
			"headers": map[string]any{
				"Location": map[string]any{
					"description": "流程下一步的站内相对路径（已加站内前缀）；不会跳转到外部或 javascript/data。",
					"schema":      map[string]any{"type": "string"},
				},
				"Cache-Control": map[string]any{
					"description": "固定 no-store。",
					"schema":      map[string]any{"type": "string"},
				},
				"X-Request-ID": map[string]any{
					"description": "本次请求编号，用于受限排障。",
					"schema":      map[string]any{"type": "string"},
				},
			},
		}, nil
	case "400", "401", "403", "404", "405", "409", "413", "415", "429", "500", "503":
		return map[string]any{
			"description": pageStatusDescription(status),
			"headers":     pageResponseHeaders(true),
			"content": map[string]any{
				// 页面处理器产生的错误以 HTML 错误页呈现；传输层前置拒绝
				// （路径规范化/CSRF/限流/并发/超时/panic 等）不经过页面处理器，
				// 实际返回统一 JSON 业务错误信封。两种形态都要如实声明。
				"text/html; charset=utf-8": map[string]any{
					"schema": map[string]any{"type": "string"},
				},
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": "#/components/schemas/Error"},
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("未登记状态码 %q", status)
	}
}

// pageResponseHeaders 返回页面响应通用头。只声明传输层确定会写入的头；不声明
// 未实现的额外错误码头（避免文档承诺 > 实际行为）。
func pageResponseHeaders(withError bool) map[string]any {
	headers := map[string]any{
		"Cache-Control": map[string]any{
			"description": "固定 no-store；页面与错误页都不缓存。",
			"schema":      map[string]any{"type": "string"},
		},
		"Content-Security-Policy": map[string]any{
			"description": "传输层统一写入的安全响应头（页面渲染时为页面 CSP 基线；传输层 JSON 拒绝时为 API 默认 CSP）。",
			"schema":      map[string]any{"type": "string"},
		},
		"X-Request-ID": map[string]any{
			"description": "本次请求编号，用于受限排障。",
			"schema":      map[string]any{"type": "string"},
		},
	}
	_ = withError
	return headers
}

// pageStatusDescription 返回状态码的直白说明。
func pageStatusDescription(status string) string {
	const transportJSON = "若由传输层前置拒绝产生（路径规范化/CSRF/限流/并发/超时/内部 panic 等），" +
		"响应为 application/json 统一业务错误信封（Error schema），不是 HTML 页面。"
	switch status {
	case "200":
		return "渲染 HTML 页面（成功结果或表单回显）。成功写操作也可能直接返回本页并展示结果，具体见状态转移。"
	case "303":
		return "写操作成功后重定向到流程下一步站内页面；未完成认证/验证的状态不会跳转到业务页。"
	case "400":
		return "表单校验失败（字段缺失/长度超限/重复字段/未知字段/内容不符合要求），页面处理器产生时以 HTML 错误摘要呈现；" + transportJSON
	case "401":
		return "没有有效会话或会话已过期/被撤销，页面处理器渲染受限提示页，不执行任何写操作；" + transportJSON
	case "403":
		return "CSRF 令牌或精确同源校验失败、页面访问级别不足、功能未启用或受限恢复会话不允许该操作；" +
			"页面处理器产生时以 HTML 错误页呈现，" + transportJSON
	case "404":
		return "页面未注册或所在模块未挂载；" + transportJSON
	case "405":
		return "页面存在但不支持该 HTTP 方法；" + transportJSON
	case "409":
		return "并发版本冲突或流程状态冲突（如 row_version 已过期、找回/恢复流程不处于允许的下一步）；" + transportJSON
	case "413":
		return "请求体超过传输层允许上限；" + transportJSON
	case "415":
		return "请求内容类型不符合要求（表单纯 urlencoded；头像上传为 multipart/form-data）；" + transportJSON
	case "429":
		return "固定窗口限流、并发上限或昂贵请求预算拒绝；按 Retry-After 等待后重试。" + transportJSON
	case "500":
		return "未预期内部错误（含 panic 恢复）；页面处理器产生时只显示通用错误摘要、不泄露内部细节或秘密；" + transportJSON
	case "503":
		return "维护模式或依赖（数据库/审计/通知等）不可用；不伪造成功。" + transportJSON
	default:
		return "页面响应。"
	}
}

// validPagePath 校验页面路径：以单个斜杠开头、无查询串/片段/百分号编码、无尾斜杠。
func validPagePath(path string) string {
	if path == "" {
		return "路径不能为空"
	}
	if !strings.HasPrefix(path, "/") {
		return "路径必须以 / 开头"
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		return "路径不能以 / 结尾"
	}
	if strings.ContainsAny(path, "?#\\% ") {
		return "路径不能包含查询串、片段、反斜杠、百分号编码或空格"
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "路径不能包含空段或点段"
		}
	}
	return ""
}

// normalizePageAccess 归一化访问级别；未知值按 public 记录（不据此放行，运行
// 时仍由页面处理器与传输层重新判定）。
func normalizePageAccess(access string) string {
	switch strings.ToLower(strings.TrimSpace(access)) {
	case "user":
		return "user"
	case "management":
		return "management"
	default:
		return "public"
	}
}

// validatePageField 校验字段契约自身的合法性。
func validatePageField(field PageField) error {
	if strings.TrimSpace(field.Name) == "" {
		return fmt.Errorf("字段名不能为空")
	}
	switch field.Kind {
	case PageFieldString, PageFieldInteger, PageFieldBoolean, PageFieldFile:
	default:
		return fmt.Errorf("字段 %s 的类型 %q 未登记", field.Name, field.Kind)
	}
	if len(field.Enum) > 0 && field.Kind != PageFieldString {
		return fmt.Errorf("字段 %s 只有字符串字段可以声明枚举", field.Name)
	}
	return nil
}

// pageFieldSchema 生成单个字段的 OpenAPI schema。
func pageFieldSchema(field PageField) map[string]any {
	schema := map[string]any{
		"type":        string(field.Kind),
		"description": field.Description,
	}
	if field.Kind == PageFieldFile {
		schema = map[string]any{"type": "string", "format": "binary", "description": field.Description}
	}
	if field.WriteOnly {
		schema["writeOnly"] = true
	}
	if field.MaxLength > 0 && field.Kind != PageFieldFile {
		schema["maxLength"] = field.MaxLength
	}
	if len(field.Enum) > 0 {
		schema["enum"] = append([]string(nil), field.Enum...)
	}
	schema["example"] = pageFieldExample(field)
	return schema
}

// pageFieldExample 生成明确合成、不可用于真实认证的示例值。
func pageFieldExample(field PageField) string {
	if len(field.Enum) > 0 {
		return field.Enum[0]
	}
	switch field.Kind {
	case PageFieldInteger:
		return "1"
	case PageFieldBoolean:
		return "true"
	case PageFieldFile:
		return "example-avatar.png（合成示例文件，不是真实用户数据）"
	}
	if field.WriteOnly {
		switch field.Name {
		case "code", "totp_code":
			return "000000（合成示例，不是有效验证码）"
		case "passkey_response", "response":
			return `{"example":"synthetic-webauthn-response-not-a-real-credential"}`
		}
		return "example-" + field.Name + "-synthetic-not-real"
	}
	switch field.Name {
	case "identifier":
		return "example-user"
	case "username", "new_username":
		return "example-user"
	case "email", "new_email":
		return "example-user@example.invalid"
	case "confirm":
		return "yes"
	}
	return "example-" + field.Name
}

// pageQueryParameter 生成 GET 查询参数对象。
func pageQueryParameter(field PageField) map[string]any {
	parameter := map[string]any{
		"name":        field.Name,
		"in":          "query",
		"required":    field.Required,
		"description": field.Description,
		"schema":      pageFieldSchema(field),
	}
	return parameter
}

// pageSecurityScheme 返回页面会话 Cookie 的安全方案定义。
func pageSecurityScheme() map[string]any {
	return map[string]any{
		"type": "apiKey",
		"in":   "cookie",
		"name": pageSessionCookieName,
		"description": "真实会话 Cookie（HttpOnly/Secure/SameSite 由宿主 Cookie 策略决定）。" +
			"页面处理器每次请求重新校验会话；Cookie 不是授权证明，服务端仍按当前权限与目标对象判定。",
	}
}
