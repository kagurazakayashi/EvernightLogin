package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// openAPIVersion 是输出的 OpenAPI 规范版本。
const openAPIVersion = "3.0.3"

// buildOpenAPIDocument 生成机器可读 OpenAPI 文档。
//
// 文档包含两类传输语义，必须分开标识：
//   - JSON API（tag=json-api）：统一业务错误信封（Error schema + request_id）。
//     当前只有健康检查与本文档端点；管理 JSON API 的请求/响应模式由后续步骤统一定义。
//   - HTML 页面（tag=page-html）：服务端渲染页面与表单。页面处理器产生的错误以
//     HTML 呈现；但传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/panic）在进入
//     页面处理器之前返回统一 JSON 错误信封，契约按实际行为同时声明两种形态。
//     路径/方法来自实际注册的页面命名路由（PageRoute）。
//
// 错误码 enum 与 x-login-error-registry 由注入的 ErrorCodeInfo 直接生成，新增错误码
// 无需手工维护第二份清单；页面操作契约来自 internal/transport/pagecontracts_*.go，
// 并与实际路由的方法/路径互相钉住，漂移时构造失败。
func buildOpenAPIDocument(prefix string, codes []ErrorCodeInfo, version string, routes []PageRoute) ([]byte, error) {
	normalizedPrefix, err := NormalizePrefix(prefix)
	if err != nil {
		return nil, err
	}
	if version == "" {
		version = "devel"
	}
	sortedCodes := make([]ErrorCodeInfo, len(codes))
	copy(sortedCodes, codes)
	sort.Slice(sortedCodes, func(left, right int) bool {
		return sortedCodes[left].Code < sortedCodes[right].Code
	})
	codeValues := make([]string, len(sortedCodes))
	registry := make(map[string]any, len(sortedCodes))
	for index, code := range sortedCodes {
		codeValues[index] = code.Code
		registry[code.Code] = map[string]any{
			"category":    code.Category,
			"message":     code.Message,
			"http_status": code.HTTPStatus,
		}
	}

	errorSchema := map[string]any{
		"type":     "object",
		"required": []string{"code", "message", "request_id"},
		"description": "统一业务错误响应（仅 JSON API）。code 是稳定错误码；message 是可公开的直白说明；" +
			"request_id 用于受限排障。OAuth/OIDC 标准协议响应与 HTML 页面错误不使用本结构。",
		"properties": map[string]any{
			"code": map[string]any{
				"type":        "string",
				"description": "稳定错误码，取值来自错误码注册表。",
				"enum":        codeValues,
			},
			"message": map[string]any{
				"type":        "string",
				"description": "可公开的直白说明，不包含内部原因或秘密。",
			},
			"request_id": map[string]any{
				"type":        "string",
				"description": "本次请求的查询编号，用于受限诊断。",
			},
			"task_id": map[string]any{
				"type":        "string",
				"description": "可选后台任务编号。",
			},
			"retry_after_seconds": map[string]any{
				"type":        "integer",
				"format":      "int32",
				"minimum":     1,
				"description": "限流请求的建议等待秒数；与 Retry-After 响应头一致，仅限流响应出现。",
			},
		},
	}
	healthSchema := map[string]any{
		"type":        "object",
		"required":    []string{"status"},
		"description": "最小健康状态；不包含配置、数据库、密钥或版本细节。",
		"properties": map[string]any{
			"status": map[string]any{"type": "string", "enum": []string{"ok"}},
		},
	}
	errorResponses := map[string]any{
		"400": errorResponse("请求内容不符合要求"),
		"401": errorResponse("无法完成登录或身份无效"),
		"403": errorResponse("请求未获准"),
		"404": errorResponse("请求的资源不存在"),
		"405": errorResponse("请求方法不受支持"),
		"413": errorResponse("请求体超过允许的大小"),
		"414": errorResponse("请求地址过长"),
		"415": errorResponse("请求内容类型不受支持"),
		"429": errorResponse("请求过于频繁，按 retry_after_seconds 等待"),
		"500": errorResponse("服务发生未预期错误"),
		"504": errorResponse("请求处理超时"),
	}
	paths := map[string]any{
		routePath(normalizedPrefix, healthSuffix): map[string]any{
			"get": map[string]any{
				"tags":               []string{pageJSONTag},
				"summary":            "最小健康检查",
				"description":        "返回固定 {\"status\":\"ok\"}；不依赖身份解析，不泄露配置、数据库路径或密钥。属于 JSON API，错误使用统一业务错误信封。",
				"operationId":        "json_healthz",
				"x-login-route-kind": "json-api",
				"responses": map[string]any{
					"200": map[string]any{
						"description": "服务进程可响应 HTTP 请求",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"$ref": "#/components/schemas/Health"},
							},
						},
					},
					"default": errorResponse("统一业务错误响应"),
				},
			},
		},
		routePath(normalizedPrefix, openAPISuffix): map[string]any{
			"get": map[string]any{
				"tags":               []string{pageJSONTag},
				"summary":            "机器可读接口契约",
				"description":        "返回本 Handler 前缀下的 OpenAPI 文档；错误码 enum 与错误码注册表一致，页面/表单操作按实际注册路由投影。",
				"operationId":        "json_openapi",
				"x-login-route-kind": "json-api",
				"responses": map[string]any{
					"200": map[string]any{
						"description": "OpenAPI 3 文档",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"type": "object"},
							},
						},
					},
					"default": errorResponse("统一业务错误响应"),
				},
			},
		},
	}

	page, err := buildPageOpenAPI(normalizedPrefix, routes)
	if err != nil {
		return nil, err
	}
	for path, item := range page.Paths {
		pathItem, ok := item.(map[string]any)
		if !ok || len(pathItem) == 0 {
			return nil, fmt.Errorf("页面路由 %q 的 OpenAPI 条目为空", path)
		}
		if existing, exists := paths[path]; exists {
			existingItem, ok := existing.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("路径 %q 的 OpenAPI 条目类型冲突", path)
			}
			for method, operation := range pathItem {
				if _, duplicate := existingItem[method]; duplicate {
					return nil, fmt.Errorf("路径 %q 的 %s 方法同时被 JSON API 与页面路由占用", path, method)
				}
				existingItem[method] = operation
			}
			continue
		}
		paths[path] = pathItem
	}

	document := map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{
			"title":   "login HTTP API 与页面表单契约",
			"version": version,
			"description": "login 的机器可读 HTTP 契约。文档区分两类传输语义：\n" +
				"1) JSON API（tag=json-api）：`{prefix}/healthz`、`{prefix}/openapi.json` 等，" +
				"错误统一为 `{code,message,request_id}` 信封；管理 JSON API 的请求/响应模式由后续步骤" +
				"统一定义，本步不伪造。\n" +
				"2) HTML 页面/表单（tag=page-html）：账户/资料/会话/注册登录/MFA/三种恢复流程的" +
				"`ui.v1` 命名路由，服务端渲染 HTML；页面处理器错误以 HTML 呈现，但传输层前置拒绝" +
				"（路径规范化/CSRF/限流/并发/超时/panic）在进入页面处理器之前返回统一 JSON 错误信封；" +
				"写操作为 `application/x-www-form-urlencoded`（头像上传为 multipart），要求 CSRF 令牌" +
				"与精确同源，成功通常 303 跳转流程下一步。\n" +
				"路径/方法来自实际注册的页面路由（运行期 ui.WebUI.Routes()）；离线一致性校验：" +
				"`go run ./scripts/reference -check`（生成物含 http-openapi.json）。\n" +
				"默认关闭的能力：OAuth 2.0/OIDC 协议端点由 `protocol.enabled`（默认 false，独立服务也可" +
				"`--enable-protocol`）显式开启，关闭时保留前缀直接 404，且不属于本文件；管理 JSON API、" +
				"托管 API、应用客服 API 同样需显式启用。\n" +
				"秘密字段标记 writeOnly，示例全部为明确合成值，不包含可用令牌、密码、恢复码或私钥。",
		},
		"tags": []any{
			map[string]any{
				"name": pageJSONTag,
				"description": "JSON API：成功返回 JSON；错误使用统一业务错误信封 " +
					"（Error schema：code/message/request_id）。",
			},
			map[string]any{
				"name": pageHTMLTag,
				"description": "HTML 页面/表单（ui.v1 命名路由）：服务端渲染；页面处理器错误为 HTML，" +
					"传输层前置拒绝（路径规范/CSRF/限流/并发/超时/panic）为统一 JSON 错误信封；" +
					"写操作要求 CSRF 与精确同源，成功通常 303 跳转。",
			},
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": map[string]any{
				"Error":  errorSchema,
				"Health": healthSchema,
			},
			"responses": page.ResponseComponents,
			"securitySchemes": map[string]any{
				"sessionCookie": page.SecurityScheme,
			},
		},
		// 错误码注册表投影：与 enum 同源生成，供机器校验。
		"x-login-error-registry": registry,
		// OAuth/OIDC 标准响应空间保留前缀；未来协议适配层不得被统一错误信封包装。
		"x-login-oauth-reserved-prefix":  OAuthReservedPrefix + "/",
		"x-login-common-error-responses": errorResponses,
		// 两类传输语义的机器说明（文档消费者按 x-login-route-kind 区分，不靠猜）。
		"x-login-route-kinds": map[string]any{
			"json-api": map[string]any{
				"error_envelope": "统一业务错误信封 Error{code,message,request_id}",
				"content_type":   "application/json",
			},
			"html-page": map[string]any{
				// 页面处理器自身的错误以 HTML 呈现；但传输层前置拒绝在进入页面处理器
				// 之前就返回统一 JSON 错误信封。契约按实际行为同时声明两种形态。
				"error_envelope": "页面处理器产生：HTML 错误页；传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/panic）：application/json 统一错误信封",
				"content_type":   "text/html; charset=utf-8（成功与页面处理器错误）或 application/json（传输层前置拒绝）",
				"csrf":           "表单隐藏令牌 + 精确同源校验（CSRF 失败由传输层返回 JSON 信封）",
				"session":        "会话 Cookie（页面处理器每次请求重新校验）",
			},
		},
		"x-login-page-contract": map[string]any{
			"version":      "ui.v1",
			"documented":   len(page.Documented),
			"unregistered": len(page.Unregistered),
			"scope":        "账户/资料/会话/注册登录/MFA/三种恢复流程（邮件找回、恢复代码重绑、人工恢复）",
			"modules":      pageModuleEnabledWhen,
			"note":         "未登记契约的页面路由（管理/审计/报告/备份/OAuth 页面等）不在本步范围，路由清单见 docs/reference/http-api.md 与 http-routes.json；后续步骤补管理组模式。",
		},
		// 页面/表单共用的传输语义与限流说明（放文档级，避免在每条操作里重复）。
		"x-login-page-transport": map[string]any{
			"response_format": "成功与页面处理器错误为 text/html；传输层前置拒绝（路径规范化/CSRF/限流/并发/超时/内部 panic）返回 application/json 统一错误信封（Error schema）。",
			"rate_limit": map[string]any{
				"dimensions":   []string{"client-ip", "endpoint", "concurrency", "request-timeout"},
				"status":       429,
				"error_code":   "RATE_LIMITED",
				"retry_header": "Retry-After",
				"response":     "application/json 统一错误信封（限流在页面处理器之前拒绝）",
				"description":  "页面与 API 共用传输层固定窗口限流、并发上限与请求期限。",
			},
			"csrf":    "写操作要求表单隐藏 CSRF 令牌（x-login-csrf 标明匿名公开表单或会话绑定）+ 精确同源校验；校验失败由传输层返回 403 application/json 错误信封。",
			"session": "user/management 访问级别声明 sessionCookie 安全方案；服务端每次请求重新校验会话与权限。",
		},
		"x-login-protocol-mode": map[string]any{
			"enabled_by":      "protocol.enabled（默认 false；独立服务 --enable-protocol 可显式开启）",
			"reserved_prefix": OAuthReservedPrefix + "/",
			"when_disabled":   "保留前缀路径返回普通 404，不使用统一业务错误信封",
			"note":            "OAuth 2.0 / OIDC 端点使用标准协议响应，不属于本文件；Discovery 只声明真实启用能力。",
		},
		"x-login-admin-json-api": map[string]any{
			"documented": false,
			"reason":     "管理 JSON API 的路由清单已由 AST 扫描生成于 docs/reference/http-api.md 与 http-routes.json；请求/响应模式在后续管理组步骤统一定义，本步不用占位 schema 伪装完整。",
		},
		"x-login-examples-policy": "所有示例均为明确合成值（example-*、000000 等），不包含可用密码、令牌、恢复码、私钥或真实用户数据。",
		"x-login-offline-check":   "go run ./scripts/reference -check：逐字节核对 docs/reference 生成物，并校验页面操作契约与实际路由的方法/路径一致。",
	}
	return json.MarshalIndent(document, "", "  ")
}

// OpenAPIDocument 生成指定前缀的基础 OpenAPI 文档（不含宿主实际注册的页面路由），
// 供公开包导出与测试使用。服务端运行期文档会追加实际注册的页面/表单操作。
func OpenAPIDocument(prefix string, codes []ErrorCodeInfo, version string) ([]byte, error) {
	return buildOpenAPIDocument(prefix, codes, version, nil)
}

// OpenAPIDocumentWithPageRoutes 生成包含实际注册页面路由的 OpenAPI 文档；页面
// 契约缺失/方法或路径漂移时返回错误（fail-closed），供文档生成与测试使用。
func OpenAPIDocumentWithPageRoutes(prefix string, codes []ErrorCodeInfo, version string,
	routes []PageRoute) ([]byte, error) {
	return buildOpenAPIDocument(prefix, codes, version, routes)
}

// errorResponse 构造统一的 JSON 错误响应描述。
func errorResponse(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/Error"},
			},
		},
	}
}

// openAPIHandler 返回固定字节的 OpenAPI 响应；文档在构造时生成一次，运行时
// 不做数据库或配置读取。
func (h *handler) handleOpenAPI(_ context.Context, w *responseWriter, _ *http.Request) error {
	header := w.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(h.openAPIDocument)
	return err
}

// validateOpenAPIDocument 在构造阶段自检文档可解析且结构完整，避免运行时才发现
// 坏文档：路径非空、操作有唯一 operationId、有响应、页面/JSON 语义标识齐全。
func validateOpenAPIDocument(document []byte) error {
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return fmt.Errorf("OpenAPI 文档不是合法 JSON: %w", err)
	}
	if decoded["openapi"] != openAPIVersion {
		return fmt.Errorf("OpenAPI 文档版本无效")
	}
	paths, ok := decoded["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return fmt.Errorf("OpenAPI 文档缺少 paths")
	}
	responseRefs := map[string]struct{}{}
	if components, ok := decoded["components"].(map[string]any); ok {
		if responses, ok := components["responses"].(map[string]any); ok {
			for name := range responses {
				responseRefs["#/components/responses/"+name] = struct{}{}
			}
		}
	}
	operationIDs := map[string]string{}
	for path, rawItem := range paths {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("OpenAPI 路径 %q 必须以 / 开头", path)
		}
		pathItem, ok := rawItem.(map[string]any)
		if !ok || len(pathItem) == 0 {
			return fmt.Errorf("OpenAPI 路径 %q 没有操作", path)
		}
		for method, rawOperation := range pathItem {
			if method != strings.ToLower(http.MethodGet) && method != strings.ToLower(http.MethodPost) {
				return fmt.Errorf("OpenAPI 路径 %q 的方法 %q 未登记", path, method)
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				return fmt.Errorf("OpenAPI 路径 %q 的 %s 操作结构无效", path, method)
			}
			operationID, _ := operation["operationId"].(string)
			if operationID == "" {
				return fmt.Errorf("OpenAPI 路径 %q 的 %s 操作缺少 operationId", path, method)
			}
			if previous, exists := operationIDs[operationID]; exists {
				return fmt.Errorf("OpenAPI operationId %q 重复（%s 与 %s %s）",
					operationID, previous, method, path)
			}
			operationIDs[operationID] = method + " " + path
			if responses, ok := operation["responses"].(map[string]any); !ok || len(responses) == 0 {
				return fmt.Errorf("OpenAPI 路径 %q 的 %s 操作缺少 responses", path, method)
			} else {
				for status, rawResponse := range responses {
					entry, ok := rawResponse.(map[string]any)
					if !ok {
						return fmt.Errorf("OpenAPI %s %s 的响应 %s 结构无效", method, path, status)
					}
					if ref, ok := entry["$ref"].(string); ok {
						if _, exists := responseRefs[ref]; !exists {
							return fmt.Errorf("OpenAPI %s %s 的响应 %s 引用未定义的组件 %q",
								method, path, status, ref)
						}
					}
				}
			}
			kind, _ := operation["x-login-route-kind"].(string)
			switch kind {
			case "json-api":
				if method != strings.ToLower(http.MethodGet) {
					return fmt.Errorf("JSON API 路径 %q 的 %s 操作只应为只读 GET", path, method)
				}
			case "html-page":
				routeName, _ := operation["x-login-route-name"].(string)
				if routeName == "" {
					return fmt.Errorf("页面操作路径 %q 的 %s 缺少命名路由", path, method)
				}
				_, hasBody := operation["requestBody"]
				if method == strings.ToLower(http.MethodPost) && !hasBody {
					return fmt.Errorf("页面写操作 %s %s 缺少 requestBody", method, path)
				}
				if method == strings.ToLower(http.MethodGet) && hasBody {
					return fmt.Errorf("页面读操作 %s %s 不应有 requestBody", method, path)
				}
			default:
				return fmt.Errorf("OpenAPI 路径 %q 的 %s 操作缺少 x-login-route-kind", path, method)
			}
		}
	}
	return nil
}
