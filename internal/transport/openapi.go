package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

// openAPIVersion 是输出的 OpenAPI 规范版本。
const openAPIVersion = "3.0.3"

// buildOpenAPIDocument 生成最小机器可读 OpenAPI 文档。文档必须与错误码注册表
// 保持一致：错误码 enum 与 x-login-error-registry 都由注入的 ErrorCodeInfo 直接
// 生成，新增错误码时无需再手工维护第二份清单。
func buildOpenAPIDocument(prefix string, codes []ErrorCodeInfo, version string) ([]byte, error) {
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
		"description": "统一业务错误响应。code 是稳定错误码；message 是可公开的直白说明；" +
			"request_id 用于受限排障。OAuth/OIDC 标准协议响应不使用本结构。",
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
				"summary":     "最小健康检查",
				"description": "返回固定 {\"status\":\"ok\"}；不依赖身份解析，不泄露配置、数据库路径或密钥。",
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
				"summary":     "机器可读接口契约",
				"description": "返回本 Handler 前缀下的 OpenAPI 文档；错误码 enum 与错误码注册表一致。",
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
	document := map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{
			"title":   "login HTTP API",
			"version": version,
			"description": "login 的最小 HTTP 契约：只包含健康检查与 OpenAPI 文档。" +
				"统一业务错误 JSON 仅用于 login API；/oauth2 前缀保留给未来 OAuth/OIDC 标准协议响应，" +
				"不被统一错误信封覆盖。",
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": map[string]any{
				"Error":  errorSchema,
				"Health": healthSchema,
			},
		},
		// 错误码注册表投影：与 enum 同源生成，供机器校验。
		"x-login-error-registry": registry,
		// OAuth/OIDC 标准响应空间保留前缀；未来协议适配层不得被统一错误信封包装。
		"x-login-oauth-reserved-prefix":  OAuthReservedPrefix + "/",
		"x-login-common-error-responses": errorResponses,
	}
	return json.MarshalIndent(document, "", "  ")
}

// OpenAPIDocument 生成指定前缀的 OpenAPI 文档，供公开包导出与测试使用。
func OpenAPIDocument(prefix string, codes []ErrorCodeInfo, version string) ([]byte, error) {
	return buildOpenAPIDocument(prefix, codes, version)
}

// errorResponse 构造统一的错误响应描述。
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

// validateOpenAPIDocument 在构造阶段自检文档可解析，避免运行时才发现坏文档。
func validateOpenAPIDocument(document []byte) error {
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return fmt.Errorf("OpenAPI 文档不是合法 JSON: %w", err)
	}
	if decoded["openapi"] != openAPIVersion {
		return fmt.Errorf("OpenAPI 文档版本无效")
	}
	return nil
}
