package transport

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

// maxJSONBodyDepth 不是解析限制，而是提醒：请求结构与字段白名单由具体业务
// 处理程序定义，传输层只负责类型、大小和单值边界。
const (
	// maxParameterBytes 是普通文本参数默认上限。
	maxParameterBytes = 2048
	// maxIdentifierBytes 是稳定标识参数默认上限。
	maxIdentifierBytes = 64
)

// decodeJSONBody 解码单值 JSON 请求体到 dst。边界：
//   - Content-Type 必须是 application/json（允许 charset=utf-8/utf8），否则 415；
//   - 请求体必须是一个 JSON 值，不接受尾随内容；
//   - 未知字段被拒绝（默认拒绝，避免静默忽略客户端字段）；
//   - 请求体大小由 Handler 的 MaxBytesReader 限制，超限返回 413。
//
// 错误响应只给出稳定错误码与固定说明，不回显请求内容或解析错误细节。
func decodeJSONBody(r *http.Request, dst any) *problem {
	if r == nil || r.Body == nil {
		return newProblem(http.StatusBadRequest, "REQ_INVALID", "请求内容不符合要求")
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return newProblem(http.StatusUnsupportedMediaType, "REQ_INVALID", "请求内容类型必须为 application/json")
	}
	if charset, exists := parameters["charset"]; exists {
		normalized := strings.ToLower(strings.TrimSpace(charset))
		if normalized != "utf-8" && normalized != "utf8" {
			return newProblem(http.StatusUnsupportedMediaType, "REQ_INVALID", "请求内容类型必须为 application/json")
		}
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return jsonDecodeProblem(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return newProblem(http.StatusBadRequest, "REQ_INVALID", "请求内容不符合要求")
	}
	return nil
}

// jsonDecodeProblem 把解码错误映射为统一 problem；MaxBytesError 映射为 413，
// 其余解析错误统一 400，不暴露字段名或值。
func jsonDecodeProblem(err error) *problem {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return newProblem(http.StatusRequestEntityTooLarge, "REQ_INVALID", "请求体超过允许的大小")
	}
	return newProblem(http.StatusBadRequest, "REQ_INVALID", "请求内容不符合要求")
}

// normalizeTextParam 规范化普通文本参数：去除首尾 ASCII 空白、拒绝控制字符、
// 非法 UTF-8 与超长值；allowUnicode=false 时只接受可见 ASCII。错误信息只包含
// 参数名，不回显参数值。
func normalizeTextParam(name, value string, maxBytes int, allowUnicode bool) (string, *problem) {
	if maxBytes <= 0 || maxBytes > 64*1024 {
		maxBytes = maxParameterBytes
	}
	trimmed := strings.Trim(value, " \t\r\n")
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > maxBytes {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 过长")
	}
	if !utf8.ValidString(trimmed) {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 无效")
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 包含控制字符")
		}
		if !allowUnicode && (character < 0x21 || character > 0x7e) {
			return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 只能包含可见 ASCII 字符")
		}
	}
	return trimmed, nil
}

// normalizeIdentifierParam 规范化稳定标识参数：只允许 ASCII 字母、数字与 . _ -，
// 长度受限。它用于用户名之外的 ID、类型、状态等机器标识；显示名称不应使用本
// 函数，以免错误拒绝国际化文本。
func normalizeIdentifierParam(name, value string, maxBytes int) (string, *problem) {
	if maxBytes <= 0 || maxBytes > 256 {
		maxBytes = maxIdentifierBytes
	}
	trimmed := strings.Trim(value, " \t\r\n")
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > maxBytes {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 过长")
	}
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if !isASCIIAlnum(character) && character != '.' && character != '_' && character != '-' {
			return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 只能包含 ASCII 字母、数字和 . _ -")
		}
	}
	return trimmed, nil
}

// singleQueryValue 读取唯一查询参数并做文本规范化。同名参数出现多次时拒绝，
// 避免“取第一个还是最后一个”的解析歧义被用于参数走私。
func singleQueryValue(r *http.Request, name string, maxBytes int, allowUnicode bool) (string, *problem) {
	if r == nil {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "请求内容不符合要求")
	}
	values, exists := r.URL.Query()[name]
	if !exists {
		return "", nil
	}
	if len(values) != 1 {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "参数 "+safeParamName(name)+" 不能重复")
	}
	return normalizeTextParam(name, values[0], maxBytes, allowUnicode)
}

// singleHeaderValue 读取唯一请求头值并做文本规范化；多值请求头被拒绝，避免
// 代理与后端解析不一致造成的安全歧义。敏感头（认证、Cookie）不应交给本函数
// 之外的业务逻辑。
func singleHeaderValue(r *http.Request, name string, maxBytes int, allowUnicode bool) (string, *problem) {
	if r == nil {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "请求内容不符合要求")
	}
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "请求头 "+safeParamName(name)+" 不能重复")
	}
	return normalizeTextParam(name, values[0], maxBytes, allowUnicode)
}

// safeParamName 把参数名压成受限的 ASCII 标识，避免把攻击者可控的名字原样写入
// 公开错误消息。
func safeParamName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "参数"
	}
	var builder strings.Builder
	for index := 0; index < len(trimmed) && builder.Len() < 32; index++ {
		character := trimmed[index]
		if isASCIIAlnum(character) || character == '_' || character == '-' || character == '.' {
			builder.WriteByte(character)
		}
	}
	if builder.Len() == 0 {
		return "参数"
	}
	return builder.String()
}

// contentLengthOrUnknown 返回请求体长度，未知（chunked）时返回 -1。
func contentLengthOrUnknown(r *http.Request) int64 {
	if r == nil || r.ContentLength < 0 {
		return -1
	}
	return r.ContentLength
}
