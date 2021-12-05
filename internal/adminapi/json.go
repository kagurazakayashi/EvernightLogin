package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// callContext 是一次管理 API 调用的可信上下文：会话身份、请求编号与路径参数。
// 处理器只能从 caller 取操作者，绝不读取请求体/查询参数里的操作者标识。
type callContext struct {
	server    *Server
	writer    http.ResponseWriter
	request   *http.Request
	requestID string
	caller    account.Caller
	params    map[string]string
}

// decodeJSON 严格解码 JSON 请求体：未知字段、重复字段映射错误、尾随内容或
// 超过上限一律拒绝；请求体为空按参数错误处理。
func (c *callContext) decodeJSON(target any) error {
	if c.request.Body == nil {
		return fmt.Errorf("%w: 缺少请求体", ErrInvalidRequest)
	}
	decoder := json.NewDecoder(c.request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		// chunked/无 Content-Length 的超限请求体只在读取时暴露为 MaxBytesError，
		// 必须映射为 413 而不是参数错误 400。
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("%w: %w", ErrBodyTooLarge, err)
		}
		return fmt.Errorf("%w: 请求体不是合法的 JSON 对象", ErrInvalidRequest)
	}
	// 拒绝尾随内容，避免“解析到第一个对象就忽略其余字节”的走私/混淆。
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("%w: %w", ErrBodyTooLarge, err)
		}
		return fmt.Errorf("%w: 请求体包含多余内容", ErrInvalidRequest)
	}
	return nil
}

// requireConfirm 校验管理写操作的确认语义。确认不是授权：权限、敏感操作策略、
// 审计仍由领域服务在服务端重新判定；这里只拒绝“未显式确认目标与后果”的请求。
func requireConfirm(confirm bool) error {
	if !confirm {
		return fmt.Errorf("%w: 写操作必须显式确认（confirm=true）", ErrInvalidRequest)
	}
	return nil
}

// requireReason 校验取消/清理/保留策略等操作的原因：原因进入真实审计，不能为空。
func requireReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 该操作必须提供原因", ErrInvalidRequest)
	}
	if len(trimmed) > MaxReasonBytes {
		return "", fmt.Errorf("%w: 原因超过 %d 字节", ErrInvalidRequest, MaxReasonBytes)
	}
	return trimmed, nil
}

// queryString 读取可选查询参数并限制长度。
func queryString(r *http.Request, key string, maxBytes int) (string, error) {
	values := r.URL.Query()[key]
	if len(values) == 0 {
		return "", nil
	}
	if len(values) > 1 {
		return "", fmt.Errorf("%w: 查询参数 %s 只能出现一次", ErrInvalidRequest, key)
	}
	value := strings.TrimSpace(values[0])
	if len(value) > maxBytes {
		return "", fmt.Errorf("%w: 查询参数 %s 过长", ErrInvalidRequest, key)
	}
	return value, nil
}

// queryInt 读取可选整数查询参数并限制范围。
func queryInt(r *http.Request, key string, defaultValue, minValue, maxValue int) (int, error) {
	raw, err := queryString(r, key, 32)
	if err != nil {
		return 0, err
	}
	if raw == "" {
		return defaultValue, nil
	}
	value, parseErr := strconv.Atoi(raw)
	if parseErr != nil {
		return 0, fmt.Errorf("%w: 查询参数 %s 必须是整数", ErrInvalidRequest, key)
	}
	if value < minValue || value > maxValue {
		return 0, fmt.Errorf("%w: 查询参数 %s 超出允许范围", ErrInvalidRequest, key)
	}
	return value, nil
}

// queryBool 读取可选的布尔查询参数（仅接受 true/false/1/0）。
func queryBool(r *http.Request, key string) (bool, error) {
	raw, err := queryString(r, key, 8)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(raw) {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	default:
		return false, fmt.Errorf("%w: 查询参数 %s 必须是布尔值", ErrInvalidRequest, key)
	}
}

// queryTime 读取可选 RFC3339 时间参数。
func queryTime(r *http.Request, key string) (time.Time, error) {
	raw, err := queryString(r, key, 64)
	if err != nil {
		return time.Time{}, err
	}
	if raw == "" {
		return time.Time{}, nil
	}
	value, parseErr := time.Parse(time.RFC3339, raw)
	if parseErr != nil {
		return time.Time{}, fmt.Errorf("%w: 查询参数 %s 必须是 RFC3339 时间", ErrInvalidRequest, key)
	}
	return value.UTC(), nil
}

// pageParams 解析受控分页参数。
func pageParams(r *http.Request) (limit, offset int, err error) {
	limit, err = queryInt(r, "limit", DefaultPageLimit, 1, MaxPageLimit)
	if err != nil {
		return 0, 0, err
	}
	offset, err = queryInt(r, "offset", 0, 0, MaxOffset)
	if err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// pathParam 读取已匹配的路径参数。
func (c *callContext) pathParam(name string) string {
	return c.params[name]
}
