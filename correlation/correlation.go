// Package correlation 定义通用关联编号（请求编号/任务编号/扩展标识）的公共格式
// 校验规则。
//
// 它是纯字符串校验的叶子包，不依赖本模块任何其它包，供公开错误契约 errs 与公开
// HTTP 契约 httpapi 共用同一实现，避免两处复制字符集/长度规则，也避免 errs 与
// httpapi 之间形成导入环。
//
// 规则：非空；长度不超过 MaxCorrelationIDLength 个 ASCII 字符；必须以 ASCII
// 字母或数字开头；只允许 ASCII 字母、数字、点、下划线与连字符。拒绝空白、换行、
// 控制字符与 Unicode，避免日志注入与歧义。
package correlation

import (
	"context"
	"fmt"
)

// MaxCorrelationIDLength 是关联编号允许的最大长度（ASCII 字符）。
const MaxCorrelationIDLength = 64

// requestIDContextKey 是请求编号在上下文中的私有键；公开 HTTP/UI 契约与 internal
// 传输实现共用同一键，避免请求编号在迁移后丢失。
type requestIDContextKey struct{}

// WithRequestID 把请求编号放入上下文；编号只用于关联与排障，不用于授权。
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// RequestIDFromContext 返回上下文中的请求编号；没有时返回空字符串。
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

// Validate 校验关联编号；label 用于错误说明（例如“请求编号”），不包含编号值。
func Validate(label, id string) error {
	if id == "" {
		return fmt.Errorf("%s不能为空", label)
	}
	if len(id) > MaxCorrelationIDLength {
		return fmt.Errorf("%s长度不能超过 %d 个字符", label, MaxCorrelationIDLength)
	}
	if !isASCIIAlnum(id[0]) {
		return fmt.Errorf("%s必须以 ASCII 字母或数字开头", label)
	}
	for index := 0; index < len(id); index++ {
		character := id[index]
		if !isASCIIAlnum(character) && character != '.' && character != '_' && character != '-' {
			return fmt.Errorf("%s只能包含 ASCII 字母、数字、点、下划线和连字符", label)
		}
	}
	return nil
}

// isASCIIAlnum 报告字节是否为 ASCII 字母或数字。
func isASCIIAlnum(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9')
}
