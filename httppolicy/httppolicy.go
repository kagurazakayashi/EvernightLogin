// Package httppolicy 定义 HTTP 传输层的公共纯策略：固定路径前缀规范化与相关长度
// 上限。它不依赖本模块的 internal 包，供公开的 config/http 契约与 internal 传输
// 实现共用同一规则；本包不解析请求、不写响应、不建立监听。
package httppolicy

import (
	"fmt"
	"strings"
)

// MaxPrefixBytes 是路径前缀最大长度。
const MaxPrefixBytes = 128

// NormalizePrefix 校验并规范化固定路径前缀。合法形式只有空字符串或
// "/segment(/segment)*"：必须以单个斜杠开头、不能以斜杠结尾、不能包含空段、
// 点段、反斜杠、百分号编码、查询串或片段。空字符串表示挂在根路径。
//
// 前缀是路由权限的一部分：前缀不匹配的请求一律 404，绝不做“去掉多余斜杠后
// 再匹配”的归一化。
func NormalizePrefix(prefix string) (string, error) {
	if prefix == "" {
		return "", nil
	}
	if len(prefix) > MaxPrefixBytes {
		return "", fmt.Errorf("路径前缀不能超过 %d 字节", MaxPrefixBytes)
	}
	if prefix[0] != '/' {
		return "", fmt.Errorf("路径前缀必须以 / 开头")
	}
	if prefix == "/" {
		return "", fmt.Errorf("路径前缀不能是单个斜杠；根路径请使用空字符串")
	}
	if strings.HasSuffix(prefix, "/") {
		return "", fmt.Errorf("路径前缀不能以 / 结尾")
	}
	if strings.ContainsAny(prefix, "%?#\\") {
		return "", fmt.Errorf("路径前缀不能包含百分号编码、查询串、片段或反斜杠")
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("路径前缀不能包含空段或点段")
		}
		for index := 0; index < len(segment); index++ {
			character := segment[index]
			if character < 0x21 || character > 0x7e {
				return "", fmt.Errorf("路径前缀只能包含可见 ASCII 字符")
			}
		}
	}
	return prefix, nil
}
