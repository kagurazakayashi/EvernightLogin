package transport

import (
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/httppolicy"
)

// NormalizePrefix 校验并规范化固定路径前缀。合法形式只有空字符串或
// "/segment(/segment)*"：必须以单个斜杠开头、不能以斜杠结尾、不能包含空段、
// 点段、反斜杠、百分号编码、查询串或片段。空字符串表示挂在根路径。
//
// 前缀是路由权限的一部分：前缀不匹配的请求一律 404，绝不做“去掉多余斜杠后
// 再匹配”的归一化。规则实现已提升到公共 httppolicy 包（单一实现）；本包装保持
// internal/transport 既有调用方零改动。
func NormalizePrefix(prefix string) (string, error) {
	return httppolicy.NormalizePrefix(prefix)
}

// canonicalRequestPath 返回可用于路由匹配的严格路径。任何需要“清理”才能匹配
// 的请求都返回 404 错误，不做重写或重定向，避免归一化绕过路由与权限：
//   - 路径必须是合法 UTF-8、可见 ASCII，不允许百分号编码（避免 %68ealthz、
//     %2f 等编码歧义）；
//   - 不允许重复斜杠、点段（. 或 ..）、反斜杠、空段；
//   - 不允许尾斜杠（根路径除外，但本步没有根路径路由）；
//   - 路径长度与查询串长度有上限。
func canonicalRequestPath(r *http.Request) (string, *problem) {
	rawPath := r.URL.EscapedPath()
	if rawPath == "" {
		return "", newProblem(http.StatusBadRequest, "REQ_INVALID", "请求路径无效")
	}
	if len(rawPath) > MaxPathBytes {
		return "", newProblem(http.StatusRequestURITooLong, "REQ_INVALID", "请求地址过长")
	}
	if len(r.URL.RawQuery) > MaxQueryBytes {
		return "", newProblem(http.StatusRequestURITooLong, "REQ_INVALID", "请求地址过长")
	}
	if strings.ContainsAny(rawPath, "%\\") {
		return "", newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
	}
	if rawPath[0] != '/' {
		return "", newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
	}
	for index := 0; index < len(rawPath); index++ {
		character := rawPath[index]
		if character < 0x21 || character > 0x7e {
			return "", newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
		}
	}
	if len(rawPath) > 1 && strings.HasSuffix(rawPath, "/") {
		return "", newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
	}
	segments := strings.Split(rawPath[1:], "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", newProblem(http.StatusNotFound, "REQ_INVALID", "请求的资源不存在")
		}
	}
	return rawPath, nil
}

// routePath 返回前缀加固定后缀的完整路由路径。
func routePath(prefix, suffix string) string {
	return prefix + suffix
}
