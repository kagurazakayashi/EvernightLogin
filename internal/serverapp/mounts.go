package serverapp

import (
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
)

// HandlerMount 是协议端点/管理 JSON API 处理程序在独立服务上的显式挂载点。
//
// 设计目的：OAuth2/OIDC/设备码/扫码协议端点与管理 JSON API 由独立包实现（本包
// 不实现它们）。交付后集成只需在 ServeOptions.ExtraMounts 中追加一项：
//
//	{Name: "oauth2", Prefix: "/api/oauth2", Handler: protocolHandler}
//
// 挂载路径 = 配置的 server.path_prefix + Prefix（前缀规范化后不会出现重复斜杠）。
// 处理程序收到的请求路径已去掉挂载前缀（与 http.StripPrefix 语义一致），因此协议
// 包无需感知部署前缀。维护模式下不挂载任何额外处理程序（只放行健康检查）。
type HandlerMount struct {
	// Name 是稳定名称（日志/诊断用），必填且不得重复。
	Name string
	// Prefix 是站内相对挂载前缀，必须是以 "/" 开头的绝对路径风格字符串，
	// 不含查询/片段/点段；挂载点之间不得互相嵌套。
	Prefix string
	// Handler 是真实处理程序，必填。
	Handler http.Handler
	// KeepPrefix 为 true 时处理程序收到完整请求路径（含挂载前缀），用于像
	// internal/adminapi 这样自带固定 BasePath 的处理器；false（默认）剥离前缀。
	KeepPrefix bool
}

// reservedMountPaths 是不允许被挂载点覆盖的内置路径（相对部署前缀）。
var reservedMountPaths = []string{"/healthz", "/openapi.json", "/_ui/"}

// ComposeHandler 把额外处理程序挂载到既有 HTTP 处理程序之上。
//
// 未配置挂载时原样返回 base（不引入额外包装）。配置非法（空名称、重复前缀、
// 互相嵌套、覆盖内置路径、nil 处理程序）时返回错误，由调用方拒绝启动，避免
// 协议端点被静默吞掉或覆盖健康检查/内置页面。
func ComposeHandler(base http.Handler, pathPrefix string, mounts []HandlerMount) (http.Handler, error) {
	if base == nil {
		return nil, fmt.Errorf("挂载额外处理程序缺少基础处理程序")
	}
	if len(mounts) == 0 {
		return base, nil
	}
	normalizedPrefix := normalizePathPrefix(pathPrefix)
	type mountedHandler struct {
		name        string
		mountedPath string
		relative    string
		handler     http.Handler
		keepPrefix  bool
	}
	mounted := make([]mountedHandler, 0, len(mounts))
	names := make(map[string]struct{}, len(mounts))
	paths := make(map[string]struct{}, len(mounts))
	for index, mount := range mounts {
		name := strings.TrimSpace(mount.Name)
		if name == "" {
			return nil, fmt.Errorf("第 %d 个挂载点缺少名称", index)
		}
		if _, exists := names[name]; exists {
			return nil, fmt.Errorf("挂载点名称重复: %s", name)
		}
		names[name] = struct{}{}
		if mount.Handler == nil {
			return nil, fmt.Errorf("挂载点 %s 缺少处理程序", name)
		}
		prefix, err := validateMountPrefix(mount.Prefix)
		if err != nil {
			return nil, fmt.Errorf("挂载点 %s: %w", name, err)
		}
		mountedPath := normalizedPrefix + prefix
		if _, exists := paths[mountedPath]; exists {
			return nil, fmt.Errorf("挂载路径重复: %s", mountedPath)
		}
		paths[mountedPath] = struct{}{}
		for _, reserved := range reservedMountPaths {
			reservedPath := normalizedPrefix + reserved
			if pathConflicts(mountedPath, reservedPath) {
				return nil, fmt.Errorf("挂载点 %s 覆盖内置路径 %s", name, reservedPath)
			}
		}
		mounted = append(mounted, mountedHandler{
			name: name, mountedPath: mountedPath, relative: prefix, handler: mount.Handler,
			keepPrefix: mount.KeepPrefix})
	}
	// 同级/嵌套检查：更长的挂载路径优先匹配，但互相嵌套会让语义含糊，直接拒绝。
	for left := 0; left < len(mounted); left++ {
		for right := left + 1; right < len(mounted); right++ {
			first, second := mounted[left].mountedPath, mounted[right].mountedPath
			if pathConflicts(first, second) {
				return nil, fmt.Errorf("挂载路径 %s 与 %s 互相嵌套或重复", first, second)
			}
		}
	}
	sort.SliceStable(mounted, func(left, right int) bool {
		return len(mounted[left].mountedPath) > len(mounted[right].mountedPath)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPath := request.URL.Path
		for _, item := range mounted {
			if requestPath != item.mountedPath &&
				!strings.HasPrefix(requestPath, item.mountedPath+"/") {
				continue
			}
			remainder := strings.TrimPrefix(requestPath, item.mountedPath)
			if remainder == "" {
				remainder = "/"
			}
			cloned := request.Clone(request.Context())
			cloned.URL.RawPath = ""
			if item.keepPrefix {
				// 自带固定 BasePath 的处理器（如 internal/adminapi）需要看到
				// “站内前缀 + 剩余路径”，而不是带部署前缀的完整路径；否则
				// 非空 server.path_prefix 下会全部 404。
				cloned.URL.Path = item.relative + remainder
			} else {
				cloned.URL.Path = remainder
			}
			item.handler.ServeHTTP(writer, cloned)
			return
		}
		base.ServeHTTP(writer, request)
	}), nil
}

// normalizePathPrefix 去掉前缀末尾的斜杠；空前缀（根部署）保持为空。
func normalizePathPrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" || trimmed == "/" {
		return ""
	}
	return strings.TrimRight(trimmed, "/")
}

// validateMountPrefix 校验挂载前缀并返回规范化形式（去末尾斜杠）。
func validateMountPrefix(prefix string) (string, error) {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return "", fmt.Errorf("挂载前缀不能为空")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("挂载前缀必须以 / 开头")
	}
	if strings.ContainsAny(trimmed, "?#\\ \t\r\n") {
		return "", fmt.Errorf("挂载前缀不能包含查询、片段、反斜杠或空白")
	}
	if strings.Contains(trimmed, "//") {
		return "", fmt.Errorf("挂载前缀不能包含重复斜杠")
	}
	cleaned := path.Clean(trimmed)
	if cleaned != trimmed && cleaned+"/" != trimmed && cleaned != strings.TrimRight(trimmed, "/") {
		return "", fmt.Errorf("挂载前缀必须是规范路径")
	}
	cleaned = strings.TrimRight(cleaned, "/")
	if cleaned == "" || cleaned == "/" {
		return "", fmt.Errorf("不能挂载到根路径")
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == ".." || segment == "." {
			return "", fmt.Errorf("挂载前缀不能包含点段")
		}
	}
	return cleaned, nil
}

// pathConflicts 报告两个站内路径是否相同或一个包含另一个（按段边界）。
func pathConflicts(first, second string) bool {
	if first == second {
		return true
	}
	return strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}
