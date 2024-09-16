package apidoc

// 本文件把管理 JSON API 路由的 AST 扫描结果导出给 scripts/adminapi-doc（步骤 270）。
// 两个命令共用同一扫描器：adminapi-doc 用它校验管理 API 契约与真实注册一致，
// 避免为了“只读一份 JSON”而在别处复制第二套路由扫描逻辑。

// ScannedAdminRoute 是管理 API 路由事实的公开投影。
type ScannedAdminRoute struct {
	// Method 是 HTTP 方法（大写）。
	Method string
	// Pattern 是相对管理 API 前缀的路径模式。
	Pattern string
	// Source 是定义位置（仓库相对路径）。
	Source string
}

// ScanAdminRoutes 扫描 adminapi/serverapp 中真实注册的管理 API 路由（只读 AST）。
// 扫描失败时返回错误（调用方可回退到 docs/reference/http-routes.json）。
func ScanAdminRoutes(root string) ([]ScannedAdminRoute, error) {
	routes, err := scanAdminRoutes(root)
	if err != nil {
		return nil, err
	}
	projected := make([]ScannedAdminRoute, 0, len(routes))
	for _, route := range routes {
		projected = append(projected, ScannedAdminRoute{
			Method: route.Method, Pattern: route.Pattern, Source: route.Source,
		})
	}
	return projected, nil
}
