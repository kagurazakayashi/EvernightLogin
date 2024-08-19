package apidoc

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 本文件扫描 HTTP 路由来源：管理 JSON API 路由、协议路径常量/端点表与内置页面
// 命名路由。扫描只读源码，不启动服务、不访问数据库。

// scanAdminRoutes 扫描管理 JSON API 路由：
//   - internal/adminapi/handler.go 中 add(method, pattern, handler) 调用；
//   - internal/adminapi 与 internal/serverapp 领域路由中的 add(...) 调用与
//     DomainRoute{Method, Pattern} 复合字面量。
func scanAdminRoutes(root string) ([]AdminRoute, error) {
	handlerPath := filepath.Join(root, filepath.FromSlash(pathAdminHandler))
	if _, err := os.Stat(handlerPath); err != nil {
		return nil, fmt.Errorf("管理 API 路由源文件 %s 不存在：%w（重构后需同步 sources.go）", pathAdminHandler, err)
	}
	seen := map[string]bool{}
	var routes []AdminRoute
	addRoute := func(method, pattern, source string) {
		if method == "" || pattern == "" {
			return
		}
		key := method + " " + pattern
		if seen[key] {
			return
		}
		seen[key] = true
		routes = append(routes, AdminRoute{Method: method, Pattern: pattern, Source: source})
	}

	handlerFile, handlerSet, err := parseAt(handlerPath)
	if err != nil {
		return nil, err
	}
	collectAddCalls(handlerFile, handlerSet, func(method, pattern string) {
		addRoute(method, pattern, pathAdminHandler)
	})

	for _, dir := range adminRouteDirs {
		dirPath := filepath.Join(root, filepath.FromSlash(dir))
		files, err := listGoFiles(dirPath)
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			file, fset, err := parseAt(path)
			if err != nil {
				return nil, err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			collectAddCalls(file, fset, func(method, pattern string) {
				addRoute(method, pattern, rel)
			})
			ast.Inspect(file, func(node ast.Node) bool {
				lit, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				typeName := compositeTypeName(lit)
				if typeName != "DomainRoute" && typeName != "domainRoute" {
					return true
				}
				methodExpr := compositeKeyValue(lit, "Method")
				patternExpr := compositeKeyValue(lit, "Pattern")
				if methodExpr == nil || patternExpr == nil {
					return true
				}
				addRoute(httpMethodName(fset, methodExpr), stringLit(patternExpr), rel)
				return true
			})
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Method != routes[j].Method {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Pattern < routes[j].Pattern
	})
	return routes, nil
}

// collectAddCalls 收集文件中形如 add(http.MethodGet, "patterns", ...) 的路由注册。
func collectAddCalls(file *ast.File, fset *token.FileSet, record func(method, pattern string)) {
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "add" || len(call.Args) < 2 {
			return true
		}
		method := httpMethodName(fset, call.Args[0])
		pattern := stringLit(call.Args[1])
		if method == "" || pattern == "" {
			return true
		}
		record(method, pattern)
		return true
	})
}

// protocolEndpointPattern 匹配协议包文档表中的 "GET /path" 端点声明。
var protocolEndpointPattern = regexp.MustCompile(`^\s*//\s+(GET|POST|PUT|DELETE|PATCH)\s+(/\S+)\s*(.*)$`)

// scanProtocol 扫描协议端点：
//   - internal/protocolapi/protocolapi.go 中导出的 Path* 路径常量（常量名 + 路径）；
//   - 同一文件包注释中的 HTTP 端点表（方法 + 路径）。
func scanProtocol(root string) ([]ProtocolPath, []ProtocolEndpoint, error) {
	protocolPath := filepath.Join(root, filepath.FromSlash(pathProtocolPaths))
	file, _, err := parseAt(protocolPath)
	if err != nil {
		return nil, nil, err
	}
	var paths []ProtocolPath
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range valueSpec.Names {
				if !name.IsExported() || !strings.HasPrefix(name.Name, "Path") {
					continue
				}
				var value ast.Expr
				if index < len(valueSpec.Values) {
					value = valueSpec.Values[index]
				}
				if value == nil {
					continue
				}
				if path := stringLit(value); path != "" {
					paths = append(paths, ProtocolPath{Name: name.Name, Path: path})
				}
			}
		}
	}
	var endpoints []ProtocolEndpoint
	for _, commentGroup := range file.Comments {
		for _, comment := range commentGroup.List {
			match := protocolEndpointPattern.FindStringSubmatch(comment.Text)
			if match == nil {
				continue
			}
			endpoints = append(endpoints, ProtocolEndpoint{Method: match[1], Path: match[2]})
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Name < paths[j].Name })
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})
	return paths, endpoints, nil
}

// scanPages 扫描根包 UIRoute 复合字面量（内置页面命名路由冻结契约）。
func scanPages(root string) ([]PageRoute, error) {
	files, err := listGoFiles(root)
	if err != nil {
		return nil, err
	}
	var pages []PageRoute
	seen := map[string]bool{}
	for _, path := range files {
		file, fset, err := parseAt(path)
		if err != nil {
			return nil, err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typeName := compositeTypeName(lit)
			if typeName != "UIRoute" && typeName != "uiRoute" {
				if typeName != "" {
					return true
				}
				if compositeKeyValue(lit, "Name") == nil || compositeKeyValue(lit, "Path") == nil {
					return true
				}
			}
			name := stringLit(compositeKeyValue(lit, "Name"))
			routePath := stringLit(compositeKeyValue(lit, "Path"))
			if name == "" || routePath == "" {
				return true
			}
			key := name + " " + routePath
			if seen[key] {
				return true
			}
			seen[key] = true
			method := httpMethodName(fset, compositeKeyValue(lit, "Method"))
			if method == "" {
				method = "GET"
			}
			pages = append(pages, PageRoute{
				Name: name, Method: method, Path: routePath,
				Access: exprString(fset, compositeKeyValue(lit, "Access")),
				Source: rel,
			})
			return true
		})
	}
	sort.Slice(pages, func(i, j int) bool {
		if pages[i].Name != pages[j].Name {
			return pages[i].Name < pages[j].Name
		}
		return pages[i].Path < pages[j].Path
	})
	return pages, nil
}
