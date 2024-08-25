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
	handlerRel, err := resolveFirstExisting(root, "管理 JSON API 路由", adminHandlerCandidates)
	if err != nil {
		return nil, err
	}
	handlerPath := filepath.Join(root, filepath.FromSlash(handlerRel))
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
		addRoute(method, pattern, handlerRel)
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
				if typeName == "DomainRoute" || typeName == "domainRoute" {
					// 显式元素类型：DomainRoute{Method: ..., Pattern: ...}。
					methodExpr := compositeKeyValue(lit, "Method")
					patternExpr := compositeKeyValue(lit, "Pattern")
					if methodExpr != nil && patternExpr != nil {
						addRoute(httpMethodName(fset, methodExpr), stringLit(patternExpr), rel)
					}
					return true
				}
				// 隐式元素类型：[]adminapi.DomainRoute{{Method: ..., Pattern: ...}, ...}
				// （设置/诊断等领域路由使用紧凑写法，元素省略类型）。
				array, ok := lit.Type.(*ast.ArrayType)
				if !ok || baseTypeName(array.Elt) != "DomainRoute" {
					return true
				}
				for _, element := range lit.Elts {
					child, ok := element.(*ast.CompositeLit)
					if !ok {
						continue
					}
					methodExpr := compositeKeyValue(child, "Method")
					patternExpr := compositeKeyValue(child, "Pattern")
					if methodExpr == nil || patternExpr == nil {
						continue
					}
					addRoute(httpMethodName(fset, methodExpr), stringLit(patternExpr), rel)
				}
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
	protocolRel, err := resolveFirstExisting(root, "协议路径常量", protocolPathCandidates)
	if err != nil {
		return nil, nil, err
	}
	protocolPath := filepath.Join(root, filepath.FromSlash(protocolRel))
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

// scanPages 扫描页面命名路由 UIRoute 复合字面量（内置页面冻结契约）。
//
// 214 起页面实现迁到公开包 ui/（ui/pages_*.go 中 routes := []UIRoute{...}，元素
// 省略类型），根包保留兼容别名；pageScanDirs 依次扫描根目录（非递归）与 ui/（递归），
// 按 name+method+path 去重。一条都没扫到则失败，提示更新 sources.go 候选目录。
func scanPages(root string) ([]PageRoute, error) {
	var files []string
	for _, dir := range pageScanDirs {
		dirPath := root
		if dir != "." {
			dirPath = filepath.Join(root, filepath.FromSlash(dir))
		}
		info, err := os.Stat(dirPath)
		if err != nil || !info.IsDir() {
			continue
		}
		if dir == "." {
			rootFiles, err := listGoFiles(dirPath)
			if err != nil {
				return nil, err
			}
			files = append(files, rootFiles...)
			continue
		}
		var dirFiles []string
		if err := walkGoFiles(dirPath, func(path string) error {
			dirFiles = append(dirFiles, path)
			return nil
		}); err != nil {
			return nil, err
		}
		files = append(files, dirFiles...)
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
			method := httpMethodName(fset, compositeKeyValue(lit, "Method"))
			if method == "" {
				method = "GET"
			}
			key := name + " " + method + " " + routePath
			if seen[key] {
				return true
			}
			seen[key] = true
			pages = append(pages, PageRoute{
				Name: name, Method: method, Path: routePath,
				Access: exprString(fset, compositeKeyValue(lit, "Access")),
				Source: rel,
			})
			return true
		})
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("未找到可扫描的页面 UIRoute 定义（已扫描：%s）；"+
			"若 214/215 把页面契约迁移到其他公共包，请更新 scripts/internal/apidoc/sources.go "+
			"的 pageScanDirs 后重试", strings.Join(pageScanDirs, "、"))
	}
	sort.Slice(pages, func(i, j int) bool {
		if pages[i].Name != pages[j].Name {
			return pages[i].Name < pages[j].Name
		}
		return pages[i].Path < pages[j].Path
	})
	return pages, nil
}
