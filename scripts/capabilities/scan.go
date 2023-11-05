// 本文件实现能力清单扫描器的源码盘点部分：只读解析仓库中的 Go 源码与模板，
// 提取"生产装配真实存在"的能力面（公开 Go 接口、管理 API 路由、协议端点、
// 页面命名路由、CLI 子命令、内置权限目录、分页证据与测试函数），供验证器
// 与能力声明交叉核对。
//
// 设计约束：
//   - 只读：不写仓库、不启动服务、不执行测试、不访问网络；
//   - 不猜测：盘点到的是源码中的静态事实（AST/常量/路由注册字面量），不是文档声称；
//   - 可复跑：同一份源码与能力声明必须得到相同结果（生成时间/提交号除外）。
package main

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// excludedDirs 是与产品能力清单无关的目录：开发协作资料、构建产物、文档、
// 数据库迁移、脚本自身与测试工具。能力清单只盘点可被宿主/协议/CLI 使用的
// 生产装配面。
var excludedDirs = map[string]bool{
	".git": true, ".github": true, ".ai": true, "dist": true, "data": true,
	"docs": true, "web": true, "migrations": true, "scripts": true, "tools": true,
}

// nestedModuleDirs 是根模块之外的嵌套 Go Module（子模块/独立示例），盘点时
// 跳过整棵子树，避免把别的模块的公开面算进本项目。
var nestedModuleDirs = map[string]bool{
	"EvernightMail": true, "go-build-all": true, "examples": true,
}

// routeEntry 是一条管理 JSON API 路由（相对管理 API 基础路径）。
type routeEntry struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
}

// bindPath 返回 "METHOD pattern" 形式，便于声明交叉核对与覆盖统计。
func (r routeEntry) bindPath() string { return r.Method + " " + r.Pattern }

// protocolPath 是 internal/protocolapi 导出的端点点位常量。
type protocolPath struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// permissionDef 是内置权限目录条目：机器标识与"是否已实现"标记（来自
// internal/preset/catalog.go 的 PermissionDefinition.Implemented，不是文档声称）。
type permissionDef struct {
	Key         string `json:"key"`
	Implemented bool   `json:"implemented"`
}

// protocolEndpoint 是协议包文档表中声明的 HTTP 端点（方法+路径）。
type protocolEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// pageRoute 是根包冻结的 UIRoute 命名路由。
type pageRoute struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Path   string `json:"path"`
	File   string `json:"file"`
	Access string `json:"access,omitempty"`
}

// cliCommand 是一个命令行子命令（按程序名分组）。
type cliCommand struct {
	Binary string `json:"binary"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// appSymbol 是 app 包的一个导出类型及其导出字段/方法。
type appSymbol struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Fields  []string `json:"fields,omitempty"`
	Methods []string `json:"methods,omitempty"`
	// FieldTypes 记录导出字段的类型文本（如 AdminPage、[]AdminUser、bool），供
	// 分页审计判断请求边界/结果继续字段与可增长列表，不做类型推断。
	FieldTypes map[string]string `json:"field_types,omitempty"`
}

// inventory 是一次源码盘点的结果。
type inventory struct {
	AppTypes        map[string]*appSymbol
	AppFuncs        []string
	AppVars         []string
	RootTypes       []string
	RootFuncs       []string
	AdminRoutes     []routeEntry
	ProtocolPaths   []protocolPath
	ProtocolEnds    []protocolEndpoint
	Pages           []pageRoute
	CLI             []cliCommand
	Permissions     []permissionDef
	Roles           []string
	Groups          []string
	TestsByPackage  map[string][]string
	FilesScanned    int
	PackagesScanned int
}

var (
	protocolEndpointLine = regexp.MustCompile(`^\s*//\s+(GET|POST|PUT|DELETE)\s+(/\S+)\s*(.*)$`)
	methodConstNames     = map[string]string{
		"MethodGet": "GET", "MethodPost": "POST", "MethodPut": "PUT",
		"MethodDelete": "DELETE", "MethodPatch": "PATCH", "MethodHead": "HEAD",
	}
)

// scanRepo 只读盘点仓库源码。返回盘点结果与（非致命的）警告。
func scanRepo(root string) (*inventory, []string, error) {
	inv := &inventory{
		AppTypes:       map[string]*appSymbol{},
		TestsByPackage: map[string][]string{},
	}
	var warnings []string
	if err := scanRootPackage(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanAppPackage(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanAdminRoutes(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanProtocol(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanPages(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanCLI(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanPermissions(root, inv); err != nil {
		return nil, nil, err
	}
	if err := scanTests(root, inv); err != nil {
		return nil, nil, err
	}
	sort.Slice(inv.AdminRoutes, func(i, j int) bool {
		return inv.AdminRoutes[i].bindPath() < inv.AdminRoutes[j].bindPath()
	})
	sort.Slice(inv.ProtocolPaths, func(i, j int) bool {
		return inv.ProtocolPaths[i].Name < inv.ProtocolPaths[j].Name
	})
	sort.Slice(inv.Pages, func(i, j int) bool {
		if inv.Pages[i].Name != inv.Pages[j].Name {
			return inv.Pages[i].Name < inv.Pages[j].Name
		}
		return inv.Pages[i].Path < inv.Pages[j].Path
	})
	sort.Slice(inv.CLI, func(i, j int) bool {
		if inv.CLI[i].Binary != inv.CLI[j].Binary {
			return inv.CLI[i].Binary < inv.CLI[j].Binary
		}
		return inv.CLI[i].Name < inv.CLI[j].Name
	})
	if len(inv.Pages) == 0 {
		warnings = append(warnings, "未盘点页面命名路由（UIRoute 字面量为空？）")
	}
	if len(inv.AdminRoutes) == 0 {
		warnings = append(warnings, "未盘点管理 API 路由（add(...) 注册为空？）")
	}
	return inv, warnings, nil
}

// shouldSkipDir 判断目录是否整棵跳过。
func shouldSkipDir(root, path string, isRoot bool) bool {
	name := filepath.Base(path)
	if excludedDirs[name] || nestedModuleDirs[name] {
		return true
	}
	if !isRoot {
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			return true
		}
	}
	return false
}

// walkGoFiles 遍历 root 下的 Go 源文件（跳过无关目录与嵌套 Module）。
// fn 收到相对 root 的斜杠路径与绝对路径。
func walkGoFiles(root string, fn func(rel, path string)) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == root {
				return nil
			}
			if shouldSkipDir(root, path, false) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		fn(filepath.ToSlash(rel), path)
		return nil
	})
}

// parseFile 解析单个 Go 文件；语法错误时返回错误（盘点必须基于真实可编译源码）。
func parseFile(fset *token.FileSet, path string) (*ast.File, error) {
	return parser.ParseFile(fset, path, nil, parser.SkipObjectResolution|parser.ParseComments)
}

// exprText 把 AST 表达式还原为源码文本（用于比对 "args[0]"、http.MethodGet 等）。
func exprText(fset *token.FileSet, expr ast.Expr) string {
	var builder strings.Builder
	if err := printer.Fprint(&builder, fset, expr); err != nil {
		return ""
	}
	return builder.String()
}

// httpMethod 从 http.MethodX 选择器或字符串字面量提取 HTTP 方法；未知返回 ""。
func httpMethod(fset *token.FileSet, expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.SelectorExpr:
		if name, ok := methodConstNames[typed.Sel.Name]; ok {
			return name
		}
	case *ast.BasicLit:
		if typed.Kind == token.STRING {
			return strings.Trim(strings.ToUpper(typed.Value), `"`)
		}
	}
	return ""
}

// stringLit 返回字符串字面量内容；不是字符串字面量时返回 ""。
func stringLit(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return strings.Trim(lit.Value, "`\"")
	}
	return ""
}

// compositeKeyValue 读取复合字面量中指定字段（Key-Value 形式）的表达式。
func compositeKeyValue(lit *ast.CompositeLit, key string) ast.Expr {
	for _, element := range lit.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == key {
			return kv.Value
		}
	}
	return nil
}

// forEachFileInDirs 对多个目录下的 Go 文件（含子目录）执行回调。
func forEachFileInDirs(fset *token.FileSet, dirs []string, fn func(rel string, file *ast.File)) error {
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			file, err := parseFile(fset, path)
			if err != nil {
				return err
			}
			fn(filepath.ToSlash(path), file)
		}
	}
	return nil
}

// listGoFiles 列出目录下（不递归）的 .go 文件路径。
func listGoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	return files, nil
}

// scanRootPackage 盘点根包（package login）的公开类型与函数名。
func scanRootPackage(root string, inv *inventory) error {
	files, err := listGoFiles(root)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	typeSeen := map[string]bool{}
	funcSeen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parseFile(fset, path)
		if err != nil {
			return err
		}
		inv.FilesScanned++
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				if typed.Tok != token.TYPE {
					continue
				}
				for _, spec := range typed.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok || !typeSpec.Name.IsExported() || typeSeen[typeSpec.Name.Name] {
						continue
					}
					typeSeen[typeSpec.Name.Name] = true
					inv.RootTypes = append(inv.RootTypes, typeSpec.Name.Name)
				}
			case *ast.FuncDecl:
				if typed.Recv != nil || !typed.Name.IsExported() || funcSeen[typed.Name.Name] {
					continue
				}
				funcSeen[typed.Name.Name] = true
				inv.RootFuncs = append(inv.RootFuncs, typed.Name.Name)
			}
		}
	}
	sort.Strings(inv.RootTypes)
	sort.Strings(inv.RootFuncs)
	return nil
}

// scanAppPackage 盘点 app 包的公开类型（含接口方法、结构字段）与导出函数。
func scanAppPackage(root string, inv *inventory) error {
	dir := filepath.Join(root, "app")
	files, err := listGoFiles(dir)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	funcSeen := map[string]bool{}
	varSeen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parseFile(fset, path)
		if err != nil {
			return err
		}
		inv.FilesScanned++
		inv.PackagesScanned++
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				if typed.Tok == token.VAR {
					for _, spec := range typed.Specs {
						valueSpec, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for _, name := range valueSpec.Names {
							if name.IsExported() && !varSeen[name.Name] {
								varSeen[name.Name] = true
								inv.AppVars = append(inv.AppVars, name.Name)
							}
						}
					}
					continue
				}
				if typed.Tok != token.TYPE {
					continue
				}
				for _, spec := range typed.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok || !typeSpec.Name.IsExported() {
						continue
					}
					symbol := inv.AppTypes[typeSpec.Name.Name]
					if symbol == nil {
						symbol = &appSymbol{Name: typeSpec.Name.Name}
						inv.AppTypes[typeSpec.Name.Name] = symbol
					}
					switch underlying := typeSpec.Type.(type) {
					case *ast.StructType:
						if symbol.Kind != "interface" {
							symbol.Kind = "struct"
						}
						if symbol.FieldTypes == nil {
							symbol.FieldTypes = map[string]string{}
						}
						for _, field := range underlying.Fields.List {
							fieldType := exprText(fset, field.Type)
							for _, name := range field.Names {
								if name.IsExported() {
									symbol.Fields = append(symbol.Fields, name.Name)
									symbol.FieldTypes[name.Name] = fieldType
								}
							}
						}
					case *ast.InterfaceType:
						symbol.Kind = "interface"
						for _, field := range underlying.Methods.List {
							for _, name := range field.Names {
								if name.IsExported() {
									symbol.Methods = append(symbol.Methods, name.Name)
								}
							}
						}
					default:
						if symbol.Kind == "" {
							symbol.Kind = "alias"
						}
					}
				}
			case *ast.FuncDecl:
				if typed.Name.IsExported() && !funcSeen[typed.Name.Name] {
					funcSeen[typed.Name.Name] = true
					inv.AppFuncs = append(inv.AppFuncs, typed.Name.Name)
				}
				// 导出接收者上的导出方法也是公开 Go 接口（如 Runtime.Admin）。
				if typed.Recv == nil || !typed.Name.IsExported() {
					continue
				}
				receiver := receiverTypeName(typed.Recv)
				if receiver == "" || !ast.IsExported(receiver) {
					continue
				}
				symbol := inv.AppTypes[receiver]
				if symbol == nil {
					symbol = &appSymbol{Name: receiver, Kind: "receiver"}
					inv.AppTypes[receiver] = symbol
				}
				symbol.Methods = append(symbol.Methods, typed.Name.Name)
			}
		}
	}
	for _, symbol := range inv.AppTypes {
		sort.Strings(symbol.Fields)
		sort.Strings(symbol.Methods)
	}
	sort.Strings(inv.AppFuncs)
	sort.Strings(inv.AppVars)
	return nil
}

// receiverTypeName 提取方法接收者的类型名（去掉指针与泛型参数）。
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok {
		expr = index.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	if selector, ok := expr.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}
	return ""
}

// scanAdminRoutes 盘点管理 JSON API 固定路由：handler.go 中 add(method, pattern, ...)
// 调用，以及领域路由（DomainRoute{Method, Pattern}）字面量。
func scanAdminRoutes(root string, inv *inventory) error {
	fset := token.NewFileSet()
	handlerPath := filepath.Join(root, "internal", "adminapi", "handler.go")
	file, err := parseFile(fset, handlerPath)
	if err != nil {
		return err
	}
	inv.FilesScanned++
	seen := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "add" || len(call.Args) < 2 {
			return true
		}
		method := httpMethod(fset, call.Args[0])
		pattern := stringLit(call.Args[1])
		if method == "" || pattern == "" {
			return true
		}
		entry := routeEntry{Method: method, Pattern: pattern, Source: "internal/adminapi/handler.go"}
		if !seen[entry.bindPath()] {
			seen[entry.bindPath()] = true
			inv.AdminRoutes = append(inv.AdminRoutes, entry)
		}
		return true
	})
	// 领域路由注册：serverapp 中既使用局部闭包 add(method, pattern, ...) 注册，
	// 也存在 adminapi.DomainRoute{Method, Pattern} 复合字面量。
	domainDirs := []string{
		filepath.Join(root, "internal", "serverapp"),
		filepath.Join(root, "internal", "adminapi"),
	}
	addRoute := func(method, pattern, source string) {
		if method == "" || pattern == "" {
			return
		}
		entry := routeEntry{Method: method, Pattern: pattern, Source: source}
		if !seen[entry.bindPath()] {
			seen[entry.bindPath()] = true
			inv.AdminRoutes = append(inv.AdminRoutes, entry)
		}
	}
	for _, dir := range domainDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			domainFile, err := parseFile(fset, path)
			if err != nil {
				return err
			}
			inv.FilesScanned++
			rel := "internal/" + filepath.Base(dir) + "/" + entry.Name()
			ast.Inspect(domainFile, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CallExpr:
					// 局部注册闭包 add(http.MethodGet, "users", ...)：前两个参数
					// 固定是方法与路由模式；其他同名函数调用不会同时满足两者。
					ident, ok := typed.Fun.(*ast.Ident)
					if !ok || ident.Name != "add" || len(typed.Args) < 2 {
						return true
					}
					addRoute(httpMethod(fset, typed.Args[0]), stringLit(typed.Args[1]), rel)
				case *ast.CompositeLit:
					typeName := compositeTypeName(typed)
					if typeName != "DomainRoute" && typeName != "domainRoute" && typeName != "" {
						return true
					}
					methodExpr := compositeKeyValue(typed, "Method")
					patternExpr := compositeKeyValue(typed, "Pattern")
					if methodExpr == nil || patternExpr == nil {
						return true
					}
					addRoute(httpMethod(fset, methodExpr), stringLit(patternExpr), rel)
				}
				return true
			})
		}
	}
	return nil
}

// compositeTypeName 返回复合字面量显式类型名（可能为空）。
func compositeTypeName(lit *ast.CompositeLit) string {
	switch typed := lit.Type.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	}
	return ""
}

// scanProtocol 盘点协议端点：导出的 Path* 常量与包文档端点表。
func scanProtocol(root string, inv *inventory) error {
	fset := token.NewFileSet()
	pathFile := filepath.Join(root, "internal", "protocolapi", "protocolapi.go")
	file, err := parseFile(fset, pathFile)
	if err != nil {
		return err
	}
	inv.FilesScanned++
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
				if index >= len(valueSpec.Values) || !strings.HasPrefix(name.Name, "Path") {
					continue
				}
				value := stringLit(valueSpec.Values[index])
				if value == "" {
					continue
				}
				inv.ProtocolPaths = append(inv.ProtocolPaths, protocolPath{Name: name.Name, Path: value})
			}
		}
	}
	docPath := filepath.Join(root, "internal", "protocolapi", "doc.go")
	docFile, err := parseFile(fset, docPath)
	if err != nil {
		return err
	}
	inv.FilesScanned++
	// 端点表在包文档注释中（protocolapi.go 顶部为主，doc.go 也可能重复声明）。
	collectProtocolEndpoints(file, inv)
	if docFile.Doc != nil {
		collectProtocolEndpoints(docFile, inv)
	}
	return nil
}

// collectProtocolEndpoints 从文件包文档注释的端点表提取 "METHOD /path" 行。
func collectProtocolEndpoints(file *ast.File, inv *inventory) {
	if file.Doc == nil {
		return
	}
	seen := map[string]bool{}
	for _, existing := range inv.ProtocolEnds {
		seen[existing.Method+" "+existing.Path] = true
	}
	for _, comment := range file.Doc.List {
		match := protocolEndpointLine.FindStringSubmatch(comment.Text)
		if match == nil {
			continue
		}
		key := match[1] + " " + match[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		inv.ProtocolEnds = append(inv.ProtocolEnds, protocolEndpoint{Method: match[1], Path: match[2]})
	}
}

// scanPages 盘点根包冻结的页面命名路由（UIRoute 复合字面量）。
func scanPages(root string, inv *inventory) error {
	files, err := listGoFiles(root)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parseFile(fset, path)
		if err != nil {
			return err
		}
		inv.FilesScanned++
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
				// 省略类型的 UIRoute 元素：必须同时具备 Name 与 Path 字段。
				if compositeKeyValue(lit, "Name") == nil || compositeKeyValue(lit, "Path") == nil {
					return true
				}
			}
			name := stringLit(compositeKeyValue(lit, "Name"))
			routePath := stringLit(compositeKeyValue(lit, "Path"))
			if name == "" || routePath == "" {
				return true
			}
			method := httpMethod(fset, compositeKeyValue(lit, "Method"))
			if method == "" {
				method = "GET"
			}
			inv.Pages = append(inv.Pages, pageRoute{
				Name: name, Method: method, Path: routePath,
				File: filepath.Base(path),
			})
			return true
		})
	}
	return nil
}

// scanCLI 盘点命令行子命令：
//   - cmd/* 中 cobra 的 Use: 字面量与顶层 switch args[0] 的 case 字面量；
//   - internal/managecli 中 args[0] 分组的子命令（归属 loginctl）。
func scanCLI(root string, inv *inventory) error {
	cmdRoot := filepath.Join(root, "cmd")
	binaries, err := os.ReadDir(cmdRoot)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	add := func(binary, name, source string) {
		name = strings.TrimSpace(strings.Fields(name)[0])
		if name == "" {
			return
		}
		// 过滤内置约定（-h/--help/--version、help、version）与程序自身名：
		// 它们是 CLI 框架行为，不是产品能力；其余子命令全部保留并要求被能力声明覆盖。
		if strings.HasPrefix(name, "-") || name == "help" || name == "version" ||
			name == binary {
			return
		}
		key := binary + ":" + name
		if seen[key] {
			return
		}
		seen[key] = true
		inv.CLI = append(inv.CLI, cliCommand{Binary: binary, Name: name, Source: source})
	}
	for _, binary := range binaries {
		if !binary.IsDir() {
			continue
		}
		dir := filepath.Join(cmdRoot, binary.Name())
		files, err := listGoFiles(dir)
		if err != nil {
			return err
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			file, err := parseFile(fset, path)
			if err != nil {
				return err
			}
			inv.FilesScanned++
			rel := "cmd/" + binary.Name() + "/" + filepath.Base(path)
			ast.Inspect(file, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CompositeLit:
					if useExpr := compositeKeyValue(typed, "Use"); useExpr != nil {
						if use := stringLit(useExpr); use != "" {
							add(binary.Name(), use, rel)
						}
					}
				case *ast.SwitchStmt:
					if exprText(fset, typed.Tag) != "args[0]" {
						return true
					}
					for _, stmt := range typed.Body.List {
						clause, ok := stmt.(*ast.CaseClause)
						if !ok {
							continue
						}
						for _, expr := range clause.List {
							if value := stringLit(expr); value != "" {
								add(binary.Name(), value, rel)
							}
						}
					}
				}
				return true
			})
		}
	}
	// 在线/本地管理命令组由 internal/managecli 统一实现，入口为 loginctl。
	manageDir := filepath.Join(root, "internal", "managecli")
	manageFiles, err := listGoFiles(manageDir)
	if err != nil {
		return err
	}
	for _, path := range manageFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parseFile(fset, path)
		if err != nil {
			return err
		}
		inv.FilesScanned++
		rel := "internal/managecli/" + filepath.Base(path)
		ast.Inspect(file, func(node ast.Node) bool {
			switchStmt, ok := node.(*ast.SwitchStmt)
			if !ok || exprText(fset, switchStmt.Tag) != "args[0]" {
				return true
			}
			for _, stmt := range switchStmt.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					if value := stringLit(expr); value != "" {
						add("loginctl", value, rel)
					}
				}
			}
			return true
		})
	}
	return nil
}

// scanPermissions 盘点内置预设目录（internal/preset/catalog.go）：
//   - PermissionDefinition{Key, Implemented}：权限键 + 代码中登记的"是否已实现"标记；
//   - RoleTemplate{Key}：预设角色；
//   - GroupTemplate{Key}：预设用户组。
//
// 只按显式元素类型（[]PermissionDefinition 等）归类，不做点号猜测。
func scanPermissions(root string, inv *inventory) error {
	path := filepath.Join(root, "internal", "preset", "catalog.go")
	fset := token.NewFileSet()
	file, err := parseFile(fset, path)
	if err != nil {
		return err
	}
	inv.FilesScanned++
	permissionSeen := map[string]bool{}
	roleSeen := map[string]bool{}
	groupSeen := map[string]bool{}
	var walk func(expr ast.Expr, elemType string)
	walk = func(expr ast.Expr, elemType string) {
		switch typed := expr.(type) {
		case *ast.CompositeLit:
			typeName := compositeTypeName(typed)
			current := elemType
			if typeName != "" {
				current = typeName
			}
			switch current {
			case "PermissionDefinition":
				key := stringLit(compositeKeyValue(typed, "Key"))
				if key != "" && !permissionSeen[key] {
					permissionSeen[key] = true
					inv.Permissions = append(inv.Permissions, permissionDef{
						Key:         key,
						Implemented: boolLit(compositeKeyValue(typed, "Implemented")),
					})
				}
			case "RoleTemplate":
				if key := stringLit(compositeKeyValue(typed, "Key")); key != "" && !roleSeen[key] {
					roleSeen[key] = true
					inv.Roles = append(inv.Roles, key)
				}
			case "GroupTemplate":
				if key := stringLit(compositeKeyValue(typed, "Key")); key != "" && !groupSeen[key] {
					groupSeen[key] = true
					inv.Groups = append(inv.Groups, key)
				}
			}
			// 复合字面量元素：显式类型为 []T 时元素类型是 T。
			childType := ""
			if array, ok := typed.Type.(*ast.ArrayType); ok {
				childType = baseTypeName(array.Elt)
			}
			for _, element := range typed.Elts {
				if kv, ok := element.(*ast.KeyValueExpr); ok {
					walk(kv.Value, "")
					continue
				}
				walk(element, childType)
			}
		}
	}
	// 从函数体与变量声明出发，按显式类型遍历复合字面量。
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if lit.Type == nil {
			return true
		}
		if _, isArray := lit.Type.(*ast.ArrayType); isArray {
			walk(lit, "")
			return false
		}
		return true
	})
	sort.Slice(inv.Permissions, func(i, j int) bool {
		return inv.Permissions[i].Key < inv.Permissions[j].Key
	})
	sort.Strings(inv.Roles)
	sort.Strings(inv.Groups)
	return nil
}

// boolLit 返回 true/false 标识符字面量的布尔值。
func boolLit(expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok && ident.Name == "true" {
		return true
	}
	return false
}

// baseTypeName 返回类型表达式的末段名称（[]T → T，pkg.T → T）。
func baseTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.StarExpr:
		return baseTypeName(typed.X)
	case *ast.ArrayType:
		return baseTypeName(typed.Elt)
	}
	return ""
}

// scanTests 盘点测试函数，按模块相对包路径分组（"."、"./app"、"./internal/x"）。
func scanTests(root string, inv *inventory) error {
	fset := token.NewFileSet()
	return walkGoFiles(root, func(rel, path string) {
		if !strings.HasSuffix(path, "_test.go") {
			return
		}
		file, err := parseFile(fset, path)
		if err != nil {
			return
		}
		inv.FilesScanned++
		packagePath := packagePathForFile(rel)
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Recv != nil {
				continue
			}
			name := funcDecl.Name.Name
			if !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Benchmark") &&
				!strings.HasPrefix(name, "Fuzz") && !strings.HasPrefix(name, "Example") {
				continue
			}
			inv.TestsByPackage[packagePath] = append(inv.TestsByPackage[packagePath], name)
		}
	})
}

// packagePathForFile 把相对路径映射为 go test 包路径（"." 表示根包）。
func packagePathForFile(rel string) string {
	dir := filepath.ToSlash(filepath.Dir(rel))
	if dir == "." || dir == "" {
		return "."
	}
	return "./" + dir
}
