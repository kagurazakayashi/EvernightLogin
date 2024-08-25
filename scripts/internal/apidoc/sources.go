// Package apidoc 生成人类与 AI 共用的接口参考（docs/reference/）。
//
// 它是 scripts/reference CLI 与 scripts/verify-docs 共享的纯本地生成库：
//   - 数据源优先使用代码导出的注册表（错误码来自 errs 包、权限目录来自
//     internal/preset、配置字段来自 config 包），避免手写第二份事实来源；
//   - HTTP 路由、页面命名路由、协议路径、CLI 命令树与公开 Go API 通过 go/parser
//     只读扫描源码得到（不导入内部实现、不启动服务、不读数据库）；
//   - 输出为确定性的 JSON 与 Markdown：全部排序、LF 行尾、无时间戳，可重复生成；
//   - 能力声明与机器可读能力映射读自 scripts/capabilities/catalog.json，并只读
//     交叉核对 docs/acceptance/capability-matrix.json 的盘点数量。
//
// 生成物只允许由 scripts/reference -write 写入；-check 与 verify-docs 逐字节比较，
// 防止文档与代码漂移。本包不修改产品源码，也不访问网络或数据库。
package apidoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// schemaVersion 是 docs/reference 生成物的格式版本；改变 JSON 结构时递增。
const schemaVersion = "evernight.reference/v1"

// 稳定输入路径（相对仓库根）。外部代码移动这些文件时，-check 会以可读错误失败，
// 提醒同步更新本文件（步骤 214/215 重构后需要复核）。
const (
	pathCapabilityCatalog = "scripts/capabilities/catalog.json"
	pathCapabilityMatrix  = "docs/acceptance/capability-matrix.json"
	pathPresetCatalog     = "internal/preset/catalog.go"
	pathSnippetFile       = "examples/reference-snippets/snippets.go"
)

// 源码候选路径（相对仓库根）。214/215 重构可能移动文件：按顺序取第一个存在的候选，
// 全部缺失时返回可操作错误，提示更新本文件后重试。
var (
	adminHandlerCandidates  = []string{"internal/adminapi/handler.go"}
	protocolPathCandidates  = []string{"internal/protocolapi/protocolapi.go"}
	presetCatalogCandidates = []string{"internal/preset/catalog.go"}
	// pageScanDirs 是页面命名路由定义目录：214 后页面实现位于公开包 ui/；
	// "." 保留根包兼容别名/旧结构扫描（不存在 UIRoute 字面量时会自然跳过）。
	pageScanDirs = []string{".", "ui"}
	// rootPackageDirs 是根包（包名 login）公开门面与兼容别名所在目录。
	rootPackageDirs = []string{"."}
)

// sourceDirs 是 AST 扫描的目录（相对仓库根）；子模块与 examples 不在此列。
var (
	// adminRouteDirs 登记管理 JSON API 路由的源码目录（handler 与领域路由）。
	adminRouteDirs = []string{"internal/adminapi", "internal/serverapp"}
	// cmdRootDir 登记三个命令行程序的源码目录。
	cmdRootDir = "cmd"
	// manageCLIDir 登记 loginctl 的本地/在线管理命令组实现。
	manageCLIDir = "internal/managecli"
	// goAPIDirs 登记公开 Go API 的源码目录（215 后 app 仍为单包、按领域分文件；
	// 若未来拆子目录，walkGoFiles 会递归覆盖）。
	goAPIDirs = []string{"app"}
)

// skipDirNames 是遍历时跳过的目录名（版本库、构建产物、子模块与示例模块）。
var skipDirNames = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"data": true, "database": true, "EvernightMail": true, "go-build-all": true,
	"examples": true, "testdata": true,
}

// parseAt 解析一个 Go 文件并返回文件、文件集与错误。
func parseAt(path string) (*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 %s 失败：%w", path, err)
	}
	return file, fset, nil
}

// listGoFiles 列出一个目录下的 Go 文件（不含子目录与 _test.go），按文件名排序。
func listGoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取目录 %s 失败：%w", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

// walkGoFiles 递归遍历目录下的非测试 Go 文件；skipDirNames 中的目录整体跳过。
func walkGoFiles(dir string, fn func(path string) error) error {
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDirNames[entry.Name()] && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		return fn(path)
	})
}

// resolveFirstExisting 返回候选路径中第一个存在的普通文件（仓库相对路径）；
// 全部缺失时返回可操作错误，提示 214/215 重构后更新候选列表。
func resolveFirstExisting(root, purpose string, candidates []string) (string, error) {
	for _, rel := range candidates {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return rel, nil
		}
	}
	return "", fmt.Errorf("未找到%s源文件；已尝试 %s。若 214/215 重构移动了文件，请更新 "+
		"scripts/internal/apidoc/sources.go 的候选列表后重试", purpose, strings.Join(candidates, "、"))
}

// exprString 用 go/printer 输出表达式文本，用于签名、类型与常量默认值。
func exprString(fset *token.FileSet, expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var builder strings.Builder
	if err := printer.Fprint(&builder, fset, expr); err != nil {
		return ""
	}
	return builder.String()
}

// stringLit 取表达式的字符串字面量值；非字面量返回空串。
func stringLit(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	value := lit.Value
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return strings.Trim(value, `"`)
}

// compositeKeyValue 取结构体复合字面量中指定键的值表达式。
func compositeKeyValue(lit *ast.CompositeLit, key string) ast.Expr {
	for _, element := range lit.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, ok := keyValue.Key.(*ast.Ident); ok && ident.Name == key {
			return keyValue.Value
		}
	}
	return nil
}

// compositeTypeName 返回复合字面量的显式类型名（可能为空）。
func compositeTypeName(lit *ast.CompositeLit) string {
	switch typed := lit.Type.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	}
	return ""
}

// baseTypeName 返回类型表达式的基础类型名（处理指针/泛型参数/限定名）。
func baseTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return baseTypeName(typed.X)
	case *ast.IndexExpr:
		return baseTypeName(typed.X)
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	}
	return ""
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
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	}
	return ""
}

// httpMethodName 把 http.MethodGet / MethodGet / "GET" 统一成大写 HTTP 方法名。
func httpMethodName(fset *token.FileSet, expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	if literal := stringLit(expr); literal != "" {
		return strings.ToUpper(strings.TrimSpace(literal))
	}
	text := exprString(fset, expr)
	if index := strings.LastIndex(text, "."); index >= 0 {
		text = text[index+1:]
	}
	const prefix = "Method"
	if strings.HasPrefix(text, prefix) {
		return strings.ToUpper(strings.TrimPrefix(text, prefix))
	}
	return ""
}

// docText 把注释组整理成单段文本（去掉 // 与首尾空白，保留换行）；空注释返回空串。
func docText(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}
	var lines []string
	for _, comment := range group.List {
		text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
		if text == "" {
			continue
		}
		lines = append(lines, text)
	}
	return strings.Join(lines, "\n")
}

// firstSentence 取文档注释的第一句（到第一个句号/分号/换行为止），用于表格摘要。
func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	cut := len(text)
	for _, marker := range []string{"。", "；", "\n"} {
		if index := strings.Index(text, marker); index >= 0 && index < cut {
			cut = index
		}
	}
	sentence := strings.TrimSpace(text[:cut])
	sentence = strings.TrimSuffix(sentence, ".")
	return sentence
}

// singleLine 把多行文本压成一行（连续空白折叠为单个空格），用于表格单元格。
func singleLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// signatureText 输出函数的参数与结果签名（不含 func 关键字），如
// "(ctx context.Context, request ListUsersRequest) (ListUsersResponse, error)"。
func signatureText(fset *token.FileSet, fn *ast.FuncType) string {
	if fn == nil {
		return "()"
	}
	params := fieldListText(fset, fn.Params, true)
	params = "(" + params + ")"
	if fn.Results == nil || len(fn.Results.List) == 0 {
		return params
	}
	results := fieldListText(fset, fn.Results, false)
	if results == "" {
		return params
	}
	singleUnnamed := len(fn.Results.List) == 1 && len(fn.Results.List[0].Names) == 0
	if singleUnnamed {
		return params + " " + results
	}
	return params + " (" + results + ")"
}

// fieldListText 输出字段列表文本；withNames 时把字段名与类型一起输出（参数），
// 否则只输出类型（结果）。返回空串表示无字段。
func fieldListText(fset *token.FileSet, list *ast.FieldList, withNames bool) string {
	if list == nil {
		return ""
	}
	var parts []string
	for _, field := range list.List {
		typeText := exprString(fset, field.Type)
		if typeText == "" {
			continue
		}
		if !withNames || len(field.Names) == 0 {
			parts = append(parts, typeText)
			continue
		}
		var names []string
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
		parts = append(parts, strings.Join(names, ", ")+" "+typeText)
	}
	return strings.Join(parts, ", ")
}

// methodSignature 输出接口方法或接收者方法的签名：方法名 + 参数/结果。
func methodSignature(fset *token.FileSet, name string, fn *ast.FuncType) string {
	return name + signatureText(fset, fn)
}

// quoteJSON 生成 JSON 字符串字面量（仅用于 schema 常量拼接，避免手写转义错误）。
func quoteJSON(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + replacer.Replace(value) + `"`
}
