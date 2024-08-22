package dependencycheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/kagurazakayashi/EvernightLogin"

// leafPackages 是允许被宿主/内部共同依赖、且不得反向 import internal/根/app 的
// 公共包。lifecycle 依赖其他公共包，但同样不得引用 internal/根/app。
var leafPackages = []string{
	"config", "errs", "netpolicy", "proxytrust", "passkeypolicy", "appids",
	"httppolicy", "httpapi", "correlation", "ui", "extension", "access",
	"lifecycle", "version",
}

// rootFileRoles 是根目录非测试 .go 文件的允许角色；新增文件必须显式登记角色，
// 不走固定文件数量门槛。
var rootFileRoles = map[string]string{
	"doc.go":             "package documentation",
	"version.go":         "version facade + ldflags variables",
	"instance.go":        "Instance lifecycle implementation",
	"embed.go":           "Instance assembly/readiness/mount implementation",
	"extension.go":       "extension registry implementation",
	"access.go":          "Instance.CheckAccess implementation",
	"http.go":            "HTTP handler facade",
	"server.go":          "Server facade",
	"alias_config.go":    "config compatibility aliases",
	"alias_errs.go":      "errors compatibility aliases",
	"alias_http.go":      "httpapi compatibility aliases",
	"alias_ui.go":        "ui compatibility aliases",
	"alias_contracts.go": "extension/access/lifecycle/version compatibility aliases",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

type importRef struct {
	Path  string
	Alias string
}

func parseFile(path string) (*ast.File, error) {
	fset := token.NewFileSet()
	return parser.ParseFile(fset, path, nil, parser.ParseComments)
}

func importsOf(dir string, includeTests bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parseFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, "\"")
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func goFiles(dir string, includeTests bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(out)
	return out, nil
}

func TestPublicLeafPackagesStayLeaf(t *testing.T) {
	root := repoRoot(t)
	for _, leaf := range leafPackages {
		dir := filepath.Join(root, filepath.FromSlash(leaf))
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("公共包 %s 不存在: %v", leaf, err)
		}
		imports, err := importsOf(dir, false)
		if err != nil {
			t.Fatalf("读取 %s imports: %v", leaf, err)
		}
		for _, imported := range imports {
			if strings.Contains(imported, "/internal/") {
				t.Errorf("公共包 %s 不得 import internal: %s", leaf, imported)
			}
			if imported == modulePath || imported == modulePath+"/app" {
				t.Errorf("公共包 %s 不得 import 根包或 app: %s", leaf, imported)
			}
		}
	}
}

func TestInternalProductionDoesNotImportRoot(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "dependencycheck" {
				return nil
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, parseErr := parseFile(path)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range file.Imports {
			if strings.Trim(spec.Path.Value, "\"") == modulePath {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描 internal: %v", err)
	}
	sort.Strings(offenders)
	for _, offender := range offenders {
		t.Errorf("internal 生产文件仍 import 根包: %s", offender)
	}
}

func TestRootImportsInternalWithoutReverseRoot(t *testing.T) {
	root := repoRoot(t)
	rootImports, err := importsOf(root, false)
	if err != nil {
		t.Fatalf("读取根包 imports: %v", err)
	}
	for _, imported := range rootImports {
		if !strings.HasPrefix(imported, modulePath+"/internal/") {
			continue
		}
		rel := strings.TrimPrefix(imported, modulePath+"/")
		visited := map[string]bool{}
		var visit func(dir string) error
		visit = func(dir string) error {
			dir = filepath.Join(root, filepath.FromSlash(dir))
			if visited[dir] {
				return nil
			}
			visited[dir] = true
			imports, err := importsOf(dir, false)
			if err != nil {
				return err
			}
			for _, dependency := range imports {
				if dependency == modulePath || dependency == modulePath+"/app" {
					return &reverseImportError{from: rel, dependency: dependency}
				}
				if strings.HasPrefix(dependency, modulePath+"/internal/") {
					child := strings.TrimPrefix(dependency, modulePath+"/")
					if err := visit(child); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := visit(rel); err != nil {
			if reverseErr, ok := err.(*reverseImportError); ok {
				t.Errorf("根包 import 的 %s 反向依赖 %s（循环风险）", reverseErr.from, reverseErr.dependency)
				continue
			}
			t.Fatalf("扫描 %s 依赖: %v", rel, err)
		}
	}
}

type reverseImportError struct{ from, dependency string }

func (e *reverseImportError) Error() string { return e.from + " -> " + e.dependency }

func TestRootDirectoryAllowlist(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("读取根目录: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		if _, ok := rootFileRoles[entry.Name()]; !ok {
			t.Errorf("根目录新增非测试文件 %s 未登记角色（仅允许 §3.2 清单）", entry.Name())
		}
	}
	for name := range rootFileRoles {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("根目录缺少允许清单必需文件 %s", name)
		}
	}
}

func TestModuleImportGraphAcyclic(t *testing.T) {
	root := repoRoot(t)
	graph := map[string][]string{}
	visited := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (name == ".git" || name == ".ai" || name == ".tmp" ||
				name == "dist" || name == "data" || name == "examples" ||
				name == "scripts" || name == "docs" || name == "web" ||
				name == "EvernightMail" || name == "go-build-all" || name == "tools") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		if visited[dir] {
			return nil
		}
		visited[dir] = true
		rel, relErr := filepath.Rel(root, dir)
		if relErr != nil {
			return relErr
		}
		pkg := modulePath
		if rel != "." {
			pkg = modulePath + "/" + filepath.ToSlash(rel)
		}
		imports, importErr := importsOf(dir, false)
		if importErr != nil {
			return importErr
		}
		for _, dependency := range imports {
			if dependency == modulePath || strings.HasPrefix(dependency, modulePath+"/internal/") ||
				strings.HasPrefix(dependency, modulePath+"/ui") {
				graph[pkg] = append(graph[pkg], dependency)
			}
		}
		sort.Strings(graph[pkg])
		return nil
	})
	if err != nil {
		t.Fatalf("构建 import 图: %v", err)
	}
	state := map[string]int{} // 0 未访问, 1 访问中, 2 完成
	var stack []string
	var visit func(pkg string) bool
	visit = func(pkg string) bool {
		switch state[pkg] {
		case 1:
			t.Errorf("检测到 import 环: %s", strings.Join(append(stack, pkg), " -> "))
			return false
		case 2:
			return true
		}
		state[pkg] = 1
		stack = append(stack, pkg)
		for _, dependency := range graph[pkg] {
			if !visit(dependency) {
				return false
			}
		}
		stack = stack[:len(stack)-1]
		state[pkg] = 2
		return true
	}
	for pkg := range graph {
		if !visit(pkg) {
			return
		}
	}
}

func TestNoPublicInternalSignatures(t *testing.T) {
	root := repoRoot(t)
	// 根包与 app 是外部宿主主要公开面；对导出声明的类型表达式检查 internal alias。
	dirs := []string{root, filepath.Join(root, "app")}
	for _, dir := range dirs {
		files, err := goFiles(dir, false)
		if err != nil {
			t.Fatalf("读取 %s: %v", dir, err)
		}
		for _, path := range files {
			file, err := parseFile(path)
			if err != nil {
				t.Fatalf("解析 %s: %v", path, err)
			}
			internalAliases := map[string]bool{}
			for _, spec := range file.Imports {
				imported := strings.Trim(spec.Path.Value, "\"")
				if !strings.Contains(imported, "/internal/") {
					continue
				}
				alias := ""
				if spec.Name != nil {
					alias = spec.Name.Name
				} else {
					alias = filepath.Base(imported)
				}
				internalAliases[alias] = true
			}
			if len(internalAliases) == 0 {
				continue
			}
			checkDecl := func(decl ast.Decl) {
				switch typed := decl.(type) {
				case *ast.FuncDecl:
					if !typed.Name.IsExported() {
						return
					}
					// receiver 未导出的方法不属于公开表面。
					if typed.Recv != nil && len(typed.Recv.List) > 0 {
						receiver := typed.Recv.List[0].Type
						if star, ok := receiver.(*ast.StarExpr); ok {
							receiver = star.X
						}
						if ident, ok := receiver.(*ast.Ident); !ok || !ident.IsExported() {
							return
						}
					}
					checkFieldList(t, typeSelectors(typed.Type.Params, internalAliases), path, typed.Name.Name)
					checkFieldList(t, typeSelectors(typed.Type.Results, internalAliases), path, typed.Name.Name)
				case *ast.GenDecl:
					for _, spec := range typed.Specs {
						switch s := spec.(type) {
						case *ast.TypeSpec:
							if !s.Name.IsExported() {
								continue
							}
							if structType, ok := s.Type.(*ast.StructType); ok {
								for _, field := range structType.Fields.List {
									for _, name := range field.Names {
										if name.IsExported() {
											checkExpr(t, field.Type, internalAliases, path, name.Name)
										}
									}
									if len(field.Names) == 0 {
										checkExpr(t, field.Type, internalAliases, path, s.Name.Name)
									}
								}
								continue
							}
							checkExpr(t, s.Type, internalAliases, path, s.Name.Name)
						case *ast.ValueSpec:
							for _, name := range s.Names {
								if name.IsExported() && s.Type != nil {
									checkExpr(t, s.Type, internalAliases, path, name.Name)
								}
							}
						}
					}
				}
			}
			for _, decl := range file.Decls {
				checkDecl(decl)
			}
		}
	}
}

func typeSelectors(list *ast.FieldList, aliases map[string]bool) []string {
	if list == nil {
		return nil
	}
	var out []string
	for _, field := range list.List {
		collectSelectors(field.Type, aliases, &out)
	}
	return out
}

func collectSelectors(expr ast.Expr, aliases map[string]bool, out *[]string) {
	ast.Inspect(expr, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := selector.X.(*ast.Ident); ok && aliases[ident.Name] {
			*out = append(*out, ident.Name+"."+selector.Sel.Name)
		}
		return true
	})
}

func checkFieldList(t *testing.T, selectors []string, path, name string) {
	t.Helper()
	if len(selectors) > 0 {
		t.Errorf("%s: 公开符号 %s 的签名引用 internal 类型: %s", path, name,
			strings.Join(selectors, ", "))
	}
}

func checkExpr(t *testing.T, expr ast.Expr, aliases map[string]bool, path, name string) {
	t.Helper()
	var selectors []string
	collectSelectors(expr, aliases, &selectors)
	if len(selectors) > 0 {
		t.Errorf("%s: 公开类型/值 %s 引用 internal 类型: %s", path, name,
			strings.Join(selectors, ", "))
	}
}

func TestExternalExamplesDoNotImportInternal(t *testing.T) {
	root := repoRoot(t)
	examplesRoot := filepath.Join(root, "examples")
	entries, err := os.ReadDir(examplesRoot)
	if err != nil {
		t.Fatalf("读取 examples: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		moduleFile := filepath.Join(examplesRoot, entry.Name(), "go.mod")
		if _, err := os.Stat(moduleFile); err != nil {
			continue
		}
		_ = filepath.WalkDir(filepath.Join(examplesRoot, entry.Name()), func(path string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && e.Name() == "vendor" {
				return filepath.SkipDir
			}
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				return nil
			}
			file, parseErr := parseFile(path)
			if parseErr != nil {
				t.Errorf("解析示例 %s: %v", path, parseErr)
				return nil
			}
			for _, spec := range file.Imports {
				if strings.Contains(strings.Trim(spec.Path.Value, "\""), modulePath+"/internal/") {
					t.Errorf("外部示例 %s 直接 import Login internal", path)
				}
			}
			return nil
		})
	}
}

func TestSubmodulesDoNotImportParentInternal(t *testing.T) {
	root := repoRoot(t)
	for _, submodule := range []string{"EvernightMail", "go-build-all"} {
		dir := filepath.Join(root, submodule)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == ".git" || entry.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			file, parseErr := parseFile(path)
			if parseErr != nil {
				return parseErr
			}
			for _, spec := range file.Imports {
				imported := strings.Trim(spec.Path.Value, "\"")
				if imported == modulePath || strings.HasPrefix(imported, modulePath+"/internal/") {
					t.Errorf("子模块 %s 依赖父模块 %s", path, imported)
				}
			}
			return nil
		})
	}
}
