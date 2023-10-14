package login_test

// 步骤 212 依赖策略检查（可复跑）：
//   - 公共叶子包（config/errs/netpolicy/proxytrust/passkeypolicy/appids/httppolicy）
//     不得 import 本模块的 internal 包、app 子包或模块根包（叶子必须自洽，否则
//     根包门面稍后 import 内部实现包时会形成循环依赖）；
//   - 根包当前 import 的每个 internal 包不得反向 import 根包（防止迁移期引入环）；
//   - 已完成迁移的根目录实现文件不得回流（config*.go/error*.go 只允许别名桥）。
//
// 该测试不调用 go 命令、不依赖编译缓存，可独立复跑；步骤 213/214/215 继续扩展
// 叶子清单与根目录允许清单。

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const policyModulePath = "github.com/kagurazakayashi/EvernightLogin"

// policyLeafPackages 是已迁出的公共叶子包目录（相对仓库根）。
var policyLeafPackages = []string{
	"config", "errs", "netpolicy", "proxytrust", "passkeypolicy", "appids", "httppolicy",
	"httpapi", "correlation",
}

// policyParseImports 解析 dir 下非测试 Go 文件的 import 路径。
func policyParseImports(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录 %s 失败: %v", dir, err)
	}
	fset := token.NewFileSet()
	var imports []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", entry.Name(), err)
		}
		for _, spec := range file.Imports {
			imports = append(imports, strings.Trim(spec.Path.Value, `"`))
		}
	}
	return imports
}

// TestPublicLeafPackagesStayLeaf 断言公共叶子包不依赖 internal/app 或根包门面。
func TestPublicLeafPackagesStayLeaf(t *testing.T) {
	for _, leaf := range policyLeafPackages {
		if _, err := os.Stat(leaf); err != nil {
			t.Fatalf("叶子包目录 %s 不存在: %v", leaf, err)
		}
		for _, imported := range policyParseImports(t, leaf) {
			if strings.Contains(imported, "/internal/") {
				t.Errorf("公共叶子包 %s 不得 import internal 包：%s", leaf, imported)
			}
			if imported == policyModulePath {
				t.Errorf("公共叶子包 %s 不得 import 根包门面（会造成循环依赖风险）：%s", leaf, imported)
			}
			if imported == policyModulePath+"/app" {
				t.Errorf("公共叶子包 %s 不得 import app 装配包：%s", leaf, imported)
			}
		}
	}
}

// TestRootPackageImportsNoCycle 断言根包当前 import 的 internal 包不反向 import
// 根包；否则根包装配内部实现时立即成环（迁移期最常见的结构回归）。
func TestRootPackageImportsNoCycle(t *testing.T) {
	rootImports := policyParseImports(t, ".")
	internalPrefix := policyModulePath + "/internal/"
	for _, imported := range rootImports {
		if !strings.HasPrefix(imported, internalPrefix) {
			continue
		}
		relative := strings.TrimPrefix(imported, policyModulePath+"/")
		dir := filepath.FromSlash(relative)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("根包 import 的 internal 包目录不存在：%s", imported)
		}
		for _, dependency := range policyParseImports(t, dir) {
			if dependency == policyModulePath {
				t.Errorf("根包 import 的 %s 反向 import 根包，形成循环依赖", imported)
			}
		}
	}
}

// TestMigratedRootImplementationStaysOut 断言已迁出的根实现文件不得回流；
// 根目录只允许别名桥（alias_*.go）保留旧公开符号。
func TestMigratedRootImplementationStaysOut(t *testing.T) {
	forbidden := []string{
		"config.go", "config_load.go", "config_diag.go", "config_secret.go",
		"errors.go", "error_codes.go", "error_code_guidance.go",
	}
	for _, name := range forbidden {
		if _, err := os.Stat(name); err == nil {
			t.Errorf("已迁出的根实现文件回流：%s（应使用 alias_*.go 别名桥）", name)
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取根目录失败: %v", err)
	}
	aliasFiles := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasPrefix(entry.Name(), "alias_") && !strings.HasSuffix(entry.Name(), "_test.go") {
			aliasFiles++
		}
	}
	if aliasFiles == 0 {
		t.Fatal("根目录缺少公共别名桥（alias_*.go）")
	}
}
