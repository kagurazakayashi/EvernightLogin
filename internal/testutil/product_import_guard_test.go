package testutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testutilImportPath 是 internal/testutil 的完整导入路径字面量（含引号）。
const testutilImportPath = `"github.com/kagurazakayashi/EvernightLogin/internal/testutil"`

// TestProductCodeDoesNotImportTestutil 守护“testutil 仅限测试使用”的约定：
// 产品代码（非 *_test.go）不得导入本包，否则测试专用辅助会进入生产构建，且可能
// 让产品二进制隐式依赖 testing 包。本测试遍历模块内所有非测试 Go 源文件做静态检查。
func TestProductCodeDoesNotImportTestutil(t *testing.T) {
	root := findModuleRoot(t)
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			// 跳过隐藏目录（.git/.ai/.agents 等）、下划线目录、vendor 与 testdata。
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		content, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(content), testutilImportPath) {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			offenders = append(offenders, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历模块源码失败: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("产品代码（非 *_test.go）不得导入 internal/testutil，发现 %d 个文件: %v",
			len(offenders), offenders)
	}
}

// findModuleRoot 从测试工作目录向上查找 go.mod，返回模块根目录。
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取测试工作目录失败: %v", err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("未找到模块根目录（缺少 go.mod）")
		}
		dir = parent
	}
}
