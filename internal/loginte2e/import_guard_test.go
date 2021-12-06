package loginte2e

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loginte2eImportPath 是 internal/loginte2e 的完整导入路径字面量（含引号）。
const loginte2eImportPath = `"github.com/kagurazakayashi/EvernightLogin/internal/loginte2e"`

// TestOnlyTestToolMayImportLibrary 守护“测试工具库不得进入生产入口”的约定：
// 只有 tools/loginte2e（薄 main）与本包测试可以导入 internal/loginte2e。
// 产品代码（根包、cmd/、internal/ 其他包）一旦导入即视为隔离破坏。
func TestOnlyTestToolMayImportLibrary(t *testing.T) {
	root := findModuleRootForGuard(t)
	var offenders []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		if relative == "tools/loginte2e/main.go" ||
			strings.HasPrefix(relative, "internal/loginte2e/") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), loginte2eImportPath) {
			offenders = append(offenders, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历模块源码失败: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("生产代码不得导入 internal/loginte2e（测试工具库），发现 %d 个文件: %v",
			len(offenders), offenders)
	}
}

// findModuleRootForGuard 从当前测试工作目录向上查找 go.mod。
func findModuleRootForGuard(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("未找到模块根目录（go.mod）")
		}
		directory = parent
	}
}
