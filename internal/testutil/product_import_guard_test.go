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

// allowedProductImporters 是“产品文件导入 internal/testutil”的有理由例外清单。
//
// 仅允许真正的测试/开发夹具包：它们自身导入 testing 或只被 *_test.go 引用，
// 不得被任何生产入口（cmd/、app/、根非测试代码、internal/serverapp 非测试装配）
// 导入，因此不会进入生产二进制。放宽整体规则或加入非测试支持包都是禁止的。
// 每个例外必须在遍历中被实际命中，否则报错要求清理过期例外。
var allowedProductImporters = map[string]string{
	"internal/mailtest/mailtest.go": "mailtest 是仅测试/开发使用的外部 EvernightMail 进程夹具包（自身导入 testing，只被 *_test.go 导入，无生产二进制引用），复用 testutil 的临时目录与清理辅助",
}

// TestProductCodeDoesNotImportTestutil 守护“testutil 仅限测试使用”的约定：
// 产品代码（非 *_test.go）不得导入本包，否则测试专用辅助会进入生产构建，且可能
// 让产品二进制隐式依赖 testing 包。本测试遍历模块内所有非测试 Go 源文件做静态检查。
func TestProductCodeDoesNotImportTestutil(t *testing.T) {
	root := findModuleRoot(t)
	var offenders []string
	allowedSeen := make(map[string]bool, len(allowedProductImporters))
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
			slashRel := filepath.ToSlash(rel)
			if _, allowed := allowedProductImporters[slashRel]; allowed {
				allowedSeen[slashRel] = true
				return nil
			}
			offenders = append(offenders, slashRel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历模块源码失败: %v", err)
	}
	for rel := range allowedProductImporters {
		if !allowedSeen[rel] {
			t.Errorf("允许清单条目未命中（文件已删除或不再导入 testutil，请清理）: %s", rel)
		}
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
