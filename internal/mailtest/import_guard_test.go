// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mailtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestProductionDoesNotImportMailtest 守护：父项目生产文件不得导入 internal/mailtest，
// 也不得导入 EvernightMail 子模块的任何包（夹具只能通过外部进程交互）。
func TestProductionDoesNotImportMailtest(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatalf("repositoryRoot: %v", err)
	}
	violations := make([]string, 0)
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			switch name {
			case ".git", "vendor", "EvernightMail", ".ai", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if strings.HasPrefix(filepath.ToSlash(relative), "internal/mailtest/") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("解析 %s 失败: %v", relative, parseErr)
			return nil
		}
		for _, importSpec := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			if strings.Contains(importPath, "internal/mailtest") || strings.HasPrefix(importPath, "github.com/kagurazakayashi/EvernightMail") {
				violations = append(violations, relative+" -> "+importPath)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("遍历源码失败: %v", walkErr)
	}
	if len(violations) > 0 {
		t.Fatalf("生产代码不得导入测试夹具或 Mail 子模块包:\n%s", strings.Join(violations, "\n"))
	}
}
