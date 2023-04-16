package appcore

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports 守卫：appcore 不得反向导入 serverapp/cmd/公开 app。
func TestNoForbiddenImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("未找到 appcore 源码")
	}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path := strings.Trim(spec.Path.Value, "\"")
			if path == "github.com/kagurazakayashi/EvernightLogin/internal/serverapp" ||
				path == "github.com/kagurazakayashi/EvernightLogin/app" ||
				strings.Contains(path, "/cmd/") {
				t.Fatalf("appcore 不得导入 %s（%s）", path, file)
			}
		}
	}
}
