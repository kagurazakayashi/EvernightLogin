package apidoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 本文件从 examples/reference-snippets 提取最小可编译示例函数，供参考文档内嵌。
// 文档中的示例代码块必须与源码逐字一致由 -check 保证；示例本身由
// `go build ./examples/reference-snippets` 做真实编译校验。

// Snippet 是一条最小可编译示例（完整函数源码，含文档注释）。
type Snippet struct {
	Symbol string
	Code   string
}

// loadSnippets 读取示例文件并提取全部以 Example 开头的公开函数。
func loadSnippets(root string) ([]Snippet, error) {
	path := filepath.Join(root, filepath.FromSlash(pathSnippetFile))
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取参考示例 %s 失败：%w（Phase A 必须提供可编译示例）", pathSnippetFile, err)
	}
	fset, file, err := parseSource(path, source)
	if err != nil {
		return nil, err
	}
	var snippets []Snippet
	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Recv != nil || funcDecl.Name == nil {
			continue
		}
		if !funcDecl.Name.IsExported() || !strings.HasPrefix(funcDecl.Name.Name, "Example") {
			continue
		}
		start := funcDecl.Pos()
		if funcDecl.Doc != nil {
			start = funcDecl.Doc.Pos()
		}
		startOffset := fset.Position(start).Offset
		endOffset := fset.Position(funcDecl.End()).Offset
		if startOffset < 0 || endOffset > len(source) || startOffset >= endOffset {
			return nil, fmt.Errorf("提取参考示例 %s 失败：源码位置越界", funcDecl.Name.Name)
		}
		code := string(source[startOffset:endOffset])
		code = strings.TrimSpace(strings.ReplaceAll(code, "\r\n", "\n"))
		snippets = append(snippets, Snippet{Symbol: funcDecl.Name.Name, Code: code})
	}
	if len(snippets) == 0 {
		return nil, fmt.Errorf("参考示例 %s 中没有 Example* 函数", pathSnippetFile)
	}
	sort.Slice(snippets, func(i, j int) bool { return snippets[i].Symbol < snippets[j].Symbol })
	return snippets, nil
}

// parseSource 解析内存中的 Go 源码（用于示例提取，不重复读取文件）。
func parseSource(path string, source []byte) (*token.FileSet, *ast.File, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 %s 失败：%w", path, err)
	}
	return fset, file, nil
}
