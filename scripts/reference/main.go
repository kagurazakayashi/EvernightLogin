// Command reference 生成并校验人类与 AI 共用的接口参考（docs/reference/）。
//
// 用法（仓库根目录）：
//
//	go run ./scripts/reference -write   # 重新生成 docs/reference 全部文件
//	go run ./scripts/reference -check   # 只读校验生成物与源码一致（CI/审计用）
//	go run ./scripts/reference -list    # 列出将生成的文件（不写文件）
//
// 退出码：0=通过；1=校验失败/生成拒绝；2=用法或环境错误。
// 生成物确定、原子写入、无时间戳；本命令不访问网络、数据库或产品运行时。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kagurazakayashi/EvernightLogin/scripts/internal/apidoc"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run 执行命令并返回进程退出码。
func run(args []string) int {
	flags := flag.NewFlagSet("reference", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	writeMode := flags.Bool("write", false, "重新生成 docs/reference 下的全部参考文件（原子写入）")
	checkMode := flags.Bool("check", false, "只读校验 docs/reference 与源码一致")
	listMode := flags.Bool("list", false, "列出将生成的文件（不写文件）")
	rootFlag := flags.String("root", "", "仓库根目录（默认为当前目录向上查找 go.mod）")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "reference: 不接受位置参数")
		flags.Usage()
		return 2
	}
	root := *rootFlag
	if root == "" {
		var err error
		root, err = findRepoRoot()
		if err != nil {
			fmt.Fprintln(os.Stderr, "reference:", err)
			return 2
		}
	}
	switch {
	case *listMode:
		model, err := apidoc.Generate(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reference: 生成模型失败：", err)
			return 2
		}
		files, issues, err := model.Files()
		if err != nil {
			fmt.Fprintln(os.Stderr, "reference: 生成文件失败：", err)
			return 2
		}
		for _, issue := range issues {
			fmt.Fprintln(os.Stderr, "WARN:", issue)
		}
		for _, name := range sortedKeys(files) {
			fmt.Println(name)
		}
		return 0
	case *checkMode:
		result, err := apidoc.Check(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reference: 校验失败：", err)
			return 2
		}
		for _, warning := range result.Warnings {
			fmt.Fprintln(os.Stderr, "WARN:", warning)
		}
		for _, issue := range result.Issues {
			fmt.Fprintln(os.Stderr, "FAIL:", issue)
		}
		if len(result.Issues) > 0 {
			fmt.Printf("REFERENCE CHECK: FAIL issues=%d\n", len(result.Issues))
			return 1
		}
		fmt.Println("REFERENCE CHECK: PASS")
		return 0
	case *writeMode:
		paths, warnings, err := apidoc.Write(root)
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, "WARN:", warning)
		}
		if err != nil {
			for _, path := range paths {
				fmt.Fprintln(os.Stderr, "WROTE:", path)
			}
			fmt.Fprintln(os.Stderr, "reference: 生成失败：", err)
			return 1
		}
		for _, path := range paths {
			fmt.Println("WROTE:", path)
		}
		fmt.Printf("REFERENCE WRITE: PASS files=%d\n", len(paths))
		return 0
	default:
		fmt.Fprintln(os.Stderr, "reference: 需要 -write、-check 或 -list 之一")
		flags.Usage()
		return 2
	}
}

// findRepoRoot 从当前工作目录向上查找包含 go.mod 的目录。
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("读取当前目录失败：%w", err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("未找到包含 go.mod 的仓库根目录（可用 -root 指定）")
		}
		dir = parent
	}
}

// sortedKeys 返回 map 键的排序列表。
func sortedKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return keys
}

// sortStrings 原地排序字符串切片（避免为单一用途引入更多依赖）。
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
