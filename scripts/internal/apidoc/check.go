package apidoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 本文件实现生成物写入与校验：
//   - Write：先在内存中生成全部文件，确认能力声明可解析后原子写入 docs/reference；
//   - Check：重新生成全部文件并与磁盘逐字节比较，同时核对机器 JSON 可解析、文档相对
//     链接可达、示例全部被引用；发现问题返回失败清单（fail-closed）。
//
// 两个操作都不修改产品源码；Write 只写 docs/reference 下由生成器拥有的文件。

// CheckResult 是一次校验结果；Issues 非空表示失败，Warnings 仅提示不阻塞。
type CheckResult struct {
	Issues   []string
	Warnings []string
}

// Write 重新生成 docs/reference 全部文件并原子写入，返回写入的相对路径与告警。
func Write(root string) ([]string, []string, error) {
	model, err := Generate(root)
	if err != nil {
		return nil, nil, err
	}
	if len(model.ClaimIssues) > 0 {
		return nil, model.ClaimIssues, fmt.Errorf(
			"能力声明存在 %d 个无法解析的公开面，拒绝生成文档（先修声明或代码）", len(model.ClaimIssues))
	}
	if model.PageOpenAPI != nil && len(model.PageOpenAPI.Issues) > 0 {
		return nil, model.PageOpenAPI.Issues, fmt.Errorf(
			"页面/表单 OpenAPI 契约存在 %d 个与真实路由不一致的问题，拒绝生成文档", len(model.PageOpenAPI.Issues))
	}
	if countIssues := validateCounts(model); len(countIssues) > 0 {
		return nil, countIssues, fmt.Errorf(
			"盘点数量低于安全下限（疑似 214/215 结构迁移未同步），拒绝生成文档")
	}
	files, snippetIssues, err := model.Files()
	if err != nil {
		return nil, nil, err
	}
	if len(snippetIssues) > 0 {
		return nil, snippetIssues, fmt.Errorf("参考示例存在 %d 个未引用问题，拒绝生成文档", len(snippetIssues))
	}
	dir := filepath.Join(root, filepath.FromSlash(referenceDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("创建参考目录失败：%w", err)
	}
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := writeFileAtomic(path, files[name]); err != nil {
			return nil, nil, err
		}
	}
	warnings := append([]string{}, model.Warnings...)
	warnings = append(warnings, model.CrossCheck.Mismatches...)
	sort.Strings(warnings)
	return paths, warnings, nil
}

// adminAPIDocFiles 是由 scripts/adminapi-doc（步骤 270）生成并校验的文件名；
// 它们不在本生成器的文件清单里，但也不是“未登记的旧文档”。
var adminAPIDocFiles = map[string]bool{
	"http-openapi-admin.json": true,
	"http-admin-api.md":       true,
}

// writeFileAtomic 先写同目录临时文件再重命名，避免中断留下半个生成物。
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".reference-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件失败（%s）：%w", path, err)
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if _, err := temp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("写入临时文件失败（%s）：%w", path, err)
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("关闭临时文件失败（%s）：%w", path, err)
	}
	if err := os.Chmod(tempPath, 0o644); err != nil {
		cleanup()
		return fmt.Errorf("设置文件权限失败（%s）：%w", path, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		cleanup()
		return fmt.Errorf("原子替换 %s 失败：%w", path, err)
	}
	return nil
}

// Check 校验 docs/reference 与源码一致。
func Check(root string) (CheckResult, error) {
	result := CheckResult{}
	model, err := Generate(root)
	if err != nil {
		return result, err
	}
	result.Warnings = append(result.Warnings, model.Warnings...)
	result.Warnings = append(result.Warnings, model.CrossCheck.Mismatches...)
	result.Issues = append(result.Issues, model.ClaimIssues...)
	if model.PageOpenAPI != nil {
		result.Issues = append(result.Issues, model.PageOpenAPI.Issues...)
	}
	result.Issues = append(result.Issues, validateCounts(model)...)
	files, snippetIssues, err := model.Files()
	if err != nil {
		return result, err
	}
	result.Issues = append(result.Issues, snippetIssues...)
	dir := filepath.Join(root, filepath.FromSlash(referenceDir))
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		result.Issues = append(result.Issues,
			fmt.Sprintf("%s 不存在：请先运行 go run ./scripts/reference -write 生成参考", referenceDir))
		return finishCheck(result), nil
	}
	expected := make([]string, 0, len(files))
	for name := range files {
		expected = append(expected, name)
	}
	sort.Strings(expected)
	for _, name := range expected {
		path := filepath.Join(root, filepath.FromSlash(name))
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			result.Issues = append(result.Issues, fmt.Sprintf("缺少生成文件 %s：%v", name, readErr))
			continue
		}
		want := files[name]
		if !bytes.Equal(got, want) {
			result.Issues = append(result.Issues, fmt.Sprintf(
				"%s 与源码不一致（%s）：%s；请运行 go run ./scripts/reference -write",
				name, describeDifference(got, want), diffExcerpt(got, want)))
		}
	}
	// 生成目录里不允许出现未登记的 .md/.json（避免旧文档被误当作权威参考）。
	// 例外：管理 JSON API 参考由 scripts/adminapi-doc 生成并自行逐字节校验（步骤 270），
	// 它们与本生成器的文件清单无关，不能因此判 reference 失败。
	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("读取 %s 失败：%v", referenceDir, readDirErr))
	} else {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			rel := referenceDir + "/" + entry.Name()
			if _, ok := files[rel]; ok {
				continue
			}
			if adminAPIDocFiles[entry.Name()] {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".md") || strings.HasSuffix(entry.Name(), ".json") {
				result.Issues = append(result.Issues, fmt.Sprintf(
					"发现未登记的生成文件 %s：请删除，或加入 scripts/internal/apidoc 的生成清单", rel))
			}
		}
	}
	// 机器 JSON 必须可解析（生成器自身错误时提前暴露）。
	for _, name := range jsonFiles() {
		raw := files[referenceDir+"/"+name]
		if raw == nil || !json.Valid(raw) {
			result.Issues = append(result.Issues, fmt.Sprintf("%s 不是合法 JSON", name))
		}
	}
	// 文档相对链接必须可达（生成物内部的交叉引用）。
	for _, name := range markdownFiles() {
		rel := referenceDir + "/" + name
		content := files[rel]
		for _, target := range markdownLinkTargets(content) {
			resolved := filepath.Join(filepath.Dir(filepath.Join(root, filepath.FromSlash(rel))), filepath.FromSlash(target))
			if _, statErr := os.Stat(resolved); statErr != nil {
				result.Issues = append(result.Issues, fmt.Sprintf("%s 的相对链接不可达：%s（解析为 %s）", name, target, filepath.ToSlash(resolved)))
			}
		}
	}
	return finishCheck(result), nil
}

// finishCheck 排序去重后返回结果。
func finishCheck(result CheckResult) CheckResult {
	result.Issues = uniqueSorted(result.Issues)
	result.Warnings = uniqueSorted(result.Warnings)
	return result
}

// uniqueSorted 排序并去重字符串切片。
func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			out = append(out, value)
		}
	}
	return out
}

// markdownLinkPattern 匹配 Markdown 行内链接目标。
var markdownLinkPattern = regexp.MustCompile(`\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// markdownLinkTargets 提取文档内的站内相对链接（跳过 http/mailto/纯锚点）。
func markdownLinkTargets(content []byte) []string {
	var targets []string
	for _, match := range markdownLinkPattern.FindAllSubmatch(content, -1) {
		target := strings.TrimSpace(string(match[1]))
		if target == "" || strings.HasPrefix(target, "#") ||
			strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "mailto:") {
			continue
		}
		if index := strings.Index(target, "#"); index >= 0 {
			target = target[:index]
		}
		if target == "" {
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

// describeDifference 概括两个文件内容的差异类型。
func describeDifference(got, want []byte) string {
	switch {
	case bytes.Contains(got, []byte("\r\n")):
		return "磁盘文件为 CRLF 行尾，生成物要求 LF"
	case len(got) == 0:
		return "磁盘文件为空"
	case len(want) == 0:
		return "生成内容为空"
	default:
		return "内容不同"
	}
}

// diffExcerpt 给出首个不同行的上下文，便于定位手工改动。
func diffExcerpt(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	for index := 0; index < len(gotLines) && index < len(wantLines); index++ {
		if gotLines[index] == wantLines[index] {
			continue
		}
		return fmt.Sprintf("第 %d 行：磁盘=%q，生成=%q",
			index+1, truncateText(gotLines[index], 80), truncateText(wantLines[index], 80))
	}
	return fmt.Sprintf("行数不同：磁盘 %d 行，生成 %d 行", len(gotLines), len(wantLines))
}

// truncateText 截断过长文本用于错误信息。
func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
