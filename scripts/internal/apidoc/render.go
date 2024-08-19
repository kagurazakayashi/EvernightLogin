package apidoc

import (
	"fmt"
	"sort"
	"strings"
)

// 本文件负责把 Model 渲染成 docs/reference 下的 Markdown 与机器 JSON。
// 输出是确定性的：所有集合已排序、行尾 LF、文件末尾单个换行、不含时间戳。
// 文档文件全部由生成器拥有，不允许手工编辑（-check 逐字节核对）。

// referenceDir 是生成物目录（相对仓库根）。
const referenceDir = "docs/reference"

// Files 渲染全部生成文件，返回仓库相对路径到内容的映射，以及“示例未被引用”等
// 交叉校验问题。调用方（Write/Check）不修改返回值。
func (m *Model) Files() (map[string][]byte, []string, error) {
	files := make(map[string][]byte, len(markdownFiles())+len(jsonFiles()))
	for name, content := range m.jsonFiles() {
		files[referenceDir+"/"+name] = content
	}
	used := map[string]bool{}
	renderers := []struct {
		name string
		fn   func(used map[string]bool) []byte
	}{
		{fileIndex, m.renderIndex},
		{fileErrors, m.renderErrors},
		{filePermissions, m.renderPermissions},
		{fileConfiguration, m.renderConfiguration},
		{fileHTTPAPI, m.renderHTTPAPI},
		{fileCLI, m.renderCLI},
		{fileGoAPI, m.renderGoAPI},
		{fileCapability, m.renderCapabilityMap},
		{fileAIIndex, m.renderAIIndex},
		{fileChangeLog, m.renderChangeLog},
	}
	for _, renderer := range renderers {
		files[referenceDir+"/"+renderer.name] = renderer.fn(used)
	}
	var issues []string
	for _, snippet := range m.Snippets {
		if !used[snippet.Symbol] {
			issues = append(issues, fmt.Sprintf(
				"参考示例 %s 未被任何生成文档引用（请内嵌到 errors.md/configuration.md/go-api.md 等，或从示例文件删除）",
				snippet.Symbol))
		}
	}
	sort.Strings(issues)
	return files, issues, nil
}

// snippetBlock 返回一个示例的 Go 代码块，并登记该示例已被引用。
func (m *Model) snippetBlock(used map[string]bool, symbol string) string {
	for _, snippet := range m.Snippets {
		if snippet.Symbol != symbol {
			continue
		}
		used[symbol] = true
		return codeBlock("go", snippet.Code)
	}
	return fmt.Sprintf("> 警告：生成器缺少参考示例 `%s`\n", symbol)
}

// markdownTable 生成确定性 Markdown 表格；单元格内的换行折叠为单行、竖线转义。
func markdownTable(headers []string, rows [][]string) string {
	var builder strings.Builder
	builder.WriteString("| " + joinCells(headers) + " |\n")
	builder.WriteString("|")
	for range headers {
		builder.WriteString("---|")
	}
	builder.WriteString("\n")
	for _, row := range rows {
		builder.WriteString("| " + joinCells(row) + " |\n")
	}
	return builder.String()
}

// joinCells 连接一行单元格（数量可以少于表头，缺失补空）。
func joinCells(cells []string) string {
	parts := make([]string, 0, len(cells))
	for _, cell := range cells {
		parts = append(parts, escapeCell(cell))
	}
	return strings.Join(parts, " | ")
}

// escapeCell 转义表格单元格：折叠空白、转义竖线、把换行改为空格。
func escapeCell(cell string) string {
	cell = strings.ReplaceAll(cell, "\r\n", "\n")
	cell = singleLine(cell)
	cell = strings.ReplaceAll(cell, "|", `\|`)
	return cell
}

// codeBlock 生成围栏代码块；内容已去掉末尾多余空行。
func codeBlock(language, code string) string {
	code = strings.ReplaceAll(code, "\r\n", "\n")
	code = strings.Trim(code, "\n")
	return "```" + language + "\n" + code + "\n```\n"
}

// paragraph 生成段落（自动补空行）。
func paragraph(text string) string {
	return strings.TrimSpace(text) + "\n"
}

// bulletList 生成无序列表。
func bulletList(items []string) string {
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString("- " + strings.TrimSpace(item) + "\n")
	}
	return builder.String()
}

// orderedList 生成有序列表。
func orderedList(items []string) string {
	var builder strings.Builder
	for index, item := range items {
		builder.WriteString(fmt.Sprintf("%d. %s\n", index+1, strings.TrimSpace(item)))
	}
	return builder.String()
}

// joinBlocks 用单个空行连接多个 Markdown 块，保证文件以一个换行结尾。
func joinBlocks(blocks ...string) []byte {
	var builder strings.Builder
	for _, block := range blocks {
		block = strings.Trim(block, "\n")
		if block == "" {
			continue
		}
		builder.WriteString(block)
		builder.WriteString("\n\n")
	}
	content := strings.TrimRight(builder.String(), "\n") + "\n"
	return []byte(content)
}

// link 生成站内相对链接文本（路径统一使用斜杠）。
func link(label, target string) string {
	return "[" + label + "](" + target + ")"
}

// countInterfaceMethods 统计全部公开服务接口方法数。
func countInterfaceMethods(goAPI *GoAPI) int {
	if goAPI == nil {
		return 0
	}
	total := 0
	for _, iface := range goAPI.Interfaces {
		total += len(iface.Methods)
	}
	return total
}

// countCLIFlags 统计全部 CLI flag 数。
func countCLIFlags(binaries []CLIBinary) int {
	total := 0
	for _, binary := range binaries {
		for _, command := range binary.Subcommands {
			total += len(command.Flags)
		}
	}
	return total
}

// classLabel 把配置重载分类翻译为直白中文。
func classLabel(class string) string {
	switch class {
	case "restart-required":
		return "重启生效"
	case "hot-reloadable":
		return "重载生效"
	default:
		return class
	}
}

// joinCode 把名称列表包装成行内代码并以顿号连接；为空返回“-”。
func joinCode(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, "`"+name+"`")
	}
	return strings.Join(parts, "、")
}

// joinPipes 把字符串列表用顿号连接；为空返回“-”。
func joinPipes(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, "、")
}

// sourceLink 生成源码定位文本（代码格式，不加链接，避免生成器依赖仓库托管地址）。
func sourceLink(source string) string {
	if source == "" {
		return "-"
	}
	return "`" + source + "`"
}
