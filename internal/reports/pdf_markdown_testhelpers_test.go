package reports

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"go.yaml.in/yaml/v3"
)

// reportTestPDFFontPath 返回预审通过的 Noto Sans SC 静态 TTF 路径。字体不进入仓库，
// 测试通过 REPORT_TEST_FONT_PATH 或预审临时目录发现；缺失时跳过 PDF 渲染用例
// （跳过原因显式记录，不把“未跑”当成通过）。
func reportTestPDFFontPath(t *testing.T) string {
	t.Helper()
	candidates := make([]string, 0, 3)
	if custom := strings.TrimSpace(os.Getenv("REPORT_TEST_FONT_PATH")); custom != "" {
		candidates = append(candidates, custom)
	}
	if localTemp := os.Getenv("LOCALAPPDATA"); localTemp != "" {
		candidates = append(candidates, filepath.Join(localTemp, "Temp",
			"dep-review-step78", "font_gstatic", "NotoSansSC-Regular.ttf"))
	}
	if temp := os.Getenv("TEMP"); temp != "" {
		candidates = append(candidates, filepath.Join(temp, "dep-review-step78",
			"font_gstatic", "NotoSansSC-Regular.ttf"))
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Size() != RequiredPDFFontBytes {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) == RequiredPDFFontSHA256 {
			return candidate
		}
	}
	t.Skip("未提供预审通过的 Noto Sans SC 静态 TTF（设置 REPORT_TEST_FONT_PATH）：跳过 PDF 渲染用例")
	return ""
}

// newFontTestEnv 构造带受信 PDF 字体的测试环境（其余依赖与默认测试环境一致）。
func newFontTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	options := newTestOptions(env)
	options.FontPath = reportTestPDFFontPath(t)
	service, err := New(options)
	if err != nil {
		t.Fatalf("构造带字体的报告服务失败: %v", err)
	}
	env.service = service
	return env
}

// pdfDecodedStream 是解压后的 PDF 流（页面内容流或 CMap 等）。
type pdfDecodedStream []byte

// pdfStreams 从原始 PDF 字节中提取全部 stream...endstream 数据并尝试 zlib 解压。
// 该解析只用于测试断言，不进入生产代码。
func pdfStreams(t *testing.T, data []byte) []pdfDecodedStream {
	t.Helper()
	streams := make([]pdfDecodedStream, 0, 16)
	search := 0
	for search < len(data) {
		index := bytes.Index(data[search:], []byte("stream\n"))
		if index < 0 {
			break
		}
		start := search + index + len("stream\n")
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			t.Fatalf("PDF 流缺少 endstream")
		}
		raw := bytes.TrimSuffix(data[start:start+end], []byte("\n"))
		if reader, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			decoded, readErr := io.ReadAll(reader)
			_ = reader.Close()
			if readErr == nil {
				streams = append(streams, decoded)
				search = start + end + len("endstream")
				continue
			}
		}
		streams = append(streams, raw)
		search = start + end + len("endstream")
	}
	return streams
}

// pdfGlyphMap 解析 ToUnicode CMap，得到 glyph ID → Unicode 文本。
func pdfGlyphMap(t *testing.T, streams []pdfDecodedStream) map[int]string {
	t.Helper()
	mapping := make(map[int]string)
	bfCharPair := regexp.MustCompile(`<([0-9A-Fa-f]{1,6})>\s*<([0-9A-Fa-f]{2,16})>`)
	bfRange := regexp.MustCompile(`<([0-9A-Fa-f]{1,6})>\s*<([0-9A-Fa-f]{1,6})>\s*<([0-9A-Fa-f]{2,16})>`)
	found := false
	for _, stream := range streams {
		text := string(stream)
		if !strings.Contains(text, "begincmap") {
			continue
		}
		found = true
		mode := ""
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasSuffix(line, "beginbfchar"):
				mode = "char"
				continue
			case line == "endbfchar":
				mode = ""
				continue
			case strings.HasSuffix(line, "beginbfrange"):
				mode = "range"
				continue
			case line == "endbfrange":
				mode = ""
				continue
			}
			if mode == "char" {
				match := bfCharPair.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				glyph, err := strconv.ParseInt(match[1], 16, 32)
				if err != nil {
					continue
				}
				mapping[int(glyph)] = pdfDecodeUnicodeHex(t, match[2])
				continue
			}
			if mode == "range" {
				match := bfRange.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				start, err1 := strconv.ParseInt(match[1], 16, 32)
				end, err2 := strconv.ParseInt(match[2], 16, 32)
				base, err3 := strconv.ParseInt(match[3], 16, 32)
				if err1 != nil || err2 != nil || err3 != nil || end < start {
					continue
				}
				for glyph := start; glyph <= end; glyph++ {
					runeValue := base + (glyph - start)
					if runeValue > 0x10FFFF {
						break
					}
					mapping[int(glyph)] = string(rune(runeValue))
				}
			}
		}
	}
	if !found {
		t.Fatalf("PDF 缺少 ToUnicode CMap（无法核对中文文本）")
	}
	if len(mapping) == 0 {
		for _, stream := range streams {
			if strings.Contains(string(stream), "begincmap") {
				t.Logf("空 ToUnicode CMap 片段: %q", tailText(string(stream), 600))
			}
		}
		t.Fatalf("ToUnicode CMap 解析结果为空")
	}
	return mapping
}

// pdfDecodeUnicodeHex 把 UTF-16BE 十六进制串解码为 Go 字符串。
func pdfDecodeUnicodeHex(t *testing.T, hexText string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexText)
	if err != nil || len(raw) == 0 || len(raw)%2 != 0 {
		return ""
	}
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		units = append(units, uint16(raw[index])<<8|uint16(raw[index+1]))
	}
	return string(utf16.Decode(units))
}

// pdfTJPattern 匹配 gopdf 的文本绘制操作 [<glyph 十六进制>] TJ。
var pdfTJPattern = regexp.MustCompile(`\[<([0-9A-Fa-f]*)>\] TJ`)

// pdfTDCoordinates 匹配文本定位操作 x y TD。
var pdfTDCoordinates = regexp.MustCompile(`(-?[0-9.]+) (-?[0-9.]+) TD`)

// pdfPageTexts 按页面顺序提取文本：每个页面一个内容流，内容流中的 TJ 数组按
// ToUnicode 映射回 Unicode；同时校验所有文本定位坐标都在页面范围内（防越界裁切）。
func pdfPageTexts(t *testing.T, data []byte) []string {
	t.Helper()
	streams := pdfStreams(t, data)
	glyphs := pdfGlyphMap(t, streams)
	pages := make([]string, 0, 8)
	for _, stream := range streams {
		text := string(stream)
		if !strings.Contains(text, " TJ") || !strings.Contains(text, "BT") {
			continue
		}
		matches := pdfTJPattern.FindAllStringSubmatch(text, -1)
		if len(matches) == 0 {
			continue
		}
		var builder strings.Builder
		for _, match := range matches {
			runes := make([]rune, 0, len(match[1])/4)
			for index := 0; index+4 <= len(match[1]); index += 4 {
				glyph, err := strconv.ParseInt(match[1][index:index+4], 16, 32)
				if err != nil {
					t.Fatalf("PDF glyph 十六进制无效: %q", match[1][index:index+4])
				}
				if mapped, exists := glyphs[int(glyph)]; exists {
					runes = append(runes, []rune(mapped)...)
				} else {
					runes = append(runes, '?')
				}
			}
			builder.WriteString(string(runes))
			builder.WriteString("\n")
		}
		for _, position := range pdfTDCoordinates.FindAllStringSubmatch(text, -1) {
			x, err := strconv.ParseFloat(position[1], 64)
			if err != nil {
				continue
			}
			y, err := strconv.ParseFloat(position[2], 64)
			if err != nil {
				continue
			}
			if x < -1 || x > pdfPageWidth+1 || y < -1 || y > pdfPageHeight+1 {
				t.Fatalf("PDF 文本坐标越界（可能被裁切）: x=%.2f y=%.2f", x, y)
			}
		}
		pages = append(pages, builder.String())
	}
	return pages
}

// pdfFlatten 去掉页面文本中的换行，便于按子串核对跨行内容。
func pdfFlatten(text string) string {
	return strings.NewReplacer("\n", "", "\r", "").Replace(text)
}

// markdownFrontMatter 解析 Markdown YAML front matter 为 map（测试校验机器可读性）。
func markdownFrontMatter(t *testing.T, document string) map[string]any {
	t.Helper()
	const delimiter = "---\n"
	if !strings.HasPrefix(document, delimiter) {
		t.Fatalf("Markdown 缺少 YAML front matter 起始分隔行: %q", firstLine(document))
	}
	rest := document[len(delimiter):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		t.Fatalf("Markdown 缺少 YAML front matter 结束分隔行")
	}
	var meta map[string]any
	if err := yaml.Unmarshal([]byte(rest[:end]), &meta); err != nil {
		t.Fatalf("Markdown front matter 不是合法 YAML: %v", err)
	}
	return meta
}

// markdownTableRows 返回 Markdown 文档中所有表格行（保留原始行文本）。
func markdownTableRows(document string) []string {
	rows := make([]string, 0, 64)
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			rows = append(rows, trimmed)
		}
	}
	return rows
}

// splitMarkdownRow 按未转义的 | 拆分表格行；首尾空段丢弃。
func splitMarkdownRow(row string) []string {
	segments := make([]string, 0, 16)
	var current strings.Builder
	escaped := false
	for _, character := range row {
		switch {
		case escaped:
			current.WriteRune(character)
			escaped = false
		case character == '\\':
			current.WriteRune(character)
			escaped = true
		case character == '|':
			segments = append(segments, current.String())
			current.Reset()
		default:
			current.WriteRune(character)
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	if len(segments) > 0 && strings.TrimSpace(segments[0]) == "" {
		segments = segments[1:]
	}
	if len(segments) > 0 && strings.TrimSpace(segments[len(segments)-1]) == "" {
		segments = segments[:len(segments)-1]
	}
	for index := range segments {
		segments[index] = strings.TrimSpace(segments[index])
	}
	return segments
}

// firstLine 返回文本第一行（用于错误信息）。
func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}
	return text
}

// tailText 返回文本末尾最多 limit 个字符（用于失败时的诊断输出）。
func tailText(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[len(runes)-limit:])
}

// artifactFilenameForTest 返回受控产物文件名（测试断言扩展名用）。
func artifactFilenameForTest(format Format) string {
	return artifactFileName("rpt_"+strings.Repeat("0", 32), format)
}

// requireContains 断言文本包含子串。
func requireContains(t *testing.T, text, want, description string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("%s 未包含 %q", description, want)
	}
}

// sha256Hex 返回字节的 SHA-256 十六进制摘要。
func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// pdfSummary 是测试中常用 PDF 断言的合集。
type pdfSummary struct {
	data  []byte
	pages []string
}

// loadPDFSummary 读取产物并解析页面文本。
func loadPDFSummary(t *testing.T, data []byte) pdfSummary {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("PDF 产物缺少 %%PDF- 魔数（不能以纯文本伪装）")
	}
	pages := pdfPageTexts(t, data)
	if len(pages) == 0 {
		t.Fatalf("PDF 没有可提取的页面文本")
	}
	return pdfSummary{data: data, pages: pages}
}

// allText 拼接全部页面文本（去换行）。
func (s pdfSummary) allText() string {
	var builder strings.Builder
	for _, page := range s.pages {
		builder.WriteString(page)
		builder.WriteString("\n")
	}
	return pdfFlatten(builder.String())
}

// pageCount 返回 PDF 页面数（以含文本的内容流计数；测试文档每页都有页脚文本）。
func (s pdfSummary) pageCount() int { return len(s.pages) }
