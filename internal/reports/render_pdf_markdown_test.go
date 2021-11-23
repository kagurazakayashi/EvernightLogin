package reports

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// TestPDFAndMarkdownSameSnapshotConsistency 生成五种格式并核对数值同源：JSON 是
// 规范化快照，CSV/Markdown/PDF 的表与汇总必须与它一致，Markdown front matter 的
// snapshot_json_sha256 必须等于 JSON 产物摘要；PDF 必须为多页、内嵌 TrueType 字体
// 且每页都有文本（无空白页）。
func TestPDFAndMarkdownSameSnapshotConsistency(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	request := env.startRequest(t)
	request.Formats = []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF, FormatMarkdown}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("报告未成功: %+v", final)
	}
	if len(final.Artifacts) != 5 {
		t.Fatalf("产物数量 = %d，期望 5", len(final.Artifacts))
	}
	artifactSHA := make(map[Format]string, len(final.Artifacts))
	for _, artifact := range final.Artifacts {
		if !artifact.Available || artifact.Bytes <= 0 || len(artifact.SHA256) != 64 {
			t.Fatalf("产物元数据不完整: %+v", artifact)
		}
		artifactSHA[artifact.Format] = artifact.SHA256
	}

	// JSON：规范化快照（数值是 JSON 数字）。
	jsonBytes := env.artifactBytes(t, reportID, FormatJSON)
	var document map[string]any
	if err := json.Unmarshal(jsonBytes, &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	activity := document["activity"].(map[string]any)
	errorsData := document["errors"].(map[string]any)
	activityTotal := int64(activity["total_distinct_users"].(float64))
	rawEvents := int64(errorsData["total_raw_events"].(float64))
	failedRequests := int64(errorsData["failed_requests"].(float64))
	failedTasks := int64(errorsData["failed_tasks"].(float64))
	if activityTotal != 7 || rawEvents != 10 || failedRequests != 6 || failedTasks != 1 {
		t.Fatalf("JSON 汇总基线不符: active=%d raw=%d req=%d task=%d",
			activityTotal, rawEvents, failedRequests, failedTasks)
	}
	if artifactSHA[FormatJSON] != sha256Hex(jsonBytes) {
		t.Fatal("JSON 产物摘要与元数据不一致")
	}

	// CSV：errors_total / activity_total 行的 value 与 JSON 一致。
	csvData := env.artifactBytes(t, reportID, FormatCSV)
	reader := csv.NewReader(strings.NewReader(string(csvData)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	csvTotals := map[string]string{}
	for _, record := range records {
		if len(record) < 11 {
			continue
		}
		if record[0] == "errors_total" {
			csvTotals[record[9]] = record[10]
		}
		if record[0] == "activity_total" {
			csvTotals[record[9]] = record[10]
		}
	}
	for metric, want := range map[string]string{
		"total_raw_events":     strconv.FormatInt(rawEvents, 10),
		"failed_requests":      strconv.FormatInt(failedRequests, 10),
		"failed_tasks":         strconv.FormatInt(failedTasks, 10),
		"total_distinct_users": strconv.FormatInt(activityTotal, 10),
	} {
		if csvTotals[metric] != want {
			t.Fatalf("CSV %s = %q，JSON 为 %q", metric, csvTotals[metric], want)
		}
	}

	// Markdown：front matter 机器可读，摘要等于 JSON 产物摘要。
	markdownBytes := env.artifactBytes(t, reportID, FormatMarkdown)
	markdown := string(markdownBytes)
	front := markdownFrontMatter(t, markdown)
	if front["report_id"] != reportID {
		t.Fatalf("front matter report_id = %v，期望 %s", front["report_id"], reportID)
	}
	if front["schema_version"] != SchemaVersion || front["template_version"] != TemplateVersion {
		t.Fatalf("front matter 版本不符: %v / %v", front["schema_version"],
			front["template_version"])
	}
	if front["snapshot_json_sha256"] != artifactSHA[FormatJSON] ||
		front["snapshot_json_sha256"] != sha256Hex(jsonBytes) {
		t.Fatalf("Markdown 快照摘要与 JSON 产物不一致: %v", front["snapshot_json_sha256"])
	}
	for key, want := range map[string]int64{
		"activity_total_distinct_users": activityTotal,
		"total_raw_events":              rawEvents,
		"failed_requests":               failedRequests,
		"failed_tasks":                  failedTasks,
	} {
		if got, ok := front[key].(int); !ok || int64(got) != want {
			t.Fatalf("front matter %s = %v，JSON 为 %d", key, front[key], want)
		}
	}
	if artifactSHA[FormatMarkdown] != sha256Hex(markdownBytes) {
		t.Fatal("Markdown 产物摘要与元数据不一致")
	}
	if !strings.HasSuffix(artifactFileName(reportID, FormatMarkdown), ".md") {
		t.Fatal("Markdown 产物扩展名不是 .md")
	}

	// PDF：真实多页 + 内嵌 TrueType 字体 + ToUnicode + 每页有文本。
	pdfData := env.artifactBytes(t, reportID, FormatPDF)
	pdf := loadPDFSummary(t, pdfData)
	if pdf.pageCount() < 2 {
		t.Fatalf("PDF 页数 = %d，期望至少 2 页", pdf.pageCount())
	}
	totalPages := pdf.pageCount()
	for index, page := range pdf.pages {
		footer := fmt.Sprintf("第 %d / %d 页", index+1, totalPages)
		if !strings.Contains(page, footer) {
			t.Logf("第 %d 页文本尾部: %q", index+1, tailText(page, 220))
		}
		requireContains(t, page, footer, "PDF 页脚")
		if index > 0 {
			requireContains(t, page, "EvernightLogin 统计报告", "PDF 续页页眉")
		}
	}
	rawPDF := string(pdfData)
	requireContains(t, rawPDF, "/FontFile2", "PDF 嵌入 TrueType 字体")
	requireContains(t, rawPDF, "/ToUnicode", "PDF 字体 ToUnicode 映射")
	if strings.Contains(rawPDF, "/FontFile3") {
		t.Fatal("PDF 使用了 CFF(FontFile3) 字体，与预审方案不符")
	}
	text := pdf.allText()
	for _, want := range []string{"统计报告", reportID, "登录活跃度", "错误明细",
		"AUTH_FAILED", "测试<脚本>", "窗口内成功认证去重用户数：7 人",
		"原始错误事件次数10", "去重失败请求数6", "去重失败任务数1"} {
		requireContains(t, text, pdfFlatten(want), "PDF 文本")
	}
	// 同一 JSON 错误码与中文特殊字符在 PDF 文本中完整出现（未因折行丢失）。
	requireContains(t, text, "=cmd|' /C calc'!A0", "PDF 特殊字符错误码")
	// L1：PDF 也必须有不可信材料/智能体不得执行声明；N1：文案完整（“为准”）。
	requireContains(t, text, "不可信材料", "PDF 不可信边界声明")
	requireContains(t, text, "智能体", "PDF 智能体约束声明")
	requireContains(t, text, "不得执行", "PDF 智能体约束声明")
	requireContains(t, text, "有效期为准", "PDF 有效期文案")
	if artifactSHA[FormatPDF] != sha256Hex(pdfData) {
		t.Fatal("PDF 产物摘要与元数据不一致")
	}
	// HTML 也来自同一快照：同一测试内核对汇总数值，防后续回归（审计 N2）。
	htmlText := string(env.artifactBytes(t, reportID, FormatHTML))
	for _, want := range []string{
		"窗口内成功认证去重用户数：<strong>7</strong>",
		"原始错误事件次数</td><td>10</td>",
		"去重失败请求数</td><td>6</td>",
		"去重失败任务数</td><td>1</td>",
	} {
		requireContains(t, htmlText, want, "HTML 数值一致性")
	}
	if strings.Contains(htmlText, "http://") || strings.Contains(htmlText, "https://") {
		t.Fatal("HTML 不应引用外部资源")
	}
	// N1：Markdown 同句文案完整。
	requireContains(t, markdown, "有效期为准", "Markdown 有效期文案")
}

// TestPDFMultiPageTableAndHeaders 验证错误明细长表跨页时每页重画表头（“续”），
// 每页都有内容与页脚（无空白页），长错误码完整保留。
func TestPDFMultiPageTableAndHeaders(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	rows := make([]stats.ErrorRow, 0, 45)
	for index := 0; index < 45; index++ {
		rows = append(rows, stats.ErrorRow{
			ErrorCode: fmt.Sprintf("ERR_LONG_%s_%02d", strings.Repeat("X", 18), index),
			Category:  stats.CategoryFailure, Severity: stats.SeverityError,
			AppID: fmt.Sprintf("app_%03d", index), RawEvents: int64(50 - index),
			FailedRequests: 1, Share: 0.01,
			FirstSeen:  baseTime.Add(-time.Duration(index) * time.Minute),
			LastSeen:   baseTime,
			Growth:     stats.Growth{Kind: stats.GrowthUnavailable},
			DataStatus: stats.DataComplete,
		})
	}
	env.source.rows = rows
	env.source.activity = 9
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("长表 PDF 生成失败: %+v", final)
	}
	pdf := loadPDFSummary(t, env.artifactBytes(t, reportID, FormatPDF))
	if pdf.pageCount() < 3 {
		t.Fatalf("长表 PDF 页数 = %d，期望至少 3 页", pdf.pageCount())
	}
	totalPages := pdf.pageCount()
	for index, page := range pdf.pages {
		requireContains(t, page, fmt.Sprintf("第 %d / %d 页", index+1, totalPages), "PDF 页脚")
		if index > 0 {
			requireContains(t, page, "EvernightLogin 统计报告", "PDF 续页页眉（非空白页）")
		} else {
			requireContains(t, page, "统计报告", "PDF 首页标题")
		}
		if len(strings.TrimSpace(page)) < 80 {
			t.Fatalf("第 %d 页内容过少（疑似空白页）: %q", index+1, page)
		}
	}
	text := pdf.allText()
	requireContains(t, text, "（续）", "跨页表头续标")
	requireContains(t, text, "EV-ROW-001", "错误明细证据编号")
	requireContains(t, text, "EV-ROW-045", "错误明细证据编号")
	requireContains(t, text, "ERR_LONG_"+strings.Repeat("X", 18)+"_00", "长错误码")
	requireContains(t, text, "ERR_LONG_"+strings.Repeat("X", 18)+"_44", "长错误码")
	if strings.Contains(string(env.artifactBytes(t, reportID, FormatPDF)), "/FontFile3") {
		t.Fatal("PDF 不应使用 CFF 字体")
	}
}

// TestPDFMissingGlyphFailsClosed 验证字体缺字时拒绝输出 PDF，而不是把缺字静默替换
// 成空格（dep-review 明确提示 gopdf 默认行为）。
func TestPDFMissingGlyphFailsClosed(t *testing.T) {
	env := newFontTestEnv(t)
	if !env.service.PDFAvailable() {
		t.Fatal("配置有效字体后 PDFAvailable 应为 true")
	}
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.rows = []stats.ErrorRow{{
		ErrorCode: "\U0010FFF0", // 平面 16 私用区，Noto Sans SC 不含该字形
		Category:  stats.CategoryUnknown, Severity: stats.SeverityUnknown,
		RawEvents: 1, FailedRequests: 1, Share: 1,
		FirstSeen: baseTime.Add(-time.Hour), LastSeen: baseTime,
		Growth: stats.Growth{Kind: stats.GrowthUnavailable}, DataStatus: stats.DataComplete,
	}}
	ctx := context.Background()
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	view, err := env.service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建 PDF 报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	if err := env.service.GenerateHandler(ctx, job); err == nil {
		t.Fatal("字体缺字时 PDF 生成应失败")
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询失败报告出错: %v", err)
	}
	if final.State != StateFailed || final.ErrorCode != string(CodeReportGeneration) {
		t.Fatalf("缺字终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if entries := env.outputEntries(t); len(entries) != 0 {
		t.Fatalf("缺字失败后不应残留产物: %v", entries)
	}
}

// TestPDFFontValidation 验证字体路径/摘要/格式的 fail-closed 校验。
func TestPDFFontValidation(t *testing.T) {
	env := newTestEnv(t)
	fontPath := reportTestPDFFontPath(t)
	// 相对路径。
	options := newTestOptions(env)
	options.FontPath = "fonts/NotoSansSC-Regular.ttf"
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("相对字体路径错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 不存在的绝对路径。
	options = newTestOptions(env)
	options.FontPath = filepath.Join(env.outputDir, "missing.ttf")
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("不存在字体错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 非预审摘要默认拒绝（即使摘要与文件本身自洽也不放行）。
	options = newTestOptions(env)
	options.FontPath = fontPath
	options.FontSHA256 = strings.Repeat("0", 64)
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("非预审摘要未显式开关错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 显式受信开关只放行“摘要匹配的字体”，摘要不符仍拒绝。
	options = newTestOptions(env)
	options.FontPath = fontPath
	options.FontSHA256 = strings.Repeat("0", 64)
	options.AllowUnreviewedPDFFont = true
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("开关放行后摘要不符错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 显式开关放行后仍要求真实 TrueType（sfnt 魔数），非 TTF 内容拒绝。
	fakePath := filepath.Join(testutil.TempDir(t), "fake.ttf")
	fakeData := make([]byte, 2<<20)
	if err := os.WriteFile(fakePath, fakeData, 0o600); err != nil {
		t.Fatalf("写测试字体失败: %v", err)
	}
	options = newTestOptions(env)
	options.FontPath = fakePath
	options.FontSHA256 = sha256Hex(fakeData)
	options.AllowUnreviewedPDFFont = true
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("非 TTF 字体错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 有效字体 + 预审摘要（含显式开关）→ 构造成功且 PDFAvailable。
	options = newTestOptions(env)
	options.FontPath = fontPath
	options.FontSHA256 = RequiredPDFFontSHA256
	options.AllowUnreviewedPDFFont = true
	service, err := New(options)
	if err != nil {
		t.Fatalf("有效字体构造失败: %v", err)
	}
	if !service.PDFAvailable() {
		t.Fatal("有效字体应启用 PDF 输出")
	}
	// 未加载字体直接调用渲染 → 明确错误，不 panic。
	if _, err := renderPDF(context.Background(), Snapshot{}, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("无字体渲染错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestMarkdownFrontMatterChaptersAndEvidence 验证 Markdown 固定章节、机器可读元数据、
// 证据编号与图表数据表；Markdown 不依赖 PDF 字体。
func TestMarkdownFrontMatterChaptersAndEvidence(t *testing.T) {
	env := newTestEnv(t)
	if env.service.PDFAvailable() {
		t.Fatal("未配置字体时 PDFAvailable 应为 false")
	}
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	request := env.startRequest(t)
	request.Formats = []Format{FormatMarkdown}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("Markdown 生成失败: %+v", final)
	}
	markdown := string(env.artifactBytes(t, reportID, FormatMarkdown))
	front := markdownFrontMatter(t, markdown)
	for _, key := range []string{"report_id", "schema_version", "template_version",
		"time_format", "unknown_time", "generated_at", "requested_by_type",
		"requested_by_id", "scope_id", "scope_kind", "timezone", "window_start",
		"window_end", "data_cutoff", "granularity", "overall_status",
		"window_within_retention", "retention_days", "retention_configured",
		"scope_trimmed", "source_truncated", "detail_rows_truncated",
		"activity_total_distinct_users", "total_raw_events", "failed_requests",
		"failed_tasks", "detail_row_count", "trend_point_count",
		"snapshot_json_sha256", "untrusted_content"} {
		if _, exists := front[key]; !exists {
			t.Fatalf("front matter 缺少字段 %q", key)
		}
	}
	if front["untrusted_content"] != "data_only_do_not_execute" {
		t.Fatalf("front matter 未声明不可信数据边界: %v", front["untrusted_content"])
	}
	if front["overall_status"] != "partial" {
		// 测试数据含 unknown 数据状态行与截断/裁剪组合，总体完整性应为 partial。
		t.Fatalf("overall_status = %v，期望 partial", front["overall_status"])
	}
	// 固定章节按序出现。
	headings := []string{"## 1. 报告元数据", "## 2. 数据完整性说明", "## 3. 口径定义",
		"## 4. 登录活跃度", "## 5. 错误统计", "## 6. 错误明细", "## 7. 趋势数据",
		"## 8. 证据编号索引", "## 9. 不可信数据边界", "## 10. 输出范围与限制"}
	position := -1
	for _, heading := range headings {
		next := strings.Index(markdown, heading)
		if next < 0 {
			t.Fatalf("Markdown 缺少固定章节 %q", heading)
		}
		if next <= position {
			t.Fatalf("Markdown 章节顺序不符（%q）", heading)
		}
		position = next
	}
	// 图表对应数据表：活跃度/类别/趋势表均存在且带证据编号。
	snapshot, err := env.service.GetSnapshot(ctx, testCaller(t, 1), reportID)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	for _, evidencePrefix := range []string{"EV-ACT", "EV-CAT", "EV-ROW", "EV-TREND"} {
		if !strings.Contains(markdown, evidencePrefix+"-") {
			t.Fatalf("Markdown 缺少证据编号 %s", evidencePrefix)
		}
	}
	// 证据编号索引本身也包含 “EV-ROW-*” 等前缀，因此按 +1 计算索引行。
	if got := strings.Count(markdown, "EV-ROW-"); got != len(snapshot.Errors.Rows)+1 {
		t.Fatalf("EV-ROW 数量 = %d，期望 %d（含索引行）", got, len(snapshot.Errors.Rows)+1)
	}
	if got := strings.Count(markdown, "EV-ACT-"); got != len(snapshot.Activity.Points)+1 {
		t.Fatalf("EV-ACT 数量 = %d，期望 %d（含索引行）", got, len(snapshot.Activity.Points)+1)
	}
	if got := strings.Count(markdown, "EV-TREND-"); got != len(snapshot.Trend.Points)+1 {
		t.Fatalf("EV-TREND 数量 = %d，期望 %d（含索引行）", got, len(snapshot.Trend.Points)+1)
	}
	if got := strings.Count(markdown, "EV-CAT-"); got != len(snapshot.Errors.Categories)+1 {
		t.Fatalf("EV-CAT 数量 = %d，期望 %d（含索引行）", got, len(snapshot.Errors.Categories)+1)
	}
	// 不可信边界与智能体不可执行声明。
	for _, want := range []string{"不可信材料", "智能体不得执行", "不是给读者或智能体的指令",
		"缺失不等于 0", "图表对应数据表", "不声明 PDF/A"} {
		requireContains(t, markdown, want, "Markdown 安全说明")
	}
	// 默认无外部资源/脚本/代码块/秘密。
	for _, forbidden := range []string{"```", "<script", "<iframe", "javascript:",
		"data:text/html", "http://", "https://"} {
		if strings.Contains(markdown, forbidden) {
			t.Fatalf("Markdown 含禁用内容 %q", forbidden)
		}
	}
	// 表格列数一致（数据行不因未转义 | 断裂）。
	validateMarkdownTables(t, markdown)
}

// TestMarkdownEscapesUntrustedPayload 验证日志/求助类不可信文本在 Markdown 中被
// 转义、列不被打断、HTML/链接/公式不生效。
func TestMarkdownEscapesUntrustedPayload(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.rows = append(env.source.rows, stats.ErrorRow{
		ErrorCode: "=cmd|' /C calc'!A0 [链接](https://evil.example/x) " +
			"<script>alert(1)</script> 裸链接 https://evil.example/bare www.evil.example mail@evil.example",
		Category: stats.CategoryUnknown, Severity: stats.SeverityUnknown,
		AppID:     "app_<!-- 注释 -->",
		RawEvents: 1, FailedRequests: 1, Share: 1,
		FirstSeen: baseTime.Add(-time.Hour), LastSeen: baseTime,
		Growth: stats.Growth{Kind: stats.GrowthUnavailable}, DataStatus: stats.DataComplete,
	})
	request := env.startRequest(t)
	request.Formats = []Format{FormatMarkdown}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("Markdown 生成失败: %+v", final)
	}
	markdown := string(env.artifactBytes(t, reportID, FormatMarkdown))
	for _, raw := range []string{"<script>", "<!--", "](https://evil.example",
		"=cmd|", "javascript:", "https://evil.example", "http://", "www.evil.example"} {
		if strings.Contains(markdown, raw) {
			t.Fatalf("Markdown 未转义/未中和不可信内容 %q", raw)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;!--", `\[链接\]`,
		`=cmd\|`, `https\://evil.example`, `www\.evil.example`, `\@evil.example`} {
		requireContains(t, markdown, escaped, "Markdown 转义结果")
	}
	// GFM 自动链接必须不存在未转义的 `://`、`www.` 或裸 `@`（L2）。
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(^|[^\\])://`),
		regexp.MustCompile(`(^|[^\\])www\.`),
		regexp.MustCompile(`(^|[^\\])[A-Za-z0-9._%+-]@`),
	} {
		if pattern.MatchString(markdown) {
			t.Fatalf("Markdown 仍含可自动链接的裸 URL/邮箱: %s", pattern.String())
		}
	}
	validateMarkdownTables(t, markdown)
}

// TestRenderSnapshotHonorsContext 验证渲染入口在上下文已取消时拒绝继续（渲染超时/
// 取消机制），防止任务取消后仍长时间渲染。
func TestRenderSnapshotHonorsContext(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	request := env.startRequest(t)
	request.Formats = []Format{FormatHTML}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("基线报告生成失败: %+v", final)
	}
	snapshot, err := env.service.GetSnapshot(ctx, testCaller(t, 1), reportID)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, format := range []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF, FormatMarkdown} {
		if _, err := env.service.renderSnapshot(cancelled, snapshot, format); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s 取消上下文渲染错误 = %v，期望 context.Canceled", format, err)
		}
	}
}

// TestFormatAndArtifactNaming 验证新增格式的稳定集合、排序与产物扩展名。
func TestFormatAndArtifactNaming(t *testing.T) {
	for _, format := range []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF,
		FormatMarkdown} {
		if !format.Valid() {
			t.Fatalf("格式 %q 应有效", format)
		}
	}
	if Format("xml").Valid() {
		t.Fatal("未知格式不应有效")
	}
	ordered := formatSortedFormats([]Format{FormatMarkdown, FormatPDF, FormatJSON,
		FormatHTML, FormatCSV, FormatPDF})
	want := []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF, FormatMarkdown}
	if len(ordered) != len(want) {
		t.Fatalf("格式排序长度 = %d，期望 %d", len(ordered), len(want))
	}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("格式排序第 %d 位 = %q，期望 %q", index, ordered[index], want[index])
		}
	}
	markdownName := artifactFilenameForTest(FormatMarkdown)
	if !strings.HasSuffix(markdownName, ".md") {
		t.Fatalf("Markdown 文件名 = %q，期望 .md 扩展名", markdownName)
	}
	if !validateArtifactName(markdownName, FormatMarkdown) {
		t.Fatal("Markdown 受控文件名应通过校验")
	}
	if validateArtifactName("report_x.markdown", FormatMarkdown) {
		t.Fatal("非受控 Markdown 扩展名不应通过校验")
	}
	if validateArtifactName(markdownName, FormatPDF) {
		t.Fatal("跨格式扩展名不应通过校验")
	}
	for _, format := range []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF} {
		if !validateArtifactName(artifactFilenameForTest(format), format) {
			t.Fatalf("格式 %q 受控文件名校验失败", format)
		}
	}
}

// TestWritePDFEvidenceArtifact 是人工/外部工具核验的辅助入口：设置了
// REPORT_TEST_PDF_OUTPUT 时把实际渲染的 PDF 写到该路径（%TEMP% 下的证据文件，
// 不进入仓库），便于用 PDF 阅读器/渲染器目检中文、分页、表头与长字段。未设置时
// 跳过，不产生任何文件。
func TestWritePDFEvidenceArtifact(t *testing.T) {
	outputPath := strings.TrimSpace(os.Getenv("REPORT_TEST_PDF_OUTPUT"))
	if outputPath == "" {
		t.Skip("未设置 REPORT_TEST_PDF_OUTPUT：跳过 PDF 证据文件导出")
	}
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	rows := make([]stats.ErrorRow, 0, 40)
	for index := 0; index < 40; index++ {
		rows = append(rows, stats.ErrorRow{
			ErrorCode: fmt.Sprintf("ERR_LONG_%s_%02d", strings.Repeat("X", 18), index),
			Category:  stats.CategoryFailure, Severity: stats.SeverityError,
			AppID: fmt.Sprintf("app_%03d", index), RawEvents: int64(50 - index),
			FailedRequests: 1, Share: 0.01,
			FirstSeen:  baseTime.Add(-time.Duration(index) * time.Minute),
			LastSeen:   baseTime,
			Growth:     stats.Growth{Kind: stats.GrowthUnavailable},
			DataStatus: stats.DataComplete,
		})
	}
	env.source.rows = rows
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("证据 PDF 生成失败: %+v", final)
	}
	data := env.artifactBytes(t, reportID, FormatPDF)
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		t.Fatalf("写入证据 PDF 失败: %v", err)
	}
	pdf := loadPDFSummary(t, data)
	if pdf.pageCount() < 3 {
		t.Fatalf("证据 PDF 页数 = %d，期望至少 3 页", pdf.pageCount())
	}
	t.Logf("证据 PDF 已写入 %s（%d 字节，%d 页，SHA-256 %s）", outputPath,
		len(data), pdf.pageCount(), sha256Hex(data))
}

// longErrorRows 构造用于渲染规模/取消场景的较慢长表数据。
func longErrorRows(count int) []stats.ErrorRow {
	rows := make([]stats.ErrorRow, 0, count)
	for index := 0; index < count; index++ {
		rows = append(rows, stats.ErrorRow{
			ErrorCode: fmt.Sprintf("ERR_LONG_%s_%03d", strings.Repeat("X", 18), index),
			Category:  stats.CategoryFailure, Severity: stats.SeverityError,
			AppID: fmt.Sprintf("app_%03d", index), RawEvents: int64(count - index),
			FailedRequests: 1, Share: 0.01,
			FirstSeen:  baseTime.Add(-time.Duration(index) * time.Minute),
			LastSeen:   baseTime,
			Growth:     stats.Growth{Kind: stats.GrowthUnavailable},
			DataStatus: stats.DataComplete,
		})
	}
	return rows
}

// hasAuditErrorCode 报告审计事件中是否出现指定错误码。
func hasAuditErrorCode(recorder *fakeRecorder, errorCode string) bool {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for _, event := range recorder.events {
		if event.ErrorCode == errorCode {
			return true
		}
	}
	return false
}

// TestGenerateRenderPhaseCanceled 验证渲染阶段（含 PDF 渲染窗口）的取消按步骤 77
// 语义收敛为 cancelled/TASK_CANCELLED，而不是 failed/REPORT_GENERATION_FAILED（B1）。
func TestGenerateRenderPhaseCanceled(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.rows = longErrorRows(60)
	ctx := context.Background()
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}

	// 路径一：进入处理器时上下文已取消（renderSnapshot 入口即返回取消）。
	view, err := env.service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := env.service.GenerateHandler(cancelled, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("入口取消生成错误 = %v，期望 context.Canceled", err)
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询取消报告失败: %v", err)
	}
	if final.State != StateCancelled || final.ErrorCode != string(CodeTaskCancelled) {
		t.Fatalf("入口取消终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if len(env.outputEntries(t)) != 0 {
		t.Fatalf("入口取消后不应有产物: %v", env.outputEntries(t))
	}
	if !hasAuditErrorCode(env.recorder, string(CodeTaskCancelled)) {
		t.Fatal("取消未以 TASK_CANCELLED 写失败审计")
	}

	// 路径二：PDF 渲染进行中取消（长表渲染窗口内 50ms 后取消）。
	env.source.rows = longErrorRows(500)
	view, err = env.service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建长表报告失败: %v", err)
	}
	job = env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	midRender, cancelMid := context.WithCancel(context.Background())
	defer cancelMid()
	timer := time.AfterFunc(50*time.Millisecond, cancelMid)
	defer timer.Stop()
	err = env.service.GenerateHandler(midRender, job)
	if err == nil {
		t.Fatal("渲染中取消应返回错误")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("渲染中取消错误 = %v，期望 context.Canceled", err)
	}
	final, err = env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询渲染中取消报告失败: %v", err)
	}
	if final.State != StateCancelled || final.ErrorCode != string(CodeTaskCancelled) {
		t.Fatalf("渲染中取消终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if len(env.outputEntries(t)) != 0 {
		t.Fatalf("渲染中取消后不应有产物: %v", env.outputEntries(t))
	}
	if !hasAuditErrorCode(env.recorder, string(CodeTaskCancelled)) {
		t.Fatal("渲染中取消未以 TASK_CANCELLED 写失败审计")
	}
}

// TestGenerateRenderPhaseTimeout 验证渲染阶段超时收敛为 failed/TASK_TIMEOUT，
// 而不是 REPORT_GENERATION_FAILED（B1）。
func TestGenerateRenderPhaseTimeout(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.rows = longErrorRows(500)
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	view, err := env.service.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	// 快照构建（替身来源）远快于 120ms；超时发生在 PDF 渲染长表期间。
	renderCtx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	err = env.service.GenerateHandler(renderCtx, job)
	if err == nil {
		t.Fatal("渲染中超时应返回错误")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("渲染中超时错误 = %v，期望 context.DeadlineExceeded", err)
	}
	final, err := env.service.Get(context.Background(), testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询超时报告失败: %v", err)
	}
	if final.State != StateFailed || final.ErrorCode != string(CodeTaskTimeout) {
		t.Fatalf("渲染中超时终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if len(env.outputEntries(t)) != 0 {
		t.Fatalf("渲染中取消后不应有产物: %v", env.outputEntries(t))
	}
	if !hasAuditErrorCode(env.recorder, string(CodeTaskTimeout)) {
		t.Fatal("超时未以 TASK_TIMEOUT 写失败审计")
	}
}

// TestPDFOverlongCategoryLabelBounded 验证超宽类别图表标签截断循环有界完成（安全 M1）：
// 直接给渲染器注入远超图表标签区宽度的类别名，不得自旋，仍能在墙钟内渲染成功且
// 数据表保留完整文本。
func TestPDFOverlongCategoryLabelBounded(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	request := env.startRequest(t)
	request.Formats = []Format{FormatHTML}
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("基线报告生成失败: %+v", final)
	}
	snapshot, err := env.service.GetSnapshot(ctx, testCaller(t, 1), reportID)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	longCategory := strings.Repeat("超宽类别标签", 20)
	snapshot.Errors.Categories = []CategoryData{{
		Category: longCategory, Severity: "error", RawEvents: 7,
		FailedRequests: 3,
	}}
	// 有界超时：若截断循环回归为无限循环，用例会在 60s 内以超时失败而不是挂死。
	renderCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	data, err := renderPDF(renderCtx, snapshot, env.service.font)
	if err != nil {
		t.Fatalf("超宽类别 PDF 渲染失败（截断循环应有界）: %v", err)
	}
	pdf := loadPDFSummary(t, data)
	if !strings.Contains(pdf.allText(), "…") {
		t.Fatal("超宽图表标签未被截断为省略号")
	}
	// 数据表仍保留完整类别名（不因图表截断而丢数据）。
	requireContains(t, pdf.allText(), longCategory, "完整类别名")
}

// TestPDFRenderInputLimits 验证渲染前输入规模上限：超过明细行数上限直接拒绝，
// 不进入渲染（安全 L4 的资源边界）。
func TestPDFRenderInputLimits(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.rows = longErrorRows(pdfMaxInputRows + 1)
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	ctx := context.Background()
	view, err := env.service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	if err := env.service.GenerateHandler(ctx, job); err == nil {
		t.Fatal("超过输入行数上限时渲染应失败")
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询失败报告出错: %v", err)
	}
	if final.State != StateFailed || final.ErrorCode != string(CodeReportGeneration) {
		t.Fatalf("输入超限终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if len(env.outputEntries(t)) != 0 {
		t.Fatalf("输入超限失败后不应有产物: %v", env.outputEntries(t))
	}
}

// validateMarkdownTables 校验 Markdown 文档中每个表格块的数据行列数与表头一致。
func validateMarkdownTables(t *testing.T, document string) {
	t.Helper()
	lines := strings.Split(document, "\n")
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		blockStart := index
		block := make([]string, 0, 8)
		for index < len(lines) {
			candidate := strings.TrimSpace(lines[index])
			if !strings.HasPrefix(candidate, "|") || !strings.HasSuffix(candidate, "|") {
				break
			}
			block = append(block, candidate)
			index++
		}
		index--
		if len(block) < 2 {
			continue
		}
		columns := len(splitMarkdownRow(block[0]))
		if columns == 0 {
			t.Fatalf("第 %d 行表格缺少列", blockStart+1)
		}
		for rowIndex := 1; rowIndex < len(block); rowIndex++ {
			if rowIndex == 1 {
				// 分隔行每列只有 ---。
				if cells := splitMarkdownRow(block[rowIndex]); len(cells) != columns {
					t.Fatalf("表格分隔行列数 = %d，期望 %d（第 %d 行）",
						len(cells), columns, blockStart+rowIndex+1)
				}
				continue
			}
			if cells := splitMarkdownRow(block[rowIndex]); len(cells) != columns {
				t.Fatalf("表格数据行列数 = %d，期望 %d（第 %d 行）",
					len(cells), columns, blockStart+rowIndex+1)
			}
		}
	}
}

// TestMarkdownAndPDFRenderTimeoutBounds 验证渲染资源常量是有限正数（超时/页数/
// 趋势行数边界），避免“无限渲染”配置。
func TestMarkdownAndPDFRenderTimeoutBounds(t *testing.T) {
	if pdfRenderTimeout <= 0 || pdfRenderTimeout > 5*time.Minute {
		t.Fatalf("pdfRenderTimeout = %v 超出合理边界", pdfRenderTimeout)
	}
	if pdfMaxPages <= 0 || pdfMaxPages > 1000 {
		t.Fatalf("pdfMaxPages = %d 超出合理边界", pdfMaxPages)
	}
	if pdfMaxTrendRows <= 0 || pdfMaxTrendRows > 5000 {
		t.Fatalf("pdfMaxTrendRows = %d 超出合理边界", pdfMaxTrendRows)
	}
	if pdfMaxInputRows <= 0 || pdfMaxInputRows > 5000 {
		t.Fatalf("pdfMaxInputRows = %d 超出合理边界", pdfMaxInputRows)
	}
	if pdfMaxInputTrendPoints <= 0 || pdfMaxInputTrendPoints > 100000 {
		t.Fatalf("pdfMaxInputTrendPoints = %d 超出合理边界", pdfMaxInputTrendPoints)
	}
	if pdfMaxArtifactBytes <= 0 || pdfMaxArtifactBytes > 128*1024*1024 {
		t.Fatalf("pdfMaxArtifactBytes = %d 超出合理边界", pdfMaxArtifactBytes)
	}
	if len(RequiredPDFFontSHA256) != hex.EncodedLen(sha256.Size) {
		t.Fatalf("RequiredPDFFontSHA256 长度 = %d", len(RequiredPDFFontSHA256))
	}
	if RequiredPDFFontBytes != 10540644 {
		t.Fatalf("RequiredPDFFontBytes = %d", RequiredPDFFontBytes)
	}
}
