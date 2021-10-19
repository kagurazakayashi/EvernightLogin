package reports

// 步骤 93 验收探针：同一固定快照下 HTML/PDF/Markdown/CSV/JSON 五种格式的数据、
// 时间口径（时区/窗口边界/粒度）、缺失说明与权限一致，以及下载权限撤销后五种格式
// 均被拒绝、异步取消“请求受理”与“实际取消”状态不被混写。
//
// 边界说明：本探针使用本包既有测试环境（临时产物目录、真实渲染器、明确标注的
// 统计来源/授权/取消替身），不冒充生产权限引擎或宿主任务执行器；PDF 使用预审
// Noto Sans SC 静态字体，字体缺失时由既有 helper 显式 skip（不把未跑当通过）。

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// step93FiveFormats 返回本步核对的全部报告格式。
func step93FiveFormats() []Format {
	return []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF, FormatMarkdown}
}

// TestStep93FiveFormatsSameSnapshotWindowAndMissingNotes 核对五格式同源数据、时间
// 口径与缺失说明一致（缺失/裁剪/截断必须显式表达，不伪造零值）。
func TestStep93FiveFormatsSameSnapshotWindowAndMissingNotes(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	// 构造部分不完整数据：窗口不在保留期、保留期未配置、来源截断、范围裁剪、
	// 模块未启用。五种格式都必须表达“缺失/不完整/裁剪”，且数值口径同一快照。
	env.source.hasMore = true
	env.source.completeness = stats.Completeness{
		WindowWithinRetention: false, RetentionDays: 30, RetentionConfigured: false,
		RetentionCutoff: baseTime.AddDate(0, 0, -30),
		MissingIntervals: []stats.MissingInterval{{
			Start: baseTime.AddDate(0, 0, -2), End: baseTime.AddDate(0, 0, -30),
			Reason: "retention"}},
		ScopeTrimmed: true, SourceTruncated: true,
		ModulesNotEnabled: []stats.Module{stats.ModuleBackup},
	}
	request := env.startRequest(t)
	request.Formats = step93FiveFormats()
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("报告状态 = %s，期望 succeeded: %s", final.State, final.ErrorCode)
	}
	if final.OverallStatus != string(stats.DataPartial) {
		t.Fatalf("总体完整性 = %s，期望 partial", final.OverallStatus)
	}
	if len(final.Artifacts) != len(step93FiveFormats()) {
		t.Fatalf("产物数量 = %d，期望 %d", len(final.Artifacts), len(step93FiveFormats()))
	}
	// 产物元数据完整且摘要自洽。
	artifactSHA := map[Format]string{}
	for _, artifact := range final.Artifacts {
		if !artifact.Available || artifact.Bytes <= 0 || len(artifact.SHA256) != 64 {
			t.Fatalf("产物元数据不完整: %+v", artifact)
		}
		artifactSHA[artifact.Format] = artifact.SHA256
	}

	// ---- JSON：时间口径与完整性事实的机器可读基准 ----
	jsonBytes := env.artifactBytes(t, reportID, FormatJSON)
	if artifactSHA[FormatJSON] != sha256Hex(jsonBytes) {
		t.Fatal("JSON 产物摘要与元数据不一致")
	}
	var document map[string]any
	if err := json.Unmarshal(jsonBytes, &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	reportMeta := document["report"].(map[string]any)
	window := reportMeta["window"].(map[string]any)
	timezone := window["timezone"].(string)
	windowStart := window["start"].(string)
	windowEnd := window["end"].(string)
	granularity := window["granularity"].(string)
	if timezone != "Asia/Shanghai" || granularity != string(stats.GranularityDay) {
		t.Fatalf("JSON 时间口径 = %s / %s", timezone, granularity)
	}
	completeness := document["completeness"].(map[string]any)
	for field, want := range map[string]bool{
		"window_within_retention": false,
		"scope_trimmed":           true,
		"source_truncated":        true,
	} {
		if got, ok := completeness[field].(bool); !ok || got != want {
			t.Fatalf("JSON completeness.%s = %v，期望 %v", field, completeness[field], want)
		}
	}
	if intervals, ok := completeness["missing_intervals"].([]any); !ok || len(intervals) == 0 {
		t.Fatalf("JSON 缺少 missing_intervals: %v", completeness["missing_intervals"])
	}
	activity := document["activity"].(map[string]any)
	errorsData := document["errors"].(map[string]any)
	activityTotal := int64(activity["total_distinct_users"].(float64))
	rawEvents := int64(errorsData["total_raw_events"].(float64))
	failedRequests := int64(errorsData["failed_requests"].(float64))
	failedTasks := int64(errorsData["failed_tasks"].(float64))

	// ---- CSV：元数据行与 JSON 同一口径；缺失说明以 note 行显式表达 ----
	csvRecords, err := csv.NewReader(strings.NewReader(
		string(env.artifactBytes(t, reportID, FormatCSV)))).ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	csvMeta := map[string]string{}
	noteRows := make([]string, 0, 8)
	csvTotals := map[string]string{}
	for _, record := range csvRecords {
		if len(record) < 16 {
			continue
		}
		if record[0] == "meta" {
			csvMeta[record[1]] = record[10]
		}
		if record[0] == "note" {
			noteRows = append(noteRows, record[15])
		}
		if record[0] == "activity_total" && record[9] == "total_distinct_users" {
			csvTotals["total_distinct_users"] = record[10]
		}
		if record[0] == "errors_total" {
			csvTotals[record[9]] = record[10]
		}
	}
	for key, want := range map[string]string{
		"timezone": timezone, "window_start": windowStart,
		"window_end": windowEnd, "granularity": granularity,
	} {
		if csvMeta[key] != want {
			t.Fatalf("CSV meta %s = %q，JSON 为 %q", key, csvMeta[key], want)
		}
	}
	if csvMeta["overall_status"] != string(stats.DataPartial) {
		t.Fatalf("CSV overall_status = %q", csvMeta["overall_status"])
	}
	for metric, want := range map[string]string{
		"total_distinct_users": itoa(activityTotal),
		"total_raw_events":     itoa(rawEvents),
		"failed_requests":      itoa(failedRequests),
		"failed_tasks":         itoa(failedTasks),
	} {
		if csvTotals[metric] != want {
			t.Fatalf("CSV %s = %q，JSON 为 %q", metric, csvTotals[metric], want)
		}
	}
	joinedNotes := strings.Join(noteRows, " ")
	for _, keyword := range []string{"未知", "不完整", "保留", "裁剪"} {
		if !strings.Contains(joinedNotes, keyword) {
			t.Fatalf("CSV 缺失说明缺少 %q: %s", keyword, joinedNotes)
		}
	}

	// ---- Markdown：front matter 与 JSON 同一时间口径/完整性，摘要绑定 JSON 产物 ----
	markdown := string(env.artifactBytes(t, reportID, FormatMarkdown))
	front := markdownFrontMatter(t, markdown)
	for key, want := range map[string]string{
		"timezone": timezone, "window_start": windowStart,
		"window_end": windowEnd, "granularity": granularity,
		"overall_status":          string(stats.DataPartial),
		"scope_trimmed":           "true",
		"source_truncated":        "true",
		"missing_intervals":       "1",
		"window_within_retention": "false",
	} {
		if got, ok := front[key].(string); ok {
			if got != want {
				t.Fatalf("Markdown front matter %s = %q，期望 %q", key, got, want)
			}
			continue
		}
		if got := strings.TrimSpace(anyToString(front[key])); got != want {
			t.Fatalf("Markdown front matter %s = %q，期望 %q", key, got, want)
		}
	}
	if front["snapshot_json_sha256"] != artifactSHA[FormatJSON] {
		t.Fatalf("Markdown 快照摘要与 JSON 产物不一致: %v", front["snapshot_json_sha256"])
	}
	for _, want := range []string{"部分（不完整）", "未知（不可当作 0）", "缺失不等于 0"} {
		requireContains(t, markdown, want, "Markdown 缺失说明")
	}

	// ---- HTML：与 JSON 同一数值/时区/窗口，缺失状态可见 ----
	htmlText := string(env.artifactBytes(t, reportID, FormatHTML))
	requireContains(t, htmlText, "时区 / 粒度</td><td>"+timezone+" / "+granularity+"</td>",
		"HTML 时间口径")
	requireContains(t, htmlText, "统计窗口</td><td>"+windowStart+" 至 "+windowEnd,
		"HTML 窗口边界")
	requireContains(t, htmlText, "部分（不完整）", "HTML 完整性")
	requireContains(t, htmlText, "未知（不可当作 0）", "HTML 未知状态")
	for _, want := range []string{
		"窗口内成功认证去重用户数：<strong>" + itoa(activityTotal) + "</strong>",
		"原始错误事件次数</td><td>" + itoa(rawEvents) + "</td>",
		"去重失败请求数</td><td>" + itoa(failedRequests) + "</td>",
		"去重失败任务数</td><td>" + itoa(failedTasks) + "</td>",
	} {
		requireContains(t, htmlText, want, "HTML 数值一致性")
	}

	// ---- PDF：分页/中文/窗口/缺失说明；每页有页脚，无空白页 ----
	pdfData := env.artifactBytes(t, reportID, FormatPDF)
	pdf := loadPDFSummary(t, pdfData)
	if pdf.pageCount() < 2 {
		t.Fatalf("PDF 页数 = %d，期望至少 2 页（分页渲染）", pdf.pageCount())
	}
	totalPages := pdf.pageCount()
	for index, page := range pdf.pages {
		if strings.TrimSpace(page) == "" {
			t.Fatalf("PDF 第 %d 页为空白页", index+1)
		}
		requireContains(t, page, fmtPageFooter(index+1, totalPages), "PDF 页脚")
	}
	pdfText := pdf.allText()
	for _, want := range []string{"时区 / 粒度", timezone + " / " + granularity,
		windowStart, "部分（不完整）", "未知（不可当作 0）", "缺失不等于 0",
		"统计报告", reportID, "登录活跃度", "错误明细"} {
		requireContains(t, pdfText, pdfFlatten(want), "PDF 文本")
	}
	for _, want := range []string{itoa(activityTotal), itoa(rawEvents)} {
		requireContains(t, pdfText, want, "PDF 数值")
	}
	rawPDF := string(pdfData)
	requireContains(t, rawPDF, "/FontFile2", "PDF 嵌入 TrueType 字体（中文可读）")
	requireContains(t, rawPDF, "/ToUnicode", "PDF 字体 ToUnicode 映射（可提取中文）")
	if artifactSHA[FormatPDF] != sha256Hex(pdfData) {
		t.Fatal("PDF 产物摘要与元数据不一致")
	}
}

// TestStep93FiveFormatsDownloadPermissionRevocation 核对同一报告五种格式的下载权限
// 一致：撤销导出权限后，直接打开与已签发的一次性令牌兑换都必须被拒绝。
func TestStep93FiveFormatsDownloadPermissionRevocation(t *testing.T) {
	env := newFontTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	request := env.startRequest(t)
	request.Formats = step93FiveFormats()
	reportID, final := env.startAndGenerate(t, request)
	if final.State != StateSucceeded {
		t.Fatalf("报告状态 = %s", final.State)
	}
	ctx := context.Background()
	caller := testCaller(t, 1)
	tickets := map[Format]string{}
	for _, format := range step93FiveFormats() {
		file, err := env.service.OpenFile(ctx, caller, reportID, format)
		if err != nil || file.Bytes == 0 || len(file.SHA256) != 64 {
			t.Fatalf("撤销前 %s 下载失败: %v", format, err)
		}
		ticket, err := env.service.IssueDownloadTicket(ctx, caller, reportID, format)
		if err != nil {
			t.Fatalf("签发 %s 下载令牌失败: %v", format, err)
		}
		tickets[format] = ticket.Token
	}
	// 撤销导出权限：五种格式的直接下载全部拒绝。
	env.authorizer.deny(PermissionExport, "system")
	for _, format := range step93FiveFormats() {
		if _, err := env.service.OpenFile(ctx, caller, reportID, format); !errors.Is(
			err, ErrAccessDenied) {
			t.Fatalf("撤销导出后 %s 下载错误 = %v，期望 ErrAccessDenied", format, err)
		}
	}
	// 撤销前已签发的一次性令牌不能绕过当前权限：兑换同样拒绝。
	for _, format := range step93FiveFormats() {
		if _, err := env.service.RedeemDownloadTicket(ctx, caller,
			tickets[format]); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("撤销导出后 %s 令牌兑换错误 = %v，期望 ErrAccessDenied", format, err)
		}
	}
	// 恢复权限后仍可下载（撤销是即时生效而非永久破坏），且令牌已一次性消费。
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	for _, format := range step93FiveFormats() {
		file, err := env.service.OpenFile(ctx, caller, reportID, format)
		if err != nil || file.Bytes == 0 {
			t.Fatalf("恢复权限后 %s 下载失败: %v", format, err)
		}
	}
	if _, err := env.service.RedeemDownloadTicket(ctx, caller,
		tickets[FormatHTML]); err == nil {
		t.Fatal("已消费的下载令牌仍可兑换")
	}
}

// TestStep93CancelRequestIsNotActualCancel 核对取消请求与实际取消的区分：
// 服务端受理（cancel_requested）时报告状态不得被写成已取消；只有任务真正收敛为
// cancelled 后才清理产物并禁止下载。
func TestStep93CancelRequestIsNotActualCancel(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	// 任务执行器只“受理取消请求”，尚未收敛为 cancelled。
	env.canceller.state = task.StateCancelRequested
	result, err := env.service.Cancel(ctx, testCaller(t, 1), view.ID,
		"用户请求取消", "req-cancel-requested")
	if err != nil {
		t.Fatalf("取消请求失败: %v", err)
	}
	if !result.Accepted || result.State != task.StateCancelRequested {
		t.Fatalf("取消受理结果 = %+v，期望 accepted + cancel_requested", result)
	}
	afterRequest, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询报告失败: %v", err)
	}
	if afterRequest.State == StateCancelled {
		t.Fatal("取消请求受理被错误写成实际取消")
	}
	if afterRequest.State != StateQueued {
		t.Fatalf("受理取消请求后状态 = %s，期望仍是 queued（等待收敛）",
			afterRequest.State)
	}
	if !env.recorder.hasAction(ActionGenerateCancel) {
		t.Fatal("缺少取消请求审计事件")
	}
	// 任务真正收敛为 cancelled：报告收敛且不可下载。
	env.canceller.state = task.StateCancelled
	result, err = env.service.Cancel(ctx, testCaller(t, 1), view.ID,
		"用户确认取消", "req-cancel-actual")
	if err != nil || result.State != task.StateCancelled {
		t.Fatalf("实际取消结果 = %+v err=%v", result, err)
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询最终报告失败: %v", err)
	}
	if final.State != StateCancelled {
		t.Fatalf("实际取消后状态 = %s，期望 cancelled", final.State)
	}
	if _, err := env.service.OpenFile(ctx, testCaller(t, 1), view.ID,
		FormatHTML); err == nil {
		t.Fatal("已实际取消的报告仍可下载")
	}
}

// fmtPageFooter 生成 PDF 页脚文本（与渲染器口径一致）。
func fmtPageFooter(page, total int) string {
	return "第 " + itoa(int64(page)) + " / " + itoa(int64(total)) + " 页"
}

// itoa 是本文件的最小整数转字符串辅助（避免与既有 helper 命名冲突）。
func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	buf := make([]byte, 0, 20)
	for value > 0 {
		buf = append(buf, byte('0'+value%10))
		value /= 10
	}
	if negative {
		buf = append(buf, '-')
	}
	for left, right := 0, len(buf)-1; left < right; left, right = left+1, right-1 {
		buf[left], buf[right] = buf[right], buf[left]
	}
	return string(buf)
}

// anyToString 把 YAML front matter 的标量转成字符串比较。
func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case int:
		return itoa(int64(typed))
	case int64:
		return itoa(typed)
	default:
		return ""
	}
}
