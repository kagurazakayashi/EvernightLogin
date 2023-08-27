// step195_acceptance_test.go — 步骤195 验收探针：审计报告五格式真实生成/独立解析、
// 下载与查看鉴权、历史报告受控、定时任务失败不污染原始审计、PDF 缺字体 fail-closed。
//
// 边界说明（不冒充生产装配）：
//   - 真实部分：reports.Service（真实渲染/鉴权/产物）、internal/task 真实执行器、
//     真实临时 SQLite（任务存储，含全部迁移）、预审 Noto Sans SC 字体（存在时）。
//   - 明确标注的测试替身：统计来源与审计写入（合成审计数据，见根 AGENTS §8/§9），
//     以及内存版历史仓储（真实 SQLite 历史往返由 internal/reports/sqlite 包测试覆盖）。
//   - PDF 在字体缺失时由 helper 显式 skip，不把“未跑”当通过；缺字体的 fail-closed
//     由独立用例在无字体服务上验证。
package reports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// step195Formats 是本步核对的全部格式。
func step195Formats() []Format {
	return []Format{FormatHTML, FormatCSV, FormatJSON, FormatPDF, FormatMarkdown}
}

// waitStep195Terminal 有界轮询报告终态（真实执行器异步线程）。
func waitStep195Terminal(t *testing.T, service *Service, ctx context.Context,
	caller account.Caller, reportID string) ReportView {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		view, err := service.Get(ctx, caller, reportID)
		if err != nil {
			t.Fatalf("查询报告失败: %v", err)
		}
		if view.State == StateSucceeded || view.State == StateFailed ||
			view.State == StateCancelled {
			return view
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待报告终态超时，最后状态 %s", view.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// htmlVisibleText 以「去掉标签 + 反转义」的方式从 HTML 提取可见文本（独立于渲染器）。
func htmlVisibleText(document string) string {
	tagPattern := regexp.MustCompile(`<[^>]*>`)
	return html.UnescapeString(tagPattern.ReplaceAllString(document, " "))
}

// TestStep195FiveFormatsRealTaskExecutor 用真实任务执行器生成五种格式并逐格式独立解析，
// 核对同源数据/中文可读/转义安全，然后验证查看/下载/历史权限的独立授权与撤销语义。
func TestStep195FiveFormatsRealTaskExecutor(t *testing.T) {
	ctx := context.Background()
	base := newTestEnv(t)
	caller := testCaller(t, 1)
	base.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	fontPath := reportTestPDFFontPath(t)

	// 真实临时 SQLite + 全部迁移 + 真实任务执行器（异步生成）。
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "reports-step195.db")))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: base.now})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}

	history := newFakeHistoryStore()
	var service *Service
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			TaskKindReportGenerate: func(handlerCtx context.Context, job task.Job) error {
				return service.GenerateHandler(handlerCtx, job)
			},
		},
		ExecutorID: "step195-executor", MaxConcurrent: 1,
		PollInterval: task.MinPollInterval, ShutdownTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造真实任务执行器失败: %v", err)
	}
	service, err = New(Options{
		Source: base.source, Authorizer: base.authorizer, Root: base.root,
		Sensitive: base.sensitive, Audit: base.recorder,
		Enqueuer: executor, Canceller: executor, Tasks: executor,
		History: history, OutputDir: testutil.TempDir(t),
		FontPath: fontPath, MaxDetailRows: 50, Now: base.now,
	})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	if err := executor.Start(ctx); err != nil {
		t.Fatalf("启动真实执行器失败: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = executor.Stop(stopCtx)
	})

	request := base.startRequest(t)
	request.Formats = step195Formats()
	view, err := service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建五格式报告失败: %v", err)
	}
	final := waitStep195Terminal(t, service, ctx, caller, view.ID)
	if final.State != StateSucceeded {
		t.Fatalf("报告终态 = %s，期望 succeeded: code=%s reason=%s",
			final.State, final.ErrorCode, final.FailureReason)
	}
	if len(final.Artifacts) != len(step195Formats()) {
		t.Fatalf("产物数量 = %d，期望 %d", len(final.Artifacts), len(step195Formats()))
	}

	// 下载五种格式（真实 OpenFile），核对产物摘要与元数据一致。
	artifactData := make(map[Format][]byte, len(step195Formats()))
	artifactSHA := make(map[Format]string, len(step195Formats()))
	for _, artifact := range final.Artifacts {
		if !artifact.Available || artifact.Bytes <= 0 || len(artifact.SHA256) != 64 {
			t.Fatalf("产物元数据不完整: %+v", artifact)
		}
		file, err := service.OpenFile(ctx, caller, view.ID, artifact.Format)
		if err != nil {
			t.Fatalf("下载 %s 失败: %v", artifact.Format, err)
		}
		if file.Bytes <= 0 || file.SHA256 != artifact.SHA256 {
			t.Fatalf("%s 下载内容与元数据不一致: bytes=%d sha=%s", artifact.Format, file.Bytes, file.SHA256)
		}
		content, readErr := os.ReadFile(file.HostPath)
		if readErr != nil {
			t.Fatalf("读取 %s 产物文件失败: %v", artifact.Format, readErr)
		}
		if sha256Hex(content) != artifact.SHA256 {
			t.Fatalf("%s 产物文件摘要与元数据不一致", artifact.Format)
		}
		artifactData[artifact.Format] = content
		artifactSHA[artifact.Format] = artifact.SHA256
	}

	// ---------- JSON：机器可读基准 ----------
	var document map[string]any
	if err := json.Unmarshal(artifactData[FormatJSON], &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	reportMeta := document["report"].(map[string]any)
	window := reportMeta["window"].(map[string]any)
	timezone := window["timezone"].(string)
	windowStart := window["start"].(string)
	windowEnd := window["end"].(string)
	granularity := window["granularity"].(string)
	activity := document["activity"].(map[string]any)
	errorsData := document["errors"].(map[string]any)
	activityTotal := int64(activity["total_distinct_users"].(float64))
	totalRawEvents := int64(errorsData["total_raw_events"].(float64))
	failedRequests := int64(errorsData["failed_requests"].(float64))
	failedTasks := int64(errorsData["failed_tasks"].(float64))
	if timezone != "Asia/Shanghai" || granularity != string(stats.GranularityDay) {
		t.Fatalf("JSON 时间口径异常: timezone=%s granularity=%s", timezone, granularity)
	}
	// 排序口径随快照透传（真实排序由 internal/stats 决定）；报告层不得改写排序声明。
	if errorsData["sort"] != string(stats.ErrorSortRaw) || errorsData["order"] != string(stats.SortDesc) {
		t.Fatalf("JSON 排序声明 = %v/%v", errorsData["sort"], errorsData["order"])
	}
	rowsJSON := errorsData["rows"].([]any)
	if len(rowsJSON) != len(base.source.rows) {
		t.Fatalf("JSON 明细行数 = %d，来源行数 = %d", len(rowsJSON), len(base.source.rows))
	}
	sourceRaw := map[int64]int{}
	for _, row := range base.source.rows {
		sourceRaw[row.RawEvents]++
	}
	for _, raw := range rowsJSON {
		row := raw.(map[string]any)
		sourceRaw[int64(row["raw_events"].(float64))]--
	}
	for rawEvents, remaining := range sourceRaw {
		if remaining != 0 {
			t.Fatalf("JSON 明细 raw_events=%d 与来源不一致", rawEvents)
		}
	}
	// 类别汇总合计 == 窗口总事件数；同一批数据在图表/表格/机器可读产物中同口径。
	categoryRawJSON := map[string]int64{}
	categoryLabels := make([]string, 0, 8)
	var categorySum int64
	for _, raw := range errorsData["categories"].([]any) {
		category := raw.(map[string]any)
		name := category["category"].(string)
		value := int64(category["raw_events"].(float64))
		categoryRawJSON[name] = value
		categorySum += value
		categoryLabels = append(categoryLabels, categoryText(name))
	}
	if categorySum != totalRawEvents {
		t.Fatalf("JSON 类别汇总 raw_events 合计 = %d，与 total_raw_events %d 不一致", categorySum, totalRawEvents)
	}
	// 趋势桶合计 == 窗口汇总（图表与汇总同口径，不把同一批事实复制到多个桶）。
	var trendSum int64
	if trend, ok := document["trend"].(map[string]any); ok {
		if points, ok := trend["points"].([]any); ok {
			for _, raw := range points {
				point := raw.(map[string]any)
				trendSum += int64(point["raw_events"].(float64))
			}
		}
	}
	if trendSum != totalRawEvents {
		t.Fatalf("JSON 趋势 raw_events 合计 = %d，与 total_raw_events %d 不一致", trendSum, totalRawEvents)
	}

	// ---------- CSV：元数据/总数与 JSON 一致 + 公式注入中和 ----------
	csvRecords, err := csv.NewReader(strings.NewReader(
		string(artifactData[FormatCSV]))).ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	csvMeta := map[string]string{}
	csvTotals := map[string]string{}
	csvCategoryRaw := map[string]string{}
	injectionCell := ""
	injectionNewline := false
	for _, record := range csvRecords {
		if len(record) < 16 {
			continue
		}
		if record[0] == "meta" {
			csvMeta[record[1]] = record[10]
		}
		if record[0] == "activity_total" && record[9] == "total_distinct_users" {
			csvTotals["total_distinct_users"] = record[10]
		}
		if record[0] == "errors_total" {
			csvTotals[record[9]] = record[10]
		}
		if record[0] == "category_summary" && record[9] == "raw_events" {
			csvCategoryRaw[record[5]] = record[10]
		}
		for _, cell := range record {
			if strings.Contains(cell, "cmd|") {
				injectionCell = cell
				if strings.Contains(cell, "\n") {
					injectionNewline = true
				}
			}
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
	for metric, want := range map[string]string{
		"total_distinct_users": itoa(activityTotal),
		"total_raw_events":     itoa(totalRawEvents),
		"failed_requests":      itoa(failedRequests),
		"failed_tasks":         itoa(failedTasks),
	} {
		if csvTotals[metric] != want {
			t.Fatalf("CSV %s = %q，JSON 为 %q", metric, csvTotals[metric], want)
		}
	}
	// CSV 类别行与 JSON 类别汇总同一口径。
	if len(csvCategoryRaw) != len(categoryRawJSON) {
		t.Fatalf("CSV 类别行数 = %d，JSON 类别数 = %d", len(csvCategoryRaw), len(categoryRawJSON))
	}
	for name, value := range categoryRawJSON {
		if csvCategoryRaw[name] != itoa(value) {
			t.Fatalf("CSV 类别 %q raw_events = %q，JSON 为 %d", name, csvCategoryRaw[name], value)
		}
	}
	if injectionCell == "" {
		t.Fatal("CSV 未包含公式注入载荷（测试数据/渲染丢失）")
	}
	if !strings.HasPrefix(injectionCell, "'") {
		t.Fatalf("CSV 公式注入未中和（首字符应为单引号）: %q", injectionCell)
	}
	if !injectionNewline {
		t.Fatalf("CSV 解析未保留字段内换行（csv.Reader 应还原为多行字段）: %q", injectionCell)
	}

	// ---------- HTML：独立去标签解析 + 转义/无远程资源 ----------
	htmlText := string(artifactData[FormatHTML])
	lowerHTML := strings.ToLower(htmlText)
	for _, forbidden := range []string{"<script", "<iframe", "<link", "src=\"http", "src='http",
		"href=\"http", "href='http", "javascript:", " onerror=", " onload=", " onclick="} {
		if strings.Contains(lowerHTML, forbidden) {
			t.Fatalf("HTML 含禁止内容 %q（离线/转义/无脚本不变量被破坏）", forbidden)
		}
	}
	if !strings.Contains(htmlText, "default-src 'none'") {
		t.Fatal("HTML 缺少 CSP default-src 'none'（远程资源未默认禁止）")
	}
	if !strings.Contains(htmlText, "<svg") {
		t.Fatal("HTML 缺少内联 SVG 图表（图表应来自真实数据）")
	}
	if !strings.Contains(htmlText, "&lt;") || strings.Contains(htmlText, "测试<脚本>") {
		t.Fatal("HTML 未正确转义不可信 payload（<、> 应转义为实体）")
	}
	visible := htmlVisibleText(htmlText)
	for _, want := range []string{
		timezone + " / " + granularity, windowStart, windowEnd,
		itoa(activityTotal), itoa(totalRawEvents), itoa(failedRequests), itoa(failedTasks),
		"登录活跃度", "错误明细",
	} {
		requireContains(t, visible, want, "HTML 可见文本")
	}
	for _, label := range categoryLabels {
		requireContains(t, visible, label, "HTML 类别图表/表格")
	}

	// ---------- Markdown：YAML front matter + 不可信边界 + 转义 ----------
	markdown := string(artifactData[FormatMarkdown])
	front := markdownFrontMatter(t, markdown)
	if got, _ := front["timezone"].(string); got != timezone {
		t.Fatalf("Markdown front matter timezone = %q，JSON 为 %q", got, timezone)
	}
	if front["snapshot_json_sha256"] != artifactSHA[FormatJSON] {
		t.Fatalf("Markdown 快照摘要与 JSON 产物不一致: %v", front["snapshot_json_sha256"])
	}
	for _, want := range []string{"不可信数据边界", "不可信材料", "不得执行", "缺失不等于 0"} {
		requireContains(t, markdown, want, "Markdown 不可信/缺失边界")
	}
	if strings.Contains(markdown, "测试<脚本>") {
		t.Fatal("Markdown 未转义不可信 payload（< 应转为 &lt;）")
	}
	if !strings.Contains(markdown, "&lt;") || !strings.Contains(markdown, "\\|") {
		t.Fatal("Markdown 表格未转义 HTML 实体/竖线（payload 可能破坏表格或触发 HTML）")
	}
	requireContains(t, markdown, itoa(activityTotal), "Markdown 活跃统计")

	// ---------- PDF：独立文本抽取（ToUnicode）+ 中文可读 + 分页 ----------
	pdf := loadPDFSummary(t, artifactData[FormatPDF])
	if pdf.pageCount() < 2 {
		t.Fatalf("PDF 页数 = %d，期望至少 2 页", pdf.pageCount())
	}
	totalPages := pdf.pageCount()
	for index, page := range pdf.pages {
		if strings.TrimSpace(page) == "" {
			t.Fatalf("PDF 第 %d 页为空白页", index+1)
		}
		requireContains(t, pdfFlatten(page), pdfFlatten(fmtPageFooter(index+1, totalPages)), "PDF 页脚")
	}
	pdfText := pdf.allText()
	for _, want := range []string{
		"统计报告", view.ID, timezone + " / " + granularity, windowStart,
		"登录活跃度", "错误明细", itoa(activityTotal), itoa(totalRawEvents),
	} {
		requireContains(t, pdfText, pdfFlatten(want), "PDF 文本")
	}
	for _, label := range categoryLabels {
		requireContains(t, pdfText, pdfFlatten(label), "PDF 类别图表/表格")
	}
	rawPDF := string(artifactData[FormatPDF])
	requireContains(t, rawPDF, "/FontFile2", "PDF 嵌入 TrueType 字体")
	requireContains(t, rawPDF, "/ToUnicode", "PDF ToUnicode 映射（中文可抽取）")

	// ---------- 历史报告受控 ----------
	historyPage, err := service.HistoryList(ctx, HistoryListRequest{Caller: caller, Limit: 10})
	if err != nil {
		t.Fatalf("读取历史列表失败: %v", err)
	}
	foundHistory := false
	for _, record := range historyPage.Records {
		if record.ID == view.ID {
			foundHistory = true
			if record.State != StateSucceeded {
				t.Fatalf("历史记录状态 = %s，期望 succeeded", record.State)
			}
		}
	}
	if !foundHistory {
		t.Fatal("历史列表缺少刚生成的成功报告")
	}

	// ---------- 查看/下载分别鉴权 + 撤销后下载拒绝 ----------
	// 只撤销导出权限：查看（read）仍可用，五个格式的下载全部拒绝。
	base.authorizer.deny(PermissionExport, ScopeSystem)
	if _, err := service.Get(ctx, caller, view.ID); err != nil {
		t.Fatalf("撤销导出后查看报告失败（查看应只需 read）: %v", err)
	}
	for _, format := range step195Formats() {
		if _, err := service.OpenFile(ctx, caller, view.ID, format); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("撤销导出后 %s 下载错误 = %v，期望 ErrAccessDenied", format, err)
		}
	}
	// 再撤销读取：查看与下载都拒绝，历史列表不得泄露该报告。
	base.authorizer.deny(PermissionRead, ScopeSystem)
	if _, err := service.Get(ctx, caller, view.ID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销读取后查看错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := service.OpenFile(ctx, caller, view.ID, FormatJSON); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销读取后下载错误 = %v，期望 ErrAccessDenied", err)
	}
	if page, err := service.HistoryList(ctx, HistoryListRequest{Caller: caller, Limit: 10}); err == nil {
		for _, record := range page.Records {
			if record.ID == view.ID {
				t.Fatal("撤销读取后历史列表仍泄露该报告")
			}
		}
	}
	// 恢复权限后仍可查看/下载（撤销即时生效，不是永久破坏）。
	base.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	if _, err := service.Get(ctx, caller, view.ID); err != nil {
		t.Fatalf("恢复权限后查看失败: %v", err)
	}
	if _, err := service.OpenFile(ctx, caller, view.ID, FormatPDF); err != nil {
		t.Fatalf("恢复权限后下载 PDF 失败: %v", err)
	}
}

// TestStep195ScheduledFailureDoesNotPolluteAudit 验证计划报告失败时：
// 历史留失败记录、任务返回失败、审计只写失败事件（无成功事件、不篡改既有审计）、
// 不产生可下载产物。
func TestStep195ScheduledFailureDoesNotPolluteAudit(t *testing.T) {
	ctx := context.Background()
	now := baseTime
	env := newPlanTestEnv(t, &now)
	plan, err := env.plans.Create(ctx, newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	schedule, err := env.scheduler.Get(ctx, plan.ScheduleID)
	if err != nil {
		t.Fatalf("读取计划载荷失败: %v", err)
	}
	// 用同一组真实依赖重建报告服务并挂上可观测历史仓库。
	history := newFakeHistoryStore()
	outputDir := testutil.TempDir(t)
	options := env.service.opts
	options.History = history
	options.OutputDir = outputDir
	service, err := New(options)
	if err != nil {
		t.Fatalf("构造带历史的报告服务失败: %v", err)
	}
	// 让统计来源在下一次生成时失败（预构建/统计读取失败，不写任何产物）。
	source, ok := env.service.opts.Source.(*fakeSource)
	if !ok {
		t.Fatalf("测试来源类型异常: %T", env.service.opts.Source)
	}
	source.err = errors.New("simulated stats source unavailable")

	// 记录执行前审计事件快照（前缀必须保持不变）。
	env.recorder.mu.Lock()
	before := append([]audit.Event(nil), env.recorder.events...)
	env.recorder.mu.Unlock()

	job := task.Job{ID: "job-step195-scheduled-failure",
		Kind: TaskKindPlannedReportGenerate, Initiator: env.caller.Actor(),
		ExecutorID: "exec-step195-failure", Payload: schedule.Payload}
	if err := service.GenerateScheduledHandler(ctx, job); err == nil {
		t.Fatal("计划报告在统计来源失败时仍返回成功")
	}

	// 历史：恰好一条 failed 记录，含失败原因，且没有成功记录。
	page, err := history.ListHistory(ctx, HistoryQuery{Access: AccessScope{AllData: true}, Limit: 10})
	if err != nil {
		t.Fatalf("读取历史失败: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("失败历史记录数 = %d，期望 1: %+v", len(page.Records), page.Records)
	}
	failedRecord := page.Records[0]
	if failedRecord.State != StateFailed {
		t.Fatalf("历史状态 = %s，期望 failed", failedRecord.State)
	}
	if strings.TrimSpace(failedRecord.FailureReason) == "" {
		t.Fatal("失败历史缺少失败原因")
	}

	// 审计：既有事件前缀不变；新增事件只能是非成功事件（失败终态），不得写成功。
	env.recorder.mu.Lock()
	after := append([]audit.Event(nil), env.recorder.events...)
	env.recorder.mu.Unlock()
	if len(after) < len(before) {
		t.Fatalf("审计事件数量减少: before=%d after=%d", len(before), len(after))
	}
	for index := range before {
		if after[index].Action != before[index].Action ||
			after[index].Outcome != before[index].Outcome {
			t.Fatalf("既有审计事件被改写: index=%d before=%s/%s after=%s/%s",
				index, before[index].Action, before[index].Outcome,
				after[index].Action, after[index].Outcome)
		}
	}
	if len(after) == len(before) {
		t.Fatal("计划失败没有写入任何失败审计事件")
	}
	for _, event := range after[len(before):] {
		if event.Outcome == audit.OutcomeSuccess {
			t.Fatalf("计划失败却写入成功审计事件: action=%s", event.Action)
		}
	}

	// 产物：失败不留下任何可下载文件。
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("读取输出目录失败: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("计划失败仍产生 %d 个产物文件", len(entries))
	}
}

// TestStep195PDFFailClosedWithoutFont 验证未配置受信字体时：构造成功但 PDF 请求被拒绝
// （fail-closed，不生成缺字体/伪扩展名 PDF），同一服务仍可生成 HTML。
func TestStep195PDFFailClosedWithoutFont(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t) // 故意不配置 FontPath
	if env.service.PDFAvailable() {
		t.Fatal("未配置字体时 PDFAvailable() 不应为 true")
	}
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	request := env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("无字体 PDF 请求错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 同一服务生成 HTML 不受影响（PDF 能力缺失不误伤其他格式）。
	request.Formats = []Format{FormatHTML}
	if _, err := env.service.Start(ctx, request); err != nil {
		t.Fatalf("无字体服务生成 HTML 失败: %v", err)
	}
}
