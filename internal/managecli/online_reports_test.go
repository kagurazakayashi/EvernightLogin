package managecli

// 本文件是在线报告命令的真实集成测试：真实 reports.Service（临时 SQLite 持久历史
// + 真实产物文件）+ 真实 adminapi Handler + 真实 session.Service 管理会话。
// 目的：验证历史列表/详情、一次性下载令牌兑换原始字节流、取消/重试状态机、
// 清理预览/执行与权限撤销后的拒绝。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	reportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reports/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// onlineReportsEnv 是真实 reports 在线环境。
type onlineReportsEnv struct {
	*onlineFixture
	service     *reports.Service
	authorizer  *onlineStatsAuthorizer
	sensitive   *onlineSensitiveFake
	history     *reportsqlite.HistoryRecorder
	reportStore *reportsqlite.Store
	outputDir   string
}

// newOnlineReportsEnv 装配真实 reports 服务（持久历史 + 真实产物目录）。
func newOnlineReportsEnv(t *testing.T) *onlineReportsEnv {
	t.Helper()
	fixture := newOnlineFixture(t)
	reportStore, err := reportsqlite.New(fixture.raw)
	if err != nil {
		t.Fatalf("构造报告仓储: %v", err)
	}
	history, err := reportsqlite.NewHistoryRecorder(reportStore)
	if err != nil {
		t.Fatalf("构造报告历史仓储: %v", err)
	}
	outputDir := t.TempDir()
	authorizer := newOnlineStatsAuthorizer()
	for _, permission := range []string{reports.PermissionRead,
		reports.PermissionExport, reports.PermissionGenerate,
		reports.PermissionCleanup} {
		authorizer.grant(fixture.userID, permission, reports.ScopeSystem,
			stats.ScopeGrant{Allowed: true, AllData: true})
	}
	sensitive := newOnlineSensitiveFake()
	service, err := reports.New(reports.Options{Source: &onlineStatsSource{},
		Authorizer: authorizer, Root: newOnlineRootFake(), Sensitive: sensitive,
		Audit: &onlineReportsAudit{}, Enqueuer: &onlineEnqueuerFake{},
		Canceller: &onlineCancellerFake{}, History: history, OutputDir: outputDir,
		MaxDetailRows: 20, Now: fixedOnlineNow})
	if err != nil {
		t.Fatalf("构造报告服务: %v", err)
	}
	fixture.serve(func(options *adminapi.Options) { options.Reports = service })
	return &onlineReportsEnv{onlineFixture: fixture, service: service,
		authorizer: authorizer, sensitive: sensitive, history: history,
		reportStore: reportStore, outputDir: outputDir}
}

// seedReport 写入一条真实持久历史（可选真实产物文件）。
func (e *onlineReportsEnv) seedReport(reportID, state string, withArtifact bool) []byte {
	e.t.Helper()
	windowJSON, err := json.Marshal(stats.Window{TimeZone: "UTC",
		Buckets: []stats.Bucket{{}}})
	if err != nil {
		e.t.Fatalf("编码报告窗口: %v", err)
	}
	record := reports.HistoryRecord{ReportID: reportID, Name: "每日统计报告",
		Template: "standard",
		Owner:    audit.Actor{Type: audit.ActorUser, ID: e.userID},
		ScopeID:  reports.ScopeSystem, ScopeKind: "system", State: state,
		Formats:    []reports.Format{reports.FormatHTML},
		DetailRows: 1, CreatedAt: onlineTestNow.Add(-2 * time.Hour),
		FinishedAt:    onlineTestNow.Add(-2 * time.Hour),
		ExpiresAt:     onlineTestNow.Add(24 * time.Hour),
		DataScopeJSON: []byte(`{"all":true}`),
		WindowJSON:    windowJSON,
	}
	var content []byte
	if withArtifact {
		content = []byte("<html><body>报告正文</body></html>")
		name := "report_" + reportID + ".html"
		if err := os.WriteFile(filepath.Join(e.outputDir, name), content, 0o600); err != nil {
			e.t.Fatalf("写入报告产物: %v", err)
		}
		digest := sha256.Sum256(content)
		record.ArtifactsJSON = []byte(`[{"format":"html","name":"` + name +
			`","bytes":` + strconv.FormatInt(int64(len(content)), 10) + `,"sha256":"` +
			hex.EncodeToString(digest[:]) + `"}]`)
	}
	if state == reports.StateFailed {
		record.ErrorCode = "REPORT_GENERATION_FAILED"
		record.FailureReason = "测试失败报告"
	}
	if err := e.history.RecordReportHistory(e.ctx, record); err != nil {
		e.t.Fatalf("写入报告历史: %v", err)
	}
	return content
}

// mustRun 执行在线命令并断言成功。
func (e *onlineReportsEnv) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, exit := e.run(args...)
	if exit != ExitOK {
		t.Fatalf("命令 %v 退出码 = %d，stderr=%s，stdout=%s", args, exit, stderr, stdout)
	}
	return stdout
}

// TestOnlineReportsRealFlow 覆盖真实报告历史、下载令牌兑换、取消/重试状态机与清理。
func TestOnlineReportsRealFlow(t *testing.T) {
	env := newOnlineReportsEnv(t)
	succeededID := "rpt_" + strings.Repeat("1", 32)
	failedID := "rpt_" + strings.Repeat("2", 32)
	content := env.seedReport(succeededID, reports.StateSucceeded, true)
	env.seedReport(failedID, reports.StateFailed, false)

	// 历史列表：真实持久历史回源。
	listData := requireOnlineSuccess(t, env.mustRun(t, "reports", "history", "list", "--json"))
	records, _ := listData["reports"].([]any)
	if len(records) != 2 {
		t.Fatalf("历史报告数 = %d，期望 2: %v", len(records), listData)
	}

	// 详情。
	detailData := requireOnlineSuccess(t, env.mustRun(t, "reports", "history",
		"detail", succeededID, "--json"))
	report, _ := detailData["report"].(map[string]any)
	if report == nil || report["id"] != succeededID || report["state"] != reports.StateSucceeded {
		t.Fatalf("报告详情不符: %v", detailData)
	}

	// 不存在（但格式合法）的报告：REQ_INVALID → 退出码 2。
	stdout, _, exit := env.run("reports", "history", "detail",
		"rpt_"+strings.Repeat("9", 32), "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "REQ_INVALID")

	// 下载令牌：签发后立即兑换原始字节流，令牌原文不出现在输出。
	outPath := filepath.Join(t.TempDir(), "report.html")
	stdout, _, exit = env.run("reports", "download-token", succeededID,
		"--format", "html", "--confirm", "ISSUE-DOWNLOAD", "--out", outPath, "--json")
	if exit != ExitOK {
		t.Fatalf("报告下载退出码 = %d，stdout=%s", exit, stdout)
	}
	downloadData := requireOnlineSuccess(t, stdout)
	saved, err := os.ReadFile(outPath)
	if err != nil || string(saved) != string(content) {
		t.Fatalf("报告产物内容不符: %v", err)
	}
	if strings.Contains(stdout, `"token"`) {
		t.Fatalf("下载输出泄露了令牌原文: %s", stdout)
	}
	download, _ := downloadData["download"].(map[string]any)
	if download == nil || download["bytes"] == nil || download["sha256"] == "" {
		t.Fatalf("下载结果缺少字节数/摘要: %v", downloadData)
	}

	// 缺少 --confirm：用法错误。
	stdout, _, exit = env.run("reports", "download-token", succeededID,
		"--format", "html", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "USAGE_INVALID")

	// 仅存在于持久历史的已完成报告没有活动任务：取消按“不存在/不可操作”拒绝
	// （REQ_INVALID，退出码 2），不伪造成已取消。
	stdout, _, exit = env.run("reports", "cancel", succeededID, "--reason", "测试取消",
		"--confirm", "CANCEL-REPORT", "--json")
	requireOnlineFailure(t, stdout, exit, ExitUsage, "REQ_INVALID")
	stdout, _, exit = env.run("reports", "retry", succeededID, "--reason", "测试重试",
		"--confirm", "RETRY-REPORT", "--json")
	requireOnlineFailure(t, stdout, exit, ExitConflict, "CONFLICT")

	// 失败报告可重试：生成新的运行记录并保留原记录。
	retried := requireOnlineSuccess(t, env.mustRun(t, "reports", "retry", failedID,
		"--reason", "测试重试", "--confirm", "RETRY-REPORT", "--json"))
	retriedView, _ := retried["report"].(map[string]any)
	newReportID, _ := retriedView["id"].(string)
	if newReportID == "" || newReportID == failedID {
		t.Fatalf("重试未产生新的报告记录: %v", retried)
	}

	// 取消刚提交的新报告：请求被接受（接受不等于已取消）。
	cancelData := requireOnlineSuccess(t, env.mustRun(t, "reports", "cancel",
		newReportID, "--reason", "测试取消", "--confirm", "CANCEL-REPORT", "--json"))
	cancelView, _ := cancelData["cancel"].(map[string]any)
	if accepted, _ := cancelView["accepted"].(bool); !accepted {
		t.Fatalf("报告取消请求未被接受: %v", cancelData)
	}

	// 清理预览与真实清理执行（无到期目标时如实返回 0，不伪造删除）。
	previewData := requireOnlineSuccess(t, env.mustRun(t, "reports", "cleanup",
		"preview", "--json"))
	preview, _ := previewData["cleanup_preview"].(map[string]any)
	if objectInt64(preview, "target_count") != 0 {
		t.Fatalf("清理预览目标数不符: %v", previewData)
	}
	cleanupData := requireOnlineSuccess(t, env.mustRun(t, "reports", "cleanup",
		"exec", "--reason", "测试清理", "--confirm", "CLEANUP", "--json"))
	cleanupResult, _ := cleanupData["cleanup_result"].(map[string]any)
	if cleanupResult == nil || objectInt64(cleanupResult, "requested_count") != 0 {
		t.Fatalf("清理执行结果不符: %v", cleanupData)
	}

	// 撤销 reports.read：列表按当前权限裁剪为空（不泄露无权对象，也不报错），
	// 详情读取则明确拒绝（服务端每次重新授权，不缓存旧结论）。
	env.authorizer.revoke(env.userID, reports.PermissionRead, reports.ScopeSystem)
	trimmed := requireOnlineSuccess(t, env.mustRun(t, "reports", "history", "list", "--json"))
	if reportsList, _ := trimmed["reports"].([]any); len(reportsList) != 0 {
		t.Fatalf("撤权后仍列出了报告: %v", trimmed)
	}
	stdout, _, exit = env.run("reports", "history", "detail", succeededID, "--json")
	requireOnlineFailure(t, stdout, exit, ExitForbidden, "ACCESS_DENIED")
}
