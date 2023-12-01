package app

// 步骤 230：审计/报告公开门面测试。
//   - 审计查询/详情/错误分类统计走真实 SQLite 与领域授权；
//   - 报告 Start/Get/OpenArtifact 使用真实任务执行器与受控产物目录，公开句柄不含路径；
//   - 任务 Get/Attempts/Cancel 真实终态；root-only 保留/清理由领域拒绝 LocalAdmin；
//   - 成功与拒绝路径均覆盖，PDF 在未部署字体时真实拒绝。

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestAuditReportsPublicFacade(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	auditSvc := runtime.Audit()
	reportsSvc := runtime.Reports()

	// 任务取消要可确定地测试 queued→cancelled：在 Start（启动执行器）之前入队，
	// 没有 worker 竞争，避免任务瞬间结束导致时序 flake（步骤 230 测试修复）。
	if runtime.base == nil || runtime.base.Tasks == nil || runtime.base.Tasks.Executor() == nil {
		t.Fatal("任务执行器未装配")
	}
	executor := runtime.base.Tasks.Executor()
	queuedJob, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: "test.public.task",
		Actor:   audit.Actor{Type: audit.ActorLocalAdmin, ID: "host-operator"},
		Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("入队测试任务: %v", err)
	}
	gotTask, err := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: local, TaskID: queuedJob.ID,
		RequestID: login.NewRequestID()})
	if err != nil || gotTask.ID != queuedJob.ID {
		t.Fatalf("读取任务 = %+v err=%v", gotTask, err)
	}
	cancel, err := auditSvc.CancelTask(ctx, AdminTaskCancelRequest{Caller: local,
		TaskID: queuedJob.ID, Reason: "测试取消", RequestID: login.NewRequestID()})
	if err != nil || !cancel.Accepted {
		t.Fatalf("取消任务 = %+v err=%v", cancel, err)
	}
	after, err := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: local, TaskID: queuedJob.ID,
		RequestID: login.NewRequestID()})
	if err != nil || after.State != string(task.StateCancelled) {
		t.Fatalf("取消后任务 = %+v err=%v", after, err)
	}
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	// 生成一条可查询的审计事件（创建用户）。
	created, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "public-audit-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建审计用户: %v", err)
	}
	events, err := auditSvc.Query(ctx, AdminListAuditEventsRequest{Caller: local,
		ScopeID: "system", Limit: 50, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("审计查询: %v", err)
	}
	if len(events.Events) == 0 {
		t.Fatal("审计查询没有事件")
	}
	target := events.Events[0]
	detail, err := auditSvc.GetEvent(ctx, AdminAuditEventRequest{Caller: local,
		ScopeID: "system", EventID: target.ID, OccurredAtHint: target.OccurredAt,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("审计详情: %v", err)
	}
	if detail.Event.ID != target.ID || detail.ScopeID != "system" {
		t.Fatalf("审计详情 = %+v", detail)
	}
	// 不存在的事件返回稳定 NOT_FOUND，不泄露底层信息。
	if _, err := auditSvc.GetEvent(ctx, AdminAuditEventRequest{Caller: local,
		ScopeID: "system", EventID: "aud_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在审计事件错误 = %v，期望 NOT_FOUND", err)
	}
	retention, err := auditSvc.Retention(ctx, AdminAuditRetentionRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil || retention.Days <= 0 {
		t.Fatalf("审计保留策略 = %+v err=%v", retention, err)
	}
	// 错误分类统计：窗口合法即成功，缺数据保留完整/未知语义。
	statsResult, err := auditSvc.ErrorStats(ctx, AdminErrorStatsRequest{Caller: local,
		ScopeID: "system", Start: clock.Now().Add(-24 * time.Hour), End: clock.Now(),
		TimeZone: "UTC", Granularity: "day", Limit: 20,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("错误分类统计: %v", err)
	}
	if statsResult.Completeness.RetentionDays <= 0 ||
		statsResult.Completeness.RetentionCutoff.IsZero() {
		t.Fatalf("错误统计完整性 = %+v", statsResult.Completeness)
	}
	if _, err := auditSvc.ErrorStats(ctx, AdminErrorStatsRequest{Caller: local,
		ScopeID: "system", Limit: 10000,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("越界错误统计错误 = %v，期望 REQ_INVALID", err)
	}
	// root-only：LocalAdmin 不是 root，领域必须拒绝。
	if _, err := auditSvc.SetRetention(ctx, AdminAuditRetentionSetRequest{Caller: local,
		RetentionDays: 90, Reason: "测试", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 修改保留策略错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := auditSvc.StartPurge(ctx, AdminAuditPurgeStartRequest{Caller: local,
		ScopeID: "system", Cutoff: clock.Now().AddDate(0, 0, -90),
		Reason: "测试", Digest: "digest", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 清理审计错误 = %v，期望 ACCESS_DENIED", err)
	}

	// 后台任务：GetTask/CancelTask 真实终态。
	if runtime.base == nil || runtime.base.Tasks == nil || runtime.base.Tasks.Executor() == nil {
		t.Fatal("任务执行器未装配")
	}
	// 已结束任务不可取消：入队后等待真实终态（无处理器会快速失败），CancelTask
	// 必须明确拒绝，不能把“请求取消”误报为成功（产品语义断言）。
	terminalJob, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: "test.public.task",
		Actor:   audit.Actor{Type: audit.ActorLocalAdmin, ID: "host-operator"},
		Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("入队终态测试任务: %v", err)
	}
	terminalDeadline := time.Now().Add(5 * time.Second)
	for {
		terminal, getErr := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: local,
			TaskID: terminalJob.ID, RequestID: login.NewRequestID()})
		if getErr != nil {
			t.Fatalf("读取终态任务: %v", getErr)
		}
		if task.State(terminal.State).Terminal() {
			break
		}
		if time.Now().After(terminalDeadline) {
			t.Fatalf("任务未在期限内进入终态: %+v", terminal)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := auditSvc.CancelTask(ctx, AdminTaskCancelRequest{Caller: local,
		TaskID: terminalJob.ID, Reason: "测试取消已结束任务",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("已结束任务取消必须拒绝")
	}
	if _, err := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: local,
		TaskID:    "job_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在任务错误 = %v，期望 NOT_FOUND", err)
	}

	// 报告能力：未部署 PDF 字体时明确不可用。
	caps, err := reportsSvc.Capabilities(ctx, AdminReportCapabilitiesRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("报告能力: %v", err)
	}
	if caps.PDFAvailable || len(caps.Formats) == 0 {
		t.Fatalf("报告能力 = %+v，PDF 未部署字体时必须不可用", caps)
	}
	if _, err := reportsSvc.Start(ctx, AdminReportStartRequest{Caller: local,
		ScopeID: "system", Formats: []string{"pdf"}, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("PDF 不可用时错误 = %v，期望 REQ_INVALID", err)
	}
	// 生成真实报告：html/csv/markdown 同源快照；任务由真实执行器完成。
	start, err := reportsSvc.Start(ctx, AdminReportStartRequest{Caller: local,
		ScopeID: "system", TimeZone: "UTC", Start: clock.Now().Add(-24 * time.Hour),
		End: clock.Now(), Granularity: "day",
		Formats: []string{"html", "csv", "markdown"}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建报告: %v", err)
	}
	report := waitPublicReport(t, ctx, reportsSvc, local, start.ID)
	if report.State != "succeeded" {
		t.Fatalf("报告终态 = %s error=%s reason=%s", report.State,
			report.ErrorCode, report.FailureReason)
	}
	if len(report.Artifacts) != 3 {
		t.Fatalf("报告产物 = %+v", report.Artifacts)
	}
	if report.Completeness.RetentionDays <= 0 {
		t.Fatalf("报告完整性缺失保留说明: %+v", report.Completeness)
	}
	for _, format := range []string{"html", "csv", "markdown"} {
		download, err := reportsSvc.OpenArtifact(ctx, AdminReportArtifactRequest{
			Caller: local, ReportID: report.ID, Format: format,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("读取 %s 产物: %v", format, err)
		}
		content := readDownload(t, download)
		if len(content) == 0 {
			t.Fatalf("%s 产物为空", format)
		}
		if strings.ContainsAny(download.FileName, `/\`) ||
			strings.Contains(download.FileName, "..") {
			t.Fatalf("%s 产物文件名泄露路径: %q", format, download.FileName)
		}
		if strings.HasPrefix(download.ContentType, "text/csv") {
			if !strings.HasPrefix(string(content), "section,series,bucket") {
				t.Fatalf("CSV 表头异常: %q", string(content[:min(80, len(content))]))
			}
		}
	}
	// 非本人/无权限管理会话拒绝读取报告。
	userSession, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: created.Username, Password: "T4!kR8#wQ2@mN6$z",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || userSession.Restricted {
		t.Fatalf("登录普通用户: %+v err=%v", userSession, err)
	}
	userCaller := runtime.AdminSession(userSession.SessionSecret)
	// 管理会话只能读/取消本人发起的任务；他人任务不泄露存在性细节。
	userJob, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: "test.public.task",
		Actor:   audit.Actor{Type: audit.ActorUser, ID: created.ID},
		Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("入队用户任务: %v", err)
	}
	ownTask, err := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: userCaller,
		TaskID: userJob.ID, RequestID: login.NewRequestID()})
	if err != nil || ownTask.ID != userJob.ID {
		t.Fatalf("管理会话读取本人任务 = %+v err=%v", ownTask, err)
	}
	if _, err := auditSvc.GetTask(ctx, AdminTaskRequest{Caller: userCaller,
		TaskID: queuedJob.ID, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("管理会话读取他人任务错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := auditSvc.CancelTask(ctx, AdminTaskCancelRequest{Caller: userCaller,
		TaskID: queuedJob.ID, Reason: "测试", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("管理会话取消他人任务错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := reportsSvc.Get(ctx, AdminReportRequest{
		Caller: userCaller, ReportID: report.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限读取报告错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := reportsSvc.OpenArtifact(ctx, AdminReportArtifactRequest{
		Caller: userCaller, ReportID: report.ID, Format: "csv",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限读取报告产物错误 = %v，期望 ACCESS_DENIED", err)
	}
}

// waitPublicReport 轮询报告真实终态，最多 10 秒。
func waitPublicReport(t *testing.T, ctx context.Context, service ReportsService,
	caller AdminCaller, reportID string) AdminReport {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := service.Get(ctx, AdminReportRequest{Caller: caller,
			ReportID: reportID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("读取报告状态: %v", err)
		}
		switch report.State {
		case "succeeded", "failed", "cancelled":
			return report
		}
		if time.Now().After(deadline) {
			t.Fatalf("报告未在期限内完成: state=%s error=%s", report.State, report.ErrorCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// readDownload 读取受控下载流并关闭。
func readDownload(t *testing.T, download AdminDownload) []byte {
	t.Helper()
	defer func() { _ = download.Reader.Close() }()
	content, err := io.ReadAll(io.LimitReader(download.Reader, 4<<20))
	if err != nil {
		t.Fatalf("读取下载流: %v", err)
	}
	return content
}
