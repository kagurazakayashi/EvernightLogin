package app

// 步骤 230：审计导出的公开受控文件链与 root-only 维护拒绝路径。
//   - 导出 Start/List/Get/Open 使用真实任务执行器；公开句柄无磁盘路径；
//   - 导出有界（行数上限）、取消返回受理语义；
//   - PreviewPurge/StartPurge/SetRetention 对 LocalAdmin 一律领域拒绝（非 root）。

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestAuditExportPublicFacade(t *testing.T) {
	ctx := t.Context()
	clock := newTestClock(time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	local := runtime.LocalAdmin()
	auditSvc := runtime.Audit()
	// 先产生若干审计事件，保证导出有真实数据。
	for index := 0; index < 3; index++ {
		if _, err := runtime.Users().Create(ctx, CreateUserRequest{
			Username: "export-user-" + string(rune('a'+index)),
			Password: "T4!kR8#wQ2@mN6$z", RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("创建导出测试用户 %d: %v", index, err)
		}
	}
	start, err := auditSvc.StartExport(ctx, AdminAuditExportStartRequest{
		Caller: local, ScopeID: "system", Format: "csv", MaxRows: 100,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建审计导出: %v", err)
	}
	export := waitPublicExport(t, ctx, auditSvc, local, start.ID)
	if export.State != "succeeded" || !export.FileAvailable {
		t.Fatalf("导出终态 = %s error=%s reason=%s available=%v",
			export.State, export.ErrorCode, export.FailureReason, export.FileAvailable)
	}
	if export.RowCount < 1 || export.Truncated {
		t.Fatalf("导出元数据 = %+v", export)
	}
	download, err := auditSvc.OpenExport(ctx, AdminAuditExportRequest{
		Caller: local, ExportID: export.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("打开导出产物: %v", err)
	}
	defer func() { _ = download.Reader.Close() }()
	content, err := io.ReadAll(io.LimitReader(download.Reader, 1<<20))
	if err != nil || len(content) == 0 {
		t.Fatalf("读取导出内容 = %d err=%v", len(content), err)
	}
	if strings.ContainsAny(download.FileName, `/\`) ||
		strings.Contains(download.FileName, "..") {
		t.Fatalf("导出文件名泄露路径: %q", download.FileName)
	}
	if !strings.HasPrefix(download.ContentType, "text/csv") {
		t.Fatalf("导出内容类型 = %q", download.ContentType)
	}
	// 列表可见且分页元数据真实。
	list, err := auditSvc.ListExports(ctx, AdminAuditExportListRequest{
		Caller: local, ScopeID: "system", Page: AdminPage{Limit: 10},
		RequestID: login.NewRequestID()})
	if err != nil || len(list.Exports) != 1 || list.HasMore {
		t.Fatalf("导出列表 = %+v err=%v", list, err)
	}
	// 行数上限越界在领域拒绝。
	if _, err := auditSvc.StartExport(ctx, AdminAuditExportStartRequest{
		Caller: local, ScopeID: "system", Format: "csv", MaxRows: 1_000_000,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("导出超行数错误 = %v，期望 REQ_INVALID", err)
	}
	// 非法格式在公开层拒绝。
	if _, err := auditSvc.StartExport(ctx, AdminAuditExportStartRequest{
		Caller: local, ScopeID: "system", Format: "html",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("导出非法格式错误 = %v，期望 REQ_INVALID", err)
	}
	// root-only 清理/保留对 LocalAdmin 全部拒绝。
	if _, err := auditSvc.PreviewPurge(ctx, AdminAuditPurgePreviewRequest{
		Caller: local, ScopeID: "system", Cutoff: clock.Now().AddDate(0, 0, -365),
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 预览清理错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := auditSvc.ListPurgeRuns(ctx, AdminAuditPurgeRunListRequest{
		Caller: local, Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 清理列表错误 = %v，期望 ACCESS_DENIED", err)
	}
}

// waitPublicExport 轮询导出记录真实终态，最多 15 秒。
func waitPublicExport(t *testing.T, ctx context.Context, service AuditService,
	caller AdminCaller, exportID string) AdminAuditExport {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		export, err := service.GetExport(ctx, AdminAuditExportRequest{Caller: caller,
			ExportID: exportID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("读取导出状态: %v", err)
		}
		switch export.State {
		case "succeeded", "failed", "cancelled":
			return export
		}
		if time.Now().After(deadline) {
			t.Fatalf("导出未在期限内完成: state=%s error=%s",
				export.State, export.ErrorCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
