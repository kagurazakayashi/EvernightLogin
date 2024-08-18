package app

// 步骤 247：运维数据链（备份/恢复/导出、审计与报告、诊断、队列状态）交叉回归。
//   - 备份时点之后的报告/审计导出元数据在恢复后必须消失（真实恢复，不是 UI 假象）；
//   - 恢复后诊断/队列状态仍可读且脱敏，不含路径/密钥/令牌；
//   - 备份→恢复→重开运行时，旧会话失效。

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestOpsRegressionBackupRestoreDataConsistency(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	ctx := env.ctx
	local := env.local
	const password = "K8$wR3!nB6@yF1#v"
	user, err := env.runtime.Users().Create(ctx, CreateUserRequest{Username: "ops-user",
		Password: password, Nickname: "运维回归", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	loginResult, err := env.runtime.Auth().Login(ctx, LoginRequest{Username: "ops-user",
		Password: password, ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("登录: %+v err=%v", loginResult, err)
	}
	oldSession := append([]byte(nil), loginResult.SessionSecret...)
	backupID := env.triggerBackup(t)
	// 备份时点之后产生运维数据：报告、审计导出、诊断快照/导出。
	reportStart, err := env.runtime.Reports().Start(ctx, AdminReportStartRequest{
		Caller: local, ScopeID: "system", TimeZone: "UTC",
		Start: env.clock.Now().Add(-24 * time.Hour), End: env.clock.Now(),
		Granularity: "day", Formats: []string{"html", "csv"},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建报告: %v", err)
	}
	report := waitPublicReport(t, ctx, env.runtime.Reports(), local, reportStart.ID)
	if report.State != "succeeded" || len(report.Artifacts) == 0 {
		t.Fatalf("报告未成功: %+v", report)
	}
	exportStart, err := env.runtime.Audit().StartExport(ctx, AdminAuditExportStartRequest{
		Caller: local, ScopeID: "system", Format: "csv", MaxRows: 100,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建审计导出: %v", err)
	}
	export := waitPublicExport(t, ctx, env.runtime.Audit(), local, exportStart.ID)
	if export.State != "succeeded" {
		t.Fatalf("审计导出未成功: %+v", export)
	}
	// 报告产物与审计导出都可真实读取；审计事件中应能关联到报告/备份动作。
	reportDownload, err := env.runtime.Reports().OpenArtifact(ctx, AdminReportArtifactRequest{
		Caller: local, ReportID: report.ID, Format: "html",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取报告产物: %v", err)
	}
	if strings.ContainsAny(reportDownload.FileName, `/\`) {
		_ = reportDownload.Reader.Close()
		t.Fatalf("报告产物文件名泄露路径: %q", reportDownload.FileName)
	}
	_ = reportDownload.Reader.Close()
	exportDownload, err := env.runtime.Audit().OpenExport(ctx, AdminAuditExportRequest{
		Caller: local, ExportID: export.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("打开审计导出: %v", err)
	}
	exportContent, err := io.ReadAll(io.LimitReader(exportDownload.Reader, 1<<20))
	_ = exportDownload.Reader.Close()
	if err != nil || len(exportContent) == 0 {
		t.Fatalf("审计导出内容: %d err=%v", len(exportContent), err)
	}
	events, err := env.runtime.Audit().Query(ctx, AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system", Limit: 100, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("审计查询: %v", err)
	}
	foundBackup, foundReport := false, false
	for _, event := range events.Events {
		if strings.Contains(event.Action, "backup") {
			foundBackup = true
		}
		if strings.Contains(event.Action, "report") {
			foundReport = true
		}
	}
	if !foundBackup || !foundReport {
		t.Fatalf("审计事件未关联备份/报告动作: backup=%v report=%v", foundBackup, foundReport)
	}
	diagnostics, err := env.runtime.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("诊断读取: %v", err)
	}
	diagnosticsJSON, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("编码诊断: %v", err)
	}
	exported, err := env.runtime.Diagnostics().Export(ctx, DiagnosticsErrorsRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("诊断导出: %v", err)
	}
	exportedJSON, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("编码诊断导出: %v", err)
	}
	if len(exportedJSON) == 0 {
		t.Fatal("诊断导出为空")
	}
	// 脱敏：不能出现数据库绝对路径、主密钥路径、用户/会话秘密/令牌。
	forbidden := []string{env.runtime.opts.DatabasePath,
		env.runtime.opts.MasterKeyFile, password,
		string(oldSession), reportStart.ID, exportStart.ID}
	for _, secret := range forbidden {
		if secret == "" {
			continue
		}
		if strings.Contains(string(diagnosticsJSON), secret) ||
			strings.Contains(string(exportedJSON), secret) {
			t.Fatalf("诊断/导出泄露敏感内容: %q", secret)
		}
	}

	// 备份→恢复（真实关闭运行时/预演/执行/重开）。
	dbPath := env.runtime.opts.DatabasePath
	keyPath := env.runtime.opts.MasterKeyFile
	recovery := env.runtime.Backup().Recovery()
	stateDir := t.TempDir()
	if err := recovery.Configure(ctx, BackupRecoveryConfigRequest{Caller: local,
		StateDir: stateDir, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Configure recovery: %v", err)
	}
	if _, err := recovery.LoadBackup(ctx, BackupRecoveryLoadRequest{Caller: local,
		BackupID: backupID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("LoadBackup: %v", err)
	}
	env.closeRuntime()
	if err := recovery.Initialize(ctx, BackupRecoveryInitializeRequest{Caller: local,
		Reason: "步骤 247 运维数据回归", Confirm: true,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Initialize recovery: %v", err)
	}
	if _, err := recovery.Rehearse(ctx, BackupRecoveryRestoreRequest{Caller: local,
		Reason: "步骤 247 预演", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Rehearse: %v", err)
	}
	if _, err := recovery.Execute(ctx, BackupRecoveryRestoreRequest{Caller: local,
		Reason: "步骤 247 实际恢复", ConfirmToken: "RESTORE",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Execute restore: %v", err)
	}
	cfg := testConfig()
	reopened, err := Open(ctx, Options{Config: &cfg, DatabasePath: dbPath,
		MasterKeyFile: keyPath, Migrate: false, CreateMasterKey: false,
		OperatorID: "host-operator", Now: env.clock.Now})
	if err != nil {
		t.Fatalf("恢复后重新打开运行时: %v", err)
	}
	defer func() { _ = reopened.Close(context.Background()) }()
	// 备份时点之后的数据消失：旧会话、报告、审计导出都不应复活/存在。
	if _, err := reopened.Sessions().Validate(ctx, oldSession); err == nil {
		t.Fatal("恢复后旧会话必须失效")
	}
	if _, err := reopened.Admin().GetUserProfile(ctx, AdminUserRequest{
		Caller: reopened.LocalAdmin(), UserID: user.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("备份时点用户应保留: %v", err)
	}
	if _, err := reopened.Reports().Get(ctx, AdminReportRequest{Caller: reopened.LocalAdmin(),
		ReportID: report.ID, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("恢复后备份时点之后的报告仍可读取")
	}
	exportList, err := reopened.Audit().ListExports(ctx, AdminAuditExportListRequest{
		Caller: reopened.LocalAdmin(), ScopeID: "system",
		Page: AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("恢复后审计导出列表: %v", err)
	}
	for _, item := range exportList.Exports {
		if item.ID == export.ID {
			t.Fatal("恢复后备份时点之后的审计导出仍存在")
		}
	}
	// 恢复后的诊断仍可读且队列状态可序列化（不要求具体计数）。
	afterReport, err := reopened.Diagnostics().Read(ctx, DiagnosticsRequest{
		Caller: reopened.LocalAdmin(), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("恢复后诊断读取: %v", err)
	}
	if afterReport.Storage.Status == "" || afterReport.Queues.Status == "" {
		t.Fatalf("恢复后诊断不完整: %+v", afterReport)
	}
}
