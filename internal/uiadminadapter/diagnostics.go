package uiadminadapter

// 步骤 233：管理页脱敏运行诊断适配器。页面授权由宿主 Authorize 回调重新判定
// diagnostics.read；本适配器只调用只读 diag 收集器并投影白名单展示字段。

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/diag"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// GetDiagnostics 返回管理页脱敏诊断视图；errorRequestID 非空时附带关联错误。
func (a *Adapter) GetDiagnostics(ctx context.Context, adminID,
	errorRequestID string) (ui.UIAdminDiagnosticsView, error) {
	if err := a.check(ctx, adminID, "diagnostics.read"); err != nil {
		return ui.UIAdminDiagnosticsView{}, err
	}
	if a.opts.Diagnostics == nil {
		return ui.UIAdminDiagnosticsView{}, adminErr("INTERNAL_ERROR")
	}
	report, err := a.opts.Diagnostics.Snapshot(ctx, diag.Scope{})
	if err != nil {
		return ui.UIAdminDiagnosticsView{}, adminErr("REQ_INVALID")
	}
	view := ui.UIAdminDiagnosticsView{
		GeneratedAt: report.GeneratedAt, Status: report.Status,
		State: report.State, Version: report.Version.Version,
		ScopeID: report.Scope.ID, StorageStatus: report.Storage.Status,
		StorageLatencyMS:     report.Storage.LatencyMS,
		PendingRestartStatus: report.Config.PendingRestartStatus,
		ErrorRequestID:       errorRequestID,
	}
	for _, item := range report.Queues.Jobs {
		view.QueueCounts = append(view.QueueCounts, ui.UIAdminDiagnosticsQueueCount{
			Kind: "job", State: item.State, Count: item.Count})
	}
	for _, item := range report.Queues.MailDeliveries {
		view.QueueCounts = append(view.QueueCounts, ui.UIAdminDiagnosticsQueueCount{
			Kind: "mail", State: item.State, Count: item.Count})
	}
	flagNames := make([]string, 0, len(report.Config.FeatureFlags))
	for name := range report.Config.FeatureFlags {
		flagNames = append(flagNames, name)
	}
	sortStrings(flagNames)
	for _, name := range flagNames {
		view.FeatureFlags = append(view.FeatureFlags, ui.UIAdminDiagnosticsFlag{
			Name: name, Enabled: report.Config.FeatureFlags[name]})
	}
	for _, field := range report.Config.PendingRestart {
		view.PendingRestart = append(view.PendingRestart, field.Field+" ("+field.Class+")")
	}
	if errorRequestID != "" {
		list, listErr := a.opts.Diagnostics.RelatedErrors(ctx, diag.Scope{},
			errorRequestID, diag.DefaultErrorLimit)
		if listErr != nil {
			view.ErrorStatus = "unavailable"
		} else {
			view.ErrorStatus = list.Status
			for _, entry := range list.Entries {
				view.Errors = append(view.Errors, ui.UIAdminDiagnosticsError{
					OccurredAt: entry.OccurredAt, Action: entry.Action,
					Outcome: entry.Outcome, ErrorCode: entry.ErrorCode,
					RequestID: entry.RequestID})
			}
		}
	}
	return view, nil
}
