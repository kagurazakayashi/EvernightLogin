package login

// 步骤 233：管理页“运行诊断”入口。
//
// 页面本身只做展示；后端适配器负责重新判定 diagnostics.read 权限并返回脱敏数据。
// 该入口是可选能力：宿主未实现 UIAdminDiagnosticsBackend 时不注册路由（404），
// 不会退化为未授权可读或占位假数据。

import (
	"context"
	"net/http"
	"time"
)

// UIPageAdminDiagnosticsOptions 是管理页诊断入口配置。
type UIPageAdminDiagnosticsOptions struct {
	// Backend 是脱敏诊断页面后端；nil 时不注册诊断页面。
	Backend UIAdminDiagnosticsBackend
}

// UIAdminDiagnosticsBackend 是管理页读取脱敏诊断的最小契约。实现必须重新判定
// diagnostics.read 权限；本类型只承载白名单展示字段，不含秘密。
type UIAdminDiagnosticsBackend interface {
	// GetDiagnostics 返回系统范围的脱敏诊断视图；errorRequestID 非空时附带按
	// 请求编号关联的错误事件（有界条数）。
	GetDiagnostics(ctx context.Context, adminID, errorRequestID string) (UIAdminDiagnosticsView, error)
}

// UIAdminDiagnosticsQueueCount 是队列状态计数（不含任务载荷/收件人）。
type UIAdminDiagnosticsQueueCount struct {
	Kind  string
	State string
	Count int64
}

// UIAdminDiagnosticsFlag 是功能开关摘要。
type UIAdminDiagnosticsFlag struct {
	Name    string
	Enabled bool
}

// UIAdminDiagnosticsError 是关联错误事件白名单字段。
type UIAdminDiagnosticsError struct {
	OccurredAt time.Time
	Action     string
	Outcome    string
	ErrorCode  string
	RequestID  string
}

// UIAdminDiagnosticsView 是管理页脱敏诊断视图。
type UIAdminDiagnosticsView struct {
	GeneratedAt          time.Time
	Status               string
	State                string
	Version              string
	ScopeID              string
	StorageStatus        string
	StorageLatencyMS     int64
	QueueCounts          []UIAdminDiagnosticsQueueCount
	FeatureFlags         []UIAdminDiagnosticsFlag
	PendingRestart       []string
	PendingRestartStatus string
	Errors               []UIAdminDiagnosticsError
	ErrorStatus          string
	ErrorRequestID       string
}

// diagnostics 渲染管理页脱敏运行诊断视图。
func (h *adminPageHandlers) diagnostics(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	options := h.pages.options.Diagnostics
	if options == nil || isNilUIValue(options.Backend) {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.diagnostics.unavailable")}, nil
	}
	errorRequestID := request.URL.Query().Get("request_id")
	view, err := options.Backend.GetDiagnostics(ctx, page.Session.UserID, errorRequestID)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.diagnostics.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{"report": view,
		"requestID": errorRequestID}}, nil
}
