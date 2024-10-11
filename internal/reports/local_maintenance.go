package reports

// 步骤 291（本地维护控制台）：报告生成的本地维护窄方法。
//
// 普通 Start 要求管理会话的 reports.read/generate/export 授权与 reports.export
// 敏感策略；本地维护控制台以 OS 访问权限生成显式报告，不要求应用会话/再次认证，
// 但仍复用同一窗口规范化、格式校验、任务入队、持久历史与关键审计实现；任务运行时
// 未启用时入队失败，返回明确稳定错误（不伪造成功）。报告列表/状态查询复用普通
// HistoryList（本地 actor 走既有可见范围）。

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护身份；只应由 cmd/login-setup（经
// internal/setupconsole）调用，不代表 Evernight 账户/HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalMaintenanceStart 提交本地维护报告生成任务；只返回受理状态与报告编号，
// 真实结果/产物由后续列表/状态查询确认（与普通 Start 一致）。
func (s *Service) LocalMaintenanceStart(ctx context.Context,
	caller LocalMaintenanceCaller, request StartRequest) (ReportView, error) {
	if caller.operatorID == "" {
		return ReportView{}, ErrAccessDenied
	}
	accountCaller, err := account.LocalBootstrapCaller(caller.operatorID)
	if err != nil {
		return ReportView{}, err
	}
	request.Caller = accountCaller
	scopeID := strings.TrimSpace(request.ScopeID)
	if scopeID == "" {
		scopeID = "system"
		request.ScopeID = scopeID
	}
	if scopeID != "system" && !app.ValidApplicationID(scopeID) {
		return ReportView{}, fmt.Errorf("%w: 报告作用范围无效（system 或 app_<应用ID>）",
			ErrInvalidRequest)
	}
	return s.startInternal(ctx, request, true)
}

// LocalMaintenanceHistory 列出本地维护可见的报告历史（复用既有可见范围/授权）。
func (s *Service) LocalMaintenanceHistory(ctx context.Context,
	caller LocalMaintenanceCaller, limit int) (HistoryListView, error) {
	if caller.operatorID == "" {
		return HistoryListView{}, ErrAccessDenied
	}
	accountCaller, err := account.LocalBootstrapCaller(caller.operatorID)
	if err != nil {
		return HistoryListView{}, err
	}
	if limit <= 0 || limit > historyMaxLimit {
		limit = historyDefaultLimit
	}
	return s.HistoryList(ctx, HistoryListRequest{Caller: accountCaller, Limit: limit})
}
