package serverapp

// 步骤 233：内置管理 API 与页面共用的脱敏运行诊断装配。
//
// 诊断数据由 internal/diag 收集（只读、白名单、无秘密）；授权由本层使用生产
// permissionChecker 在每次请求重新判定 diagnostics.read + 明确 system/应用范围。
// 本文件不新增第二套权限实现，也不把管理会话本身当作权限。

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/diag"
)

// newDiagnosticsCollector 从共享装配依赖构造只读诊断收集器。state 为 nil 时
// 返回 "unknown"；配置路径只用于待重启字段比较。
func newDiagnosticsCollector(deps Deps, state func() string) *diag.Collector {
	var db *sql.DB
	if deps.Store != nil {
		db = deps.Store.DB()
	}
	options := diag.Options{Config: deps.Config, ConfigPath: deps.ConfigPath,
		Build: login.CurrentBuildInfo(), DB: db, Logger: deps.Logger, Now: deps.Now}
	if state != nil {
		options.State = state
	}
	return diag.New(options)
}

// buildAdminDiagnosticsRoutes 构造管理 API 的只读诊断路由。路由仅在诊断依赖
// 可用时注册；授权在每次请求判定。
func buildAdminDiagnosticsRoutes(deps Deps, managed *ManagedServices) []adminapi.DomainRoute {
	if managed == nil || managed.Checker == nil || deps.Store == nil {
		return nil
	}
	collector := newDiagnosticsCollector(deps, nil)
	if collector == nil {
		return nil
	}
	authorize := func(ctx context.Context, caller account.Caller,
		scope diag.Scope) error {
		actor := caller.Actor()
		if actor.Type != audit.ActorUser {
			return &adminapi.DomainError{Code: "ACCESS_DENIED",
				Message: "诊断需要真实管理用户会话"}
		}
		if err := managed.Checker.check(ctx, actor.ID, "diagnostics.read", scope.ID); err != nil {
			return &adminapi.DomainError{Code: "ACCESS_DENIED",
				Message: "无权查看该范围的运行诊断", Cause: err}
		}
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 3)
	routes = append(routes, adminapi.DomainRoute{Method: http.MethodGet,
		Pattern: "diagnostics", Handler: func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			scope, scopeErr := diagnosticsScope(request)
			if scopeErr != nil {
				return nil, scopeErr
			}
			if err := authorize(ctx, caller, scope); err != nil {
				return nil, err
			}
			report, err := collector.Snapshot(ctx, scope)
			if err != nil {
				return nil, diagnosticsDomainError(err)
			}
			return report, nil
		}})
	routes = append(routes, adminapi.DomainRoute{Method: http.MethodGet,
		Pattern: "diagnostics/errors", Handler: func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			scope, scopeErr := diagnosticsScope(request)
			if scopeErr != nil {
				return nil, scopeErr
			}
			if err := authorize(ctx, caller, scope); err != nil {
				return nil, err
			}
			limit, limitErr := diagnosticsLimit(request)
			if limitErr != nil {
				return nil, limitErr
			}
			list, err := collector.RelatedErrors(ctx, scope,
				strings.TrimSpace(request.URL.Query().Get("request_id")), limit)
			if err != nil {
				return nil, diagnosticsDomainError(err)
			}
			return list, nil
		}})
	routes = append(routes, adminapi.DomainRoute{Method: http.MethodGet,
		Pattern: "diagnostics/export", Handler: func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			scope, scopeErr := diagnosticsScope(request)
			if scopeErr != nil {
				return nil, scopeErr
			}
			if err := authorize(ctx, caller, scope); err != nil {
				return nil, err
			}
			limit, limitErr := diagnosticsLimit(request)
			if limitErr != nil {
				return nil, limitErr
			}
			report, err := collector.Snapshot(ctx, scope)
			if err != nil {
				return nil, diagnosticsDomainError(err)
			}
			errorRequestID := strings.TrimSpace(request.URL.Query().Get("request_id"))
			export := map[string]any{"exported_at": deps.Now().UTC(), "report": report}
			if errorRequestID != "" {
				list, listErr := collector.RelatedErrors(ctx, scope, errorRequestID, limit)
				if listErr != nil {
					return nil, diagnosticsDomainError(listErr)
				}
				export["errors"] = list
			}
			return export, nil
		}})
	return routes
}

// diagnosticsScope 解析并校验 scope 查询参数（默认 system）。
func diagnosticsScope(request *http.Request) (diag.Scope, error) {
	raw := strings.TrimSpace(request.URL.Query().Get("scope"))
	if raw == "" || raw == "system" {
		return diag.NormalizeScope(diag.Scope{})
	}
	scope, err := diag.NormalizeScope(diag.Scope{Kind: "application", ID: raw})
	if err != nil {
		return diag.Scope{}, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "诊断作用范围无效", Cause: err}
	}
	return scope, nil
}

// diagnosticsLimit 解析关联错误条数上限（0 使用诊断服务默认，超硬上限拒绝）。
func diagnosticsLimit(request *http.Request) (int, error) {
	raw := strings.TrimSpace(request.URL.Query().Get("limit"))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > diag.MaxErrorLimit {
		return 0, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "诊断错误条数必须在 1～50 之间"}
	}
	return value, nil
}

// diagnosticsDomainError 把诊断收集错误映射为稳定管理 API 错误；不泄露底层文本。
func diagnosticsDomainError(err error) error {
	code := "INTERNAL_ERROR"
	if diag.ErrInvalidScope(err) {
		code = "REQ_INVALID"
	}
	if context.Canceled == err || context.DeadlineExceeded == err {
		code = "INTERNAL_ERROR"
	}
	return &adminapi.DomainError{Code: code, Message: "诊断数据暂时不可用", Cause: err}
}
