package serverapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"net/http"
	"strings"
)

// buildAdminWriteRoutes 构造步骤 156 的管理写路由（用户/组/角色/应用/客服）。
// 写操作复用管理页面适配器（同一 Authorize/领域事务/审计），本层只负责确认/JSON
// 白名单与统一错误码；管理会话强认证与 CSRF 已由 adminapi 外壳强制。
func buildAdminWriteRoutes(managed *ManagedServices, pages *Pages) []adminapi.DomainRoute {
	if managed == nil || pages == nil {
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 12)
	add := func(method, pattern string,
		handler func(ctx context.Context, caller account.Caller, request *http.Request) (any, error)) {
		routes = append(routes, adminapi.DomainRoute{Method: method, Pattern: pattern,
			Handler: func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
				if pages.Admin == nil && pages.RBAC == nil && pages.Support == nil && pages.Apps == nil {
					return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "管理写适配器未装配"}
				}
				return handler(ctx, caller, request)
			}})
	}

	add(http.MethodPost, "users", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Admin.CreateUser(ctx, caller.Actor().ID, ui.UIAdminCreateUser{
			Username: adminString(body, "username"), Nickname: adminString(body, "nickname"),
			Biography: adminString(body, "biography"), Language: adminString(body, "language"),
			Timezone: adminString(body, "timezone")})
		if err != nil {
			return nil, adminUIError(err)
		}
		return adminUserJSON(view), nil
	})
	add(http.MethodPost, "users/{user_id}/state", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		action := adminString(body, "action")
		view, changed, err := pages.Admin.SetUserState(ctx, caller.Actor().ID, adminPathParam(request),
			action, adminInt64(body, "expected_row_version"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		result := adminUserJSON(view)
		result["changed"] = changed
		return result, nil
	})
	add(http.MethodPost, "groups", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Admin.CreateGroup(ctx, caller.Actor().ID, adminString(body, "scope_id"),
			adminString(body, "group_key"), adminString(body, "name"), adminString(body, "description"),
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "scope_id": view.ScopeID, "group_key": view.GroupKey,
			"name": view.Name, "description": view.Description}, nil
	})
	add(http.MethodPost, "roles", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.RBAC.CreateRole(ctx, caller.Actor().ID, ui.UIRBACCreateRole{
			ScopeID: adminString(body, "scope_id"), Key: adminString(body, "key"),
			Name: adminString(body, "name"), Description: adminString(body, "description"),
			Limits: adminString(body, "limits")}, adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "scope_id": view.ScopeID, "key": view.Key,
			"name": view.Name, "enabled": view.Enabled}, nil
	})
	add(http.MethodPost, "roles/{role_id}/assignments", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		result, err := pages.RBAC.AssignRole(ctx, caller.Actor().ID, adminPathParam(request),
			adminString(body, "target_kind"), adminString(body, "target_id"),
			adminRequestID(body, request), adminBool(body, "assign"))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"action": result.Action, "target_kind": result.TargetKind,
			"target_id": result.TargetID, "changed": result.Changed}, nil
	})
	add(http.MethodPut, "applications/{application_id}", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		appID := adminLastPathPart(request)
		view, err := pages.Apps.UpdateApplication(ctx, caller.Actor().ID, appID,
			ui.UIApplicationChange{Name: adminString(body, "name"),
				Description: adminString(body, "description"), Homepage: adminString(body, "homepage"),
				OwnerUserID: adminString(body, "owner_user_id"),
				ContactInfo: adminString(body, "contact_info")},
			adminInt64(body, "expected_row_version"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "name": view.Name, "status": view.Status,
			"row_version": view.RowVersion}, nil
	})
	add(http.MethodPost, "applications/{application_id}/state", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, changed, err := pages.Apps.SetApplicationState(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminBool(body, "enable"),
			adminInt64(body, "expected_row_version"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "status": view.Status, "changed": changed}, nil
	})
	add(http.MethodPost, "support/cases", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Support == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "客服适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Support.CreateCase(ctx, caller.Actor().ID,
			adminString(body, "target_user_id"), adminString(body, "reason"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "target_user_id": view.TargetUserID,
			"status": view.Status, "row_version": view.RowVersion}, nil
	})
	add(http.MethodPost, "support/cases/{case_id}/send-reset", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Support == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "客服适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		result, err := pages.Support.SendReset(ctx, caller.Actor().ID, adminLastPathPart(request),
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"sent": result.Sent, "manual_review": result.ManualReview,
			"status": result.Status}, nil
	})
	add(http.MethodPost, "support/recovery/requests", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Support == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "客服适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Support.CreateRecoveryRequest(ctx, caller.Actor().ID,
			ui.UISupportRecoveryCreate{TargetUserID: adminString(body, "target_user_id"),
				Operation: adminString(body, "operation"), VerificationBasis: adminString(body, "verification_basis"),
				VerificationReference: adminString(body, "verification_reference"),
				EvidenceSummary:       adminString(body, "evidence_summary"), Reason: adminString(body, "reason"),
				Delivery: adminString(body, "delivery"), SupportCaseID: adminString(body, "support_case_id")},
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "status": view.Status, "row_version": view.RowVersion}, nil
	})
	add(http.MethodPost, "support/recovery/{request_id}/approve", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Support == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "客服适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		approval, err := pages.Support.ApproveRecovery(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminString(body, "note"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": approval.ID, "status": approval.Status,
			"approver_user_id": approval.ApproverUserID}, nil
	})
	add(http.MethodPost, "support/recovery/{request_id}/execute", func(ctx context.Context, caller account.Caller, request *http.Request) (any, error) {
		if pages.Support == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "客服适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		execution, err := pages.Support.ExecuteRecovery(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": execution.ID, "status": execution.Status,
			"sessions_revoked": execution.SessionsRevoked,
			"factors_reset":    execution.FactorsReset, "error_code": execution.ErrorCode}, nil
	})
	return routes
}

// adminWriteBody 解析写请求 JSON：要求 confirm=true，拒绝未知/重复字段与超大
// 输入；返回原始字段 map 供白名单取值（confirm 不进入领域输入）。
func adminWriteBody(request *http.Request) (map[string]json.RawMessage, error) {
	if request == nil || request.Body == nil {
		return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "缺少请求体"}
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 64<<10))
	if err != nil {
		return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "读取请求体失败"}
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "请求体不是合法 JSON 对象"}
	}
	confirm := false
	if raw, ok := fields["confirm"]; ok {
		_ = json.Unmarshal(raw, &confirm)
	}
	if !confirm {
		return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "写操作必须显式 confirm=true"}
	}
	delete(fields, "confirm")
	return fields, nil
}

// adminString/adminInt64/adminBool/adminRequestID 读取白名单字段并忽略缺失值。
func adminString(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	var value string
	_ = json.Unmarshal(raw, &value)
	return strings.TrimSpace(value)
}
func adminInt64(fields map[string]json.RawMessage, key string) int64 {
	raw, ok := fields[key]
	if !ok {
		return 0
	}
	var value int64
	_ = json.Unmarshal(raw, &value)
	return value
}
func adminBool(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]
	if !ok {
		return false
	}
	var value bool
	_ = json.Unmarshal(raw, &value)
	return value
}
func adminRequestID(fields map[string]json.RawMessage, request *http.Request) string {
	if value := adminString(fields, "request_id"); value != "" {
		return value
	}
	if request != nil {
		return request.Header.Get("X-Request-ID")
	}
	return ""
}

// adminLastPathPart/adminLastPathPartPrevious 读取当前或倒数第二路径段（{id} 在
// 末段或倒数第二段时使用）。
func adminLastPathPart(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	return parts[len(parts)-1]
}
func adminLastPathPartPrevious(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// adminUserJSON 转换管理用户视图（脱敏）。
func adminUserJSON(view ui.UIAdminUserView) map[string]any {
	return map[string]any{"id": view.UserID, "username": view.Username, "nickname": view.Nickname,
		"status": view.Status, "row_version": view.RowVersion,
		"created_at": view.CreatedAt, "updated_at": view.UpdatedAt}
}

// adminUIError 把页面适配器稳定错误映射到 adminapi DomainError；未知错误不泄露。
func adminUIError(err error) error {
	type coded interface{ Error() string }
	_ = coded(nil)
	var accountErr *ui.UIAdminError
	if errors.As(err, &accountErr) {
		return &adminapi.DomainError{Code: accountErr.Code, Cause: err}
	}
	var rbacErr *ui.UIRBACError
	if errors.As(err, &rbacErr) {
		return &adminapi.DomainError{Code: rbacErr.Code, Cause: err}
	}
	var appsErr *ui.UIAppsError
	if errors.As(err, &appsErr) {
		return &adminapi.DomainError{Code: appsErr.Code, Cause: err}
	}
	var supportErr *ui.UISupportError
	if errors.As(err, &supportErr) {
		return &adminapi.DomainError{Code: supportErr.Code, Cause: err}
	}
	return &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: fmt.Sprintf("管理写失败: %T", err)}
}

// adminList/adminStringList 读取 JSON 数组字段；缺失/类型不符返回 nil。
func adminList(fields map[string]json.RawMessage, key string) []string {
	raw, ok := fields[key]
	if !ok {
		return nil
	}
	var values []string
	_ = json.Unmarshal(raw, &values)
	return values
}
func adminStringList(fields map[string]json.RawMessage, key string) []string {
	return adminList(fields, key)
}
