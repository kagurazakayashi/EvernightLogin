package serverapp

// 步骤 234：管理 API 账户有效期读写路由。
//
// 复用账户领域服务的真实授权（users.read/users.update）、root 保护、乐观并发与
// 关键审计；管理会话强认证与 CSRF 由 adminapi 外壳强制。本层只解析白名单请求
// 字段并投影脱敏视图，不直接访问数据库。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// buildAdminValidityRoutes 构造账户有效期读写路由；未装配账户服务时不注册。
func buildAdminValidityRoutes(managed *ManagedServices) []adminapi.DomainRoute {
	if managed == nil || managed.Account == nil {
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 2)
	routes = append(routes, adminapi.DomainRoute{Method: http.MethodGet,
		Pattern: "users/{user_id}/validity", Handler: func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			caller, callerErr := validityAccountCaller(caller, "")
			if callerErr != nil {
				return nil, callerErr
			}
			validity, err := managed.Account.GetUserValidity(ctx, caller,
				adminValidityUserID(request))
			if err != nil {
				return nil, adminValidityError(err)
			}
			return adminValidityJSON(validity), nil
		}})
	routes = append(routes, adminapi.DomainRoute{Method: http.MethodPost,
		Pattern: "users/{user_id}/validity", Handler: func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			body, bodyErr := adminWriteBody(request)
			if bodyErr != nil {
				return nil, bodyErr
			}
			caller, callerErr := validityAccountCaller(caller, adminRequestID(body, request))
			if callerErr != nil {
				return nil, callerErr
			}
			validFrom, timeErr := adminValidityTime(body, "valid_from")
			if timeErr != nil {
				return nil, timeErr
			}
			validUntil, timeErr := adminValidityTime(body, "valid_until")
			if timeErr != nil {
				return nil, timeErr
			}
			result, err := managed.Account.SetValidity(ctx, caller,
				account.ValidityCommandRequest{UserID: adminValidityUserID(request),
					ValidFrom: validFrom, ValidUntil: validUntil,
					ExpectedRowVersion: adminInt64(body, "expected_row_version")})
			if err != nil {
				return nil, adminValidityError(err)
			}
			validity, validityErr := managed.Account.GetUserValidity(ctx, caller,
				result.User.ID)
			if validityErr != nil {
				return nil, adminValidityError(validityErr)
			}
			view := adminValidityJSON(validity)
			view["changed"] = result.Changed
			view["previous_valid_from"] = formatOptionalTime(result.PreviousValidFrom)
			view["previous_valid_until"] = formatOptionalTime(result.PreviousValidUntil)
			return view, nil
		}})
	return routes
}

// validityAccountCaller 要求真实管理用户会话并绑定请求编号；不接受其他主体类型。
func validityAccountCaller(caller account.Caller,
	requestID string) (account.Caller, error) {
	if caller.Actor().Type != audit.ActorUser {
		return account.Caller{}, &adminapi.DomainError{Code: "ACCESS_DENIED",
			Message: "账户有效期管理需要真实管理用户会话"}
	}
	userCaller, err := account.UserCaller(caller.Actor().ID)
	if err != nil {
		return account.Caller{}, &adminapi.DomainError{Code: "ACCESS_DENIED",
			Message: "管理会话主体无效"}
	}
	if requestID == "" {
		return userCaller, nil
	}
	bound, err := userCaller.WithRequestID(requestID)
	if err != nil {
		return account.Caller{}, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "请求编号格式无效"}
	}
	return bound, nil
}

// adminValidityTime 解析可选 RFC3339 时间字段；缺省/null/空串表示不限制该端。
func adminValidityTime(fields map[string]json.RawMessage, key string) (*time.Time, error) {
	raw := adminString(fields, key)
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: key + " 必须是 RFC3339 UTC 时间"}
	}
	return &parsed, nil
}

// adminValidityJSON 投影脱敏有效期视图（时间统一 UTC RFC3339Nano）。
func adminValidityJSON(validity account.UserValidity) map[string]any {
	return map[string]any{"user_id": validity.UserID, "status": string(validity.Status),
		"is_root":     validity.IsRoot,
		"valid_from":  formatOptionalTime(validity.ValidFrom),
		"valid_until": formatOptionalTime(validity.ValidUntil),
		"row_version": validity.RowVersion, "available": validity.Available,
		"reason": string(validity.Reason), "checked_at": validity.CheckedAt}
}

// formatOptionalTime 输出 UTC RFC3339Nano；nil 输出 JSON null。
func formatOptionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// adminValidityError 把账户领域错误映射为稳定管理 API 错误码；不泄露底层文本。
func adminValidityError(err error) error {
	code := string(account.CodeOf(err))
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &adminapi.DomainError{Code: code, Message: "账户有效期操作失败", Cause: err}
}

// adminValidityUserID 从 /users/{user_id}/validity 路径取用户 ID（倒数第二段）。
func adminValidityUserID(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}
