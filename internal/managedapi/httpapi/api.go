// Package httpapi 是业务托管管理 API 的 HTTP 传输层（步骤 147）。
//
// 边界：
//   - 认证主体只能由可信边界建立：用户会话 secret 来自既有 session.Service；
//     应用服务身份 secret/证书由 managedapi 内的真实 oauthclient 校验。app_id
//     只来自 URL 路径与认证主体，绝不接受 query/body 自报。
//   - 本包只做传输：严格 JSON、API 版本/request_id/envelope/HTTP 状态、幂等记录；
//     操作/字段/对象范围/行版本/审计仍由 internal/managedapi 统一判定。
//   - 不复用管理 adminapi（管理强会话与业务应用凭据是不同认证边界）。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	// DefaultBasePath 是业务托管管理 API 默认挂载前缀。
	DefaultBasePath = "/api/managed/v1"
	// APIVersion 是本传输层唯一接受的版本，必须同时出现在路径与请求头。
	APIVersion = "v1"
	// DefaultMaxBodyBytes 是单个请求体上限（1 MiB）。
	DefaultMaxBodyBytes int64 = 1 << 20
	// MaxIdempotencyKeyBytes 是幂等键长度上限。
	MaxIdempotencyKeyBytes = 200
)

// Service 是本传输层使用的托管管理服务子集；生产实现是 *managedapi.Service。
type Service interface {
	GetApplication(ctx context.Context, principal managedapi.Principal,
		request managedapi.GetApplicationRequest) (managedapi.View, error)
	ListMembers(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListMembersRequest) (managedapi.MemberListResult, error)
	GetMember(ctx context.Context, principal managedapi.Principal,
		request managedapi.GetMemberRequest) (managedapi.MemberView, error)
	UpdateMemberProfile(ctx context.Context, principal managedapi.Principal,
		request managedapi.UpdateMemberProfileRequest) (managedapi.MemberView, error)
	UpdateMemberStatus(ctx context.Context, principal managedapi.Principal,
		request managedapi.MemberActionRequest, enable bool) (managedapi.MemberView, error)
	RemoveMember(ctx context.Context, principal managedapi.Principal,
		request managedapi.MemberActionRequest) error
	CreateUserWithMembership(ctx context.Context, principal managedapi.Principal,
		request managedapi.CreateUserRequest) (managedapi.MemberView, error)

	ListGroups(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListGroupsRequest) (managedapi.ListResult, error)
	GetGroup(ctx context.Context, principal managedapi.Principal,
		request managedapi.GetGroupRequest) (managedapi.View, error)
	CreateGroup(ctx context.Context, principal managedapi.Principal,
		request managedapi.CreateGroupRequest) (managedapi.View, error)
	UpdateGroup(ctx context.Context, principal managedapi.Principal,
		request managedapi.UpdateGroupRequest) (managedapi.View, error)
	DeleteGroup(ctx context.Context, principal managedapi.Principal,
		request managedapi.DeleteGroupRequest) error
	ListGroupMembers(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListGroupMembersRequest) (managedapi.ListResult, error)
	UpdateGroupMembers(ctx context.Context, principal managedapi.Principal,
		request managedapi.GroupMembersRequest, add bool) error

	ListRoles(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListRolesRequest) (managedapi.ListResult, error)
	GetRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.GetRoleRequest) (managedapi.View, error)
	CreateRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.CreateRoleRequest) (managedapi.View, error)
	UpdateRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.UpdateRoleRequest) (managedapi.View, error)
	DeleteRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.DeleteRoleRequest) error
	ListRolePermissions(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListRoleSubresourceRequest) ([]managedapi.View, error)
	ListRoleAssignments(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListRoleSubresourceRequest) (map[string]any, error)
	AssignUserRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.RoleTargetRequest, assign bool) error
	AssignGroupRole(ctx context.Context, principal managedapi.Principal,
		request managedapi.RoleGroupTargetRequest, assign bool) error

	ListPermissions(ctx context.Context, principal managedapi.Principal,
		request managedapi.ListPermissionsRequest) (managedapi.ListResult, error)
	GetPermission(ctx context.Context, principal managedapi.Principal,
		request managedapi.GetPermissionRequest) (managedapi.View, error)
	CreatePermission(ctx context.Context, principal managedapi.Principal,
		request managedapi.CreatePermissionRequest) (managedapi.View, error)
	UpdatePermission(ctx context.Context, principal managedapi.Principal,
		request managedapi.UpdatePermissionRequest) (managedapi.View, error)
	DeletePermission(ctx context.Context, principal managedapi.Principal,
		request managedapi.PermissionActionRequest) error
	SetPermissionEnabled(ctx context.Context, principal managedapi.Principal,
		request managedapi.PermissionActionRequest, enable bool) (managedapi.View, error)
}

// SessionService 是从请求恢复真实会话的最小契约；生产实现是 *session.Service。
type SessionService interface {
	SessionSecretFromRequest(request *http.Request) (string, bool)
	Validate(ctx context.Context, secret string) (session.Session, error)
}

// ErrorCode / APIError 是传输层稳定错误；code 必须来自根错误码注册表。
type APIError struct {
	HTTPStatus int
	Code       string
	Message    string
	Retryable  bool
}

func (e APIError) Error() string { return e.Code + ": " + e.Message }

// Envelope 是成功响应包络。
type Envelope struct {
	RequestID  string `json:"request_id"`
	APIVersion string `json:"api_version"`
	Data       any    `json:"data,omitempty"`
}

// ErrorEnvelope 是失败响应包络。
type ErrorEnvelope struct {
	RequestID  string       `json:"request_id"`
	APIVersion string       `json:"api_version"`
	Error      ErrorPayload `json:"error"`
}

// ErrorPayload 是稳定错误信息（不含内部细节）。
type ErrorPayload struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// IdempotencyScope 是一次幂等记录的作用域；应用、主体与 key 三元组隔离。
type IdempotencyScope struct {
	ApplicationID string
	PrincipalKind string
	PrincipalID   string
	Key           string
}

// StoredResponse 是已完成请求可重放的响应；不包含认证头或请求明文。
type StoredResponse struct {
	Status int
	Body   []byte
}

// IdempotencyStore 是幂等记录持久化契约。Begin 必须原子插入或返回已有记录：
//   - 已有 completed 且 request_hash 相同：返回 stored 供重放；
//   - 已有 completed 但 hash 不同：conflict=true；
//   - 已有 in_progress：conflict=true（不得把未完成当成成功）。
type IdempotencyStore interface {
	Begin(ctx context.Context, scope IdempotencyScope, operation, requestHash string,
		now, expiresAt time.Time) (stored *StoredResponse, conflict bool, err error)
	Complete(ctx context.Context, scope IdempotencyScope, status int, body []byte) error
	Abort(ctx context.Context, scope IdempotencyScope) error
}

// Error helpers for tests/adapters.
func invalidRequest(message string) APIError {
	return APIError{HTTPStatus: http.StatusBadRequest, Code: string(managedapi.CodeReqInvalid), Message: message}
}
func accessDenied(message string) APIError {
	return APIError{HTTPStatus: http.StatusForbidden, Code: string(managedapi.CodeAccessDenied), Message: message}
}
func unauthorized(message string) APIError {
	return APIError{HTTPStatus: http.StatusUnauthorized, Code: string(managedapi.CodeAccessDenied), Message: message}
}
func conflict(message string) APIError {
	return APIError{HTTPStatus: http.StatusConflict, Code: string(managedapi.CodeConflict), Message: message}
}
func unavailable(message string) APIError {
	return APIError{HTTPStatus: http.StatusServiceUnavailable, Code: string(managedapi.CodeDBUnavailable), Message: message}
}

// asAPIError 把领域/传输错误映射为稳定 HTTP 错误；未知错误只返回内部错误，不泄露细节。
func asAPIError(err error) APIError {
	var apiErr APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	code := managedapi.CodeOf(err)
	switch code {
	case managedapi.CodeReqInvalid:
		return APIError{HTTPStatus: http.StatusBadRequest, Code: string(code), Message: "请求参数或字段未通过校验"}
	case managedapi.CodeAccessDenied, managedapi.CodePermissionRequired,
		managedapi.CodeAppMembershipRequired, managedapi.CodeAppScopeMismatch,
		managedapi.CodeResourceForbidden:
		return APIError{HTTPStatus: http.StatusForbidden, Code: string(code), Message: "当前主体无权执行该操作或访问该对象"}
	case managedapi.CodeUserDisabled, managedapi.CodeClientDisabled:
		return APIError{HTTPStatus: http.StatusLocked, Code: string(code), Message: "目标账户或应用已停用"}
	case managedapi.CodeConflict:
		return APIError{HTTPStatus: http.StatusConflict, Code: string(code), Message: "数据已变化或请求与幂等记录冲突，请重新读取后再试"}
	case managedapi.CodeDBUnavailable:
		return APIError{HTTPStatus: http.StatusServiceUnavailable, Code: string(code), Message: "存储暂时不可用，操作未完成", Retryable: true}
	case managedapi.CodeAuditWriteFailed:
		return APIError{HTTPStatus: http.StatusServiceUnavailable, Code: string(code), Message: "安全审计不可用，操作未完成", Retryable: true}
	case managedapi.CodeRateLimited:
		return APIError{HTTPStatus: http.StatusTooManyRequests, Code: string(code), Message: "请求过于频繁", Retryable: true}
	default:
		return APIError{HTTPStatus: http.StatusInternalServerError, Code: string(managedapi.CodeInternalError), Message: "服务无法完成请求"}
	}
}

// marshalResponse 编码 envelope；失败时返回内部错误（不会写半截 JSON）。
func marshalResponse(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		fallback := ErrorEnvelope{Error: ErrorPayload{Code: string(managedapi.CodeInternalError),
			Message: "响应编码失败"}}
		encoded, _ = json.Marshal(fallback)
	}
	return encoded
}
