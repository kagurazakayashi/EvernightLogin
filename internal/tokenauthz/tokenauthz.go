// Package tokenauthz 实现 Token 与应用权限的联合授权判定（步骤 56）。
//
// 它面向可信资源服务（业务应用自己的服务端或宿主嵌入调用），一次完成：
// 访问凭证验证（类型/签名/签发方/有效期/audience/撤销状态）、可信应用身份与
// client_id→资源 audience 映射核对、用户或服务主体识别、应用/成员/账户状态与
// 当前权限（scope 与角色权限取交集）、all/any 组合以及可选数据范围资源检查。
//
// 安全不变量：
//   - 调用者必须是可信资源服务/宿主上下文：ResourceService 只能由可信边界
//     （mTLS 映射、客户端认证或嵌入代码）构造并显式声明 application_id 与
//     audience；绝不接受请求参数自称的 app_id/audience。
//   - 令牌验证只走 internal/token 的成熟实现（ES256、固定 issuer、拒绝
//     jku/x5u/x5c/jwk/crit）；ID Token、Refresh Token、会话秘密都不能冒充
//     Access Token。无状态 JWT 的撤销感知依赖注入的在线撤销检查（
//     internal/oauthflow 的 AccessTokenRevoked），未注入时服务拒绝构造，
//     fail-closed，绝不把“无法检查撤销”当成有效。
//   - 令牌的 client_id 必须映射到可信资源服务声明的同一应用，且该客户端当前
//     登记的 audience 仍包含资源 audience；跨应用、应用停用、客户端注销一律
//     拒绝（APP_SCOPE_MISMATCH/CLIENT_DISABLED/TOKEN_INVALID）。
//   - 业务所需权限由业务服务端确定（Permissions 非空），本服务不接受“空要求
//     即放行”：空列表按参数错误拒绝，避免业务漏配权限要求时静默放行。
//   - 用户主体使用 internal/authz 实时计算当前有效权限（禁用优先、未知/停用/
//     root_only 拒绝、all/any），不缓存权限结果，权限撤销后下一次判定立即生效；
//     服务主体（client_credentials）的权限模型由宿主注入的
//     ServicePrincipalAuthorizer 显式判定，未注入时拒绝，不能把持有服务令牌
//     当成自动获得管理权限，也不能把 scope 当角色权限。
//   - 业务资源归属不能由权限名推断：可选 ResourceID 只按已配置的数据范围交集
//     判定；归属/对象状态必须由业务服务或可信扩展另行校验（本步不实现）。
//   - 依赖（令牌存储、客户端登记、撤销存储、权限存储、服务身份策略）不可用时
//     返回 AUTHZ_UNAVAILABLE 错误，业务必须默认拒绝；不把内部错误细节泄露给
//     无权调用者。本包不新增 HTTP 业务路由之外的依赖，也不启动后台协程。
package tokenauthz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 领域错误哨兵。错误文本不包含令牌原文、用户输入或内部存储细节。
var (
	// ErrOptionsInvalid 表示构造参数缺失或越界（缺依赖必须拒绝构造）。
	ErrOptionsInvalid = errors.New("联合授权判定选项无效")
	// ErrInvalidRequest 表示请求参数错误（协议层 400，非业务拒绝）。
	ErrInvalidRequest = errors.New("联合授权判定请求无效")
	// ErrCallerUntrusted 表示调用者不是可信资源服务/宿主上下文（403）。
	ErrCallerUntrusted = errors.New("调用者不是可信资源服务")
	// ErrUnavailable 表示依赖暂时不可用，无法完成判定（503，业务必须拒绝）。
	ErrUnavailable = errors.New("联合授权判定依赖暂时不可用")
	// ErrInternal 表示未分类内部故障（500）。
	ErrInternal = errors.New("联合授权判定内部错误")
)

// ErrorCode 是与根包错误码注册表一致的字面值（只复用既有 46 码，不新增码）。
type ErrorCode string

const (
	// CodeReqInvalid 请求内容不符合要求（协议参数错误）。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeAccessDenied 请求未获准（精确原因只向受信调用者披露）。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeTokenInvalid 访问凭证无效（签名/格式/签发方/类型/主体不合法）。
	CodeTokenInvalid ErrorCode = "TOKEN_INVALID"
	// CodeTokenExpired 访问凭证已过期。
	CodeTokenExpired ErrorCode = "TOKEN_EXPIRED"
	// CodeTokenRevoked 访问凭证已被撤销（在线撤销标记命中）。
	CodeTokenRevoked ErrorCode = "TOKEN_REVOKED"
	// CodeTokenAudienceMismatch 访问凭证不能用于当前应用资源。
	CodeTokenAudienceMismatch ErrorCode = "TOKEN_AUDIENCE_MISMATCH"
	// CodeClientAuthFailed 调用程序身份验证失败（HTTP 认证器拒绝）。
	CodeClientAuthFailed ErrorCode = "CLIENT_AUTH_FAILED"
	// CodeClientDisabled 应用/客户端已停用。
	CodeClientDisabled ErrorCode = "CLIENT_DISABLED"
	// CodeUserDisabled 账户当前不可使用。
	CodeUserDisabled ErrorCode = "USER_DISABLED"
	// CodeAppMembershipRequired 用户尚未获准使用此应用。
	CodeAppMembershipRequired ErrorCode = "APP_MEMBERSHIP_REQUIRED"
	// CodePermissionRequired 缺少当前操作所需权限。
	CodePermissionRequired ErrorCode = "PERMISSION_REQUIRED"
	// CodePermissionDisabled 此项权限已停用。
	CodePermissionDisabled ErrorCode = "PERMISSION_DISABLED"
	// CodePermissionUnknown 请求的权限未登记。
	CodePermissionUnknown ErrorCode = "PERMISSION_UNKNOWN"
	// CodeAppScopeMismatch 请求超出调用应用范围（跨应用令牌/权限）。
	CodeAppScopeMismatch ErrorCode = "APP_SCOPE_MISMATCH"
	// CodeResourceForbidden 资源不属于获准的数据范围。
	CodeResourceForbidden ErrorCode = "RESOURCE_FORBIDDEN"
	// CodeAuthzUnavailable 暂时无法判定访问权限（依赖不可用）。
	CodeAuthzUnavailable ErrorCode = "AUTHZ_UNAVAILABLE"
	// CodeInternalError 服务发生未预期错误。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// codeMessages 是错误码的直白中文说明，与根包错误码手册一致；业务拒绝响应
// 同时携带 code 与 message，调用者不需要猜测代码含义。
var codeMessages = map[ErrorCode]string{
	CodeReqInvalid:            "请求内容不符合要求",
	CodeAccessDenied:          "请求未获准",
	CodeTokenInvalid:          "访问凭证无效",
	CodeTokenExpired:          "访问凭证已过期",
	CodeTokenRevoked:          "访问凭证已被撤销",
	CodeTokenAudienceMismatch: "访问凭证不能用于当前应用资源",
	CodeClientAuthFailed:      "调用程序身份验证失败",
	CodeClientDisabled:        "应用已停用",
	CodeUserDisabled:          "账户当前不可使用",
	CodeAppMembershipRequired: "用户尚未获准使用此应用",
	CodePermissionRequired:    "缺少当前操作所需权限",
	CodePermissionDisabled:    "此项权限已停用",
	CodePermissionUnknown:     "请求的权限未登记",
	CodeAppScopeMismatch:      "请求超出调用应用范围",
	CodeResourceForbidden:     "不能操作该记录",
	CodeAuthzUnavailable:      "暂时无法判定访问权限",
	CodeInternalError:         "服务发生未预期错误",
}

// MessageOf 返回错误码的直白中文说明；未登记码返回空字符串。
func MessageOf(code ErrorCode) string { return codeMessages[code] }

// CodeOf 把协议/依赖错误映射为已登记错误码（业务拒绝使用 Decision.Code，
// 不经过本函数）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrCallerUntrusted):
		return CodeAccessDenied
	case errors.Is(err, ErrUnavailable):
		return CodeAuthzUnavailable
	default:
		return CodeInternalError
	}
}

// Mode 是权限组合模式（与 internal/authz 同一契约：all 为默认，any 需显式指定）。
type Mode = authz.Mode

const (
	// ModeAll 要求全部所需权限都满足（默认）。
	ModeAll = authz.ModeAll
	// ModeAny 允许任一所需权限满足即可（显式指定）。
	ModeAny = authz.ModeAny
)

// 判定原因码（稳定机器标识，写入受限审计并只向受信调用者返回）。
const (
	reasonTokenInvalid      = "token_invalid"
	reasonTokenExpired      = "token_expired"
	reasonTokenRevoked      = "token_revoked_online"
	reasonAudienceMismatch  = "audience_mismatch"
	reasonClientUnavailable = "client_unavailable"
	reasonClientInactive    = "client_inactive"
	reasonCrossApplication  = "cross_application"
	reasonAudienceRemoved   = "audience_not_registered"
	reasonInvalidSubject    = "invalid_subject"
	reasonPermissionDenied  = "permission_not_granted"
	reasonAuthzUnavailable  = "authz_unavailable"
	reasonServicePolicyMiss = "service_principal_policy_missing"
	reasonServiceDenied     = "service_principal_policy_denied"
	reasonInsufficientScope = "insufficient_scope"
)

// 请求编号前缀与生成随机字节数。
const (
	requestIDPrefix      = "azreq_"
	requestIDRandomBytes = 16
	// maxRequestIDBytes 是请求编号长度上限（与既有请求编号契约一致）。
	maxRequestIDBytes = 64
)

// ResourceService 是可信资源服务身份。字段不导出，只能由可信边界通过
// NewResourceService 构造；绝不能把 HTTP 请求里的 app_id/audience 直接填入。
type ResourceService struct {
	serviceID     string
	applicationID string
	audience      string
}

// NewResourceService 校验并构造可信资源服务身份。serviceID 是写入审计的稳定
// 服务标识，applicationID 是资源所属应用（权限作用范围），audience 是该资源在
// OAuth 客户端登记中的目标资源标识。任一非法返回 ErrOptionsInvalid。
func NewResourceService(serviceID, applicationID, audience string) (ResourceService, error) {
	serviceID = strings.TrimSpace(serviceID)
	actor := audit.Actor{Type: audit.ActorSystem, ID: serviceID}
	if err := actor.Validate(); err != nil {
		return ResourceService{}, fmt.Errorf("%w: 资源服务标识无效", ErrOptionsInvalid)
	}
	if !app.ValidApplicationID(applicationID) {
		return ResourceService{}, fmt.Errorf("%w: 资源所属应用标识无效", ErrOptionsInvalid)
	}
	parsed, err := oauthclient.ParseAudiences([]string{audience})
	if err != nil || len(parsed) != 1 || parsed[0] != audience {
		return ResourceService{}, fmt.Errorf("%w: 资源 audience 无效", ErrOptionsInvalid)
	}
	return ResourceService{serviceID: serviceID, applicationID: applicationID, audience: audience}, nil
}

// ServiceID 返回可信资源服务标识。
func (r ResourceService) ServiceID() string { return r.serviceID }

// ApplicationID 返回资源所属应用（权限作用范围）。
func (r ResourceService) ApplicationID() string { return r.applicationID }

// Audience 返回资源 audience。
func (r ResourceService) Audience() string { return r.audience }

// validate 校验身份字段完整性（防止宿主零值/篡改）。
func (r ResourceService) validate() error {
	if r.serviceID == "" || r.applicationID == "" || r.audience == "" {
		return ErrCallerUntrusted
	}
	if !app.ValidApplicationID(r.applicationID) {
		return ErrCallerUntrusted
	}
	if err := (audit.Actor{Type: audit.ActorSystem, ID: r.serviceID}).Validate(); err != nil {
		return ErrCallerUntrusted
	}
	if parsed, err := oauthclient.ParseAudiences([]string{r.audience}); err != nil ||
		len(parsed) != 1 || parsed[0] != r.audience {
		return ErrCallerUntrusted
	}
	return nil
}

// actor 返回写入审计的系统主体身份。
func (r ResourceService) actor() audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: r.serviceID}
}

// Request 是联合授权判定请求。AccessToken 是 Access Token 原文；Permissions 是
// 业务服务端确定的所需权限（不能由浏览器删减）；Mode 默认 all；ResourceID 可选，
// 只用于数据范围检查；RequestID 由宿主传入或由服务生成，用于关联受限审计。
type Request struct {
	AccessToken string
	Permissions []string
	Mode        authz.Mode
	ResourceID  string
	RequestID   string
	// RequiredScopes 是业务服务端额外要求的 OAuth Scope（可选）。它只用于要求
	// 令牌授权范围必须覆盖的 scope，绝不映射为角色权限：令牌 scope 与所需权限
	// 分别判定、取交集。为空表示不额外要求 scope。
	RequiredScopes []string
}

// PermissionDecision 是单个所需权限的判定结果。
type PermissionDecision struct {
	Key     string    `json:"key"`
	Allowed bool      `json:"allowed"`
	Code    ErrorCode `json:"code,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// Decision 是一次联合判定的完整结果。Allow=false 表示业务拒绝（HTTP 200 +
// allow=false）；Code/Reason 是稳定错误码与精确原因，只向受信资源服务披露。
// 令牌验证失败时不返回 Subject/ClientID 等可能不可信的声明。
type Decision struct {
	Allow     bool      `json:"allow"`
	Code      ErrorCode `json:"code,omitempty"`
	Message   string    `json:"message,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RequestID string    `json:"request_id"`

	// SubjectType/Subject 只在令牌验证通过后披露（user 为真实用户 ID，
	// service 为服务客户端 ID；不暴露 scope 之外的会话或秘密）。
	SubjectType string `json:"subject_type,omitempty"`
	Subject     string `json:"subject,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	// ApplicationID 是本次判定的权限作用范围（可信资源服务所属应用）。
	ApplicationID string `json:"application_id,omitempty"`
	// Scopes 是令牌声明的 OAuth scope；它表达令牌授权范围，不映射为角色权限。
	Scopes []string `json:"scopes,omitempty"`

	// Permissions 是逐项权限判定（受信调用者可见）。
	Permissions []PermissionDecision `json:"permissions,omitempty"`
	// ResourceID 是可选的数据范围检查目标；ResourceAllowed 表示其判定结果。
	ResourceID      string `json:"resource_id,omitempty"`
	ResourceAllowed bool   `json:"resource_allowed,omitempty"`
}

// ServicePrincipal 是已验证的服务身份令牌主体（client_credentials）。
type ServicePrincipal struct {
	ClientID      string
	ApplicationID string
	Scopes        []string
	Audiences     []string
	TokenID       string
}

// ServicePermissionRequest 是服务主体权限判定请求（业务服务确定的要求）。
type ServicePermissionRequest struct {
	Permissions []string
	Mode        authz.Mode
	ResourceID  string
}

// ServicePrincipalDecision 是服务主体权限策略的判定结果。
type ServicePrincipalDecision struct {
	Allow  bool
	Code   ErrorCode
	Reason string
}

// ServicePrincipalAuthorizer 判定服务身份（client_credentials）是否具备所需业务
// 权限。服务主体没有用户角色权限存储，权限模型必须由宿主安全策略显式决定；
// 未注入（nil）时本包对服务主体的权限要求一律拒绝，绝不把持有服务令牌当成自动
// 获得权限，也不把 OAuth scope 当角色权限。
type ServicePrincipalAuthorizer interface {
	AuthorizeServicePrincipal(ctx context.Context, service ResourceService,
		principal ServicePrincipal, request ServicePermissionRequest) (ServicePrincipalDecision, error)
}

// TokenVerifier 是访问凭证验证契约；生产实现为 *internal/token.Service，
// 测试可使用严格替身（只在测试路径）。
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, raw, expectedAudience string) (token.AccessClaims, error)
}

// RevocationChecker 是访问令牌在线撤销检查契约；生产实现为
// *internal/oauthflow.Service 的 AccessTokenRevoked（无状态 JWT 的撤销只能在线
// 感知，未注入时本服务拒绝构造）。返回错误表示存储不可用（fail-closed）。
type RevocationChecker interface {
	AccessTokenRevoked(ctx context.Context, claims token.AccessClaims) (bool, error)
}

// PermissionEngine 是 internal/authz.Service 中本包使用的最小只读接口；本包
// 不缓存权限结果，每次判定都按当前授权状态重新计算。
type PermissionEngine interface {
	Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error)
}

// AuditRecorder 是安全审计失败事件写入契约；生产实现为 *internal/audit.Recorder。
// 审计写入失败只记录运行日志，不改变拒绝判定（判定为只读操作）。
type AuditRecorder interface {
	RecordFailure(ctx context.Context, event audit.Event) error
}

// validUserID 报告用户 ID 是否合法。
func validUserID(userID string) bool { return account.ValidUserID(userID) }

// newRequestID 生成默认请求编号（azreq_ + 128 位随机数的十六进制）。
func newRequestID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, requestIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrInternal)
	}
	return requestIDPrefix + hex.EncodeToString(buffer), nil
}

// normalizeRequestID 校验宿主提供的请求编号并返回规范化值；空值生成新编号。
func normalizeRequestID(raw string, random io.Reader) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return newRequestID(random)
	}
	if len(trimmed) > maxRequestIDBytes || account.ValidateRequestID(trimmed) != nil {
		return "", fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	return trimmed, nil
}

// validateResourceID 校验资源标识：非空、≤authz.MaxResourceIDBytes 字节、无控制
// 字符或首尾空白（与 internal/authz 资源检查契约一致，避免两处语义漂移）。
func validateResourceID(resourceID string) error {
	if resourceID == "" {
		return fmt.Errorf("%w: 资源标识不能为空", ErrInvalidRequest)
	}
	if len(resourceID) > authz.MaxResourceIDBytes {
		return fmt.Errorf("%w: 资源标识过长", ErrInvalidRequest)
	}
	if strings.TrimSpace(resourceID) != resourceID {
		return fmt.Errorf("%w: 资源标识不能包含首尾空白", ErrInvalidRequest)
	}
	for _, character := range resourceID {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%w: 资源标识包含控制字符", ErrInvalidRequest)
		}
	}
	return nil
}

// normalizeMode 校验并规范化 all/any 模式，默认 all。
func normalizeMode(mode authz.Mode) (authz.Mode, error) {
	if mode == "" {
		return authz.ModeAll, nil
	}
	if !mode.Valid() {
		return "", fmt.Errorf("%w: 权限组合模式必须是 all 或 any", ErrInvalidRequest)
	}
	return mode, nil
}

// normalizePermissions 校验并去重所需权限（1～authz.MaxRequirements 个）。
// 空要求按参数错误拒绝：所需权限由业务服务端确定，空列表可能是漏配，不能因此
// 静默放行；权限键非法或超量同样拒绝。
func normalizePermissions(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: 至少需要一个所需权限（空要求不放行）", ErrInvalidRequest)
	}
	if len(keys) > authz.MaxRequirements {
		return nil, fmt.Errorf("%w: 所需权限数量不能超过 %d", ErrInvalidRequest, authz.MaxRequirements)
	}
	seen := make(map[string]struct{}, len(keys))
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := permission.ValidateKey(key)
		if err != nil {
			return nil, fmt.Errorf("%w: 所需权限键无效", ErrInvalidRequest)
		}
		if _, duplicated := seen[value]; duplicated {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

// scopesContainAll 报告令牌 scope 是否覆盖业务要求的全部 scope（精确匹配）。
func scopesContainAll(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		set[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

// containsAudience 报告登记列表是否包含指定 audience（精确匹配）。
func containsAudience(audiences []string, audience string) bool {
	for _, value := range audiences {
		if value == audience {
			return true
		}
	}
	return false
}
