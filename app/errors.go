package app

import (
	"context"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// requestIDOption 把合法的请求编号转成错误选项；空值或非法值被忽略（调用方必须
// 先用 resolveRequestID/ValidateRequestID 拒绝非法编号，不在这里静默“修正”）。
func requestIDOption(requestIDs ...string) login.ErrorOption {
	for _, requestID := range requestIDs {
		if login.ValidateRequestID(requestID) == nil {
			return login.WithRequestID(requestID)
		}
	}
	return nil
}

// configError 返回稳定的 CONFIG_INVALID AppError。可选 requestID 用于把本次调用
// 的请求编号带入返回错误；没有合法编号时错误对象不带编号。
func configError(message string, requestIDs ...string) error {
	return login.NewAppError(login.CodeConfigInvalid, message, requestIDOption(requestIDs...))
}

// resolveRequestID 统一处理公开门面一次调用的请求编号，成功链、审计与错误返回
// 共用同一个值：
//   - 显式提供时必须是合法编号（ASCII 字母数字与 . _ -，1～64 字符），非法编号
//     直接返回 REQ_INVALID，且不执行任何领域查询或写入；
//   - 未提供时优先复用 context 中 HTTP 防护层已解析的编号（HTTP 入口与直接 Go
//     调用因此可关联），否则生成一个新的合法编号。
//
// 请求编号不是凭证，只用于关联调用、领域审计与返回错误；它不能用于授权判断。
func resolveRequestID(ctx context.Context, requestID string) (string, error) {
	if requestID != "" {
		if err := login.ValidateRequestID(requestID); err != nil {
			return "", login.NewAppError(login.CodeReqInvalid, "请求编号格式无效")
		}
		return requestID, nil
	}
	if fromContext := transport.RequestIDFromContext(ctx); fromContext != "" &&
		login.ValidateRequestID(fromContext) == nil {
		return fromContext, nil
	}
	return login.NewRequestID(), nil
}

// wrapInternal 把内部错误包装为不泄露内部细节的公开错误：只返回 INTERNAL_ERROR
// 与固定摘要，不保留原始错误链（避免宿主通过 errors.Is/As 或 %v 看到内部路径、
// SQL、密钥材料等信息）。内部错误需要诊断时由内部装配层按脱敏字段记录日志。
// 可选 requestID 用于把本次调用的请求编号带入返回错误。
func wrapInternal(message string, err error, requestIDs ...string) error {
	if err == nil {
		return login.NewAppError(login.CodeInternalError, message, requestIDOption(requestIDs...))
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, message, requestIDOption(requestIDs...))
}

// mapAuthError 把认证错误映射为公开稳定错误；不返回账户存在性细节。
func mapAuthError(err error) error {
	if err == nil {
		return nil
	}
	message := "登录失败"
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "disabled") || strings.Contains(lower, "禁用") {
		return login.NewAppError(login.CodeUserDisabled, "账户当前不可使用")
	}
	return login.NewAppError(login.CodeAuthFailed, message)
}

// mapServiceError 是通用内部错误映射；只返回稳定公开码与直白说明。
func mapServiceError(err error) error {
	if err == nil {
		return nil
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, "操作未完成")
}

// domainCodeToPublic 把各领域模块的稳定错误码投影到根包已登记错误码。领域码只
// 复用根包注册表，不新增、不改语义；未知码回退为 INTERNAL_ERROR。
var domainCodeToPublic = map[string]login.ErrorCode{
	"REQ_INVALID":          login.CodeReqInvalid,
	"AUTH_FAILED":          login.CodeAuthFailed,
	"ACCESS_DENIED":        login.CodeAccessDenied,
	"REAUTH_REQUIRED":      login.CodeReauthRequired,
	"MFA_REQUIRED":         login.CodeMFARequired,
	"MFA_REBIND_REQUIRED":  login.CodeMFARebindRequired,
	"CHALLENGE_INVALID":    login.CodeChallengeInvalid,
	"RATE_LIMITED":         login.CodeRateLimited,
	"CONFLICT":             login.CodeConflict,
	"AUTHZ_UNAVAILABLE":    login.CodeAuthzUnavailable,
	"DB_UNAVAILABLE":       login.CodeDBUnavailable,
	"AUDIT_WRITE_FAILED":   login.CodeAuditWriteFailed,
	"MAIL_DELIVERY_FAILED": login.CodeMailDeliveryFailed,
	"INTERNAL_ERROR":       login.CodeInternalError,
	"USER_DISABLED":        login.CodeUserDisabled,
	// 委派/权限引擎的稳定码（只复用根包已登记错误码）：
	"PERMISSION_REQUIRED":     login.CodePermissionRequired,
	"APP_SCOPE_MISMATCH":      login.CodeAppScopeMismatch,
	"CLIENT_DISABLED":         login.CodeClientDisabled,
	"RESOURCE_FORBIDDEN":      login.CodeResourceForbidden,
	"APP_MEMBERSHIP_REQUIRED": login.CodeAppMembershipRequired,
}

// mapDomainError 把领域错误码映射为稳定公开错误；message 是面向调用者的直白
// 摘要，不包含内部细节、秘密或账户存在性信息。可选 requestID 是本次调用已解析
// 的请求编号，会原样带入返回错误（不重新生成），使调用、领域审计与错误可关联。
func mapDomainError(message string, code string, requestIDs ...string) error {
	if public, ok := domainCodeToPublic[code]; ok {
		return login.NewAppError(public, message, requestIDOption(requestIDs...))
	}
	return login.NewAppError(login.CodeInternalError, message, requestIDOption(requestIDs...))
}

// ===== 公开门面“已授权但目标不存在”的稳定语义 =====

// NotFoundCode 是公开门面“已通过调用身份与权限检查、但目标记录不存在”的稳定
// 公开错误码字符串。
//
// 边界说明：本码不加入根包错误码注册表。注册表的 48 个码描述协议/业务拒绝，
// 而“合法未找到”是授权查询的正常结果，不是拒绝或故障；门面用专用公开类型
// NotFoundError + 本稳定码表达，避免宿主把合法未找到误当成 REQ_INVALID 参数
// 错误，也避免未经授权时用它探测记录是否存在（未通过权限检查时必须返回
// ACCESS_DENIED 等拒绝码，而不是本码）。
const NotFoundCode = "NOT_FOUND"

// ErrNotFound 是公开门面未找到语义的稳定哨兵；errors.Is(err, ErrNotFound) 与
// IsNotFound(err) 都成立。外部模块不需要、也不能导入 internal/account 等内部包。
var ErrNotFound = errors.New("目标记录不存在")

// NotFoundError 表示一次已授权查询（或已授权写入）没有找到目标记录。公开字段
// 只包含固定的资源类别与请求编号，不含查询值（用户名、邮箱等）或内部细节，避免
// 通过消息回显泄露输入或用于探测。
type NotFoundError struct {
	// Resource 是目标资源类别，固定小写英文标识（如 "user"、"role"）。
	Resource string
	// RequestID 是本次调用的请求编号；空编号已按统一规则生成。
	RequestID string
}

// Code 返回稳定公开码 NotFoundCode。注意它刻意不是 login.ErrorCode：NOT_FOUND
// 不加入根包错误码注册表（见上），避免改变已发布的协议/业务拒绝码集合。
func (e *NotFoundError) Code() string { return NotFoundCode }

// Message 返回直白公开说明；按资源类别给出固定文案，不含用户输入。
func (e *NotFoundError) Message() string {
	resource := ""
	if e != nil {
		resource = e.Resource
	}
	switch resource {
	case "user":
		return "未找到目标用户"
	case "role":
		return "未找到目标角色"
	case "application":
		return "未找到目标应用"
	default:
		return "未找到目标记录"
	}
}

// HTTPStatus 返回建议的普通受保护接口 HTTP 状态（404），供宿主协议适配层使用。
func (e *NotFoundError) HTTPStatus() int { return 404 }

// Error 返回可对外记录或展示的单行文本："NOT_FOUND: 未找到目标用户 request_id=..."。
func (e *NotFoundError) Error() string {
	message := e.Message()
	requestID := ""
	if e != nil {
		requestID = e.RequestID
	}
	if requestID == "" {
		return NotFoundCode + ": " + message
	}
	return NotFoundCode + ": " + message + " request_id=" + requestID
}

// Unwrap 返回 ErrNotFound，保证 errors.Is(err, ErrNotFound) 成立。
func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// newNotFoundError 构造带资源类别与本次请求编号的公开未找到错误。
func newNotFoundError(resource, requestID string) error {
	return &NotFoundError{Resource: resource, RequestID: requestID}
}

// IsNotFound 判断错误链是否表示“已授权但目标不存在”。它是外部模块判断该语义的
// 唯一推荐入口，不需要导入 internal 包，也不依赖内部领域错误码。
func IsNotFound(err error) bool {
	return err != nil && errors.Is(err, ErrNotFound)
}

// AsNotFound 在错误链中查找 NotFoundError；找到返回它和 true。
func AsNotFound(err error) (*NotFoundError, bool) {
	if err == nil {
		return nil, false
	}
	var notFound *NotFoundError
	if errors.As(err, &notFound) {
		return notFound, true
	}
	return nil, false
}

// ===== 已授权查询的领域错误投影 =====

// notFoundWhen 报告 err 是否命中给定的领域“目标不存在”哨兵；命中时转换为带本次
// 请求编号的公开 NotFoundError。sentinel 只允许传领域包的 ErrXxxNotFound 值。
func notFoundWhen(err error, sentinel error, resource, requestID string) (error, bool) {
	if err == nil || sentinel == nil {
		return nil, false
	}
	if errors.Is(err, sentinel) {
		return newNotFoundError(resource, requestID), true
	}
	return nil, false
}
