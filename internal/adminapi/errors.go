package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
)

// 领域与传输错误。管理 API 不新增错误码：所有错误码必须来自根包注册表投影；
// 领域服务通过各自的 CodeOf 映射到既有码，本包只负责 HTTP 状态与公开说明。
var (
	ErrOptionsInvalid = errors.New("管理 API 配置无效")
	// ErrAccessDenied 表示认证/授权/敏感操作判定的统一拒绝原因；对外不区分
	// “无权”和“不可见”，避免枚举。
	ErrAccessDenied = errors.New("管理 API 请求未获准")
	// ErrInvalidRequest 表示请求参数不符合要求。
	ErrInvalidRequest = errors.New("管理 API 请求无效")
	// ErrUnavailable 表示所请求能力未装配（路由未挂载时不会出现）。
	ErrUnavailable = errors.New("管理 API 能力未装配")
	// ErrBodyTooLarge 表示请求体超过本包上限（含 chunked 无 Content-Length 的
	// 情况）；对外映射 413，而不是笼统的 400。
	ErrBodyTooLarge = errors.New("管理 API 请求体超过允许大小")
)

// errorCode 是管理 API 会返回的错误码（全部为根包既有登记码）。
type errorCode string

const (
	codeReqInvalid        errorCode = "REQ_INVALID"
	codeAuthFailed        errorCode = "AUTH_FAILED"
	codeAccessDenied      errorCode = "ACCESS_DENIED"
	codePermissionRequire errorCode = "PERMISSION_REQUIRED"
	codeReauthRequired    errorCode = "REAUTH_REQUIRED"
	codeResourceForbidden errorCode = "RESOURCE_FORBIDDEN"
	codeReportAccess      errorCode = "REPORT_ACCESS_DENIED"
	codeConflict          errorCode = "CONFLICT"
	codeTaskCancelConf    errorCode = "TASK_CANCEL_CONFLICT"
	codeTaskCancelled     errorCode = "TASK_CANCELLED"
	codeTaskTimeout       errorCode = "TASK_TIMEOUT"
	codeDBUnavailable     errorCode = "DB_UNAVAILABLE"
	codeAuthzUnavailable  errorCode = "AUTHZ_UNAVAILABLE"
	codeAuditWriteFailed  errorCode = "AUDIT_WRITE_FAILED"
	codeExportPathUnsafe  errorCode = "EXPORT_PATH_UNSAFE"
	codeBackupInvalid     errorCode = "BACKUP_INVALID"
	codeBackupFailed      errorCode = "BACKUP_FAILED"
	codeBackupCancelForb  errorCode = "BACKUP_CANCEL_FORBIDDEN"
	codeReportGeneration  errorCode = "REPORT_GENERATION_FAILED"
	codeMailFailed        errorCode = "MAIL_DELIVERY_FAILED"
	codeInternalError     errorCode = "INTERNAL_ERROR"
)

// emittedErrorCodes 是本包可能返回的错误码全集（全部为根包既有登记码）。
// 测试会逐项核对根包注册表与 HTTP 状态，防止出现未登记码或状态漂移。
var emittedErrorCodes = []string{
	string(codeReqInvalid), string(codeAuthFailed), string(codeAccessDenied),
	string(codePermissionRequire), string(codeReauthRequired),
	string(codeResourceForbidden), string(codeReportAccess), string(codeConflict),
	string(codeTaskCancelConf), string(codeTaskCancelled), string(codeTaskTimeout),
	string(codeDBUnavailable), string(codeAuthzUnavailable),
	string(codeAuditWriteFailed), string(codeExportPathUnsafe),
	string(codeBackupInvalid), string(codeBackupFailed), string(codeBackupCancelForb),
	string(codeReportGeneration), string(codeMailFailed), string(codeInternalError),
}

// EmittedErrorCodes 返回本包可能返回的错误码副本，供宿主文档、CLI 与错误码
// 一致性测试使用。它不改变注册表，也不允许调用方新增码。
func EmittedErrorCodes() []string {
	copied := make([]string, len(emittedErrorCodes))
	copy(copied, emittedErrorCodes)
	return copied
}

// fallbackStatus 是根包注册表 HTTPStatus=0（后台任务/警告类）时管理 API 使用的
// 稳定映射：任务结果类默认 409，故障类 500，其余 400。
var fallbackStatus = map[errorCode]int{
	codeTaskCancelled:     http.StatusConflict,
	codeTaskTimeout:       http.StatusGatewayTimeout,
	codeBackupFailed:      http.StatusInternalServerError,
	codeReportGeneration:  http.StatusInternalServerError,
	codeResourceForbidden: http.StatusForbidden,
	codeMailFailed:        http.StatusBadGateway,
}

// problem 是统一错误：稳定错误码、公开说明、HTTP 状态；cause 只用于运行日志，
// 绝不写入响应。
type problem struct {
	status  int
	code    string
	message string
	cause   error
}

// Error 返回单行诊断文本，仅用于错误链与内部日志。
func (p *problem) Error() string {
	if p == nil {
		return ""
	}
	return p.code + ": " + p.message
}

// Unwrap 返回内部原因。
func (p *problem) Unwrap() error {
	if p == nil {
		return nil
	}
	return p.cause
}

// codeProblem 用注册表投影构造错误；未知码一律降级为 INTERNAL_ERROR，防止
// 返回未登记错误码。
func (s *Server) codeProblem(code string, cause error) *problem {
	info, ok := s.codes[code]
	if !ok {
		info, ok = s.codes[string(codeInternalError)]
		if !ok {
			return &problem{status: http.StatusInternalServerError,
				code: string(codeInternalError), message: "服务发生未预期错误", cause: cause}
		}
	}
	status := info.HTTPStatus
	if status == 0 {
		if mapped, exists := fallbackStatus[errorCode(info.Code)]; exists {
			status = mapped
		} else {
			status = http.StatusBadRequest
		}
	}
	message := strings.TrimSpace(info.Message)
	if message == "" {
		message = "请求未获准"
	}
	return &problem{status: status, code: info.Code, message: message, cause: cause}
}

// problemFor 把处理程序/领域服务错误映射为统一 problem。领域错误码优先使用
// 领域 CodeOf 的结果（全部复用根包既有码）；未知错误一律 INTERNAL_ERROR，
// 不向响应泄露原始错误文本、路径或秘密。
func (s *Server) problemFor(ctx context.Context, err error) *problem {
	if err == nil {
		return nil
	}
	var existing *problem
	if errors.As(err, &existing) {
		return existing
	}
	if errors.Is(err, context.Canceled) && ctx != nil && ctx.Err() != nil {
		return s.codeProblem(string(codeReqInvalid), err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return s.codeProblem(string(codeInternalError), err)
	}
	if errors.Is(err, ErrBodyTooLarge) {
		p := s.codeProblem(string(codeReqInvalid), err)
		p.status = http.StatusRequestEntityTooLarge
		p.message = "请求体超过允许的大小"
		return p
	}
	if errors.Is(err, ErrInvalidRequest) {
		return s.codeProblem(string(codeReqInvalid), err)
	}
	if errors.Is(err, ErrAccessDenied) {
		return s.codeProblem(string(codeAccessDenied), err)
	}
	return s.codeProblem(string(codeInternalError), err)
}

// errorPayload 是统一错误响应正文；与根 HTTP 传输层契约保持相同字段，并额外
// 带 ok=false 便于 CLI/宿主统一判断。OAuth 协议响应不使用该结构。
type errorPayload struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// writeProblem 写出统一错误 JSON。响应已开始写出时不再改写。
func (s *Server) writeProblem(w http.ResponseWriter, requestID string, p *problem) {
	if p == nil {
		p = s.codeProblem(string(codeInternalError), nil)
	}
	if p.status < 400 || p.status > 599 {
		p.status = http.StatusInternalServerError
	}
	if p.cause != nil && p.status >= 500 {
		// 只记录错误码与请求编号，不记录可能含秘密或用户输入的原始错误文本。
		s.logger.Error("管理 API 请求失败", "request_id", requestID, "error_code", p.code)
	}
	body, err := json.Marshal(errorPayload{Code: p.code, Message: p.message, RequestID: requestID})
	if err != nil {
		p.status = http.StatusInternalServerError
		body = []byte(`{"ok":false,"code":"INTERNAL_ERROR","message":"服务发生未预期错误","request_id":""}`)
	}
	header := w.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.status)
	_, _ = w.Write(body)
}

// successEnvelope 是统一成功响应：ok、请求编号与数据。列表分页信息放在 data 内，
// 不提供伪造总数。
type successEnvelope struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
	Data      any    `json:"data,omitempty"`
}

// writeSuccess 写出统一成功 JSON。
func (s *Server) writeSuccess(w http.ResponseWriter, requestID string, data any) {
	body, err := json.Marshal(successEnvelope{OK: true, RequestID: requestID, Data: data})
	if err != nil {
		s.writeProblem(w, requestID, s.codeProblem(string(codeInternalError), err))
		return
	}
	header := w.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// isNil 报告接口依赖是否为空（含带类型的 nil 指针），避免“看起来已装配、
// 实际调用空指针”的故障。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return reflected.IsNil()
	default:
		return false
	}
}
