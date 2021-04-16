package login

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// MaxCorrelationIDLength 是 request_id 与 task_id 允许的最大长度（ASCII 字符）。
	MaxCorrelationIDLength = 64
	// MaxPublicMessageLength 是公开错误消息允许的最大字符数（按 Unicode 字符计）。
	MaxPublicMessageLength = 200
	// requestIDPrefix 是本项目生成请求编号的固定前缀。
	requestIDPrefix = "req_"
)

// requestIDFallbackCounter 只在 crypto/rand 不可用时用于生成非秘密的请求编号。
var requestIDFallbackCounter atomic.Uint64

// NewRequestID 生成一个可对外返回的请求编号：固定前缀 "req_" 加 32 位十六进制
// 随机数，总长 36，满足 ValidateRequestID 的限制。请求编号不是秘密，但必须是
// 不可预测且不含控制字符的紧凑字符串，避免日志注入和编号碰撞。
func NewRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return requestIDPrefix + hex.EncodeToString(random[:])
	}
	// crypto/rand 不可用时退回时间加计数器；它不用于安全凭证，只需保证格式和
	// 同一进程内不重复。
	return fmt.Sprintf("%s%016x%016x", requestIDPrefix,
		uint64(time.Now().UnixNano()), requestIDFallbackCounter.Add(1))
}

// ValidateRequestID 校验外部传入或自行生成的请求编号。允许 ASCII 字母、数字、
// 点、下划线和连字符，必须以字母或数字开头，长度 1～MaxCorrelationIDLength。
// 拒绝空白、换行、控制字符和 Unicode 字符，避免日志注入与歧义。
func ValidateRequestID(id string) error {
	return validateCorrelationID("请求编号", id)
}

// ValidateTaskID 校验任务编号，规则与请求编号相同。任务编号生成在后台任务
// 步骤实现，本步只预留字段与校验。
func ValidateTaskID(id string) error {
	return validateCorrelationID("任务编号", id)
}

func validateCorrelationID(label, id string) error {
	if id == "" {
		return fmt.Errorf("%s不能为空", label)
	}
	if len(id) > MaxCorrelationIDLength {
		return fmt.Errorf("%s长度不能超过 %d 个字符", label, MaxCorrelationIDLength)
	}
	if !isASCIIAlnum(id[0]) {
		return fmt.Errorf("%s必须以 ASCII 字母或数字开头", label)
	}
	for index := 0; index < len(id); index++ {
		character := id[index]
		if !isASCIIAlnum(character) && character != '.' && character != '_' && character != '-' {
			return fmt.Errorf("%s只能包含 ASCII 字母、数字、点、下划线和连字符", label)
		}
	}
	return nil
}

func isASCIIAlnum(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9')
}

// ErrorOption 在构造 AppError 时设置可选字段。
type ErrorOption func(*AppError)

// WithCause 设置内部原因。原因只通过 errors.Unwrap/errors.Is/errors.As 访问，
// 不会出现在公开消息、Error()、JSON 或结构化日志中；不得把秘密写入原因文本。
func WithCause(err error) ErrorOption {
	return func(appError *AppError) {
		appError.cause = err
	}
}

// WithRequestID 设置请求编号。非法编号会被忽略，不会写入错误对象；调用方应在
// 接受外部编号前先用 ValidateRequestID 检查。
func WithRequestID(id string) ErrorOption {
	return func(appError *AppError) {
		if ValidateRequestID(id) == nil {
			appError.requestID = id
		}
	}
}

// WithTaskID 设置任务编号。任务编号是预留字段，生成在后台任务步骤实现；非法
// 编号会被忽略。
func WithTaskID(id string) ErrorOption {
	return func(appError *AppError) {
		if ValidateTaskID(id) == nil {
			appError.taskID = id
		}
	}
}

// WithInternalReasonCode 设置受限内部原因码，仅供审计、任务状态或有权诊断者
// 使用。它不会出现在公开消息、JSON、Error() 或日志中。
func WithInternalReasonCode(code string) ErrorOption {
	return func(appError *AppError) {
		if validateCorrelationID("内部原因码", code) == nil {
			appError.reasonCode = code
		}
	}
}

// AppError 是本项目的统一错误类型，分离稳定错误码、可公开消息、请求编号、
// 任务编号与内部原因链。
//
// 安全边界：
//
//   - Error()、JSON、结构化日志只包含错误码、公开消息和编号；不包含内部原因
//     （cause）、内部原因码（reason code）或堆栈。
//   - 公开消息会去除控制字符并限制长度，防止日志注入和过长输出。
//   - 未注册错误码会被替换为 INTERNAL_ERROR，禁止向调用者返回未登记码。
//   - 内部原因通过 Unwrap 保留，供 errors.Is/errors.As 和受限诊断使用；不要把
//     秘密写入原因文本。
type AppError struct {
	code       ErrorCode
	message    string
	requestID  string
	taskID     string
	reasonCode string
	cause      error
}

// NewAppError 构造统一错误。code 必须已注册，否则回退为 INTERNAL_ERROR；
// message 为空时使用手册中的默认公开消息；自定义消息会去除控制字符并限制长度。
func NewAppError(code ErrorCode, message string, options ...ErrorOption) *AppError {
	definition, known := LookupErrorCode(code)
	if !known {
		definition, _ = LookupErrorCode(CodeInternalError)
	}
	if message == "" {
		message = definition.DefaultMessage
	}
	cleaned := sanitizePublicText(message)
	if cleaned == "" {
		cleaned = definition.DefaultMessage
	}
	appError := &AppError{code: definition.Code, message: cleaned}
	if !known {
		appError.reasonCode = "unregistered_error_code"
	}
	for _, option := range options {
		if option != nil {
			option(appError)
		}
	}
	return appError
}

// Code 返回稳定错误码。
func (e *AppError) Code() ErrorCode {
	if e == nil {
		return CodeInternalError
	}
	return e.code
}

// Category 返回错误码分类。
func (e *AppError) Category() ErrorCategory {
	definition, ok := LookupErrorCode(e.Code())
	if !ok {
		return CategoryInternal
	}
	return definition.Category
}

// HTTPStatus 返回手册建议的普通受保护业务接口 HTTP 状态；0 表示手册为“—”，
// 由具体接口或任务结果决定，不强制映射。
func (e *AppError) HTTPStatus() int {
	definition, ok := LookupErrorCode(e.Code())
	if !ok {
		return 500
	}
	return definition.HTTPStatus
}

// Message 返回可公开的直白说明，不包含内部原因。
func (e *AppError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// RequestID 返回本次错误关联的请求编号；没有时为空。
func (e *AppError) RequestID() string {
	if e == nil {
		return ""
	}
	return e.requestID
}

// TaskID 返回本次错误关联的任务编号；没有时为空。任务编号生成在后台任务步骤
// 实现，本步只预留字段。
func (e *AppError) TaskID() string {
	if e == nil {
		return ""
	}
	return e.taskID
}

// InternalReasonCode 返回受限内部原因码，仅供审计、任务状态或有权诊断者使用。
// 不得向普通调用者、公开页面或报告输出。
func (e *AppError) InternalReasonCode() string {
	if e == nil {
		return ""
	}
	return e.reasonCode
}

// Unwrap 返回内部原因，支持 errors.Is/errors.As。内部原因不进入公开输出。
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Error 返回可对外记录或展示的单行文本，格式为
// "CODE: message [request_id=...] [task_id=...]"。不包含内部原因或堆栈。
func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(string(e.code))
	builder.WriteString(": ")
	builder.WriteString(e.message)
	if e.requestID != "" {
		builder.WriteString(" request_id=")
		builder.WriteString(e.requestID)
	}
	if e.taskID != "" {
		builder.WriteString(" task_id=")
		builder.WriteString(e.taskID)
	}
	return builder.String()
}

// Format 实现 fmt.Formatter，确保 %v、%+v、%#v 等格式都只输出公开 Error()，
// 不会泄露内部原因、原因码或未来可能加入的堆栈。
func (e *AppError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

// GoString 实现 fmt.GoStringer，覆盖 %#v 的默认结构体打印。
func (e *AppError) GoString() string {
	return e.Error()
}

// MarshalJSON 输出可公开的错误 JSON，字段与错误码手册的返回约定一致：code、
// message、可选 request_id 和 task_id。内部原因与原因码不序列化。
func (e *AppError) MarshalJSON() ([]byte, error) {
	payload := struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id,omitempty"`
		TaskID    string `json:"task_id,omitempty"`
	}{
		Code:      string(e.Code()),
		Message:   e.Message(),
		RequestID: e.RequestID(),
		TaskID:    e.TaskID(),
	}
	return json.Marshal(payload)
}

// LogValue 实现 slog.LogValuer，让结构化日志只记录错误码、分类、公开消息和
// 编号，不记录内部原因、原因码或错误文本中的潜在机密。
func (e *AppError) LogValue() slog.Value {
	attributes := []slog.Attr{
		slog.String("code", string(e.Code())),
		slog.String("category", string(e.Category())),
		slog.String("message", e.Message()),
	}
	if e.RequestID() != "" {
		attributes = append(attributes, slog.String("request_id", e.RequestID()))
	}
	if e.TaskID() != "" {
		attributes = append(attributes, slog.String("task_id", e.TaskID()))
	}
	return slog.GroupValue(attributes...)
}

// AsAppError 在原因链中查找 AppError；找到返回它和 true。
func AsAppError(err error) (*AppError, bool) {
	if err == nil {
		return nil, false
	}
	var appError *AppError
	if errors.As(err, &appError) {
		return appError, true
	}
	return nil, false
}

// IsErrorCode 报告原因链中是否存在指定错误码的 AppError。
func IsErrorCode(err error, code ErrorCode) bool {
	appError, ok := AsAppError(err)
	return ok && appError.Code() == code
}

// ErrorCodeOf 返回原因链中第一个 AppError 的错误码；没有时返回 false。
func ErrorCodeOf(err error) (ErrorCode, bool) {
	appError, ok := AsAppError(err)
	if !ok {
		return "", false
	}
	return appError.Code(), true
}

// FromError 把任意错误转为 AppError。已经是 AppError 的返回原对象；其他错误
// 包成 INTERNAL_ERROR，生成新的请求编号并保留原因链。nil 返回 nil。
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}
	if appError, ok := AsAppError(err); ok {
		return appError
	}
	return NewAppError(CodeInternalError, "",
		WithCause(err), WithRequestID(NewRequestID()))
}

// sanitizePublicText 把公开文本压成单行：控制字符（含 CR/LF/TAB/NUL）替换为
// 空格、连续空格折叠、首尾去空白，并限制最大字符数。它是日志注入与超长输出的
// 第一道防线，不用于秘密脱敏。
func sanitizePublicText(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	previousSpace := false
	for _, character := range text {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if character == ' ' {
			if previousSpace {
				continue
			}
			previousSpace = true
		} else {
			previousSpace = false
		}
		builder.WriteRune(character)
	}
	cleaned := strings.TrimSpace(builder.String())
	runes := []rune(cleaned)
	if len(runes) > MaxPublicMessageLength {
		cleaned = string(runes[:MaxPublicMessageLength-3]) + "..."
	}
	return cleaned
}
