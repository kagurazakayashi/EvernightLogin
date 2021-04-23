package credential

import (
	"errors"
	"fmt"
)

// 本包错误分为两层：
//   - 对外安全错误：ErrInvalidCredential、ErrStoreUnavailable、ErrRequestInvalid，
//     消息固定、不包含凭证是否存在、令牌、验证码、摘要或数据库细节；
//   - 内部诊断：invalidError 通过 InvalidReason 暴露失败类别，供审计/日志使用，
//     调用方不得把类别直接回传给外部请求。
var (
	// ErrInvalidCredential 表示凭证无效或已失效。未知凭证、用途/目标/应用不匹配、
	// 过期、已消费、已撤销、尝试次数用尽与验证内容错误共用该错误，避免外部据此
	// 判断具体凭证是否存在或处于什么状态。
	ErrInvalidCredential = errors.New("credential: 凭证无效或已失效")
	// ErrRequestInvalid 表示调用方参数格式不合法（不是凭证本身失效）。
	ErrRequestInvalid = errors.New("credential: 请求参数无效")
	// ErrStoreUnavailable 表示凭证存储不可用；此时操作没有成功，调用方不得当作
	// 消费或签发成功处理。
	ErrStoreUnavailable = errors.New("credential: 凭证存储不可用")
	// ErrOptionsInvalid 表示服务构造选项无效。
	ErrOptionsInvalid = errors.New("credential: 服务选项无效")
	// ErrKeyUnavailable 表示验证所需主密钥不可用（例如密钥环缺少记录中的 key_id）。
	// 验证路径会把它映射为对外统一的 ErrInvalidCredential，避免暴露凭证存在性；
	// 签发路径直接返回该错误供内部运维诊断。
	ErrKeyUnavailable = errors.New("credential: 验证密钥不可用")
	// ErrRandomSource 表示安全随机源不可用；此时不会签发任何凭证。
	ErrRandomSource = errors.New("credential: 安全随机源不可用")
)

// Reason 是凭证验证失败的内部原因类别。它只用于结构化日志、审计事件和诊断，
// 不得直接作为外部错误码或响应字段；对外统一映射为 ErrInvalidCredential。
type Reason string

const (
	// ReasonNotFound 表示凭据 ID 不存在。
	ReasonNotFound Reason = "not_found"
	// ReasonBindingMismatch 表示用途、目标、应用或凭证形态与签发时不符。
	ReasonBindingMismatch Reason = "binding_mismatch"
	// ReasonExpired 表示凭证已过有效期。
	ReasonExpired Reason = "expired"
	// ReasonConsumed 表示凭证已经被消费。
	ReasonConsumed Reason = "consumed"
	// ReasonRevoked 表示凭证已被撤销。
	ReasonRevoked Reason = "revoked"
	// ReasonAttemptsExhausted 表示尝试次数已达上限。
	ReasonAttemptsExhausted Reason = "attempts_exhausted"
	// ReasonSecretMismatch 表示提供的令牌或验证码不匹配。
	ReasonSecretMismatch Reason = "secret_mismatch"
	// ReasonConsumeConflict 表示验证通过后条件消费失败，通常是并发消费、恰好过期
	// 或被撤销；调用方绝不能把它当作成功。
	ReasonConsumeConflict Reason = "consume_conflict"
	// ReasonNotActive 表示取消操作时凭证已不是可撤销的活动状态。
	ReasonNotActive Reason = "not_active"
	// ReasonKeyUnavailable 表示验证码所需密钥不在密钥环中。
	ReasonKeyUnavailable Reason = "key_unavailable"
)

// invalidError 是 ErrInvalidCredential 的内部实现，携带失败原因但不改变对外
// 错误文本。Error() 固定返回 ErrInvalidCredential.Error()，因此不同失败原因在
// 外部观察下不可区分。
type invalidError struct {
	reason Reason
}

// Error 返回固定通用消息；不包含凭证 ID、用途、目标或任何秘密。
func (e *invalidError) Error() string {
	return ErrInvalidCredential.Error()
}

// Unwrap 让 errors.Is(err, ErrInvalidCredential) 成立。
func (e *invalidError) Unwrap() error {
	return ErrInvalidCredential
}

// Reason 返回内部失败原因；只有同一进程内有权诊断的代码（审计、日志）可使用。
func (e *invalidError) Reason() Reason {
	return e.reason
}

// newInvalid 构造带内部原因的统一凭证无效错误。
func newInvalid(reason Reason) error {
	return &invalidError{reason: reason}
}

// InvalidReason 返回 err 链中凭证验证失败的内部原因。它不是对外错误的一部分；
// 调用方可以记录到审计/运行日志，但不能写入公开响应。
func InvalidReason(err error) (Reason, bool) {
	var invalid *invalidError
	if errors.As(err, &invalid) {
		return invalid.reason, true
	}
	return "", false
}

// requestInvalid 构造参数错误；detail 只描述字段格式，不包含秘密值。
func requestInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRequestInvalid}, args...)...)
}
