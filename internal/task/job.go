package task

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// DefaultMaxConcurrent 是执行器默认并发执行任务数。
	DefaultMaxConcurrent = 2
	// MaxAllowedConcurrent 是允许的最大并发执行任务数；与本地资源上限一致，
	// 不允许把单实例执行器配置成无限并发。
	MaxAllowedConcurrent = 6
	// DefaultPollInterval 是队列轮询间隔；本包不做定时调度，只轮询待执行队列。
	DefaultPollInterval = 200 * time.Millisecond
	// MinPollInterval/PollInterval 上界，避免忙等或过慢。
	MinPollInterval = 20 * time.Millisecond
	MaxPollInterval = 5 * time.Second
	// DefaultShutdownTimeout 是停止执行器时等待运行中处理器退出的默认期限。
	DefaultShutdownTimeout = 10 * time.Second
	// MinShutdownTimeout/MaxShutdownTimeout 是关闭期限范围。
	MinShutdownTimeout = 1 * time.Second
	MaxShutdownTimeout = 60 * time.Second
	// DefaultTimeoutSeconds 是任务未指定墙钟上限时的默认值。
	DefaultTimeoutSeconds = 300
	// MinTimeoutSeconds/MaxTimeoutSeconds 是任务墙钟上限范围（1 秒～24 小时）。
	MinTimeoutSeconds = 1
	MaxTimeoutSeconds = 24 * 60 * 60
	// MaxPayloadBytes 是任务载荷 JSON 的最大字节数，防止把执行器当大对象存储。
	MaxPayloadBytes = 16 * 1024
	// MaxJobAttempts 是允许配置的最大尝试次数（含首次执行）；重试必须同时受
	// 退避策略约束，禁止无限重试。
	MaxJobAttempts = 10
	// MaxKindBytes、MaxMutexKeyBytes、MaxReasonBytes 是任务字段上限。
	MaxKindBytes     = 64
	MaxMutexKeyBytes = 128
	MaxReasonBytes   = 256
	// jobIDPrefix 是任务编号前缀。
	jobIDPrefix = "job_"
	// jobIDRandomBytes 是任务编号的随机字节数（128 位）。
	jobIDRandomBytes = 16
	// maxFailureReasonBytes 是写入 failure_reason 的安全说明上限。
	maxFailureReasonBytes = 256
)

// State 是后台任务状态。
type State string

const (
	// StateQueued 表示已入队、等待执行。
	StateQueued State = "queued"
	// StateRunning 表示处理器正在执行。
	StateRunning State = "running"
	// StateSucceeded 表示成功终态。
	StateSucceeded State = "succeeded"
	// StateFailed 表示失败终态（含重启中断恢复）。
	StateFailed State = "failed"
	// StateCancelRequested 表示取消请求已接受，但处理器可能仍在收尾；不是终态。
	StateCancelRequested State = "cancel_requested"
	// StateCancelled 表示实际已取消终态。
	StateCancelled State = "cancelled"
	// StateTimedOut 表示墙钟超时终态。
	StateTimedOut State = "timed_out"
)

// Valid 报告状态是否已定义。
func (s State) Valid() bool {
	switch s {
	case StateQueued, StateRunning, StateSucceeded, StateFailed, StateCancelRequested, StateCancelled, StateTimedOut:
		return true
	default:
		return false
	}
}

// Terminal 报告是否为终态。终态不可被晚到的取消覆盖。
func (s State) Terminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateCancelled || s == StateTimedOut
}

// Job 是持久化的后台任务。Initiator 是可信发起身份，ExecutorID 是执行器稳定
// 标识，Canceller 记录取消请求人；CancellationReason 是取消原因。Payload 只
// 保存 JSON，不保存秘密。Attempt 是已开始的尝试次数，MaxAttempts 是含首次执行
// 的尝试上限；NextAttemptAt 是退避后的最早可领取时间（零值表示立即可领取）。
// PermissionRequired 为 true 时执行器每次尝试前都必须通过可信权限复验。
type Job struct {
	ID                 string
	Kind               string
	State              State
	Initiator          audit.Actor
	ExecutorID         string
	Canceller          *audit.Actor
	CancellationReason string
	Payload            json.RawMessage
	MutexKey           string
	TimeoutSeconds     int
	Attempt            int
	MaxAttempts        int
	PermissionRequired bool
	ErrorCode          string
	FailureReason      string
	RequestID          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	StartedAt          time.Time
	CancelRequestedAt  time.Time
	FinishedAt         time.Time
	NextAttemptAt      time.Time
}

// Deadline 返回任务墙钟截止时间；尚未开始时以创建时间加超时估算。
func (j Job) Deadline() time.Time {
	start := j.StartedAt
	if start.IsZero() {
		start = j.CreatedAt
	}
	return start.Add(time.Duration(j.TimeoutSeconds) * time.Second)
}

// Handler 是任务处理器。
//
// 约定：必须响应 ctx 取消与期限；使用 exec.CommandContext 等方式清理子进程；
// 必须让同一任务的重跑幂等或提供补偿，因为执行器只能保证状态机与审计可靠，
// 不能保证外部副作用恰好执行一次。处理器返回错误时错误文本会被截断并去除控制
// 字符后写入 failure_reason，不得包含秘密。
type Handler func(ctx context.Context, job Job) error

// EnqueueRequest 是入队参数。Actor 必须来自可信调用上下文，不得使用请求参数
// 自称身份；匿名身份被拒绝。MaxAttempts 默认 1（不重试），范围 1～10；
// PermissionRequired 为 true 时执行器必须在每次尝试前复验权限。
type EnqueueRequest struct {
	Kind               string
	Actor              audit.Actor
	Payload            json.RawMessage
	MutexKey           string
	TimeoutSeconds     int
	MaxAttempts        int
	PermissionRequired bool
	RequestID          string
}

// CancelRequest 是取消参数。Actor 是取消请求人（可信上下文），Reason 是取消
// 原因；系统停机取消由执行器以系统主体自动发起，不使用本请求。
type CancelRequest struct {
	JobID     string
	Actor     audit.Actor
	Reason    string
	RequestID string
}

// CancelResult 是取消请求结果。Accepted 表示取消请求被接受（queued 任务会直接
// 变为 cancelled；running 任务进入 cancel_requested，尚未真正取消）。State 是
// 处理后的真实状态；AlreadyRequested 表示此前已接受过取消请求。
type CancelResult struct {
	Accepted         bool
	AlreadyRequested bool
	State            State
}

// NewJobID 生成任务编号：job_ 加 128 位安全随机数的十六进制表示。
func NewJobID() (string, error) {
	buffer := make([]byte, jobIDRandomBytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成任务编号", ErrInternalRandomSource)
	}
	return jobIDPrefix + hex.EncodeToString(buffer), nil
}

// validateJobID 校验任务编号格式：job_ 加 32 位小写十六进制。
func validateJobID(id string) error {
	if len(id) != len(jobIDPrefix)+2*jobIDRandomBytes || !strings.HasPrefix(id, jobIDPrefix) {
		return fmt.Errorf("%w: 任务编号格式无效", ErrInvalidRequest)
	}
	for i := len(jobIDPrefix); i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: 任务编号格式无效", ErrInvalidRequest)
		}
	}
	return nil
}

// normalizeEnqueueRequest 填充默认值并校验入队参数。
func normalizeEnqueueRequest(request EnqueueRequest) (EnqueueRequest, error) {
	if err := validateToken("任务类型", request.Kind, MaxKindBytes, true); err != nil {
		return EnqueueRequest{}, err
	}
	if err := validateTrustedActor(request.Actor); err != nil {
		return EnqueueRequest{}, err
	}
	payload := request.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) > MaxPayloadBytes {
		return EnqueueRequest{}, fmt.Errorf("%w: 任务载荷超过 %d 字节", ErrInvalidRequest, MaxPayloadBytes)
	}
	if !json.Valid(payload) {
		return EnqueueRequest{}, fmt.Errorf("%w: 任务载荷不是合法 JSON", ErrInvalidRequest)
	}
	if err := validateToken("互斥键", request.MutexKey, MaxMutexKeyBytes, false); err != nil {
		return EnqueueRequest{}, err
	}
	timeout := request.TimeoutSeconds
	if timeout == 0 {
		timeout = DefaultTimeoutSeconds
	}
	if timeout < MinTimeoutSeconds || timeout > MaxTimeoutSeconds {
		return EnqueueRequest{}, fmt.Errorf("%w: 任务墙钟上限必须在 %d～%d 秒之间", ErrInvalidRequest, MinTimeoutSeconds, MaxTimeoutSeconds)
	}
	if err := validateCorrelationID("请求编号", request.RequestID); err != nil {
		return EnqueueRequest{}, err
	}
	maxAttempts := request.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1
	}
	if maxAttempts < 1 || maxAttempts > MaxJobAttempts {
		return EnqueueRequest{}, fmt.Errorf("%w: 最大尝试次数必须在 1～%d 之间", ErrInvalidRequest, MaxJobAttempts)
	}
	request.Payload = payload
	request.TimeoutSeconds = timeout
	request.MaxAttempts = maxAttempts
	return request, nil
}

// normalizeCancelRequest 校验取消参数。
func normalizeCancelRequest(request CancelRequest) (CancelRequest, error) {
	if err := validateJobID(request.JobID); err != nil {
		return CancelRequest{}, err
	}
	if err := validateTrustedActor(request.Actor); err != nil {
		return CancelRequest{}, err
	}
	if err := validateReason(request.Reason); err != nil {
		return CancelRequest{}, err
	}
	if err := validateCorrelationID("请求编号", request.RequestID); err != nil {
		return CancelRequest{}, err
	}
	return request, nil
}

// validateTrustedActor 校验可信操作者并拒绝匿名身份。
func validateTrustedActor(actor audit.Actor) error {
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedActor, err)
	}
	if actor.Type == audit.ActorAnonymous {
		return fmt.Errorf("%w: 匿名调用者不能创建或取消任务", ErrUntrustedActor)
	}
	return nil
}

// validateReason 校验取消原因：必填、合法 UTF-8、无控制字符、长度受限；允许
// 中英文可打印文本，但不得包含换行或控制字符。
func validateReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: 取消原因不能为空", ErrInvalidRequest)
	}
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: 取消原因超过 %d 字节", ErrInvalidRequest, MaxReasonBytes)
	}
	if !utf8.ValidString(reason) {
		return fmt.Errorf("%w: 取消原因不是合法 UTF-8", ErrInvalidRequest)
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: 取消原因不能包含控制字符", ErrInvalidRequest)
		}
	}
	return nil
}

// validateToken 校验稳定标识：非空/可选、长度受限、ASCII 字母数字与 . _ -。
func validateToken(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s不能为空", ErrInvalidRequest, name)
		}
		return nil
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidRequest, name, max)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrInvalidRequest, name)
		}
	}
	return nil
}

// validateCorrelationID 校验请求编号的字符集、首字符与长度。
func validateCorrelationID(name, id string) error {
	if id == "" {
		return nil
	}
	if len(id) > 64 {
		return fmt.Errorf("%w: %s超过 64 字节", ErrInvalidRequest, name)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 {
			if !alnum {
				return fmt.Errorf("%w: %s首字符必须是 ASCII 字母或数字", ErrInvalidRequest, name)
			}
			continue
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrInvalidRequest, name)
		}
	}
	return nil
}

// sanitizeFailureReason 把处理器错误文本限制为安全的短说明，不保存堆栈、控制
// 字符或超长内容；处理器必须避免在错误中放入秘密。
func sanitizeFailureReason(message string) string {
	var builder strings.Builder
	for _, r := range message {
		if r < 0x20 || r == 0x7f {
			continue
		}
		builder.WriteRune(r)
		if builder.Len() >= maxFailureReasonBytes {
			break
		}
	}
	trimmed := strings.TrimSpace(builder.String())
	if trimmed == "" {
		return "任务处理器失败"
	}
	return trimmed
}

// discardLogger 返回写入丢弃输出的日志器。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
