package mailer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TaskKindMailDelivery 是投递任务的稳定类型标识；宿主机把它与 Handler 一起注册
// 到 internal/task 执行器。
const TaskKindMailDelivery = "mail.delivery"

// Action 是投递授权动作。
type Action string

const (
	// ActionEnqueueDelivery 表示创建投递。
	ActionEnqueueDelivery Action = "mail.delivery.enqueue"
	// ActionQueryDelivery 表示查询投递状态。
	ActionQueryDelivery Action = "mail.delivery.query"
	// ActionRetryDelivery 表示对失败投递发起受控重试。
	ActionRetryDelivery Action = "mail.delivery.retry"
)

// Valid 报告动作是否受支持。
func (a Action) Valid() bool {
	switch a {
	case ActionEnqueueDelivery, ActionQueryDelivery, ActionRetryDelivery:
		return true
	}
	return false
}

// Caller 是可信边界建立的操作者上下文（与项目其他领域一致：字段不导出，
// 只能通过构造函数建立，不能由请求参数自称）。
type Caller struct {
	actor audit.Actor
}

// SystemCaller 构造系统组件操作者；默认授权器缺失时受信系统主体仍可执行投递
// 管理操作（历史投递数据由系统流程维护）。
func SystemCaller(componentID string) (Caller, error) {
	return newCaller(audit.ActorSystem, componentID)
}

// LocalAdminCaller 构造本地管理员操作者。
func LocalAdminCaller(operatorID string) (Caller, error) {
	return newCaller(audit.ActorLocalAdmin, operatorID)
}

// UserCaller 构造普通用户操作者；读写他人投递必须由 Authorizer 按数据范围放行。
func UserCaller(userID string) (Caller, error) {
	return newCaller(audit.ActorUser, userID)
}

func newCaller(kind audit.ActorKind, id string) (Caller, error) {
	actor := audit.Actor{Type: kind, ID: id}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 操作者标识无效", ErrInvalidMessage)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回底层审计身份。
func (c Caller) Actor() audit.Actor { return c.actor }

// Authorizer 判定调用者能否对某条投递执行动作。record 为 nil 表示动作不针对
// 具体记录（入队）。实现必须按可信数据范围检查，不能只看动作；返回错误一律按
// 拒绝处理。未配置授权器时只允许 system/local_admin 主体（fail-closed 于普通用户）。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action, record *Record) error
}

const (
	// DefaultMaxAttempts 是单条投递的默认尝试上限（含首次）。
	DefaultMaxAttempts = 3
	// MinMaxAttempts/MaxMaxAttempts 是尝试上限允许范围。
	MinMaxAttempts = 1
	MaxMaxAttempts = 10
	// DefaultDeliveryTimeoutSeconds 是默认单次投递任务超时。
	DefaultDeliveryTimeoutSeconds = 120
	// MinDeliveryTimeoutSeconds/MaxDeliveryTimeoutSeconds 是超时允许范围。
	MinDeliveryTimeoutSeconds = 30
	MaxDeliveryTimeoutSeconds = 600
	// MaxListLimit 是投递查询单页上限。
	MaxListLimit = 100
	// deliveryPayloadPurpose 是加密载荷的用途绑定。
	deliveryPayloadPurpose = "mail.payload"
	// deliveryIDPrefix 是投递记录编号前缀。
	deliveryIDPrefix = "mdl_"
)

// DeliveryState 是投递记录状态。queued/sending 可能因进程重启残留，Handler 用
// 幂等判断重新投递或确认终态。
type DeliveryState string

const (
	// DeliveryQueued 表示已入队，等待任务执行。
	DeliveryQueued DeliveryState = "queued"
	// DeliverySending 表示正在尝试发送。
	DeliverySending DeliveryState = "sending"
	// DeliverySucceeded 表示发送后端已接受邮件。
	DeliverySucceeded DeliveryState = "succeeded"
	// DeliveryFailed 表示终止失败（不可重试或重试次数耗尽）。
	DeliveryFailed DeliveryState = "failed"
	// DeliveryCancelled 表示因取消而中止。
	DeliveryCancelled DeliveryState = "cancelled"
)

// Valid 报告状态是否受支持。
func (s DeliveryState) Valid() bool {
	switch s {
	case DeliveryQueued, DeliverySending, DeliverySucceeded, DeliveryFailed, DeliveryCancelled:
		return true
	}
	return false
}

// Record 是一条持久化投递记录。SealedPayload 是 secrets.Sealer 加密后的模板数据，
// 数据库中不保存明文验证码/链接；邮件正文与渲染结果不落库。
type Record struct {
	ID             string
	IdempotencyKey string
	Kind           Kind
	Recipient      string
	// OwnerType/OwnerID 是入队操作者，用于幂等键归属校验与数据范围授权。
	OwnerType     audit.ActorKind
	OwnerID       string
	State         DeliveryState
	Attempts      int
	MaxAttempts   int
	TaskID        string
	LastErrorCode string
	LastErrorKind FailureKind
	SealedPayload []byte
	RequestID     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ListQuery 是投递查询条件；零值 State/Recipient 表示不过滤。OwnerType/OwnerID
// 是数据范围过滤：普通用户查询时由服务强制为本人的归属，避免枚举他人收件人。
type ListQuery struct {
	State     DeliveryState
	Recipient string
	OwnerType audit.ActorKind
	OwnerID   string
	Limit     int
}

// Store 是投递记录持久化契约。实现必须在 idempotency_key 上保证唯一约束，
// Create 遇到重复键返回已有记录与 created=false，而不是报错或覆盖。
type Store interface {
	Create(ctx context.Context, record Record) (stored Record, created bool, err error)
	Get(ctx context.Context, id string) (Record, error)
	GetByIdempotencyKey(ctx context.Context, key string) (Record, error)
	SetTaskID(ctx context.Context, id, taskID string, now time.Time) error
	MarkSending(ctx context.Context, id string, attempt int, now time.Time) error
	Finish(ctx context.Context, id string, state DeliveryState, errorCode string, kind FailureKind, now time.Time) error
	Requeue(ctx context.Context, id, taskID string, now time.Time) error
	List(ctx context.Context, query ListQuery) ([]Record, error)
}

// AuditRecorder 是投递审计最小契约，生产使用 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
}

// Enqueuer 是任务入队最小契约，生产使用 *task.Executor。
type Enqueuer interface {
	Enqueue(ctx context.Context, request task.EnqueueRequest) (task.Job, error)
}

// DeliveryOptions 是投递服务构造配置。
type DeliveryOptions struct {
	Store     Store
	Sender    Sender
	Templates *TemplateSet
	Sealer    *secrets.Sealer
	Recorder  AuditRecorder
	Enqueuer  Enqueuer
	// Authorizer 是查询/受控重试的授权实现；nil 时这两类操作拒绝。
	Authorizer Authorizer
	// From 是发件地址，必填。
	From Address
	// MaxAttempts 是默认尝试上限；0 使用默认值。
	MaxAttempts int
	// TimeoutSeconds 是单次投递任务超时；0 使用默认值。
	TimeoutSeconds int
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// Random 是投递编号安全随机源；nil 使用 crypto/rand。
	Random io.Reader
}

// DeliveryService 是可靠投递服务：幂等入队、任务执行、状态查询与受控重试。
//
// 语义：一次投递成功只说明发送后端接受了邮件；外部系统不保证恰好一次送达，
// 幂等键用于阻止重复入队，但不能阻止任务重试造成的重复邮件。
type DeliveryService struct {
	opts DeliveryOptions
}

// NewDeliveryService 校验配置并创建投递服务。
func NewDeliveryService(options DeliveryOptions) (*DeliveryService, error) {
	if options.Store == nil || options.Sender == nil || options.Templates == nil ||
		options.Sealer == nil || options.Enqueuer == nil {
		return nil, fmt.Errorf("%w: 存储/发送器/模板/加密器/任务入队器均为必填", ErrOptionsInvalid)
	}
	if options.From.Spec == "" {
		return nil, fmt.Errorf("%w: 发件地址必填", ErrOptionsInvalid)
	}
	if err := validateAddrSpec(options.From.Spec); err != nil {
		return nil, fmt.Errorf("%w: 发件地址: %v", ErrOptionsInvalid, err)
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.MaxAttempts < MinMaxAttempts || options.MaxAttempts > MaxMaxAttempts {
		return nil, fmt.Errorf("%w: 尝试上限必须在 %d～%d", ErrOptionsInvalid, MinMaxAttempts, MaxMaxAttempts)
	}
	if options.TimeoutSeconds == 0 {
		options.TimeoutSeconds = DefaultDeliveryTimeoutSeconds
	}
	if options.TimeoutSeconds < MinDeliveryTimeoutSeconds || options.TimeoutSeconds > MaxDeliveryTimeoutSeconds {
		return nil, fmt.Errorf("%w: 投递超时必须在 %d～%d 秒", ErrOptionsInvalid, MinDeliveryTimeoutSeconds, MaxDeliveryTimeoutSeconds)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &DeliveryService{opts: options}, nil
}

// EnqueueRequest 是入队参数。Actor 必须来自可信上下文；IdempotencyKey 在业务侧
// 按"同一封邮件"稳定生成（例如事件 ID + 收件人），重复入队返回既有记录。
type EnqueueRequest struct {
	Caller         Caller
	IdempotencyKey string
	Kind           Kind
	Recipient      string
	Data           RenderRequest
	RequestID      string
	MaxAttempts    int
}

// EnqueueResult 是入队结果。Duplicate 表示幂等键已存在、没有创建新任务。
type EnqueueResult struct {
	Record    Record
	Duplicate bool
}

// Enqueue 幂等入队一封邮件：先校验模板数据，再加密模板数据落库，最后创建任务。
func (s *DeliveryService) Enqueue(ctx context.Context, request EnqueueRequest) (EnqueueResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.authorize(ctx, request.Caller, ActionEnqueueDelivery, nil); err != nil {
		return EnqueueResult{}, err
	}
	if !request.Kind.Valid() {
		return EnqueueResult{}, fmt.Errorf("%w: 不支持的模板用途 %q", ErrInvalidMessage, request.Kind)
	}
	if len(request.IdempotencyKey) < 8 || len(request.IdempotencyKey) > 128 {
		return EnqueueResult{}, fmt.Errorf("%w: 幂等键长度必须在 8～128 字节", ErrInvalidMessage)
	}
	if _, err := ParseAddress(request.Recipient); err != nil {
		return EnqueueResult{}, err
	}
	if !request.Data.Kind.Valid() || request.Data.Kind != request.Kind {
		return EnqueueResult{}, fmt.Errorf("%w: 入队用途 %q 与模板数据用途 %q 不一致", ErrInvalidMessage, request.Kind, request.Data.Kind)
	}
	if request.MaxAttempts == 0 {
		request.MaxAttempts = s.opts.MaxAttempts
	}
	if request.MaxAttempts < MinMaxAttempts || request.MaxAttempts > MaxMaxAttempts {
		return EnqueueResult{}, fmt.Errorf("%w: 尝试上限必须在 %d～%d", ErrInvalidMessage, MinMaxAttempts, MaxMaxAttempts)
	}
	// 入队前先渲染一次，尽早发现模板数据/链接/注入问题；渲染结果不保存。
	if _, err := s.opts.Templates.Render(request.Data); err != nil {
		return EnqueueResult{}, err
	}
	deliveryID := s.newDeliveryID()
	sealed, err := s.sealPayload(deliveryID, request.Data)
	if err != nil {
		return EnqueueResult{}, err
	}
	now := s.opts.Now().UTC()
	record := Record{
		ID:             deliveryID,
		IdempotencyKey: request.IdempotencyKey,
		Kind:           request.Kind,
		Recipient:      request.Recipient,
		OwnerType:      request.Caller.actor.Type,
		OwnerID:        request.Caller.actor.ID,
		State:          DeliveryQueued,
		MaxAttempts:    request.MaxAttempts,
		SealedPayload:  sealed,
		RequestID:      request.RequestID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	stored, created, err := s.opts.Store.Create(ctx, record)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("%w: 创建投递记录: %v", ErrStoreUnavailable, err)
	}
	if !created {
		// 幂等命中：只有同一归属主体可以取回既有记录，避免用幂等键跨用户探测
		// 或取回他人的收件人/状态。
		if stored.OwnerType != request.Caller.actor.Type || stored.OwnerID != request.Caller.actor.ID {
			return EnqueueResult{}, fmt.Errorf("%w: 幂等键归属不匹配", ErrAccessDenied)
		}
		return EnqueueResult{Record: stored, Duplicate: true}, nil
	}
	job, err := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind:           TaskKindMailDelivery,
		Actor:          request.Caller.actor,
		Payload:        deliveryJobPayload(record.ID),
		MutexKey:       record.ID,
		TimeoutSeconds: s.opts.TimeoutSeconds,
		MaxAttempts:    request.MaxAttempts,
		RequestID:      request.RequestID,
	})
	if err != nil {
		// 入队失败：记录显式标记 failed 并写入可诊断错误码，避免留下无主 queued
		// 记录；调用方可通过受控 Retry 重新投递。取消风暴下仍需写入状态与审计。
		writeCtx := context.WithoutCancel(ctx)
		_ = s.opts.Store.Finish(writeCtx, record.ID, DeliveryFailed, CodeQueueFailed, FailureTransient, s.opts.Now().UTC())
		_ = s.recordAudit(writeCtx, request.Caller.actor, "mail.enqueue_failed", record, audit.OutcomeFailure, CodeQueueFailed, request.RequestID)
		return EnqueueResult{}, fmt.Errorf("%w: 创建投递任务: %v", ErrStoreUnavailable, err)
	}
	if err := s.opts.Store.SetTaskID(ctx, record.ID, job.ID, s.opts.Now().UTC()); err != nil {
		return EnqueueResult{}, fmt.Errorf("%w: 关联投递任务: %v", ErrStoreUnavailable, err)
	}
	record.TaskID = job.ID
	if err := s.recordAudit(ctx, request.Caller.actor, "mail.enqueue", record, audit.OutcomeSuccess, "", request.RequestID); err != nil {
		return EnqueueResult{}, err
	}
	return EnqueueResult{Record: record}, nil
}

// Get 按权限查询单条投递记录（不返回加密载荷）。
func (s *DeliveryService) Get(ctx context.Context, caller Caller, id string) (Record, error) {
	record, err := s.opts.Store.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if err := s.authorize(ctx, caller, ActionQueryDelivery, &record); err != nil {
		return Record{}, err
	}
	record.SealedPayload = nil
	return record, nil
}

// List 按权限分页查询投递记录（不返回加密载荷）。
func (s *DeliveryService) List(ctx context.Context, caller Caller, query ListQuery) ([]Record, error) {
	if err := s.authorize(ctx, caller, ActionQueryDelivery, nil); err != nil {
		return nil, err
	}
	if query.State != "" && !query.State.Valid() {
		return nil, fmt.Errorf("%w: 非法状态 %q", ErrInvalidMessage, query.State)
	}
	if query.Limit == 0 || query.Limit > MaxListLimit {
		query.Limit = MaxListLimit
	}
	// 数据范围：普通用户只能看到本人创建的投递；系统/本地管理员可全量。即使配置
	// 了 Authorizer 也不允许普通用户跨用户枚举（Authorizer 只做动作/记录级判断，
	// 不提供列表数据范围）。
	if caller.actor.Type == audit.ActorUser {
		query.OwnerType = audit.ActorUser
		query.OwnerID = caller.actor.ID
	}
	records, err := s.opts.Store.List(ctx, query)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i].SealedPayload = nil
	}
	return records, nil
}

// Retry 对终止失败的投递发起受控重试。只有 failed 状态允许重试；每次重试重新
// 创建一个任务，幂等键保持不变，不会产生第二条投递记录。
func (s *DeliveryService) Retry(ctx context.Context, caller Caller, id, requestID string) (Record, error) {
	record, err := s.opts.Store.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if err := s.authorize(ctx, caller, ActionRetryDelivery, &record); err != nil {
		return Record{}, err
	}
	if record.State != DeliveryFailed {
		return Record{}, fmt.Errorf("%w: 只有 failed 状态可重试，当前 %s", ErrDeliveryConflict, record.State)
	}
	// 先 CAS failed->queued 再入队：任务即使立刻被领取也能看到 queued 并发送，
	// 不会出现"记录已回 queued 但任务已结束且无人发送"的静默丢失。CAS 失败说明
	// 并发已处理，直接拒绝。
	if err := s.opts.Store.Requeue(ctx, record.ID, "", s.opts.Now().UTC()); err != nil {
		return Record{}, err
	}
	job, enqueueErr := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind:           TaskKindMailDelivery,
		Actor:          caller.actor,
		Payload:        deliveryJobPayload(record.ID),
		MutexKey:       record.ID,
		TimeoutSeconds: s.opts.TimeoutSeconds,
		MaxAttempts:    record.MaxAttempts,
		RequestID:      requestID,
	})
	if enqueueErr != nil {
		// 入队失败回写 failed + 可诊断错误码，不留无主 queued。
		writeCtx := context.WithoutCancel(ctx)
		_ = s.opts.Store.Finish(writeCtx, record.ID, DeliveryFailed, CodeQueueFailed, FailureTransient, s.opts.Now().UTC())
		_ = s.recordAudit(writeCtx, caller.actor, "mail.retry_failed", record, audit.OutcomeFailure, CodeQueueFailed, requestID)
		return Record{}, fmt.Errorf("%w: 创建重试任务: %v", ErrStoreUnavailable, enqueueErr)
	}
	if err := s.opts.Store.SetTaskID(ctx, record.ID, job.ID, s.opts.Now().UTC()); err != nil {
		return Record{}, fmt.Errorf("%w: 关联重试任务: %v", ErrStoreUnavailable, err)
	}
	record.State = DeliveryQueued
	record.TaskID = job.ID
	record.LastErrorCode = ""
	record.LastErrorKind = FailureNone
	if err := s.recordAudit(ctx, caller.actor, "mail.retry", record, audit.OutcomeSuccess, "", requestID); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Handler 是注册到 task 执行器的投递处理器。它必须可重入：已成功/已取消/终止
// 失败的记录不会再次发送；queued/sending 残留（重启恢复）会继续投递。
func (s *DeliveryService) Handler(ctx context.Context, job task.Job) error {
	var payload struct {
		DeliveryID string `json:"delivery_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.DeliveryID == "" {
		return task.NonRetryable(fmt.Errorf("%w: 投递任务载荷无效", ErrInvalidMessage))
	}
	// 读取与终态写入不受调用方取消影响：取消路径也需要可靠记录 cancelled 状态。
	readCtx := context.WithoutCancel(ctx)
	record, err := s.opts.Store.Get(readCtx, payload.DeliveryID)
	if err != nil {
		if errors.Is(err, ErrDeliveryNotFound) {
			return task.NonRetryable(err)
		}
		return err
	}
	switch record.State {
	case DeliverySucceeded, DeliveryCancelled, DeliveryFailed:
		// 终态（含重启前已完成）：幂等，不重复发送。
		return nil
	}
	if err := ctx.Err(); err != nil {
		s.finish(ctx, record, DeliveryCancelled, classifySendError(err), job, "mail.cancelled")
		return task.NonRetryable(err)
	}

	data, err := s.openPayload(record)
	if err != nil {
		s.finish(ctx, record, DeliveryFailed, newSendError(FailurePermanent, CodeInvalidMessage, err), job, "mail.failed")
		return task.NonRetryable(err)
	}
	content, err := s.opts.Templates.Render(data)
	if err != nil {
		s.finish(ctx, record, DeliveryFailed, newSendError(FailurePermanent, CodeInvalidMessage, err), job, "mail.failed")
		return task.NonRetryable(err)
	}
	to, err := ParseAddress(record.Recipient)
	if err != nil {
		s.finish(ctx, record, DeliveryFailed, newSendError(FailurePermanent, CodeAddressRejected, err), job, "mail.failed")
		return task.NonRetryable(err)
	}
	message := Message{From: s.opts.From, To: []Address{to}, Subject: content.Subject, TextBody: content.TextBody}

	if err := s.opts.Store.MarkSending(ctx, record.ID, job.Attempt, s.opts.Now().UTC()); err != nil {
		return err
	}
	sendErr := s.opts.Sender.Send(ctx, message)
	if sendErr == nil {
		// 终态写入不受调用方取消影响：发送已成功，必须可靠记录 succeeded。
		writeCtx := context.WithoutCancel(ctx)
		if err := s.opts.Store.Finish(writeCtx, record.ID, DeliverySucceeded, "", FailureNone, s.opts.Now().UTC()); err != nil {
			return err
		}
		_ = s.recordAudit(writeCtx, job.Initiator, "mail.delivered", record, audit.OutcomeSuccess, "", job.RequestID)
		return nil
	}
	sendErr = classifySendError(sendErr)
	code := CodeOf(sendErr)
	kind := KindOf(sendErr)
	terminal := !IsRetryable(sendErr) || job.Attempt >= record.MaxAttempts
	// 任务被取消/超时时执行器不会再重试本任务；若仍落 queued 会留下无人执行的
	// 孤儿记录（Retry 只允许 failed）。因此取消场景直接落终态 failed + 稳定的
	// 取消错误码，保留受控 Retry 的恢复路径（重复发送可接受，不谎报成功）。
	if ctxErr := ctx.Err(); ctxErr != nil {
		code = CodeCancelled
		kind = FailurePermanent
		terminal = true
	}
	state := DeliveryQueued
	if terminal {
		state = DeliveryFailed
	}
	writeCtx := context.WithoutCancel(ctx)
	if err := s.opts.Store.Finish(writeCtx, record.ID, state, code, kind, s.opts.Now().UTC()); err != nil {
		return err
	}
	action := "mail.retry_scheduled"
	if terminal {
		action = "mail.failed"
	}
	_ = s.recordAudit(writeCtx, job.Initiator, action, record, audit.OutcomeFailure, code, job.RequestID)
	// 返回给任务层的错误只保留稳定代码，避免 SMTP 回显/收件人进入 failure_reason。
	if terminal {
		return task.NonRetryable(safeTaskError(sendErr))
	}
	return safeTaskError(sendErr)
}

// safeTaskError 去掉底层 SMTP 错误文本，只保留分类与稳定代码，防止任务
// failure_reason 写入服务端回显（可能含收件人或服务器细节）。
func safeTaskError(err error) error {
	var sendErr *SendError
	if errors.As(err, &sendErr) {
		return &SendError{Kind: sendErr.Kind, Code: sendErr.Code}
	}
	return newSendError(FailureTransient, CodeUnavailable, nil)
}

// finish 记录终态/重排队并写审计。调用方的 ctx 可能已取消（取消路径），因此
// 状态与审计写入使用剥离取消的 context，避免取消风暴让状态永远停在 queued。
func (s *DeliveryService) finish(ctx context.Context, record Record, state DeliveryState, sendErr error, job task.Job, action string) {
	writeCtx := context.WithoutCancel(ctx)
	code := CodeOf(sendErr)
	kind := KindOf(sendErr)
	_ = s.opts.Store.Finish(writeCtx, record.ID, state, code, kind, s.opts.Now().UTC())
	_ = s.recordAudit(writeCtx, job.Initiator, action, record, audit.OutcomeFailure, code, job.RequestID)
}

// authorize 执行投递授权。未配置授权器时只允许受信系统/本地管理员主体；普通
// 用户读写（含他人数据范围）一律拒绝，必须由宿主提供 Authorizer。
func (s *DeliveryService) authorize(ctx context.Context, caller Caller, action Action, record *Record) error {
	if !action.Valid() {
		return fmt.Errorf("%w: 未定义动作 %q", ErrAccessDenied, action)
	}
	if err := caller.actor.Validate(); err != nil {
		return fmt.Errorf("%w: 操作者: %v", ErrAccessDenied, err)
	}
	trusted := caller.actor.Type == audit.ActorSystem || caller.actor.Type == audit.ActorLocalAdmin
	if s.opts.Authorizer == nil {
		if !trusted {
			return fmt.Errorf("%w: 普通用户操作需要配置投递授权器", ErrAccessDenied)
		}
		return nil
	}
	if err := s.opts.Authorizer.Authorize(ctx, caller, action, record); err != nil {
		return fmt.Errorf("%w: %v", ErrAccessDenied, err)
	}
	return nil
}

// recordAudit 写入投递审计；投递审计失败不回滚已完成的安全操作与投递状态，只
// 返回错误供调用方告警（通知失败不能回滚已完成的安全操作）。
func (s *DeliveryService) recordAudit(ctx context.Context, actor audit.Actor, action string, record Record, outcome audit.Outcome, code, requestID string) error {
	if s.opts.Recorder == nil {
		return nil
	}
	return s.opts.Recorder.Record(ctx, audit.Event{
		Actor:     actor,
		Action:    action,
		Target:    audit.Target{Type: "mail_delivery", ID: record.ID},
		Outcome:   outcome,
		ErrorCode: code,
		RequestID: requestID,
		TaskID:    record.TaskID,
	})
}

// sealPayload 加密模板数据（验证码/找回链接等）。绑定对象 ID 是投递记录 ID，
// 复制密文到其他记录/用途后解密会失败。
func (s *DeliveryService) sealPayload(deliveryID string, data RenderRequest) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: 编码模板数据: %v", ErrInvalidMessage, err)
	}
	sealed, err := s.opts.Sealer.Seal(secrets.Binding{Purpose: deliveryPayloadPurpose, ObjectID: deliveryID, ScopeID: secrets.ScopeSystem}, plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: 加密模板数据: %v", ErrStoreUnavailable, err)
	}
	return sealed, nil
}

// openPayload 解密模板数据；绑定对象 ID 必须是该记录的 ID。
func (s *DeliveryService) openPayload(record Record) (RenderRequest, error) {
	plaintext, err := s.opts.Sealer.Open(secrets.Binding{Purpose: deliveryPayloadPurpose, ObjectID: record.ID, ScopeID: secrets.ScopeSystem}, record.SealedPayload)
	if err != nil {
		return RenderRequest{}, fmt.Errorf("%w: 解密模板数据: %v", ErrStoreUnavailable, err)
	}
	var data RenderRequest
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return RenderRequest{}, fmt.Errorf("%w: 解码模板数据: %v", ErrInvalidMessage, err)
	}
	return data, nil
}

// newDeliveryID 生成投递记录编号：mdl_ 加 128 位安全随机数十六进制。
func (s *DeliveryService) newDeliveryID() string {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		// 随机源失败属于不可用环境；返回带时间戳的编号会破坏唯一性，因此 panic
		// 由上层按失败处理（投递是后台能力，不能静默生成可猜测编号）。
		panic(fmt.Sprintf("mailer: 生成投递编号失败: %v", err))
	}
	return deliveryIDPrefix + hex.EncodeToString(buffer)
}

// deliveryJobPayload 构造投递任务载荷（只含记录 ID，禁止把秘密写进任务载荷）。
func deliveryJobPayload(deliveryID string) json.RawMessage {
	return json.RawMessage(`{"delivery_id":"` + deliveryID + `"}`)
}

// ParseDeliveryState 解析状态文本。
func ParseDeliveryState(value string) (DeliveryState, bool) {
	state := DeliveryState(strings.ToLower(strings.TrimSpace(value)))
	return state, state.Valid()
}
