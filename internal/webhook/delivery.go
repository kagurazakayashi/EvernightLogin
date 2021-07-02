package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/netguard"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

const (
	// 请求头名称（消费方验证契约，README 与 examples/webhookverify 同步）。
	headerEventID    = "X-Evernight-Event-Id"
	headerEventType  = "X-Evernight-Event-Type"
	headerDeliveryID = "X-Evernight-Delivery-Id"
	headerTimestamp  = "X-Evernight-Timestamp"
	headerSignature  = "X-Evernight-Signature"
	userAgentValue   = "EvernightLogin-Webhook/1.0"
	// 失败分类（写入投递记录，供失败查询/统计；不含远端回显）。
	kindRetryable = "retryable"
	kindPermanent = "permanent"
	kindCancelled = "cancelled"
	kindTimeout   = "timeout"
)

// Handler 是注册到 internal/task 执行器的投递处理器。它必须可重入：终态直接返回；
// queued/sending 残留（重启恢复）继续投递。每次尝试重新校验目标、重新签名（时间戳
// 刷新）并重新分类响应；成功与否以投递记录终态为准。
func (s *Service) Handler(ctx context.Context, job task.Job) error {
	var payload struct {
		DeliveryID string `json:"delivery_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil || !validDeliveryID(payload.DeliveryID) {
		return task.NonRetryable(fmt.Errorf("%w: 投递任务载荷无效", ErrInvalidRequest))
	}
	readCtx := context.WithoutCancel(ctx)
	delivery, found, err := s.opts.Store.GetDelivery(readCtx, payload.DeliveryID)
	if err != nil {
		return err
	}
	if !found {
		return task.NonRetryable(fmt.Errorf("%w: 投递记录不存在", ErrDeliveryNotFound))
	}
	switch delivery.State {
	case DeliverySucceeded, DeliveryCancelled:
		return nil
	case DeliveryFailed:
		// 已终态失败（含重启前/重试耗尽/入队失败）：队列残留不再发送。
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		// 任务墙钟到期时执行器会记 timed_out 且不再重排：直接写 failed + TASK_TIMEOUT，
		// 否则投递记录会卡在 queued 且无任务、无法经 RetryDelivery 恢复。只有明确取消
		// （context.Canceled）才写 cancelled。
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return s.finishWallClockTimeout(readCtx, delivery, job)
		}
		s.finishCancelled(readCtx, delivery, job)
		return task.NonRetryable(ctxErr)
	}
	event, eventFound, err := s.opts.Store.GetEvent(readCtx, delivery.EventID)
	if err != nil {
		return err
	}
	if !eventFound {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "event_missing", 0)
		return task.NonRetryable(fmt.Errorf("%w: 事件记录不存在", ErrEventInvalid))
	}
	endpoint, endpointFound, err := s.opts.Store.GetEndpoint(readCtx, delivery.EndpointID)
	if err != nil {
		return err
	}
	if !endpointFound || endpoint.Status != EndpointActive {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "endpoint_disabled", 0)
		return task.NonRetryable(fmt.Errorf("%w: 端点已停用或不存在", ErrEndpointNotFound))
	}
	active, err := s.opts.Store.ApplicationActive(readCtx, endpoint.ApplicationID)
	if err != nil {
		return err
	}
	if !active {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "application_disabled", 0)
		return task.NonRetryable(fmt.Errorf("%w: 应用已停用", ErrAccessDenied))
	}
	// 每次尝试都重新校验目标 URL（不信任登记时的解析结果）并重新解析 DNS。
	target, err := s.validator.ValidateURL(endpoint.URL)
	if err != nil {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "endpoint_blocked", 0)
		return task.NonRetryable(fmt.Errorf("%w: %v", ErrEndpointBlocked, err))
	}
	now := s.now()
	secrets, err := s.opts.Store.UsableSecrets(readCtx, endpoint.ID, now)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "signing_secret_missing", 0)
		return task.NonRetryable(fmt.Errorf("%w: 没有可用签名密钥", ErrSecretNotFound))
	}
	body, err := buildEventBody(event, delivery.ApplicationID)
	if err != nil {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "event_payload_invalid", 0)
		return task.NonRetryable(fmt.Errorf("%w: 事件体构建失败", ErrEventInvalid))
	}
	keys := make([][]byte, 0, len(secrets))
	for _, secret := range secrets {
		plaintext, openErr := s.openSecret(secret)
		if openErr != nil {
			continue
		}
		keys = append(keys, plaintext)
	}
	if len(keys) == 0 {
		s.finishTerminal(readCtx, delivery, job, kindPermanent, "signing_secret_unavailable", 0)
		return task.NonRetryable(fmt.Errorf("%w: 签名密钥解密失败", ErrStoreUnavailable))
	}
	timestamp := now.Unix()
	signatures := make([]string, 0, len(keys))
	for _, key := range keys {
		signatures = append(signatures, Sign(key, timestamp, body))
	}
	if err := s.opts.Store.MarkDeliverySending(ctx, delivery.ID, job.Attempt, now); err != nil {
		return err
	}
	status, sendErr := s.send(ctx, target.String(), delivery, event, body,
		SignatureHeader(timestamp, signatures))
	switch {
	case sendErr == nil && status >= 200 && status < 300:
		writeCtx := context.WithoutCancel(ctx)
		if err := s.opts.Store.FinishDelivery(writeCtx, delivery.ID, DeliverySucceeded, "",
			"", status, s.now()); err != nil {
			return err
		}
		_ = s.opts.Audit.Record(writeCtx, audit.Event{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
			AppID:   delivery.ApplicationID,
			Action:  "webhook.delivered",
			Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
			Outcome: audit.OutcomeSuccess, RequestID: job.RequestID,
		})
		return nil
	case errors.Is(sendErr, netguard.ErrBlocked):
		s.finishTerminal(context.WithoutCancel(ctx), delivery, job, kindPermanent,
			"endpoint_blocked", status)
		return task.NonRetryable(fmt.Errorf("%w: 目标被出站策略拒绝", ErrEndpointBlocked))
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		// 任务墙钟到期（执行器不会重排该任务）：直接 failed 使 RetryDelivery 可达。
		return s.finishWallClockTimeout(context.WithoutCancel(ctx), delivery, job)
	case errors.Is(sendErr, context.DeadlineExceeded):
		// 单次 HTTP 请求超时且任务墙钟仍有余量：未耗尽回 queued 走正常有界重试，
		// 耗尽写 failed（可受控重试）。
		return s.finishTimeoutOrRetry(context.WithoutCancel(ctx), delivery, job, status)
	case errors.Is(sendErr, context.Canceled) ||
		(ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled)):
		s.finishCancelled(context.WithoutCancel(ctx), delivery, job)
		return task.NonRetryable(context.Canceled)
	}
	retryable := retryableStatus(status) || errors.Is(sendErr, netguard.ErrUnavailable) ||
		sendErr != nil
	if !retryable || job.Attempt >= delivery.MaxAttempts {
		s.finishTerminal(context.WithoutCancel(ctx), delivery, job, kindPermanent,
			"delivery_failed", status)
		return task.NonRetryable(fmt.Errorf("%w: 投递失败", ErrStoreUnavailable))
	}
	// 可重试：记录回 queued（保留尝试数），由任务执行器按有界退避重排。
	writeCtx := context.WithoutCancel(ctx)
	if err := s.opts.Store.FinishDelivery(writeCtx, delivery.ID, DeliveryQueued,
		string(CodeWebhookDeliveryFailed), kindRetryable, status, s.now()); err != nil {
		return err
	}
	_ = s.opts.Audit.RecordFailure(writeCtx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		AppID:   delivery.ApplicationID,
		Action:  "webhook.delivery.retry_scheduled",
		Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeWebhookDeliveryFailed),
		ReasonCode: "delivery_retry", RequestID: job.RequestID,
	})
	return fmt.Errorf("%w: 投递暂时失败", ErrStoreUnavailable)
}

// send 执行一次受限 HTTP POST；返回响应状态码（无响应时为 0）与传输错误。
func (s *Service) send(ctx context.Context, targetURL string, delivery DeliveryRecord,
	event EventRecord, body []byte, signatureHeader string) (int, error) {
	client := s.validator.NewClient()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return 0, netguard.ErrInvalidURL
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("User-Agent", userAgentValue)
	request.Header.Set(headerEventID, event.ID)
	request.Header.Set(headerEventType, event.Type)
	request.Header.Set(headerDeliveryID, delivery.ID)
	request.Header.Set(headerSignature, signatureHeader)
	if index := strings.Index(signatureHeader, "t="); index == 0 {
		parts := strings.SplitN(signatureHeader, ",", 2)
		if len(parts) == 2 {
			request.Header.Set(headerTimestamp, strings.TrimPrefix(parts[0], "t="))
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, classifyTransportError(err)
	}
	defer response.Body.Close()
	// 响应体只读取上限字节用于诊断，不落库（失败查询只返回状态码与稳定错误码）。
	_, _ = s.validator.ReadLimitedBody(response.Body)
	return response.StatusCode, nil
}

// classifyTransportError 把传输错误归为策略拒绝（永久）或暂时不可用（可重试）。
func classifyTransportError(err error) error {
	if errors.Is(err, netguard.ErrBlocked) || errors.Is(err, netguard.ErrInvalidURL) {
		return netguard.ErrBlocked
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// 保留超时语义：调用方据此写 TASK_TIMEOUT 超时失败而不是取消。
		return context.DeadlineExceeded
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return netguard.ErrUnavailable
}

// retryableStatus 报告 HTTP 状态是否可按有界重试重试。
func retryableStatus(status int) bool {
	if status == 0 {
		return true
	}
	return status == http.StatusRequestTimeout || status == 425 ||
		status == http.StatusTooManyRequests || status >= 500
}

// finishWallClockTimeout 处理任务墙钟到期：执行器会记 timed_out 且不再重排，因此
// 直接写终态 failed + TASK_TIMEOUT（不写 queued），让 RetryDelivery（failed→queued）
// 成为唯一恢复路径；这不是取消，也不是系统故障。
func (s *Service) finishWallClockTimeout(ctx context.Context, delivery DeliveryRecord,
	job task.Job) error {
	_ = s.opts.Store.FinishDelivery(ctx, delivery.ID, DeliveryFailed,
		string(CodeTaskTimeout), kindTimeout, 0, s.now())
	_ = s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		AppID:   delivery.ApplicationID,
		Action:  "webhook.delivery.timeout_failed",
		Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeTaskTimeout),
		ReasonCode: "delivery_timeout", RequestID: job.RequestID,
	})
	return task.NonRetryable(fmt.Errorf("%w: 投递任务墙钟超时", ErrStoreUnavailable))
}

// finishTimeoutOrRetry 处理单次尝试超时：超时是“失败”而非“取消”，属于可重试失败。
// 未耗尽时把投递回 queued 并返回可重试错误（由 internal/task 按 RetryPolicy 有界
// 退避重排）；耗尽时写终态 failed + TASK_TIMEOUT，使 RetryDelivery（failed→queued）
// 可达。只有明确取消才写 cancelled。
func (s *Service) finishTimeoutOrRetry(ctx context.Context, delivery DeliveryRecord,
	job task.Job, status int) error {
	terminal := job.Attempt >= delivery.MaxAttempts
	state := DeliveryQueued
	action := "webhook.delivery.timeout_retry"
	if terminal {
		state = DeliveryFailed
		action = "webhook.delivery.timeout_failed"
	}
	_ = s.opts.Store.FinishDelivery(ctx, delivery.ID, state, string(CodeTaskTimeout),
		kindTimeout, status, s.now())
	_ = s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		AppID:   delivery.ApplicationID,
		Action:  action,
		Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeTaskTimeout),
		ReasonCode: "delivery_timeout", RequestID: job.RequestID,
	})
	if terminal {
		return task.NonRetryable(fmt.Errorf("%w: 投递超时且重试耗尽", ErrStoreUnavailable))
	}
	return fmt.Errorf("%w: 投递超时", ErrStoreUnavailable)
}

// finishTerminal 写入失败终态并写失败审计（endpoint/app 失效或投递失败）。
func (s *Service) finishTerminal(ctx context.Context, delivery DeliveryRecord, job task.Job,
	kind, reason string, status int) {
	_ = s.opts.Store.FinishDelivery(ctx, delivery.ID, DeliveryFailed,
		string(CodeWebhookDeliveryFailed), kind, status, s.now())
	_ = s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		AppID:   delivery.ApplicationID,
		Action:  "webhook.delivery.failed",
		Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeWebhookDeliveryFailed),
		ReasonCode: stableReason(reason), RequestID: job.RequestID,
	})
}

// finishCancelled 写入取消终态并写失败审计（任务被取消/停机）。
func (s *Service) finishCancelled(ctx context.Context, delivery DeliveryRecord, job task.Job) {
	_ = s.opts.Store.FinishDelivery(ctx, delivery.ID, DeliveryCancelled,
		string(CodeTaskCancelled), kindCancelled, 0, s.now())
	_ = s.opts.Audit.RecordFailure(ctx, audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		AppID:   delivery.ApplicationID,
		Action:  "webhook.delivery.cancelled",
		Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeTaskCancelled),
		ReasonCode: "cancelled", RequestID: job.RequestID,
	})
}

// buildEventBody 构造实际发送的事件体（固定结构、稳定序列化；data 为白名单 JSON）。
func buildEventBody(event EventRecord, applicationID string) ([]byte, error) {
	data := map[string]string{}
	if len(event.PayloadJSON) > 0 {
		if err := json.Unmarshal(event.PayloadJSON, &data); err != nil {
			return nil, err
		}
	}
	envelope := EventEnvelope{
		ID: event.ID, Type: securityevent.Type(event.Type), Version: eventVersion,
		OccurredAt:    event.OccurredAt.UTC().Format(time.RFC3339),
		ApplicationID: applicationID,
		Subject:       EventSubject{UserID: event.SubjectUserID},
		Data:          data,
	}
	return json.Marshal(envelope)
}

// ===== 查询 / 取消 / 重试 =====

// GetDelivery 按权限查询投递记录（不含事件 payload/秘密）。
func (s *Service) GetDelivery(ctx context.Context, caller Caller,
	deliveryID string) (Delivery, error) {
	ctx = normalizeContext(ctx)
	record, found, err := s.opts.Store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return Delivery{}, err
	}
	if !found {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err := s.authorize(ctx, caller, ActionQueryDelivery, record.ApplicationID); err != nil {
		return Delivery{}, err
	}
	return s.deliveryView(ctx, record)
}

// ListDeliveries 按应用/端点/状态分页查询投递记录。
func (s *Service) ListDeliveries(ctx context.Context, caller Caller,
	query ListDeliveriesQuery) ([]Delivery, error) {
	ctx = normalizeContext(ctx)
	if query.ApplicationID == "" {
		return nil, fmt.Errorf("%w: 必须指定应用范围", ErrInvalidRequest)
	}
	if query.State != "" && !query.State.Valid() {
		return nil, fmt.Errorf("%w: 投递状态无效", ErrInvalidRequest)
	}
	if err := s.authorize(ctx, caller, ActionQueryDelivery, query.ApplicationID); err != nil {
		return nil, err
	}
	records, err := s.opts.Store.ListDeliveries(ctx, query)
	if err != nil {
		return nil, err
	}
	views := make([]Delivery, 0, len(records))
	for _, record := range records {
		view, viewErr := s.deliveryView(ctx, record)
		if viewErr != nil {
			return nil, viewErr
		}
		views = append(views, view)
	}
	return views, nil
}

// CancelDelivery 取消未终态的投递：queued 直接 cancelled，running 进入 cancel_requested
// 由 handler 收敛；终态返回状态冲突。取消不改变已完成的安全撤销。
func (s *Service) CancelDelivery(ctx context.Context, caller Caller, deliveryID, reason,
	requestID string) error {
	ctx = normalizeContext(ctx)
	if isNil(s.opts.Canceller) {
		return fmt.Errorf("%w: 未装配任务取消能力", ErrAccessDenied)
	}
	record, found, err := s.opts.Store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return err
	}
	if !found {
		return ErrDeliveryNotFound
	}
	if err := s.authorize(ctx, caller, ActionCancelDelivery, record.ApplicationID); err != nil {
		return err
	}
	switch record.State {
	case DeliverySucceeded, DeliveryFailed, DeliveryCancelled:
		return ErrDeliveryConflict
	}
	if record.TaskID == "" {
		return ErrDeliveryConflict
	}
	result, err := s.opts.Canceller.RequestCancel(ctx, task.CancelRequest{
		JobID:  record.TaskID,
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
		Reason: stableReason(reason), RequestID: requestID,
	})
	if err != nil {
		return ErrStoreUnavailable
	}
	if !result.Accepted && !result.AlreadyRequested {
		return ErrDeliveryConflict
	}
	// queued 任务会被执行器直接置 cancelled；这里同步收敛投递状态，避免查询长时间
	// 显示 queued（取消请求已接受不等于已完成，running 由 handler 收敛）。
	if record.State == DeliveryQueued {
		_ = s.opts.Store.FinishDelivery(ctx, record.ID, DeliveryCancelled,
			string(CodeTaskCancelled), kindCancelled, 0, s.now())
	}
	return nil
}

// RetryDelivery 对终态失败的投递发起受控重试（CAS failed→queued 后重新入队，不新建事件）。
func (s *Service) RetryDelivery(ctx context.Context, caller Caller, deliveryID,
	requestID string) (Delivery, error) {
	ctx = normalizeContext(ctx)
	record, found, err := s.opts.Store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return Delivery{}, err
	}
	if !found {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err := s.authorize(ctx, caller, ActionRetryDelivery, record.ApplicationID); err != nil {
		return Delivery{}, err
	}
	if record.State != DeliveryFailed {
		return Delivery{}, ErrDeliveryConflict
	}
	if err := s.opts.Store.RequeueDelivery(ctx, deliveryID, s.now()); err != nil {
		return Delivery{}, err
	}
	jobPayload, err := json.Marshal(map[string]string{"delivery_id": deliveryID})
	if err != nil {
		return Delivery{}, ErrStoreUnavailable
	}
	job, err := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: TaskKindWebhookDelivery, Actor: caller.actor, Payload: jobPayload,
		MutexKey: deliveryID, TimeoutSeconds: s.timeout, MaxAttempts: record.MaxAttempts,
		RequestID: requestID,
	})
	if err != nil {
		_ = s.opts.Store.FinishDelivery(context.WithoutCancel(ctx), deliveryID, DeliveryFailed,
			string(CodeWebhookDeliveryFailed), "queue_failed", 0, s.now())
		return Delivery{}, ErrStoreUnavailable
	}
	if err := s.opts.Store.SetDeliveryTask(ctx, deliveryID, job.ID, s.now()); err != nil {
		return Delivery{}, err
	}
	record.State = DeliveryQueued
	record.TaskID = job.ID
	record.LastErrorCode = ""
	record.LastErrorKind = ""
	record.FinishedAt = time.Time{}
	return s.deliveryView(ctx, record)
}

// deliveryView 组合事件类型用于查询展示（不含 payload）。
func (s *Service) deliveryView(ctx context.Context, record DeliveryRecord) (Delivery, error) {
	eventType := ""
	if event, found, err := s.opts.Store.GetEvent(ctx, record.EventID); err == nil && found {
		eventType = event.Type
	}
	return Delivery{
		ID: record.ID, EventID: record.EventID, EndpointID: record.EndpointID,
		ApplicationID: record.ApplicationID, EventType: securityevent.Type(eventType),
		State: record.State, Attempts: record.Attempts, MaxAttempts: record.MaxAttempts,
		TaskID: record.TaskID, LastErrorCode: record.LastErrorCode,
		LastErrorKind: record.LastErrorKind, LastResponseStatus: record.LastResponseStatus,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt, FinishedAt: record.FinishedAt,
	}, nil
}

// Ensure io/http/strconv imports used by helpers are referenced (编译期断言辅助)。
var (
	_ = io.Discard
	_ = http.MethodPost
	_ = strconv.Itoa
)
