package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// Emit 实现 securityevent.Emitter：校验事件白名单→幂等落库事件与投递→逐个入队。
//
// 语义：事件与其投递在同一事务内创建（至少一次送达的可靠起点）；入队失败把该投递
// 标记 failed + WEBHOOK_DELIVERY_FAILED 并写失败审计，不回滚已创建的事件，也不影响
// 产生方已完成的禁用/撤销/退出（通知失败不回滚安全操作）。重复 Emit（相同幂等键）
// 返回既有事件、不重复投递。
func (s *Service) Emit(ctx context.Context, event securityevent.Event) error {
	ctx = normalizeContext(ctx)
	if err := validateEvent(event); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
			"webhook.event.denied", event.ApplicationID, "event_invalid",
			CodeReqInvalid, event.RequestID)
		return err
	}
	records, truncated, targetErr := s.resolveFanout(ctx, event)
	if targetErr != nil {
		return targetErr
	}
	payload, err := marshalData(event.Data)
	if err != nil {
		return fmt.Errorf("%w: 事件数据编码失败", ErrEventInvalid)
	}
	now := s.now()
	eventRecord := EventRecord{
		ID: mustNewID(s.opts.Random, eventIDPrefix), IdempotencyKey: event.IdempotencyKey,
		Type: string(event.Type), ApplicationID: event.ApplicationID,
		SubjectUserID: event.UserID, PayloadJSON: payload, Truncated: truncated,
		RequestID: event.RequestID, OccurredAt: event.OccurredAt.UTC(), CreatedAt: now,
	}
	deliveries := make([]DeliveryRecord, 0, len(records))
	for _, endpoint := range records {
		deliveries = append(deliveries, DeliveryRecord{
			ID: mustNewID(s.opts.Random, deliveryIDPrefix), EventID: eventRecord.ID,
			EndpointID: endpoint.ID, ApplicationID: endpoint.ApplicationID,
			State: DeliveryQueued, MaxAttempts: s.maxAttempts, RequestID: event.RequestID,
			CreatedAt: now, UpdatedAt: now,
		})
	}
	stored, duplicate, err := s.opts.Store.CreateEventWithDeliveries(ctx, eventRecord, deliveries)
	if err != nil {
		return err
	}
	if duplicate {
		s.opts.Logger.Info("Webhook 事件幂等命中，未重复投递", "event_id", stored.ID,
			"type", stored.Type)
		return nil
	}
	if truncated {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
			"webhook.event.truncated", event.ApplicationID, "fanout_truncated",
			CodeWebhookDeliveryFailed, event.RequestID)
	}
	s.enqueueDeliveries(ctx, deliveries)
	return nil
}

// resolveFanout 解析事件的接收端点：应用级事件只取该应用的 active 端点；用户级事件
// 取“用户仍为 active 成员的应用”的 active 端点。超过 MaxFanoutEndpoints 时截断并标记。
func (s *Service) resolveFanout(ctx context.Context,
	event securityevent.Event) ([]EndpointRecord, bool, error) {
	if event.ApplicationID != "" {
		active, err := s.opts.Store.ApplicationActive(ctx, event.ApplicationID)
		if err != nil {
			return nil, false, err
		}
		if !active {
			// 应用已停用：仍记录事件（可查询），但不向该应用投递。
			return nil, false, nil
		}
		records, err := s.opts.Store.ListActiveEndpointsForApps(ctx,
			[]string{event.ApplicationID})
		if err != nil {
			return nil, false, err
		}
		return limitFanout(records)
	}
	appIDs, err := s.opts.Store.UserAppIDs(ctx, event.UserID)
	if err != nil {
		return nil, false, err
	}
	records, err := s.opts.Store.ListActiveEndpointsForApps(ctx, appIDs)
	if err != nil {
		return nil, false, err
	}
	return limitFanout(records)
}

func limitFanout(records []EndpointRecord) ([]EndpointRecord, bool, error) {
	if len(records) > MaxFanoutEndpoints {
		return records[:MaxFanoutEndpoints], true, nil
	}
	return records, false, nil
}

// enqueueDeliveries 逐个入队投递任务；失败写终态 failed + 失败审计（不留无主 queued）。
func (s *Service) enqueueDeliveries(ctx context.Context, deliveries []DeliveryRecord) {
	for _, delivery := range deliveries {
		jobPayload, err := json.Marshal(map[string]string{"delivery_id": delivery.ID})
		if err != nil {
			continue
		}
		job, enqueueErr := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
			Kind: TaskKindWebhookDelivery, Actor: audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
			Payload: jobPayload, MutexKey: delivery.ID, TimeoutSeconds: s.timeout,
			MaxAttempts: delivery.MaxAttempts, RequestID: delivery.RequestID,
		})
		if enqueueErr != nil {
			writeCtx := context.WithoutCancel(ctx)
			_ = s.opts.Store.FinishDelivery(writeCtx, delivery.ID, DeliveryFailed,
				string(CodeWebhookDeliveryFailed), "queue_failed", 0, s.now())
			_ = s.opts.Audit.RecordFailure(writeCtx, audit.Event{
				Actor:   audit.Actor{Type: audit.ActorSystem, ID: "webhook"},
				AppID:   delivery.ApplicationID,
				Action:  "webhook.delivery.queue_failed",
				Target:  audit.Target{Type: "webhook_delivery", ID: delivery.ID},
				Outcome: audit.OutcomeFailure, ErrorCode: string(CodeWebhookDeliveryFailed),
				ReasonCode: "queue_failed", RequestID: delivery.RequestID,
			})
			continue
		}
		if err := s.opts.Store.SetDeliveryTask(ctx, delivery.ID, job.ID, s.now()); err != nil {
			s.opts.Logger.Warn("Webhook 投递任务关联失败", "delivery_id", delivery.ID)
		}
	}
}
