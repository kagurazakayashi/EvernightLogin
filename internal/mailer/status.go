package mailer

import (
	"context"
	"fmt"
)

// CountsStore 是投递状态计数的可选存储能力；实现方应返回按状态分组的计数。
type CountsStore interface {
	// Counts 返回各投递状态的记录数量；未知状态可不返回。
	Counts(ctx context.Context) (map[DeliveryState]int, error)
}

// DeliveryStatus 是投递聚合状态（只读、无收件人/正文/秘密）。
type DeliveryStatus struct {
	// Known 表示存储支持计数；false 时 Counts 为 nil，不伪造零值。
	Known bool
	// Counts 是 queued/sending/succeeded/failed/cancelled 的计数。
	Counts map[DeliveryState]int
	// RecentErrorCodes 是最近失败记录的去重错误码（最多 5 个）。
	RecentErrorCodes []string
}

// Status 返回投递聚合状态。它不授权、不读取模板明文；调用方负责管理权限。
func (s *DeliveryService) Status(ctx context.Context) (DeliveryStatus, error) {
	status := DeliveryStatus{}
	if counter, ok := s.opts.Store.(CountsStore); ok {
		counts, err := counter.Counts(ctx)
		if err != nil {
			return DeliveryStatus{}, err
		}
		status.Known = true
		status.Counts = counts
	}
	records, err := s.opts.Store.List(ctx, ListQuery{State: DeliveryFailed, Limit: 5})
	if err != nil {
		return DeliveryStatus{}, err
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.LastErrorCode == "" {
			continue
		}
		if _, duplicate := seen[record.LastErrorCode]; duplicate {
			continue
		}
		seen[record.LastErrorCode] = struct{}{}
		status.RecentErrorCodes = append(status.RecentErrorCodes, record.LastErrorCode)
		if len(status.RecentErrorCodes) >= 5 {
			break
		}
	}
	return status, nil
}

// Reconcile 有界扫描进程重启后残留的 sending 记录，将它们标记为永久失败并
// 保留错误码，绝不自动重发。返回本次修复的记录数；单条更新失败立即返回错误。
// limit<=0 时使用默认上限 200，且无论如何不超过 500，避免无界扫描。
func (s *DeliveryService) Reconcile(ctx context.Context, limit int) (int, error) {
	if s == nil || s.opts.Store == nil {
		return 0, fmt.Errorf("%w: 投递存储为空", ErrOptionsInvalid)
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	records, err := s.opts.Store.List(ctx, ListQuery{State: DeliverySending, Limit: limit})
	if err != nil {
		return 0, err
	}
	now := s.opts.Now()
	repaired := 0
	for _, record := range records {
		if err := s.opts.Store.Finish(ctx, record.ID, DeliveryFailed, CodeUnavailable, FailurePermanent, now); err != nil {
			return repaired, err
		}
		repaired++
	}
	return repaired, nil
}
