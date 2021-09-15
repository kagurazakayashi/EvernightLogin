// 本文件实现维护状态外部入口（本地 CLI/受控 API）与恢复后处置：查看恢复后默认
// 暂停清单、标记已审查、受控重新启用旧调度计划与 Webhook 端点，以及独立重试恢复
// 审计合并。所有入口都要求 root 或受控本地应急管理员，不提供匿名远程通道。
package restore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
)

// 恢复后处置对象类型稳定取值（与迁移 CHECK 一致）。
const (
	DispositionSchedule     = "schedule"
	DispositionWebhook      = "webhook"
	DispositionJob          = "job"
	DispositionMail         = "mail"
	DispositionNotification = "notification"
)

// MaxReenableItems 是单次受控重新启用的对象数上限（防止无界批量操作）。
const MaxReenableItems = 1000

// PausedItem 是恢复后默认暂停/取消的一个对象记录。
type PausedItem struct {
	ID            int64      `json:"id"`
	RestoreID     string     `json:"restore_id"`
	Kind          string     `json:"kind"`
	TargetID      string     `json:"target_id"`
	PreviousState string     `json:"previous_state"`
	PausedAt      time.Time  `json:"paused_at"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
	ReenabledAt   *time.Time `json:"reenabled_at,omitempty"`
}

// DispositionReport 是最近一次成功恢复后的默认暂停/取消清单与审查状态。
type DispositionReport struct {
	RestoreID      string           `json:"restore_id,omitempty"`
	Generation     uint64           `json:"generation"`
	ReviewRequired bool             `json:"review_required"`
	Counts         map[string]int64 `json:"counts"`
	Items          []PausedItem     `json:"items"`
}

// Disposition 返回最近一次成功恢复的处置清单。它只读，不修改任何对象状态；需要
// root 或受控本地应急管理员权限。
func (s *Service) Disposition(ctx context.Context, caller account.Caller) (DispositionReport, error) {
	ctx = normalizeContext(ctx)
	if _, err := s.authorize(ctx, caller); err != nil {
		return DispositionReport{}, err
	}
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return DispositionReport{}, err
	}
	defer func() { _ = store.Close() }()
	return readDisposition(ctx, store)
}

// readDisposition 从当前数据库读取最近一次成功恢复与其暂停清单。
func readDisposition(ctx context.Context, store interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}) (DispositionReport, error) {
	report := DispositionReport{Counts: make(map[string]int64), Items: make([]PausedItem, 0)}
	exists, err := genericTableExists(ctx, store, "restore_runs")
	if err != nil {
		return DispositionReport{}, err
	}
	if !exists {
		return report, nil
	}
	var restoreID string
	var generation int64
	var completedAt int64
	rowErr := queryRow(ctx, store, `SELECT restore_id, generation, completed_at_ms
FROM restore_runs WHERE status='completed' ORDER BY completed_at_ms DESC, restore_id LIMIT 1`,
		nil, &restoreID, &generation, &completedAt)
	if errors.Is(rowErr, sql.ErrNoRows) {
		return report, nil
	}
	if rowErr != nil {
		return DispositionReport{}, fmt.Errorf("%w: 无法读取恢复运行记录", ErrStoreUnavailable)
	}
	report.RestoreID = restoreID
	report.Generation = uint64(generation)
	items, err := readPausedItems(ctx, store, restoreID)
	if err != nil {
		return DispositionReport{}, err
	}
	report.Items = items
	for _, item := range items {
		report.Counts[item.Kind]++
		if item.ReviewedAt == nil {
			report.ReviewRequired = true
		}
	}
	return report, nil
}

// readPausedItems 读取指定恢复运行的暂停清单。
func readPausedItems(ctx context.Context, store queryer, restoreID string) ([]PausedItem, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,restore_id,kind,target_id,
previous_state,paused_at_ms,reviewed_at_ms,reenabled_at_ms
FROM restore_paused_items WHERE restore_id=? ORDER BY id`, restoreID)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取恢复暂停清单", ErrStoreUnavailable)
	}
	defer rows.Close()
	items := make([]PausedItem, 0, 8)
	for rows.Next() {
		var item PausedItem
		var pausedAt int64
		var reviewedAt, reenabledAt sql.NullInt64
		if err := rows.Scan(&item.ID, &item.RestoreID, &item.Kind, &item.TargetID,
			&item.PreviousState, &pausedAt, &reviewedAt, &reenabledAt); err != nil {
			return nil, fmt.Errorf("%w: 恢复暂停清单行格式非法", ErrStoreUnavailable)
		}
		item.PausedAt = time.UnixMilli(pausedAt).UTC()
		if reviewedAt.Valid {
			value := time.UnixMilli(reviewedAt.Int64).UTC()
			item.ReviewedAt = &value
		}
		if reenabledAt.Valid {
			value := time.UnixMilli(reenabledAt.Int64).UTC()
			item.ReenabledAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 遍历恢复暂停清单失败", ErrStoreUnavailable)
	}
	return items, nil
}

// ReviewRequest 是标记恢复后处置清单已审查的请求。
type ReviewRequest struct {
	Caller    account.Caller
	RequestID string
	RestoreID string
}

// ReviewDisposition 标记最近一次（或指定）恢复运行的暂停清单已人工审查；它不
// 重新启用任何对象，重新启用必须单独调用 ReenablePaused。返回本次标记条数。
func (s *Service) ReviewDisposition(ctx context.Context, request ReviewRequest) (int64, error) {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return 0, err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return 0, err
	}
	if s.State().Mode == maintenance.ModeMaintenance {
		return 0, fmt.Errorf("%w: 维护状态下不能执行处置审查", ErrMaintenanceRequired)
	}
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = store.Close() }()
	var reviewed int64
	transactionErr := store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		restoreID := request.RestoreID
		if restoreID == "" {
			if err := tx.QueryRowContext(ctx, `SELECT restore_id FROM restore_runs
WHERE status='completed' ORDER BY completed_at_ms DESC, restore_id LIMIT 1`).
				Scan(&restoreID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("%w: 没有可审查的恢复运行记录", ErrInvalidRequest)
				}
				return fmt.Errorf("读取恢复运行记录失败: %w", err)
			}
		}
		result, err := tx.ExecContext(ctx, `UPDATE restore_paused_items
SET reviewed_at_ms=? WHERE restore_id=? AND reviewed_at_ms IS NULL`,
			s.nowUTC().UnixMilli(), restoreID)
		if err != nil {
			return fmt.Errorf("标记恢复处置审查失败: %w", err)
		}
		reviewed, err = result.RowsAffected()
		if err != nil {
			return fmt.Errorf("统计审查条数失败: %w", err)
		}
		return nil
	})
	if transactionErr != nil {
		return 0, fmt.Errorf("%w: %w", ErrStoreUnavailable, transactionErr)
	}
	if err := s.recordAuditEvent(ctx, audit.Event{
		Actor: actor, Action: ActionReview,
		Target:  audit.Target{Type: TargetTypeDisposition, ID: request.RestoreID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{{Field: "reviewed_items",
			After: fmt.Sprintf("%d", reviewed)}},
		RequestID: requestID,
		DedupeKey: "restore-review:" + request.RestoreID + ":" +
			fmt.Sprintf("%d", reviewed),
	}); err != nil {
		return reviewed, fmt.Errorf("%w（审查已记录但审计写入失败）", ErrAuditUnavailable)
	}
	return reviewed, nil
}

// ReenableRequest 是受控重新启用旧调度计划/Webhook 端点的请求。
type ReenableRequest struct {
	Caller    account.Caller
	RequestID string
	Reason    string
	// Kinds 限定重新启用的对象类型（schedule/webhook）；为空表示两类都处理。
	Kinds []string
	// RestoreID 限定恢复运行；为空使用最近一次成功恢复。
	RestoreID string
}

// ReenableResult 是受控重新启用的真实结果。
type ReenableResult struct {
	RestoreID string `json:"restore_id"`
	Schedules int64  `json:"schedules"`
	Webhooks  int64  `json:"webhooks"`
	Total     int64  `json:"total"`
	Skipped   int64  `json:"skipped"`
}

// ReenablePaused 受控重新启用最近一次恢复中被默认暂停的旧调度计划与 Webhook 端点。
// 只允许显式类型（schedule/webhook）；取消的任务、邮件与通知不可通过本入口恢复，
// 必须由各自正常入口重新创建。要求 root/本地应急管理员，写审计并记录真实操作者。
func (s *Service) ReenablePaused(ctx context.Context, request ReenableRequest) (ReenableResult, error) {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return ReenableResult{}, err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return ReenableResult{}, err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return ReenableResult{}, err
	}
	kinds := make(map[string]bool, 2)
	if len(request.Kinds) == 0 {
		kinds[DispositionSchedule] = true
		kinds[DispositionWebhook] = true
	}
	for _, kind := range request.Kinds {
		switch kind {
		case DispositionSchedule, DispositionWebhook:
			kinds[kind] = true
		default:
			return ReenableResult{}, fmt.Errorf(
				"%w: 只能重新启用调度计划或 Webhook 端点，任务/邮件/通知必须重新创建",
				ErrInvalidRequest)
		}
	}
	if s.State().Mode == maintenance.ModeMaintenance {
		return ReenableResult{}, fmt.Errorf("%w: 维护状态下不能重新启用处置对象",
			ErrMaintenanceRequired)
	}
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return ReenableResult{}, err
	}
	defer func() { _ = store.Close() }()
	result := ReenableResult{}
	nowMS := s.nowUTC().UnixMilli()
	transactionErr := store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		restoreID := request.RestoreID
		if restoreID == "" {
			if err := tx.QueryRowContext(ctx, `SELECT restore_id FROM restore_runs
WHERE status='completed' ORDER BY completed_at_ms DESC, restore_id LIMIT 1`).
				Scan(&restoreID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("%w: 没有可处置的恢复运行记录", ErrInvalidRequest)
				}
				return fmt.Errorf("读取恢复运行记录失败: %w", err)
			}
		}
		result.RestoreID = restoreID
		items, err := readPausedItemsTx(ctx, tx, restoreID)
		if err != nil {
			return err
		}
		processed := 0
		for _, item := range items {
			if item.ReenabledAt != nil {
				continue
			}
			if !kinds[item.Kind] {
				result.Skipped++
				continue
			}
			if processed >= MaxReenableItems {
				result.Skipped++
				continue
			}
			switch item.Kind {
			case DispositionSchedule:
				affected, err := reenableRows(ctx, tx, `UPDATE schedules
SET enabled=1, updated_at_ms=? WHERE id=? AND enabled=0`, nowMS, item.TargetID)
				if err != nil {
					return fmt.Errorf("重新启用调度计划失败: %w", err)
				}
				result.Schedules += affected
			case DispositionWebhook:
				affected, err := reenableRows(ctx, tx, `UPDATE webhook_endpoints
SET status='active', row_version=row_version+1, updated_at_ms=?
WHERE id=? AND status='disabled'`, nowMS, item.TargetID)
				if err != nil {
					return fmt.Errorf("重新启用 Webhook 端点失败: %w", err)
				}
				result.Webhooks += affected
			}
			if _, err := tx.ExecContext(ctx, `UPDATE restore_paused_items
SET reenabled_at_ms=?, reviewed_at_ms=COALESCE(reviewed_at_ms, ?) WHERE id=?`,
				nowMS, nowMS, item.ID); err != nil {
				return fmt.Errorf("记录重新启用状态失败: %w", err)
			}
			processed++
		}
		return nil
	})
	if transactionErr != nil {
		return ReenableResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, transactionErr)
	}
	result.Total = result.Schedules + result.Webhooks
	if err := s.recordAuditEvent(ctx, audit.Event{
		Actor: actor, Action: ActionReenable,
		Target:  audit.Target{Type: TargetTypeDisposition, ID: result.RestoreID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{
			{Field: "reason", After: reason},
			{Field: "schedules", After: fmt.Sprintf("%d", result.Schedules)},
			{Field: "webhooks", After: fmt.Sprintf("%d", result.Webhooks)},
		},
		RequestID: requestID,
		DedupeKey: "restore-reenable:" + result.RestoreID + ":" +
			fmt.Sprintf("%d", nowMS),
	}); err != nil {
		return result, fmt.Errorf("%w（重新启用已提交但审计写入失败）",
			ErrAuditUnavailable)
	}
	return result, nil
}

// readPausedItemsTx 在事务内读取指定恢复运行的暂停清单。
func readPausedItemsTx(ctx context.Context, tx *sql.Tx, restoreID string) (
	[]PausedItem, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,restore_id,kind,target_id,
previous_state,paused_at_ms,reviewed_at_ms,reenabled_at_ms
FROM restore_paused_items WHERE restore_id=? ORDER BY id`, restoreID)
	if err != nil {
		return nil, fmt.Errorf("读取恢复暂停清单失败: %w", err)
	}
	defer rows.Close()
	items := make([]PausedItem, 0, 8)
	for rows.Next() {
		var item PausedItem
		var pausedAt int64
		var reviewedAt, reenabledAt sql.NullInt64
		if err := rows.Scan(&item.ID, &item.RestoreID, &item.Kind, &item.TargetID,
			&item.PreviousState, &pausedAt, &reviewedAt, &reenabledAt); err != nil {
			return nil, fmt.Errorf("恢复暂停清单行格式非法: %w", err)
		}
		item.PausedAt = time.UnixMilli(pausedAt).UTC()
		if reviewedAt.Valid {
			value := time.UnixMilli(reviewedAt.Int64).UTC()
			item.ReviewedAt = &value
		}
		if reenabledAt.Valid {
			value := time.UnixMilli(reenabledAt.Int64).UTC()
			item.ReenabledAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历恢复暂停清单失败: %w", err)
	}
	return items, nil
}

// reenableRows 执行受控重新启用语句并返回真实影响行数。
func reenableRows(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// MaintenanceRequest 是外部进入/退出维护状态的请求（本地 CLI/受控 API）。
type MaintenanceRequest struct {
	Caller    account.Caller
	Reason    string
	RequestID string
	// Force 仅用于退出维护：存在未完成恢复尝试时仍显式退出（高风险，需操作者确认）。
	Force bool
}

// EnterMaintenance 让服务进入维护状态（阻止新写入、有界等待在途写入收束），并写
// 库外审计。它不执行恢复；供运维在手工维护/迁移前使用。
func (s *Service) EnterMaintenance(ctx context.Context, request MaintenanceRequest) error {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return err
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		return err
	}
	release, err := s.controller.LockRestore(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRestoreLocked, err)
	}
	defer release()
	operator := maintenance.Operator{Type: string(actor.Type), ID: actor.ID,
		Machine: s.machineName()}
	if err := s.controller.EnterMaintenance(ctx, maintenance.EnterRequest{
		Operator: operator, Reason: reason, RequestID: requestID,
	}); err != nil {
		return s.wrapMaintenanceError(err)
	}
	if _, err := s.appendJournal(ctx, journalEvent{
		RestoreID: sessionID, Actor: actor, Action: ActionMaintenanceEnter,
		TargetType: TargetTypeRestore, TargetID: sessionID, Outcome: audit.OutcomeSuccess,
		RequestID: requestID,
		Changes:   []audit.FieldChange{{Field: "reason", After: reason}},
	}); err != nil {
		// 维护状态已生效；审计失败按 fail-closed 返回错误，但保持维护（保守方向）。
		return err
	}
	return nil
}

// ExitMaintenance 显式退出维护状态；存在未完成恢复尝试时必须 Force。退出后尝试把
// 库外审计日志合并进当前数据库；合并不完整时返回错误但日志仍完整保留。
func (s *Service) ExitMaintenance(ctx context.Context, request MaintenanceRequest) error {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return err
	}
	requestID, err := normalizeCorrelationID(request.RequestID)
	if err != nil {
		return err
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		return err
	}
	release, err := s.controller.LockRestore(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRestoreLocked, err)
	}
	defer release()
	if _, err := s.appendJournal(ctx, journalEvent{
		RestoreID: sessionID, Actor: actor, Action: ActionMaintenanceExit,
		TargetType: TargetTypeRestore, TargetID: sessionID, Outcome: audit.OutcomeSuccess,
		RequestID: requestID,
		Changes: []audit.FieldChange{{Field: "reason", After: reason},
			{Field: "force", After: fmt.Sprintf("%t", request.Force)}},
	}); err != nil {
		return err
	}
	// 先可靠合并库外恢复审计，再退出维护状态：合并失败时保持维护（fail-closed），
	// 库外日志仍完整保留，可重试 restore-merge-audit 后再次退出。
	if _, mergeErr := s.MergeAudit(ctx, request.Caller); mergeErr != nil {
		return mergeErr
	}
	if err := s.controller.ExitMaintenance(ctx, maintenance.ExitRequest{
		Operator: maintenance.Operator{Type: string(actor.Type), ID: actor.ID,
			Machine: s.machineName()},
		Reason: reason, Force: request.Force,
	}); err != nil {
		return s.wrapMaintenanceError(err)
	}
	return nil
}

// MergeAudit 独立重试把库外恢复审计合并进当前数据库；合并幂等，失败时库外日志
// 保持不变。要求 root 或受控本地应急管理员权限。
func (s *Service) MergeAudit(ctx context.Context, caller account.Caller) (int, error) {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, caller)
	if err != nil {
		return 0, err
	}
	// 允许在维护状态下补合并：数据库可能是“已恢复并完成凭证失效但审计未合并”的
	// 状态；数据库不可用时合并会返回错误并保持维护。
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = store.Close() }()
	sessionID, err := s.newSessionID()
	if err != nil {
		return 0, err
	}
	merged, mergeErr := s.mergeJournalToDB(ctx, store, actor, sessionID)
	if mergeErr != nil {
		return merged, fmt.Errorf("%w: %w", ErrAuditUnavailable, mergeErr)
	}
	return merged, nil
}

// newSessionID 生成维护/合并会话关联编号（mnt_ + 128 位随机十六进制）。
func (s *Service) newSessionID() (string, error) {
	restoreID, err := s.newRestoreID()
	if err != nil {
		return "", err
	}
	return "mnt_" + restoreID[len(restoreIDPrefix):], nil
}

// queryer 是只读查询接口（*storagesqlite.Store 与 *sql.Tx 都满足）。
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// genericTableExists 报告数据库中是否存在指定表。
func genericTableExists(ctx context.Context, store queryer, name string) (bool, error) {
	var count int
	if err := queryRow(ctx, store,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
		[]any{name}, &count); err != nil {
		return false, fmt.Errorf("%w: 无法检查数据库表结构", ErrStoreUnavailable)
	}
	return count > 0, nil
}

// queryRow 在查询器上执行单行扫描；args 为 SQL 参数，destinations 为扫描目标。
func queryRow(ctx context.Context, store queryer, query string, args []any,
	destinations ...any) error {
	rows, err := store.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	return rows.Scan(destinations...)
}
