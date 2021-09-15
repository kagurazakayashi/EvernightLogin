// 本文件实现恢复审计的“库外追加日志 → 恢复后数据库安全审计”可靠合并，以及合并
// 失败时的 fail-closed 语义。
package restore

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// journalEvent 是 appendJournal 的入参；RestoreID 关联同一次恢复或维护会话。
type journalEvent struct {
	RestoreID  string
	Actor      audit.Actor
	Action     string
	TargetType string
	TargetID   string
	Outcome    audit.Outcome
	ErrorCode  string
	ReasonCode string
	RequestID  string
	Changes    []audit.FieldChange
}

// appendJournal 追加一条恢复审计事件到库外日志并 fsync。任何失败都返回
// ErrAuditUnavailable，调用方必须 fail-closed（不得在审计缺失时继续关键步骤）。
func (s *Service) appendJournal(ctx context.Context, event journalEvent) (JournalEntry, error) {
	if s == nil || s.journal == nil {
		return JournalEntry{}, fmt.Errorf("%w: 恢复审计日志未初始化", ErrAuditUnavailable)
	}
	if event.RestoreID == "" {
		return JournalEntry{}, fmt.Errorf("%w: 恢复审计缺少关联编号", ErrAuditUnavailable)
	}
	if event.TargetType == "" {
		event.TargetType = TargetTypeRestore
	}
	entry, err := s.journal.Append(ctx, JournalEntry{
		RestoreID:  event.RestoreID,
		At:         s.nowUTC(),
		ActorType:  string(event.Actor.Type),
		ActorID:    event.Actor.ID,
		Action:     event.Action,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Outcome:    string(event.Outcome),
		ErrorCode:  event.ErrorCode,
		ReasonCode: event.ReasonCode,
		RequestID:  event.RequestID,
		Changes:    event.Changes,
	})
	if err != nil {
		return JournalEntry{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return entry, nil
}

// mergeJournalToDB 把库外审计日志的全部事件按幂等去重键合并进给定数据库的安全
// 审计表，并写入一条合并结果事件。已存在的去重键按幂等跳过；其它写入失败返回
// ErrAuditUnavailable，调用方必须保持维护并保留库外日志以便重试。
func (s *Service) mergeJournalToDB(ctx context.Context, store *storagesqlite.Store,
	actor audit.Actor, restoreID string) (int, error) {
	ctx = normalizeContext(ctx)
	if store == nil {
		return 0, fmt.Errorf("%w: 目标数据库为空", ErrAuditUnavailable)
	}
	entries, err := s.journal.Entries()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	merged := 0
	for _, entry := range entries {
		prepared, prepareErr := audit.PrepareEvent(entry.toAuditEvent(), entry.At)
		if prepareErr != nil {
			return merged, fmt.Errorf("%w: 恢复审计事件无法规范化", ErrAuditUnavailable)
		}
		appendErr := s.appendAuditEvent(ctx, store, prepared)
		if appendErr == nil {
			merged++
			continue
		}
		if errors.Is(appendErr, audit.ErrDuplicateEvent) {
			continue
		}
		return merged, fmt.Errorf("%w: %w", ErrAuditUnavailable, appendErr)
	}
	marker := audit.Event{
		Actor:   actor,
		Action:  ActionAuditMerged,
		Target:  audit.Target{Type: TargetTypeRestore, ID: restoreID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{
			{Field: "merged_events", After: fmt.Sprintf("%d", merged)},
		},
		DedupeKey: "restore-audit-merge:" + restoreID,
	}
	if err := s.appendAuditEvent(ctx, store, marker); err != nil &&
		!errors.Is(err, audit.ErrDuplicateEvent) {
		return merged, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return merged, nil
}

// appendAuditEvent 在已打开的数据库上追加一条已准备/待准备的审计事件。重复
// 去重键原样返回 audit.ErrDuplicateEvent，调用方可按幂等处理。
func (s *Service) appendAuditEvent(ctx context.Context, store *storagesqlite.Store,
	event audit.Event) error {
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		return fmt.Errorf("%w: 无法构造审计存储", ErrAuditUnavailable)
	}
	prepared := event
	if prepared.OccurredAt.IsZero() {
		prepared.OccurredAt = s.nowUTC()
	}
	if prepared.ID == "" {
		normalized, err := audit.PrepareEvent(prepared, prepared.OccurredAt)
		if err != nil {
			return fmt.Errorf("%w: 审计事件无法规范化", ErrAuditUnavailable)
		}
		prepared = normalized
	}
	return auditStore.Append(ctx, prepared)
}

// recordAuditEvent 在 s 当前活动数据库上独立写入一条审计事件（恢复后处置/审查用）。
func (s *Service) recordAuditEvent(ctx context.Context, event audit.Event) error {
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	appendErr := s.appendAuditEvent(ctx, store, event)
	if errors.Is(appendErr, audit.ErrDuplicateEvent) {
		return nil
	}
	if appendErr != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, appendErr)
	}
	return nil
}

// openLiveStore 打开当前活动数据库（恢复后处理/审查用）；调用方负责关闭。
func (s *Service) openLiveStore(ctx context.Context) (*storagesqlite.Store, error) {
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(s.databasePath))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return store, nil
}
