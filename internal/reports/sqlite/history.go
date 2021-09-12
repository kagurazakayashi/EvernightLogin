package sqlite

// 本文件把 reports.HistoryRecorder 适配到报告历史 SQLite 仓储，使报告服务在真实
// 终态时写入持久历史。适配层只做字段映射与受控默认值，不做授权、不改写状态。
// 读取契约在同目录 lifecycle.go 的 *HistoryRecorder 方法中实现。

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
)

// HistoryRecorder 是 reports.HistoryRecorder 的 SQLite 实现。
type HistoryRecorder struct {
	store *Store
}

// NewHistoryRecorder 包装报告历史仓储；store 为空时拒绝构造。
func NewHistoryRecorder(store *Store) (*HistoryRecorder, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: 报告历史仓储为空", reports.ErrOptionsInvalid)
	}
	return &HistoryRecorder{store: store}, nil
}

// RecordReportHistory 实现 reports.HistoryRecorder：把服务端给定的受控历史条目
// 写入持久层。状态/产物/失败原因均来自服务端真实记录，本方法不补造成功状态。
// 乱序写入的状态回退由仓储 UpsertHistory 的单调状态规则拒绝。
func (h *HistoryRecorder) RecordReportHistory(ctx context.Context,
	record reports.HistoryRecord) error {
	return h.store.UpsertHistory(ctx, historyRecordToStore(record))
}
