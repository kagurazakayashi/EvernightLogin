package reports

// 本文件实现报告历史/运行记录的持久化接线（步骤 79 后端收口）：报告从排队、运行
// 到真实终态（完成/失败/取消/超时）时，把与内存记录一致的受控元数据交给宿主注入
// 的 HistoryRecorder 写入持久层；执行前权限复验拒绝也会留一条“未生成”记录。
//
// 安全不变量：
//   - 历史只写真实状态：不把排队/取消请求写成完成，不伪造成功；导出目录中的产物
//     清理后历史不再声称可下载（状态与产物引用保持服务端事实）。
//   - 历史只含受控元数据与步骤 77 已裁剪的聚合快照；不含宿主路径、原始审计正文、
//     凭证或自由文本秘密。
//   - HistoryRecorder 未装配时跳过写入（不伪造内存历史为持久历史）；写入失败只
//     告警，不改变已经提交的报告终态，也不把失败回滚成成功。
//   - 历史读取必须由服务层按当前权限与数据范围裁剪；本文件不提供无授权全量读取。

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// HistoryRecord 是报告历史持久化条目。它由服务端从真实报告记录生成，页面/仓储
// 只能消费该受控视图；State 使用真实任务/报告状态（取消请求与实际取消分开）。
type HistoryRecord struct {
	ReportID       string
	PlanID         string
	Name           string
	Owner          audit.Actor
	ScopeID        string
	ScopeKind      string
	AppID          string
	Template       string
	State          string
	Formats        []Format
	Categories     []stats.Category
	TrendMetric    stats.Metric
	DetailRows     int
	DataScopeJSON  []byte
	WindowJSON     []byte
	SnapshotJSON   []byte
	ArtifactsJSON  []byte
	TaskID         string
	ExecutorID     string
	ErrorCode      string
	FailureReason  string
	RequestID      string
	CreatedAt      time.Time
	StartedAt      time.Time
	FinishedAt     time.Time
	ExpiresAt      time.Time
	RetentionUntil time.Time
	// CleanupState 是报告文件清理状态（none/pending/cleaned）。它只描述报告产物
	// 文件，不代表原始审计记录被删除。
	CleanupState string
	// RetryOf 是重试来源报告编号（空表示不是重试），用于链式关联与页面追踪。
	RetryOf string
}

// historyDataScope 是历史中保存的生成时数据范围引用（不含权限缓存或明文规则）。
// 进程重启后回源历史时用它判断调用者当前数据范围是否仍覆盖生成时范围。
type historyDataScope struct {
	All       bool     `json:"all"`
	Resources []string `json:"resources,omitempty"`
}

// encodeHistoryDataScope 把生成时数据范围编码为受控 JSON。
func encodeHistoryDataScope(scope dataScope) []byte {
	encoded, err := json.Marshal(historyDataScope{
		All: scope.All, Resources: append([]string(nil), scope.Resources...)})
	if err != nil {
		return []byte("{}")
	}
	return encoded
}

// decodeHistoryDataScope 解析历史数据范围；缺失/非法按最小范围（空）处理，
// 回源授权时仍需当前权限覆盖，不会因解析失败而放宽。
func decodeHistoryDataScope(raw []byte) dataScope {
	if len(raw) == 0 {
		return dataScope{}
	}
	var scope historyDataScope
	if err := json.Unmarshal(raw, &scope); err != nil {
		return dataScope{}
	}
	return dataScope{All: scope.All, Resources: append([]string(nil), scope.Resources...)}
}

// HistoryRecorder 是报告历史持久化契约（生产实现为 internal/reports/sqlite 的
// 适配器）。实现必须只按给定受控视图写入，不得从其他来源补写或回滚报告状态。
type HistoryRecorder interface {
	RecordReportHistory(ctx context.Context, record HistoryRecord) error
}

// historyArtifact 是历史中保存的产物元数据：只含可核对字段，不含宿主路径。
type historyArtifact struct {
	Format string `json:"format"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// historyState 把内存报告状态映射为历史状态：超时是独立终态（不写成一般失败）。
func historyState(record reportRecord) string {
	if record.State == StateFailed && record.ErrorCode == string(CodeTaskTimeout) {
		return "timed_out"
	}
	return record.State
}

// reportHistoryRecord 从内存报告记录构造受控历史条目；快照/产物序列化失败时保留
// 空引用而不是写一段无法解析的半成品（历史仍可见，页面显示“引用不可用”）。
func (s *Service) reportHistoryRecord(record reportRecord) HistoryRecord {
	entry := HistoryRecord{
		ReportID: record.ID, PlanID: record.PlanID, Name: record.Name,
		Owner: record.RequestedBy, ScopeID: record.ScopeID,
		ScopeKind: record.ScopeKind, AppID: record.AppID, Template: record.Template,
		State: historyState(record), Formats: append([]Format(nil), record.Formats...),
		Categories:  append([]stats.Category(nil), record.Categories...),
		TrendMetric: record.TrendMetric, DetailRows: record.DetailRows,
		DataScopeJSON: encodeHistoryDataScope(record.DataScope),
		TaskID:        record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, CleanupState: "none",
		RetryOf: record.RetryOf,
	}
	if entry.Name == "" {
		entry.Name = "统计报告"
	}
	if entry.Template == "" {
		entry.Template = "standard"
	}
	if window, err := json.Marshal(record.Window); err == nil {
		entry.WindowJSON = window
	} else {
		entry.WindowJSON = []byte("{}")
	}
	if record.Snapshot != nil {
		if snapshot, err := json.Marshal(record.Snapshot); err == nil {
			entry.SnapshotJSON = snapshot
		}
	}
	artifacts := make([]historyArtifact, 0, len(record.Artifacts))
	for _, format := range record.Formats {
		artifact, ok := record.Artifacts[format]
		if !ok {
			continue
		}
		artifacts = append(artifacts, historyArtifact{
			Format: string(artifact.Format), Name: artifact.FileName,
			Bytes: artifact.Bytes, SHA256: artifact.SHA256,
		})
	}
	if encoded, err := json.Marshal(artifacts); err == nil {
		entry.ArtifactsJSON = encoded
	} else {
		entry.ArtifactsJSON = []byte("[]")
	}
	return entry
}

// persistHistory 把当前内存记录的真实状态写入持久历史（若已装配）。它必须不改变
// 报告状态机：写入失败只告警，调用方继续返回真实终态。
func (s *Service) persistHistory(ctx context.Context, reportID string) {
	if isNil(s.opts.History) {
		return
	}
	record, found := s.get(reportID)
	if !found {
		return
	}
	entry := s.reportHistoryRecord(record)
	if err := s.opts.History.RecordReportHistory(ctx, entry); err != nil {
		s.opts.Logger.Error("报告历史持久化写入失败",
			"report_id", reportID, "code", string(CodeDBUnavailable))
	}
}

// persistRejectedHistory 记录一次执行前权限复验拒绝：状态为 failed、错误码
// ACCESS_DENIED，说明“未创建任务/未生成报告”，避免把拒绝伪装成完成或普通失败。
// 它用于计划触发生成在创建报告记录前即被拒绝的场景。
func (s *Service) persistRejectedHistory(ctx context.Context, entry HistoryRecord) {
	if isNil(s.opts.History) {
		return
	}
	if entry.ReportID == "" {
		id, err := s.newID(reportIDPrefix)
		if err != nil {
			return
		}
		entry.ReportID = id
	}
	if entry.State == "" {
		entry.State = StateFailed
	}
	if entry.ErrorCode == "" {
		entry.ErrorCode = string(CodeAccessDenied)
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = s.now()
	}
	entry.FinishedAt = entry.CreatedAt
	if entry.Name == "" {
		entry.Name = "计划报告（未生成）"
	}
	if entry.Template == "" {
		entry.Template = "standard"
	}
	if len(entry.Formats) == 0 {
		entry.Formats = []Format{FormatHTML}
	}
	if len(entry.WindowJSON) == 0 {
		entry.WindowJSON = []byte("{}")
	}
	if len(entry.DataScopeJSON) == 0 {
		entry.DataScopeJSON = []byte("{}")
	}
	if len(entry.ArtifactsJSON) == 0 {
		entry.ArtifactsJSON = []byte("[]")
	}
	if entry.CleanupState == "" {
		entry.CleanupState = "none"
	}
	if err := s.opts.History.RecordReportHistory(ctx, entry); err != nil {
		s.opts.Logger.Error("计划执行拒绝历史写入失败",
			"code", string(CodeDBUnavailable))
	}
}
